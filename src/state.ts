/**
 * Local state in ~/.vet-skills/ (override with VET_SKILLS_HOME):
 *   id           anonymous client id (install-count proxy; never tied to an email)
 *   cache.json   verdicts by artifact hash, with ETag and fetch time (24 h TTL)
 *   policy.yaml  the personal policy, or the org policy as last fetched
 *   org.json     org slug, agent id, policy version, enforcement (org mode only)
 *   agent.token  org-mode agent token (0600)
 *   log.jsonl    last 30 days of decisions, for `vet-skills why`
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync, appendFileSync, chmodSync, unlinkSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { DEFAULT_POLICY, SOLO_POLICY, parsePolicyYaml, serializePolicyYaml, type Policy } from "./policy/index.js";

export const VERSION = "0.9.0";
export const HOME = process.env.VET_SKILLS_HOME ?? join(homedir(), ".vet-skills");
export const API = (process.env.KILLERSKILLS_API ?? "https://killerskills.ai").replace(/\/$/, "");

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_MAX = 10_000;

export type CredentialSurface = { env: { name: string; kind: "credential" | "config"; files: string[] }[]; flags: string[]; files: string[]; hosts: { host: string; own: boolean; files: string[] }[]; scanned: number };

export type CachedVerdict = { fetchedAt: number; etag?: string; data: ResolveResponse };

export type ResolveResponse = {
  status: "scored" | "unscored";
  skill: { name: string; registry: string; registry_label: string; install_count: number; page: string; kind: string };
  publisher: { handle: string; verified: boolean; age_days: number };
  version: { semver: string; artifact_hash: string; declared_permissions: { network: string[]; filesystem: string[]; memory: boolean } };
  verdict: { id: string; score: number; label: "verified" | "caution" | "blocked"; duration_ms: number; scenarios_run: number } | null;
  trace_summary: { egress_hosts: { host: string; declared: boolean; implied?: string }[]; files_read: string[]; files_written: string[]; memory_writes: unknown[]; tool_shadowing: { tool: string; server: string }[]; coverage?: { level: "full" | "startup_only" | "install_failed" | "install_only"; summary: string; tested: string[]; untested: string[]; needs: string[] } | null } | null;
  findings: { rule_id: string; severity: string; title: string; detail: string; file?: string | null; line?: number | null; evidence?: string | null }[];
  last_safe_version: { semver: string; score: number } | null;
  /** What the code asks for and where it talks to (engine ≥ 1.8); null until the version has been run under it. */
  credentials?: CredentialSurface | null;
  /** Open or confirmed incident: a hook elsewhere saw this package misbehave (open = honeypot re-run pending; confirmed = observed). */
  incident?: { status: "open" | "confirmed"; source: "field" | "sandbox"; opened_at: string; kinds: string[]; machines: number; note: string | null; page: string } | null;
};

export type OrgState = { slug: string; agentId: string; policyVersion: number; enforcement: "observe" | "enforce"; joinedAt: string };

export type LogEntry = {
  at: string; skill: string; semver: string; hash: string | null; decision: string; wouldBe?: string; reason: string;
  policy: string; offline: boolean; chosen?: string; requestId?: string;
};

function ensureHome() {
  if (!existsSync(HOME)) mkdirSync(HOME, { recursive: true, mode: 0o700 });
}

export function clientId(): string {
  ensureHome();
  const p = join(HOME, "id");
  if (existsSync(p)) return readFileSync(p, "utf8").trim();
  const id = randomUUID();
  writeFileSync(p, id + "\n", { mode: 0o600 });
  return id;
}

export function readCache(): Record<string, CachedVerdict> {
  const p = join(HOME, "cache.json");
  if (!existsSync(p)) return {};
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return {}; }
}

export function cacheGet(hash: string): CachedVerdict | null {
  const c = readCache()[hash];
  if (!c) return null;
  if (Date.now() - c.fetchedAt > CACHE_TTL_MS) return null;
  return c;
}

export function cachePut(hash: string, entry: CachedVerdict) {
  ensureHome();
  const c = readCache();
  c[hash] = entry;
  const keys = Object.keys(c);
  if (keys.length > CACHE_MAX) {
    keys.sort((a, b) => c[a].fetchedAt - c[b].fetchedAt).slice(0, keys.length - CACHE_MAX).forEach((k) => delete c[k]);
  }
  writeFileSync(join(HOME, "cache.json"), JSON.stringify(c));
}

export function cacheSize(): number {
  return Object.keys(readCache()).length;
}

export function readPolicy(): { policy: Policy; source: "org" | "personal" | "default" } {
  const p = join(HOME, "policy.yaml");
  const org = readOrg();
  if (existsSync(p)) return { policy: parsePolicyYaml(readFileSync(p, "utf8")), source: org ? "org" : "personal" };
  return { policy: org ? DEFAULT_POLICY : SOLO_POLICY, source: "default" };
}

export function writePolicy(policy: Policy | string) {
  ensureHome();
  writeFileSync(join(HOME, "policy.yaml"), typeof policy === "string" ? policy : serializePolicyYaml(policy));
}

export function readOrg(): OrgState | null {
  const p = join(HOME, "org.json");
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}

export function writeOrg(o: OrgState | null) {
  ensureHome();
  const p = join(HOME, "org.json");
  if (!o) { if (existsSync(p)) unlinkSync(p); return; }
  writeFileSync(p, JSON.stringify(o, null, 2) + "\n", { mode: 0o600 });
}

export function readToken(): string | null {
  const p = join(HOME, "agent.token");
  return existsSync(p) ? readFileSync(p, "utf8").trim() : null;
}

export function writeToken(t: string | null) {
  ensureHome();
  const p = join(HOME, "agent.token");
  if (!t) { if (existsSync(p)) unlinkSync(p); return; }
  writeFileSync(p, t + "\n", { mode: 0o600 });
  chmodSync(p, 0o600);
}

export function appendLog(e: LogEntry) {
  ensureHome();
  appendFileSync(join(HOME, "log.jsonl"), JSON.stringify(e) + "\n");
}

export function readLog(): LogEntry[] {
  const p = join(HOME, "log.jsonl");
  if (!existsSync(p)) return [];
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  return readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l) as LogEntry; } catch { return null; } }).filter((e): e is LogEntry => !!e && Date.parse(e.at) > cutoff);
}

export function stateSummary() {
  const sz = (f: string) => (existsSync(join(HOME, f)) ? statSync(join(HOME, f)).size : 0);
  return { home: HOME, cacheEntries: cacheSize(), cacheBytes: sz("cache.json"), logBytes: sz("log.jsonl") };
}

/* ---------------------------------------------------------------- telemetry */

/**
 * Anonymous usage telemetry for machines that are not enrolled in an org: skill name, version, registry, decision,
 * agent kind, hook version and OS, under the random client id. Never code, prompts, paths, hostnames or emails.
 * Off when VET_SKILLS_TELEMETRY is 0/false/off, DO_NOT_TRACK=1, or after `vet-skills telemetry off`.
 */
export function telemetryEnabled(): boolean {
  const env = (process.env.VET_SKILLS_TELEMETRY ?? "").toLowerCase();
  if (["0", "false", "off", "no"].includes(env)) return false;
  if (process.env.DO_NOT_TRACK === "1") return false;
  const p = join(HOME, "telemetry");
  if (existsSync(p)) return readFileSync(p, "utf8").trim() !== "off";
  return true;
}

export function setTelemetry(on: boolean) {
  ensureHome();
  writeFileSync(join(HOME, "telemetry"), on ? "on\n" : "off\n", { mode: 0o600 });
}

/** True the first time it is called on this machine (the caller prints the telemetry notice once). */
export function telemetryNoticePending(): boolean {
  ensureHome();
  const p = join(HOME, "telemetry-notice");
  if (existsSync(p)) return false;
  writeFileSync(p, new Date().toISOString() + "\n", { mode: 0o600 });
  return true;
}

/** Rate-limit a hint to once per UTC day (key = hint name). */
export function hintOncePerDay(key: string): boolean {
  ensureHome();
  const p = join(HOME, `hint-${key.replace(/[^\w-]/g, "_")}`);
  const today = new Date().toISOString().slice(0, 10);
  if (existsSync(p) && readFileSync(p, "utf8").trim() === today) return false;
  writeFileSync(p, today + "\n", { mode: 0o600 });
  return true;
}
