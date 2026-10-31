/**
 * Verify signed verdicts and pin them in a lockfile.
 *
 *   vet-skills verify <skill>[@ver] | <path>   fetch the attestation, check the signature, compare the hash of what is on disk
 *   vet-skills lock                            write vet-skills.lock for every installed skill (hash + verdict + attestation + key)
 *   vet-skills verify --lock                   offline: re-hash installed skills against the lock and re-check every signature
 *
 * Attestations are DSSE envelopes over a KillerSkills statement, signed with
 * Ed25519. Keys come from /.well-known/killerskills-keys.json over TLS; a key
 * seen in a lockfile is pinned, and VET_SKILLS_TRUSTED_KEYS (comma-separated
 * kids) restricts verification to those.
 */
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { API, VERSION } from "./state.js";
import { resolveSkill } from "./api.js";

export interface Envelope { payloadType: string; payload: string; signatures: { keyid: string; sig: string }[] }
export interface Statement { _type: string; issuer: string; issued_at: string; subject: { name: string; publisher: string; registry: string; version: string; artifact_hash: string }; predicate: { verdict_id: string; label: string; score: number; engine_version: string; scenarios_run: number; static_only: boolean; detonated_at: string; superseded: boolean; verdict_url: string } }
export interface Jwk { kid: string; kty: string; crv: string; x: string; dev?: boolean }
export interface LockEntry { name: string; path: string; artifact_hash: string; verdict: { id: string; label: string; score: number; engine_version: string } | null; attestation: Envelope | null }
export interface Lockfile { version: 1; generated_at: string; generated_by: string; issuer: string; keys: Jwk[]; skills: LockEntry[] }

export const LOCKFILE = "vet-skills.lock";
const PAYLOAD_TYPE = "application/vnd.killerskills.verdict+json";
const SKIP = new Set(["node_modules", ".git", ".pglite", ".next", "__pycache__", ".venv"]);

/** Same canonical hash as the sandbox: sorted paths, "\0", bytes, "\0". */
export function bundleHash(root: string): string {
  const h = createHash("sha256");
  const walk = (dir: string) => {
    for (const name of readdirSync(dir).sort()) {
      if (SKIP.has(name)) continue;
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile() && st.size <= 2 * 1024 * 1024) { h.update(relative(root, p).split(sep).join("/")); h.update("\0"); h.update(readFileSync(p)); h.update("\0"); }
    }
  };
  walk(root);
  return h.digest("hex");
}

function pae(payloadType: string, payload: Buffer) {
  const t = Buffer.from(payloadType);
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), payload]);
}

export function verifyEnvelope(env: Envelope, keys: Jwk[]): { ok: boolean; statement: Statement | null; kid: string | null; reason: string } {
  if (env.payloadType !== PAYLOAD_TYPE) return { ok: false, statement: null, kid: null, reason: `unexpected payload type ${env.payloadType}` };
  const payload = Buffer.from(env.payload, "base64");
  const trusted = (process.env.VET_SKILLS_TRUSTED_KEYS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  for (const sig of env.signatures) {
    const k = keys.find((x) => x.kid === sig.keyid);
    if (!k) continue;
    if (trusted.length && !trusted.includes(k.kid)) return { ok: false, statement: null, kid: k.kid, reason: `key ${k.kid} is not in VET_SKILLS_TRUSTED_KEYS` };
    if (k.dev) return { ok: false, statement: null, kid: k.kid, reason: "signed with a development key" };
    try {
      const pub = createPublicKey({ key: { kty: k.kty, crv: k.crv, x: k.x }, format: "jwk" });
      if (cryptoVerify(null, pae(env.payloadType, payload), pub, Buffer.from(sig.sig, "base64"))) return { ok: true, statement: JSON.parse(payload.toString("utf8")) as Statement, kid: k.kid, reason: "signature valid" };
      return { ok: false, statement: null, kid: k.kid, reason: "signature does not verify" };
    } catch (e) { return { ok: false, statement: null, kid: k.kid, reason: (e as Error).message }; }
  }
  return { ok: false, statement: null, kid: env.signatures[0]?.keyid ?? null, reason: "no known key for this signature" };
}

async function getJson<T>(url: string): Promise<T | null> {
  try { const r = await fetch(url, { headers: { accept: "application/json", "user-agent": `vet-skills/${VERSION}` }, signal: AbortSignal.timeout(8000) }); return r.ok ? ((await r.json()) as T) : null; } catch { return null; }
}

export async function fetchKeys(): Promise<Jwk[]> {
  const r = await getJson<{ keys: Jwk[] }>(`${API}/.well-known/killerskills-keys.json`);
  return r?.keys ?? [];
}

export async function fetchAttestationByHash(hash: string): Promise<Envelope | null> { return getJson<Envelope>(`${API}/api/v1/verdicts/${hash}/attestation`); }

/** Installed skills on this machine: name → dir. */
export function installedSkills(): { name: string; path: string }[] {
  const out: { name: string; path: string }[] = [];
  for (const base of [join(process.cwd(), ".claude", "skills"), join(homedir(), ".claude", "skills"), join(homedir(), ".claude", "plugins")]) {
    if (!existsSync(base)) continue;
    for (const name of readdirSync(base).sort()) { const p = join(base, name); if (statSync(p).isDirectory() && !out.some((x) => x.name === name)) out.push({ name, path: p }); }
  }
  return out;
}

export interface VerifyReport { subject: string; hash: string; ok: boolean; detail: string; statement: Statement | null }

/** Verify one thing: a local directory, or a registry skill (by name, optionally @version). */
export async function verifyOne(target: string, keys: Jwk[]): Promise<VerifyReport> {
  const dir = resolve(target);
  let hash: string; let subject = target; let page: string | null = null;
  if (existsSync(dir) && statSync(dir).isDirectory()) { hash = bundleHash(dir); subject = `${target} (${hash.slice(0, 12)}…)`; }
  else {
    const [name, ver] = target.split("@").length > 2 ? [target.slice(0, target.lastIndexOf("@")), target.slice(target.lastIndexOf("@") + 1)] : target.includes("@") && !target.startsWith("@") ? target.split("@") : [target, undefined];
    const r = await resolveSkill(name);
    if (!r.ok) return { subject, hash: "", ok: false, detail: r.offline ? "offline" : `not found: ${r.error}`, statement: null };
    if (ver && r.data.version.semver !== ver) return { subject, hash: "", ok: false, detail: `latest scored version is ${r.data.version.semver}; verify a local checkout of ${ver} with a path instead`, statement: null };
    hash = r.data.version.artifact_hash; page = r.data.skill.page; subject = `${r.data.skill.name}@${r.data.version.semver}`;
    const local = installedSkills().find((s) => s.name === r.data.skill.name);
    if (local) { const lh = bundleHash(local.path); if (lh !== hash) return { subject, hash: lh, ok: false, detail: `installed copy at ${local.path} hashes to ${lh.slice(0, 12)}…, attested version is ${hash.slice(0, 12)}…`, statement: null }; }
  }
  const env = await fetchAttestationByHash(hash);
  if (!env) return { subject, hash, ok: false, detail: `no attestation for ${hash.slice(0, 12)}… (unscored, demo or signing not configured)${page ? ` · ${API}${page}` : ""}`, statement: null };
  const v = verifyEnvelope(env, keys);
  if (!v.ok || !v.statement) return { subject, hash, ok: false, detail: v.reason, statement: null };
  if (v.statement.subject.artifact_hash !== hash) return { subject, hash, ok: false, detail: "attestation is for a different artifact", statement: v.statement };
  return { subject, hash, ok: true, detail: `${v.statement.predicate.label} ${v.statement.predicate.score} · engine ${v.statement.predicate.engine_version} · signed by ${v.kid}${v.statement.predicate.superseded ? " · superseded" : ""}`, statement: v.statement };
}

export async function writeLock(dir = process.cwd()): Promise<{ file: string; lock: Lockfile; missing: string[] }> {
  const keys = await fetchKeys();
  const skills: LockEntry[] = []; const missing: string[] = [];
  for (const s of installedSkills()) {
    const hash = bundleHash(s.path);
    const env = await fetchAttestationByHash(hash);
    const v = env ? verifyEnvelope(env, keys) : null;
    if (!v?.ok || !v.statement) missing.push(s.name);
    skills.push({ name: s.name, path: s.path, artifact_hash: hash, verdict: v?.statement ? { id: v.statement.predicate.verdict_id, label: v.statement.predicate.label, score: v.statement.predicate.score, engine_version: v.statement.predicate.engine_version } : null, attestation: v?.ok ? env : null });
  }
  const lock: Lockfile = { version: 1, generated_at: new Date().toISOString(), generated_by: `vet-skills ${VERSION}`, issuer: API, keys: keys.filter((k) => !k.dev), skills };
  const file = join(dir, LOCKFILE);
  writeFileSync(file, `${JSON.stringify(lock, null, 2)}\n`);
  return { file, lock, missing };
}

export function readLock(dir = process.cwd()): Lockfile | null {
  const file = join(dir, LOCKFILE);
  if (!existsSync(file)) return null;
  try { return JSON.parse(readFileSync(file, "utf8")) as Lockfile; } catch { return null; }
}

/** Offline check: every pinned skill still hashes the same and its attestation still verifies with the pinned keys. */
export function verifyLock(lock: Lockfile): VerifyReport[] {
  return lock.skills.map((e) => {
    const path = existsSync(e.path) ? e.path : installedSkills().find((s) => s.name === e.name)?.path;
    if (!path) return { subject: e.name, hash: e.artifact_hash, ok: false, detail: "not installed", statement: null };
    const hash = bundleHash(path);
    if (hash !== e.artifact_hash) return { subject: e.name, hash, ok: false, detail: `changed on disk: ${hash.slice(0, 12)}… (locked ${e.artifact_hash.slice(0, 12)}…)`, statement: null };
    if (!e.attestation) return { subject: e.name, hash, ok: true, detail: "hash matches · pinned by hash only (no attestation when locked)", statement: null };
    const v = verifyEnvelope(e.attestation, lock.keys);
    if (!v.ok || !v.statement) return { subject: e.name, hash, ok: false, detail: v.reason, statement: null };
    if (v.statement.subject.artifact_hash !== hash) return { subject: e.name, hash, ok: false, detail: "attestation is for a different artifact", statement: v.statement };
    return { subject: e.name, hash, ok: true, detail: `${v.statement.predicate.label} ${v.statement.predicate.score} · engine ${v.statement.predicate.engine_version} · signed by ${v.kid}`, statement: v.statement };
  });
}
