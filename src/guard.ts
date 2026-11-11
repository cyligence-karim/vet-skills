/**
 * `vet-skills guard`: every MCP server on this machine runs under the guard, without anyone remembering to type it.
 *
 *   guard install [--project]   rewrite the MCP configs of Claude Code, Claude Desktop, Cursor, Windsurf, Gemini CLI and
 *                               Codex so each stdio server is launched as `vet-skills guard exec --server <name> -- <cmd>`.
 *                               Idempotent; originals are kept in ~/.vet-skills/guard/wrapped.json.
 *   guard uninstall             put the original commands back.
 *   guard status                what is wrapped, what ran, what it contacted, what was held.
 *   guard exec --server <name> --client <agent> [--secrets …] -- <cmd…>   (called by the client) run one server under the guard:
 *       · the verdict for the package is looked up; a blocked version or a confirmed incident refuses to launch (policy);
 *       · credential variables the verdict names are brokered: the server gets placeholders, the real value goes only to
 *         the vendor's host (policy runtime.secrets);
 *       · every host contacted is recorded; the first time this package version reaches one nothing on record names,
 *         the user is told (runtime.new_host), or the connection is refused;
 *       · tool calls follow runtime.tools: allow, deny, or hold for approval;
 *       · the session is written to ~/.vet-skills/runtime/guard.jsonl and, on an enrolled machine, reported to the org;
 *         an un-enrolled machine with telemetry on sends an anonymous sighting (package, version, hosts) so a server that
 *         misbehaves on one laptop is re-run in the honeypot for everyone.
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join } from "node:path";
import { approvalCreate, approvalPoll, guardReport, guardSighting, launchCheck, resolveSkill, type GuardSessionReport } from "./api.js";
import { guard, parseRunArgs, type GuardEvent, type RunOptions } from "./run.js";
import { HOME, VERSION, clientId, readOrg, readPolicy, telemetryEnabled, type ResolveResponse } from "./state.js";
import { mint, secretsSpecFor, type Minted } from "./exchange.js";
import type { SecretBinding } from "./broker.js";
import type { ToolRule } from "./policy/index.js";

export type GuardClient = "claude-code" | "claude-desktop" | "cursor" | "windsurf" | "gemini" | "codex" | "grok" | "vscode" | "copilot" | "kiro" | "qwen" | "cline" | "zed" | "amp" | "opencode";
interface ConfigSpec { path: string; client: GuardClient; format: "mcpServers" | "claude-json" | "vscode" | "codex-toml" | "amp" | "zed" | "opencode"; scope: "user" | "project" }

const GUARD_DIR = join(HOME, "guard");
const WRAPPED = join(GUARD_DIR, "wrapped.json");
const BASELINE = join(GUARD_DIR, "hosts.json");
const OPAQUE = join(GUARD_DIR, "opaque.json");
const LOG = join(HOME, "runtime", "guard.jsonl");

export function configSpecs(opts: { home?: string; project?: string | null } = {}): ConfigSpec[] {
  const home = opts.home ?? homedir();
  const user: ConfigSpec[] = [
    { path: join(home, ".claude.json"), client: "claude-code", format: "claude-json", scope: "user" },
    { path: join(home, ".cursor", "mcp.json"), client: "cursor", format: "mcpServers", scope: "user" },
    { path: join(home, ".codeium", "windsurf", "mcp_config.json"), client: "windsurf", format: "mcpServers", scope: "user" },
    { path: join(home, ".gemini", "settings.json"), client: "gemini", format: "mcpServers", scope: "user" },
    { path: join(home, ".codex", "config.toml"), client: "codex", format: "codex-toml", scope: "user" },
    { path: join(home, ".grok", "config.toml"), client: "grok", format: "codex-toml", scope: "user" },
    { path: join(process.env.COPILOT_HOME ?? join(home, ".copilot"), "mcp-config.json"), client: "copilot", format: "mcpServers", scope: "user" },
    { path: join(home, ".kiro", "settings", "mcp.json"), client: "kiro", format: "mcpServers", scope: "user" },
    { path: join(home, ".qwen", "settings.json"), client: "qwen", format: "mcpServers", scope: "user" },
    { path: process.env.CLINE_MCP_SETTINGS_PATH ?? join(home, ".cline", "data", "settings", "cline_mcp_settings.json"), client: "cline", format: "mcpServers", scope: "user" },
    { path: join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), client: "cline", format: "mcpServers", scope: "user" },
    { path: join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), client: "cline", format: "mcpServers", scope: "user" },
    { path: join(home, "AppData", "Roaming", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), client: "cline", format: "mcpServers", scope: "user" },
    { path: join(process.env.XDG_CONFIG_HOME ?? join(home, ".config"), "zed", "settings.json"), client: "zed", format: "zed", scope: "user" },
    { path: join(home, "AppData", "Roaming", "Zed", "settings.json"), client: "zed", format: "zed", scope: "user" },
    { path: join(home, ".config", "amp", "settings.json"), client: "amp", format: "amp", scope: "user" },
    { path: join(process.env.XDG_CONFIG_HOME ?? join(home, ".config"), "opencode", "opencode.json"), client: "opencode", format: "opencode", scope: "user" },
    { path: join(process.env.XDG_CONFIG_HOME ?? join(home, ".config"), "opencode", "opencode.jsonc"), client: "opencode", format: "opencode", scope: "user" },
    { path: join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), client: "claude-desktop", format: "mcpServers", scope: "user" },
    { path: join(home, ".config", "Claude", "claude_desktop_config.json"), client: "claude-desktop", format: "mcpServers", scope: "user" },
    { path: join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"), client: "claude-desktop", format: "mcpServers", scope: "user" },
  ];
  const project: ConfigSpec[] = opts.project ? [
    { path: join(opts.project, ".mcp.json"), client: "claude-code", format: "mcpServers", scope: "project" },
    { path: join(opts.project, ".cursor", "mcp.json"), client: "cursor", format: "mcpServers", scope: "project" },
    { path: join(opts.project, ".vscode", "mcp.json"), client: "vscode", format: "vscode", scope: "project" },
    { path: join(opts.project, ".gemini", "settings.json"), client: "gemini", format: "mcpServers", scope: "project" },
    { path: join(opts.project, ".github", "mcp.json"), client: "copilot", format: "mcpServers", scope: "project" },
    { path: join(opts.project, ".kiro", "settings", "mcp.json"), client: "kiro", format: "mcpServers", scope: "project" },
    { path: join(opts.project, ".qwen", "settings.json"), client: "qwen", format: "mcpServers", scope: "project" },
    { path: join(opts.project, ".zed", "settings.json"), client: "zed", format: "zed", scope: "project" },
    { path: join(opts.project, ".amp", "settings.json"), client: "amp", format: "amp", scope: "project" },
    { path: join(opts.project, "opencode.json"), client: "opencode", format: "opencode", scope: "project" },
    { path: join(opts.project, ".opencode", "opencode.json"), client: "opencode", format: "opencode", scope: "project" },
  ] : [];
  return [...user, ...project].filter((s) => existsSync(s.path));
}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);
interface ServerEntry { command?: string | string[]; args?: string[]; env?: Record<string, string>; url?: string; type?: string; [k: string]: unknown }

/** The absolute `vet-skills` to put in configs: GUI clients start with a short PATH. Falls back to `npx -y vet-skills@<version>`. */
export function guardBinary(): { command: string; prefix: string[] } {
  if (process.env.VET_SKILLS_BIN) return { command: process.env.VET_SKILLS_BIN, prefix: [] };
  const r = spawnSync(platform() === "win32" ? "where" : "which", ["vet-skills"], { encoding: "utf8" });
  const found = r.status === 0 ? r.stdout.split(/\r?\n/).map((s) => s.trim()).find(Boolean) : null;
  if (found) return { command: found, prefix: [] };
  return { command: "npx", prefix: ["-y", `vet-skills@${VERSION}`] };
}

export const isWrapped = (e: ServerEntry) => Array.isArray(e.args) && e.args.includes("guard") && e.args.includes("exec") && /vet-skills|npx$/.test(String(e.command ?? ""));

function wrapEntry(name: string, client: GuardClient, e: ServerEntry, bin = guardBinary()): ServerEntry | null {
  if (!e.command || isWrapped(e) || e.url || (e.type && e.type !== "stdio" && e.type !== "local")) return null;
  if (typeof e.command !== "string" && !Array.isArray(e.command)) return null; // older nested { path, args } shape
  if (Array.isArray(e.command)) {
    // OpenCode keeps the whole command line in one array.
    const cmd = e.command as string[]; if (!cmd.length || isWrappedArray(cmd)) return null;
    return { ...e, command: [bin.command, ...bin.prefix, "guard", "exec", "--server", name, "--client", client, "--", ...cmd] };
  }
  return { ...e, command: bin.command, args: [...bin.prefix, "guard", "exec", "--server", name, "--client", client, "--", e.command, ...(e.args ?? [])] };
}
const isWrappedArray = (cmd: string[]) => cmd.includes("guard") && cmd.includes("exec") && /vet-skills|npx$/.test(cmd[0] ?? "");
/** The original command of a wrapped entry, read back from its own args (so uninstall works even without wrapped.json). */
export function unwrapEntry(e: ServerEntry): ServerEntry | null {
  if (Array.isArray(e.command)) { const cmd = e.command as string[]; if (!isWrappedArray(cmd)) return null; const i = cmd.indexOf("--"); if (i < 0 || i === cmd.length - 1) return null; return { ...e, command: cmd.slice(i + 1) }; }
  if (!isWrapped(e) || !Array.isArray(e.args)) return null;
  const i = e.args.indexOf("--"); if (i < 0 || i === e.args.length - 1) return null;
  const orig = e.args.slice(i + 1);
  return { ...e, command: orig[0], args: orig.slice(1) };
}

interface Touched { file: string; client: GuardClient; wrapped: string[]; skipped: { name: string; why: string }[] }

function readJsonc(text: string): unknown {
  try { return JSON.parse(text); } catch { /* fall through */ }
  const noComments = text.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_m, s1: string | undefined) => s1 ?? "");
  try { return JSON.parse(noComments.replace(/,(\s*[}\]])/g, "$1")); } catch { return null; }
}

/** Every `mcpServers`-shaped map in a config, with a path label for wrapped.json. */
function serverMaps(spec: ConfigSpec, root: Json): { label: string; map: Json }[] {
  if (spec.format === "vscode") return isObj(root.servers) ? [{ label: "servers", map: root.servers }] : [];
  if (spec.format === "amp") return isObj(root["amp.mcpServers"]) ? [{ label: "amp.mcpServers", map: root["amp.mcpServers"] as Json }] : [];
  if (spec.format === "zed") return isObj(root.context_servers) ? [{ label: "context_servers", map: root.context_servers }] : [];
  if (spec.format === "opencode") {
    if (!isObj(root.mcp)) return [];
    const mcp = root.mcp as Json;
    return isObj(mcp.servers) ? [{ label: "mcp.servers", map: mcp.servers }] : [{ label: "mcp", map: mcp }];
  }
  const out: { label: string; map: Json }[] = [];
  if (isObj(root.mcpServers)) out.push({ label: "mcpServers", map: root.mcpServers });
  if (spec.format === "claude-json" && isObj(root.projects)) for (const [p, v] of Object.entries(root.projects)) if (isObj(v) && isObj(v.mcpServers)) out.push({ label: `projects.${p}.mcpServers`, map: v.mcpServers });
  return out;
}

function rewriteJson(spec: ConfigSpec, mode: "wrap" | "unwrap", bin: ReturnType<typeof guardBinary>): Touched | null {
  const text = readFileSync(spec.path, "utf8");
  const root = readJsonc(text);
  if (!isObj(root)) return null;
  const t: Touched = { file: spec.path, client: spec.client, wrapped: [], skipped: [] };
  let changed = false;
  for (const { map } of serverMaps(spec, root)) {
    for (const [name, v] of Object.entries(map)) {
      if (!isObj(v)) continue;
      const e = v as ServerEntry;
      if (mode === "wrap") {
        const w = wrapEntry(name, spec.client, e, bin);
        if (!w) { if (!isWrapped(e) && !(Array.isArray(e.command) && isWrappedArray(e.command as string[]))) t.skipped.push({ name, why: e.url || (e.type && e.type !== "stdio" && e.type !== "local") ? "remote server (http/sse); the guard wraps stdio servers" : isObj(e.command) ? "older nested command shape; edit it to command/args and re-run" : "no command" }); continue; }
        map[name] = w; t.wrapped.push(name); changed = true;
      } else {
        const u = unwrapEntry(e); if (!u) continue;
        map[name] = u; t.wrapped.push(name); changed = true;
      }
    }
  }
  if (changed) { backup(spec.path, text); writeFileSync(spec.path, JSON.stringify(root, null, 2) + "\n"); }
  return t;
}

/** Codex and Grok CLI keep MCP servers in TOML: `[mcp_servers.NAME]` with `command = "…"` and `args = [...]`. Only those two lines move. */
export function rewriteCodexToml(text: string, mode: "wrap" | "unwrap", bin: ReturnType<typeof guardBinary>, client: GuardClient = "codex"): { text: string; wrapped: string[] } {
  const lines = text.split("\n");
  const wrapped: string[] = []; const removed: number[] = [];
  let section: string | null = null; let cmdIdx = -1; let argsIdx = -1;
  const flush = () => {
    if (section === null) return;
    if (cmdIdx >= 0) {
      const cmd = lines[cmdIdx].match(/^\s*command\s*=\s*"((?:\\.|[^"])*)"/)?.[1] ?? null;
      const argsLine = argsIdx >= 0 ? lines[argsIdx] : null;
      const args: string[] = argsLine ? [...(argsLine.match(/\[(.*)\]/)?.[1] ?? "").matchAll(/"((?:\\.|[^"])*)"/g)].map((m) => m[1]) : [];
      const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
      if (cmd && mode === "wrap" && !(args.includes("guard") && args.includes("exec"))) {
        const w = wrapEntry(section, client, { command: cmd, args }, bin)!;
        lines[cmdIdx] = `command = ${q(String(w.command))}`;
        const argsText = `args = [${w.args!.map(q).join(", ")}]`;
        if (argsIdx >= 0) lines[argsIdx] = argsText; else lines.splice(cmdIdx + 1, 0, argsText);
        wrapped.push(section);
      } else if (cmd && mode === "unwrap" && args.includes("guard") && args.includes("exec")) {
        const u = unwrapEntry({ command: cmd, args })!;
        lines[cmdIdx] = `command = ${q(String(u.command))}`;
        if (argsIdx >= 0) { if (u.args!.length) lines[argsIdx] = `args = [${u.args!.map(q).join(", ")}]`; else removed.push(argsIdx); }
        wrapped.push(section);
      }
    }
    section = null; cmdIdx = -1; argsIdx = -1;
  };
  for (let i = 0; i < lines.length; i++) {
    const h = lines[i].match(/^\s*\[mcp_servers\.([^\]]+)\]\s*$/);
    if (h || /^\s*\[/.test(lines[i])) { flush(); section = h ? h[1].replace(/^"|"$/g, "") : null; continue; }
    if (section !== null) { if (/^\s*command\s*=/.test(lines[i])) cmdIdx = i; else if (/^\s*args\s*=/.test(lines[i])) argsIdx = i; }
  }
  flush();
  return { text: lines.filter((_l, i) => !removed.includes(i)).join("\n"), wrapped };
}

function backup(path: string, text: string) {
  try { mkdirSync(join(GUARD_DIR, "backup"), { recursive: true, mode: 0o700 }); writeFileSync(join(GUARD_DIR, "backup", `${createHash("sha1").update(path).digest("hex").slice(0, 10)}-${Date.now()}.bak`), text); } catch { /* best effort */ }
}

export function installGuard(opts: { project?: string | null; home?: string } = {}): Touched[] {
  const bin = guardBinary();
  const out: Touched[] = [];
  for (const spec of configSpecs(opts)) {
    try {
      if (spec.format === "codex-toml") {
        const text = readFileSync(spec.path, "utf8");
        const r = rewriteCodexToml(text, "wrap", bin, spec.client);
        if (r.wrapped.length) { backup(spec.path, text); writeFileSync(spec.path, r.text); }
        out.push({ file: spec.path, client: spec.client, wrapped: r.wrapped, skipped: [] });
      } else { const t = rewriteJson(spec, "wrap", bin); if (t) out.push(t); }
    } catch (e) { out.push({ file: spec.path, client: spec.client, wrapped: [], skipped: [{ name: "*", why: (e as Error).message }] }); }
  }
  const reg = readWrapped(); reg.installedAt ??= new Date().toISOString(); reg.binary = bin; reg.files = [...new Set([...(reg.files ?? []), ...out.filter((t) => t.wrapped.length).map((t) => t.file)])];
  writeWrapped(reg);
  return out;
}

export function uninstallGuard(opts: { project?: string | null; home?: string } = {}): Touched[] {
  const bin = guardBinary();
  const out: Touched[] = [];
  for (const spec of configSpecs(opts)) {
    try {
      if (spec.format === "codex-toml") {
        const text = readFileSync(spec.path, "utf8");
        const r = rewriteCodexToml(text, "unwrap", bin, spec.client);
        if (r.wrapped.length) { backup(spec.path, text); writeFileSync(spec.path, r.text); }
        out.push({ file: spec.path, client: spec.client, wrapped: r.wrapped, skipped: [] });
      } else { const t = rewriteJson(spec, "unwrap", bin); if (t) out.push(t); }
    } catch (e) { out.push({ file: spec.path, client: spec.client, wrapped: [], skipped: [{ name: "*", why: (e as Error).message }] }); }
  }
  const reg = readWrapped(); reg.files = []; reg.installedAt = undefined; writeWrapped(reg);
  return out;
}

interface WrappedRegistry { installedAt?: string; binary?: { command: string; prefix: string[] }; files?: string[] }
function readWrapped(): WrappedRegistry { try { return JSON.parse(readFileSync(WRAPPED, "utf8")) as WrappedRegistry; } catch { return {}; } }
function writeWrapped(r: WrappedRegistry) { mkdirSync(GUARD_DIR, { recursive: true, mode: 0o700 }); writeFileSync(WRAPPED, JSON.stringify(r, null, 2) + "\n"); }

/** Servers currently wrapped, read from the configs themselves. */
export function wrappedServers(opts: { project?: string | null; home?: string } = {}): { file: string; client: GuardClient; name: string; command: string }[] {
  const out: { file: string; client: GuardClient; name: string; command: string }[] = [];
  for (const spec of configSpecs(opts)) {
    try {
      const text = readFileSync(spec.path, "utf8");
      if (spec.format === "codex-toml") {
        const probe = rewriteCodexToml(text, "unwrap", guardBinary());
        for (const n of probe.wrapped) out.push({ file: spec.path, client: spec.client, name: n, command: "(toml)" });
        continue;
      }
      const root = readJsonc(text); if (!isObj(root)) continue;
      for (const { map } of serverMaps(spec, root)) for (const [name, v] of Object.entries(map)) { if (isObj(v) && isWrapped(v as ServerEntry)) { const u = unwrapEntry(v as ServerEntry); out.push({ file: spec.path, client: spec.client, name, command: [u?.command, ...(u?.args ?? [])].filter(Boolean).join(" ") }); } }
    } catch { /* skip */ }
  }
  return out;
}

/* ------------------------------------------------------------------ exec */

/** The registrable domain of a host (api.supabase.com → supabase.com), good enough for binding secrets. */
export function registrableDomain(host: string): string {
  const h = host.toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  const parts = h.split(".").filter(Boolean);
  if (parts.length <= 2) return h;
  const second = /^(co|com|org|net|gov|edu|ac)$/.test(parts[parts.length - 2]) && parts[parts.length - 1].length === 2;
  return parts.slice(second ? -3 : -2).join(".");
}

interface Baseline { [pkgAtVersion: string]: { hosts: string[]; sessions: number; last: string } }
function readBaseline(): Baseline { try { return JSON.parse(readFileSync(BASELINE, "utf8")) as Baseline; } catch { return {}; } }
function writeBaseline(b: Baseline) { try { mkdirSync(GUARD_DIR, { recursive: true, mode: 0o700 }); writeFileSync(BASELINE, JSON.stringify(b)); } catch { /* best effort */ } }
function readOpaque(): string[] { try { return JSON.parse(readFileSync(OPAQUE, "utf8")) as string[]; } catch { return []; } }
function writeOpaque(hosts: string[]) { try { mkdirSync(GUARD_DIR, { recursive: true, mode: 0o700 }); writeFileSync(OPAQUE, JSON.stringify([...new Set(hosts)])); } catch { /* best effort */ } }

export function appendGuardLog(e: Record<string, unknown>) { try { mkdirSync(dirname(LOG), { recursive: true }); appendFileSync(LOG, JSON.stringify({ at: new Date().toISOString(), ...e }) + "\n"); } catch { /* best effort */ } }
export function readGuardLog(days = 7): Record<string, unknown>[] {
  try { const since = Date.now() - days * 86_400_000; return readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } }).filter((x): x is Record<string, unknown> => !!x && Date.parse(String(x.at)) >= since); } catch { return []; }
}

export interface ExecArgs { server: string; client: string; secrets?: string; cmd: string[] }
export function parseExecArgs(argv: string[]): ExecArgs | { error: string } {
  let server = "", client = "unknown", secrets: string | undefined;
  let i = 0;
  while (i < argv.length && argv[i] !== "--") {
    const a = argv[i]; const v = argv[i + 1];
    if (a === "--server" && v) { server = v; i += 2; } else if (a === "--client" && v) { client = v; i += 2; } else if (a === "--secrets" && v) { secrets = v; i += 2; } else return { error: `guard exec: unknown option ${a}` };
  }
  const cmd = argv.slice(i + 1);
  if (argv[i] !== "--" || !cmd.length) return { error: "usage: vet-skills guard exec --server <name> --client <agent> [--secrets NAME=host,…] -- <command…>" };
  return { server: server || cmd[0], client, secrets, cmd };
}

/** Run one MCP server under the guard with the runtime policy applied. Called by the client; stdio is the MCP stream. */
export async function execGuarded(a: ExecArgs): Promise<number> {
  const log = (l: string) => process.stderr.write(`vet-skills guard · ${l}\n`);
  // Label is the client's name for the server; the query is the package the command runs (parseRunArgs infers it from npx/uvx).
  const parsed = parseRunArgs(["--", ...a.cmd]);
  if ("error" in parsed) { log(parsed.error); return 2; }
  parsed.opts.label = a.server;
  const { policy, source } = readPolicy();
  const rt = policy.runtime;
  const org = readOrg();
  const query = parsed.opts.query ?? a.server;
  const session = randomBytes(6).toString("hex");
  const started = new Date().toISOString();
  // What is this package? The verdict decides the launch, the bindings and what counts as an expected host.
  const r = await resolveSkill(query, undefined, "mcp");
  const v: ResolveResponse | null = r.ok ? r.data : null;
  const pkg = v?.skill.name ?? query; const semver = v?.version.semver ?? null; const registry = v?.skill.registry ?? null;
  const key = `${registry ?? "?"}:${pkg}@${semver ?? "?"}`;
  const report: GuardSessionReport = { session, server: a.server, client: a.client, pkg: v ? pkg : null, registry, semver, started, ended: null, final: false, exit_code: null, machine: clientId(), cwd_hash: createHash("sha256").update(process.cwd()).digest("hex").slice(0, 16), hosts: [], tools: [], secrets: [], canary: false, poison: [], launch: "ran", launch_reason: null, guard_version: VERSION, policy_version: org?.policyVersion ?? null };
  const toolStats = new Map<string, { tool: string; calls: number; denied: number; approved: number }>();
  // Per-call decisions for the org's record: deny and held always one row; allow folded per (tool, minute) with a count
  // unless the org asked for full capture. Argument key names only. Replies are matched by JSON-RPC id.
  const decisions: NonNullable<GuardSessionReport["decisions"]> = [];
  const byRpcId = new Map<string, number>();
  const fullCapture = process.env.VET_SKILLS_FULL_DECISIONS === "1";
  const flush = async (final: boolean) => {
    report.final = final; report.ended = final ? new Date().toISOString() : null;
    appendGuardLog({ kind: final ? "session" : "progress", session, server: a.server, client: a.client, pkg: report.pkg, semver, hosts: report.hosts.length, tools: [...toolStats.values()].reduce((n, t) => n + t.calls, 0), secrets: report.secrets.length, canary: report.canary, exit: report.exit_code });
    if (org) { const res = await guardReport(report).catch(() => null); if (res && res.ok && res.data.alerts?.length) for (const al of res.data.alerts) log(`org alert · ${al.detail}`); }
    else if (telemetryEnabled() && v) await guardSighting({ pkg, registry, semver, hosts: report.hosts.map((h) => ({ host: h.host, expected: h.expected })), placeholder_refused: report.secrets.some((s) => s.refused), canary: report.canary, guard_version: VERSION, os: process.platform }).catch(() => null);
  };
  // Kill switch: a blocked verdict or a confirmed incident does not launch (policy), and the network's flag is asked too.
  const flagged: string[] = [];
  if (v?.verdict?.label === "blocked") flagged.push(`its verdict is Blocked (${v.verdict.score}/100)`);
  if (v?.incident?.status === "confirmed") flagged.push(`a confirmed incident is open: ${v.incident.note ?? v.incident.kinds.join(", ")}`);
  const lc = await launchCheck(pkg, semver, registry).catch(() => null);
  if (lc && lc.ok && lc.data.state === "revoked") flagged.push(`it is revoked across the network${lc.data.reason ? `: ${lc.data.reason}` : ""}`);
  if (lc && lc.ok && lc.data.state === "under_review") log(`${pkg}${semver ? `@${semver}` : ""} is under review${lc.data.reason ? `: ${lc.data.reason}` : ""}${lc.data.page ? ` · https://killerskills.ai${lc.data.page}` : ""}`);
  if (flagged.length) {
    const why = flagged.join("; ");
    if (rt.blockedVersions === "refuse") {
      report.launch = "refused"; report.launch_reason = why; report.exit_code = 1;
      appendGuardLog({ kind: "launch_refused", session, server: a.server, pkg, semver, why });
      log(`✕ not launching ${a.server} (${pkg}${semver ? `@${semver}` : ""}): ${why}.${v?.skill.page ? ` https://killerskills.ai${v.skill.page}` : ""} Policy runtime.blocked_versions: refuse${source === "org" ? " (org)" : ""}.`);
      await flush(true);
      return 1;
    }
    report.launch = "warned"; report.launch_reason = why;
    log(`⚠ launching ${a.server} although ${why} (policy runtime.blocked_versions: warn)`);
  }
  // Short-lived credentials first: a policy exchange rule for a variable this server wants replaces the long-lived value
  // in our environment with a minted, scoped, minutes-long token; the broker then binds that. Failure falls back to the
  // long-lived value under the broker, and says so.
  const wants = new Set<string>([...(v?.credentials?.env.filter((e) => e.kind === "credential").map((e) => e.name) ?? []), ...(v?.trace_summary?.coverage?.needs ?? []).filter((n) => /^[A-Z][A-Z0-9_]+$/.test(n))]);
  const minted: Minted[] = [];
  for (const rule of rt.exchange) {
    const applies = wants.has(rule.var) || !!process.env[rule.var] || (rule.kind === "aws_sts" && (wants.has("AWS_ACCESS_KEY_ID") || !!process.env.AWS_ACCESS_KEY_ID));
    if (!applies) continue;
    try {
      const m = await mint(rule);
      for (const [k, val] of Object.entries(m.values)) process.env[k] = val;
      minted.push(m);
      const mins = Math.max(1, Math.round((m.expiresAt.getTime() - Date.now()) / 60_000));
      report.secrets.push({ name: rule.var, host: m.host, refused: false, exchange: { kind: m.kind, scope: m.scope, expires: m.expiresAt.toISOString() } });
      log(`exchanged ${rule.var} for a ${mins}-minute ${m.kind.replace("_", " ")} credential (${m.scope}); the long-lived value stays on this machine`);
    } catch (e) { log(`⚠ ${rule.var}: ${(e as Error).message}; falling back to the long-lived value under the broker`); }
  }
  // Secrets: the variables the verdict names as credentials, present in this environment, bound to the vendor's hosts.
  let secrets = a.secrets;
  if (minted.length) secrets = [secretsSpecFor(minted), a.secrets].filter(Boolean).join(",");
  if (!secrets && rt.secrets === "broker" && v?.credentials) {
    const own = v.credentials.hosts.filter((h) => h.own).map((h) => registrableDomain(h.host));
    const implied = (v.trace_summary?.egress_hosts ?? []).map((h) => h.implied).filter((x): x is string => !!x);
    const bind = own[0] ?? implied[0] ?? null;
    const names = v.credentials.env.filter((e) => e.kind === "credential" && process.env[e.name]).map((e) => e.name);
    if (names.length && bind) secrets = names.map((n) => `${n}=${bind}`).join(",");
    else if (names.length) log(`${names.join(", ")} present but no vendor host is on record for ${pkg}; passing through (pin with --secrets NAME=host)`);
  } else if (rt.secrets === "passthrough" && v?.credentials?.env.some((e) => e.kind === "credential" && process.env[e.name])) log(`runtime.secrets: passthrough — the server receives real credential values`);
  // Hosts: what the verdict saw or declared, plus what this machine has already seen this version contact.
  const base = readBaseline(); const prior = base[key]?.hosts ?? [];
  const declared = [...new Set([...(v?.version.declared_permissions.network ?? []), ...(v?.trace_summary?.egress_hosts ?? []).filter((h) => h.declared).map((h) => h.host), ...(v?.credentials?.hosts ?? []).filter((h) => h.own).map((h) => h.host)])];
  const known = [...new Set([...declared, ...prior])];
  const enforce = rt.network === "enforce" || rt.newHost === "block";
  const ownHosts = (v?.credentials?.hosts ?? []).filter((h) => h.own).map((h) => h.host);
  const opaque = readOpaque();
  const rules: ToolRule[] = rt.tools;
  const approver = org ? makeApprover({ server: a.server, pkg: report.pkg, semver, session, timeout: rt.approvalTimeoutSeconds, log }) : undefined;
  const sessionHosts = new Set<string>();
  let live: SecretBinding[] = [];
  const opts: RunOptions = {
    deny: [], net: known, observe: !enforce, label: a.server, query, secrets, opaque, ownHosts, toolRules: rules, defaultToolAction: rt.defaultToolAction, approver,
    onBindings: (b) => { live = b; },
    log,
    onEvent: (e: GuardEvent) => {
      appendGuardLog({ ...e, session, server: a.server, pkg: report.pkg, semver });
      if (e.kind === "host") { const first = !prior.includes(e.host); sessionHosts.add(e.host); report.hosts.push({ host: e.host, port: e.port, mode: e.mode, expected: e.expected, first_seen_here: first }); if (!e.expected && first && rt.newHost !== "allow" && base[key]?.sessions) log(`⚠ new host for ${pkg}${semver ? `@${semver}` : ""}: ${e.host} — never seen in ${base[key].sessions} earlier session${base[key].sessions === 1 ? "" : "s"} on this machine${v?.skill.page ? ` · https://killerskills.ai${v.skill.page}` : ""}`); }
      else if (e.kind === "tool_call") {
        const t = toolStats.get(e.tool) ?? { tool: e.tool, calls: 0, denied: 0, approved: 0 }; t.calls++; if (e.action === "denied" || e.action === "refused") t.denied++; if (e.action === "approved") t.approved++; toolStats.set(e.tool, t); report.tools = [...toolStats.values()];
        const now = new Date();
        const outcome = e.action === "allowed" ? "allow" : e.action === "approved" ? "held" : e.action === "held" ? "held" : "deny";
        if (e.action === "held") { /* the outcome row is written when the approval resolves (approved/denied event follows) */ }
        else if (outcome === "allow" && !fullCapture) {
          const minute = now.toISOString().slice(0, 16);
          const idx = decisions.findIndex((d) => d.outcome === "allow" && d.tool === e.tool && d.at.slice(0, 16) === minute);
          if (idx >= 0) { decisions[idx].count++; if (e.id !== undefined) byRpcId.set(String(e.id), idx); }
          else { decisions.push({ tool: e.tool, outcome: "allow", rule: e.rule ?? "default", at: now.toISOString(), count: 1, reply_observed: null, approval_id: null, disposition: null, arg_keys: e.args.slice(0, 20) }); if (e.id !== undefined) byRpcId.set(String(e.id), decisions.length - 1); }
        } else {
          decisions.push({ tool: e.tool, outcome, rule: e.action === "refused" ? "canary" : e.reason === "--deny" ? "--deny" : (e.rule ?? "default"), at: now.toISOString(), count: 1, reply_observed: e.action === "approved" ? false : null, approval_id: e.approvalId ?? null, disposition: e.action === "approved" ? "approved" : e.action === "denied" && e.approvalId ? "denied" : null, arg_keys: e.args.slice(0, 20) });
          if (e.id !== undefined && e.action !== "denied" && e.action !== "refused") byRpcId.set(String(e.id), decisions.length - 1);
        }
        report.decisions = decisions.slice(-2000);
      }
      else if (e.kind === "tool_reply") { const idx = byRpcId.get(String(e.id)); if (idx !== undefined && decisions[idx]) { decisions[idx].reply_observed = true; byRpcId.delete(String(e.id)); } }
      else if (e.kind === "secret") report.secrets.push({ name: e.name, host: e.host, refused: e.refused });
      else if (e.kind === "canary") report.canary = true;
      else if (e.kind === "poison") report.poison.push(`${e.tool}: ${e.summary}`);
      else if (e.kind === "pin_fallback") writeOpaque([...opaque, e.host]);
      else if (e.kind === "exit") report.exit_code = e.code;
    },
  };
  appendGuardLog({ kind: "start", session, server: a.server, client: a.client, pkg: report.pkg, semver, label: v?.verdict?.label ?? null, coverage: v?.trace_summary?.coverage?.level ?? null, enforce, secrets: secrets ? secrets.split(",").map((s) => s.split("=")[0]) : [] });
  log(`${a.server} → ${pkg}${semver ? `@${semver}` : ""}${v?.verdict ? ` · ${v.verdict.label} ${v.verdict.score}` : " · no verdict on record"}${v?.trace_summary?.coverage ? ` · ${v.trace_summary.coverage.level.replace("_", " ")}` : ""} · policy ${policy.name} (${source})`);
  const timer = setInterval(() => { flush(false).catch(() => null); }, 5 * 60_000); timer.unref();
  // Renewal: a minted credential nearing expiry in a long session is minted again and swapped into the live bindings;
  // the server keeps its placeholder and never notices.
  const renew = setInterval(async () => {
    for (let i = 0; i < minted.length; i++) {
      const m = minted[i];
      if (m.expiresAt.getTime() - Date.now() > 3 * 60_000) continue;
      const rule = rt.exchange.find((r) => Object.keys(m.values).includes(r.var) || (r.kind === "aws_sts" && m.kind === "aws_sts"));
      if (!rule) continue;
      try {
        const fresh = await mint(rule);
        for (const [k, val] of Object.entries(fresh.values)) { const b = live.find((x) => x.name === k); if (b) b.value = val; }
        await m.revoke?.().catch(() => null);
        minted[i] = fresh;
        log(`renewed ${rule.var} (${fresh.kind.replace("_", " ")}, expires ${fresh.expiresAt.toISOString().slice(11, 16)} UTC)`);
      } catch (e) { log(`⚠ could not renew ${rule.var}: ${(e as Error).message}; the current token expires ${m.expiresAt.toISOString().slice(11, 16)} UTC`); }
    }
  }, 60_000); renew.unref();
  const code = await guard(parsed.cmd, opts);
  clearInterval(timer); clearInterval(renew);
  for (const m of minted) { await m.revoke?.().catch(() => null); if (m.revoke) log(`revoked the ${m.kind.replace("_", " ")} credential minted for this session`); }
  // Baseline: the hosts this version reached on this machine, so the next session knows what is new.
  const b = readBaseline(); const cur = b[key] ?? { hosts: [], sessions: 0, last: started };
  cur.hosts = [...new Set([...cur.hosts, ...sessionHosts])].slice(0, 200); cur.sessions += 1; cur.last = new Date().toISOString(); b[key] = cur; writeBaseline(b);
  await flush(true);
  return code;
}

/** Enrolled machines: a held tool call becomes an approval request the org decides (dashboard or Slack); the guard polls. */
function makeApprover(ctx: { server: string; pkg: string | null; semver: string | null; session: string; timeout: number; log: (l: string) => void }): RunOptions["approver"] {
  return async ({ tool, args, rule }) => {
    const preview = Object.entries(args).slice(0, 8).map(([k, val]) => `${k}=${typeof val === "string" ? JSON.stringify(val.slice(0, 60)) : Array.isArray(val) ? `[${val.length}]` : typeof val}`).join(" ");
    const c = await approvalCreate({ server: ctx.server, pkg: ctx.pkg, semver: ctx.semver, tool, arg_keys: Object.keys(args), arg_preview: preview.slice(0, 400), reason: rule?.reason ?? null, session: ctx.session, timeout_seconds: ctx.timeout });
    if (!c.ok) return { allowed: false, by: `approval request failed (${c.error}); denied` };
    const approvalId = c.data.id;
    ctx.log(`approval requested for ${tool}: ${c.data.url}`);
    const deadline = Date.now() + ctx.timeout * 1000;
    let wait = 2000;
    while (Date.now() < deadline) {
      await new Promise((res) => setTimeout(res, wait)); wait = Math.min(10_000, wait * 1.5);
      const p = await approvalPoll(c.data.id);
      if (!p.ok) continue;
      if (p.data.status === "approved") return { allowed: true, by: p.data.by ?? "approver", id: approvalId };
      if (p.data.status === "denied") return { allowed: false, by: p.data.by ? `denied by ${p.data.by}` : "denied", id: approvalId };
      if (p.data.status === "expired") break;
    }
    return { allowed: false, by: `no decision within ${ctx.timeout}s`, id: approvalId };
  };
}

/** `guard status`: wrapped servers and the last seven days of sessions. */
export function guardStatus(opts: { project?: string | null; home?: string } = {}): string[] {
  const lines: string[] = [];
  const w = wrappedServers(opts);
  const reg = readWrapped();
  lines.push(w.length ? `${w.length} MCP server${w.length === 1 ? "" : "s"} under the guard${reg.installedAt ? ` since ${reg.installedAt.slice(0, 10)}` : ""}:` : "No MCP server is under the guard. Run: vet-skills guard install");
  for (const s of w) lines.push(`  ${s.name.padEnd(28)} ${s.client.padEnd(14)} ${s.command}`);
  const log = readGuardLog(7);
  const sessions = log.filter((e) => e.kind === "start");
  const hosts = log.filter((e) => e.kind === "host");
  const newHosts = hosts.filter((e) => e.expected === false);
  const denied = log.filter((e) => e.kind === "tool_call" && (e.action === "denied" || e.action === "refused"));
  const held = log.filter((e) => e.kind === "tool_call" && e.action === "approved");
  const refusedSecrets = log.filter((e) => e.kind === "secret" && e.refused === true);
  const refusedLaunch = log.filter((e) => e.kind === "launch_refused");
  lines.push("", `Last 7 days: ${sessions.length} session${sessions.length === 1 ? "" : "s"} · ${new Set(hosts.map((h) => h.host)).size} distinct hosts · ${newHosts.length} contact${newHosts.length === 1 ? "" : "s"} to hosts nothing on record named · ${denied.length} tool call${denied.length === 1 ? "" : "s"} denied · ${held.length} approved · ${refusedSecrets.length} placeholder${refusedSecrets.length === 1 ? "" : "s"} refused · ${refusedLaunch.length} launch${refusedLaunch.length === 1 ? "" : "es"} refused`);
  const byHost = new Map<string, Set<string>>();
  for (const h of newHosts) { const k = `${h.pkg ?? h.server}${h.semver ? `@${h.semver}` : ""}`; const set = byHost.get(k) ?? new Set<string>(); set.add(String(h.host)); byHost.set(k, set); }
  for (const [k, set] of byHost) lines.push(`  ${k}: ${[...set].slice(0, 6).join(", ")}${set.size > 6 ? ` +${set.size - 6}` : ""}`);
  for (const l of refusedLaunch.slice(-5)) lines.push(`  ✕ ${l.server}: ${l.why}`);
  for (const s of refusedSecrets.slice(-5)) lines.push(`  ✕ ${s.server}: ${s.name} placeholder sent to ${s.host}`);
  return lines;
}
