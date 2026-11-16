/**
 * `vet-skills secrets migrate | list | set | rm` and `vet-skills prove`.
 *
 * migrate: finds credentials written into agent configs (the ones `inventory` reports by name) and moves each into the
 * guard's store, leaving a `vs-store://` reference; puts the servers that use them under the guard so the reference is
 * resolved at launch; shows the plan and asks once before writing; keeps a backup of each config with the values
 * replaced by their references. A value is never printed.
 *
 * prove: a read-only check that no credential for an MCP server sits in an agent config, in the environment of a running
 * agent process, or in the guard's own files. It reports what it checked and what it could not, and lists exactly where
 * a value still lives. It checks those places; it is not a statement about the rest of the machine.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { platform } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { isLiteralCredential } from "./policy/index.js";
import { backup, configSpecs, installGuard, isCredentialHeader, isObj, isWrapped, isWrappedRemote, parseRemoteArgs, readJsonc, serverMaps, type ConfigSpec, type Json, type ServerEntry } from "./guard.js";
import { SecretStore, isStoreRef, keyOfRef, refFor } from "./store.js";
import { HOME } from "./state.js";

export interface Candidate { file: string; client: string; server: string; name: string; /** env: a value in the entry's env map. header: a remote entry's header (moved when the server is bridged). environment: a ${NAME} reference whose value is in this shell. */ from: "env" | "header" | "environment"; key: string }
export interface MigratePlan { candidates: Candidate[]; manual: { file: string; server: string; name: string; why: string }[]; toGuard: number }
type Opts = { home?: string; project?: string | null; env?: NodeJS.ProcessEnv; store?: SecretStore };

const envMapOf = (e: ServerEntry): Record<string, unknown> | null => (isObj(e.env) ? (e.env as Json) : isObj(e.environment) ? (e.environment as Json) : null);
const envRefName = (v: unknown): string | null => (typeof v === "string" ? (v.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/)?.[1] ?? v.match(/^\$([A-Za-z_][A-Za-z0-9_]*)$/)?.[1] ?? v.match(/^env:([A-Za-z_][A-Za-z0-9_]*)$/)?.[1] ?? null) : null);
const CRED_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTH)/i;
/** A remote entry's header that carries a credential as a literal (not a ${VAR} template, not a store reference). */
const literalHeader = (name: string, val: unknown) => typeof val === "string" && isCredentialHeader(name) && !val.startsWith("vs-store://") && !/\$\{|^(Bearer\s+)?\$[A-Za-z_]|^env:/.test(val) && val.trim().length >= 8;
const guardable = (e: ServerEntry) => isWrapped(e) || (typeof e.command === "string" && !!e.command && !e.url) || (Array.isArray(e.command) && (e.command as unknown[]).length > 0);

/** Codex and Grok CLI keep env in TOML: `env = { KEY = "v" }` on the server's table, or a `[mcp_servers.NAME.env]` table. `decide` returns the replacement for a value, or null to leave it. */
export function rewriteTomlEnv(text: string, decide: (server: string, name: string, value: string) => string | null): string {
  const lines = text.split("\n"); let server: string | null = null; let inEnv = false;
  const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  const unq = (s: string) => s.replace(/\\(["\\])/g, "$1");
  for (let i = 0; i < lines.length; i++) {
    const h = lines[i].match(/^\s*\[mcp_servers\.("?)([^\]."]+)\1(\.env)?\]\s*$/);
    if (h) { server = h[2]; inEnv = !!h[3]; continue; }
    if (/^\s*\[/.test(lines[i])) { server = null; inEnv = false; continue; }
    if (server === null) continue;
    const srv = server;
    if (inEnv) lines[i] = lines[i].replace(/^(\s*"?([\w.-]+)"?\s*=\s*)"((?:\\.|[^"\\])*)"/, (m, pre: string, name: string, val: string) => { const r = decide(srv, name, unq(val)); return r === null ? m : `${pre}${q(r)}`; });
    else if (/^\s*env\s*=\s*\{/.test(lines[i])) lines[i] = lines[i].replace(/("?([\w.-]+)"?\s*=\s*)"((?:\\.|[^"\\])*)"/g, (m, pre: string, name: string, val: string) => { const r = decide(srv, name, unq(val)); return r === null ? m : `${pre}${q(r)}`; });
  }
  return lines.join("\n");
}

function keyFor(store: SecretStore, spec: ConfigSpec, server: string, name: string, value: string | null): string {
  const key = `${spec.client}/${server}/${name}`.replace(/[^\w.@/:~#-]/g, "_");
  const prev = store.get(key);
  return prev !== null && value !== null && prev !== value ? `${key}#${createHash("sha1").update(spec.path).digest("hex").slice(0, 6)}` : key;
}

/** Walk every config once. With `apply`, values are stored (and read back) and the config rewritten; without, nothing is written. */
function walk(opts: Opts, apply: boolean): MigratePlan & { written: string[]; failed: { name: string; why: string }[] } {
  const store = opts.store ?? new SecretStore(); const env = opts.env ?? process.env;
  const plan: MigratePlan & { written: string[]; failed: { name: string; why: string }[] } = { candidates: [], manual: [], toGuard: 0, written: [], failed: [] };
  for (const spec of configSpecs(opts)) {
    let text: string; try { text = readFileSync(spec.path, "utf8"); } catch { continue; }
    const moved: { key: string; value: string }[] = [];
    // One decision per (server, name, value): store it when applying, and return what the config should hold instead.
    const take = (server: string, name: string, value: string, from: Candidate["from"]): string | null => {
      const key = keyFor(store, spec, server, name, value);
      plan.candidates.push({ file: spec.path, client: spec.client, server, name, from, key });
      if (!apply) return null;
      const r = store.set(key, value);
      if (!r.ok) { plan.failed.push({ name: `${server}/${name}`, why: r.error }); return null; }
      moved.push({ key, value });
      return refFor(key);
    };
    if (spec.format === "codex-toml") {
      const next = rewriteTomlEnv(text, (server, name, value) => {
        if (isLiteralCredential(name, value)) return take(server, name, value, "env");
        const ref = envRefName(value); if (ref && CRED_NAME.test(ref) && env[ref]) return take(server, name, env[ref]!, "environment");
        return null;
      });
      if (apply && next !== text) { backup(spec.path, text, moved); writeFileSync(spec.path, next); plan.written.push(spec.path); }
      continue;
    }
    const root = readJsonc(text); if (!isObj(root)) continue;
    let changed = false;
    for (const { map } of serverMaps(spec, root)) for (const [server, v] of Object.entries(map)) {
      if (!isObj(v)) continue; const e = v as ServerEntry;
      if (isWrappedRemote(e)) continue;
      const em = envMapOf(e);
      if (em) for (const [name, val] of Object.entries(em)) {
        if (typeof val !== "string" || isStoreRef(val)) continue;
        const literal = isLiteralCredential(name, val); const ref = literal ? null : envRefName(val);
        const fromEnv = ref && CRED_NAME.test(ref) && env[ref] ? env[ref]! : null;
        if (!literal && !fromEnv) continue;
        if (!guardable(e)) { plan.manual.push({ file: spec.path, server, name, why: "this entry has a shape the guard cannot wrap, so a reference would not be resolved" }); continue; }
        const r = take(server, name, literal ? val : fromEnv!, literal ? "env" : "environment");
        if (r) { em[name] = r; changed = true; }
      }
      // A remote entry's credential headers move when `guard install` bridges it (below); listed here so the plan is complete.
      if (!e.command && isObj(e.headers)) for (const [name, val] of Object.entries(e.headers)) if (literalHeader(name, val)) plan.candidates.push({ file: spec.path, client: spec.client, server, name, from: "header", key: `${spec.client}/${server}/${name}` });
      // Credentials passed as arguments cannot be moved without changing how the server is started.
      const argv = Array.isArray(e.command) ? (e.command as unknown[]) : Array.isArray(e.args) ? e.args : [];
      for (const a of argv) if (typeof a === "string" && isLiteralCredential("", a.replace(/^--?[\w-]+=/, ""))) plan.manual.push({ file: spec.path, server, name: "(an argument)", why: "a token is passed as a command-line argument; move it to an env variable, then run this again" });
    }
    if (apply && changed) { backup(spec.path, text, moved); writeFileSync(spec.path, JSON.stringify(root, null, 2) + "\n"); plan.written.push(spec.path); }
  }
  plan.toGuard = installGuard({ home: opts.home, project: opts.project, dryRun: true }).reduce((n, t) => n + t.wrapped.length, 0);
  return plan;
}

export const planMigration = (opts: Opts = {}): MigratePlan => { const { candidates, manual, toGuard } = walk(opts, false); return { candidates, manual, toGuard }; };

/** Apply: env values first (stored, read back, replaced by references), then `guard install`, which wraps the servers and bridges remotes, moving their header values. Old guard backups are scrubbed of every stored value. */
export function applyMigration(opts: Opts = {}): { moved: number; guarded: number; failed: { name: string; why: string }[]; files: string[]; scrubbed: number } {
  const store = opts.store ?? new SecretStore();
  const r = walk({ ...opts, store }, true);
  const touched = installGuard({ home: opts.home, project: opts.project });
  const headerMoves = touched.reduce((n, t) => n + (t.moved?.length ?? 0), 0);
  return { moved: r.candidates.filter((c) => c.from !== "header").length - r.failed.length + headerMoves, guarded: touched.reduce((n, t) => n + t.wrapped.length, 0), failed: r.failed, files: [...new Set([...r.written, ...touched.filter((t) => t.wrapped.length).map((t) => t.file)])], scrubbed: scrubGuardFiles(store) };
}

const GUARD_FILES_SKIP = /(^|[\\/])(secrets\.json|store\.key)$/;
function guardFiles(): string[] {
  const out: string[] = [];
  const rec = (dir: string, depth: number) => {
    let names: string[]; try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      const p = join(dir, n); let st; try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) { if (depth < 4 && n !== "node_modules") rec(p, depth + 1); }
      else if (st.isFile() && st.size < 20_000_000 && !GUARD_FILES_SKIP.test(p)) out.push(p);
    }
  };
  rec(HOME, 0);
  return out;
}
/** Replace every stored value found in the guard's own files (old config backups, logs) with its reference. Returns the number of files changed. */
export function scrubGuardFiles(store = new SecretStore()): number {
  const vals = store.values(); if (!vals.length) return 0;
  let n = 0;
  for (const f of guardFiles()) {
    let text: string; try { text = readFileSync(f, "utf8"); } catch { continue; }
    let next = text;
    for (const v of vals) { next = next.split(v.value).join(refFor(v.key)); const esc = JSON.stringify(v.value).slice(1, -1); if (esc !== v.value) next = next.split(esc).join(refFor(v.key)); }
    if (next !== text) { try { writeFileSync(f, next); n++; } catch { /* read-only: prove will say so */ } }
  }
  return n;
}

/* ------------------------------------------------------------------ prove */

export interface Finding { where: "config" | "process" | "guard files"; location: string; server?: string; name: string; detail: string; fix: string }
export interface Proof { pass: boolean; checked: { configs: number; servers: number; processes: number; guard_files: number; stored: number }; not_checked: string[]; findings: Finding[] }

/** An agent process: a desktop app bundle (macOS reports the full path, and VS Code's binary is called Electron), or a CLI by its binary name. */
export const isAgentProcess = (comm: string) => /(Claude|Cursor|Windsurf|Visual Studio Code|Code - Insiders|Zed|Kiro)\.app\//.test(comm) || /^(claude|cursor|codex|gemini|windsurf|code|zed|kiro|qwen|grok|copilot|amp|opencode)(\.exe)?$/i.test(comm.split(/[\\/]/).pop()!.trim());
/** Running agent processes of this user, with their environment where the OS lets the same user read it. */
function agentProcesses(): { ok: boolean; why?: string; procs: { pid: number; name: string; env: string }[] } {
  const os = platform();
  if (os === "win32") return { ok: false, why: "running agent processes (reading another process's environment is not supported on Windows)", procs: [] };
  const ps = spawnSync("ps", ["-eo", "pid=,uid=,comm="], { encoding: "utf8", timeout: 5000 });
  if (ps.status !== 0) return { ok: false, why: "running agent processes (ps did not run)", procs: [] };
  const uid = typeof process.getuid === "function" ? process.getuid() : -1;
  const procs: { pid: number; name: string; env: string }[] = []; let unreadable = 0;
  for (const line of ps.stdout.split("\n")) {
    const m = line.trim().match(/^(\d+)\s+(\d+)\s+(.+)$/); if (!m) continue;
    const pid = Number(m[1]); if (Number(m[2]) !== uid || pid === process.pid || pid === process.ppid) continue;
    const comm = m[3]; if (!isAgentProcess(comm) || /vet-skills/.test(comm)) continue;
    let env = "";
    if (os === "linux") { try { env = readFileSync(`/proc/${pid}/environ`, "utf8").split("\0").join("\n"); } catch { unreadable++; continue; } }
    else { const r = spawnSync("ps", ["eww", "-o", "command=", "-p", String(pid)], { encoding: "utf8", timeout: 5000 }); if (r.status !== 0 || !/ (PATH|HOME|USER)=/.test(r.stdout)) { unreadable++; continue; } env = r.stdout.replace(/ (?=[A-Za-z_][A-Za-z0-9_]*=)/g, "\n"); }
    procs.push({ pid, name: (comm.match(/([^/]+)\.app\//)?.[1] ?? comm.split(/[\\/]/).pop()!).slice(0, 40), env });
  }
  return { ok: true, why: unreadable ? `${unreadable} agent process${unreadable === 1 ? "" : "es"} whose environment the OS would not show` : undefined, procs };
}

export function prove(opts: Opts & { processes?: { pid: number; name: string; env: string }[] } = {}): Proof {
  const store = opts.store ?? new SecretStore();
  const findings: Finding[] = []; const not: string[] = [];
  const stored = store.values();
  const wanted = new Map<string, string>(); // credential names guarded servers are passed → the server that names them
  let configs = 0, servers = 0;
  for (const spec of configSpecs(opts)) {
    let text: string; try { text = readFileSync(spec.path, "utf8"); } catch { continue; }
    configs++;
    for (const v of stored) if (text.includes(v.value)) findings.push({ where: "config", location: spec.path, name: v.key.split("/").pop()!, detail: `the value the guard holds as ${v.key} is also written in this file`, fix: "run `vet-skills secrets migrate`" });
    if (spec.format === "codex-toml") {
      rewriteTomlEnv(text, (server, name, value) => { if (isLiteralCredential(name, value)) findings.push({ where: "config", location: spec.path, server, name, detail: "credential value written in the config", fix: "run `vet-skills secrets migrate`" }); else if (isStoreRef(value)) { wanted.set(name, server); if (!store.has(keyOfRef(value))) findings.push({ where: "config", location: spec.path, server, name, detail: `references ${keyOfRef(value)}, which is not in the guard's store; the server will start without it`, fix: `run \`vet-skills secrets set ${keyOfRef(value)}\`` }); } else if (envRefName(value)) wanted.set(envRefName(value)!, server); return null; });
      servers += (text.match(/^\s*\[mcp_servers\.[^\].]+\]\s*$/gm) ?? []).length;
      continue;
    }
    const root = readJsonc(text); if (!isObj(root)) { not.push(`${spec.path} (could not be parsed)`); continue; }
    for (const { map } of serverMaps(spec, root)) for (const [server, v] of Object.entries(map)) {
      if (!isObj(v)) continue; const e = v as ServerEntry; servers++;
      const em = envMapOf(e) ?? {};
      for (const [name, val] of Object.entries(em)) {
        if (isLiteralCredential(name, val)) findings.push({ where: "config", location: spec.path, server, name, detail: "credential value written in the config", fix: "run `vet-skills secrets migrate`" });
        else if (isStoreRef(val)) { wanted.set(name, server); if (!store.has(keyOfRef(val))) findings.push({ where: "config", location: spec.path, server, name, detail: `references ${keyOfRef(val)}, which is not in the guard's store; the server will start without it`, fix: `run \`vet-skills secrets set ${keyOfRef(val)}\`` }); else if (!isWrapped(e)) findings.push({ where: "config", location: spec.path, server, name, detail: "references the guard's store but the server is not under the guard, so it receives the reference instead of the value", fix: "run `vet-skills guard install`" }); }
        else if (envRefName(val) && CRED_NAME.test(name)) wanted.set(envRefName(val)!, server);
      }
      if (!e.command && isObj(e.headers)) for (const [name, val] of Object.entries(e.headers)) if (literalHeader(name, val)) findings.push({ where: "config", location: spec.path, server, name, detail: "credential header written in the config", fix: "run `vet-skills secrets migrate`" });
      if (isWrappedRemote(e)) { const cmd = Array.isArray(e.command) ? (e.command as string[]) : [String(e.command), ...(e.args ?? [])]; const p = parseRemoteArgs(cmd.slice(cmd.indexOf("remote") + 1)); if (!("error" in p)) for (const h of p.headers) { if (isStoreRef(h.value) && !store.has(keyOfRef(h.value))) findings.push({ where: "config", location: spec.path, server, name: h.name, detail: `references ${keyOfRef(h.value)}, which is not in the guard's store`, fix: `run \`vet-skills secrets set ${keyOfRef(h.value)}\`` }); const ref = envRefName(h.value.replace(/^(Bearer|Basic|token)\s+/i, "")); if (ref) wanted.set(ref, server); } }
      const argv = Array.isArray(e.command) ? (e.command as unknown[]) : Array.isArray(e.args) ? e.args : [];
      for (const a of argv) if (typeof a === "string" && isLiteralCredential("", a.replace(/^--?[\w-]+=/, ""))) findings.push({ where: "config", location: spec.path, server, name: "(an argument)", detail: "a token is passed as a command-line argument", fix: "move it to an env variable in the config, then run `vet-skills secrets migrate`" });
    }
  }
  // Running agents: a value the guard holds, or a credential a guarded server is passed by name, sitting in the agent's own environment.
  let procs = opts.processes; let processes = 0;
  if (!procs) { const ap = agentProcesses(); if (!ap.ok) not.push(ap.why!); else { procs = ap.procs; if (ap.why) not.push(ap.why); } }
  for (const p of procs ?? []) {
    processes++;
    for (const v of stored) if (p.env.includes(v.value)) findings.push({ where: "process", location: `${p.name} (pid ${p.pid})`, name: v.key.split("/").pop()!, detail: `the value the guard holds as ${v.key} is in this process's environment`, fix: "remove the export from your shell profile and restart the agent" });
    for (const [name, server] of wanted) { const m = p.env.match(new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=(.+)$`, "m")); const cur = m ? m[1].trim() : ""; if (cur.length >= 8 && !cur.startsWith("vs-store://") && !stored.some((v) => v.value === cur)) findings.push({ where: "process", location: `${p.name} (pid ${p.pid})`, server, name, detail: `${name}, which ${server} is passed, is set in this process's environment`, fix: "run `vet-skills secrets migrate` from a shell where it is set, remove the export from your shell profile, restart the agent" }); }
  }
  // The guard's own files: logs, pins, old config backups.
  const files = guardFiles();
  for (const f of files) {
    let text: string; try { text = readFileSync(f, "utf8"); } catch { continue; }
    for (const v of stored) if (text.includes(v.value)) findings.push({ where: "guard files", location: f, name: v.key.split("/").pop()!, detail: `holds the value stored as ${v.key}`, fix: "run `vet-skills secrets migrate` (it scrubs the guard's backups and logs)" });
    if (/\.bak$/.test(f)) { const root = readJsonc(text); const seen = new Set<string>(); const scan = (o: unknown, depth: number) => { if (!isObj(o) || depth > 8) return; for (const [k, v] of Object.entries(o)) { if ((k === "env" || k === "environment" || k === "headers") && isObj(v)) { for (const [n, val] of Object.entries(v)) if (isLiteralCredential(k === "headers" ? n.replace(/-/g, "_") : n, val) && !seen.has(n)) { seen.add(n); findings.push({ where: "guard files", location: f, name: n, detail: "an old config backup with a credential value in it", fix: "delete this backup file once the config it came from works" }); } } else scan(v, depth + 1); } }; scan(root, 0); }
  }
  if (!existsSync(join(HOME, "guard"))) not.push("the guard's files (the guard has not been installed on this machine)");
  not.push("credentials read from files by a server (~/.aws, ~/.config/gh and similar)", "your shell profile and other files outside agent configs", "servers that sign in with OAuth (the agent holds that session)");
  const dedup = [...new Map(findings.map((f) => [`${f.where}|${f.location}|${f.server ?? ""}|${f.name}|${f.detail}`, f])).values()];
  return { pass: dedup.length === 0, checked: { configs, servers, processes, guard_files: files.length, stored: stored.length }, not_checked: not, findings: dedup };
}

/* ------------------------------------------------------------------ cli */

const ask = (q: string) => new Promise<string>((res) => { const rl = createInterface({ input: process.stdin, output: process.stderr }); rl.question(q, (a) => { rl.close(); res(a.trim()); }); });
function readSecret(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) return new Promise((res) => { let b = ""; process.stdin.on("data", (d) => (b += d)); process.stdin.on("end", () => res(b.replace(/\r?\n$/, ""))); });
  return new Promise((res) => {
    process.stderr.write(prompt); const stdin = process.stdin; stdin.setRawMode(true); stdin.resume(); let b = "";
    const on = (d: Buffer) => { for (const ch of d.toString()) { if (ch === "\r" || ch === "\n" || ch === "\u0004") { stdin.setRawMode(false); stdin.pause(); stdin.off("data", on); process.stderr.write("\n"); res(b); return; } if (ch === "\u0003") { stdin.setRawMode(false); process.exit(130); } if (ch === "\u007f") b = b.slice(0, -1); else b += ch; } };
    stdin.on("data", on);
  });
}
const short = (p: string) => p.replace(process.env.HOME ?? "\0", "~");

export async function secretsCmd(argv: string[], flags: { yes?: boolean; json?: boolean; project?: boolean; dryRun?: boolean }): Promise<number> {
  const sub = argv[0]; const store = new SecretStore(); const project = flags.project ? process.cwd() : null;
  if (sub === "list" || sub === undefined) {
    const rows = store.list();
    if (flags.json) { console.log(JSON.stringify(rows, null, 2)); return 0; }
    if (!rows.length) { console.log("The guard's store is empty. `vet-skills secrets migrate` moves credentials written in agent configs into it."); return 0; }
    for (const r of rows) console.log(`  ${r.key.padEnd(48)} ${r.backend.padEnd(15)} ${r.at.slice(0, 10)}`);
    console.log(`\n${rows.length} credential${rows.length === 1 ? "" : "s"} held. Names only: a value is never printed.`);
    return 0;
  }
  if (sub === "set") {
    if (!argv[1]) { console.error("usage: vet-skills secrets set <key>   (the value is read from stdin, or typed without echo)"); return 2; }
    const v = await readSecret(`Value for ${argv[1]} (not shown): `);
    const r = store.set(argv[1], v);
    console.log(r.ok ? `✓ stored ${argv[1]} (${r.backend}). Reference it in a config as ${refFor(argv[1])}` : `✕ ${r.error}`);
    return r.ok ? 0 : 1;
  }
  if (sub === "rm") { if (!argv[1]) { console.error("usage: vet-skills secrets rm <key>"); return 2; } const ok = store.delete(argv[1]); console.log(ok ? `✓ removed ${argv[1]}` : `✕ ${argv[1]} is not in the store`); return ok ? 0 : 1; }
  if (sub === "migrate") {
    const plan = planMigration({ project, store });
    if (flags.json && flags.dryRun) { console.log(JSON.stringify(plan, null, 2)); return 0; }
    if (!plan.candidates.length && !plan.manual.length) { console.log("✓ No credential value is written in an agent config on this machine. `vet-skills prove` checks the rest."); return 0; }
    if (plan.candidates.length) {
      console.log(`${plan.candidates.length} credential${plan.candidates.length === 1 ? "" : "s"} to move into the guard's store (${store.preferred()}):\n`);
      for (const c of plan.candidates) console.log(`  ${`${c.server} · ${c.name}`.padEnd(44)} ${c.from === "environment" ? "from this shell's environment" : c.from === "header" ? "header in" : "written in"} ${short(c.file)}\n  ${"".padEnd(44)} → ${refFor(c.key)}`);
      console.log(`\nEach config keeps a reference in place of the value; a backup is kept with the values removed.${plan.toGuard ? ` ${plan.toGuard} server${plan.toGuard === 1 ? "" : "s"} will be put under the guard so the references are resolved at launch.` : ""} \`vet-skills guard uninstall\` puts values and commands back.`);
    }
    for (const m of plan.manual) console.log(`  by hand: ${m.server} · ${m.name} in ${short(m.file)}: ${m.why}`);
    if (flags.dryRun || !plan.candidates.length) return plan.manual.length ? 1 : 0;
    if (!flags.yes) { if (!process.stdin.isTTY) { console.error("\nNot a terminal: re-run with --yes to apply."); return 2; } const a = await ask("\nMove them? [y/N] "); if (!/^y(es)?$/i.test(a)) { console.log("Nothing was changed."); return 0; } }
    const r = applyMigration({ project, store });
    for (const f of r.failed) console.log(`✕ ${f.name}: ${f.why}; left as it was`);
    console.log(`\n✓ ${r.moved} credential${r.moved === 1 ? "" : "s"} moved, ${r.guarded} server${r.guarded === 1 ? "" : "s"} put under the guard${r.scrubbed ? `, ${r.scrubbed} guard file${r.scrubbed === 1 ? "" : "s"} scrubbed` : ""}. Restart the agents, then run \`vet-skills prove\`.`);
    if (plan.candidates.some((c) => c.from === "environment")) console.log("Credentials taken from this shell's environment are still exported there: remove them from your shell profile, or `prove` will find them in the agent's environment.");
    return r.failed.length ? 1 : 0;
  }
  console.error("usage: vet-skills secrets migrate [--dry-run] [--yes] [--project] | list | set <key> | rm <key>"); return 2;
}

export function proveCmd(flags: { json?: boolean; project?: boolean }): number {
  const p = prove({ project: flags.project ? process.cwd() : null });
  if (flags.json) { console.log(JSON.stringify(p, null, 2)); return p.pass ? 0 : 1; }
  const c = p.checked;
  const scope = `${c.configs} agent config${c.configs === 1 ? "" : "s"} (${c.servers} server${c.servers === 1 ? "" : "s"}), ${c.processes} running agent process${c.processes === 1 ? "" : "es"}, ${c.guard_files} of the guard's own files`;
  if (p.pass) console.log(`PASS  No credential for an MCP server was found in ${scope}.${c.stored ? ` The guard holds ${c.stored}.` : ""}`);
  else {
    console.log(`FAIL  ${p.findings.length} place${p.findings.length === 1 ? "" : "s"} where a credential still lives (checked ${scope}):\n`);
    for (const f of p.findings) console.log(`  ${f.where.padEnd(12)} ${short(f.location)}${f.server ? ` · ${f.server}` : ""} · ${f.name}\n  ${"".padEnd(12)} ${f.detail}\n  ${"".padEnd(12)} → ${f.fix}`);
  }
  console.log(`\nNot checked: ${p.not_checked.join("; ")}.`);
  console.log("This is a check of those places on this machine, read-only. A process running as you can still ask the store for a value; see the docs for what the store does and does not protect.");
  return p.pass ? 0 : 1;
}
