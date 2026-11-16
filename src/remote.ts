/**
 * `vet-skills guard remote --server <name> --client <agent> --url <https://…> [--sse] [--header NAME=VALUE]…`
 *
 * The guard in front of a remote MCP server. `guard install` rewrites a remote entry that carries a credential header
 * into this command, so the agent starts a local process and talks stdio to it; this process speaks Streamable HTTP
 * (or the older HTTP+SSE) to the server and adds the header itself. The agent's config and process hold the header's
 * name and a `vs-store://` reference; the value is read from the guard's store here and sent to the configured origin
 * only (a redirect to another origin is refused).
 *
 * Everything the stdio guard does to tool calls applies unchanged (relay.ts): deny rules, holds for approval, the
 * record of each call by tool and argument names. On top of that:
 *   - the server's tool list is compared with the one last seen here; new tools and rewritten descriptors follow policy
 *     runtime.on_change: allow, warn (default) or hold (those tools are refused until someone approves the change);
 *   - the launch check is asked at start and every minute, keyed by the server's host, so an org can revoke a remote
 *     server; runtime.revoke_running decides whether a live session is told or stopped.
 *
 * Not wrapped: servers that sign the user in with OAuth or a browser (the agent does that itself, and the guard is not
 * in that path), and entries with the credential in the URL.
 */
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { approvalCreate, approvalPoll, guardReport, launchCheck, type GuardSessionReport } from "./api.js";
import { appendGuardLog, decisionRecorder, makeApprover, parseRemoteArgs, type RemoteSpec } from "./guard.js";
import { createRelay, type RelayEvent } from "./relay.js";
import { SecretStore, isStoreRef, keyOfRef } from "./store.js";
import { HOME, VERSION, clientId, readOrg, readPolicy, telemetryEnabled } from "./state.js";

const REMOTE = join(HOME, "guard", "remote.json");
export interface RemoteBaseline { [server: string]: { url: string; tools: Record<string, string>; version: string | null; at: string; acceptNext?: boolean; pending?: { id: string; hash: string } } }
export function readRemoteBaseline(): RemoteBaseline { try { return JSON.parse(readFileSync(REMOTE, "utf8")) as RemoteBaseline; } catch { return {}; } }
function writeRemoteBaseline(b: RemoteBaseline) { try { mkdirSync(join(HOME, "guard"), { recursive: true, mode: 0o700 }); writeFileSync(REMOTE, JSON.stringify(b, null, 2)); } catch { /* best effort */ } }
/** `vet-skills guard approve <server>` for a remote server: its next tool list becomes the baseline. */
export function approveRemote(server: string): { ok: boolean; message: string } {
  const b = readRemoteBaseline(); const key = Object.keys(b).find((k) => k === server || k.endsWith(`/${server}`));
  if (!key) return { ok: false, message: "" };
  b[key].acceptNext = true; delete b[key].pending; writeRemoteBaseline(b);
  return { ok: true, message: `The tools ${server} lists next will be accepted and become the new baseline. Held tools work again from the next call.` };
}

/** The same 16-hex descriptor hash the sandbox records: a tool's description and input schema. */
export const descriptorHash = (t: { description?: string; inputSchema?: unknown }) => createHash("sha256").update(`${t.description ?? ""}\n${JSON.stringify(t.inputSchema ?? {})}`).digest("hex").slice(0, 16);

/** `${VAR}`, `$VAR` and `env:VAR` in a header template, from the environment the agent started us with. */
export function expandEnv(template: string, env: NodeJS.ProcessEnv): { value: string; missing: string[] } {
  const missing: string[] = [];
  const get = (n: string) => { const v = env[n]; if (v === undefined || v === "") { missing.push(n); return ""; } return v; };
  if (/^env:/.test(template)) return { value: get(template.slice(4)), missing };
  const value = template.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}/g, (_m, n: string) => get(n)).replace(/\$([A-Z_][A-Z0-9_]*)/g, (_m, n: string) => get(n));
  return { value, missing };
}

/** Server-sent events → one callback per event. */
export function sseParser(onEvent: (event: string, data: string) => void) {
  let buf = "";
  return (chunk: string) => {
    buf += chunk.replace(/\r\n/g, "\n");
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i); buf = buf.slice(i + 2);
      let event = "message"; const data: string[] = [];
      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
      }
      if (data.length) onEvent(event, data.join("\n"));
    }
  };
}

async function pump(body: ReadableStream<Uint8Array> | null, onChunk: (s: string) => void, signal: AbortSignal) {
  if (!body) return;
  const reader = body.getReader(); const dec = new TextDecoder();
  try { for (;;) { const { done, value } = await reader.read(); if (done || signal.aborted) break; onChunk(dec.decode(value, { stream: true })); } } catch { /* stream ended */ }
}

export interface TransportHooks { onMessage: (line: string) => void; log: (l: string) => void; onClosed: (why: string) => void; onInit?: (info: { name?: string; version?: string }) => void }

/** MCP client transport to one remote server: Streamable HTTP, falling back to (or told to use) HTTP+SSE. */
export class RemoteTransport {
  private sessionId: string | null = null; private proto: string | null = null;
  private mode: "http" | "sse"; private postUrl: string | null = null; private endpointReady: Promise<void> | null = null;
  private ready: Promise<void> = Promise.resolve(); private initialized = false;
  private abort = new AbortController(); private closed = false; private authWarned = false;
  private origin: string;
  constructor(private url: string, kind: "http" | "sse", private headers: () => Record<string, string>, private hooks: TransportHooks) { this.mode = kind; this.origin = new URL(url).origin; }

  private deliver(data: string) { try { this.hooks.onMessage(JSON.stringify(JSON.parse(data))); } catch { /* not JSON: dropped */ } }
  private reply(id: unknown, message: string) { if (id !== undefined && id !== null) this.hooks.onMessage(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32001, message } })); }

  /** Legacy transport: one long GET; its first event names the URL to POST to. */
  private openSse(): Promise<void> {
    if (this.endpointReady) return this.endpointReady;
    this.endpointReady = new Promise<void>((resolve, reject) => {
      fetch(this.url, { headers: { accept: "text/event-stream", ...this.headers() }, redirect: "manual", signal: this.abort.signal }).then((res) => {
        if (!res.ok) { reject(new Error(`${new URL(this.url).host} answered ${res.status} to the event stream`)); return; }
        const parse = sseParser((event, data) => {
          if (event === "endpoint") {
            const u = new URL(data, this.url);
            if (u.origin !== this.origin) { reject(new Error(`the server asked for messages to be posted to another origin (${u.host}); refused, the credential stays with ${new URL(this.url).host}`)); return; }
            this.postUrl = u.toString(); resolve();
          } else this.deliver(data);
        });
        void pump(res.body, parse, this.abort.signal).then(() => { if (!this.closed) this.hooks.onClosed("the server closed the event stream"); });
      }).catch((e: Error) => reject(e));
    });
    return this.endpointReady;
  }

  private async post(url: string, line: string, extra: Record<string, string>): Promise<Response> {
    let res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...this.headers(), ...extra }, body: line, redirect: "manual", signal: this.abort.signal });
    // A redirect is followed once and only within the origin the credential belongs to.
    if (res.status >= 300 && res.status < 400) {
      const to = res.headers.get("location"); const u = to ? new URL(to, url) : null;
      if (!u || u.origin !== this.origin) throw new Error(`redirect to ${u?.host ?? "nowhere"} refused: the credential is only sent to ${new URL(this.url).host}`);
      res = await fetch(u, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...this.headers(), ...extra }, body: line, redirect: "manual", signal: this.abort.signal });
    }
    return res;
  }

  /** One JSON-RPC message from the agent. Never throws: a failure is answered to the agent when the message had an id. */
  send(line: string): Promise<void> {
    let msg: { id?: unknown; method?: string } = {};
    try { msg = JSON.parse(line) as typeof msg; } catch { return Promise.resolve(); }
    const isInit = msg.method === "initialize";
    // Until the handshake has an answer nothing else is sent: the session id and protocol version come from it.
    const run = async () => {
      try {
        if (this.mode === "sse") { await this.openSse(); const r = await this.post(this.postUrl!, line, {}); if (!r.ok && r.status !== 202) this.fail(msg.id, r.status); await r.body?.cancel().catch(() => null); return; }
        const extra: Record<string, string> = { ...(this.sessionId ? { "mcp-session-id": this.sessionId } : {}), ...(this.proto && !isInit ? { "mcp-protocol-version": this.proto } : {}) };
        const res = await this.post(this.url, line, extra);
        if (isInit && !this.initialized && (res.status === 404 || res.status === 405)) {
          // An older server that only speaks HTTP+SSE.
          await res.body?.cancel().catch(() => null);
          this.mode = "sse"; this.hooks.log("the server does not accept Streamable HTTP; using HTTP+SSE");
          await this.openSse(); const r = await this.post(this.postUrl!, line, {}); if (!r.ok && r.status !== 202) this.fail(msg.id, r.status); await r.body?.cancel().catch(() => null); return;
        }
        const sid = res.headers.get("mcp-session-id"); if (sid) this.sessionId = sid;
        if (res.status === 202 || res.status === 204) { await res.body?.cancel().catch(() => null); return; }
        if (!res.ok) { this.fail(msg.id, res.status); await res.body?.cancel().catch(() => null); return; }
        const ct = res.headers.get("content-type") ?? "";
        const seen = (data: string) => { if (isInit) this.noteInit(data); this.deliver(data); };
        if (ct.includes("text/event-stream")) {
          await pump(res.body, sseParser((_e, data) => seen(data)), this.abort.signal);
        } else {
          const text = await res.text();
          try { const j = JSON.parse(text) as unknown; for (const one of Array.isArray(j) ? j : [j]) seen(JSON.stringify(one)); } catch { this.reply(msg.id, "the server answered with something that is not JSON"); }
        }
      } catch (e) {
        if (this.closed) return;
        const cause = (e as { cause?: { code?: string; message?: string } }).cause;
        const why = `${(e as Error).message}${cause?.code || cause?.message ? ` (${cause.code ?? cause.message})` : ""}`;
        this.hooks.log(`request failed: ${why}`); this.reply(msg.id, `vet-skills guard could not reach the server: ${why}`);
      }
    };
    if (isInit || !this.initialized) { this.ready = this.ready.then(run); return this.ready; }
    return run();
  }
  private noteInit(data: string) {
    try {
      const j = JSON.parse(data) as { result?: { protocolVersion?: string; serverInfo?: { name?: string; version?: string } } };
      if (!j.result) return;
      this.proto = j.result.protocolVersion ?? null; this.initialized = true;
      this.hooks.onInit?.(j.result.serverInfo ?? {});
      if (this.mode === "http") void this.listen();
    } catch { /* not the handshake */ }
  }
  /** Server-initiated messages (Streamable HTTP): an optional GET stream. A server that does not offer one answers 405. */
  private async listen() {
    try {
      const res = await fetch(this.url, { headers: { accept: "text/event-stream", ...this.headers(), ...(this.sessionId ? { "mcp-session-id": this.sessionId } : {}), ...(this.proto ? { "mcp-protocol-version": this.proto } : {}) }, redirect: "manual", signal: this.abort.signal });
      if (!res.ok || !(res.headers.get("content-type") ?? "").includes("text/event-stream")) { await res.body?.cancel().catch(() => null); return; }
      await pump(res.body, sseParser((_e, data) => this.deliver(data)), this.abort.signal);
    } catch { /* optional */ }
  }
  private fail(id: unknown, status: number) {
    const host = new URL(this.url).host;
    const why = status === 401 || status === 403
      ? `${host} answered ${status}: the credential the guard holds was not accepted, or this server wants a browser sign-in (OAuth), which the guard does not wrap. Check it with \`vet-skills secrets list\`, or run \`vet-skills guard uninstall\` to let the agent sign in itself.`
      : status === 404 && this.sessionId ? `${host} no longer knows this session (404); restart the agent to reconnect.` : `${host} answered ${status}.`;
    if (!this.authWarned || (status !== 401 && status !== 403)) this.hooks.log(why);
    if (status === 401 || status === 403) this.authWarned = true;
    this.reply(id, `vet-skills guard: ${why}`);
  }
  async close() {
    if (this.closed) return; this.closed = true;
    if (this.mode === "http" && this.sessionId) await fetch(this.url, { method: "DELETE", headers: { ...this.headers(), "mcp-session-id": this.sessionId }, redirect: "manual", signal: AbortSignal.timeout(2000) }).then((r) => r.body?.cancel()).catch(() => null);
    this.abort.abort();
  }
}

/** Resolve the header set once: stored values from the store, templates from the environment. Names of what could not be resolved come back. */
export function resolveHeaders(spec: RemoteSpec, store: SecretStore, env: NodeJS.ProcessEnv): { headers: Record<string, string>; held: string[]; missing: string[] } {
  const headers: Record<string, string> = {}; const held: string[] = []; const missing: string[] = [];
  for (const h of spec.headers) {
    if (isStoreRef(h.value)) { const v = store.get(keyOfRef(h.value)); if (v === null) missing.push(`${h.name} (not in the guard's store: vet-skills secrets set ${keyOfRef(h.value)})`); else { headers[h.name] = v; held.push(h.name); } }
    else { const x = expandEnv(h.value, env); if (x.missing.length) missing.push(`${h.name} (environment variable ${x.missing.join(", ")} is not set)`); else headers[h.name] = x.value; }
  }
  return { headers, held, missing };
}

/** Run the bridge. stdin/stdout are the agent's MCP stream; resolves with the exit code when the agent hangs up. */
export async function execRemote(argv: string[], io: { stdin?: NodeJS.ReadableStream; stdout?: NodeJS.WritableStream } = {}): Promise<number> {
  const log = (l: string) => process.stderr.write(`vet-skills guard · ${l}\n`);
  const spec = parseRemoteArgs(argv);
  if ("error" in spec) { log(spec.error); return 2; }
  const stdin = io.stdin ?? process.stdin; const stdout = io.stdout ?? process.stdout;
  const u = new URL(spec.url); const host = u.hostname;
  const { policy, source } = readPolicy(); const rt = policy.runtime; const org = readOrg();
  const session = randomBytes(6).toString("hex"); const started = new Date().toISOString();
  const report: GuardSessionReport = { session, server: spec.server, client: spec.client, pkg: host, registry: "remote", semver: null, started, ended: null, final: false, exit_code: null, machine: clientId(), cwd_hash: createHash("sha256").update(process.cwd()).digest("hex").slice(0, 16), hosts: [], tools: [], secrets: [], canary: false, poison: [], launch: "ran", launch_reason: null, guard_version: VERSION, policy_version: org?.policyVersion ?? null };
  const rec = decisionRecorder(report);
  const flush = async (final: boolean) => {
    report.final = final; report.ended = final ? new Date().toISOString() : null;
    appendGuardLog({ kind: final ? "session" : "progress", session, server: spec.server, client: spec.client, pkg: host, remote: true, tools: [...rec.toolStats.values()].reduce((n, t) => n + t.calls, 0), secrets: report.secrets.length, exit: report.exit_code });
    if (org) { const res = await guardReport(report).catch(() => null); if (res && res.ok && res.data.alerts?.length) for (const al of res.data.alerts) log(`org alert · ${al.detail}`); }
  };
  const refuseLaunch = async (why: string) => { report.launch = "refused"; report.launch_reason = why; report.exit_code = 1; appendGuardLog({ kind: "launch_refused", session, server: spec.server, pkg: host, why }); await flush(true); return 1; };

  // Kill switch, keyed by host: an org (or the network) can revoke a remote server like a package version.
  // An enrolled machine always asks (its org's revocations apply). A personal machine asks only with field signals on,
  // since the question carries the server's host name.
  const mayAsk = !!org || telemetryEnabled();
  const lc = mayAsk ? await launchCheck(host, null, "remote").catch(() => null) : null;
  if (lc && lc.ok && lc.data.state === "revoked") {
    const why = `${host} is revoked${lc.data.reason ? `: ${lc.data.reason}` : ""}`;
    if (rt.blockedVersions === "refuse") { log(`✕ not connecting ${spec.server}: ${why}. Policy runtime.blocked_versions: refuse${source === "org" ? " (org)" : ""}.`); return refuseLaunch(why); }
    report.launch = "warned"; report.launch_reason = why; log(`⚠ connecting ${spec.server} although ${why} (policy runtime.blocked_versions: warn)`);
  }
  const resolved = resolveHeaders(spec, new SecretStore(), process.env);
  if (resolved.missing.length) { const why = `cannot build the request headers for ${spec.server}: ${resolved.missing.join("; ")}`; log(`✕ ${why}`); return refuseLaunch(why); }
  for (const name of resolved.held) report.secrets.push({ name, host, refused: false });
  report.hosts.push({ host, port: Number(u.port) || (u.protocol === "https:" ? 443 : 80), mode: "brokered", expected: true, first_seen_here: false });

  // What changed since the tools this server listed last time on this machine.
  const baseKey = `${spec.client}/${spec.server}`;
  const held = new Map<string, string>();
  let lastTools: Record<string, string> | null = null; let serverVersion: string | null = null;
  const acceptCurrent = () => { if (!lastTools) return; const b = readRemoteBaseline(); b[baseKey] = { url: spec.url, tools: lastTools, version: serverVersion, at: new Date().toISOString() }; writeRemoteBaseline(b); held.clear(); };
  const onTools = (tools: { name?: string; description?: string; inputSchema?: unknown }[]) => {
    const now: Record<string, string> = {}; for (const t of tools) if (t.name) now[t.name] = descriptorHash(t);
    lastTools = now;
    const b = readRemoteBaseline(); const prev = b[baseKey];
    if (!prev || prev.url !== spec.url || prev.acceptNext) { if (prev?.acceptNext) log(`${spec.server}: tool list accepted (vet-skills guard approve)`); acceptCurrent(); return; }
    const added = Object.keys(now).filter((n) => !(n in prev.tools)).sort();
    const rewritten = Object.keys(now).filter((n) => n in prev.tools && prev.tools[n] !== now[n]).sort();
    if (!added.length && !rewritten.length) { if (prev.version !== serverVersion) acceptCurrent(); return; }
    const what = [added.length ? `${added.length} new tool${added.length === 1 ? "" : "s"} (${added.slice(0, 4).join(", ")}${added.length > 4 ? ", …" : ""})` : "", rewritten.length ? `${rewritten.length} rewritten tool descriptor${rewritten.length === 1 ? "" : "s"} (${rewritten.slice(0, 4).join(", ")}${rewritten.length > 4 ? ", …" : ""})` : ""].filter(Boolean).join(" · ");
    appendGuardLog({ kind: "remote_changed", session, server: spec.server, pkg: host, added, rewritten, action: rt.onChange });
    if (rt.onChange === "allow") { acceptCurrent(); return; }
    if (rt.onChange === "warn") { if (report.launch === "ran") { report.launch = "warned"; report.launch_reason = `${spec.server} changed since it was last used here: ${what}`; } log(`⚠ ${spec.server} (${host}) changed since it was last used here: ${what}. Continuing (policy runtime.on_change: warn).`); acceptCurrent(); return; }
    const why = `${spec.server} changed since it was last used here (${what}); policy runtime.on_change: hold`;
    for (const n of [...added, ...rewritten]) held.set(n, why);
    const hash = createHash("sha256").update(JSON.stringify(now)).digest("hex").slice(0, 16);
    if (!org) { log(`✕ holding ${added.length + rewritten.length} tool${added.length + rewritten.length === 1 ? "" : "s"} of ${spec.server}: ${what}. The rest keep working. To accept: vet-skills guard approve ${spec.server}`); return; }
    void (async () => {
      let id = prev.pending?.hash === hash ? prev.pending.id : null;
      if (!id) {
        const c = await approvalCreate({ server: spec.server, pkg: host, semver: serverVersion, tool: `tools changed on ${spec.server}`, arg_keys: [...added.map((n) => `tool:${n}`), ...rewritten.map((n) => `rewritten:${n}`)].slice(0, 50), arg_preview: what.slice(0, 400), reason: "runtime.on_change: hold", session, timeout_seconds: 3600 }).catch(() => null);
        if (!c || !c.ok) { log(`✕ holding the changed tools of ${spec.server}: ${what}. The approval request could not be created; held until the org can be reached.`); return; }
        id = c.data.id; const bb = readRemoteBaseline(); if (bb[baseKey]) { bb[baseKey].pending = { id, hash }; writeRemoteBaseline(bb); }
        log(`✕ holding the changed tools of ${spec.server}: ${what}. Approval requested: ${c.data.url}`);
      } else log(`✕ still holding the changed tools of ${spec.server}: ${what}. An approver has not decided yet.`);
      const deadline = Date.now() + 3600_000;
      while (Date.now() < deadline && held.size) {
        await new Promise((r) => setTimeout(r, 5000).unref());
        const p = await approvalPoll(id).catch(() => null);
        if (p && p.ok && p.data.status === "approved") { log(`${spec.server}: change approved by ${p.data.by ?? "an approver"}`); acceptCurrent(); return; }
        if (p && p.ok && (p.data.status === "denied" || p.data.status === "expired")) { log(`${spec.server}: change ${p.data.status}${p.data.by ? ` by ${p.data.by}` : ""}; the changed tools stay held`); return; }
      }
    })();
  };

  const inflight = new Set<Promise<void>>();
  const label = spec.server;
  let finished = false; let done: (code: number) => void = () => undefined;
  const exit = new Promise<number>((r) => { done = r; });
  const emit = (e: RelayEvent) => {
    try {
      appendGuardLog({ ...e, session, server: spec.server, pkg: host });
      if (e.kind === "tool_call") { rec.record(e); report.tools = [...rec.toolStats.values()]; } else if (e.kind === "tool_reply") rec.record(e);
      else if (e.kind === "canary") report.canary = true; else if (e.kind === "poison") report.poison.push(`${e.tool}: ${e.summary}`);
    } catch { /* never break the relay */ }
  };
  const transport = new RemoteTransport(spec.url, spec.sse ? "sse" : "http", () => resolved.headers, {
    onMessage: (line) => { stdout.write(line + "\n"); relay.inspect(line); },
    log,
    onClosed: (why) => { if (!finished) { log(`${spec.server}: ${why}`); finish(0); } },
    onInit: (info) => { serverVersion = info.version ?? null; report.semver = serverVersion; },
  });
  const relay = createRelay({
    label: spec.server, deny: [], toolRules: rt.tools, defaultToolAction: rt.defaultToolAction,
    approver: org ? makeApprover({ server: spec.server, pkg: host, semver: null, session, timeout: rt.approvalTimeoutSeconds, log }) : undefined,
    held: (tool) => { if (!held.has(tool)) return null; if (readRemoteBaseline()[baseKey]?.acceptNext) { acceptCurrent(); return null; } return held.get(tool)!; },
  }, { toServer: (line) => { const p = transport.send(line); inflight.add(p); void p.finally(() => inflight.delete(p)); }, toAgent: (line) => { stdout.write(line + "\n"); }, log, emit, onTools });

  const timer = setInterval(() => { flush(false).catch(() => null); }, 5 * 60_000); timer.unref();
  let revokedSeen = false;
  const watch = setInterval(async () => {
    if (revokedSeen || !mayAsk) return;
    const r = await launchCheck(host, null, "remote").catch(() => null);
    if (!r || !r.ok || r.data.state !== "revoked") return;
    revokedSeen = true;
    const why = `${host} was revoked while connected${r.data.reason ? `: ${r.data.reason}` : ""}`;
    report.launch_reason = why;
    appendGuardLog({ kind: "revoked_running", session, server: spec.server, pkg: host, why, action: rt.revokeRunning });
    if (rt.revokeRunning === "kill") { report.launch = "stopped"; relay.stop(why); finish(1); }
    else { report.launch = "warned"; log(`⚠ ${why}. The connection stays open (policy runtime.revoke_running: warn); restart the agent to drop it, or set revoke_running: kill.`); await flush(false).catch(() => null); }
  }, Math.max(5_000, Number(process.env.VET_SKILLS_REVOKE_POLL_MS) || 60_000)); watch.unref();

  function finish(code: number) {
    if (finished) return; finished = true;
    clearInterval(timer); clearInterval(watch);
    report.exit_code = code;
    const { calls, denied } = relay.counts();
    void transport.close().then(() => flush(true)).catch(() => null).then(() => { log(`${label} disconnected · ${calls} tool call${calls === 1 ? "" : "s"}, ${denied} denied`); done(code); });
  }

  if ((process.env.HTTPS_PROXY || process.env.https_proxy) && process.env.NODE_USE_ENV_PROXY !== "1" && !/^(localhost|127\.0\.0\.1)$/.test(host)) log(`HTTPS_PROXY is set but the guard connects to ${host} directly. If this network requires the proxy, set NODE_USE_ENV_PROXY=1 in this server's env (Node 22.21 or later).`);
  appendGuardLog({ kind: "start", session, server: spec.server, client: spec.client, pkg: host, remote: true, transport: spec.sse ? "sse" : "http", secrets: resolved.held });
  log(`${spec.server} → ${host} (remote, ${spec.sse ? "HTTP+SSE" : "Streamable HTTP"})${resolved.held.length ? ` · holding ${resolved.held.join(", ")}; the agent's config has the name only` : ""} · policy ${policy.name} (${source})`);
  let buf = "";
  stdin.on("data", (chunk: Buffer | string) => {
    buf += chunk.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); if (line.trim()) void relay.fromAgent(line); }
  });
  // The agent hung up: let what was already sent get its answer (ten seconds at most), then close.
  stdin.on("end", () => { void relay.drained().then(() => Promise.race([Promise.allSettled([...inflight]), new Promise((r) => setTimeout(r, 10_000).unref())])).then(() => finish(0)); });
  return exit;
}
