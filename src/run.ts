/**
 * `vet-skills run [--deny a,b] [--net declared|host1,host2|off] [--secrets NAME=host,…] -- <command…>`
 *
 * A guard between the agent and a stdio MCP server. The server runs as the
 * command given; the agent talks to this process. In between:
 *   - tools/call for a denied tool name is answered with an error and never
 *     reaches the server (names, or globs like "delete_*");
 *   - every tool call is recorded in runtime observation (tool name and the
 *     argument key names only, never values), attributed to the server;
 *   - with --net, the server's HTTP(S)_PROXY points at an in-process allow-list
 *     proxy: "declared" takes the hosts the KillerSkills verdict saw as declared,
 *     or give a list. Clients that do not honor proxies are not contained, and
 *     the guard says so once at start;
 *   - with --secrets, named environment variables are replaced by placeholders in the server's environment and the
 *     real values are put into its requests to the bound host only (TLS terminated with a per-run CA; broker.ts).
 *
 * This is "run with restrictions" for a package the policy would otherwise
 * block or sandbox. It is not a container: filesystem access is unchanged.
 */
import { spawn, spawnSync } from "node:child_process";
import { homedir, platform } from "node:os";
import { existsSync } from "node:fs";
import { createServer, request as httpRequest, type Server } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect } from "node:net";
import { TLSSocket, createSecureContext } from "node:tls";
import { brokerEnv, parseSecrets, substitute, RunCA, type SecretBinding } from "./broker.js";
import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { resolveSkill } from "./api.js";
import { hiddenTextFindings, hiddenSummary } from "./policy/index.js";
import { canariesIn, describeCanary, readCanaries } from "./canary.js";
import { HOME } from "./state.js";

export interface RunOptions { deny: string[]; net: "off" | "declared" | string[]; label: string; query?: string; log?: (l: string) => void; /** Filesystem (and on macOS network) containment around the server process. */ contain?: boolean; /** `NAME=host,…`: secrets the guard holds and injects only into requests to that host (see broker.ts). */ secrets?: string }

/** The broker side of the proxy: bound hosts are TLS-terminated and their requests rewritten. */
export interface BrokerHooks { ca: RunCA; bindings: SecretBinding[]; onBroker: (host: string, used: SecretBinding[], refused: SecretBinding[]) => void }

const globToRe = (g: string) => new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i");

/** A tiny CONNECT/GET proxy that only forwards to allowed hosts (exact or suffix match). With a broker, bound hosts are
 *  terminated and rewritten (see broker.ts). */
export function startAllowlistProxy(hosts: string[], onDeny: (host: string) => void, broker?: BrokerHooks): Promise<{ url: string; close: () => void }> {
  const allowed = (h: string) => hosts.some((a) => h === a || h.endsWith(`.${a}`));
  // With a broker every allowed host is terminated, not only the bound ones: that is how a placeholder sent to the
  // wrong host becomes visible. Clients that pin certificates will refuse the run's CA; use --net without --secrets then.
  const bound = (_h: string) => broker !== undefined;
  const srv: Server = createServer((req, res) => {
    // Plain HTTP: forward only to allowed hosts.
    let host = "";
    try { host = new URL(req.url ?? "").hostname; } catch { /* absolute-form expected */ }
    if (!host || !allowed(host)) { onDeny(host || "?"); res.writeHead(403, { "content-type": "text/plain" }); res.end(`vet-skills run: ${host} is not an allowed host\n`); return; }
    const u = new URL(req.url!);
    if (broker && bound(host)) { relayRewritten(req, res, { host, port: Number(u.port || 80), tls: false, path: `${u.pathname}${u.search}` }, broker); return; }
    const up = connect(Number(u.port || 80), u.hostname, () => {
      up.write(`${req.method} ${u.pathname}${u.search} HTTP/1.1\r\n`);
      for (const [k, v] of Object.entries(req.headers)) if (k !== "proxy-connection") up.write(`${k}: ${Array.isArray(v) ? v.join(", ") : v}\r\n`);
      up.write("\r\n");
      req.pipe(up); up.pipe(res.socket!);
    });
    up.on("error", () => { try { res.writeHead(502); res.end(); } catch { /* closed */ } });
  });
  // Requests arriving on a terminated TLS tunnel land here, already decrypted; the socket remembers its host.
  const mitm: Server = createServer((req, res) => {
    const sock = req.socket as TLSSocket & { brokerHost?: string; brokerPort?: number };
    relayRewritten(req, res, { host: sock.brokerHost ?? "", port: sock.brokerPort ?? 443, tls: true, path: req.url ?? "/" }, broker!);
  });
  srv.on("connect", (req, socket, head) => {
    const [host, port] = (req.url ?? "").split(":");
    if (!host || !allowed(host)) { onDeny(host || "?"); socket.end("HTTP/1.1 403 Forbidden\r\n\r\n"); return; }
    if (broker && bound(host)) {
      let leaf: { key: string; cert: string };
      try { leaf = broker.ca.leaf(host); } catch { socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); return; }
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      const tls = new TLSSocket(socket, { isServer: true, secureContext: createSecureContext({ key: leaf.key, cert: leaf.cert }), ALPNProtocols: ["http/1.1"] }) as TLSSocket & { brokerHost?: string; brokerPort?: number };
      tls.brokerHost = host; tls.brokerPort = Number(port || 443);
      tls.on("error", () => socket.destroy());
      if (head.length) tls.unshift(head);
      mitm.emit("connection", tls);
      return;
    }
    const up = connect(Number(port || 443), host, () => { socket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); if (head.length) up.write(head); socket.pipe(up); up.pipe(socket); });
    up.on("error", () => socket.end()); socket.on("error", () => up.end());
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => { const a = srv.address() as { port: number }; resolve({ url: `http://127.0.0.1:${a.port}`, close: () => { srv.closeAllConnections(); srv.close(); mitm.closeAllConnections(); mitm.close(); } }); }));
}

const MAX_REWRITE_BODY = 4 * 1024 * 1024;

/** Forward one decrypted request to its real host with the bound secrets substituted into headers, path and body. */
function relayRewritten(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse, to: { host: string; port: number; tls: boolean; path: string }, broker: BrokerHooks) {
  const chunks: Buffer[] = []; let size = 0;
  req.on("data", (c: Buffer) => { chunks.push(c); size += c.length; });
  req.on("end", () => {
    const used: SecretBinding[] = []; const refused: SecretBinding[] = [];
    const take = (r: { used: SecretBinding[]; refused: SecretBinding[] }) => { used.push(...r.used); refused.push(...r.refused); };
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (k === "proxy-connection" || k === "proxy-authorization") continue;
      const r = substitute(Array.isArray(v) ? v.join(", ") : String(v ?? ""), to.host, broker.bindings); take(r); headers[k] = r.text;
    }
    const pathR = substitute(to.path, to.host, broker.bindings); take(pathR);
    let body: Buffer | string = Buffer.concat(chunks);
    if (size <= MAX_REWRITE_BODY && size > 0) { const text = body.toString("latin1"); const r = substitute(text, to.host, broker.bindings); if (r.used.length || r.refused.length) { take(r); body = Buffer.from(r.text, "latin1"); headers["content-length"] = String(body.length); delete headers["transfer-encoding"]; } }
    broker.onBroker(to.host, [...new Set(used)], [...new Set(refused)]);
    const mk = to.tls ? httpsRequest : httpRequest;
    const up = mk({ host: to.host, port: to.port, method: req.method, path: pathR.text, headers, servername: to.host }, (r) => { res.writeHead(r.statusCode ?? 502, r.headers); r.pipe(res); });
    up.on("error", () => { try { res.writeHead(502); res.end(); } catch { /* closed */ } });
    up.end(body);
  });
}

/** Hosts the verdict's sandbox run saw and the package declared, for --net declared. */
export async function declaredHosts(query: string): Promise<string[]> {
  const r = await resolveSkill(query);
  if (!r.ok || !r.data.trace_summary) return [];
  return r.data.trace_summary.egress_hosts.filter((h) => h.declared).map((h) => h.host);
}

/** Paths a contained server must never read: where credentials live. */
export const CREDENTIAL_DIRS = [".ssh", ".aws", ".config/gh", ".config/gcloud", ".azure", ".kube", ".gnupg", ".docker", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".vet-skills", "Library/Keychains", "Library/Application Support/Claude", ".claude", ".cursor", ".codeium", ".config/Code"];

/**
 * Wrap the server command in the OS sandbox when one is available.
 *   macOS: sandbox-exec. Reads everywhere except credential paths; writes only in the project, temp and cache dirs;
 *          outbound network only to the allow-list proxy on localhost (so a client that ignores HTTPS_PROXY gets
 *          nothing, not a leak).
 *   Linux: bubblewrap. Same filesystem rules; the network stays in the host namespace and is shaped by the proxy only.
 *   Elsewhere, or when the tool is missing, the command runs as is and the log says so.
 */
export function containWrap(cmd: string[], proxyPort: number | null): { cmd: string[]; note: string } {
  const home = homedir();
  const project = process.cwd();
  const writable = [project, "/tmp", "/private/tmp", process.env.TMPDIR ?? "/tmp", join(home, ".cache"), join(home, ".npm"), join(home, "Library/Caches"), join(home, ".local/share/uv"), join(home, ".local/share/pnpm")];
  const creds = CREDENTIAL_DIRS.map((d) => join(home, d));
  if (platform() === "darwin" && existsSync("/usr/bin/sandbox-exec")) {
    const q = (s: string) => `"${s.replace(/"/g, '\\"')}"`;
    const profile = [
      "(version 1)", "(allow default)",
      `(deny file-read* ${creds.map((p) => `(subpath ${q(p)})`).join(" ")})`,
      `(deny file-write* (subpath ${q(home)}))`,
      `(allow file-write* ${writable.map((p) => `(subpath ${q(p)})`).join(" ")})`,
      "(deny network-outbound)",
      ...(proxyPort ? [`(allow network-outbound (remote ip "localhost:${proxyPort}") (remote unix-socket))`] : ["(allow network-outbound (remote unix-socket))"]),
    ].join("\n");
    return { cmd: ["/usr/bin/sandbox-exec", "-p", profile, ...cmd], note: `contained (macOS sandbox: credential paths unreadable, writes limited to the project and caches, network only through the guard${proxyPort ? "" : "; no proxy, so no network at all"})` };
  }
  if (platform() === "linux" && spawnSync("bwrap", ["--version"], { stdio: "ignore" }).status === 0) {
    const args = ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"];
    for (const p of writable) if (existsSync(p) && !p.startsWith("/tmp") && !p.startsWith("/private")) args.push("--bind", p, p);
    for (const p of creds) if (existsSync(p)) args.push("--tmpfs", p);
    args.push("--die-with-parent", "--");
    return { cmd: ["bwrap", ...args, ...cmd], note: "contained (bubblewrap: credential paths empty, writes limited to the project and caches; network shaped by the guard proxy only)" };
  }
  return { cmd, note: platform() === "linux" ? "containment unavailable: install bubblewrap (apt install bubblewrap) for filesystem containment; running with the guard only" : platform() === "win32" ? "containment is not available on Windows (use WSL); running with the guard only" : "containment unavailable on this machine; running with the guard only" };
}

const RUNTIME = join(HOME, "runtime");
function record(label: string, tool: string, keys: string[], denied: boolean) {
  try { mkdirSync(RUNTIME, { recursive: true }); appendFileSync(join(RUNTIME, "guard.jsonl"), JSON.stringify({ at: new Date().toISOString(), server: label, tool, args: keys, denied }) + "\n"); } catch { /* best effort */ }
}

/** Relay newline-delimited JSON-RPC both ways, filtering tools/call. Returns the server's exit code. */
export async function guard(cmd: string[], opts: RunOptions): Promise<number> {
  const log = opts.log ?? ((l) => process.stderr.write(`vet-skills run · ${l}\n`));
  const deny = opts.deny.map(globToRe);
  let proxy: { url: string; close: () => void } | null = null;
  let hosts: string[] = [];
  const blockedHosts = new Map<string, number>();
  // Credential broker: the server gets placeholders; the proxy puts the real values into requests to the bound hosts.
  let broker: BrokerHooks | null = null; let ca: RunCA | null = null;
  const brokered = new Set<string>();
  if (opts.secrets) {
    const p = parseSecrets(opts.secrets);
    if (p.error) { log(p.error); return 2; }
    for (const n of p.missing) log(`--secrets: ${n} is not set in the environment; nothing to broker for it`);
    if (p.bindings.length) {
      try { ca = RunCA.create(); } catch (e) { log((e as Error).message); return 2; }
      broker = { ca, bindings: p.bindings, onBroker: (host, used, refused) => {
        for (const b of used) { const k = `${b.name}→${host}`; if (!brokered.has(k)) { brokered.add(k); log(`brokered ${b.name} into a request to ${host}`); } }
        for (const b of refused) { const k = `!${b.name}→${host}`; if (!brokered.has(k)) { brokered.add(k); record(opts.label, `secret:${b.name}`, [host], true); log(`✕ ${opts.label} sent the ${b.name} placeholder to ${host}, which it is not bound to (bound: ${b.host}). The real value never left this process; treat the server as hostile.`); } }
      } };
    }
  }
  if (opts.net !== "off" || broker) {
    hosts = opts.net === "declared" ? await declaredHosts(opts.query ?? opts.label) : opts.net === "off" ? [] : opts.net;
    if (opts.net === "declared" && !hosts.length && !broker) log(`no declared hosts on record for ${opts.query ?? opts.label}; network stays open (use --net host1,host2 to pin it)`);
    else {
      for (const b of broker?.bindings ?? []) if (!hosts.includes(b.host)) hosts.push(b.host);
      if (opts.net === "off" && broker) log(`--secrets implies a network pin: only ${hosts.join(", ")} reachable (add --net to widen it)`);
      proxy = await startAllowlistProxy(hosts, (h) => { blockedHosts.set(h, (blockedHosts.get(h) ?? 0) + 1); if (blockedHosts.get(h) === 1) log(`blocked connection to ${h} (answered 403; the server keeps running)`); }, broker ?? undefined);
    }
  }
  const env = { ...process.env, ...(proxy ? { HTTP_PROXY: proxy.url, HTTPS_PROXY: proxy.url, http_proxy: proxy.url, https_proxy: proxy.url, NO_PROXY: "127.0.0.1,localhost", ALL_PROXY: proxy.url } : {}), ...(broker && ca ? brokerEnv(broker.bindings, ca.caBundle, ca.caPem) : {}) };
  log(`guarding ${opts.label}${deny.length ? ` · denying ${opts.deny.join(", ")}` : ""}${proxy ? ` · network limited to ${hosts.join(", ")} (clients that ignore HTTPS_PROXY are not contained)` : ""}${broker ? ` · holding ${broker.bindings.map((b) => `${b.name} for ${b.host}`).join(", ")} (the server sees placeholders)` : ""}`);
  let launch = cmd;
  if (opts.contain) { const w = containWrap(cmd, proxy ? Number(new URL(proxy.url).port) : null); launch = w.cmd; log(w.note); }
  const child = spawn(launch[0], launch.slice(1), { stdio: ["pipe", "pipe", "inherit"], env });
  const pending = new Map<number | string, string>();
  const canaryReg = readCanaries();
  let calls = 0, deniedCalls = 0;
  // agent → server
  let inBuf = "";
  process.stdin.on("data", (chunk) => {
    inBuf += chunk.toString();
    let i;
    while ((i = inBuf.indexOf("\n")) >= 0) {
      const line = inBuf.slice(0, i); inBuf = inBuf.slice(i + 1);
      if (!line.trim()) continue;
      let m: { id?: number | string; method?: string; params?: { name?: string; arguments?: Record<string, unknown> } } | null = null;
      try { m = JSON.parse(line); } catch { /* pass through */ }
      if (m?.method === "tools/call" && m.params?.name) {
        const name = m.params.name;
        const keys = Object.keys(m.params.arguments ?? {});
        calls++;
        // A planted canary in the arguments the agent is sending to this server: exfiltration in progress. Refuse the call.
        const leak = canariesIn(line, canaryReg);
        if (leak.length) {
          deniedCalls++; record(opts.label, name, keys, true);
          log(`✕ CREDENTIAL EXFILTRATION: ${describeCanary(leak[0])} value in the arguments of tools/call ${name}; call refused. Revoke real credentials in that folder.`);
          if (m.id !== undefined) process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32600, message: `vet-skills run refused tools/call ${name}: the arguments carry a planted canary credential (exfiltration).` } }) + "\n");
          continue;
        }
        if (deny.some((re) => re.test(name))) {
          deniedCalls++;
          record(opts.label, name, keys, true);
          log(`denied tools/call ${name}`);
          if (m.id !== undefined) process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: `Tool "${name}" is denied by vet-skills run on this machine.` } }) + "\n");
          continue;
        }
        record(opts.label, name, keys, false);
        if (m.id !== undefined) pending.set(m.id, name);
      }
      child.stdin.write(line + "\n");
    }
  });
  process.stdin.on("end", () => child.stdin.end());
  // server → agent: relayed as is, but inspected. tools/list descriptions are instructions the agent will follow; a
  // tools/call result is data that must not carry any. Findings are logged and told to the agent out of band (stderr).
  let outBuf = "";
  const warned = new Set<string>();
  child.stdout.on("data", (chunk) => {
    process.stdout.write(chunk);
    outBuf += chunk.toString();
    let i;
    while ((i = outBuf.indexOf("\n")) >= 0) {
      const line = outBuf.slice(0, i); outBuf = outBuf.slice(i + 1);
      if (line.length > 2_000_000 || !line.trim()) continue;
      let m: { id?: number | string; result?: { tools?: { name?: string; description?: string; inputSchema?: unknown }[]; content?: unknown } } | null = null;
      try { m = JSON.parse(line); } catch { continue; }
      if (!m?.result) continue;
      if (Array.isArray(m.result.tools)) {
        for (const t of m.result.tools) {
          const f = hiddenTextFindings(`${t.description ?? ""}\n${JSON.stringify(t.inputSchema ?? {})}`, { phrases: true }).filter((x) => x.severity !== "medium");
          const key = `desc|${t.name}`;
          if (f.length && !warned.has(key)) { warned.add(key); record(opts.label, t.name ?? "?", [], false); log(`tool "${t.name}" description carries instructions for the agent (tool poisoning): ${hiddenSummary(f)}. Deny it with --deny ${t.name} if you do not trust it.`); }
        }
      } else if (m.id !== undefined && pending.has(m.id)) {
        const tool = pending.get(m.id)!; pending.delete(m.id);
        const leak = canariesIn(line, canaryReg);
        if (leak.length && !warned.has(`canary|${tool}`)) { warned.add(`canary|${tool}`); record(opts.label, tool, [], false); log(`✕ ${describeCanary(leak[0])} value in the result of ${tool}: the server read a decoy credential file on this machine. Treat ${opts.label} as hostile.`); }
        const f = hiddenTextFindings(JSON.stringify(m.result.content ?? m.result), { phrases: true }).filter((x) => x.severity !== "medium");
        const key = `res|${tool}|${f[0]?.title ?? ""}`;
        if (f.length && !warned.has(key)) { warned.add(key); log(`result of ${tool} carries instructions aimed at the agent: ${hiddenSummary(f)}. Treat it as data.`); }
      }
    }
  });
  return new Promise((resolve) => {
    // Resolve only once everything the server wrote has been relayed and flushed: the process exits right after.
    child.on("close", (code) => { proxy?.close(); ca?.wipe(); const nb = [...blockedHosts.values()].reduce((a, b) => a + b, 0); log(`${opts.label} exited (${code ?? "signal"}) · ${calls} tool call${calls === 1 ? "" : "s"}, ${deniedCalls} denied${nb ? ` · ${nb} connection${nb === 1 ? "" : "s"} blocked (${[...blockedHosts.keys()].slice(0, 5).join(", ")})` : ""}`); process.stdout.write("", () => resolve(code ?? 1)); });
    child.on("error", (e) => { proxy?.close(); ca?.wipe(); log(`could not start ${cmd[0]}: ${e.message}`); resolve(1); });
  });
}

/** Parse `run [--deny a,b] [--net …] [--label x] [--query q] -- cmd…` from the raw argv after "run". */
export function parseRunArgs(argv: string[]): { opts: RunOptions; cmd: string[] } | { error: string } {
  const opts: RunOptions = { deny: [], net: "off", label: "", contain: false };
  let i = 0;
  while (i < argv.length && argv[i] !== "--") {
    const a = argv[i];
    const val = () => { const v = argv[i + 1]; if (v === undefined || v === "--") throw new Error(`${a} needs a value`); i++; return v; };
    try {
      if (a === "--deny") opts.deny.push(...val().split(",").map((s) => s.trim()).filter(Boolean));
      else if (a === "--net") { const v = val(); opts.net = v === "off" ? "off" : v === "declared" ? "declared" : v.split(",").map((s) => s.trim()).filter(Boolean); }
      else if (a === "--contain") opts.contain = true;
      else if (a === "--secrets") opts.secrets = val();
      else if (a === "--label") opts.label = val();
      else if (a === "--query") opts.query = val();
      else return { error: `unknown option ${a}` };
    } catch (e) { return { error: (e as Error).message }; }
    i++;
  }
  const cmd = argv.slice(i + 1);
  if (argv[i] !== "--" || !cmd.length) return { error: "usage: vet-skills run [--contain] [--deny tool,glob*] [--net declared|host1,host2|off] [--secrets NAME=host,…] -- <command…>" };
  if (!opts.label) {
    // "npx -y @scope/pkg" → "@scope/pkg"; "uvx pkg" → "pkg"; else the binary.
    const pkg = cmd.find((x, k) => k > 0 && !x.startsWith("-") && /^(npx|uvx|pipx|bunx)$/.test(cmd[0])) ?? cmd[0];
    opts.label = pkg; opts.query ??= pkg.replace(/^@/, "").replace(/@[^/]*$/, "");
  }
  return { opts, cmd };
}
