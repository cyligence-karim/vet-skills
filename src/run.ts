/**
 * `vet-skills run [--deny a,b] [--net declared|host1,host2|off] -- <command…>`
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
 *     the guard says so once at start.
 *
 * This is "run with restrictions" for a package the policy would otherwise
 * block or sandbox. It is not a container: filesystem access is unchanged.
 */
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { connect } from "node:net";
import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { resolveSkill } from "./api.js";
import { HOME } from "./state.js";

export interface RunOptions { deny: string[]; net: "off" | "declared" | string[]; label: string; query?: string; log?: (l: string) => void }

const globToRe = (g: string) => new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i");

/** A tiny CONNECT/GET proxy that only forwards to allowed hosts (exact or suffix match). */
export function startAllowlistProxy(hosts: string[], onDeny: (host: string) => void): Promise<{ url: string; close: () => void }> {
  const allowed = (h: string) => hosts.some((a) => h === a || h.endsWith(`.${a}`));
  const srv: Server = createServer((req, res) => {
    // Plain HTTP: forward only to allowed hosts.
    let host = "";
    try { host = new URL(req.url ?? "").hostname; } catch { /* absolute-form expected */ }
    if (!host || !allowed(host)) { onDeny(host || "?"); res.writeHead(403, { "content-type": "text/plain" }); res.end(`vet-skills run: ${host} is not an allowed host\n`); return; }
    const u = new URL(req.url!);
    const up = connect(Number(u.port || 80), u.hostname, () => {
      up.write(`${req.method} ${u.pathname}${u.search} HTTP/1.1\r\n`);
      for (const [k, v] of Object.entries(req.headers)) if (k !== "proxy-connection") up.write(`${k}: ${Array.isArray(v) ? v.join(", ") : v}\r\n`);
      up.write("\r\n");
      req.pipe(up); up.pipe(res.socket!);
    });
    up.on("error", () => { try { res.writeHead(502); res.end(); } catch { /* closed */ } });
  });
  srv.on("connect", (req, socket, head) => {
    const [host, port] = (req.url ?? "").split(":");
    if (!host || !allowed(host)) { onDeny(host || "?"); socket.end("HTTP/1.1 403 Forbidden\r\n\r\n"); return; }
    const up = connect(Number(port || 443), host, () => { socket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); if (head.length) up.write(head); socket.pipe(up); up.pipe(socket); });
    up.on("error", () => socket.end()); socket.on("error", () => up.end());
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => { const a = srv.address() as { port: number }; resolve({ url: `http://127.0.0.1:${a.port}`, close: () => srv.close() }); }));
}

/** Hosts the verdict's sandbox run saw and the package declared, for --net declared. */
export async function declaredHosts(query: string): Promise<string[]> {
  const r = await resolveSkill(query);
  if (!r.ok || !r.data.trace_summary) return [];
  return r.data.trace_summary.egress_hosts.filter((h) => h.declared).map((h) => h.host);
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
  if (opts.net !== "off") {
    hosts = opts.net === "declared" ? await declaredHosts(opts.query ?? opts.label) : opts.net;
    if (opts.net === "declared" && !hosts.length) log(`no declared hosts on record for ${opts.query ?? opts.label}; network stays open (use --net host1,host2 to pin it)`);
    else proxy = await startAllowlistProxy(hosts, (h) => log(`blocked connection to ${h}`));
  }
  const env = { ...process.env, ...(proxy ? { HTTP_PROXY: proxy.url, HTTPS_PROXY: proxy.url, http_proxy: proxy.url, https_proxy: proxy.url, NO_PROXY: "127.0.0.1,localhost", ALL_PROXY: proxy.url } : {}) };
  log(`guarding ${opts.label}${deny.length ? ` · denying ${opts.deny.join(", ")}` : ""}${proxy ? ` · network limited to ${hosts.join(", ")} (clients that ignore HTTPS_PROXY are not contained)` : ""}`);
  const child = spawn(cmd[0], cmd.slice(1), { stdio: ["pipe", "pipe", "inherit"], env });
  const pending = new Map<number | string, string>();
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
  // server → agent, untouched
  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  return new Promise((resolve) => {
    // Resolve only once everything the server wrote has been relayed and flushed: the process exits right after.
    child.on("close", (code) => { proxy?.close(); log(`${opts.label} exited (${code ?? "signal"}) · ${calls} tool call${calls === 1 ? "" : "s"}, ${deniedCalls} denied`); process.stdout.write("", () => resolve(code ?? 1)); });
    child.on("error", (e) => { proxy?.close(); log(`could not start ${cmd[0]}: ${e.message}`); resolve(1); });
  });
}

/** Parse `run [--deny a,b] [--net …] [--label x] [--query q] -- cmd…` from the raw argv after "run". */
export function parseRunArgs(argv: string[]): { opts: RunOptions; cmd: string[] } | { error: string } {
  const opts: RunOptions = { deny: [], net: "off", label: "" };
  let i = 0;
  while (i < argv.length && argv[i] !== "--") {
    const a = argv[i];
    const val = () => { const v = argv[i + 1]; if (v === undefined || v === "--") throw new Error(`${a} needs a value`); i++; return v; };
    try {
      if (a === "--deny") opts.deny.push(...val().split(",").map((s) => s.trim()).filter(Boolean));
      else if (a === "--net") { const v = val(); opts.net = v === "off" ? "off" : v === "declared" ? "declared" : v.split(",").map((s) => s.trim()).filter(Boolean); }
      else if (a === "--label") opts.label = val();
      else if (a === "--query") opts.query = val();
      else return { error: `unknown option ${a}` };
    } catch (e) { return { error: (e as Error).message }; }
    i++;
  }
  const cmd = argv.slice(i + 1);
  if (argv[i] !== "--" || !cmd.length) return { error: "usage: vet-skills run [--deny tool,glob*] [--net declared|host1,host2|off] -- <command…>" };
  if (!opts.label) {
    // "npx -y @scope/pkg" → "@scope/pkg"; "uvx pkg" → "pkg"; else the binary.
    const pkg = cmd.find((x, k) => k > 0 && !x.startsWith("-") && /^(npx|uvx|pipx|bunx)$/.test(cmd[0])) ?? cmd[0];
    opts.label = pkg; opts.query ??= pkg.replace(/^@/, "").replace(/@[^/]*$/, "");
  }
  return { opts, cmd };
}
