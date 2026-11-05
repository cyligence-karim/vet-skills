import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { connect } from "node:net";
import { parseRunArgs, startAllowlistProxy } from "../src/run.ts";

test("run: argument parsing and label inference", () => {
  const p = parseRunArgs(["--deny", "delete_*,send_email", "--net", "declared", "--", "npx", "-y", "@acme/crm-mcp@1.2.0"]);
  assert.ok(!("error" in p));
  assert.deepEqual(p.opts.deny, ["delete_*", "send_email"]);
  assert.equal(p.opts.net, "declared");
  assert.equal(p.opts.label, "@acme/crm-mcp@1.2.0");
  assert.equal(p.opts.query, "acme/crm-mcp");
  assert.ok("error" in parseRunArgs(["npx", "pkg"]), "needs --");
});

test("run: denied tool calls are answered by the guard, allowed ones reach the server", async () => {
  const fixture = join(mkdtempSync(join(tmpdir(), "vs-run-")), "server.js");
  writeFileSync(fixture, `const rl = require("node:readline").createInterface({ input: process.stdin });
rl.on("line", (line) => { let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1.0.0" } } }) + "\\n");
  if (m.method === "tools/list") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "echo", description: "Echo", inputSchema: { type: "object" } }, { name: "x", description: "", inputSchema: { type: "object" } }] } }) + "\\n");
  if (m.method === "tools/call") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { content: [] } }) + "\\n"); });
rl.on("close", () => process.exit(0));`);
  const child = spawn("node", [join(import.meta.dirname, "../dist/index.js"), "run", "--deny", "x", "--label", "fixture", "--", "node", fixture], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, NODE_TEST_CONTEXT: undefined, VET_SKILLS_HOME: join(import.meta.dirname, "../.tmp-vs-home") } as NodeJS.ProcessEnv });
  let out = "", err = "";
  child.stdout.on("data", (c) => (out += c)); child.stderr.on("data", (c) => (err += c));
  const send = (m: object) => child.stdin.write(JSON.stringify(m) + "\n");
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "x", arguments: { a: 1 } } });
  send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "echo", arguments: { text: "hi" } } });
  const exited = new Promise((r) => child.on("exit", r));
  await new Promise((r) => setTimeout(r, 1500));
  child.stdin.end();
  await exited;
  const lines = out.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const denied = lines.find((l) => l.id === 3);
  assert.ok(denied?.error && /denied/.test(denied.error.message), "denied reply from the guard");
  assert.ok(lines.find((l) => l.id === 2)?.result?.tools?.length === 2, "tools/list passed through");
  assert.match(err, /denied tools\/call x/);
  assert.match(err, /1 denied/);
});

test("run: allow-list proxy refuses CONNECT to other hosts", async () => {
  const denied: string[] = [];
  const p = await startAllowlistProxy(["api.example.com"], (h) => denied.push(h));
  const { port } = new URL(p.url);
  const res = await new Promise<string>((resolve) => {
    const s = connect(Number(port), "127.0.0.1", () => s.write("CONNECT evil.example.org:443 HTTP/1.1\r\nHost: evil.example.org:443\r\n\r\n"));
    let d = ""; s.on("data", (c: Buffer) => (d += c)); s.on("close", () => resolve(d)); s.on("end", () => resolve(d));
  });
  p.close();
  assert.match(res, /403/);
  assert.deepEqual(denied, ["evil.example.org"]);
});

test("run --contain: wraps in the OS sandbox when available, never breaks the command otherwise", async () => {
  const { containWrap, CREDENTIAL_DIRS } = await import("../src/run.ts");
  const w = containWrap(["node", "server.js"], 4321);
  assert.ok(w.cmd.slice(-2).join(" ") === "node server.js", "the server command is preserved at the end");
  assert.ok(CREDENTIAL_DIRS.includes(".ssh") && CREDENTIAL_DIRS.includes(".aws"));
  if (process.platform === "linux" && w.cmd[0] === "bwrap") { assert.ok(w.cmd.includes("--ro-bind") && w.cmd.includes("--die-with-parent")); assert.match(w.note, /contained/); }
  else if (process.platform === "darwin" && w.cmd[0] === "/usr/bin/sandbox-exec") { assert.match(w.cmd[2], /deny file-read\*[^\n]*\.ssh/); assert.match(w.cmd[2], /localhost:4321/); }
  else assert.match(w.note, /unavailable|not available/);
});
