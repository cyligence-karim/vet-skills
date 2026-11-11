import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";

const home = mkdtempSync(join(tmpdir(), "vs-guard-home-"));
process.env.VET_SKILLS_HOME = join(home, ".vet-skills");
process.env.VET_SKILLS_BIN = "/opt/vet-skills/bin/vet-skills";
const { configSpecs, installGuard, uninstallGuard, wrappedServers, guardStatus, rewriteCodexToml, parseExecArgs, registrableDomain, unwrapEntry, isWrapped } = await import("../src/guard.ts");

test("guard install wraps every stdio server in every client config, idempotently, and uninstall restores the originals", () => {
  mkdirSync(join(home, ".cursor"), { recursive: true }); mkdirSync(join(home, ".codex"), { recursive: true }); mkdirSync(join(home, ".gemini"), { recursive: true }); mkdirSync(join(home, ".grok"), { recursive: true });
  writeFileSync(join(home, ".grok", "config.toml"), `[models]\ndefault = "grok-code"\n\n[mcp_servers.linear]\ncommand = "npx"\nargs = ["-y", "linear-mcp"]\n`);
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { supabase: { command: "npx", args: ["-y", "@supabase/mcp-server-supabase"], env: { SUPABASE_ACCESS_TOKEN: "x" } }, remote: { type: "http", url: "https://mcp.example/sse" } }, projects: { "/work/app": { mcpServers: { fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/work/app"] } } } } }));
  writeFileSync(join(home, ".cursor", "mcp.json"), `{\n  // cursor allows comments\n  "mcpServers": { "github": { "command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"], },\n  }\n}\n`);
  writeFileSync(join(home, ".gemini", "settings.json"), JSON.stringify({ theme: "dark", mcpServers: { ctx7: { command: "npx", args: ["-y", "@upstash/context7-mcp"] } } }));
  writeFileSync(join(home, ".codex", "config.toml"), `model = "o3"\n\n[mcp_servers.sentry]\ncommand = "npx"\nargs = ["-y", "@sentry/mcp-server"]\nenv = { SENTRY_TOKEN = "t" }\n\n[mcp_servers.plain]\ncommand = "uvx"\n\n[other]\nx = 1\n`);
  const specs = configSpecs({ home });
  assert.deepEqual(specs.map((s) => s.client).sort(), ["claude-code", "codex", "cursor", "gemini", "grok"]);
  const t = installGuard({ home });
  assert.deepEqual(t.find((x) => x.client === "claude-code")?.wrapped, ["supabase", "fs"]);
  assert.equal(t.find((x) => x.client === "claude-code")?.skipped[0]?.name, "remote");
  assert.equal(wrappedServers({ home }).length, 7);
  assert.deepEqual(t.find((x) => x.client === "grok")?.wrapped, ["linear"]);
  assert.match(readFileSync(join(home, ".grok", "config.toml"), "utf8"), /"--client", "grok", "--", "npx", "-y", "linear-mcp"/);
  assert.deepEqual(installGuard({ home }).reduce((n, x) => n + x.wrapped.length, 0), 0, "idempotent");
  const st = guardStatus({ home }); assert.match(st[0], /7 MCP servers under the guard/);
  assert.equal(uninstallGuard({ home }).reduce((n, x) => n + x.wrapped.length, 0), 7);
  assert.equal(wrappedServers({ home }).length, 0);
  assert.equal(JSON.parse(readFileSync(join(home, ".claude.json"), "utf8")).mcpServers.supabase.command, "npx");
});

test("guard: json configs round-trip through wrap and unwrap (helpers)", () => {
  const e = { command: "npx", args: ["-y", "@supabase/mcp-server-supabase"], env: { T: "x" } };
  const wrapped = { ...e, command: "/opt/vet-skills/bin/vet-skills", args: ["guard", "exec", "--server", "supabase", "--client", "cursor", "--", "npx", "-y", "@supabase/mcp-server-supabase"] };
  assert.ok(isWrapped(wrapped)); assert.ok(!isWrapped(e));
  assert.deepEqual(unwrapEntry(wrapped), e);
  assert.equal(unwrapEntry(e), null);
});

test("guard: codex toml rewrite touches only command/args lines and round-trips", () => {
  const toml = `model = "o3"\n\n[mcp_servers.sentry]\ncommand = "npx"\nargs = ["-y", "@sentry/mcp-server"]\nenv = { SENTRY_TOKEN = "t" }\n\n[mcp_servers.plain]\ncommand = "uvx"\n\n[other]\nx = 1\n`;
  const bin = { command: "/opt/vet-skills/bin/vet-skills", prefix: [] };
  const w = rewriteCodexToml(toml, "wrap", bin);
  assert.deepEqual(w.wrapped, ["sentry", "plain"]);
  assert.match(w.text, /\[mcp_servers\.sentry\]\ncommand = "\/opt\/vet-skills\/bin\/vet-skills"\nargs = \["guard", "exec", "--server", "sentry", "--client", "codex", "--", "npx", "-y", "@sentry\/mcp-server"\]\nenv = \{ SENTRY_TOKEN = "t" \}/);
  assert.match(w.text, /\[mcp_servers\.plain\]\ncommand = "\/opt\/vet-skills\/bin\/vet-skills"\nargs = \["guard", "exec", "--server", "plain", "--client", "codex", "--", "uvx"\]/);
  assert.match(w.text, /\[other\]\nx = 1/);
  const again = rewriteCodexToml(w.text, "wrap", bin);
  assert.deepEqual(again.wrapped, []);
  const u = rewriteCodexToml(w.text, "unwrap", bin);
  assert.deepEqual(u.wrapped, ["sentry", "plain"]);
  assert.match(u.text, /\[mcp_servers\.sentry\]\ncommand = "npx"\nargs = \["-y", "@sentry\/mcp-server"\]\nenv/);
  assert.match(u.text, /\[mcp_servers\.plain\]\ncommand = "uvx"\n\n\[other\]/);
});

test("guard exec: argument parsing and domain binding", () => {
  const a = parseExecArgs(["--server", "supabase", "--client", "cursor", "--", "npx", "-y", "@supabase/mcp-server-supabase"]);
  assert.ok(!("error" in a)); assert.equal(a.server, "supabase"); assert.equal(a.client, "cursor"); assert.deepEqual(a.cmd, ["npx", "-y", "@supabase/mcp-server-supabase"]);
  assert.ok("error" in parseExecArgs(["--server", "x", "npx"]));
  assert.equal(registrableDomain("api.supabase.com"), "supabase.com");
  assert.equal(registrableDomain("https://api.example.co.uk/v1"), "example.co.uk");
  assert.equal(registrableDomain("github.com"), "github.com");
});

test("guard install/uninstall against a fake home via the built CLI", async () => {
  // The real entry point reads homedir(); point HOME (and USERPROFILE) at the fixture so configSpecs finds the files above.
  const run = (args: string[]) => new Promise<{ code: number | null; out: string; err: string }>((res) => {
    const ch = spawn("node", [join(import.meta.dirname, "../dist/index.js"), ...args], { env: { ...process.env, HOME: home, USERPROFILE: home, VET_SKILLS_HOME: join(home, ".vet-skills"), VET_SKILLS_BIN: "/opt/vet-skills/bin/vet-skills", NODE_TEST_CONTEXT: undefined } as NodeJS.ProcessEnv });
    let out = "", err = ""; ch.stdout.on("data", (c) => (out += c)); ch.stderr.on("data", (c) => (err += c)); ch.on("close", (code) => res({ code, out, err }));
  });
  const r1 = await run(["guard", "install"]);
  assert.equal(r1.code, 0, r1.err);
  assert.match(r1.out, /claude-code: supabase, fs now run under the guard/);
  assert.match(r1.out, /remote skipped — remote server/);
  assert.match(r1.out, /cursor: github now run/); assert.match(r1.out, /gemini: ctx7 now run/); assert.match(r1.out, /codex: sentry, plain now run/);
  const claude = JSON.parse(readFileSync(join(home, ".claude.json"), "utf8"));
  assert.equal(claude.mcpServers.supabase.command, "/opt/vet-skills/bin/vet-skills");
  assert.deepEqual(claude.mcpServers.supabase.args.slice(0, 6), ["guard", "exec", "--server", "supabase", "--client", "claude-code"]);
  assert.deepEqual(claude.mcpServers.supabase.env, { SUPABASE_ACCESS_TOKEN: "x" }, "env is untouched: the guard brokers it at launch");
  assert.equal(claude.mcpServers.remote.url, "https://mcp.example/sse");
  assert.equal(claude.projects["/work/app"].mcpServers.fs.args.at(-1), "/work/app");
  const cursor = JSON.parse(readFileSync(join(home, ".cursor", "mcp.json"), "utf8"));
  assert.equal(cursor.mcpServers.github.args.at(-1), "ghcr.io/github/github-mcp-server");
  const r2 = await run(["guard", "install"]);
  assert.match(r2.out, /already under the guard/);
  const st = await run(["guard", "status"]);
  assert.match(st.out, /7 MCP servers under the guard/);
  const r3 = await run(["guard", "uninstall"]);
  assert.equal(r3.code, 0, r3.err);
  const back = JSON.parse(readFileSync(join(home, ".claude.json"), "utf8"));
  assert.equal(back.mcpServers.supabase.command, "npx"); assert.deepEqual(back.mcpServers.supabase.args, ["-y", "@supabase/mcp-server-supabase"]);
  assert.match(readFileSync(join(home, ".codex", "config.toml"), "utf8"), /\[mcp_servers\.sentry\]\ncommand = "npx"\nargs = \["-y", "@sentry\/mcp-server"\]/);
  assert.equal(wrappedServers({}).length >= 0, true);
});

test("guard exec runs a server under the guard in observe mode, records hosts and tool calls, and applies tool rules", async () => {
  const dir = mkdtempSync(join(tmpdir(), "vs-guard-exec-"));
  const fixture = join(dir, "server.js");
  writeFileSync(fixture, `const rl = require("node:readline").createInterface({ input: process.stdin });
rl.on("line", (line) => { let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1.0.0" } } }) + "\\n");
  if (m.method === "tools/list") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "list_rows", description: "List", inputSchema: { type: "object" } }, { name: "delete_table", description: "Delete", inputSchema: { type: "object" } }] } }) + "\\n");
  if (m.method === "tools/call") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "ok " + m.params.name }] } }) + "\\n"); });
rl.on("close", () => process.exit(0));`);
  const vsHome = join(dir, "vs-home"); mkdirSync(vsHome, { recursive: true });
  // A strict personal policy: destructive tools denied (no approver on a personal machine), everything observed.
  writeFileSync(join(vsHome, "policy.yaml"), "name: strict\nversion: 1\nruntime:\n  network: observe\n  tools:\n    - match: 'delete_*'\n      action: deny\n      reason: destructive\n");
  const child = spawn("node", [join(import.meta.dirname, "../dist/index.js"), "guard", "exec", "--server", "fixture", "--client", "test", "--", "node", fixture], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, VET_SKILLS_HOME: vsHome, KILLERSKILLS_API: "http://127.0.0.1:9", VET_SKILLS_TELEMETRY: "0", NODE_TEST_CONTEXT: undefined } as NodeJS.ProcessEnv });
  let out = "", err = "";
  child.stdout.on("data", (c) => (out += c)); child.stderr.on("data", (c) => (err += c));
  const send = (m: unknown) => child.stdin.write(JSON.stringify(m) + "\n");
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_rows", arguments: { table: "users" } } });
  send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "delete_table", arguments: { table: "users" } } });
  await new Promise((r) => setTimeout(r, 1500));
  child.stdin.end();
  const code = await new Promise<number | null>((r) => child.on("close", r));
  assert.equal(code, 0, err);
  const lines = out.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(lines.find((l) => l.id === 3)?.result?.content?.[0]?.text, "ok list_rows");
  assert.match(lines.find((l) => l.id === 4)?.error?.message ?? "", /denied by your organization's runtime policy: destructive/);
  assert.match(err, /fixture → .* no verdict on record/);
  assert.match(err, /denied tools\/call delete_table \(policy: delete_\*\)/);
  const log = readFileSync(join(vsHome, "runtime", "guard.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  assert.ok(log.some((e) => e.kind === "start" && e.server === "fixture"));
  assert.ok(log.some((e) => e.kind === "tool_call" && e.tool === "list_rows" && e.action === "allowed"));
  assert.ok(log.some((e) => e.kind === "tool_call" && e.tool === "delete_table" && e.action === "denied"));
  assert.ok(log.some((e) => e.kind === "session" && e.tools === 2));
});
