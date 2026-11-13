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

test("guard: Copilot, Kiro, Qwen, Cline, Zed, Amp and OpenCode configs wrap and unwrap", () => {
  const home = mkdtempSync(join(tmpdir(), "vs-guard-more-"));
  for (const d of [".copilot", ".kiro/settings", ".qwen", ".cline/data/settings", ".config/zed", ".config/amp", ".config/opencode"]) mkdirSync(join(home, d), { recursive: true });
  writeFileSync(join(home, ".copilot", "mcp-config.json"), JSON.stringify({ mcpServers: { gh: { type: "local", command: "npx", args: ["-y", "@github/mcp"], tools: ["*"] }, remote: { type: "http", url: "https://x" } } }));
  writeFileSync(join(home, ".kiro", "settings", "mcp.json"), JSON.stringify({ mcpServers: { fs: { command: "uvx", args: ["fs-mcp"], disabled: false, autoApprove: [] } } }));
  writeFileSync(join(home, ".qwen", "settings.json"), JSON.stringify({ hooks: {}, mcpServers: { ctx: { command: "npx", args: ["ctx"] } } }));
  writeFileSync(join(home, ".cline", "data", "settings", "cline_mcp_settings.json"), JSON.stringify({ mcpServers: { brave: { command: "npx", args: ["brave"], env: { K: "v" } } } }));
  writeFileSync(join(home, ".config", "zed", "settings.json"), JSON.stringify({ theme: "One Dark", context_servers: { pg: { command: "npx", args: ["pg-mcp"], env: {} }, old: { command: { path: "x", args: [] } } } }));
  writeFileSync(join(home, ".config", "amp", "settings.json"), JSON.stringify({ "amp.mcpServers": { linear: { command: "npx", args: ["linear-mcp"] } } }));
  writeFileSync(join(home, ".config", "opencode", "opencode.json"), JSON.stringify({ $schema: "https://opencode.ai/config.json", mcp: { servers: { ex: { type: "local", command: ["npx", "-y", "example-mcp"], environment: { K: "{env:K}" } }, rem: { type: "remote", url: "https://x" } } } }));
  process.env.VET_SKILLS_BIN = "/opt/vs/vet-skills";
  const t = installGuard({ home });
  const by = (c: string) => t.find((x) => x.client === c)!;
  assert.deepEqual(by("copilot").wrapped, ["gh"]); assert.equal(by("copilot").skipped[0].name, "remote");
  assert.deepEqual(by("kiro").wrapped, ["fs"]); assert.deepEqual(by("qwen").wrapped, ["ctx"]); assert.deepEqual(by("cline").wrapped, ["brave"]);
  assert.deepEqual(by("zed").wrapped, ["pg"]); assert.match(by("zed").skipped[0].why, /nested/);
  assert.deepEqual(by("amp").wrapped, ["linear"]); assert.deepEqual(by("opencode").wrapped, ["ex"]);
  const oc = JSON.parse(readFileSync(join(home, ".config", "opencode", "opencode.json"), "utf8"));
  assert.deepEqual(oc.mcp.servers.ex.command, ["/opt/vs/vet-skills", "guard", "exec", "--server", "ex", "--client", "opencode", "--", "npx", "-y", "example-mcp"]);
  assert.deepEqual(oc.mcp.servers.ex.environment, { K: "{env:K}" });
  const zed = JSON.parse(readFileSync(join(home, ".config", "zed", "settings.json"), "utf8")); assert.equal(zed.theme, "One Dark"); assert.equal(zed.context_servers.pg.command, "/opt/vs/vet-skills");
  // Idempotent, then uninstall restores every original.
  assert.equal(installGuard({ home }).reduce((n, x) => n + x.wrapped.length, 0), 0);
  assert.equal(uninstallGuard({ home }).reduce((n, x) => n + x.wrapped.length, 0), 7);
  assert.deepEqual(JSON.parse(readFileSync(join(home, ".config", "opencode", "opencode.json"), "utf8")).mcp.servers.ex.command, ["npx", "-y", "example-mcp"]);
  assert.equal(JSON.parse(readFileSync(join(home, ".copilot", "mcp-config.json"), "utf8")).mcpServers.gh.command, "npx");
  delete process.env.VET_SKILLS_BIN;
});

test("guard status names servers added after install; a dry run changes nothing", () => {
  const home = mkdtempSync(join(tmpdir(), "vs-guard-added-"));
  mkdirSync(join(home, ".cursor"), { recursive: true });
  writeFileSync(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { a: { command: "npx", args: ["a"] } } }));
  process.env.VET_SKILLS_BIN = "/opt/vs/vet-skills";
  installGuard({ home });
  const before = readFileSync(join(home, ".cursor", "mcp.json"), "utf8");
  const cfg = JSON.parse(before); cfg.mcpServers.b = { command: "uvx", args: ["b-mcp"] }; writeFileSync(join(home, ".cursor", "mcp.json"), JSON.stringify(cfg));
  const dry = installGuard({ home, dryRun: true });
  assert.deepEqual(dry.flatMap((t) => t.wrapped), ["b"]);
  assert.equal(JSON.parse(readFileSync(join(home, ".cursor", "mcp.json"), "utf8")).mcpServers.b.command, "uvx", "dry run did not write");
  const status = guardStatus({ home }).join("\n");
  assert.match(status, /1 stdio server configured since then and NOT under the guard: b \(cursor\)/);
  installGuard({ home });
  assert.ok(!/NOT under the guard/.test(guardStatus({ home }).join("\n")));
  delete process.env.VET_SKILLS_BIN;
});

test("live revocation: a version revoked mid-session is stopped (kill) or announced (warn); pending calls get the reason", async () => {
  const { createServer } = await import("node:http");
  let revoked = false;
  const api = createServer((req, res) => {
    if (req.url?.startsWith("/api/v1/runtime/launch-check")) { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(revoked ? { state: "revoked", reason: "confirmed exfiltration in 1.0.0", page: "/threats" } : { state: "clear", reason: null, page: null })); return; }
    res.statusCode = 404; res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));
  const port = (api.address() as { port: number }).port;
  const dir = mkdtempSync(join(tmpdir(), "vs-guard-revoke-"));
  const fixture = join(dir, "server.js");
  // A server that answers quickly except for slow_export, which never answers: that call is pending when the revocation lands.
  writeFileSync(fixture, `const rl = require("node:readline").createInterface({ input: process.stdin });
rl.on("line", (line) => { let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1.0.0" } } }) + "\\n");
  if (m.method === "tools/call" && m.params.name !== "slow_export") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "ok" }] } }) + "\\n"); });
process.on("SIGTERM", () => process.exit(0));`);
  const run = async (mode: "kill" | "warn") => {
    revoked = false;
    const vsHome = mkdtempSync(join(dir, `home-${mode}-`));
    writeFileSync(join(vsHome, "policy.yaml"), `name: p\nversion: 1\nruntime:\n  network: observe\n  revoke_running: ${mode}\n`);
    const child = spawn("node", [join(import.meta.dirname, "../dist/index.js"), "guard", "exec", "--server", "fixture", "--client", "test", "--", "node", fixture], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, VET_SKILLS_HOME: vsHome, KILLERSKILLS_API: `http://127.0.0.1:${port}`, VET_SKILLS_TELEMETRY: "0", VET_SKILLS_REVOKE_POLL_MS: "5000", NODE_TEST_CONTEXT: undefined } as NodeJS.ProcessEnv });
    let out = "", err = "";
    child.stdout.on("data", (c) => (out += c)); child.stderr.on("data", (c) => (err += c));
    const closed = new Promise<number | null>((r) => child.on("close", r));
    const send = (m: unknown) => { if (!child.stdin.destroyed) child.stdin.write(JSON.stringify(m) + "\n"); };
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "slow_export", arguments: {} } });
    await new Promise((r) => setTimeout(r, 1500));
    revoked = true;
    await new Promise((r) => setTimeout(r, 6500));
    if (mode === "warn") { send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "ping", arguments: {} } }); await new Promise((r) => setTimeout(r, 500)); child.stdin.end(); }
    const code = await Promise.race([closed, new Promise<string>((r) => setTimeout(() => r("timeout"), 8000))]);
    if (code === "timeout") child.kill("SIGKILL");
    const lines = out.split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const log = readFileSync(join(vsHome, "runtime", "guard.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    return { code, err, lines, log };
  };
  try {
  const k = await run("kill");
  assert.notEqual(k.code, "timeout", "guard exits once the server is stopped");
  assert.match(k.lines.find((l) => l.id === 2)?.error?.message ?? "", /Server stopped by the guard: .*revoked while running: confirmed exfiltration/);
  assert.match(k.err, /stopping fixture: .* · 1 pending call answered with the reason/);
  assert.ok(k.log.some((e) => e.kind === "revoked_running" && e.action === "kill"));
  const w = await run("warn");
  assert.match(w.err, /revoked while running.*keeps running \(policy runtime\.revoke_running: warn\)/);
  assert.equal(w.lines.find((l) => l.id === 3)?.result?.content?.[0]?.text, "ok", "warn mode leaves the server answering");
  assert.ok(!w.lines.some((l) => l.id === 2 && l.error), "the pending call was not cancelled in warn mode");
  } finally { api.closeAllConnections(); api.close(); }
});

test("update check: a new version that reaches for more is announced (warn) or held until approved (hold); an identical one just runs", async () => {
  const { createServer } = await import("node:http");
  let current = "1.0.15"; let escalates = true; const diffCalls: string[] = [];
  const api = createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    const u = new URL(req.url ?? "/", "http://x");
    if (u.pathname === "/api/v1/resolve") { res.end(JSON.stringify({ skill: { name: "postmark-mcp", registry: "npm", page: "/skills/npm/postmark-mcp", kind: "mcp_server" }, version: { semver: current, declared_permissions: { network: [], filesystem: [], memory: false } }, verdict: { label: "verified", score: 88 }, incident: null, credentials: null, trace_summary: { coverage: { level: "full", needs: [] } } })); return; }
    if (u.pathname === "/api/v1/runtime/launch-check") { res.end(JSON.stringify({ state: "clear", reason: null, page: null })); return; }
    if (u.pathname === "/api/v1/diff") { diffCalls.push(`${u.searchParams.get("from")}→${u.searchParams.get("to")}`); res.end(JSON.stringify({ package: "postmark-mcp", registry: "npm", from: u.searchParams.get("from"), to: u.searchParams.get("to"), added: { hosts: escalates ? ["giftshop.club"] : [], tools: [], credentialEnv: [], credentialFiles: [], installScripts: [], memoryWrites: [] }, removed: { hosts: [], tools: [], credentialEnv: [], credentialFiles: [] }, changedTools: escalates ? ["send_email"] : [], escalates, comparable: true, notes: [], summary: escalates ? "1 new host (giftshop.club) · 1 rewritten tool descriptor (send_email)" : "nothing new reached for", from_verdict: null, to_verdict: null })); return; }
    res.statusCode = 404; res.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));
  const port = (api.address() as { port: number }).port;
  const dir = mkdtempSync(join(tmpdir(), "vs-guard-update-"));
  const fixture = join(dir, "server.js");
  writeFileSync(fixture, `const rl = require("node:readline").createInterface({ input: process.stdin });
rl.on("line", (line) => { let m; try { m = JSON.parse(line); } catch { return; } if (m.method === "initialize") process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { serverInfo: { name: "f" } } }) + "\\n"); });
rl.on("close", () => process.exit(0));`);
  const vsHome = join(dir, "home"); mkdirSync(vsHome, { recursive: true });
  const cli = join(import.meta.dirname, "../dist/index.js");
  const env = { ...process.env, VET_SKILLS_HOME: vsHome, KILLERSKILLS_API: `http://127.0.0.1:${port}`, VET_SKILLS_TELEMETRY: "0", NODE_TEST_CONTEXT: undefined } as NodeJS.ProcessEnv;
  const policy = (mode: string) => writeFileSync(join(vsHome, "policy.yaml"), `name: p\nversion: 1\nruntime:\n  network: observe\n  on_change: ${mode}\n`);
  const launch = async () => {
    const child = spawn("node", [cli, "guard", "exec", "--server", "postmark", "--client", "test", "--", "node", fixture], { stdio: ["pipe", "pipe", "pipe"], env });
    let out = "", err = ""; child.stdout.on("data", (c) => (out += c)); child.stderr.on("data", (c) => (err += c));
    const closed = new Promise<number | null>((r) => child.on("close", r));
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n");
    await new Promise((r) => setTimeout(r, 1200)); if (!child.stdin.destroyed) child.stdin.end();
    return { code: await closed, out, err };
  };
  const pins = () => JSON.parse(readFileSync(join(vsHome, "guard", "pins.json"), "utf8"));
  try {
    policy("warn");
    const first = await launch(); assert.equal(first.code, 0, first.err); assert.equal(pins()["npm:postmark-mcp"].semver, "1.0.15"); assert.equal(diffCalls.length, 0, "first run sets the baseline without a comparison");
    // Warn: launches, says what changed, moves the baseline.
    current = "1.0.16";
    const warned = await launch(); assert.equal(warned.code, 0, warned.err);
    assert.match(warned.err, /postmark-mcp 1\.0\.15 → 1\.0\.16 reaches for more than the version last run here: 1 new host \(giftshop\.club\)/);
    assert.match(warned.out, /"id":1/); assert.equal(pins()["npm:postmark-mcp"].semver, "1.0.16"); assert.deepEqual(diffCalls, ["1.0.15→1.0.16"]);
    // Hold: refuses to launch, the server never starts, the baseline stays.
    policy("hold"); current = "1.0.17";
    const held = await launch(); assert.equal(held.code, 1);
    assert.match(held.err, /holding postmark: .*Policy runtime\.on_change: hold — to accept it: vet-skills guard approve postmark-mcp/);
    assert.equal(held.out, "", "nothing was relayed from a held server"); assert.equal(pins()["npm:postmark-mcp"].semver, "1.0.16");
    // Approve on a personal machine, then it launches and the baseline moves.
    const ap = await new Promise<string>((r) => { const c = spawn("node", [cli, "guard", "approve", "postmark-mcp"], { env }); let o = ""; c.stdout.on("data", (d) => (o += d)); c.on("close", () => r(o)); });
    assert.match(ap, /next version of postmark-mcp to launch will be accepted/);
    const after = await launch(); assert.equal(after.code, 0, after.err); assert.match(after.err, /1\.0\.16 → 1\.0\.17 accepted/); assert.equal(pins()["npm:postmark-mcp"].semver, "1.0.17");
    // Hold with an update that reaches for nothing new: runs without asking anyone.
    escalates = false; current = "1.0.18";
    const quiet = await launch(); assert.equal(quiet.code, 0, quiet.err); assert.match(quiet.err, /1\.0\.17 → 1\.0\.18: nothing new reached for/); assert.equal(pins()["npm:postmark-mcp"].semver, "1.0.18");
    // The diff command prints it and exits 3 on escalation.
    escalates = true;
    const dc = await new Promise<{ code: number | null; o: string }>((r) => { const c = spawn("node", [cli, "diff", "postmark-mcp", "1.0.15", "1.0.16"], { env }); let o = ""; c.stdout.on("data", (d) => (o += d)); c.on("close", (code) => r({ code, o })); });
    assert.equal(dc.code, 3); assert.match(dc.o, /\+ hosts\s+giftshop\.club/); assert.match(dc.o, /~ rewritten descriptors\s+send_email/);
  } finally { api.closeAllConnections(); api.close(); }
});
