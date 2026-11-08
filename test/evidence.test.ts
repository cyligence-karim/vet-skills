import { test } from "node:test";
import assert from "node:assert/strict";

const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

test("evidence: a startup-only Verified is qualified, lists tested/untested/needs, and recommends the credential broker, never a pasted token", async () => {
  const { renderEvidence, recommendation } = await import("../src/evidence.ts");
  const e = {
    label: "verified" as const, score: 85, name: "mcp-server-supabase",
    coverage: { level: "startup_only" as const, summary: "Started with a decoy SUPABASE_ACCESS_TOKEN and answered initialize; the tool list did not come back. Authenticated tool behavior not tested.", tested: ["server startup with a tagged decoy in SUPABASE_ACCESS_TOKEN", "MCP initialize"], untested: ["the tool list", "what the tools do when called with a real credential"], needs: ["SUPABASE_ACCESS_TOKEN"] },
    egress: [{ host: "api.supabase.com", declared: true, implied: "supabase.com" }], filesRead: [], memoryWrites: 0,
    findings: [{ rule_id: "AST04", severity: "medium", title: "MCP server using network transport (SSE/HTTP)", detail: "dist/x.js:1 · …", file: "dist/x.js", line: 1, evidence: "createServer(" }, { rule_id: "AST06", severity: "medium", title: "npx invocation of non-well-known package", detail: "dist/x.js:286 · …", file: "dist/x.js", line: 286, evidence: "npx -y something" }],
  };
  const out = strip(renderEvidence(e).join("\n"));
  assert.match(out, /Coverage\s+Started with a decoy SUPABASE_ACCESS_TOKEN/);
  assert.match(out, /not tested\s+the tool list/);
  assert.match(out, /needs\s+SUPABASE_ACCESS_TOKEN — give it to the guard with --secrets, never to a chat or a report/);
  assert.match(out, /AST04 medium\s+MCP server using network transport/);
  assert.match(out, /resolves informational for an MCP server/);
  assert.match(out, /resolves pin the package to an exact version/);
  const r = recommendation(e);
  assert.equal(r.verdict, "Install with a scoped credential, under the guard.");
  assert.match(strip(r.detail.join(" ")), /vet-skills run --secrets SUPABASE_ACCESS_TOKEN=supabase\.com -- <the server's command>/);
  assert.match(strip(r.detail.join(" ")), /reached only api\.supabase\.com, its publisher's own host/);
  assert.doesNotMatch(out, /paste (your|the) token here|enter your token/i);
});

test("evidence: blocked, undeclared host, install failure and clean full runs each get a recommendation that follows from the evidence", async () => {
  const { recommendation } = await import("../src/evidence.ts");
  const base = { score: 70, name: "x", filesRead: [], memoryWrites: 0, findings: [], coverage: null, egress: [] };
  assert.equal(recommendation({ ...base, label: "blocked", findings: [{ rule_id: "AST07", severity: "critical", title: "Installer lure: README sends the reader to a committed archive", detail: "" }] }).verdict, "Do not install.");
  const und = recommendation({ ...base, label: "caution", coverage: { level: "full", summary: "Server started and answered tools/list.", tested: [], untested: [], needs: [] }, egress: [{ host: "collect.evil.xyz", declared: false }] });
  assert.equal(und.verdict, "Install only if you know what these hosts are."); assert.match(strip(und.detail.join(" ")), /--net collect\.evil\.xyz/);
  assert.equal(recommendation({ ...base, label: "caution", filesRead: ["~/.aws/credentials"], egress: [{ host: "collect.evil.xyz", declared: false }] }).verdict, "Do not install.");
  assert.equal(recommendation({ ...base, label: "verified", coverage: { level: "install_failed", summary: "Not started: dependency install failed; the server itself was not observed.", tested: [], untested: [], needs: [] } }).verdict, "Treat this as a static verdict.");
  assert.equal(recommendation({ ...base, label: "verified", coverage: { level: "full", summary: "Server started and answered tools/list.", tested: [], untested: [], needs: [] } }).verdict, "Reasonable to install.");
});

test("check output: the label line carries the coverage qualifier and the evidence block", async () => {
  process.env.VET_SKILLS_HOME = (await import("node:fs")).mkdtempSync((await import("node:path")).join((await import("node:os")).tmpdir(), "vs-ev-"));
  const { renderCheck: renderReport } = await import(`../src/check.ts?e=${Date.now()}`);
  const resolved = {
    status: "scored" as const, skill: { name: "mcp-server-supabase", registry: "npm", registry_label: "npm", install_count: 535577, page: "/skills/npm/mcp-server-supabase", kind: "mcp_server" },
    publisher: { handle: "supabase", verified: false, age_days: 16 }, version: { semver: "0.16.1", artifact_hash: "x", declared_permissions: { network: [], filesystem: ["./"], memory: false } },
    verdict: { id: "v", score: 85, label: "verified" as const, duration_ms: 45000, scenarios_run: 2 },
    trace_summary: { egress_hosts: [], files_read: [], files_written: [], memory_writes: [], tool_shadowing: [], coverage: { level: "startup_only" as const, summary: "Startup only; authenticated tool behavior not tested.", tested: ["server startup over stdio (initialize sent)"], untested: ["the tool list (the server exited before answering)"], needs: ["SUPABASE_ACCESS_TOKEN"] } },
    findings: [], last_safe_version: null,
  };
  const out = strip(renderReport({ resolved, decision: { decision: "allow", reason: "score 85 ≥ 70", rules: [], restrictions: undefined } as never, policyLabel: "personal defaults", offline: false } as never));
  assert.match(out, /\[VERIFIED\] 85\/100 · startup only/);
  assert.match(out, /Coverage\s+Startup only; authenticated tool behavior not tested\./);
  assert.match(out, /Recommendation\s+Install with a scoped credential, under the guard\./);
});
