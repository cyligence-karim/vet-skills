import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const vsHome = join(mkdtempSync(join(tmpdir(), "vs-ptest-")), ".vet-skills");
process.env.VET_SKILLS_HOME = vsHome;
const { localRecord, testPolicy, renderTest, renderSuggestion, parseSince } = await import("../src/policytest.ts");
const { parsePolicyYaml, suggestPolicy, replayTools, DEFAULT_POLICY } = await import("../src/policy/index.js");

const at = (d: number, h = 10) => new Date(Date.UTC(2026, 10, d, h)).toISOString();
const call = (d: number, server: string, tool: string, action = "allowed") => ({ at: at(d), kind: "tool_call", session: `s${d}`, server, tool, args: ["id"], action });
/** A known observe log: two servers, used and never-used tools, one unexpected host, one changed tool list. */
const LOG: Record<string, unknown>[] = [
  { at: at(1), kind: "start", session: "s1", server: "github" },
  { at: at(1), kind: "tools", session: "s1", server: "github", tools: [{ name: "list_issues", ro: true }, { name: "create_issue" }, { name: "delete_repo" }, { name: "merge_pull_request" }, { name: "search_code" }] },
  { at: at(1), kind: "tools", session: "s1", server: "db", tools: [{ name: "run_query" }, { name: "drop_table" }, { name: "describe_table" }] },
  ...[1, 2, 3, 4].map((d) => call(d, "github", "list_issues")),
  call(2, "github", "create_issue"), call(3, "github", "create_issue"),
  call(3, "db", "run_query"), call(4, "db", "run_query"), call(5, "db", "run_query"),
  { ...call(5, "db", "drop_table", "held") }, { ...call(5, "db", "drop_table", "approved") },
  { at: at(4), kind: "host", session: "s4", server: "db", host: "collect.example.net", port: 443, mode: "tunnel", expected: false },
  { at: at(5), kind: "remote_changed", session: "s5", server: "tracker", added: ["export_all"], rewritten: [] },
];

test("a policy that denies one tool: the report shows exactly the calls to that tool as denied and nothing else", () => {
  const rec = localRecord(LOG);
  assert.deepEqual(rec.calls.map((c) => [`${c.server}/${c.tool}`, c.calls, c.allowed, c.held, c.denied]).sort(), [["db/drop_table", 1, 0, 1, 0], ["db/run_query", 3, 3, 0, 0], ["github/create_issue", 2, 2, 0, 0], ["github/list_issues", 4, 4, 0, 0]]);
  const policy = parsePolicyYaml("name: strict\nversion: 3\nruntime:\n  new_host: block\n  on_change: hold\n  tools:\n    - match: 'github/create_issue'\n      action: deny\n      reason: tickets go through the tracker\n");
  const r = testPolicy(policy, rec, 30);
  assert.deepEqual(r.tools.rows.filter((x) => x.outcome === "deny").map((x) => [x.server, x.tool, x.calls, x.rule, x.changed]), [["github", "create_issue", 2, "github/create_issue", 2]]);
  assert.deepEqual(r.tools.totals, { calls: 10, allow: 8, hold: 0, deny: 2, changed: 3, servers: 2, tools: 4 });
  assert.equal(r.tools.rows.find((x) => x.tool === "drop_table")!.changed, 1, "a call that was held then would be allowed now");
  assert.deepEqual([r.network.unexpected_hosts, r.network.outcome, r.changes.count, r.changes.outcome], [1, "deny", 1, "hold"]);
  assert.match(r.next, /Look at the 1 tool this policy would deny that was actually used \(github\/create_issue\)/);
  const text = renderTest(r);
  assert.match(text, /strict v3 replayed on this machine's guard log, last 30 days: 5 sessions, 10 tool calls across 2 servers/);
  assert.match(text, /deny\s+github\/create_issue\s+2×\s+rule github\/create_issue \(tickets go through the tracker\) · 2 would change/);
  assert.match(text, /Nothing was changed/);
});

test("suggest then test on the same log: nothing that was used is denied, and every rule names the calls behind it", () => {
  const rec = localRecord(LOG);
  const s = suggestPolicy(rec.calls, rec.listed);
  assert.deepEqual(s.rules.map((r) => `${r.action} ${r.match}`), [
    "allow db/drop_table", "allow db/run_query", "allow github/create_issue", "allow github/list_issues",
    "deny github/delete_repo", "approve github/merge_pull_request",
  ]);
  assert.equal(s.rules.find((r) => r.match === "github/list_issues")!.evidence, "4 recorded calls, last 2026-11-04");
  assert.equal(s.rules.find((r) => r.match === "github/delete_repo")!.evidence, "listed by the server, 0 recorded calls");
  assert.ok(!s.rules.some((r) => /search_code|describe_table/.test(r.match)), "never-used reads get no rule");
  const yaml = renderSuggestion(DEFAULT_POLICY, s, 30);
  assert.match(yaml, /match: "?github\/list_issues"?\s+# 4 recorded calls, last 2026-11-04/);
  const policy = parsePolicyYaml(yaml);
  assert.equal(policy.runtime.onChange, "hold");
  const r = testPolicy(policy, rec, 30);
  assert.deepEqual([r.tools.totals.deny, r.tools.totals.hold, r.tools.totals.allow], [0, 0, 10]);
  assert.match(r.next, /Safe to publish: none of the 10 recorded calls would have been held or denied/);
  assert.deepEqual(suggestPolicy(rec.calls, rec.listed), s, "deterministic");
});

test("groups, empty logs and the since flag", () => {
  const r = replayTools({ tools: [{ match: "delete_*", action: "approve" }], defaultToolAction: "allow" }, [
    { server: "gh", tool: "delete_branch", calls: 3, allowed: 3, held: 0, denied: 0, group: "platform" },
    { server: "gh", tool: "list_prs", calls: 9, allowed: 9, held: 0, denied: 0, group: "platform" },
    { server: "gh", tool: "delete_branch", calls: 1, allowed: 1, held: 0, denied: 0, group: "data" },
  ]);
  assert.deepEqual(r.byGroup, [{ group: "platform", calls: 12, allow: 9, hold: 3, deny: 0 }, { group: "data", calls: 1, allow: 0, hold: 1, deny: 0 }]);
  assert.equal(r.rows[0].calls, 4);
  const empty = testPolicy(DEFAULT_POLICY, localRecord([]), 7);
  assert.match(empty.next, /no recorded activity/);
  assert.deepEqual([parseSince("7d"), parseSince("12h"), parseSince("2w"), parseSince("5"), parseSince("nonsense"), parseSince(undefined)], [7, 0.5, 14, 5, 30, 30]);
});

test("the built CLI: policy suggest writes a file, policy test reads it, neither changes the policy in force", () => {
  mkdirSync(join(vsHome, "runtime"), { recursive: true });
  const now = Date.now();
  writeFileSync(join(vsHome, "runtime", "guard.jsonl"), LOG.map((e, i) => JSON.stringify({ ...e, at: new Date(now - (LOG.length - i) * 60_000).toISOString() })).join("\n") + "\n");
  const env = { ...process.env, VET_SKILLS_HOME: vsHome, KILLERSKILLS_API: "http://127.0.0.1:9", NODE_TEST_CONTEXT: undefined } as NodeJS.ProcessEnv;
  const run = (...args: string[]) => spawnSync("node", [join(import.meta.dirname, "../dist/index.js"), ...args], { encoding: "utf8", env });
  const before = run("policy", "show").stdout;
  const out = join(vsHome, "suggested.yaml");
  const s = run("policy", "suggest", "--out", out);
  assert.equal(s.status, 0, s.stderr); assert.match(s.stdout, /4 tools allowed by name, 1 held, 1 denied\. Nothing is in force yet/);
  assert.match(readFileSync(out, "utf8"), /^# Suggested by vet-skills policy suggest/);
  const t = run("policy", "test", out, "--since", "7d");
  assert.equal(t.status, 0, t.stderr); assert.match(t.stdout, /Safe to publish/);
  const j = JSON.parse(run("policy", "test", out, "--json").stdout); assert.equal(j.tools.totals.deny, 0);
  assert.equal(run("policy", "show").stdout, before, "the policy in force is untouched");
  assert.equal(run("policy", "test").status, 2);
  assert.equal(run("policy", "test", out, "--org-wide").status, 1, "org-wide needs an enrolled machine");
});
