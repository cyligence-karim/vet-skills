import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
process.env.VET_SKILLS_HOME = join(mkdtempSync(join(tmpdir(), "vs-scoped-")), ".vet-skills");
const { perToolHooks } = await import("../src/guard.ts");
const { toolClass, parsePolicyYaml: parsePolicy, serializePolicyYaml: serializePolicy } = await import("../src/policy/index.js");
import type { SecretBinding } from "../src/broker.ts";
import type { Minted } from "../src/exchange.ts";

test("tool class: the policy's globs, then the server's annotation, then the name", () => {
  assert.equal(toolClass("list_issues"), "read");
  assert.equal(toolClass("get-file"), "read");
  assert.equal(toolClass("getRepo"), "read");
  assert.equal(toolClass("create_issue"), "write");
  assert.equal(toolClass("getaway_plan"), "write", "a read verb must be followed by a separator");
  assert.equal(toolClass("run_query"), "write", "anything not plainly a read is a write");
  assert.equal(toolClass("github/list_issues"), "read", "a server/ prefix is ignored");
  assert.equal(toolClass("sync", { readOnlyHint: true }), "read");
  assert.equal(toolClass("list_and_purge", { readOnlyHint: false }), "write");
  assert.equal(toolClass("list_issues", { readOnlyHint: true }, { writeTools: ["list_*"] }), "write", "the policy has the last word");
  assert.equal(toolClass("run_report", null, { readTools: ["run_report"] }), "read");
});

test("policy: scope per_tool and its overrides survive a round trip", () => {
  const p = parsePolicy("name: p\nversion: 1\nruntime:\n  exchange:\n    - var: GITHUB_TOKEN\n      kind: github_app\n      scope: per_tool\n      read_permissions: { contents: read }\n      write_tools: ['merge_*']\n    - var: AWS_ACCESS_KEY_ID\n      kind: aws_sts\n      role_arn: arn:aws:iam::1:role/dev\n      scope: per_tool\n      read_policy_arns: ['arn:aws:iam::aws:policy/job-function/ViewOnlyAccess']\n");
  assert.deepEqual([p.runtime.exchange[0].scope, p.runtime.exchange[0].readPermissions, p.runtime.exchange[0].writeTools], ["per_tool", { contents: "read" }, ["merge_*"]]);
  assert.deepEqual(p.runtime.exchange[1].readPolicyArns, ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"]);
  assert.deepEqual(parsePolicy(serializePolicy(p)).runtime.exchange, p.runtime.exchange);
});

test("per-tool credentials: read-only until a write call is in flight, read-only again when the last one returns", async () => {
  const live: SecretBinding[] = [{ name: "GITHUB_TOKEN", host: "api.github.com", value: "read-1", placeholder: "vsk_x" }];
  const read: Minted = { values: { GITHUB_TOKEN: "read-1" }, host: "api.github.com", expiresAt: new Date(Date.now() + 3600_000), kind: "github_app", scope: "r", access: "read" };
  const scoped = [{ rule: { var: "GITHUB_TOKEN", kind: "github_app" as const, scope: "per_tool" as const }, read, full: null as Minted | null, writers: new Set<number | string>() }];
  let mints = 0; let fail = false; const events: Record<string, unknown>[] = []; const logs: string[] = [];
  const mintFn = (async () => { if (fail) throw new Error("GitHub said no"); mints++; return { values: { GITHUB_TOKEN: `write-${mints}` }, host: "api.github.com", expiresAt: new Date(Date.now() + 3600_000), kind: "github_app", scope: "w", access: "full" } as Minted; }) as never;
  const h = perToolHooks(scoped, () => live, (l) => logs.push(l), (e) => events.push(e), mintFn);
  h.onTools!([{ name: "sync_now", annotations: { readOnlyHint: true } }]);

  assert.equal(await h.beforeCall!("list_issues", 1), null);
  assert.equal(await h.beforeCall!("sync_now", 2), null);
  assert.deepEqual([live[0].value, mints], ["read-1", 0], "reads never mint or raise");

  assert.equal(await h.beforeCall!("create_issue", 3), null);
  assert.deepEqual([live[0].value, mints], ["write-1", 1]);
  assert.equal(await h.beforeCall!("merge_pull_request", 4), null);
  assert.equal(mints, 1, "the write token is reused while it is valid");
  h.afterCall!("create_issue", 3);
  assert.equal(live[0].value, "write-1", "still raised: another write is in flight");
  h.afterCall!("list_issues", 1);
  assert.equal(live[0].value, "write-1");
  h.afterCall!("merge_pull_request", 4);
  assert.equal(live[0].value, "read-1", "lowered when the last write returned");
  assert.deepEqual(events.map((e) => [e.kind, e.tool, e.name]), [["credential_raised", "create_issue", "GITHUB_TOKEN"]]);
  assert.ok(!JSON.stringify(events).includes("write-1") && !logs.join("\n").includes("write-1"), "no token value in events or logs");

  scoped[0].full = { ...scoped[0].full!, expiresAt: new Date(Date.now() + 5_000) };
  assert.equal(await h.beforeCall!("delete_branch", 5), null);
  assert.deepEqual([live[0].value, mints], ["write-2", 2], "a token about to expire is minted again");
  h.afterCall!("delete_branch", 5);

  fail = true; scoped[0].full = null;
  assert.match((await h.beforeCall!("create_issue", 6))!, /it is a write, and a write-capable github app credential could not be minted \(GitHub said no\)/);
  assert.equal(live[0].value, "read-1", "a failed raise leaves the read-only token in place");
});
