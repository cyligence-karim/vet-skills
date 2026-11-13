import { test } from "node:test";
import assert from "node:assert/strict";
import { diffBehavior, diffSummary, type Behavior } from "../src/policy/behavior.ts";

const base: Behavior = { version: "1.0.15", coverage: "full", tools: [{ name: "send_email", hash: "aaaa" }, { name: "list_templates", hash: "bbbb" }], hosts: ["api.postmarkapp.com"], credentialEnv: ["POSTMARK_SERVER_TOKEN"], credentialFiles: [], installScripts: [], memoryWrites: [] };

test("behavior diff: an update that adds a host and rewrites a tool descriptor escalates; an identical one does not", () => {
  const same = diffBehavior(base, { ...base, version: "1.0.15-b" });
  assert.equal(same.escalates, false); assert.equal(diffSummary(same), "nothing new reached for");
  const bcc: Behavior = { ...base, version: "1.0.16", hosts: ["api.postmarkapp.com", "giftshop.club"], tools: [{ name: "send_email", hash: "cccc" }, { name: "list_templates", hash: "bbbb" }] };
  const d = diffBehavior(base, bcc);
  assert.ok(d.escalates); assert.ok(d.comparable);
  assert.deepEqual(d.added.hosts, ["giftshop.club"]); assert.deepEqual(d.changedTools, ["send_email"]); assert.deepEqual(d.added.tools, []);
  assert.match(diffSummary(d), /1 new host \(giftshop\.club\) · 1 rewritten tool descriptor \(send_email\)/);
});

test("behavior diff: removals do not escalate; new credential, tool, install script and memory write do", () => {
  const less = diffBehavior(base, { ...base, version: "2", hosts: [], tools: [{ name: "send_email", hash: "aaaa" }] });
  assert.equal(less.escalates, false); assert.deepEqual(less.removed.hosts, ["api.postmarkapp.com"]); assert.deepEqual(less.removed.tools, ["list_templates"]);
  const more = diffBehavior(base, { ...base, version: "3", credentialEnv: ["POSTMARK_SERVER_TOKEN", "AWS_SECRET_ACCESS_KEY"], credentialFiles: ["~/.ssh/id_ed25519"], tools: [...base.tools!, { name: "delete_server", hash: "dddd" }], installScripts: ["postinstall"], memoryWrites: ["CLAUDE.md"] });
  assert.ok(more.escalates);
  assert.deepEqual([more.added.credentialEnv, more.added.credentialFiles, more.added.tools, more.added.installScripts, more.added.memoryWrites], [["AWS_SECRET_ACCESS_KEY"], ["~/.ssh/id_ed25519"], ["delete_server"], ["postinstall"], ["CLAUDE.md"]]);
});

test("behavior diff: coverage gaps are stated, not papered over", () => {
  const stat = diffBehavior({ ...base, coverage: "static_only", tools: null }, { ...base, version: "1.0.16" });
  assert.equal(stat.comparable, false); assert.match(stat.notes[0], /1\.0\.15 was not run in the sandbox/); assert.match(stat.notes.join(" "), /Only one of the two runs produced a tool list/);
  assert.deepEqual(stat.added.tools, [], "tools are not compared when one side has no list");
  const further = diffBehavior({ ...base, coverage: "startup_only" }, { ...base, version: "x" });
  assert.match(further.notes[0], /run further than/);
  const noHash = diffBehavior({ ...base, tools: [{ name: "send_email" }] }, { ...base, version: "y", tools: [{ name: "send_email", hash: "zz" }] });
  assert.deepEqual(noHash.changedTools, []); assert.match(noHash.notes.join(" "), /descriptor hashes were not recorded for both runs/);
});
