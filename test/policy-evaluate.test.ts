import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_POLICY, SOLO_POLICY, evaluate, parsePolicyYaml, serializePolicyYaml, flagsFromTrace, type VerdictInput, type PublisherInput, toolRuleFor } from "../src/policy/index.ts";

const stripe: PublisherInput = { handle: "stripe", verified: true, ageDays: 600 };
const devtools: PublisherInput = { handle: "devtools-cloud", verified: false, ageDays: 9 };
const docforge: PublisherInput = { handle: "docforge", verified: false, ageDays: 140 };

const verified: VerdictInput = { id: "vd_at", score: 98, label: "verified", flags: {} };
const caution: VerdictInput = { id: "vd_pdf", score: 61, label: "caution", flags: { fs_outside_project: true, unpinned_deps: true }, declaredNetwork: ["api.pdf.co"] };
const blocked: VerdictInput = { id: "vd_dh", score: 14, label: "blocked", flags: { credential_reads: true, undeclared_egress: true, memory_writes: true, tool_shadowing: true }, lastSafeVersion: { semver: "2.2.4", score: 88 } };

test("verified skill from an allow-listed publisher is allowed", () => {
  const d = evaluate({ policy: DEFAULT_POLICY, verdict: verified, publisher: stripe });
  assert.equal(d.decision, "allow");
  assert.match(d.reason, /allow-listed/);
});

test("the deploy-helper storyline: blocked by behavior with the last safe version named", () => {
  const d = evaluate({ policy: DEFAULT_POLICY, verdict: blocked, publisher: { ...devtools, ageDays: 40 } });
  assert.equal(d.decision, "block");
  assert.equal(d.kind, "blocked_exception");
  assert.match(d.reason, /credential paths/);
  assert.match(d.reason, /2\.2\.4 \(88\)/);
});

test("a 9-day-old publisher is blocked before the verdict is even consulted", () => {
  const d = evaluate({ policy: DEFAULT_POLICY, verdict: verified, publisher: devtools });
  assert.equal(d.decision, "block");
  assert.equal(d.rules[0].rule, "publisher_age");
});

test("the pdf-tools-pro storyline: caution + fs_outside_project → approval under default-strict", () => {
  const d = evaluate({ policy: DEFAULT_POLICY, verdict: caution, publisher: docforge });
  assert.equal(d.decision, "approval_required");
  assert.deepEqual(d.restrictions, { filesystem: ["./"] });
});

test("caution with only warnings sandboxes under default-strict", () => {
  const v: VerdictInput = { ...caution, flags: { unpinned_deps: true } };
  const d = evaluate({ policy: DEFAULT_POLICY, verdict: v, publisher: docforge });
  assert.equal(d.decision, "sandbox");
  assert.deepEqual(d.restrictions, { filesystem: ["./"] });
});

test("the solo policy allows caution with a warning", () => {
  const d = evaluate({ policy: SOLO_POLICY, verdict: caution, publisher: docforge });
  assert.equal(d.decision, "allow");
  assert.match(d.reason, /warnings/);
});

test("unscored defers under detonate, blocks under block", () => {
  assert.equal(evaluate({ policy: DEFAULT_POLICY, verdict: null, publisher: docforge }).decision, "defer");
  assert.equal(evaluate({ policy: { ...DEFAULT_POLICY, unknownAction: "block" }, verdict: null, publisher: docforge }).decision, "block");
});

test("offline with no cache fails open by default and can be made to fail closed", () => {
  assert.equal(evaluate({ policy: DEFAULT_POLICY, verdict: null, publisher: null, offline: true }).decision, "allow");
  assert.equal(evaluate({ policy: { ...DEFAULT_POLICY, offlineAction: "block" }, verdict: null, publisher: null, offline: true }).decision, "block");
});

test("observe mode reports the would-be decision and lets the install through", () => {
  const d = evaluate({ policy: DEFAULT_POLICY, verdict: blocked, publisher: { ...devtools, ageDays: 40 }, enforcement: "observe" });
  assert.equal(d.decision, "observe");
  assert.equal(d.wouldBe, "block");
});

test("score below minimum blocks even when behavior is clean", () => {
  const d = evaluate({ policy: DEFAULT_POLICY, verdict: { id: "x", score: 30, label: "blocked", flags: {} }, publisher: docforge });
  assert.equal(d.decision, "block");
  assert.match(d.reason, /below the policy minimum/);
});

test("allow-listed publisher bypasses thresholds but not behavior blocks", () => {
  const low = { id: "x", score: 30, label: "blocked" as const, flags: {} };
  assert.equal(evaluate({ policy: DEFAULT_POLICY, verdict: low, publisher: stripe }).decision, "allow");
  assert.equal(evaluate({ policy: DEFAULT_POLICY, verdict: { ...low, flags: { credential_reads: true } }, publisher: stripe }).decision, "block");
});

test("yaml round-trips", () => {
  const text = serializePolicyYaml(DEFAULT_POLICY);
  const p = parsePolicyYaml(text);
  assert.deepEqual(p, DEFAULT_POLICY);
  const partial = parsePolicyYaml("min_score: 70\ncaution: approval\nbehavior:\n  unpinned_deps: block\n");
  assert.equal(partial.minScore, 70);
  assert.equal(partial.cautionAction, "approval");
  assert.equal(partial.behavior.unpinned_deps, "block");
  assert.equal(partial.behavior.credential_reads, "block");
});

test("flags are derived from a trace summary", () => {
  const f = flagsFromTrace({ files_read: ["~/.ssh/id_ed25519", "~/Downloads/a.pdf"], egress_hosts: [{ host: "telemetry-cdn.xyz", declared: false }], memory_writes: [{}], tool_shadowing: [] }, [{ rule_id: "AST07", title: "Unpinned dependency" }]);
  assert.equal(f.credential_reads, true);
  assert.equal(f.undeclared_egress, true);
  assert.equal(f.memory_writes, true);
  assert.equal(f.tool_shadowing, false);
  assert.equal(f.fs_outside_project, true);
  assert.equal(f.unpinned_deps, true);
});

test("partial_coverage clause: a startup-only Verified stands by default, is handled as Caution / approval / block when the policy says so; full coverage is untouched", () => {
  const partial: VerdictInput = { ...verified, coverage: "startup_only" };
  const asLabelled = evaluate({ policy: DEFAULT_POLICY, verdict: partial, publisher: docforge });
  assert.equal(asLabelled.decision, "allow");
  assert.ok(asLabelled.rules.some((r) => r.rule === "partial_coverage" && r.outcome === "pass" && /label stands/.test(r.detail)));
  const asCaution = evaluate({ policy: { ...DEFAULT_POLICY, partialCoverage: "caution" }, verdict: partial, publisher: docforge });
  assert.equal(asCaution.decision, "sandbox", JSON.stringify(asCaution));
  assert.ok(asCaution.rules.some((r) => r.rule === "partial_coverage" && r.outcome === "warn"));
  assert.equal(evaluate({ policy: { ...DEFAULT_POLICY, partialCoverage: "approval" }, verdict: partial, publisher: docforge }).decision, "approval_required");
  assert.equal(evaluate({ policy: { ...DEFAULT_POLICY, partialCoverage: "block" }, verdict: partial, publisher: docforge }).decision, "block");
  assert.equal(evaluate({ policy: { ...DEFAULT_POLICY, partialCoverage: "block" }, verdict: { ...verified, coverage: "full" }, publisher: docforge }).decision, "allow");
  // Allow-listed publishers bypass it like the other thresholds; the YAML round-trips.
  assert.equal(evaluate({ policy: { ...DEFAULT_POLICY, partialCoverage: "block", publishers: { ...DEFAULT_POLICY.publishers, allow: ["docforge"] } }, verdict: partial, publisher: docforge }).decision, "allow");
  const y = serializePolicyYaml({ ...DEFAULT_POLICY, partialCoverage: "approval" });
  assert.match(y, /partial_coverage: approval/);
  assert.equal(parsePolicyYaml(y).partialCoverage, "approval");
  assert.equal(parsePolicyYaml("name: x\nversion: 1\n").partialCoverage, "as_labelled");
});

test("policy YAML accepts the documented caution_action / unknown_action spellings as well as the serialized ones", () => {
  const p = parsePolicyYaml("name: mine\nmin_score: 60\ncaution_action: approval\nunknown_action: block\n");
  assert.equal(p.cautionAction, "approval"); assert.equal(p.unknownAction, "block");
  assert.equal(parsePolicyYaml("caution: block\n").cautionAction, "block");
});

test("runtime clause: parsed with defaults, round-trips, and tool rules match tool or server/tool", () => {
  const d = parsePolicyYaml("name: x\nversion: 1\n");
  assert.equal(d.runtime.network, "observe"); assert.equal(d.runtime.newHost, "warn"); assert.equal(d.runtime.secrets, "broker"); assert.equal(d.runtime.blockedVersions, "refuse");
  assert.ok(d.runtime.tools.some((t) => t.match === "delete_*" && t.action === "approve"));
  const y = parsePolicyYaml("name: x\nruntime:\n  network: enforce\n  new_host: block\n  tools:\n    - match: 'github/delete_*'\n      action: deny\n    - match: '*'\n      action: allow\n  default_tool_action: approve\n  approval_timeout_seconds: 5\n");
  assert.equal(y.runtime.network, "enforce"); assert.equal(y.runtime.newHost, "block"); assert.equal(y.runtime.approvalTimeoutSeconds, 10);
  assert.equal(toolRuleFor(y.runtime.tools, "github", "delete_repo")?.action, "deny");
  assert.equal(toolRuleFor(y.runtime.tools, "gitlab", "delete_repo")?.action, "allow");
  assert.equal(toolRuleFor([], "x", "y"), null);
  const back = parsePolicyYaml(serializePolicyYaml(y));
  assert.deepEqual(back.runtime, y.runtime);
});
