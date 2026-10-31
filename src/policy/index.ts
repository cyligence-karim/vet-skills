/**
 * @killerskills/policy
 *
 * The install-decision engine. Given a verdict (or none), the publisher, and an
 * org or personal policy, produce the decision the vet-skills hook enforces and
 * the server records. Pure: no I/O, deterministic, same result in the CLI and
 * the API so the dashboard's audit log always matches what the developer saw.
 *
 * Spec: "Data Model & Verdict API" → Org API (evaluate decision values), Scoring.
 */
import YAML from "yaml";

/* ------------------------------------------------------------------ types */

export type VerdictLabel = "verified" | "caution" | "blocked";
export type BehaviorFlag = "credential_reads" | "undeclared_egress" | "memory_writes" | "tool_shadowing" | "fs_outside_project" | "unpinned_deps";
export type RuleAction = "block" | "approval" | "warn";
export type CautionAction = "sandbox" | "approval" | "allow" | "block";
export type UnknownAction = "detonate" | "block" | "approval" | "allow";
export type AgentKind = "claude_code" | "cursor" | "codex" | "copilot" | "gemini_cli" | "other";

export interface Policy {
  name: string;
  version: number;
  minScore: number;
  cautionAction: CautionAction;
  unknownAction: UnknownAction;
  /** When the verdict API is unreachable and nothing is cached. Fail-open default. */
  offlineAction: "allow" | "block" | "approval";
  behavior: Record<BehaviorFlag, RuleAction>;
  publishers: { allow: string[]; block: string[]; blockYoungerThanDays: number };
  agents: AgentKind[];
  approvals: { ttlDays: number; blockedExceptionApprovers: number };
}

export interface VerdictInput {
  id: string;
  score: number;
  label: VerdictLabel;
  flags: Partial<Record<BehaviorFlag, boolean>>;
  /** Hosts the trace observed, with whether the manifest declared them. */
  egress?: { host: string; declared: boolean }[];
  declaredNetwork?: string[];
  lastSafeVersion?: { semver: string; score: number } | null;
}

export interface PublisherInput {
  handle: string;
  verified: boolean;
  ageDays: number;
}

export interface EvaluateInput {
  policy: Policy;
  verdict: VerdictInput | null;
  publisher: PublisherInput | null;
  /** "observe" logs the would-be decision and lets the install proceed. */
  enforcement?: "observe" | "enforce";
  agentKind?: AgentKind;
  /** True when the hook could not reach the API and had no cached verdict. */
  offline?: boolean;
}

export type DecisionKind = "allow" | "sandbox" | "approval_required" | "block" | "defer" | "observe";

export interface Restrictions {
  filesystem?: string[];
  network?: string[];
  memory?: boolean;
  env_passthrough?: string[];
}

export interface RuleResult {
  rule: string;
  outcome: "pass" | "warn" | "approval" | "block" | "info";
  detail: string;
}

export interface Decision {
  decision: DecisionKind;
  /** The decision that would apply with enforcement on (same as `decision` unless observing). */
  wouldBe: Exclude<DecisionKind, "observe">;
  reason: string;
  kind?: "caution" | "unknown" | "blocked_exception";
  restrictions?: Restrictions;
  lastSafeVersion?: { semver: string; score: number } | null;
  rules: RuleResult[];
  policy: { name: string; version: number };
}

/* --------------------------------------------------------------- defaults */

export const DEFAULT_POLICY: Policy = {
  name: "default-strict",
  version: 1,
  minScore: 50,
  cautionAction: "sandbox",
  unknownAction: "detonate",
  offlineAction: "allow",
  behavior: {
    credential_reads: "block",
    undeclared_egress: "block",
    memory_writes: "block",
    tool_shadowing: "block",
    fs_outside_project: "approval",
    unpinned_deps: "warn",
  },
  publishers: { allow: ["anthropic", "github", "stripe", "vercel-labs"], block: [], blockYoungerThanDays: 30 },
  agents: ["claude_code", "cursor", "codex", "copilot", "gemini_cli", "other"],
  approvals: { ttlDays: 90, blockedExceptionApprovers: 2 },
};

/** The permissive personal policy the CLI uses before anyone configures one. */
export const SOLO_POLICY: Policy = {
  ...DEFAULT_POLICY,
  name: "personal",
  cautionAction: "allow",
  behavior: { ...DEFAULT_POLICY.behavior, fs_outside_project: "warn" },
  publishers: { allow: [], block: [], blockYoungerThanDays: 0 },
};

export const FLAG_LABEL: Record<BehaviorFlag, string> = {
  credential_reads: "reads credential paths",
  undeclared_egress: "network egress to undeclared hosts",
  memory_writes: "writes agent memory / instruction files",
  tool_shadowing: "shadows another tool's description",
  fs_outside_project: "filesystem access outside project",
  unpinned_deps: "unpinned dependencies",
};

/* ------------------------------------------------------------------- yaml */

const FLAGS: BehaviorFlag[] = ["credential_reads", "undeclared_egress", "memory_writes", "tool_shadowing", "fs_outside_project", "unpinned_deps"];

export function parsePolicyYaml(text: string): Policy {
  const y = (YAML.parse(text) ?? {}) as Record<string, unknown>;
  const num = (v: unknown, d: number) => (typeof v === "number" && Number.isFinite(v) ? v : d);
  const str = <T extends string>(v: unknown, allowed: readonly T[], d: T): T => (allowed.includes(v as T) ? (v as T) : d);
  const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);
  const b = (y.behavior ?? {}) as Record<string, unknown>;
  const p = (y.publishers ?? {}) as Record<string, unknown>;
  const a = (y.approvals ?? {}) as Record<string, unknown>;
  const behavior = { ...DEFAULT_POLICY.behavior };
  for (const f of FLAGS) behavior[f] = str(b[f], ["block", "approval", "warn"] as const, DEFAULT_POLICY.behavior[f]);
  return {
    name: typeof y.name === "string" ? y.name : DEFAULT_POLICY.name,
    version: num(y.version, 1),
    minScore: Math.min(100, Math.max(0, num(y.min_score, DEFAULT_POLICY.minScore))),
    cautionAction: str(y.caution, ["sandbox", "approval", "allow", "block"] as const, DEFAULT_POLICY.cautionAction),
    unknownAction: str(y.unknown, ["detonate", "block", "approval", "allow"] as const, DEFAULT_POLICY.unknownAction),
    offlineAction: str(y.offline, ["allow", "block", "approval"] as const, DEFAULT_POLICY.offlineAction),
    behavior,
    publishers: {
      allow: list(p.allow),
      block: list(p.block),
      blockYoungerThanDays: num(p.block_younger_than_days, DEFAULT_POLICY.publishers.blockYoungerThanDays),
    },
    agents: list(y.agents).filter((k): k is AgentKind => ["claude_code", "cursor", "codex", "copilot", "gemini_cli", "other"].includes(k)),
    approvals: {
      ttlDays: num(a.ttl_days, DEFAULT_POLICY.approvals.ttlDays),
      blockedExceptionApprovers: num(a.blocked_exception_approvers, DEFAULT_POLICY.approvals.blockedExceptionApprovers),
    },
  };
}

export function serializePolicyYaml(p: Policy): string {
  return YAML.stringify({
    name: p.name,
    version: p.version,
    min_score: p.minScore,
    caution: p.cautionAction,
    unknown: p.unknownAction,
    offline: p.offlineAction,
    behavior: p.behavior,
    publishers: { allow: p.publishers.allow, block: p.publishers.block, block_younger_than_days: p.publishers.blockYoungerThanDays },
    agents: p.agents,
    approvals: { ttl_days: p.approvals.ttlDays, blocked_exception_approvers: p.approvals.blockedExceptionApprovers },
  });
}

/* --------------------------------------------------------------- evaluate */

export function labelFor(score: number): VerdictLabel {
  return score >= 80 ? "verified" : score >= 50 ? "caution" : "blocked";
}

function restrictionsFor(v: VerdictInput, flagged: BehaviorFlag[]): Restrictions | undefined {
  const r: Restrictions = {};
  if (flagged.includes("fs_outside_project")) r.filesystem = ["./"];
  if (flagged.includes("undeclared_egress")) r.network = v.declaredNetwork ?? v.egress?.filter((e) => e.declared).map((e) => e.host) ?? [];
  if (flagged.includes("memory_writes")) r.memory = false;
  return Object.keys(r).length ? r : undefined;
}

export function evaluate(input: EvaluateInput): Decision {
  const { policy, verdict, publisher } = input;
  const enforcement = input.enforcement ?? "enforce";
  const rules: RuleResult[] = [];
  const pol = { name: policy.name, version: policy.version };
  const done = (wouldBe: Exclude<DecisionKind, "observe">, reason: string, extra: Partial<Decision> = {}): Decision => ({
    decision: enforcement === "observe" ? "observe" : wouldBe,
    wouldBe,
    reason,
    rules,
    policy: pol,
    lastSafeVersion: verdict?.lastSafeVersion ?? null,
    ...extra,
  });

  // Agent scope: a policy that does not cover this agent kind does not apply.
  if (input.agentKind && policy.agents.length && !policy.agents.includes(input.agentKind)) {
    rules.push({ rule: "agent_scope", outcome: "info", detail: `policy does not cover ${input.agentKind}; allowing` });
    return done("allow", `policy ${policy.name} does not apply to ${input.agentKind}`);
  }

  // Publisher block-list and age.
  if (publisher) {
    if (policy.publishers.block.includes(publisher.handle)) {
      rules.push({ rule: "publisher_blocked", outcome: "block", detail: `${publisher.handle} is on the block list` });
      return done("block", `publisher ${publisher.handle} is blocked by policy`, { kind: "blocked_exception" });
    }
    const allowListed = policy.publishers.allow.includes(publisher.handle);
    if (!allowListed && policy.publishers.blockYoungerThanDays > 0 && publisher.ageDays < policy.publishers.blockYoungerThanDays) {
      rules.push({ rule: "publisher_age", outcome: "block", detail: `publisher is ${publisher.ageDays} days old (< ${policy.publishers.blockYoungerThanDays})` });
      return done("block", `publisher ${publisher.handle} is ${publisher.ageDays} days old; policy blocks publishers younger than ${policy.publishers.blockYoungerThanDays} days`, { kind: "blocked_exception" });
    }
    rules.push({ rule: "publisher", outcome: "pass", detail: allowListed ? `${publisher.handle} is allow-listed` : `${publisher.handle} · ${publisher.ageDays} days` });
  }

  // Offline with nothing cached: fail-open by default.
  if (input.offline && !verdict) {
    rules.push({ rule: "offline", outcome: policy.offlineAction === "block" ? "block" : "warn", detail: `verdict API unreachable; policy offline action = ${policy.offlineAction}` });
    if (policy.offlineAction === "block") return done("block", "verdict API unreachable and policy blocks unknown installs when offline", { kind: "unknown" });
    if (policy.offlineAction === "approval") return done("approval_required", "verdict API unreachable; approval required for unscored installs", { kind: "unknown" });
    return done("allow", "verdict API unreachable; allowing with a warning (fail-open)");
  }

  // Unscored.
  if (!verdict) {
    rules.push({ rule: "unscored", outcome: policy.unknownAction === "block" ? "block" : "info", detail: `no verdict; policy unknown action = ${policy.unknownAction}` });
    switch (policy.unknownAction) {
      case "detonate": return done("defer", "no verdict yet; detonating before deciding", { kind: "unknown" });
      case "block": return done("block", "no verdict and policy blocks unscored skills", { kind: "unknown" });
      case "approval": return done("approval_required", "no verdict; approval required for unscored skills", { kind: "unknown" });
      case "allow": return done("allow", "no verdict; policy allows unscored skills with a warning");
    }
  }

  // Behavior rules, independent of score.
  const flagged = FLAGS.filter((f) => verdict.flags[f]);
  let approvalFlag: BehaviorFlag | null = null;
  const warnings: BehaviorFlag[] = [];
  for (const f of flagged) {
    const action = policy.behavior[f];
    rules.push({ rule: `behavior.${f}`, outcome: action, detail: FLAG_LABEL[f] });
    if (action === "block") {
      const extra = verdict.lastSafeVersion ? `; last safe version ${verdict.lastSafeVersion.semver} (${verdict.lastSafeVersion.score})` : "";
      return done("block", `${FLAG_LABEL[f]}${extra}`, { kind: "blocked_exception" });
    }
    if (action === "approval" && !approvalFlag) approvalFlag = f;
    if (action === "warn") warnings.push(f);
  }
  for (const f of FLAGS) if (!verdict.flags[f]) rules.push({ rule: `behavior.${f}`, outcome: "pass", detail: FLAG_LABEL[f] });

  const allowListed = !!publisher && policy.publishers.allow.includes(publisher.handle);

  // Score threshold (allow-listed publishers bypass thresholds, not behavior rules).
  if (!allowListed && verdict.score < policy.minScore) {
    rules.push({ rule: "min_score", outcome: "block", detail: `${verdict.score} < ${policy.minScore}` });
    const extra = verdict.lastSafeVersion ? `; last safe version ${verdict.lastSafeVersion.semver} (${verdict.lastSafeVersion.score})` : "";
    return done("block", `score ${verdict.score} is below the policy minimum ${policy.minScore}${extra}`, { kind: "blocked_exception" });
  }
  rules.push({ rule: "min_score", outcome: "pass", detail: allowListed ? "bypassed (allow-listed publisher)" : `${verdict.score} ≥ ${policy.minScore}` });

  const restrictions = restrictionsFor(verdict, [...warnings, ...(approvalFlag ? [approvalFlag] : [])]);

  if (approvalFlag) {
    return done("approval_required", `${FLAG_LABEL[approvalFlag]} requires approval`, { kind: "caution", restrictions });
  }

  // Caution band.
  if (!allowListed && verdict.label === "caution") {
    rules.push({ rule: "caution", outcome: policy.cautionAction === "block" ? "block" : policy.cautionAction === "approval" ? "approval" : "warn", detail: `score ${verdict.score} in caution band; action = ${policy.cautionAction}` });
    switch (policy.cautionAction) {
      case "sandbox": return done("sandbox", `score ${verdict.score} is in the caution band; installing sandboxed`, { kind: "caution", restrictions: restrictions ?? { filesystem: ["./"] } });
      case "approval": return done("approval_required", `score ${verdict.score} is in the caution band; approval required`, { kind: "caution", restrictions });
      case "block": return done("block", `score ${verdict.score} is in the caution band; policy blocks caution`, { kind: "caution" });
      case "allow": break;
    }
  }

  const warnText = warnings.length ? ` (warnings: ${warnings.map((w) => FLAG_LABEL[w]).join(", ")})` : "";
  return done("allow", `${allowListed ? "allow-listed publisher" : `score ${verdict.score}, ${verdict.label}`}${warnText}`, { restrictions });
}

/** Simulate a policy against a set of (verdict, publisher) pairs; returns counts for the dashboard panel. */
export function simulate(policy: Policy, items: { verdict: VerdictInput | null; publisher: PublisherInput | null; agentKind?: AgentKind }[]) {
  const counts = { allow: 0, sandbox: 0, approval_required: 0, block: 0, defer: 0 };
  for (const it of items) {
    const d = evaluate({ policy, verdict: it.verdict, publisher: it.publisher, agentKind: it.agentKind, enforcement: "enforce" });
    counts[d.decision as keyof typeof counts] += 1;
  }
  return counts;
}

/** Derive behavior flags from a trace summary as the verdict API returns it. */
export function flagsFromTrace(t: {
  files_read?: string[];
  egress_hosts?: { host: string; declared: boolean }[];
  memory_writes?: unknown[];
  tool_shadowing?: unknown[];
  files_written?: string[];
} | null | undefined, findings: { rule_id: string; title: string }[] = []): VerdictInput["flags"] {
  if (!t) return {};
  const credential = (p: string) => /(^|\/)(\.ssh|\.aws|\.npmrc|\.config\/gh|\.netrc|\.docker\/config\.json|keychain)/i.test(p) || /credentials|id_(rsa|ed25519)/i.test(p);
  const outsideProject = (p: string) => p.startsWith("~") || p.startsWith("/");
  return {
    credential_reads: (t.files_read ?? []).some(credential),
    undeclared_egress: (t.egress_hosts ?? []).some((e) => !e.declared),
    memory_writes: (t.memory_writes ?? []).length > 0,
    tool_shadowing: (t.tool_shadowing ?? []).length > 0,
    fs_outside_project: [...(t.files_read ?? []), ...(t.files_written ?? [])].some((p) => outsideProject(p) && !credential(p)),
    unpinned_deps: findings.some((f) => /unpinned/i.test(f.title)),
  };
}

export * from "./discover.js";
