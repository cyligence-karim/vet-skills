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
  /**
   * Runtime context clause: what the hook does when a skill's sensitive action is explained by the user's own actions
   * this session (they named the host or path in a prompt, or touched it themselves in the last 30 minutes).
   * allow_when_user_touched → allowed with a one-line notice, recorded as a scoped allow (session, skill, resource, 30 min).
   * hold → held and the agent told to ask, as if there were no context. Actions with no supporting context are always held.
   */
  context: Record<ContextKind, ContextAction>;
  /**
   * Coverage clause: what to do with a verdict whose honeypot run did not reach the server's tools (startup only, not
   * started, install only, or static only). `as_labelled` keeps the published label; `caution` treats a Verified as
   * Caution so the caution action applies; `approval` and `block` are what they say. Full-coverage verdicts are untouched.
   */
  partialCoverage: CoverageAction;
  /**
   * Runtime clause: how the guard treats an MCP server it launches on a developer's machine (`vet-skills guard`).
   *   network   observe: every host is recorded and allowed; enforce: only hosts the verdict saw or declared, plus the hosts
   *             credentials are bound to, are reachable (the rest get 403 and are recorded as blocked).
   *   new_host  what happens the first time this package version contacts a host no verdict, declaration or earlier
   *             guarded session on this machine has seen: allow silently, warn (recorded, told to the user), block.
   *   secrets   broker: credential variables the verdict names are replaced by placeholders and injected only into
   *             requests to the vendor's hosts; passthrough: the server gets the real values (recorded as such).
   *   blocked_versions  refuse: a version whose verdict is blocked, or with a confirmed incident, does not launch; warn: launches with a notice.
   *   tools     tool-call rules, first match wins. `match` is a glob on `tool` or `server/tool`; `action` is allow, deny, or
   *             approve (held until someone with the approval link decides; denied if nobody does within the timeout).
   *   default_tool_action  for calls no rule matches.
   */
  runtime: RuntimePolicy;
}
export interface RuntimePolicy {
  network: "observe" | "enforce";
  newHost: "allow" | "warn" | "block";
  secrets: "broker" | "passthrough";
  blockedVersions: "refuse" | "warn";
  /** A version revoked or confirmed malicious while its server is already running: stop the process, or only say so. */
  revokeRunning: "warn" | "kill";
  /** A server launching a different artifact than the one last run here, whose behavior diff adds a host, credential or tool. */
  onChange: "allow" | "warn" | "hold";
  /** The least sandbox coverage a verdict may rest on before the guard treats the version as unvetted (warns at launch). */
  minCoverage: "any" | "install_only" | "startup_only" | "full";
  tools: ToolRule[];
  defaultToolAction: ToolAction;
  /** Seconds a held tool call waits for an approval before it is denied. */
  approvalTimeoutSeconds: number;
  /**
   * Short-lived credentials: instead of brokering the long-lived value, the guard exchanges it for a scoped token that
   * lives minutes, per launch, and revokes it at exit where the vendor allows. The server only ever holds a placeholder
   * for a credential that will be dead within the hour.
   */
  exchange: ExchangeRule[];
}
export type ExchangeKind = "github_app" | "aws_sts" | "gcp_impersonate";
export interface ExchangeRule {
  /** The variable the server expects (GITHUB_TOKEN, AWS_ACCESS_KEY_ID …). For aws_sts the three AWS variables are set together. */
  var: string;
  kind: ExchangeKind;
  /** Host the minted credential is bound to; defaults per kind (api.github.com · amazonaws.com · googleapis.com). */
  host?: string;
  /** github_app: non-secret ids (the private key stays on the machine: VET_GITHUB_APP_KEY_FILE); repositories and permissions scope the token. */
  appId?: string; installationId?: string; repositories?: string[]; permissions?: Record<string, string>;
  /** aws_sts: the role to assume, lifetime (900–3600 s) and an optional inline session policy (JSON) that narrows it further. */
  roleArn?: string; durationSeconds?: number; sessionPolicy?: string;
  /** gcp_impersonate: the service account and scopes; lifetime in seconds (≤ 3600). */
  serviceAccount?: string; scopes?: string[];
}
export type ToolAction = "allow" | "deny" | "approve";
export interface ToolRule { match: string; action: ToolAction; reason?: string }
export const DEFAULT_RUNTIME: RuntimePolicy = { network: "observe", newHost: "warn", secrets: "broker", blockedVersions: "refuse", revokeRunning: "warn", onChange: "warn", minCoverage: "any", tools: [], defaultToolAction: "allow", approvalTimeoutSeconds: 300, exchange: [] };
/** Tool names that change or destroy state: the strict runtime policy holds them for approval. */
export const DESTRUCTIVE_TOOL_GLOBS = ["delete_*", "*_delete", "remove_*", "drop_*", "destroy_*", "purge_*", "force_push*", "*_force", "execute_sql", "run_sql", "run_query", "send_email", "send_message", "transfer_*", "pay_*", "deploy_*", "rotate_*", "revoke_*"];
export type CoverageLevel = "full" | "startup_only" | "install_failed" | "install_only" | "static_only";
/** What a partial-coverage verdict does: the label stands as published (default), or it is treated as Caution (so the caution action applies), or it needs approval, or it is blocked. */
export type CoverageAction = "as_labelled" | "caution" | "approval" | "block";
export type ContextKind = "credential_read" | "egress_unexpected" | "memory_write" | "outside_project_write";
export type ContextAction = "allow_when_user_touched" | "hold";
export const CONTEXT_KINDS: readonly ContextKind[] = ["credential_read", "egress_unexpected", "memory_write", "outside_project_write"];
export const DEFAULT_CONTEXT: Record<ContextKind, ContextAction> = { credential_read: "allow_when_user_touched", egress_unexpected: "allow_when_user_touched", memory_write: "allow_when_user_touched", outside_project_write: "allow_when_user_touched" };

export interface VerdictInput {
  id: string;
  score: number;
  label: VerdictLabel;
  flags: Partial<Record<BehaviorFlag, boolean>>;
  /** Hosts the trace observed, with whether the manifest declared them. */
  egress?: { host: string; declared: boolean }[];
  /** How far the honeypot run got (engine ≥ 1.8); "static_only" when nothing ran. Unknown when absent. */
  coverage?: CoverageLevel;
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
  partialCoverage: "as_labelled",
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
  context: DEFAULT_CONTEXT,
  runtime: { ...DEFAULT_RUNTIME, tools: DESTRUCTIVE_TOOL_GLOBS.map((g) => ({ match: g, action: "approve" as const, reason: "changes or destroys state" })) },
};

/** The permissive personal policy the CLI uses before anyone configures one. */
export const SOLO_POLICY: Policy = {
  ...DEFAULT_POLICY,
  name: "personal",
  cautionAction: "allow",
  behavior: { ...DEFAULT_POLICY.behavior, fs_outside_project: "warn" },
  publishers: { allow: [], block: [], blockYoungerThanDays: 0 },
  // A personal machine has nobody to approve: destructive tools run, the guard records and says so.
  runtime: { ...DEFAULT_RUNTIME, tools: [] },
};

/** Matches a tool rule glob against `tool` or `server/tool`. */
export function toolRuleFor(rules: ToolRule[], server: string, tool: string): ToolRule | null {
  const re = (g: string) => new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i");
  for (const r of rules) { const x = re(r.match); if (x.test(tool) || x.test(`${server}/${tool}`)) return r; }
  return null;
}

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
  const cx = (y.context ?? {}) as Record<string, unknown>;
  const context = { ...DEFAULT_CONTEXT };
  for (const k of CONTEXT_KINDS) context[k] = str(cx[k], ["allow_when_user_touched", "hold"] as const, DEFAULT_CONTEXT[k]);
  const rt = (y.runtime ?? {}) as Record<string, unknown>;
  const tools: ToolRule[] = Array.isArray(rt.tools) ? rt.tools.flatMap((t) => {
    if (!t || typeof t !== "object") return [];
    const o = t as Record<string, unknown>;
    if (typeof o.match !== "string" || !o.match.trim()) return [];
    return [{ match: o.match.trim().slice(0, 200), action: str(o.action, ["allow", "deny", "approve"] as const, "allow"), ...(typeof o.reason === "string" ? { reason: o.reason.slice(0, 200) } : {}) }];
  }).slice(0, 200) : DEFAULT_POLICY.runtime.tools;
  const runtime: RuntimePolicy = {
    network: str(rt.network, ["observe", "enforce"] as const, DEFAULT_RUNTIME.network),
    newHost: str(rt.new_host, ["allow", "warn", "block"] as const, DEFAULT_RUNTIME.newHost),
    secrets: str(rt.secrets, ["broker", "passthrough"] as const, DEFAULT_RUNTIME.secrets),
    blockedVersions: str(rt.blocked_versions, ["refuse", "warn"] as const, DEFAULT_RUNTIME.blockedVersions),
    revokeRunning: str(rt.revoke_running, ["warn", "kill"] as const, DEFAULT_RUNTIME.revokeRunning),
    onChange: str(rt.on_change, ["allow", "warn", "hold"] as const, DEFAULT_RUNTIME.onChange),
    minCoverage: str(rt.min_coverage, ["any", "install_only", "startup_only", "full"] as const, DEFAULT_RUNTIME.minCoverage),
    tools,
    defaultToolAction: str(rt.default_tool_action, ["allow", "deny", "approve"] as const, DEFAULT_RUNTIME.defaultToolAction),
    approvalTimeoutSeconds: Math.min(3600, Math.max(10, num(rt.approval_timeout_seconds, DEFAULT_RUNTIME.approvalTimeoutSeconds))),
    exchange: Array.isArray(rt.exchange) ? rt.exchange.flatMap((e) => {
      if (!e || typeof e !== "object") return [];
      const o = e as Record<string, unknown>;
      if (typeof o.var !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(o.var) || !["github_app", "aws_sts", "gcp_impersonate"].includes(String(o.kind))) return [];
      const sv = (k: string) => (typeof o[k] === "string" ? (o[k] as string).slice(0, 400) : undefined);
      const r: ExchangeRule = { var: o.var, kind: o.kind as ExchangeKind };
      if (sv("host")) r.host = sv("host")!.toLowerCase();
      if (sv("app_id")) r.appId = sv("app_id"); if (sv("installation_id")) r.installationId = sv("installation_id");
      if (Array.isArray(o.repositories)) r.repositories = o.repositories.map(String).slice(0, 100);
      if (o.permissions && typeof o.permissions === "object") r.permissions = Object.fromEntries(Object.entries(o.permissions as Record<string, unknown>).filter(([, v]) => typeof v === "string").map(([k, v]) => [k, String(v)]).slice(0, 50));
      if (sv("role_arn")) r.roleArn = sv("role_arn"); if (typeof o.duration_seconds === "number") r.durationSeconds = Math.min(3600, Math.max(900, o.duration_seconds)); if (sv("session_policy")) r.sessionPolicy = typeof o.session_policy === "string" ? (o.session_policy as string).slice(0, 4000) : undefined;
      if (sv("service_account")) r.serviceAccount = sv("service_account"); if (Array.isArray(o.scopes)) r.scopes = o.scopes.map(String).slice(0, 20);
      return [r];
    }).slice(0, 50) : [],
  };
  return {
    name: typeof y.name === "string" ? y.name : DEFAULT_POLICY.name,
    version: num(y.version, 1),
    minScore: Math.min(100, Math.max(0, num(y.min_score, DEFAULT_POLICY.minScore))),
    // Both spellings are accepted: the docs wrote `caution_action` / `unknown_action` while the serializer wrote `caution` / `unknown`.
    cautionAction: str(y.caution ?? y.caution_action, ["sandbox", "approval", "allow", "block"] as const, DEFAULT_POLICY.cautionAction),
    unknownAction: str(y.unknown ?? y.unknown_action, ["detonate", "block", "approval", "allow"] as const, DEFAULT_POLICY.unknownAction),
    offlineAction: str(y.offline ?? y.offline_action, ["allow", "block", "approval"] as const, DEFAULT_POLICY.offlineAction),
    partialCoverage: str(y.partial_coverage, ["as_labelled", "caution", "approval", "block"] as const, DEFAULT_POLICY.partialCoverage),
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
    context,
    runtime,
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
    partial_coverage: p.partialCoverage,
    behavior: p.behavior,
    publishers: { allow: p.publishers.allow, block: p.publishers.block, block_younger_than_days: p.publishers.blockYoungerThanDays },
    agents: p.agents,
    approvals: { ttl_days: p.approvals.ttlDays, blocked_exception_approvers: p.approvals.blockedExceptionApprovers },
    context: p.context ?? DEFAULT_CONTEXT,
    runtime: { network: p.runtime.network, new_host: p.runtime.newHost, secrets: p.runtime.secrets, blocked_versions: p.runtime.blockedVersions, revoke_running: p.runtime.revokeRunning, on_change: p.runtime.onChange, min_coverage: p.runtime.minCoverage, default_tool_action: p.runtime.defaultToolAction, approval_timeout_seconds: p.runtime.approvalTimeoutSeconds, tools: p.runtime.tools.map((t) => ({ match: t.match, action: t.action, ...(t.reason ? { reason: t.reason } : {}) })), ...(p.runtime.exchange.length ? { exchange: p.runtime.exchange.map((e) => ({ var: e.var, kind: e.kind, ...(e.host ? { host: e.host } : {}), ...(e.appId ? { app_id: e.appId } : {}), ...(e.installationId ? { installation_id: e.installationId } : {}), ...(e.repositories ? { repositories: e.repositories } : {}), ...(e.permissions ? { permissions: e.permissions } : {}), ...(e.roleArn ? { role_arn: e.roleArn } : {}), ...(e.durationSeconds ? { duration_seconds: e.durationSeconds } : {}), ...(e.sessionPolicy ? { session_policy: e.sessionPolicy } : {}), ...(e.serviceAccount ? { service_account: e.serviceAccount } : {}), ...(e.scopes ? { scopes: e.scopes } : {}) })) } : {}) },
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
  const { policy, publisher } = input;
  const verdictIn = input.verdict;
  const enforcement = input.enforcement ?? "enforce";
  const rules: RuleResult[] = [];
  const pol = { name: policy.name, version: policy.version };
  const done = (wouldBe: Exclude<DecisionKind, "observe">, reason: string, extra: Partial<Decision> = {}): Decision => ({
    decision: enforcement === "observe" ? "observe" : wouldBe,
    wouldBe,
    reason,
    rules,
    policy: pol,
    lastSafeVersion: verdictIn?.lastSafeVersion ?? null,
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
  if (input.offline && !verdictIn) {
    rules.push({ rule: "offline", outcome: policy.offlineAction === "block" ? "block" : "warn", detail: `verdict API unreachable; policy offline action = ${policy.offlineAction}` });
    if (policy.offlineAction === "block") return done("block", "verdict API unreachable and policy blocks unknown installs when offline", { kind: "unknown" });
    if (policy.offlineAction === "approval") return done("approval_required", "verdict API unreachable; approval required for unscored installs", { kind: "unknown" });
    return done("allow", "verdict API unreachable; allowing with a warning (fail-open)");
  }

  // Unscored.
  if (!verdictIn) {
    rules.push({ rule: "unscored", outcome: policy.unknownAction === "block" ? "block" : "info", detail: `no verdict; policy unknown action = ${policy.unknownAction}` });
    switch (policy.unknownAction) {
      case "detonate": return done("defer", "no verdict yet; detonating before deciding", { kind: "unknown" });
      case "block": return done("block", "no verdict and policy blocks unscored skills", { kind: "unknown" });
      case "approval": return done("approval_required", "no verdict; approval required for unscored skills", { kind: "unknown" });
      case "allow": return done("allow", "no verdict; policy allows unscored skills with a warning");
    }
  }
  let verdict: VerdictInput = verdictIn;

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

  // Coverage clause: a label the run did not earn in full is handled as the policy says. Default keeps the label.
  const partial = verdict.coverage !== undefined && verdict.coverage !== "full";
  const coverageText = verdict.coverage ? verdict.coverage.replace(/_/g, " ") : "unknown";
  if (!allowListed && partial && policy.partialCoverage !== "as_labelled") {
    if (policy.partialCoverage === "block") { rules.push({ rule: "partial_coverage", outcome: "block", detail: `coverage ${coverageText}; policy blocks partial coverage` }); return done("block", `the honeypot run covered ${coverageText}; policy requires full coverage`, { kind: "blocked_exception" }); }
    if (policy.partialCoverage === "approval") { rules.push({ rule: "partial_coverage", outcome: "approval", detail: `coverage ${coverageText}` }); return done("approval_required", `the honeypot run covered ${coverageText}; policy requires approval for partial coverage`, { kind: "caution", restrictions }); }
    rules.push({ rule: "partial_coverage", outcome: "warn", detail: `coverage ${coverageText}; treated as caution` });
    verdict = { ...verdict, label: verdict.label === "blocked" ? "blocked" : "caution" };
  } else if (partial) rules.push({ rule: "partial_coverage", outcome: "pass", detail: `coverage ${coverageText}; label stands (partial_coverage: as_labelled)` });

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
export * from "./secrets.js";
export * from "./lure-lite.js";
export * from "./hidden.js";
