/**
 * The decision flow (spec: CLI hook contract):
 *   resolve → hash → cached verdict? → lookup → reachable? → evaluate (org: server, solo: local) → decision
 * Everything here is fail-open: an unreachable API never blocks an install unless the policy says so.
 */
import { evaluate, flagsFromTrace, type Decision, type VerdictInput, type PublisherInput } from "./policy/index.js";
import { sendTelemetry, resolveSkill, verdictByHash, evaluateRemote } from "./api.js";
import { platform } from "node:os";
import { VERSION, appendLog, cacheGet, cachePut, readOrg, readPolicy, telemetryEnabled, telemetryNoticePending, type ResolveResponse } from "./state.js";
import { c, fmtInstalls, pad } from "./render.js";
import { readLock } from "./attest.js";

export type CheckResult = {
  resolved: ResolveResponse | null;
  decision: Decision;
  source: "cache" | "api" | "offline";
  cacheAge?: number;
  remote?: { approvalRequestId?: string; jobId?: string };
  offline: boolean;
  policyLabel: string;
};

export function toVerdictInput(r: ResolveResponse): VerdictInput | null {
  if (!r.verdict) return null;
  return {
    id: r.verdict.id,
    score: r.verdict.score,
    label: r.verdict.label,
    flags: flagsFromTrace(r.trace_summary, r.findings),
    egress: r.trace_summary?.egress_hosts,
    declaredNetwork: r.version.declared_permissions.network,
    lastSafeVersion: r.last_safe_version,
  };
}

export function toPublisherInput(r: ResolveResponse): PublisherInput {
  return { handle: r.publisher.handle, verified: r.publisher.verified, ageDays: r.publisher.age_days };
}

export async function check(q: string, opts: { quiet?: boolean; agentKind?: "claude_code" | "cursor" | "codex" | "copilot" | "gemini_cli" | "other"; /** Registry the install command implies (npm, pypi, docker, plugins); narrows the lookup. */ registry?: string } = {}): Promise<CheckResult> {
  const org = readOrg();
  const { policy, source: policySource } = readPolicy();
  const policyLabel = org ? `${org.slug}/${policy.name}` : policy.name;
  const say = (s: string) => { if (!opts.quiet) process.stderr.write(s + "\n"); };

  say(`${c.muted("Resolving")} ${q} …`);

  // 1. Resolve by name (the registry returns the hash). A cached verdict for the same identifier short-circuits.
  let resolved: ResolveResponse | null = null;
  let source: CheckResult["source"] = "api";
  let offline = false;
  let cacheAge: number | undefined;

  let res = await resolveSkill(q, opts.registry);
  // Enrolled machines can refer to their org's private skills by bare name (or org/name).
  if (!res.ok && !res.offline && org) {
    const bare = q.replace(/^[^/]+\//, "");
    const priv = await resolveSkill(`${org.slug}/${bare}`, "private");
    if (priv.ok) res = priv;
  }
  if (res.ok) {
    resolved = res.data;
    const cached = cacheGet(resolved.version.artifact_hash);
    if (cached) { source = "cache"; cacheAge = Date.now() - cached.fetchedAt; }
    cachePut(resolved.version.artifact_hash, { fetchedAt: Date.now(), etag: res.etag, data: resolved });
  } else if (res.offline) {
    offline = true;
    // Try the cache by scanning for a matching name (hash unknown without the registry).
    source = "offline";
  }

  say(`${c.muted("vet-skills")} ${c.faint(VERSION)} · policy ${c.ink2(policyLabel)}${source === "cache" ? c.muted(` · cached verdict (${Math.round((cacheAge ?? 0) / 60000)}m)`) : offline ? c.caution(" · API unreachable, fail-open") : ""}${org?.enforcement === "observe" ? c.muted(" · observe mode") : ""}`);

  const verdict = resolved ? toVerdictInput(resolved) : null;
  const publisher = resolved ? toPublisherInput(resolved) : null;

  // 2. Org mode: the server decides (it also records the audit event). Fall back to local evaluation when unreachable.
  let decision: Decision;
  let remote: CheckResult["remote"];
  if (org && resolved && !offline) {
    const ev = await evaluateRemote({ artifact_hash: resolved.version.artifact_hash, name: resolved.skill.name, semver: resolved.version.semver, verdict_id: resolved.verdict?.id ?? null, agent_kind: opts.agentKind ?? "other" });
    if (ev.ok) {
      const d = ev.data;
      decision = evaluate({ policy, verdict, publisher, enforcement: org.enforcement, agentKind: opts.agentKind });
      // Server is authoritative for the decision; keep local rule trace for display.
      decision = { ...decision, decision: d.decision, wouldBe: (d.would_be as Decision["wouldBe"]) ?? decision.wouldBe, reason: d.reason, restrictions: (d.restrictions as Decision["restrictions"]) ?? decision.restrictions, lastSafeVersion: d.last_safe_version ?? decision.lastSafeVersion };
      remote = { approvalRequestId: d.approval_request_id, jobId: d.job_id };
    } else {
      offline = offline || ev.offline;
      decision = evaluate({ policy, verdict, publisher, enforcement: org.enforcement, agentKind: opts.agentKind, offline: ev.offline && !verdict });
    }
  } else {
    decision = evaluate({ policy, verdict, publisher, enforcement: org?.enforcement ?? "enforce", agentKind: opts.agentKind, offline: offline && !verdict });
  }

  appendLog({
    at: new Date().toISOString(), skill: resolved?.skill.name ?? q, semver: resolved?.version.semver ?? "?", hash: resolved?.version.artifact_hash ?? null,
    decision: decision.decision, wouldBe: decision.wouldBe, reason: decision.reason, policy: `${policyLabel} v${policy.version} (${policySource})`, offline, requestId: remote?.approvalRequestId,
  });

  // Not enrolled: send the decision anonymously (enrolled machines report through the org API instead).
  if (!org && telemetryEnabled()) {
    if (telemetryNoticePending()) process.stderr.write(c.muted("vet-skills sends anonymous usage (skill name, version, decision, agent type; never code, prompts or paths). Opt out: vet-skills telemetry off") + "\n");
    await sendTelemetry({ skill: resolved?.skill.name ?? q, semver: resolved?.version.semver ?? null, registry: resolved?.skill.registry ?? null, decision: decision.decision, would_be: decision.wouldBe ?? null, agent_kind: opts.agentKind ?? "other", hook_version: VERSION, os: platform(), offline }).catch(() => null);
  }

  // A vet-skills.lock in the working directory pins the bytes that were attested: anything else for the same name is blocked, whatever the policy says.
  const lock = readLock();
  const pinned = lock && resolved ? lock.skills.find((e) => e.name === resolved!.skill.name) : null;
  if (pinned && resolved && pinned.artifact_hash !== resolved.version.artifact_hash) {
    const why = `vet-skills.lock pins ${resolved.skill.name} to ${pinned.artifact_hash.slice(0, 12)}…; registry has ${resolved.version.artifact_hash.slice(0, 12)}… (${resolved.version.semver}). Run \`vet-skills lock\` to accept it.`;
    return { resolved, decision: { ...decision, decision: "block", wouldBe: "block", reason: why }, source, cacheAge, remote, offline, policyLabel };
  }
  return { resolved, decision, source, cacheAge, remote, offline, policyLabel };
}

/* ------------------------------------------------------------- rendering */

export function renderCheck(r: CheckResult): string {
  const lines: string[] = [];
  const { resolved, decision } = r;
  lines.push("");
  if (!resolved) {
    lines.push(`${c.pill("UNSCORED", "neutral")} ${c.muted(r.offline ? "could not reach the verdict API" : "not found in any registry we index")}`);
    lines.push(`${c.ink2("Policy says:")} ${decision.reason}.`);
    lines.push("");
    return lines.join("\n") + "\n";
  }
  const v = resolved.verdict;
  const head = `${resolved.skill.name}@${resolved.version.semver} · ${resolved.publisher.handle} · ${fmtInstalls(resolved.skill.install_count)} installs`;
  if (!v) {
    lines.push(`${c.pill("UNSCORED", "neutral")} ${c.muted(`first time anyone has installed this version · publisher ${resolved.publisher.age_days} days old`)}`);
    lines.push(`${c.ink2("Policy says:")} ${decision.reason}.`);
    lines.push("");
    return lines.join("\n") + "\n";
  }
  const tone = v.label;
  lines.push(`${c.pill(v.label.toUpperCase(), tone)} ${c.score(v.score, tone)}${c.faint("/100")} ${c.muted(head)}`);
  const inc = resolved.incident;
  if (inc?.source === "field") lines.push(inc.status === "open"
    ? `${c.caution("!")} ${c.ink2("Open incident:")} ${c.muted(`a hook on ${inc.machines} machine${inc.machines === 1 ? "" : "s"} reported ${inc.kinds.map((k) => k.replace(/_/g, " ")).join(", ")}; honeypot re-run pending (killerskills.ai${inc.page})`)}`
    : `${c.blocked("✕")} ${c.ink2("Confirmed incident:")} ${c.muted(`reported from the field, then observed in the honeypot${inc.note ? `: ${inc.note}` : ""} (killerskills.ai${inc.page})`)}`);
  lines.push("");

  // Observed in sandbox
  const t = resolved.trace_summary;
  if (t) {
    lines.push(c.ink2(`Observed in sandbox (${v.scenarios_run} scenarios, ${Math.round(v.duration_ms / 1000)}s):`));
    const undeclared = t.egress_hosts.filter((e) => !e.declared);
    const declared = t.egress_hosts.filter((e) => e.declared);
    if (undeclared.length) lines.push(`  ${c.blocked("✕")} ${pad("network", 10)} ${c.blocked(`${undeclared.map((e) => e.host).join(", ")} — undeclared`)}`);
    else lines.push(`  ${c.verified("✓")} ${pad("network", 10)} ${c.muted(declared.length ? `${declared.map((e) => e.host).join(", ")} only — matches declaration` : "no egress")}`);
    if (t.memory_writes.length) lines.push(`  ${c.blocked("✕")} ${pad("memory", 10)} wrote agent memory (${t.memory_writes.length})`);
    else lines.push(`  ${c.verified("✓")} ${pad("memory", 10)} ${c.muted("no writes")}`);
    const cred = t.files_read.filter((p) => /\.ssh|\.aws|\.npmrc|credentials|\.config\/gh/.test(p));
    const outside = t.files_read.filter((p) => (p.startsWith("~") || p.startsWith("/")) && !cred.includes(p));
    if (cred.length) lines.push(`  ${c.blocked("✕")} ${pad("filesystem", 10)} reads ${cred.join(", ")}`);
    else if (outside.length) lines.push(`  ${c.caution("!")} ${pad("filesystem", 10)} reads ${outside.join(", ")} beyond project scope`);
    else lines.push(`  ${c.verified("✓")} ${pad("filesystem", 10)} ${c.muted("project only")}`);
    if (t.tool_shadowing.length) lines.push(`  ${c.caution("!")} ${pad("tools", 10)} shadows ${t.tool_shadowing.map((s) => s.tool).join(", ")}`);
    for (const f of resolved.findings.filter((f) => /unpinned/i.test(f.title))) lines.push(`  ${c.caution("!")} ${pad("supply", 10)} ${f.detail.replace(/^.*· /, "")}`);
    lines.push("");
  }

  // Policy
  lines.push(`${c.ink2("Policy")} ${r.policyLabel}:`);
  for (const rule of decision.rules.filter((x) => x.outcome !== "pass" || x.rule === "min_score")) {
    const mark = rule.outcome === "block" ? c.blocked("✕") : rule.outcome === "approval" || rule.outcome === "warn" ? c.caution("!") : rule.outcome === "pass" ? c.verified("✓") : c.muted("·");
    lines.push(`  ${mark} ${pad(rule.rule.replace("behavior.", "").replace(/_/g, " "), 22)} ${c.muted(rule.detail)}`);
  }
  lines.push("");
  return lines.join("\n") + "\n";
}

export function renderOutcome(r: CheckResult, chosen?: string): string {
  const d = r.decision;
  const name = r.resolved ? `${r.resolved.skill.name}@${r.resolved.version.semver}` : "skill";
  switch (d.decision) {
    case "allow": return `${c.verified("✓")} Allowed ${name} ${c.muted(`· ${d.reason}`)}`;
    case "sandbox": return `${c.verified("✓")} Installed ${name} ${c.muted(`sandboxed · ${restrictionText(d.restrictions)}`)}`;
    case "approval_required": return `${c.caution("!")} ${name} needs approval ${c.muted(`· ${d.reason}`)}${r.remote?.approvalRequestId ? c.muted(` · request ${r.remote.approvalRequestId}`) : ""}\n${c.muted("You can keep working; the install completes when it's approved.")}`;
    case "block": return `${c.blocked("✕")} Blocked ${name} ${c.muted(`· ${d.reason}`)}${d.lastSafeVersion ? `\n${c.muted("Pin instead:")} ${c.ink2(`${name.split("@")[0]}@${d.lastSafeVersion.semver}`)} ${c.muted(`(score ${d.lastSafeVersion.score})`)}` : ""}${r.resolved ? `\n${c.muted("Full report:")} killerskills.ai${r.resolved.skill.page}/${r.resolved.version.semver}` : ""}`;
    case "defer": return `${c.caution("◐")} ${name} is unscored; policy says detonate first ${c.muted("(usually 30–60s)")}\n${c.muted("Run")} vet-skills detonate ${name} ${c.muted("to watch the trace, or re-run the install in a minute.")}`;
    case "observe": return `${c.muted("◦")} Observe mode: would have been ${c.ink2(d.wouldBe)} ${c.muted(`· ${d.reason}`)} — proceeding.`;
  }
  void chosen;
  return "";
}

export function restrictionText(r?: Decision["restrictions"]) {
  if (!r) return "no restrictions";
  const parts: string[] = [];
  if (r.filesystem) parts.push(`fs restricted to ${r.filesystem.join(", ")}`);
  if (r.network) parts.push(`network: ${r.network.length ? r.network.join(", ") : "none"}`);
  if (r.memory === false) parts.push("memory writes denied");
  return parts.join(" · ") || "no restrictions";
}
