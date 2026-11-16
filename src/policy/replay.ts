/**
 * Proof before rollout: what a runtime policy would have done with activity that already happened, and a starting
 * policy built from that activity. Pure and shared by the CLI (the machine's own guard log) and the dashboard (an
 * organization's recorded decisions). Deterministic: the same activity and policy give the same report, and every
 * suggested rule carries the observations it rests on.
 */
import { toolClass, toolRuleFor, type RuntimePolicy, type ToolRule } from "./index.js";

/** Tool calls as they were recorded: who was called, how often, and what the policy in force did at the time. */
export interface ObservedCalls { server: string; tool: string; calls: number; /** what happened then */ allowed: number; held: number; denied: number; last?: string | null; /** an optional grouping the caller wants totals for (a team) */ group?: string }
export type ReplayOutcome = "allow" | "hold" | "deny";
export interface ReplayRow { server: string; tool: string; calls: number; outcome: ReplayOutcome; rule: string; reason?: string; /** calls whose outcome under the proposed policy differs from what happened */ changed: number; last: string | null }
export interface ReplayReport {
  rows: ReplayRow[];
  totals: { calls: number; allow: number; hold: number; deny: number; changed: number; servers: number; tools: number };
  byGroup: { group: string; calls: number; allow: number; hold: number; deny: number }[];
}

const OUT: Record<string, ReplayOutcome> = { allow: "allow", approve: "hold", deny: "deny" };

/** Apply the proposed policy's tool rules to recorded calls. Nothing else about the policy is consulted here. */
export function replayTools(runtime: Pick<RuntimePolicy, "tools" | "defaultToolAction">, observed: ObservedCalls[]): ReplayReport {
  const merged = new Map<string, ReplayRow>(); const groups = new Map<string, ReplayReport["byGroup"][number]>();
  for (const o of observed) {
    if (!o.tool || o.calls <= 0) continue;
    const rule = toolRuleFor(runtime.tools, o.server, o.tool);
    const outcome = OUT[rule?.action ?? runtime.defaultToolAction] ?? "allow";
    const key = `${o.server}\u0000${o.tool}`;
    const row = merged.get(key) ?? { server: o.server, tool: o.tool, calls: 0, outcome, rule: rule?.match ?? "default", ...(rule?.reason ? { reason: rule.reason } : {}), changed: 0, last: null };
    row.calls += o.calls;
    // A call counts as changed when the proposed outcome is not the one it got: an allowed call now held or denied, and so on.
    row.changed += outcome === "allow" ? o.held + o.denied : outcome === "hold" ? o.allowed + o.denied : o.allowed + o.held;
    if (o.last && (!row.last || o.last > row.last)) row.last = o.last;
    merged.set(key, row);
    if (o.group !== undefined) { const g = groups.get(o.group) ?? { group: o.group, calls: 0, allow: 0, hold: 0, deny: 0 }; g.calls += o.calls; g[outcome] += o.calls; groups.set(o.group, g); }
  }
  const rank: Record<ReplayOutcome, number> = { deny: 0, hold: 1, allow: 2 };
  const rows = [...merged.values()].sort((a, b) => rank[a.outcome] - rank[b.outcome] || b.calls - a.calls || a.server.localeCompare(b.server) || a.tool.localeCompare(b.tool));
  const sum = (o: ReplayOutcome) => rows.filter((r) => r.outcome === o).reduce((n, r) => n + r.calls, 0);
  return {
    rows,
    totals: { calls: rows.reduce((n, r) => n + r.calls, 0), allow: sum("allow"), hold: sum("hold"), deny: sum("deny"), changed: rows.reduce((n, r) => n + r.changed, 0), servers: new Set(rows.map((r) => r.server)).size, tools: rows.length },
    byGroup: [...groups.values()].sort((a, b) => b.deny + b.hold - (a.deny + a.hold) || b.calls - a.calls || a.group.localeCompare(b.group)),
  };
}

/** The single next step a replay supports. */
export function replayNextStep(r: ReplayReport): string {
  if (!r.totals.calls) return "There is no recorded activity in this window, so the replay says nothing yet. Run the guard in observe mode first.";
  const quiet = [...new Set(r.rows.map((x) => x.server))].filter((s) => r.rows.filter((x) => x.server === s).every((x) => x.outcome === "allow"));
  const denied = r.rows.filter((x) => x.outcome === "deny" && x.calls > 0);
  if (!denied.length && !r.totals.hold) return `Safe to publish: none of the ${r.totals.calls} recorded calls would have been held or denied.`;
  if (denied.length) return `Look at the ${denied.length} tool${denied.length === 1 ? "" : "s"} this policy would deny that ${denied.length === 1 ? "was" : "were"} actually used (${denied.slice(0, 3).map((x) => `${x.server}/${x.tool}`).join(", ")}${denied.length > 3 ? ", …" : ""}) before publishing.${quiet.length ? ` ${quiet.length} server${quiet.length === 1 ? " is" : "s are"} unaffected.` : ""}`;
  return `Nothing used would be denied; ${r.totals.hold} call${r.totals.hold === 1 ? "" : "s"} would wait for an approver. Check that someone is on hand to approve, then publish.${quiet.length ? ` ${quiet.length} server${quiet.length === 1 ? " is" : "s are"} unaffected.` : ""}`;
}

/** A tool a server listed, whether or not it was ever called. */
export interface ListedTool { server: string; tool: string; readOnlyHint?: boolean | null }
export interface SuggestedRule extends ToolRule { evidence: string }
export interface Suggestion { rules: SuggestedRule[]; onChange: "hold"; notes: string[] }

const DESTRUCTIVE = /^(delete|remove|drop|destroy|purge|wipe|truncate|erase|reset|revoke|force|kill|terminate|uninstall|rm)([_\-A-Z]|$)/;

/**
 * A starting policy from observed use, by fixed rules:
 *   1. every tool that was actually called is allowed, by its exact server/tool name;
 *   2. every tool a server listed that was never called, and that deletes or destroys by name, is denied;
 *   3. every other never-called tool that is a write is held for approval;
 *   4. version and tool-list changes are held (runtime.on_change: hold).
 * Tools the guard never saw listed are not covered by any rule and fall to the policy's default action.
 */
export function suggestPolicy(observed: ObservedCalls[], listed: ListedTool[]): Suggestion {
  const used = new Map<string, { server: string; tool: string; calls: number; last: string | null }>();
  for (const o of observed) { if (!o.tool || o.calls <= 0) continue; const k = `${o.server}/${o.tool}`; const e = used.get(k) ?? { server: o.server, tool: o.tool, calls: 0, last: null }; e.calls += o.calls; if (o.last && (!e.last || o.last > e.last)) e.last = o.last; used.set(k, e); }
  const rules: SuggestedRule[] = [];
  for (const [k, e] of [...used].sort((a, b) => a[0].localeCompare(b[0]))) rules.push({ match: k, action: "allow", reason: "used", evidence: `${e.calls} recorded call${e.calls === 1 ? "" : "s"}${e.last ? `, last ${e.last.slice(0, 10)}` : ""}` });
  const seen = new Set<string>();
  for (const t of [...listed].sort((a, b) => `${a.server}/${a.tool}`.localeCompare(`${b.server}/${b.tool}`))) {
    const k = `${t.server}/${t.tool}`; if (used.has(k) || seen.has(k)) continue; seen.add(k);
    if (toolClass(t.tool, typeof t.readOnlyHint === "boolean" ? { readOnlyHint: t.readOnlyHint } : null) !== "write") continue;
    if (DESTRUCTIVE.test(t.tool)) rules.push({ match: k, action: "deny", reason: "never used; deletes or destroys by name", evidence: "listed by the server, 0 recorded calls" });
    else rules.push({ match: k, action: "approve", reason: "never used; a write", evidence: "listed by the server, 0 recorded calls" });
  }
  const notes: string[] = [];
  if (!used.size) notes.push("No tool calls are on record in this window, so nothing is allowed by name. Run the guard in observe mode for a week and suggest again.");
  if (!listed.length) notes.push("No tool lists are on record (the guard records them from version 0.14), so no never-used tool could be denied or held.");
  return { rules, onChange: "hold", notes };
}
