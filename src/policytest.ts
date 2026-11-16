/**
 * `vet-skills policy test <file> [--since 30d] [--org-wide] [--json]` and `vet-skills policy suggest [--since 30d] [--out file]`.
 *
 * test: replays what the guard recorded on this machine (or, with --org-wide, what every enrolled machine reported to
 * the organization) against a proposed policy file and says what would have been allowed, warned about, held or
 * denied, grouped by server and tool. Nothing is changed: not the policy in force, not the log.
 *
 * suggest: writes a starting policy from the same record by fixed rules (policy/replay.ts), with the observations
 * behind every rule as a comment beside it.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { parsePolicyYaml, replayNextStep, replayTools, serializePolicyYaml, suggestPolicy, type ListedTool, type ObservedCalls, type Policy, type ReplayReport } from "./policy/index.js";
import { policyReplay } from "./api.js";
import { readGuardLog } from "./guard.js";
import { c, pad } from "./render.js";
import { readOrg, readPolicy } from "./state.js";

/** `30d`, `12h`, `2w`; a bare number is days. */
export function parseSince(v: string | undefined, fallback = 30): number {
  const m = /^(\d+(?:\.\d+)?)\s*([dhw]?)$/i.exec((v ?? "").trim());
  if (!m) return fallback;
  const n = Number(m[1]); const u = m[2].toLowerCase();
  return Math.min(365, Math.max(1 / 24, u === "h" ? n / 24 : u === "w" ? n * 7 : n));
}

export interface LocalRecord { calls: ObservedCalls[]; listed: ListedTool[]; hosts: { server: string; host: string; contacts: number }[]; changes: { server: string; what: string; at: string }[]; sessions: number; from: string | null }
/** Fold the guard log into what the replay needs. A held call is counted by how it ended (approved or denied). */
export function localRecord(events: Record<string, unknown>[]): LocalRecord {
  const calls = new Map<string, ObservedCalls>(); const listed = new Map<string, ListedTool>(); const hosts = new Map<string, { server: string; host: string; contacts: number }>();
  const changes: LocalRecord["changes"] = []; const sessions = new Set<string>(); let from: string | null = null;
  for (const e of events) {
    const server = typeof e.server === "string" ? e.server : null; const at = typeof e.at === "string" ? e.at : null;
    if (at && (!from || at < from)) from = at;
    if (typeof e.session === "string") sessions.add(e.session);
    if (!server) continue;
    if (e.kind === "tool_call" && typeof e.tool === "string" && e.action !== "held") {
      const k = `${server}\u0000${e.tool}`; const o = calls.get(k) ?? { server, tool: e.tool, calls: 0, allowed: 0, held: 0, denied: 0, last: null };
      o.calls++; if (e.action === "allowed") o.allowed++; else if (e.action === "approved") o.held++; else o.denied++;
      if (at && (!o.last || at > o.last)) o.last = at;
      calls.set(k, o);
    } else if (e.kind === "tools" && Array.isArray(e.tools)) {
      for (const t of e.tools as { name?: unknown; ro?: unknown }[]) if (typeof t.name === "string") listed.set(`${server}\u0000${t.name}`, { server, tool: t.name, readOnlyHint: typeof t.ro === "boolean" ? t.ro : null });
    } else if (e.kind === "host" && e.expected === false && typeof e.host === "string") {
      const k = `${server}\u0000${e.host}`; const h = hosts.get(k) ?? { server, host: e.host, contacts: 0 }; h.contacts++; hosts.set(k, h);
    } else if ((e.kind === "update_escalates" || e.kind === "remote_changed") && at) {
      const added = Array.isArray(e.added) ? e.added.length : 0; const rewritten = Array.isArray(e.rewritten) ? e.rewritten.length : 0;
      changes.push({ server, at, what: e.kind === "remote_changed" ? `tool list changed (${added} new, ${rewritten} rewritten)` : `update reached for more${typeof e.summary === "string" ? `: ${e.summary}` : ""}` });
    }
  }
  return { calls: [...calls.values()], listed: [...listed.values()], hosts: [...hosts.values()].sort((a, b) => b.contacts - a.contacts), changes, sessions: sessions.size, from };
}

export interface TestReport { scope: "this machine" | "organization"; days: number; policy: string; sessions: number; tools: ReplayReport; network: { unexpected_hosts: number; contacts: number; outcome: "allow" | "warn" | "deny"; hosts: { server: string; host: string; contacts: number }[] }; changes: { count: number; outcome: "allow" | "warn" | "hold"; items: LocalRecord["changes"] }; next: string }

export function testPolicy(policy: Policy, rec: LocalRecord, days: number): TestReport {
  const rt = policy.runtime;
  const tools = replayTools(rt, rec.calls);
  const netOutcome = rt.network === "enforce" || rt.newHost === "block" ? "deny" : rt.newHost === "warn" ? "warn" : "allow";
  return {
    scope: "this machine", days, policy: `${policy.name} v${policy.version}`, sessions: rec.sessions, tools,
    network: { unexpected_hosts: rec.hosts.length, contacts: rec.hosts.reduce((n, h) => n + h.contacts, 0), outcome: netOutcome, hosts: rec.hosts.slice(0, 50) },
    changes: { count: rec.changes.length, outcome: rt.onChange, items: rec.changes.slice(0, 50) },
    next: replayNextStep(tools),
  };
}

const tone = (o: string) => (o === "allow" ? c.verified : o === "deny" ? c.blocked : c.caution);
export function renderTest(r: TestReport): string {
  const out: string[] = []; const t = r.tools.totals;
  out.push(`${c.bold(r.policy)} replayed on ${r.scope === "organization" ? "what enrolled machines reported" : "this machine's guard log"}, last ${Math.round(r.days)} day${Math.round(r.days) === 1 ? "" : "s"}: ${r.sessions} session${r.sessions === 1 ? "" : "s"}, ${t.calls} tool call${t.calls === 1 ? "" : "s"} across ${t.servers} server${t.servers === 1 ? "" : "s"}.`, "");
  out.push(`  ${c.verified(pad(`allow ${t.allow}`, 14))} ${c.caution(pad(`hold ${t.hold}`, 14))} ${c.blocked(pad(`deny ${t.deny}`, 14))} ${c.muted(`${t.changed} call${t.changed === 1 ? "" : "s"} would end differently than ${t.changed === 1 ? "it" : "they"} did`)}`);
  let last = "";
  for (const row of r.tools.rows) {
    if (row.outcome !== last) { out.push("", c.muted(`  would ${row.outcome}`)); last = row.outcome; }
    out.push(`  ${tone(row.outcome)(pad(row.outcome, 6))} ${pad(`${row.server}/${row.tool}`, 44)} ${pad(`${row.calls}×`, 7)} ${c.muted(`rule ${row.rule}${row.reason ? ` (${row.reason})` : ""}${row.changed ? ` · ${row.changed} would change` : ""}`)}`);
  }
  if (r.tools.byGroup.length) { out.push("", c.muted("  by team")); for (const g of r.tools.byGroup) out.push(`  ${pad(g.group, 28)} ${pad(`${g.calls} calls`, 12)} ${c.caution(pad(`hold ${g.hold}`, 10))} ${c.blocked(`deny ${g.deny}`)}`); }
  if (r.scope === "this machine") {
    out.push("", `  network: ${r.network.unexpected_hosts} host${r.network.unexpected_hosts === 1 ? "" : "s"} nothing on record named (${r.network.contacts} contact${r.network.contacts === 1 ? "" : "s"}) would be ${tone(r.network.outcome)(r.network.outcome === "deny" ? "blocked" : r.network.outcome === "warn" ? "warned about" : "allowed")}`);
    for (const h of r.network.hosts.slice(0, 6)) out.push(c.muted(`    ${h.server} → ${h.host} (${h.contacts}×)`));
    out.push(`  changes: ${r.changes.count} update${r.changes.count === 1 ? "" : "s"} or tool-list change${r.changes.count === 1 ? "" : "s"} would be ${tone(r.changes.outcome === "hold" ? "hold" : r.changes.outcome)(r.changes.outcome === "hold" ? "held for approval" : r.changes.outcome === "warn" ? "warned about" : "allowed")}`);
  }
  out.push("", `${c.bold("Next:")} ${r.next}`, c.muted("Nothing was changed. The replay covers recorded tool calls by name; it cannot know what a call it would have denied would have done."));
  return out.join("\n");
}

/** The suggested policy as YAML on top of the policy in force, each rule with its evidence as a trailing comment. */
export function renderSuggestion(base: Policy, s: ReturnType<typeof suggestPolicy>, days: number): string {
  const next: Policy = { ...base, runtime: { ...base.runtime, onChange: s.onChange, tools: s.rules.map(({ match, action, reason }) => ({ match, action, ...(reason ? { reason } : {}) })) } };
  let yaml = serializePolicyYaml(next);
  // Evidence as comments, matched by the rule's exact name (the serializer writes one rule per `match:` line).
  for (const r of s.rules) {
    const re = new RegExp(`^(\\s*-\\s*match:\\s*["']?${r.match.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}["']?)\\s*$`, "m");
    yaml = yaml.replace(re, `$1   # ${r.evidence}`);
  }
  const head = [`# Suggested by vet-skills policy suggest from the last ${Math.round(days)} days of this machine's guard log.`, `# Rules: used tools are allowed by name; never-used tools that delete or destroy are denied; other never-used writes are`, `# held for approval; updates and tool-list changes are held. Check it with: vet-skills policy test <this file>`, ...s.notes.map((n) => `# Note: ${n}`), ""];
  return head.join("\n") + yaml;
}

export async function policyTestCmd(file: string | undefined, flags: { since?: string; json?: boolean; orgWide?: boolean }): Promise<number> {
  if (!file) { console.error("usage: vet-skills policy test <policy.yaml> [--since 30d] [--org-wide] [--json]"); return 2; }
  let text: string; let policy: Policy;
  try { text = readFileSync(file, "utf8"); policy = parsePolicyYaml(text); } catch (e) { console.error(`${c.blocked("✕")} ${file}: ${(e as Error).message}`); return 2; }
  const days = parseSince(flags.since);
  if (flags.orgWide) {
    if (!readOrg()) { console.error(`${c.blocked("✕")} --org-wide needs a machine enrolled in an organization (vet-skills join).`); return 1; }
    const r = await policyReplay(text, Math.round(days));
    if (!r.ok) { console.error(`${c.blocked("✕")} ${r.error}`); return 1; }
    const report: TestReport = { scope: "organization", days: r.data.days, policy: `${policy.name} v${policy.version}`, sessions: r.data.sessions, tools: r.data.tools, network: { unexpected_hosts: 0, contacts: 0, outcome: "allow", hosts: [] }, changes: { count: 0, outcome: policy.runtime.onChange, items: [] }, next: r.data.next };
    console.log(flags.json ? JSON.stringify(report, null, 2) : renderTest(report));
    return 0;
  }
  const report = testPolicy(policy, localRecord(readGuardLog(days)), days);
  console.log(flags.json ? JSON.stringify(report, null, 2) : renderTest(report));
  return 0;
}

export function policySuggestCmd(flags: { since?: string; out?: string; json?: boolean }): number {
  const days = parseSince(flags.since);
  const rec = localRecord(readGuardLog(days));
  const s = suggestPolicy(rec.calls, rec.listed);
  if (flags.json) { console.log(JSON.stringify(s, null, 2)); return 0; }
  const yaml = renderSuggestion(readPolicy().policy, s, days);
  if (flags.out) { writeFileSync(flags.out, yaml); console.log(`${c.verified("✓")} Wrote ${flags.out}: ${s.rules.filter((r) => r.action === "allow").length} tools allowed by name, ${s.rules.filter((r) => r.action === "approve").length} held, ${s.rules.filter((r) => r.action === "deny").length} denied. Nothing is in force yet.\n  Check it:  vet-skills policy test ${flags.out}\n  Apply it:  vet-skills policy set ${flags.out}${readOrg() ? "   (this machine is in an org: paste it into the dashboard's policy editor instead)" : ""}`); }
  else process.stdout.write(yaml);
  return 0;
}
