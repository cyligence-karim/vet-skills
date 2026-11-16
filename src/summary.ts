/**
 * `vet-skills guard summary [--since 2h] [--markdown] [--json] [--fail-on denied|unexpected-host|refused|any]`
 *
 * What the guard recorded in a window, for a job log or a pull request: sessions, tool calls by outcome, hosts nothing
 * on record named, launches it refused. Built for CI and other headless runs, where nobody is watching stderr. With
 * --fail-on the exit code is 1 when the named thing happened, so a pipeline can stop on it. Read-only.
 */
import { readGuardLog } from "./guard.js";
import { localRecord, parseSince } from "./policytest.js";

export type FailOn = "denied" | "unexpected-host" | "refused" | "any" | "none";
export interface GuardSummary {
  hours: number; sessions: number; servers: string[];
  calls: { total: number; allowed: number; held: number; denied: number };
  byTool: { server: string; tool: string; calls: number; denied: number }[];
  unexpectedHosts: { server: string; host: string; contacts: number }[];
  refused: { server: string; why: string }[]; stopped: { server: string; why: string }[];
  changes: { server: string; what: string }[]; credentialsHeld: number; canary: boolean; poison: string[];
}

export function summarize(events: Record<string, unknown>[], hours: number): GuardSummary {
  const rec = localRecord(events);
  const servers = new Set<string>(); const started = new Set<string>(); const refused: GuardSummary["refused"] = []; const stopped: GuardSummary["stopped"] = []; const poison = new Set<string>(); let held = 0; let canary = false;
  for (const e of events) {
    const server = typeof e.server === "string" ? e.server : "?";
    if (e.kind === "start") { servers.add(server); if (typeof e.session === "string") started.add(e.session); if (Array.isArray(e.secrets)) held += e.secrets.length; }
    else if (e.kind === "secret" && e.refused !== true) held++;
    else if (e.kind === "launch_refused") refused.push({ server, why: String(e.why ?? "") });
    else if (e.kind === "stopped" || e.kind === "revoked_running") stopped.push({ server, why: String(e.reason ?? e.why ?? "") });
    else if (e.kind === "canary") canary = true;
    else if (e.kind === "poison" && typeof e.tool === "string") poison.add(`${server}/${e.tool}`);
  }
  const c = rec.calls.reduce((a, x) => ({ total: a.total + x.calls, allowed: a.allowed + x.allowed, held: a.held + x.held, denied: a.denied + x.denied }), { total: 0, allowed: 0, held: 0, denied: 0 });
  return {
    hours, sessions: started.size || (rec.calls.length ? rec.sessions : 0), servers: [...new Set([...servers, ...rec.calls.map((x) => x.server)])].filter((s) => s !== "?").sort(), calls: c,
    byTool: rec.calls.map((x) => ({ server: x.server, tool: x.tool, calls: x.calls, denied: x.denied })).sort((a, b) => b.denied - a.denied || b.calls - a.calls || `${a.server}/${a.tool}`.localeCompare(`${b.server}/${b.tool}`)),
    unexpectedHosts: rec.hosts, refused, stopped, changes: rec.changes.map((x) => ({ server: x.server, what: x.what })), credentialsHeld: held, canary, poison: [...poison].sort(),
  };
}

/** Reasons the run should fail under --fail-on; empty when it should pass. */
export function failures(s: GuardSummary, on: FailOn): string[] {
  const out: string[] = [];
  const all = on === "any";
  if ((all || on === "denied") && s.calls.denied) out.push(`${s.calls.denied} tool call${s.calls.denied === 1 ? " was" : "s were"} denied`);
  if ((all || on === "unexpected-host") && s.unexpectedHosts.length) out.push(`${s.unexpectedHosts.length} host${s.unexpectedHosts.length === 1 ? "" : "s"} nothing on record named ${s.unexpectedHosts.length === 1 ? "was" : "were"} contacted (${s.unexpectedHosts.slice(0, 3).map((h) => h.host).join(", ")})`);
  if ((all || on === "refused") && (s.refused.length || s.stopped.length)) out.push(`${s.refused.length + s.stopped.length} server launch${s.refused.length + s.stopped.length === 1 ? " was" : "es were"} refused or stopped`);
  if (on !== "none" && s.canary) out.push("a planted decoy credential was read or sent");
  return out;
}

const md = (v: string) => v.replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
export function renderSummary(s: GuardSummary, markdown: boolean): string {
  const window = s.hours >= 48 ? `${Math.round(s.hours / 24)} days` : `${Math.round(s.hours * 10) / 10} hour${s.hours === 1 ? "" : "s"}`;
  if (!s.sessions && !s.refused.length) return markdown ? `### vet-skills guard\n\nNo guarded MCP session was recorded in the last ${window}. If an agent ran in this job, its servers were not under the guard: run \`vet-skills guard install --project\` before it starts.\n` : `No guarded MCP session was recorded in the last ${window}. If an agent ran, its servers were not under the guard: run \`vet-skills guard install --project\` first.`;
  const head = `${s.sessions} guarded session${s.sessions === 1 ? "" : "s"} across ${s.servers.length} server${s.servers.length === 1 ? "" : "s"} in the last ${window}: ${s.calls.total} tool call${s.calls.total === 1 ? "" : "s"} (${s.calls.allowed} allowed, ${s.calls.held} approved after a hold, ${s.calls.denied} denied), ${s.unexpectedHosts.length} unexpected host${s.unexpectedHosts.length === 1 ? "" : "s"}, ${s.refused.length + s.stopped.length} launch${s.refused.length + s.stopped.length === 1 ? "" : "es"} refused or stopped, ${s.credentialsHeld} credential${s.credentialsHeld === 1 ? "" : "s"} held by the guard.`;
  const notes = [
    ...s.refused.map((r) => `refused ${r.server}: ${r.why}`), ...s.stopped.map((r) => `stopped ${r.server}: ${r.why}`),
    ...s.unexpectedHosts.slice(0, 20).map((h) => `${h.server} contacted ${h.host} (${h.contacts}×), which nothing on record named`),
    ...s.changes.slice(0, 20).map((x) => `${x.server}: ${x.what}`), ...s.poison.map((p) => `${p}: tool description or result carried instructions aimed at the agent`),
    ...(s.canary ? ["a planted decoy credential was read or sent: treat the server involved as hostile"] : []),
  ];
  if (markdown) {
    const rows = s.byTool.slice(0, 50).map((t) => `| ${md(t.server)} | ${md(t.tool)} | ${t.calls} | ${t.denied} |`);
    return [`### vet-skills guard`, "", head, "", ...(rows.length ? ["| Server | Tool | Calls | Denied |", "|---|---|---:|---:|", ...rows, ""] : []), ...(notes.length ? ["**Worth a look**", "", ...notes.map((n) => `- ${md(n)}`), ""] : []), "_Tool and argument names only; no arguments, results or credential values are recorded._", ""].join("\n");
  }
  return [head, "", ...s.byTool.slice(0, 50).map((t) => `  ${`${t.server}/${t.tool}`.padEnd(44)} ${String(t.calls).padStart(5)}×${t.denied ? `  ${t.denied} denied` : ""}`), ...(notes.length ? ["", ...notes.map((n) => `  ! ${n}`)] : [])].join("\n");
}

export function summaryCmd(flags: { since?: string; markdown?: boolean; json?: boolean; failOn?: string }): number {
  const days = parseSince(flags.since, 1);
  const s = summarize(readGuardLog(days), days * 24);
  const on = (["denied", "unexpected-host", "refused", "any", "none"] as const).find((x) => x === flags.failOn) ?? "none";
  if (flags.failOn && on === "none" && flags.failOn !== "none") { console.error(`--fail-on takes denied, unexpected-host, refused, any or none (got ${flags.failOn})`); return 2; }
  console.log(flags.json ? JSON.stringify(s, null, 2) : renderSummary(s, !!flags.markdown));
  const why = failures(s, on);
  if (why.length) { console.error(`\nvet-skills guard summary: failing because ${why.join("; ")} (--fail-on ${on}).`); return 1; }
  return 0;
}
