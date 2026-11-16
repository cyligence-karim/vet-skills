/**
 * `vet-skills review-pack [--since 30d] [--out dir]`: an access-review pack for one machine, no organization needed.
 *
 * A folder of dated evidence a developer can hand to whoever reviews their agent tooling: the inventory, the policy in
 * force, how each credential is handled, tool calls by outcome, and every hold, denial, refusal and change the guard
 * recorded, each row citing the line of the guard log it came from. A PDF summary, a scope-limits section and a map of
 * where to look by control theme come with it. Names only: no arguments, results or credential values.
 *
 * Deterministic: the same guard log, configs and period give the same record files and the same core hash. The core
 * hash covers the record files; the PDF, README and manifest describe them and are hashed individually.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { LOCAL_PACK_THEMES, Pdf, THEME_NOTE, serializePolicyYaml, type Component } from "./policy/index.js";
import { discoverLocal } from "./discover.js";
import { buildInventory, type Inventory } from "./inventory.js";
import { parseSince } from "./policytest.js";
import { HOME, VERSION, readOrg, readPolicy } from "./state.js";
import { SecretStore } from "./store.js";

export const LOCAL_SCHEMA = "arp-local-1.0";
const sha = (b: string | Uint8Array) => createHash("sha256").update(b).digest("hex");
const csvCell = (v: unknown) => { const s = v === null || v === undefined ? "" : String(v); return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
const csv = (head: string[], rows: unknown[][]) => [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\n") + "\n";

export const SCOPE_LIMITS = [
  "This pack covers one machine and what its guard recorded: MCP servers launched under the guard from the supported agents, in the period shown. A server that was not under the guard appears in the inventory and nowhere else.",
  "Not covered: shell commands and file reads an agent makes outside MCP tool calls; remote servers that sign in with OAuth or a browser; anything the agent did before the guard was installed or while it was uninstalled.",
  "Tool calls are recorded by tool name and argument names. Argument values, results and credential values are never recorded, so the pack cannot show what data a call carried.",
  "A configured rule is not evidence it was exercised, and a recorded call is not evidence of what the call did.",
  "The inventory is a snapshot taken when the pack was made, not a history of the period. Policy history is not kept on a personal machine: policy.yaml is the policy in force at generation time.",
  "The guard log is a local file the machine's user can edit. The hashes in manifest.json show this pack was not altered after it was written; they do not show the log was complete or untouched before that.",
  "KillerSkills verdicts in the inventory describe what a sandbox run reached for that version; see the verdict page for its coverage.",
];

export interface LocalPackInput { events: Record<string, unknown>[]; inventory: Inventory; components: Component[]; policyYaml: string; policySource: string; stored: string[]; from: Date; to: Date; generatedAt: Date; machine: string }
export interface LocalPack { files: Map<string, Uint8Array | string>; manifest: Record<string, unknown>; coreHash: string }

/** Pure: everything the pack contains is computed from the input. `generatedAt` appears in the manifest, README and PDF only. */
export function buildLocalPack(x: LocalPackInput): LocalPack {
  const iso = (d: Date) => d.toISOString();
  const inWindow = x.events.map((e, i) => ({ e, line: i + 1 })).filter(({ e }) => typeof e.at === "string" && e.at >= iso(x.from) && e.at <= iso(x.to));
  // events.csv: one row per hold, denial, refusal, stop or change, in log order, with the log line it came from.
  const ev: unknown[][] = [];
  const calls = new Map<string, { server: string; tool: string; calls: number; allowed: number; held: number; denied: number; first: string; last: string }>();
  const sessions = new Set<string>();
  for (const { e, line } of inWindow) {
    const at = String(e.at); const server = typeof e.server === "string" ? e.server : ""; const pkg = typeof e.pkg === "string" ? e.pkg : "";
    if (typeof e.session === "string" && e.kind === "start") sessions.add(e.session);
    if (e.kind === "tool_call" && typeof e.tool === "string") {
      if (e.action !== "held") {
        const k = `${server}\u0000${e.tool}`; const c = calls.get(k) ?? { server, tool: e.tool, calls: 0, allowed: 0, held: 0, denied: 0, first: at, last: at };
        c.calls++; if (e.action === "allowed") c.allowed++; else if (e.action === "approved") c.held++; else c.denied++;
        if (at < c.first) c.first = at; if (at > c.last) c.last = at; calls.set(k, c);
      }
      if (e.action === "held") ev.push([at, "tool_call_held", server, pkg, e.tool, String(e.reason ?? ""), "", line]);
      else if (e.action === "approved") ev.push([at, "tool_call_approved", server, pkg, e.tool, "", String(e.by ?? ""), line]);
      else if (e.action === "denied" || e.action === "refused") ev.push([at, "tool_call_denied", server, pkg, e.tool, String(e.reason ?? ""), String(e.by ?? ""), line]);
    } else if (e.kind === "launch_refused") ev.push([at, "launch_refused", server, pkg, "", String(e.why ?? ""), "", line]);
    else if (e.kind === "revoked_running") ev.push([at, "revoked_while_running", server, pkg, "", String(e.why ?? ""), String(e.action ?? ""), line]);
    else if (e.kind === "stopped") ev.push([at, "server_stopped", server, pkg, "", String(e.reason ?? ""), "", line]);
    else if (e.kind === "update_escalates") ev.push([at, "update_reached_for_more", server, pkg, "", String(e.summary ?? ""), String(e.action ?? ""), line]);
    else if (e.kind === "remote_changed") ev.push([at, "tool_list_changed", server, pkg, "", `${Array.isArray(e.added) ? e.added.length : 0} new, ${Array.isArray(e.rewritten) ? e.rewritten.length : 0} rewritten`, String(e.action ?? ""), line]);
    else if (e.kind === "host" && e.expected === false) ev.push([at, "unexpected_host", server, pkg, "", String(e.host ?? ""), String(e.mode ?? ""), line]);
    else if (e.kind === "credential_raised") ev.push([at, "write_credential_minted", server, pkg, String(e.tool ?? ""), String(e.name ?? ""), String(e.exchange ?? ""), line]);
    else if (e.kind === "canary") ev.push([at, "decoy_credential_touched", server, pkg, String(e.tool ?? ""), String(e.where ?? ""), "", line]);
  }
  const toolRows = [...calls.values()].sort((a, b) => a.server.localeCompare(b.server) || a.tool.localeCompare(b.tool));
  // credentials.json: for each credential name, who is handed it and where its value lives.
  const refs = new Set(x.stored);
  const credentials = x.inventory.credentials.map((k) => ({ name: k.name, class: k.class, uses: k.uses.map((u) => ({ agent: u.agent, server: u.server, transport: u.transport, guarded: u.guarded, value: u.plaintext ? "written in the agent's config" : [...refs].some((r) => r.endsWith(`/${u.server}/${k.name}`)) ? "held in the guard's store" : "referenced from the environment" })) }));
  const inv = { agents: x.inventory.agents, other_findings: x.inventory.other_findings, totals: x.inventory.totals };

  const files = new Map<string, Uint8Array | string>();
  files.set("inventory.json", JSON.stringify(inv, null, 2) + "\n");
  files.set("credentials.json", JSON.stringify({ stored_in_guard: [...refs].sort(), credentials }, null, 2) + "\n");
  files.set("policy.yaml", x.policyYaml.endsWith("\n") ? x.policyYaml : x.policyYaml + "\n");
  files.set("tool_calls.csv", csv(["server", "tool", "calls", "allowed", "approved_after_hold", "denied", "first_at", "last_at"], toolRows.map((r) => [r.server, r.tool, r.calls, r.allowed, r.held, r.denied, r.first, r.last])));
  files.set("events.csv", csv(["at", "event", "server", "package_or_host", "tool", "detail", "actor_or_action", "guard_log_line"], ev));
  const core = [...files.keys()].sort();
  const coreHash = sha(core.map((n) => `${n} ${sha(files.get(n)!)}`).join("\n"));

  const t = x.inventory.totals; const sum = toolRows.reduce((a, r) => ({ calls: a.calls + r.calls, allowed: a.allowed + r.allowed, held: a.held + r.held, denied: a.denied + r.denied }), { calls: 0, allowed: 0, held: 0, denied: 0 });
  const period = `${iso(x.from).slice(0, 10)} to ${iso(x.to).slice(0, 10)} (UTC)`;
  const p = new Pdf();
  p.title("Agent-Tool Access Review Pack: one machine");
  p.p(`Machine: ${x.machine}   Period: ${period}   Generated: ${iso(x.generatedAt)}   Schema: ${LOCAL_SCHEMA}   vet-skills ${VERSION}`);
  p.h2("1. Scope and what this pack does not cover");
  for (const l of SCOPE_LIMITS) p.p(l);
  p.h2("2. Inventory at generation time");
  p.p(`${t.servers} MCP server(s) in ${t.agents} agent(s): ${t.guarded} under the guard, ${t.not_guarded} local and not under the guard, ${t.remote} remote; ${t.no_verdict} with no verdict, ${t.blocked} with a blocked verdict; ${t.plaintext} credential(s) written in a config; ${t.skills} skill(s). [inventory.json]`);
  const srv = x.inventory.agents.flatMap((a) => a.servers.map((s) => [a.label, s.name, s.transport, s.guarded ? "guarded" : s.transport === "stdio" ? "not guarded" : "outside", s.verdict ? `${s.verdict.label}${s.verdict.exact ? "" : " (latest)"}` : s.package ? "no verdict" : "-", s.package ? `${s.package.name}${s.version ? `@${s.version}` : ""}` : s.target]));
  if (srv.length) p.table(["Agent", "Server", "Transport", "Guard", "Verdict", "Package or host"], srv.slice(0, 80), [16, 18, 9, 11, 18, 34]);
  p.h2("3. Policy in force");
  p.p(`The policy on this machine at generation time came from: ${x.policySource}. The full text is policy.yaml. No policy history is kept on a personal machine. [policy.yaml]`);
  p.h2("4. Credential handling");
  p.p(`${credentials.length} credential name(s) are handed to MCP servers; the guard's store holds ${refs.size} value(s). [credentials.json]`);
  const cr = credentials.flatMap((k) => k.uses.map((u) => [k.name, u.server, u.agent, u.guarded ? "guarded" : "not guarded", u.value]));
  if (cr.length) p.table(["Credential", "Server", "Agent", "Guard", "Where the value is"], cr.slice(0, 80), [30, 18, 16, 11, 31]);
  p.h2("5. Activity in the period");
  p.p(`${sessions.size} guarded session(s) started. ${sum.calls} tool call(s): ${sum.allowed} allowed, ${sum.held} approved after a hold, ${sum.denied} denied. [tool_calls.csv]`);
  if (toolRows.length) p.table(["Server", "Tool", "Calls", "Denied", "Last"], toolRows.slice(0, 80).map((r) => [r.server, r.tool, String(r.calls), String(r.denied), r.last.slice(0, 16)]), [20, 40, 7, 7, 17]);
  p.p(`${ev.length} event(s) worth a reviewer's attention (holds, denials, refusals, stops, changes, unexpected hosts). Each row cites its line in the guard log. [events.csv]`);
  if (ev.length) p.table(["At", "Event", "Server", "Detail", "Line"], ev.slice(0, 80).map((r) => [String(r[0]).slice(0, 16), String(r[1]), String(r[2]), `${r[4] ? `${r[4]}: ` : ""}${r[5]}`, String(r[7])]), [17, 24, 16, 42, 6]);
  p.h2("6. Where to look, by control theme");
  p.p(`${THEME_NOTE} [manifest.json#control_themes]`);
  for (const th of LOCAL_PACK_THEMES) p.p(`Evidence relevant to ${th.theme.toLowerCase()}: ` + th.evidence.map((e) => `${e.file} (${e.records})`).join("; ") + ".", 9);
  p.small(`Integrity: manifest.json hashes every file; core hash ${coreHash} covers the record files. This pack supports evidence gathering for a review. It is not a certification, and KillerSkills holds no SOC 2 report at the time of generation.`);
  const pdf = p.build();

  const readme = [`AGENT-TOOL ACCESS REVIEW PACK: ONE MACHINE`, ``, `Machine: ${x.machine}`, `Period: ${period}`, `Generated: ${iso(x.generatedAt)} by vet-skills ${VERSION} (schema ${LOCAL_SCHEMA})`, ``, `FILES`, `  review.pdf        Readable summary; every statement cites a file here.`, `  inventory.json    Agents, MCP servers, guarded or not, verdicts, credential names, skills. A snapshot at generation time.`, `  credentials.json  For each credential name: the servers handed it and where its value lives. Names only.`, `  policy.yaml       The policy in force on this machine at generation time.`, `  tool_calls.csv    Tool calls in the period by server and tool, with outcomes.`, `  events.csv        Holds, denials, refusals, stops, changes and unexpected hosts, each with its guard log line.`, `  manifest.json     Period, file hashes, the core hash, scope limits and the control-theme map.`, ``, `WHAT THIS PACK DOES NOT COVER`, ...SCOPE_LIMITS.map((l) => `  - ${l}`), ``, `VERIFY`, `  sha256 of each file is in manifest.json. core_hash = sha256 of the sorted "name sha256" lines of: ${core.join(", ")}.`, ``].join("\n");
  files.set("review.pdf", pdf); files.set("README.txt", readme);
  const manifest = {
    schema: LOCAL_SCHEMA, machine: x.machine, period: { start: iso(x.from), end: iso(x.to) }, generated_at: iso(x.generatedAt), vet_skills: VERSION, policy_source: x.policySource,
    row_counts: { servers: t.servers, credentials: credentials.length, tool_call_rows: toolRows.length, events: ev.length, sessions: sessions.size },
    scope_limits: SCOPE_LIMITS, control_themes: { note: THEME_NOTE, themes: LOCAL_PACK_THEMES },
    redactions: ["Argument values and results of tool calls are never recorded.", "Credential values are never recorded; names and where the value lives only."],
    integrity: { method: "sha256 per file; core_hash = sha256 of the sorted 'name sha256' lines for the record files", core_files: core },
    core_hash: coreHash, files: [...files.keys()].sort().map((n) => ({ name: n, bytes: typeof files.get(n) === "string" ? Buffer.byteLength(files.get(n) as string) : (files.get(n) as Uint8Array).length, sha256: sha(files.get(n)!) })),
  };
  files.set("manifest.json", JSON.stringify(manifest, null, 2) + "\n");
  return { files, manifest, coreHash };
}

/** Check a pack folder against its manifest: every file's hash and the core hash. */
export function verifyLocalPack(dir: string): { ok: boolean; mismatches: string[]; coreHash: string | null } {
  let m: { files: { name: string; sha256: string }[]; core_hash: string; integrity: { core_files: string[] } };
  try { m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")); } catch { return { ok: false, mismatches: ["manifest.json missing or unreadable"], coreHash: null }; }
  const mismatches: string[] = []; const got = new Map<string, string>();
  for (const f of m.files) { try { const h = sha(readFileSync(join(dir, f.name))); got.set(f.name, h); if (h !== f.sha256) mismatches.push(`${f.name} hash differs`); } catch { mismatches.push(`${f.name} missing`); } }
  const core = sha([...m.integrity.core_files].sort().map((n) => `${n} ${got.get(n) ?? "missing"}`).join("\n"));
  if (core !== m.core_hash) mismatches.push("core_hash differs");
  return { ok: !mismatches.length, mismatches, coreHash: m.core_hash };
}

export async function reviewPackCmd(argv: string[], flags: { since?: string; out?: string; json?: boolean; project?: boolean }): Promise<number> {
  if (argv[0] === "verify") {
    if (!argv[1]) { console.error("usage: vet-skills review-pack verify <folder>"); return 2; }
    const v = verifyLocalPack(argv[1]);
    console.log(v.ok ? `✓ ${argv[1]}: every file matches its hash; core hash ${v.coreHash}` : `✕ ${argv[1]}: ${v.mismatches.join("; ")}`);
    return v.ok ? 0 : 1;
  }
  const days = parseSince(flags.since);
  const to = new Date(); const from = new Date(to.getTime() - days * 86_400_000);
  let events: Record<string, unknown>[] = [];
  try { events = readFileSync(join(HOME, "runtime", "guard.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return {}; } }); } catch { /* no guard log yet */ }
  const components = discoverLocal({ project: flags.project ? process.cwd() : undefined });
  const inventory = await buildInventory({ components });
  const { policy, source } = readPolicy();
  const pack = buildLocalPack({ events, inventory, components, policyYaml: serializePolicyYaml(policy), policySource: source === "org" ? `the organization ${readOrg()?.slug ?? ""}` : source === "personal" ? "this machine's policy file" : "the built-in default", stored: new SecretStore().list().map((k) => k.key), from, to, generatedAt: to, machine: createHash("sha256").update(HOME).digest("hex").slice(0, 12) });
  const dir = flags.out ?? `vet-skills-review-${from.toISOString().slice(0, 10)}_${to.toISOString().slice(0, 10)}`;
  mkdirSync(dir, { recursive: true });
  for (const [name, data] of pack.files) writeFileSync(join(dir, name), data);
  const rc = pack.manifest.row_counts as Record<string, number>;
  if (flags.json) console.log(JSON.stringify({ dir, core_hash: pack.coreHash, row_counts: rc }, null, 2));
  else {
    console.log(`✓ Review pack written to ${dir}/ (${Math.round(days)} days): ${rc.servers} servers, ${rc.credentials} credential names, ${rc.tool_call_rows} tool rows, ${rc.events} events.`);
    console.log(`  review.pdf is the readable summary; README.txt lists what the pack does not cover. Core hash ${pack.coreHash.slice(0, 16)}…`);
    console.log(`  Check it later: vet-skills review-pack verify ${dir}`);
    if (readOrg()) console.log(`  This machine is in ${readOrg()!.slug}: the organization's pack (vet-skills review create) covers every enrolled machine and carries a reviewer's acknowledgment.`);
  }
  return 0;
}
