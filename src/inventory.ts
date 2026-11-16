/**
 * `vet-skills inventory`: what this machine's agents can reach, in one table. Per agent: its MCP servers (local and
 * remote), whether each runs under the guard, the KillerSkills verdict for the version in use, the credential names
 * its config passes, and its installed skills. Every finding carries the command that fixes it.
 *
 * Read-only: no config is modified. Only names are read out of a config (the parser drops values and arguments), and
 * nothing is sent anywhere on a machine that is not enrolled, apart from verdict lookups by package name and version.
 */
import { execFile } from "node:child_process";
import type { Component } from "./policy/index.js";
import { resolveSkill } from "./api.js";
import { discoverLocal } from "./discover.js";
import { readPins } from "./guard.js";
import { c, pad } from "./render.js";

export const AGENT_LABEL: Record<string, string> = {
  claude_code: "Claude Code", claude_desktop: "Claude Desktop", cursor: "Cursor", vscode: "VS Code", windsurf: "Windsurf", gemini_cli: "Gemini CLI", codex: "Codex CLI",
  grok: "Grok CLI", copilot: "Copilot CLI", kiro: "Kiro", qwen: "Qwen Code", cline: "Cline", zed: "Zed", amp: "Amp", opencode: "OpenCode", continue: "Continue", any: "Other",
};
/** Agents with a command-line binary that answers `--version` quickly. Desktop apps are reported without a version. */
const VERSION_BIN: Record<string, string> = { claude_code: "claude", codex: "codex", gemini_cli: "gemini", grok: "grok", copilot: "copilot", qwen: "qwen", cursor: "cursor", amp: "amp", opencode: "opencode", kiro: "kiro" };
/** Agents `vet-skills guard install` can put under the guard (Continue is listed and checked, not wrapped). */
const GUARDABLE = new Set(["claude_code", "claude_desktop", "cursor", "vscode", "windsurf", "gemini_cli", "codex", "grok", "copilot", "kiro", "qwen", "cline", "zed", "amp", "opencode"]);

export type InventoryVerdict = { label: "verified" | "caution" | "blocked"; version: string; exact: boolean; page: string } | null;
export interface InventoryServer {
  name: string; file: string; scope: "user" | "project";
  transport: "stdio" | "http" | "sse";
  /** Package spec for registry packages, the host for remote servers, otherwise the executable's name. */
  target: string;
  package: { registry: string; name: string } | null;
  /** The version in use and how we know it: pinned in the config, or the one the guard last launched here. */
  version: string | null; versionSource: "config" | "last run" | null;
  guarded: boolean;
  verdict: InventoryVerdict;
  /** Names only. */
  credentials: string[];
  /** Credential names whose value is written into the config file itself. */
  plaintext: string[];
  fixes: string[];
}
export interface InventorySkill { name: string; file: string; scope: "user" | "project"; verdict: InventoryVerdict; fixes: string[] }
export interface InventoryAgent { agent: string; label: string; version: string | null; servers: InventoryServer[]; skills: InventorySkill[] }
export interface Inventory {
  generated_at: string;
  agents: InventoryAgent[];
  /** Files with a pasted credential that no listed server accounts for, installer lures and hidden instructions. */
  other_findings: { kind: string; file: string; detail: string; fix: string }[];
  totals: { agents: number; servers: number; guarded: number; not_guarded: number; remote: number; no_verdict: number; blocked: number; plaintext: number; skills: number };
}

type Lookup = (q: string, registry?: string) => Promise<{ label: "verified" | "caution" | "blocked"; version: string; page: string } | null>;
const remoteLookup: Lookup = async (q, registry) => {
  const r = await resolveSkill(q, registry);
  if (!r.ok || !r.data.verdict) return null;
  return { label: r.data.verdict.label, version: r.data.version.semver, page: r.data.skill.page };
};

function agentVersion(bin: string): Promise<string | null> {
  return new Promise((res) => {
    try {
      execFile(bin, ["--version"], { timeout: 2500, windowsHide: true }, (err, stdout) => res(err ? null : (String(stdout).match(/\d+\.\d+\.\d+[\w.-]*/)?.[0] ?? null)));
    } catch { res(null); }
  });
}

const spec = (p: { name: string }, v: string | null) => (v ? `${p.name}@${v}` : p.name);

export async function buildInventory(opts: { home?: string; project?: string; components?: Component[]; lookup?: Lookup; pins?: Record<string, { semver: string }>; probeVersions?: boolean } = {}): Promise<Inventory> {
  const comps = opts.components ?? discoverLocal({ home: opts.home, project: opts.project });
  const lookup = opts.lookup ?? remoteLookup;
  const pins = opts.pins ?? readPins();
  const secrets = comps.filter((x) => x.kind === "secret");
  const claimed = new Set<Component>();
  const cache = new Map<string, Promise<Awaited<ReturnType<Lookup>>>>();
  const once = (q: string, registry?: string) => { const k = `${registry ?? ""}|${q}`; if (!cache.has(k)) cache.set(k, lookup(q, registry).catch(() => null)); return cache.get(k)!; };

  const byAgent = new Map<string, InventoryAgent>();
  const agentOf = (a: string) => { if (!byAgent.has(a)) byAgent.set(a, { agent: a, label: AGENT_LABEL[a] ?? a, version: null, servers: [], skills: [] }); return byAgent.get(a)!; };

  await Promise.all(comps.filter((x) => x.kind === "mcp_server").map(async (x) => {
    const remote = x.transport === "http";
    const pin = x.package ? pins[`${x.package.registry}:${x.package.name}`] : undefined;
    const version = x.package?.version ?? pin?.semver ?? null;
    const versionSource = x.package?.version ? "config" as const : pin?.semver ? "last run" as const : null;
    let verdict: InventoryVerdict = null;
    if (x.package) {
      const exact = version ? await once(`${x.package.name}@${version}`, x.package.registry) : null;
      if (exact) verdict = { ...exact, exact: true };
      // No version known: the latest verdict is the best available answer, and the table says it is the latest, not this machine's.
      else if (!version) { const latest = await once(x.package.name, x.package.registry); if (latest) verdict = { ...latest, exact: false }; }
    }
    const names = [...new Set([...x.envKeys, ...x.headerKeys])];
    const pasted = secrets.filter((sec) => sec.path === x.path);
    // Written in the file: a value our secret patterns recognize, or any literal under a credential-like name.
    const plaintext = names.filter((n) => pasted.some((sec) => sec.envKeys.includes(n)) || (x.literalKeys ?? []).includes(n));
    if (plaintext.length) for (const sec of pasted) claimed.add(sec);
    const fixes: string[] = [];
    if (verdict?.label === "blocked") fixes.push(`blocked verdict: remove it from ${x.path}; \`vet-skills check ${x.package!.name}\` shows why`);
    if (!remote && !x.guarded) fixes.push(GUARDABLE.has(x.agent) ? "not guarded: run `vet-skills guard install`" : `not guarded: the guard does not wrap ${AGENT_LABEL[x.agent] ?? x.agent} configs yet`);
    if (remote && !x.guarded) fixes.push(names.length ? "remote server outside the guard: run `vet-skills guard install` to bridge it and move its credential header into the guard's store" : "remote server outside the guard: it signs in by itself (OAuth) or takes no credential, which the guard does not wrap");
    if (x.package && !verdict) fixes.push(version ? `no verdict for ${version}: run \`vet-skills try ${spec(x.package, version)}\`` : `no verdict: run \`vet-skills try ${x.package.name}\``);
    if (!x.package && !remote) fixes.push("local command: there is no registry package to look up a verdict for");
    if (plaintext.length) fixes.push(`credential value written in ${x.path} (${plaintext.join(", ")}): run \`vet-skills secrets migrate\``);
    agentOf(x.agent).servers.push({
      name: x.name, file: x.path, scope: x.scope, transport: remote ? (x.remoteKind ?? "http") : "stdio",
      target: x.package ? spec(x.package, x.package.version ?? null) : x.urlHost ?? x.command ?? "",
      package: x.package ? { registry: x.package.registry, name: x.package.name } : null,
      version, versionSource, guarded: !!x.guarded, verdict, credentials: names, plaintext, fixes,
    });
  }));

  await Promise.all(comps.filter((x) => x.kind === "skill").slice(0, 100).map(async (x) => {
    const v = await once(x.name);
    agentOf(x.agent === "any" ? "claude_code" : x.agent).skills.push({ name: x.name, file: x.path, scope: x.scope, verdict: v ? { ...v, exact: false } : null, fixes: v?.label === "blocked" ? [`blocked verdict: remove ${x.path}`] : v ? [] : ["no verdict: this skill is not in a registry KillerSkills tests"] });
  }));

  if (opts.probeVersions !== false) await Promise.all([...byAgent.values()].map(async (a) => { const bin = VERSION_BIN[a.agent]; if (bin) a.version = await agentVersion(bin); }));

  const other: Inventory["other_findings"] = [];
  for (const sec of secrets) if (!claimed.has(sec)) other.push({ kind: "credential in a config file", file: sec.path, detail: sec.detail ?? sec.name, fix: "rotate it, then reference an environment variable" });
  for (const l of comps.filter((x) => x.kind === "lure")) other.push({ kind: "installer lure", file: l.path, detail: l.detail ?? l.name, fix: "do not run anything from this folder; remove it" });
  for (const h of comps.filter((x) => x.kind === "instructions" && / \(hidden text\)$/.test(x.name))) other.push({ kind: "hidden instructions", file: h.path, detail: h.detail ?? "", fix: "open the file and remove the text you did not write" });

  const order = Object.keys(AGENT_LABEL);
  const agents = [...byAgent.values()].sort((a, b) => order.indexOf(a.agent) - order.indexOf(b.agent));
  for (const a of agents) { a.servers.sort((x, y) => x.name.localeCompare(y.name) || x.file.localeCompare(y.file)); a.skills.sort((x, y) => x.name.localeCompare(y.name)); }
  const servers = agents.flatMap((a) => a.servers);
  return {
    generated_at: new Date().toISOString(), agents, other_findings: other,
    totals: {
      agents: agents.length, servers: servers.length, guarded: servers.filter((s) => s.guarded).length,
      not_guarded: servers.filter((s) => s.transport === "stdio" && !s.guarded).length, remote: servers.filter((s) => s.transport !== "stdio").length,
      no_verdict: servers.filter((s) => s.package && !s.verdict).length, blocked: servers.filter((s) => s.verdict?.label === "blocked").length,
      plaintext: servers.filter((s) => s.plaintext.length).length + other.filter((o) => o.kind === "credential in a config file").length,
      skills: agents.reduce((n, a) => n + a.skills.length, 0),
    },
  };
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const tone = (v: InventoryVerdict) => (!v ? c.muted : v.label === "verified" ? c.verified : v.label === "blocked" ? c.blocked : c.caution);
const verdictCell = (v: InventoryVerdict, hasPackage: boolean) => (v ? `${v.label}${v.exact ? "" : " (latest)"}` : hasPackage ? "no verdict" : "-");

/** The human table. One block per agent, one row per server, the fix under the row it belongs to, one next step at the end. */
export function renderInventory(inv: Inventory): string {
  const out: string[] = [];
  const t = inv.totals;
  if (!t.servers && !t.skills && !inv.other_findings.length) {
    return `${c.verified("✓")} Nothing is configured yet: no MCP servers or skills in the places Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex CLI, Gemini CLI and the other supported agents keep them.\n\nBefore you install one: ${c.ink2("vet-skills check <name>")}`;
  }
  for (const a of inv.agents) {
    out.push("", `${c.bold(a.label)}${a.version ? c.muted(` ${a.version}`) : ""}  ${c.muted(`${plural(a.servers.length, "MCP server")}${a.skills.length ? `, ${plural(a.skills.length, "skill")}` : ""}`)}`);
    for (const s of a.servers) {
      const guard = s.guarded ? c.verified(pad("guarded", 12)) : s.transport !== "stdio" ? c.caution(pad("remote", 12)) : c.caution(pad("not guarded", 12));
      const ver = s.version ? `${s.version}${s.versionSource === "last run" ? " (last run)" : ""}` : s.package ? "unpinned" : "";
      out.push(`  ${pad(s.name, 22)} ${pad(s.transport, 6)} ${guard} ${tone(s.verdict)(pad(verdictCell(s.verdict, !!s.package), 18))} ${c.ink2(s.package ? s.package.name : s.target)}${ver ? c.muted(` ${ver}`) : ""}`);
      if (s.credentials.length) out.push(c.muted(`  ${" ".repeat(22)} passes: ${s.credentials.slice(0, 6).join(", ")}${s.credentials.length > 6 ? ` +${s.credentials.length - 6}` : ""}`));
      for (const f of s.fixes) out.push(c.muted(`  ${" ".repeat(22)} → ${f}`));
    }
    if (a.skills.length) {
      out.push(c.muted("  skills"));
      for (const k of a.skills) out.push(`  ${pad(k.name, 22)} ${pad("", 6)} ${pad("", 12)} ${tone(k.verdict)(pad(verdictCell(k.verdict, true), 18))} ${c.muted(k.file)}`);
    }
  }
  if (inv.other_findings.length) {
    out.push("", c.bold("Also found"));
    for (const o of inv.other_findings) out.push(`  ${c.blocked(o.kind)}  ${o.file}`, c.muted(`    ${o.detail}`), c.muted(`    → ${o.fix}`));
  }
  out.push("", `${plural(t.servers, "MCP server")} in ${plural(t.agents, "agent")}: ${t.guarded} guarded, ${t.not_guarded} not guarded, ${t.remote} remote · ${t.no_verdict} with no verdict · ${t.blocked} blocked · ${plural(t.plaintext, "credential")} written in a config · ${plural(t.skills, "skill")}`);
  out.push(`${c.bold("Next:")} ${nextStep(inv)}`);
  return out.join("\n");
}

/** The single most useful thing to do next. */
export function nextStep(inv: Inventory): string {
  const t = inv.totals;
  const lure = inv.other_findings.find((o) => o.kind === "installer lure");
  if (lure) return `remove ${lure.file}; it matches a malware delivery pattern.`;
  if (t.blocked) return "remove the server with a blocked verdict (marked above).";
  if (t.plaintext) return "run `vet-skills secrets migrate` to move the credentials written in config files into the guard's store (and rotate any that were shared or committed).";
  if (t.not_guarded) return `run \`vet-skills guard install\` to put ${plural(t.not_guarded, "local server")} under the guard. It starts by recording; nothing is blocked until a policy says so.`;
  if (t.no_verdict) return "run `vet-skills try <package>` for the servers with no verdict.";
  if (inv.agents.some((a) => a.servers.some((s) => s.transport !== "stdio" && !s.guarded))) return "review the remote servers that are not under the guard: `vet-skills guard install` bridges the ones with a credential header.";
  return "nothing to fix. Run `vet-skills guard status` to see what the guarded servers reached this week.";
}

/** What an enrolled machine reports: the parsed components, with the version each package was last launched at filled in. */
export function componentsForSync(comps: Component[], pins: Record<string, { semver: string }> = readPins()): Component[] {
  return comps.map((x) => {
    if (x.kind !== "mcp_server" || !x.package || x.package.version) return x;
    const pin = pins[`${x.package.registry}:${x.package.name}`];
    return pin?.semver ? { ...x, package: { ...x.package, version: pin.semver } } : x;
  });
}
