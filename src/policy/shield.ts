/**
 * KillerSkills Shield: a small, readable file for one package version that lists the narrowing actions the guard
 * already enforces, and the evidence each one rests on. Pure and dependency-free, shared by the site and the CLI.
 *
 * A shield only narrows. It is built from what a sandbox run recorded, it never adds a host, allows a tool or widens
 * anything, and `narrows()` proves that for every shield before it is stored or published. No model is involved in
 * building one here, and nothing in this file makes a decision at run time: `compileShield` maps a shield onto flags
 * and rules the guard already has.
 */
import { DESTRUCTIVE_TOOL_GLOBS, toolClass, type ToolRule } from "./index.js";
import { IRREVERSIBLE_TOOL } from "./replay.js";

export const SHIELD_SCHEMA = "killerskills.shield/v1";
export const SHIELD_PAYLOAD_TYPE = "application/vnd.killerskills.shield.v1+yaml";
/** The first CLI whose `run` enforces every lever a v1 shield may carry. */
export const SHIELD_MIN_CLI = "0.16.0";
export type ShieldLever = "pin" | "net" | "contain" | "tools" | "secrets";

export interface ShieldPackage { registry: string; name: string; semver: string; artifact_hash: string }
export interface Shield {
  schema: typeof SHIELD_SCHEMA;
  package: ShieldPackage;
  finding_refs: { kind: "exposure_finding" | "drift_event" | "replay"; ref: string }[];
  evidence: { verdict_id: string; engine_version: string; coverage: string; ran_at: string };
  rules: {
    pin?: { semver: string; artifact_hash: string; reason: string; evidence: string };
    net?: { mode: "hosts" | "closed"; hosts: string[]; reason: string; evidence: string };
    contain?: { enabled: true; reason: string; evidence: string };
    tools?: { match: string; action: "deny" | "approve"; reason: string; evidence: string }[];
    secrets?: { name: string; host: string; evidence: string }[];
  };
  not_enforced: string[];
  drafted_by: string;
  min_cli: string;
  created_at: string;
}

/** What a sandbox run recorded, in the shape a shield is built from. Names and hosts only. */
export interface ShieldEvidence {
  package: ShieldPackage;
  verdictId: string; engineVersion: string; coverage: string; ranAt: string;
  /** Every host the run contacted, with whether the package declares it. */
  egress: { host: string; declared: boolean }[];
  /** Hosts named in the package's code as where a credential goes. */
  surfaceHosts: string[];
  /** Credential files the run read, as `~/.aws/credentials`. */
  credentialFiles: string[];
  /** Tool names the run saw, or null when the list is not known. */
  tools: string[] | null;
  /** Credential variables the code reads, with the host each is sent to when the code shows one. */
  credentialEnv: { name: string; host: string | null }[];
  /** A published change between this version and the one before it, when the earlier version did not show it. */
  drift?: { id: string; fromSemver: string; fromArtifactHash: string; summary: string; eligible: boolean } | null;
  findingRefs?: Shield["finding_refs"];
}

const glob = (g: string) => new RegExp(`^${g.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`, "i");
const DESTRUCTIVE = DESTRUCTIVE_TOOL_GLOBS.map(glob);
const bare = (t: string) => (t.includes("/") ? t.slice(t.lastIndexOf("/") + 1) : t);
const uniq = (xs: string[]) => [...new Set(xs)].sort();
const HOST = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d+)?$/i;

/** Which builder rules wrote a shield. A stored shield from older rules is rebuilt, never served. */
export const SHIELD_RULES = "rules.2";
/**
 * The registry a launcher downloads the package from. It stays reachable under every network rule, because the
 * shielded command starts the server through npx or uvx and a refused download would stop it before it starts.
 */
export const REGISTRY_HOSTS: Record<string, string[]> = { npm: ["registry.npmjs.org"], pypi: ["pypi.org", "files.pythonhosted.org"] };
const registryHosts = (registry: string) => REGISTRY_HOSTS[registry] ?? [];
const isRegistryHost = (h: string) => Object.values(REGISTRY_HOSTS).some((l) => l.includes(h));

export const SHIELD_CAVEATS = [
  "The network limit applies to clients that honor proxies.",
  "Filesystem containment uses sandbox-exec on macOS and bwrap on Linux. It is not available on Windows.",
  "Subprocess limits are not part of this shield version.",
  "Extra file paths beyond the credential set, and removing variables from the server's environment, are not part of this shield version.",
];

/** A shield from stored evidence alone. The same evidence always gives the same bytes. Returns null when nothing in the evidence calls for a rule. */
export function buildRuleShield(e: ShieldEvidence, createdAt = e.ranAt): Shield | null {
  const rules: Shield["rules"] = {};
  const notEnforced = [...SHIELD_CAVEATS];
  const declared = uniq([...e.egress.filter((h) => h.declared).map((h) => h.host), ...e.surfaceHosts].filter((h) => HOST.test(h) && !isRegistryHost(h)));
  const undeclared = uniq(e.egress.filter((h) => !h.declared && !isRegistryHost(h.host)).map((h) => h.host));

  if (e.credentialFiles.length) rules.contain = { enabled: true, reason: `read ${uniq(e.credentialFiles).slice(0, 3).join(", ")} in our sandbox`, evidence: "traces.files_read" };
  if (undeclared.length) {
    if (declared.length) rules.net = { mode: "hosts", hosts: declared, reason: `contacted ${undeclared.length === 1 ? "a host" : `${undeclared.length} hosts`} it does not declare; only the hosts it declares stay reachable`, evidence: "traces.egress_hosts declared=true" };
    else { rules.net = { mode: "closed", hosts: [], reason: "contacted a host it does not declare, and no declared host is on record", evidence: "traces.egress_hosts" }; notEnforced.unshift("No declared host is on record for this package, so this shield leaves it only the package registry. A tool that needs the network for its work stops working under it until you add the hosts you use to the list."); }
  }
  if (e.tools?.length) {
    const t: NonNullable<Shield["rules"]["tools"]> = [];
    for (const name of uniq(e.tools.map(bare))) {
      if (toolClass(name) !== "write") continue;
      // Deny only a name that says it deletes or destroys. A tool that sends, deploys or pays is often the reason the
      // server is installed, so it is held for approval, the same as the default policy does.
      if (IRREVERSIBLE_TOOL.test(name)) t.push({ match: name, action: "deny", reason: "deletes or destroys by name", evidence: "IRREVERSIBLE_TOOL" });
      else if (DESTRUCTIVE.some((re) => re.test(name))) t.push({ match: name, action: "approve", reason: "changes state outside this machine by name", evidence: "DESTRUCTIVE_TOOL_GLOBS" });
      else t.push({ match: name, action: "approve", reason: "changes state", evidence: "toolClass" });
    }
    if (t.length) rules.tools = t;
  }
  const brokered = e.credentialEnv.filter((c) => c.host && HOST.test(c.host)).map((c) => ({ name: c.name, host: c.host!, evidence: "verdicts.credential_surface" })).sort((a, b) => a.name.localeCompare(b.name));
  if (brokered.length) rules.secrets = brokered;
  if (e.drift?.eligible) rules.pin = { semver: e.drift.fromSemver, artifact_hash: e.drift.fromArtifactHash, reason: `${e.package.semver} ${e.drift.summary.replace(/^\S+\s/, "").replace(/\.$/, "")}; ${e.drift.fromSemver} did not`, evidence: `drift ${e.drift.id}` };

  // Tool rules and brokering are refinements. A tool list is not something the run recorded the server doing, so on
  // their own they never make a shield.
  const substantive = !!rules.contain || !!rules.net || !!rules.pin;
  if (!substantive) return null;
  if (rules.tools?.some((t) => t.action === "approve")) notEnforced.push("Approval for write tools applies only when the guard is installed (vet-skills guard install). The one-line command denies the destructive tools and leaves the rest as they are.");
  return { schema: SHIELD_SCHEMA, package: e.package, finding_refs: [...(e.findingRefs ?? [])].sort((a, b) => `${a.kind}${a.ref}`.localeCompare(`${b.kind}${b.ref}`)), evidence: { verdict_id: e.verdictId, engine_version: e.engineVersion, coverage: e.coverage, ran_at: e.ranAt }, rules, not_enforced: notEnforced, drafted_by: SHIELD_RULES, min_cli: SHIELD_MIN_CLI, created_at: createdAt };
}

/** What a person must read before using this shield. Shown next to the rules, never folded away. Null when there is nothing. */
export function shieldCaution(s: Shield): string | null {
  if (s.rules.net?.mode === "closed") return "We have no declared host on record for this package, so this shield leaves it the package registry and nothing else. If the tool needs the network for its work, add the hosts you use to the --net list. Every host you do not list is refused, including the one our run saw.";
  return null;
}

export function leversOf(s: Shield): ShieldLever[] {
  return (["pin", "net", "contain", "tools", "secrets"] as ShieldLever[]).filter((k) => { const v = s.rules[k]; return Array.isArray(v) ? v.length > 0 : !!v; });
}

/** What each lever does, in words a person outside security can read. No host, tool or package name appears. */
export function leverWords(s: Shield): string[] {
  const out: string[] = [];
  if (s.rules.pin) out.push("Pins the last version we saw without this behavior.");
  if (s.rules.net) out.push(s.rules.net.mode === "closed" ? "Closes the network for this tool, apart from the package registry it installs from." : `Limits the network to the ${s.rules.net.hosts.length === 1 ? "one host" : `${s.rules.net.hosts.length} hosts`} the tool declares, and the package registry it installs from.`);
  if (s.rules.contain) out.push("Keeps credential files outside the project out of reach.");
  const deny = (s.rules.tools ?? []).filter((t) => t.action === "deny").length, approve = (s.rules.tools ?? []).filter((t) => t.action === "approve").length;
  if (deny) out.push(`Denies ${deny === 1 ? "one tool that deletes or destroys by name" : `${deny} tools that delete or destroy by name`}.`);
  if (approve) out.push(`Holds ${approve === 1 ? "one write tool" : `${approve} write tools`} for approval when the guard is installed.`);
  if (s.rules.secrets?.length) out.push("Hands the server a placeholder in place of each credential, swapped for the real value only on the way to its own host.");
  return out;
}

/* ------------------------------------------------------------ the proof that a shield only narrows */

export function narrows(s: Shield, e: ShieldEvidence): { ok: boolean; why: string[] } {
  const why: string[] = [];
  const allowed = new Set([...e.egress.filter((h) => h.declared).map((h) => h.host), ...e.surfaceHosts]);
  if (s.package.artifact_hash !== e.package.artifact_hash || s.package.name !== e.package.name || s.package.semver !== e.package.semver) why.push("The shield is for a different package version than the evidence.");
  if (s.rules.net) {
    for (const h of s.rules.net.hosts) if (!allowed.has(h)) why.push(`The network rule adds a host the run never saw as declared: ${h}.`);
    if (s.rules.net.mode === "closed" && s.rules.net.hosts.length) why.push("A closed network lists hosts.");
    if (s.rules.net.mode === "hosts" && !s.rules.net.hosts.length) why.push("A host list with no hosts would leave the network open.");
  } else if (e.egress.some((h) => !h.declared && !isRegistryHost(h.host))) why.push("The run contacted an undeclared host and the shield has no network rule.");
  if (e.credentialFiles.length && !s.rules.contain) why.push("The run read a credential file and the shield does not contain it.");
  for (const t of s.rules.tools ?? []) if ((t.action as string) !== "deny" && (t.action as string) !== "approve") why.push(`A tool rule may only deny or hold for approval: ${t.match}.`);
  const mustDeny = (e.tools ?? []).map(bare).filter((n) => toolClass(n) === "write" && IRREVERSIBLE_TOOL.test(n));
  for (const n of uniq(mustDeny)) if (!(s.rules.tools ?? []).some((t) => t.action === "deny" && glob(t.match).test(n))) why.push(`A destructive tool is not denied: ${n}.`);
  for (const b of s.rules.secrets ?? []) if (!e.credentialEnv.some((c) => c.name === b.name && c.host === b.host)) why.push(`A brokered credential is sent somewhere the code does not show: ${b.name}.`);
  if (s.rules.pin && (!e.drift?.eligible || s.rules.pin.semver !== e.drift.fromSemver || s.rules.pin.artifact_hash !== e.drift.fromArtifactHash)) why.push("The pin is not the version before a published change.");
  const rules = [s.rules.pin, s.rules.net, s.rules.contain, ...(s.rules.tools ?? []), ...(s.rules.secrets ?? [])].filter(Boolean) as { evidence?: string }[];
  if (rules.some((r) => !r.evidence)) why.push("Every rule needs evidence.");
  return { ok: why.length === 0, why };
}

/* ------------------------------------------------------------ onto flags the guard already has */

export interface CompiledShield { runArgs: string[]; pin: { semver: string; artifact_hash: string } | null; toolRules: ToolRule[]; notes: string[] }
export function compileShield(s: Shield): CompiledShield {
  const runArgs: string[] = [], notes: string[] = [];
  if (s.rules.contain) runArgs.push("--contain");
  // In the CLI, "--net off" means no network limit at all, so a closed network is never written that way. Every
  // network rule is a host list: the registry the launcher downloads from, then the declared hosts if there are any.
  if (s.rules.net) { const reg = registryHosts(s.package.registry); runArgs.push("--net", [...reg, ...(s.rules.net.mode === "closed" ? [] : s.rules.net.hosts)].join(",") || "localhost"); }
  const deny = (s.rules.tools ?? []).filter((t) => t.action === "deny").map((t) => t.match);
  if (deny.length) runArgs.push("--deny", deny.join(","));
  if (s.rules.secrets?.length) runArgs.push("--secrets", s.rules.secrets.map((b) => `${b.name}=${b.host}`).join(","));
  if ((s.rules.tools ?? []).some((t) => t.action === "approve")) notes.push("Write tools are held for approval only under the installed guard.");
  if (s.rules.net?.mode === "closed") notes.push("The network is closed for this tool: only the package registry stays reachable.");
  return { runArgs, pin: s.rules.pin ? { semver: s.rules.pin.semver, artifact_hash: s.rules.pin.artifact_hash } : null, toolRules: (s.rules.tools ?? []).map((t) => ({ match: t.match, action: t.action, reason: t.reason })), notes };
}

const RUNNERS = /^(npx|bunx|pnpx|uvx|pipx)$/;
/** Apply the pin to a launch command: `npx -y pkg` becomes `npx -y pkg@1.2.3`, an existing version is replaced. Unknown launchers are returned unchanged. */
export function pinLaunch(launch: string[], s: Shield): string[] {
  if (!s.rules.pin || !launch.length || !RUNNERS.test(launch[0].split(/[\\/]/).pop() ?? "")) return launch;
  const name = s.package.name;
  const sep = /^(uvx|pipx)$/.test(launch[0]) ? "==" : "@";
  return launch.map((a) => (a === name || a.startsWith(`${name}@`) || a.startsWith(`${name}==`) ? `${name}${sep}${s.rules.pin!.semver}` : a));
}
/** The launch argv under the shield: `npx -y vet-skills run <flags> -- <the server's own command>`. */
export function shieldedLaunch(launch: string[], s: Shield): string[] {
  return ["npx", "-y", "vet-skills", "run", ...compileShield(s).runArgs, "--", ...pinLaunch(launch, s)];
}
const sh = (a: string) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`);
export function shieldCommand(launch: string[], s: Shield): string { return shieldedLaunch(launch, s).map(sh).join(" "); }

export type SnippetFormat = "mcpServers" | "claude-json" | "vscode" | "codex-toml" | "amp" | "zed" | "opencode";
/**
 * The text to paste into a client's config for one server. `launch` is the server's own command and arguments as the
 * user has them. Environment and header blocks are left out on purpose: the user keeps theirs exactly as they are, so
 * no value is ever written by us.
 */
export function renderShieldSnippet(format: SnippetFormat, serverName: string, launch: string[], s: Shield): string {
  const argv = shieldedLaunch(launch, s);
  const key = JSON.stringify(serverName);
  switch (format) {
    case "codex-toml":
      return `[mcp_servers.${/^[\w-]+$/.test(serverName) ? serverName : key}]\ncommand = ${JSON.stringify(argv[0])}\nargs = [${argv.slice(1).map((a) => JSON.stringify(a)).join(", ")}]`;
    case "opencode":
      return `${key}: {\n  "type": "local",\n  "command": ${JSON.stringify(argv)}\n}`;
    case "vscode":
      return `${key}: {\n  "type": "stdio",\n  "command": ${JSON.stringify(argv[0])},\n  "args": ${JSON.stringify(argv.slice(1))}\n}`;
    default:
      return `${key}: {\n  "command": ${JSON.stringify(argv[0])},\n  "args": ${JSON.stringify(argv.slice(1))}\n}`;
  }
}

/* ------------------------------------------------------------ canonical YAML, and a strict reader for it */

const q = (v: string) => JSON.stringify(v);
/** Canonical YAML: fixed key order, every string quoted, two-space indent. Hashing and signing use exactly these bytes. */
export function serializeShield(s: Shield): string {
  const L: string[] = [];
  const map = (indent: string, o: Record<string, string | boolean | string[]>, first = "") => {
    let lead = first;
    for (const [k, v] of Object.entries(o)) { L.push(`${indent}${lead}${k}: ${Array.isArray(v) ? `[${v.map(q).join(", ")}]` : typeof v === "boolean" ? String(v) : q(v)}`); if (lead) { indent += "  "; lead = ""; } }
  };
  L.push(`schema: ${q(s.schema)}`, "package:"); map("  ", { registry: s.package.registry, name: s.package.name, semver: s.package.semver, artifact_hash: s.package.artifact_hash });
  L.push(s.finding_refs.length ? "finding_refs:" : "finding_refs: []"); for (const f of s.finding_refs) map("  ", { kind: f.kind, ref: f.ref }, "- ");
  L.push("evidence:"); map("  ", { verdict_id: s.evidence.verdict_id, engine_version: s.evidence.engine_version, coverage: s.evidence.coverage, ran_at: s.evidence.ran_at });
  L.push("rules:");
  if (s.rules.pin) { L.push("  pin:"); map("    ", { semver: s.rules.pin.semver, artifact_hash: s.rules.pin.artifact_hash, reason: s.rules.pin.reason, evidence: s.rules.pin.evidence }); }
  if (s.rules.net) { L.push("  net:"); map("    ", { mode: s.rules.net.mode, hosts: s.rules.net.hosts, reason: s.rules.net.reason, evidence: s.rules.net.evidence }); }
  if (s.rules.contain) { L.push("  contain:"); map("    ", { enabled: true, reason: s.rules.contain.reason, evidence: s.rules.contain.evidence }); }
  if (s.rules.tools?.length) { L.push("  tools:"); for (const t of s.rules.tools) map("    ", { match: t.match, action: t.action, reason: t.reason, evidence: t.evidence }, "- "); }
  if (s.rules.secrets?.length) { L.push("  secrets:"); for (const b of s.rules.secrets) map("    ", { name: b.name, host: b.host, evidence: b.evidence }, "- "); }
  L.push(s.not_enforced.length ? "not_enforced:" : "not_enforced: []"); for (const n of s.not_enforced) L.push(`  - ${q(n)}`);
  L.push(`drafted_by: ${q(s.drafted_by)}`, `min_cli: ${q(s.min_cli)}`, `created_at: ${q(s.created_at)}`, "");
  return L.join("\n");
}

type Node = string | boolean | string[] | Node[] | { [k: string]: Node };
function scalar(v: string): Node {
  const t = v.trim();
  if (t === "true") return true;
  if (t === "[]") return [];
  if (t.startsWith("[")) return JSON.parse(t) as string[];
  if (t.startsWith('"')) return JSON.parse(t) as string;
  throw new Error(`unquoted value: ${t.slice(0, 40)}`);
}
/** Reads only the YAML `serializeShield` writes. Anything else is an error, which is the point. */
function readYaml(text: string): Node {
  const lines = text.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#"));
  let i = 0;
  const block = (indent: number): Node => {
    const isList = lines[i]?.slice(indent).startsWith("- ");
    if (isList) {
      const out: Node[] = [];
      while (i < lines.length && lines[i].startsWith(`${" ".repeat(indent)}- `)) {
        const rest = lines[i].slice(indent + 2);
        if (/^[\w]+:/.test(rest)) { lines[i] = `${" ".repeat(indent + 2)}${rest}`; out.push(block(indent + 2)); }
        else { out.push(scalar(rest)); i++; }
      }
      return out;
    }
    const obj: Record<string, Node> = {};
    while (i < lines.length) {
      const line = lines[i];
      const cur = line.length - line.trimStart().length;
      if (cur < indent) break;
      if (cur > indent) throw new Error(`unexpected indent at: ${line.trim().slice(0, 40)}`);
      const m = line.trim().match(/^([\w]+):(.*)$/);
      if (!m) throw new Error(`not a key: ${line.trim().slice(0, 40)}`);
      if (m[1] in obj) throw new Error(`duplicate key ${m[1]}`);
      i++;
      obj[m[1]] = m[2].trim() ? scalar(m[2]) : block(indent + 2);
    }
    return obj;
  };
  const root = block(0);
  if (i < lines.length) throw new Error("trailing content");
  return root;
}

const KEYS: Record<string, string[]> = {
  root: ["schema", "package", "finding_refs", "evidence", "rules", "not_enforced", "drafted_by", "min_cli", "created_at"],
  package: ["registry", "name", "semver", "artifact_hash"], evidence: ["verdict_id", "engine_version", "coverage", "ran_at"],
  rules: ["pin", "net", "contain", "tools", "secrets"], pin: ["semver", "artifact_hash", "reason", "evidence"], net: ["mode", "hosts", "reason", "evidence"],
  contain: ["enabled", "reason", "evidence"], tool: ["match", "action", "reason", "evidence"], secret: ["name", "host", "evidence"], ref: ["kind", "ref"],
};
function only(o: unknown, where: keyof typeof KEYS, required = true): Record<string, Node> {
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error(`${where} must be a map`);
  for (const k of Object.keys(o)) if (!KEYS[where].includes(k)) throw new Error(`unknown key ${where}.${k}`);
  if (required && where !== "rules") for (const k of KEYS[where]) if (!(k in (o as object))) throw new Error(`missing ${where}.${k}`);
  return o as Record<string, Node>;
}
const str = (v: Node, what: string): string => { if (typeof v !== "string") throw new Error(`${what} must be a string`); return v; };

/** Strict: an unknown key, an unknown lever, an action other than deny or approve, or a shield that needs a newer CLI all throw. */
export function parseShield(text: string, o: { cliVersion?: string } = {}): Shield {
  const r = only(readYaml(text), "root");
  if (r.schema !== SHIELD_SCHEMA) throw new Error(`unsupported shield schema ${String(r.schema)}`);
  const pkg = only(r.package, "package"), ev = only(r.evidence, "evidence"), rules = only(r.rules, "rules");
  const out: Shield = {
    schema: SHIELD_SCHEMA,
    package: { registry: str(pkg.registry, "registry"), name: str(pkg.name, "name"), semver: str(pkg.semver, "semver"), artifact_hash: str(pkg.artifact_hash, "artifact_hash") },
    finding_refs: (r.finding_refs as Node[]).map((f) => { const x = only(f, "ref"); const kind = str(x.kind, "kind"); if (!["exposure_finding", "drift_event", "replay"].includes(kind)) throw new Error(`unknown finding kind ${kind}`); return { kind: kind as Shield["finding_refs"][number]["kind"], ref: str(x.ref, "ref") }; }),
    evidence: { verdict_id: str(ev.verdict_id, "verdict_id"), engine_version: str(ev.engine_version, "engine_version"), coverage: str(ev.coverage, "coverage"), ran_at: str(ev.ran_at, "ran_at") },
    rules: {}, not_enforced: (r.not_enforced as Node[]).map((n) => str(n, "not_enforced")), drafted_by: str(r.drafted_by, "drafted_by"), min_cli: str(r.min_cli, "min_cli"), created_at: str(r.created_at, "created_at"),
  };
  if (rules.pin) { const p = only(rules.pin, "pin"); out.rules.pin = { semver: str(p.semver, "pin.semver"), artifact_hash: str(p.artifact_hash, "pin.artifact_hash"), reason: str(p.reason, "pin.reason"), evidence: str(p.evidence, "pin.evidence") }; }
  if (rules.net) {
    const n = only(rules.net, "net"); const mode = str(n.mode, "net.mode");
    if (mode !== "hosts" && mode !== "closed") throw new Error(`unknown net mode ${mode}`);
    const hosts = (n.hosts as Node[]).map((h) => str(h, "net.hosts"));
    for (const h of hosts) if (!HOST.test(h)) throw new Error(`not a host: ${h}`);
    out.rules.net = { mode, hosts, reason: str(n.reason, "net.reason"), evidence: str(n.evidence, "net.evidence") };
  }
  if (rules.contain) { const c = only(rules.contain, "contain"); if (c.enabled !== true) throw new Error("contain.enabled must be true"); out.rules.contain = { enabled: true, reason: str(c.reason, "contain.reason"), evidence: str(c.evidence, "contain.evidence") }; }
  if (rules.tools) out.rules.tools = (rules.tools as Node[]).map((t) => { const x = only(t, "tool"); const action = str(x.action, "tool.action"); if (action !== "deny" && action !== "approve") throw new Error(`a shield may only deny or hold a tool, not ${action}`); return { match: str(x.match, "tool.match"), action, reason: str(x.reason, "tool.reason"), evidence: str(x.evidence, "tool.evidence") }; });
  if (rules.secrets) out.rules.secrets = (rules.secrets as Node[]).map((b) => { const x = only(b, "secret"); return { name: str(x.name, "secret.name"), host: str(x.host, "secret.host"), evidence: str(x.evidence, "secret.evidence") }; });
  if (o.cliVersion && cmp(out.min_cli, o.cliVersion) > 0) throw new Error(`this shield needs vet-skills ${out.min_cli} or newer; this is ${o.cliVersion}`);
  return out;
}
function cmp(a: string, b: string): number { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0); } return 0; }
