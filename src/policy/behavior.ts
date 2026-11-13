/**
 * Version behavior diff: what one version of a package did in the sandbox compared with another. Pure and shared by the
 * API (which builds a Behavior from a stored trace) and the guard (which decides whether an update needs a person).
 *
 * The diff is over observed behavior, not source: tools the server listed (and a hash of each descriptor when the run
 * recorded one), hosts it contacted, credential variables it reads, credential files it opened, install scripts, and
 * files it wrote into agent memory. A change that only shows with a real credential, or on a path the run did not
 * reach, is not in a trace and so not in a diff; `notes` says when the two runs are not comparable.
 */
export interface Behavior {
  version: string;
  /** How far the run got: full | startup_only | install_only | install_failed | static_only. */
  coverage: string;
  /** Tools from tools/list; null when the server never listed (or the package is not an MCP server). */
  tools: { name: string; hash?: string }[] | null;
  hosts: string[];
  credentialEnv: string[];
  credentialFiles: string[];
  installScripts: string[];
  memoryWrites: string[];
}

export interface BehaviorDiff {
  from: string; to: string;
  added: { hosts: string[]; tools: string[]; credentialEnv: string[]; credentialFiles: string[]; installScripts: string[]; memoryWrites: string[] };
  removed: { hosts: string[]; tools: string[]; credentialEnv: string[]; credentialFiles: string[] };
  /** Tools present in both whose descriptor (description + input schema) hash differs. Empty when either run has no hashes. */
  changedTools: string[];
  /** True when the newer version reaches for something the older one did not: a host, a credential, a tool, a rewritten tool descriptor, an install script or agent memory. */
  escalates: boolean;
  /** False when one side was not run far enough for the comparison to mean much. */
  comparable: boolean;
  notes: string[];
}

const RANK: Record<string, number> = { static_only: 0, install_failed: 0, install_only: 1, startup_only: 2, full: 3 };
const minus = (a: string[], b: string[]) => { const s = new Set(b); return [...new Set(a)].filter((x) => !s.has(x)).sort(); };

export function diffBehavior(from: Behavior, to: Behavior): BehaviorDiff {
  const fromTools = from.tools ?? []; const toTools = to.tools ?? [];
  const fromByName = new Map(fromTools.map((t) => [t.name, t.hash]));
  const toolsComparable = from.tools !== null && to.tools !== null;
  const addedTools = toolsComparable ? minus(toTools.map((t) => t.name), fromTools.map((t) => t.name)) : [];
  const removedTools = toolsComparable ? minus(fromTools.map((t) => t.name), toTools.map((t) => t.name)) : [];
  const changedTools = toolsComparable ? toTools.filter((t) => t.hash && fromByName.get(t.name) && fromByName.get(t.name) !== t.hash).map((t) => t.name).sort() : [];
  const added = {
    hosts: minus(to.hosts, from.hosts), tools: addedTools,
    credentialEnv: minus(to.credentialEnv, from.credentialEnv), credentialFiles: minus(to.credentialFiles, from.credentialFiles),
    installScripts: minus(to.installScripts, from.installScripts), memoryWrites: minus(to.memoryWrites, from.memoryWrites),
  };
  const removed = { hosts: minus(from.hosts, to.hosts), tools: removedTools, credentialEnv: minus(from.credentialEnv, to.credentialEnv), credentialFiles: minus(from.credentialFiles, to.credentialFiles) };
  const notes: string[] = [];
  const rf = RANK[from.coverage] ?? 0, rt = RANK[to.coverage] ?? 0;
  const comparable = rf >= 1 && rt >= 1;
  if (!comparable) notes.push(`${rf < 1 ? from.version : to.version} was not run in the sandbox (${(rf < 1 ? from.coverage : to.coverage).replace(/_/g, " ")}); the comparison covers what static analysis recorded only.`);
  else if (rf < rt) notes.push(`${to.version} was run further than ${from.version} (${to.coverage.replace(/_/g, " ")} vs ${from.coverage.replace(/_/g, " ")}); some additions may be first observations rather than changes.`);
  else if (rf > rt) notes.push(`${to.version} was run less far than ${from.version} (${to.coverage.replace(/_/g, " ")} vs ${from.coverage.replace(/_/g, " ")}); behavior past startup is not compared.`);
  if (!toolsComparable && (from.tools !== null || to.tools !== null)) notes.push("Only one of the two runs produced a tool list; tools are not compared.");
  if (toolsComparable && toTools.length && !toTools.some((t) => t.hash && fromByName.get(t.name))) notes.push("Tool descriptor hashes were not recorded for both runs; renamed or added tools are compared, rewritten descriptions are not.");
  const escalates = added.hosts.length + added.tools.length + added.credentialEnv.length + added.credentialFiles.length + added.installScripts.length + added.memoryWrites.length + changedTools.length > 0;
  return { from: from.version, to: to.version, added, removed, changedTools, escalates, comparable, notes };
}

/** One line a person can act on. */
export function diffSummary(d: BehaviorDiff): string {
  const parts: string[] = [];
  const add = (n: string[], one: string, many: string) => { if (n.length) parts.push(`${n.length} new ${n.length === 1 ? one : many} (${n.slice(0, 4).join(", ")}${n.length > 4 ? ", …" : ""})`); };
  add(d.added.hosts, "host", "hosts"); add(d.added.credentialEnv, "credential variable", "credential variables"); add(d.added.credentialFiles, "credential file", "credential files");
  add(d.added.tools, "tool", "tools");
  if (d.changedTools.length) parts.push(`${d.changedTools.length} rewritten tool descriptor${d.changedTools.length === 1 ? "" : "s"} (${d.changedTools.slice(0, 4).join(", ")}${d.changedTools.length > 4 ? ", …" : ""})`);
  add(d.added.installScripts, "install script", "install scripts"); add(d.added.memoryWrites, "agent-memory write", "agent-memory writes");
  return parts.length ? parts.join(" · ") : "nothing new reached for";
}
