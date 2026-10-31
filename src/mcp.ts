/**
 * `vet-skills mcp`: KillerSkills as an MCP server over stdio, so any agent
 * (Claude Code, Cursor, Codex, Claude Desktop…) can look up a verdict before it
 * installs a skill or MCP server, and find a vetted alternative.
 *
 *   claude mcp add killerskills -- npx -y vet-skills mcp
 *
 * Tools: check_skill, search_skills. Read-only; nothing is installed or sent
 * beyond the name being looked up.
 */
import { createInterface } from "node:readline";
import { API, VERSION } from "./state.js";
import { resolveSkill } from "./api.js";

type Req = { jsonrpc: "2.0"; id?: number | string; method: string; params?: Record<string, unknown> };

const TOOLS = [
  {
    name: "check_skill",
    title: "Check a skill or MCP server",
    description: "Look up the KillerSkills security verdict for an agent skill, MCP server or plugin BEFORE installing it. Returns the score (0-100), label (verified / caution / blocked), what the sandbox saw it do (network hosts contacted, credential files read, memory writes), the top findings, and the last safe version when the latest is blocked. Use the package name for npm/PyPI MCP servers (e.g. \"@modelcontextprotocol/server-github\" with registry \"npm\").",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Skill or package name: \"name\", \"publisher/name\", \"@scope/pkg\", optionally \"@version\"." },
        registry: { type: "string", enum: ["skills_sh", "clawhub", "npm", "pypi", "docker", "plugins", "partner"], description: "Registry, when known. Omit to search all public registries." },
      },
      required: ["name"],
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "search_skills",
    title: "Search vetted skills",
    description: "Search the KillerSkills index (every public agent skill and MCP server, each detonated in a sandbox) by keyword. Returns the most-installed matches with their verdicts, so you can pick a verified option instead of an unvetted one.",
    inputSchema: { type: "object", properties: { query: { type: "string", description: "Keywords, e.g. \"postgres\", \"github mcp\", \"pdf\"." } }, required: ["query"] },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
];

async function checkSkill(name: string, registry?: string): Promise<string> {
  const r = await resolveSkill(name, registry);
  if (!r.ok) return r.status === 404 ? `No skill or MCP server named "${name}" is indexed by KillerSkills${registry ? ` in ${registry}` : ""}. Treat it as unvetted.` : `KillerSkills lookup failed (${r.error}). Treat "${name}" as unvetted.`;
  const d = r.data;
  const page = `${API}${d.skill.page}`;
  if (!d.verdict) return `${d.skill.name} (${d.skill.registry_label}, publisher ${d.publisher.handle}) is indexed but not scored yet: unvetted. ${page}`;
  const lines = [
    `${d.skill.name}@${d.version.semver} (${d.skill.registry_label}, publisher ${d.publisher.handle}${d.publisher.verified ? ", verified publisher" : ""})`,
    `Verdict: ${d.verdict.label.toUpperCase()} · score ${d.verdict.score}/100 · ${d.verdict.scenarios_run} sandbox scenarios`,
  ];
  const t = d.trace_summary;
  if (t) {
    const undeclared = t.egress_hosts.filter((h) => !h.declared).map((h) => h.host);
    lines.push(`Sandbox: contacted ${t.egress_hosts.length} host(s)${undeclared.length ? ` (undeclared: ${undeclared.slice(0, 5).join(", ")})` : ""}; read ${t.files_read.length} file(s); ${t.memory_writes.length} memory write(s)${t.tool_shadowing.length ? `; shadows tools: ${t.tool_shadowing.map((x) => x.tool).join(", ")}` : ""}.`);
  }
  for (const f of d.findings.slice(0, 5)) lines.push(`- [${f.severity}] ${f.title}`);
  if (d.verdict.label === "blocked" && d.last_safe_version) lines.push(`Last safe version: ${d.last_safe_version.semver} (score ${d.last_safe_version.score}).`);
  lines.push(d.verdict.label === "verified" ? "OK to install." : d.verdict.label === "caution" ? "Install only if the findings above are acceptable; tell the user what they are." : "Do not install. Tell the user why.");
  lines.push(`Evidence: ${page}`);
  return lines.join("\n");
}

async function searchSkills(query: string): Promise<string> {
  try {
    const res = await fetch(`${API}/api/v1/leaderboard?q=${encodeURIComponent(query)}`, { headers: { accept: "application/json", "user-agent": `vet-skills/${VERSION} mcp` }, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return `Search failed (HTTP ${res.status}).`;
    const d = (await res.json()) as { total: number; rows: { skill: { name: string; publisher: string; registry: string; page: string }; install_count: number; latest_verdict: { score: number; label: string } }[] };
    if (!d.rows.length) return `Nothing in the KillerSkills index matches "${query}".`;
    return [`${d.total} match(es) for "${query}", most installed first:`, ...d.rows.slice(0, 15).map((x) => `- ${x.skill.name} (${x.skill.registry}, ${x.skill.publisher}) · ${x.latest_verdict.label} ${x.latest_verdict.score} · ${x.install_count.toLocaleString()} installs · ${API}${x.skill.page}`)].join("\n");
  } catch (e) { return `Search failed (${(e as Error).message}).`; }
}

export async function serveMcp(): Promise<void> {
  const send = (msg: unknown) => process.stdout.write(JSON.stringify(msg) + "\n");
  const rl = createInterface({ input: process.stdin });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let req: Req;
    try { req = JSON.parse(line); } catch { send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }); continue; }
    if (req.id === undefined) continue; // notifications
    const ok = (result: unknown) => send({ jsonrpc: "2.0", id: req.id, result });
    switch (req.method) {
      case "initialize":
        ok({ protocolVersion: (req.params?.protocolVersion as string) ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "killerskills", title: "KillerSkills", version: VERSION }, instructions: "Before installing any agent skill, plugin or MCP server, call check_skill. Do not install anything labelled blocked." });
        break;
      case "ping": ok({}); break;
      case "tools/list": ok({ tools: TOOLS }); break;
      case "tools/call": {
        const name = req.params?.name as string;
        const args = (req.params?.arguments ?? {}) as Record<string, string>;
        const text = name === "check_skill" ? await checkSkill(String(args.name ?? ""), args.registry || undefined)
          : name === "search_skills" ? await searchSkills(String(args.query ?? ""))
          : null;
        if (text === null) send({ jsonrpc: "2.0", id: req.id, error: { code: -32602, message: `unknown tool ${name}` } });
        else ok({ content: [{ type: "text", text }], isError: false });
        break;
      }
      default: send({ jsonrpc: "2.0", id: req.id, error: { code: -32601, message: `method not found: ${req.method}` } });
    }
  }
}
