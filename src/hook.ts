/**
 * Agent hook integration.
 *
 * Claude Code: a PreToolUse hook on Bash. `vet-skills hook eval` reads the hook
 * JSON on stdin, extracts an install command (`npx skills add …`, `skills add …`,
 * `claude plugin install …`, `claude mcp add …`), runs the check, and exits 2 with
 * the reason to block, 0 to allow (with a notice on stderr for sandbox/observe).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { applyRemovals } from "./sync.js";
import { check, renderOutcome, renderCheck } from "./check.js";
import { report, scanGithubRepo } from "./api.js";
import { API } from "./state.js";
import { hintOncePerDay, readOrg } from "./state.js";

export const INSTALL_PATTERNS: { re: RegExp; kind: "skill" | "plugin" | "mcp" }[] = [
  { re: /(?:npx\s+(?:-y\s+)?)?skills\s+add\s+(\S+)/, kind: "skill" },
  { re: /claude\s+plugin\s+install\s+(\S+)/, kind: "plugin" },
  { re: /claude\s+mcp\s+add(?:-json)?\s+(\S+)/, kind: "mcp" },
  { re: /vet-skills\s+install\s+(\S+)/, kind: "skill" },
];

/** `claude mcp add --transport http|sse <name> <url>` (flags in any order, quoted values respected). Only name and URL are returned — never headers or env values. */
export function extractRemoteMcp(command: string): { name: string; url: string } | null {
  const m = command.match(/claude\s+mcp\s+add(?:-json)?\s+(.*)$/s);
  if (!m) return null;
  const args = (m[1].match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map((a) => a.replace(/^(['"])(.*)\1$/, "$2"));
  const takesValue = /^(--transport|-t|--scope|-s|--header|-H|--env|-e)$/;
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (takesValue.test(a)) { i += 1; continue; }
    if (a.startsWith("-")) continue;
    positional.push(a);
  }
  const url = positional.find((a) => /^https?:\/\//.test(a));
  if (!url) return null;
  const name = positional.find((a) => a !== url) ?? new URL(url).hostname;
  return { name, url };
}

/**
 * The package behind a stdio MCP server install: `claude mcp add <name> -- npx -y <pkg>` → npm,
 * `-- uvx <pkg>` → pypi, `-- docker run … mcp/<image>` → docker. Returns the registry-qualified query.
 */
export function extractStdioPackage(command: string): { q: string; registry: "npm" | "pypi" | "docker" } | null {
  const tail = command.split(/\s--\s/)[1];
  if (!tail) return null;
  const args = (tail.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map((a) => a.replace(/^(['"])(.*)\1$/, "$2"));
  const [bin, ...rest] = args;
  // "pkg@1.2.3" / "@scope/pkg@1.2.3" → without the version; "@scope/pkg" → "scope/pkg" (publisher/name for the resolver).
  const strip = (s: string) => s.replace(/(.)@[^@/]+$/, "$1");
  if (/^(npx|bunx|pnpm)$/.test(bin ?? "")) { const pkg = rest.find((a) => !a.startsWith("-") && a !== "dlx" && a !== "exec"); return pkg ? { q: strip(pkg).replace(/^@/, ""), registry: "npm" } : null; }
  if (/^(uvx|pipx)$/.test(bin ?? "")) { const pkg = rest.find((a) => !a.startsWith("-") && a !== "run"); return pkg ? { q: strip(pkg).toLowerCase().replace(/\[.*\]$/, ""), registry: "pypi" } : null; }
  if (bin === "docker") { const img = rest.find((a) => /^(ghcr\.io\/|docker\.io\/)?[\w.-]+\/[\w.-]+(:[\w.-]+)?$/.test(a) && !a.startsWith("-")); if (!img) return null; const m = img.replace(/:[\w.-]+$/, "").match(/mcp\/([\w.-]+)$/); return m ? { q: m[1], registry: "docker" } : null; }
  return null;
}

/** `owner/repo`, a github.com URL, or `git clone …github.com/owner/repo` → the repository, when the install points at GitHub. */
export function extractGithubRepo(target: string, command: string): { owner: string; repo: string } | null {
  const m = target.match(/^(?:https?:\/\/|git@)?github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$/i) ?? command.match(/git\s+clone\s+(?:--[^\s]+\s+)*(?:https?:\/\/|git@)?github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\s|$)/i);
  if (m) return { owner: m[1], repo: m[2] };
  // skills.sh accepts owner/repo as a GitHub shorthand; treat two plain segments as that when no registry is named.
  const s = target.match(/^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([\w.-]{1,100})$/);
  return s ? { owner: s[1], repo: s[2] } : null;
}

export function extractInstall(command: string): { q: string; kind: "skill" | "plugin" | "mcp"; registry?: string } | null {
  for (const p of INSTALL_PATTERNS) {
    const m = command.match(p.re);
    if (!m) continue;
    const q = m[1].replace(/^['"]|['"]$/g, "");
    if (p.kind === "mcp") {
      const pkg = extractStdioPackage(command);
      if (pkg) return { q: pkg.q, kind: "mcp", registry: pkg.registry };
      const remote = extractRemoteMcp(command);
      if (remote) return { q: remote.name, kind: "mcp" };
    }
    if (p.kind === "plugin") return { q: q.split("@")[0], kind: "plugin", registry: "plugins" };
    return { q, kind: p.kind };
  }
  return null;
}

export async function hookEval(stdin: string): Promise<number> {
  let payload: { tool_name?: string; tool_input?: { command?: string } } = {};
  try { payload = JSON.parse(stdin); } catch { return 0; }
  if (payload.tool_name !== "Bash" || !payload.tool_input?.command) return 0;
  const cmd = payload.tool_input.command;
  if (/^\s*vet-skills\s+(check|why|status|sync|policy|detonate|hook|join|leave|block|publish)\b/.test(cmd)) return 0;
  const found = extractInstall(cmd);
  const cloned = found ? null : (cmd.match(/\bgit\s+clone\b/) ? extractGithubRepo("", cmd) : null);
  if (!found && !cloned) return 0;

  // Installs straight from GitHub (npx skills add owner/repo, a github.com URL, git clone) have no registry verdict.
  // Ask the public repo scan instead; an installer lure is blocked outright, anything else is reported and allowed.
  const gh = cloned ?? (found && found.kind === "skill" && !found.registry ? extractGithubRepo(found.q, cmd) : null);
  if (gh) {
    const scan = await scanGithubRepo(gh.owner, gh.repo);
    if (scan.ok && scan.data.installer_lure) {
      process.stderr.write(`vet-skills blocked this: ${gh.owner}/${gh.repo} looks like an installer lure (malware delivery pattern).\n${scan.data.lure_reasons.slice(0, 3).map((x) => `  ✕ ${x}`).join("\n")}\nReal skills and MCP servers install from source, never from a committed ZIP. Do not download or run anything from this repository.\nReport: ${API}${scan.data.page}\n`);
      return 2;
    }
    if (cloned) return 0;
    if (scan.ok && !scan.data.installer_lure) {
      const s = scan.data.summary;
      if (s.high || s.credentials) process.stderr.write(`vet-skills · ${gh.owner}/${gh.repo}: ${scan.data.headline} ${API}${scan.data.page}\n`);
    }
  }
  if (!found) return 0;

  const r = await check(found.q, { quiet: true, agentKind: "claude_code", registry: found.registry });
  const out = renderOutcome(r);
  const remote = found.kind === "mcp" ? extractRemoteMcp(cmd) : null;
  // Report the remote MCP server (if any) and apply anything the org asked of this machine, quietly.
  const watch = async () => {
    if (!readOrg()) return;
    const res = await report({ installed: [], removed: [], ...(remote ? { mcp_servers: [remote] } : {}) }).catch(() => null);
    if (res?.ok && res.data.pending_removals.length) await applyRemovals(res.data.pending_removals, (l) => process.stderr.write(`vet-skills · ${l}\n`)).catch(() => 0);
  };
  switch (r.decision.decision) {
    case "allow":
    case "observe":
      await watch();
      process.stderr.write(out + "\n");
      return 0;
    case "sandbox":
      await watch();
      process.stderr.write(out + "\n");
      return 0;
    case "approval_required":
      process.stderr.write(`vet-skills blocked this install pending approval.\n${out}\n\nDo not retry the install until a reviewer approves it; run \`vet-skills status\` to check.\n`);
      return 2;
    case "defer":
      process.stderr.write(`vet-skills deferred this install: the skill is unscored and policy requires detonation first.\n${out}\n`);
      return 2;
    case "block":
      process.stderr.write(`vet-skills blocked this install by ${readOrg() ? "org" : "your"} policy.\n${renderCheck(r)}\n${out}\n`);
      if (!readOrg() && hintOncePerDay("teams")) process.stderr.write("Running this for a team? One policy across every developer's agents, approvals and inventory: https://killerskills.ai/pricing\n");
      return 2;
  }
  return 0;
}

/** Writes the Claude Code hook into ~/.claude/settings.json (merging, idempotent). */
export function installClaudeCodeHook(): { path: string; changed: boolean } {
  const dir = join(homedir(), ".claude");
  const path = join(dir, "settings.json");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  let settings: Record<string, unknown> = {};
  if (existsSync(path)) { try { settings = JSON.parse(readFileSync(path, "utf8")); } catch { settings = {}; } }
  const hooks = (settings.hooks ??= {}) as Record<string, unknown[]>;
  const pre = (hooks.PreToolUse ??= []) as { matcher?: string; hooks?: { type: string; command: string }[] }[];
  const post = (hooks.PostToolUse ??= []) as { matcher?: string; hooks?: { type: string; command: string }[] }[];
  let changed = false;
  if (!pre.some((h) => h.hooks?.some((x) => /vet-skills hook eval/.test(x.command)))) { pre.push({ matcher: "Bash", hooks: [{ type: "command", command: "vet-skills hook eval" }] }); changed = true; }
  // Runtime observation: every tool call after the fact, attributed to the active skill or MCP server and compared with its sandbox trace.
  if (!post.some((h) => h.hooks?.some((x) => /vet-skills hook observe/.test(x.command)))) { post.push({ matcher: "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch|Skill|mcp__.*", hooks: [{ type: "command", command: "vet-skills hook observe" }] }); changed = true; }
  if (changed) writeFileSync(path, JSON.stringify(settings, null, 2) + "\n");
  return { path, changed };
}
