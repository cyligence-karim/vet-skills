/**
 * `vet-skills discover`: inventory this machine's agent configuration — MCP
 * servers, skills, plugins, hooks and instruction files from Claude Code,
 * Cursor, Windsurf, Claude Desktop, Gemini CLI and Codex — parsed locally with
 * the same parser the GitHub scan uses. Only names leave the machine (the
 * parser drops env/header values and arguments), and only when enrolled.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { USER_CONFIG_FILES, USER_SKILL_DIRS, isAgentConfigPath, parseAgentConfig, type Component } from "@killerskills/policy";

const MAX_BYTES = 2 * 1024 * 1024;

function read(path: string): string | null {
  try { const st = statSync(path); if (!st.isFile() || st.size > MAX_BYTES) return null; return readFileSync(path, "utf8"); } catch { return null; }
}

/** Components declared in the home directory, plus the current project when `project` is set. */
export function discoverLocal(opts: { home?: string; project?: string } = {}): Component[] {
  const home = opts.home ?? homedir();
  const out: Component[] = [];
  for (const f of USER_CONFIG_FILES) {
    const text = read(join(home, f.path));
    if (text !== null) out.push(...parseAgentConfig(f.path, text, "user"));
  }
  for (const dir of USER_SKILL_DIRS) {
    const abs = join(home, dir);
    if (!existsSync(abs)) continue;
    for (const name of safeList(abs)) {
      const rel = `${dir}/${name}/SKILL.md`;
      const text = read(join(home, rel));
      if (text !== null) out.push(...parseAgentConfig(rel, text, "user"));
    }
  }
  if (opts.project) for (const rel of walk(opts.project, "", 0)) { const text = read(join(opts.project, rel)); if (text !== null) out.push(...parseAgentConfig(rel, text, "project")); }
  const seen = new Set<string>();
  return out.filter((c) => { const k = `${c.kind}|${c.name}|${c.path}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

function safeList(dir: string): string[] { try { return readdirSync(dir); } catch { return []; } }

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "vendor", "target", ".venv", "venv"]);
function walk(root: string, rel: string, depth: number): string[] {
  if (depth > 6) return [];
  const out: string[] = [];
  for (const name of safeList(join(root, rel))) {
    if (SKIP.has(name)) continue;
    const r = rel ? `${rel}/${name}` : name;
    let st; try { st = statSync(join(root, r)); } catch { continue; }
    if (st.isDirectory()) out.push(...walk(root, r, depth + 1));
    else if (isAgentConfigPath(r)) out.push(r);
    if (out.length > 200) break;
  }
  return out;
}
