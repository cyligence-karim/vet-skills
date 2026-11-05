/**
 * `vet-skills discover`: inventory this machine's agent configuration — MCP
 * servers, skills, plugins, hooks and instruction files from Claude Code,
 * Cursor, Windsurf, Claude Desktop, Gemini CLI and Codex — parsed locally with
 * the same parser the GitHub scan uses. Only names leave the machine (the
 * parser drops env/header values and arguments), and only when enrolled.
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { USER_CONFIG_FILES, USER_SKILL_DIRS, findSecrets, isAgentConfigPath, localLureFindings, parseAgentConfig, type Component, type LocalFile } from "./policy/index.js";

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
    if (text !== null) { out.push(...parseAgentConfig(f.path, text, "user")); out.push(...secretComponent(f.path, text, "user")); }
  }
  for (const dir of USER_SKILL_DIRS) {
    const abs = join(home, dir);
    if (!existsSync(abs)) continue;
    for (const name of safeList(abs)) {
      const rel = `${dir}/${name}/SKILL.md`;
      const text = read(join(home, rel));
      if (text !== null) out.push(...parseAgentConfig(rel, text, "user"));
      out.push(...lureComponent(join(home, dir, name), `${dir}/${name}`, "user"));
    }
  }
  if (opts.project) {
    for (const rel of walk(opts.project, "", 0)) { const text = read(join(opts.project, rel)); if (text !== null) { out.push(...parseAgentConfig(rel, text, "project")); out.push(...secretComponent(rel, text, "project")); } }
    for (const dir of [".claude/skills", "skills"]) for (const name of safeList(join(opts.project, dir))) out.push(...lureComponent(join(opts.project, dir, name), `${dir}/${name}`, "project"));
  }
  const seen = new Set<string>();
  return out.filter((c) => { const k = `${c.kind}|${c.name}|${c.path}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

/** A credential value pasted into a config file: kind, key and line only; the value never leaves this function. */
function secretComponent(rel: string, text: string, scope: "user" | "project"): Component[] {
  const found = findSecrets(rel, text).slice(0, 10);
  if (!found.length) return [];
  return [{ kind: "secret", name: found.length === 1 ? found[0].label : `${found.length} committed credentials`, path: rel, scope, agent: "any", envKeys: [...new Set(found.map((f) => f.keyName).filter((k): k is string => !!k))], headerKeys: [], detail: found.map((f) => `${f.label}${f.keyName ? ` under "${f.keyName}"` : ""} (line ${f.line})`).join("; ") }];
}

const HASH_MAX = 32 * 1024 * 1024;
/** Files of one installed skill folder, hashed (for the campaign IOC list) with small .txt contents read for the disguised-script check. */
function skillFiles(root: string, rel = "", depth = 0, out: LocalFile[] = []): LocalFile[] {
  if (depth > 4 || out.length >= 300) return out;
  for (const name of safeList(join(root, rel))) {
    if (SKIP.has(name)) continue;
    const r = rel ? `${rel}/${name}` : name;
    let st; try { st = statSync(join(root, r)); } catch { continue; }
    if (st.isDirectory()) { skillFiles(root, r, depth + 1, out); continue; }
    if (!st.isFile()) continue;
    const f: LocalFile = { path: r, bytes: st.size };
    if (st.size <= HASH_MAX) { try { f.sha256 = createHash("sha256").update(readFileSync(join(root, r))).digest("hex"); } catch { /* unreadable */ } }
    if (/\.txt$/i.test(name) && st.size <= 512 * 1024) f.text = read(join(root, r));
    out.push(f);
    if (out.length >= 300) break;
  }
  return out;
}

/** Installer-lure signals inside an installed skill folder (the Agent Lure Stealer shape: a ZIP, a .bat, a LuaJIT runtime, Lua saved as .txt). */
function lureComponent(abs: string, rel: string, scope: "user" | "project"): Component[] {
  let st; try { st = statSync(abs); } catch { return []; }
  if (!st.isDirectory()) return [];
  const found = localLureFindings(skillFiles(abs));
  if (!found.length) return [];
  const critical = found.some((f) => f.severity === "critical");
  const name = critical ? "Installer lure (malware delivery pattern)" : "Suspicious files in skill folder";
  return [{ kind: "lure", name, path: rel, scope, agent: "any", envKeys: [], headerKeys: [], detail: found.slice(0, 6).map((f) => `${f.title}: ${f.path}`).join("; ") }];
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
