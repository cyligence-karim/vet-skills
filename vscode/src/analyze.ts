/**
 * Pure analysis of one config file: components (names only, via the shared
 * parser), committed credential values (kind and line only), and the line each
 * component sits on, so the editor can put a diagnostic next to it.
 */
import { parseAgentConfig, isAgentConfigPath, USER_CONFIG_FILES, findSecrets, type Component, type SecretFinding } from "../../src/policy/index.js";

export interface Located { c: Component; line: number }

export function isConfigFile(path: string): boolean {
  const p = path.replace(/\\/g, "/");
  return isAgentConfigPath(p) || USER_CONFIG_FILES.some((f) => p.endsWith("/" + f.path)) || /(^|\/)(claude_desktop_config|mcp_config|mcp)\.json$/.test(p) || /(^|\/)\.codex\/config\.toml$/.test(p);
}

/** The repo-relative or user-relative path the parser keys its rules on. */
export function parserPath(fsPath: string): string {
  const p = fsPath.replace(/\\/g, "/");
  for (const f of USER_CONFIG_FILES) if (p.endsWith("/" + f.path)) return f.path;
  const m = p.match(/(^|\/)(\.mcp\.json|\.cursor\/mcp\.json|\.claude\/settings(\.local)?\.json|\.claude\/[^/]+|\.codex\/config\.toml|\.gemini\/settings\.json|\.vscode\/mcp\.json|CLAUDE\.md|AGENTS\.md|\.cursorrules)$/);
  return m ? m[2] : p.split("/").pop() ?? p;
}

export function analyzeText(fsPath: string, text: string): { components: Located[]; secrets: SecretFinding[] } {
  const rel = parserPath(fsPath);
  const scope = USER_CONFIG_FILES.some((f) => rel === f.path) ? "user" : "project";
  let comps: Component[] = [];
  try { comps = parseAgentConfig(rel, text, scope); } catch { comps = []; }
  const lines = text.split("\n");
  const lineOf = (name: string) => {
    const needles = [`"${name}"`, `[mcp_servers.${name}]`, `[mcp.servers.${name}]`, name];
    for (const n of needles) { const i = lines.findIndex((l) => l.includes(n)); if (i >= 0) return i; }
    return 0;
  };
  const secrets = /\.(json|toml|ya?ml)$/i.test(fsPath) ? findSecrets(rel, text) : [];
  return { components: comps.map((c) => ({ c, line: lineOf(c.name) })), secrets };
}

export function resolveQuery(c: Component): { q: string; registry?: string } | null {
  if (c.package) return { q: c.package.name.replace(/^@/, ""), registry: c.package.registry };
  if (c.kind === "skill" || c.kind === "plugin") return { q: c.name };
  return null;
}
