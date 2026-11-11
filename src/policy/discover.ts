/**
 * Agent-configuration discovery, shared by the GitHub org scan (server) and
 * `vet-skills discover` (laptops). Pure: given a file path and its text,
 * return the skills, MCP servers, plugins, hooks and instruction files it
 * declares.
 *
 * Redaction is part of the contract: only names ever leave this module.
 * Environment variable and header VALUES, argument values other than the
 * package being run, and URL paths and query strings are dropped here, so no
 * caller can store a secret by accident.
 */

export type ComponentKind = "mcp_server" | "skill" | "plugin" | "hook" | "instructions" | "lure" | "secret";

export interface Component {
  kind: ComponentKind;
  /** Server key, skill name, plugin@marketplace, hook event, or the instruction file name. */
  name: string;
  /** File the component was declared in (repo-relative, or ~/-relative on a laptop). */
  path: string;
  scope: "project" | "user";
  /** Agent the file belongs to. */
  agent: "claude_code" | "cursor" | "vscode" | "windsurf" | "claude_desktop" | "gemini_cli" | "codex" | "grok" | "copilot" | "kiro" | "qwen" | "cline" | "zed" | "amp" | "opencode" | "continue" | "any";
  transport?: "stdio" | "http";
  /** The package a stdio server runs, when it is a registry package (npx / uvx / docker). */
  package?: { registry: "npm" | "pypi" | "docker"; name: string };
  /** Executable for stdio servers and hooks: "npx", "node", "python", "./bin/x" (never its arguments). */
  command?: string;
  /** Remote servers: host only. */
  urlHost?: string;
  /** Names only. */
  envKeys: string[];
  headerKeys: string[];
  /** Extra context: the hook's tool matcher, a plugin's marketplace, an instruction file's size. */
  detail?: string;
}

/* ---------------------------------------------------------------- which files */

const PROJECT_FILES: { re: RegExp; agent: Component["agent"] }[] = [
  { re: /(^|\/)\.mcp\.json$/, agent: "claude_code" },
  { re: /(^|\/)\.claude\/settings(\.local)?\.json$/, agent: "claude_code" },
  { re: /(^|\/)\.claude\/skills\/[^/]+\/SKILL\.md$/i, agent: "claude_code" },
  { re: /(^|\/)\.claude\/(commands|agents)\/[^/]+\.md$/i, agent: "claude_code" },
  { re: /(^|\/)\.cursor\/mcp\.json$/, agent: "cursor" },
  { re: /(^|\/)\.cursor\/rules\/[^/]+\.mdc?$/, agent: "cursor" },
  { re: /(^|\/)\.vscode\/mcp\.json$/, agent: "vscode" },
  { re: /(^|\/)\.gemini\/settings\.json$/, agent: "gemini_cli" },
  { re: /(^|\/)\.codex\/config\.toml$/, agent: "codex" },
  { re: /(^|\/)\.grok\/config\.toml$/, agent: "grok" },
  { re: /(^|\/)\.grok\/hooks\/[^/]+\.json$/, agent: "grok" },
  { re: /(^|\/)\.github\/copilot-instructions\.md$/, agent: "copilot" },
  { re: /(^|\/)\.github\/(mcp|hooks\/[^/]+)\.json$/, agent: "copilot" },
  { re: /(^|\/)\.kiro\/(settings\/mcp|hooks\/[^/]+)\.json$/, agent: "kiro" },
  { re: /(^|\/)\.qwen\/settings\.json$/, agent: "qwen" },
  { re: /(^|\/)\.cline\/hooks\/[^/]+$/, agent: "cline" },
  { re: /(^|\/)\.zed\/settings\.json$/, agent: "zed" },
  { re: /(^|\/)\.amp\/settings\.jsonc?$/, agent: "amp" },
  { re: /(^|\/)(\.opencode\/)?opencode\.jsonc?$/, agent: "opencode" },
  { re: /(^|\/)\.continue\/(config\.yaml|mcpServers\/[^/]+\.yaml)$/, agent: "continue" },
  { re: /(^|\/)(CLAUDE|AGENTS|GEMINI)\.md$/, agent: "any" },
  { re: /(^|\/)\.(cursorrules|windsurfrules|clinerules)$/, agent: "any" },
];

/** Files on a laptop, relative to the home directory (the CLI expands them per OS). */
export const USER_CONFIG_FILES: { path: string; agent: Component["agent"] }[] = [
  { path: ".claude.json", agent: "claude_code" },
  { path: ".claude/settings.json", agent: "claude_code" },
  { path: ".claude/CLAUDE.md", agent: "claude_code" },
  { path: ".cursor/mcp.json", agent: "cursor" },
  { path: ".codeium/windsurf/mcp_config.json", agent: "windsurf" },
  { path: ".gemini/settings.json", agent: "gemini_cli" },
  { path: ".codex/config.toml", agent: "codex" },
  { path: ".grok/config.toml", agent: "grok" },
  { path: ".copilot/mcp-config.json", agent: "copilot" },
  { path: ".kiro/settings/mcp.json", agent: "kiro" },
  { path: ".qwen/settings.json", agent: "qwen" },
  { path: ".cline/data/settings/cline_mcp_settings.json", agent: "cline" },
  { path: "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", agent: "cline" },
  { path: ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", agent: "cline" },
  { path: ".config/zed/settings.json", agent: "zed" },
  { path: ".config/amp/settings.json", agent: "amp" },
  { path: ".config/opencode/opencode.json", agent: "opencode" },
  { path: ".config/opencode/opencode.jsonc", agent: "opencode" },
  { path: ".continue/config.yaml", agent: "continue" },
  { path: "Library/Application Support/Claude/claude_desktop_config.json", agent: "claude_desktop" },
  { path: ".config/Claude/claude_desktop_config.json", agent: "claude_desktop" },
  { path: "AppData/Roaming/Claude/claude_desktop_config.json", agent: "claude_desktop" },
];
/** Directories on a laptop whose immediate subfolders are skills (each with a SKILL.md). */
export const USER_SKILL_DIRS = [".claude/skills"];

export function isAgentConfigPath(path: string): boolean {
  return PROJECT_FILES.some((f) => f.re.test(path));
}

function agentFor(path: string): Component["agent"] {
  const p = PROJECT_FILES.find((f) => f.re.test(path));
  if (p) return p.agent;
  const u = USER_CONFIG_FILES.find((f) => path.endsWith(f.path));
  return u?.agent ?? "any";
}

/* ------------------------------------------------------------------ parsing */

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : null);
const keysOf = (v: unknown) => (isObj(v) ? Object.keys(v).filter((k) => /^[\w.-]{1,120}$/.test(k)).slice(0, 50) : []);

/** Strip comments and trailing commas: VS Code and Cursor configs are JSONC. */
function parseJsonc(text: string): unknown {
  try { return JSON.parse(text); } catch { /* fall through */ }
  const noComments = text.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_m, s1: string | undefined) => s1 ?? "");
  try { return JSON.parse(noComments.replace(/,(\s*[}\]])/g, "$1")); } catch { return null; }
}

/** The registry package a stdio command runs: `npx -y @scope/pkg@1.2` → npm @scope/pkg; `uvx pkg` → pypi; `docker run … mcp/x` → docker. */
export function stdioPackage(command: string, args: string[]): Component["package"] | undefined {
  const bin = command.split(/[\\/]/).pop()?.replace(/\.(cmd|exe)$/i, "") ?? "";
  const strip = (s: string) => s.replace(/(.)@[^@/]+$/, "$1");
  if (/^(npx|bunx|pnpx)$/.test(bin) || (bin === "pnpm" && args[0] === "dlx")) {
    const pkg = args.find((a) => !a.startsWith("-") && a !== "dlx" && a !== "exec");
    return pkg && /^(@[\w.-]+\/)?[\w.-]+(@[\w.^~<>=*-]+)?$/.test(pkg) ? { registry: "npm", name: strip(pkg) } : undefined;
  }
  if (/^(uvx|pipx)$/.test(bin) || (bin === "uv" && args[0] === "tool")) {
    const pkg = args.find((a) => !a.startsWith("-") && !["run", "tool"].includes(a));
    return pkg && /^[\w.\-[\]]+(==[\w.]+)?$/.test(pkg) ? { registry: "pypi", name: pkg.toLowerCase().replace(/\[.*\]$/, "").replace(/==.*$/, "").replace(/_/g, "-") } : undefined;
  }
  if (bin === "docker") {
    const img = args.find((a, i) => i > 0 && !a.startsWith("-") && /^([\w.-]+\.[\w]+\/)?[\w.-]+\/[\w.-]+(:[\w.-]+)?$/.test(a) && !/^-/.test(args[i - 1] ?? ""));
    if (!img) return undefined;
    return { registry: "docker", name: img.replace(/:[\w.-]+$/, "").replace(/^(docker\.io|ghcr\.io)\//, "") };
  }
  return undefined;
}

function hostOf(u: string | null): string | undefined {
  if (!u) return undefined;
  try { return new URL(u).host.toLowerCase(); } catch { return undefined; }
}

function serverComponents(servers: unknown, path: string, scope: Component["scope"], agent: Component["agent"]): Component[] {
  if (!isObj(servers)) return [];
  const out: Component[] = [];
  for (const [name, raw] of Object.entries(servers).slice(0, 200)) {
    if (!isObj(raw)) continue;
    const url = str(raw.url) ?? str(raw.serverUrl) ?? str(raw.httpUrl);
    const cmdArr = Array.isArray(raw.command) ? raw.command.filter((a): a is string => typeof a === "string") : null;
    const command = cmdArr ? cmdArr[0] ?? null : str(raw.command);
    const args = cmdArr ? cmdArr.slice(1) : Array.isArray(raw.args) ? raw.args.filter((a): a is string => typeof a === "string") : [];
    const envKeys = keysOf(raw.env ?? raw.environment);
    const headerKeys = keysOf(raw.headers);
    if (url) out.push({ kind: "mcp_server", name, path, scope, agent, transport: "http", urlHost: hostOf(url), envKeys, headerKeys });
    else if (command) {
      // A command written as one string ("npx -y pkg") is split for package detection; only the binary is kept.
      const parts = args.length ? [command, ...args] : command.split(/\s+/);
      const bin = parts[0];
      out.push({ kind: "mcp_server", name, path, scope, agent, transport: "stdio", command: bin.split(/[\\/]/).pop(), package: stdioPackage(bin, parts.slice(1)), envKeys, headerKeys });
    }
  }
  return out;
}

function claudeSettings(j: Json, path: string, scope: Component["scope"]): Component[] {
  const out: Component[] = [];
  const agent = "claude_code" as const;
  if (isObj(j.enabledPlugins)) {
    for (const [id, on] of Object.entries(j.enabledPlugins).slice(0, 200)) {
      if (on === false) continue;
      const [plugin, marketplace] = id.split("@");
      out.push({ kind: "plugin", name: plugin, path, scope, agent, envKeys: [], headerKeys: [], detail: marketplace ? `from ${marketplace}` : undefined });
    }
  }
  if (isObj(j.hooks)) {
    for (const [event, groups] of Object.entries(j.hooks)) {
      if (!Array.isArray(groups)) continue;
      for (const g of groups) {
        if (!isObj(g) || !Array.isArray(g.hooks)) continue;
        for (const h of g.hooks) {
          if (!isObj(h)) continue;
          const cmd = str(h.command);
          if (!cmd) continue;
          const bin = cmd.trim().split(/\s+/)[0];
          out.push({ kind: "hook", name: event, path, scope, agent, command: bin.split(/[\\/]/).pop(), envKeys: [], headerKeys: [], detail: str(g.matcher) ? `on ${str(g.matcher)}` : "on every tool call" });
        }
      }
    }
  }
  out.push(...serverComponents(j.mcpServers, path, scope, agent));
  return out;
}

/** `[mcp_servers.name]` tables in Codex's or Grok CLI's config.toml: command, args, env keys. */
function codexToml(text: string, path: string, scope: Component["scope"], agent: Component["agent"] = "codex"): Component[] {
  const out: Component[] = [];
  const blocks = text.split(/^\s*\[/m).slice(1);
  for (const b of blocks) {
    const head = b.match(/^mcp_servers\.("?)([\w.-]+)\1\]/);
    if (head) {
      const body = b.slice(b.indexOf("]") + 1);
      const command = body.match(/^\s*command\s*=\s*"([^"]+)"/m)?.[1];
      const args = [...(body.match(/^\s*args\s*=\s*\[([^\]]*)\]/m)?.[1] ?? "").matchAll(/"([^"]*)"/g)].map((m) => m[1]);
      const url = body.match(/^\s*url\s*=\s*"([^"]+)"/m)?.[1] ?? null;
      const envKeys = [...(body.match(/^\s*env\s*=\s*\{([^}]*)\}/m)?.[1] ?? "").matchAll(/([\w.-]+)\s*=/g)].map((m) => m[1]);
      if (url) out.push({ kind: "mcp_server", name: head[2], path, scope, agent, transport: "http", urlHost: hostOf(url), envKeys, headerKeys: [] });
      else if (command) out.push({ kind: "mcp_server", name: head[2], path, scope, agent, transport: "stdio", command: command.split(/[\\/]/).pop(), package: stdioPackage(command, args), envKeys, headerKeys: [] });
    }
    const envTable = b.match(/^mcp_servers\.("?)([\w.-]+)\1\.env\]/);
    if (envTable) {
      const target = out.find((c) => c.name === envTable[2]);
      if (target) target.envKeys.push(...[...b.slice(b.indexOf("]") + 1).matchAll(/^\s*([\w.-]+)\s*=/gm)].map((m) => m[1]));
    }
  }
  return out;
}

function skillName(path: string, text: string): string {
  const fm = text.match(/^---\s*\n([\s\S]*?)\n---/);
  const n = fm?.[1].match(/^name:\s*["']?([^"'\n]+)["']?\s*$/m)?.[1]?.trim();
  return n || path.split("/").slice(-2, -1)[0] || "skill";
}

/**
 * Components declared by one file. `scope` is "user" for laptop files under the
 * home directory, "project" for files in a repository.
 */
export function parseAgentConfig(path: string, text: string, scope: Component["scope"] = "project"): Component[] {
  const p = path.replace(/\\/g, "/");
  const agent = agentFor(p);
  const base = p.split("/").pop() ?? p;
  if (/\/SKILL\.md$/i.test(p)) return [{ kind: "skill", name: skillName(p, text), path: p, scope, agent: "claude_code", envKeys: [], headerKeys: [] }];
  if (/\.(md|mdc)$/i.test(p) || /^\.(cursorrules|windsurfrules|clinerules)$/.test(base)) {
    const kind = /\/\.claude\/commands\//.test(`/${p}`) ? "slash command" : /\/\.claude\/agents\//.test(`/${p}`) ? "subagent" : "instructions";
    return [{ kind: "instructions", name: kind === "instructions" ? base : `${kind}: ${base.replace(/\.md$/i, "")}`, path: p, scope, agent, envKeys: [], headerKeys: [], detail: `${text.length.toLocaleString("en-US")} characters` }];
  }
  if (/config\.toml$/.test(p)) return codexToml(text, p, scope, agent === "grok" ? "grok" : "codex");
  if (/\.ya?ml$/.test(p)) return continueYaml(text, p, scope);
  const j = parseJsonc(text);
  if (!isObj(j)) return [];
  if (agent === "zed") return serverComponents(j.context_servers, p, scope, "zed");
  if (agent === "amp") return serverComponents(j["amp.mcpServers"], p, scope, "amp");
  if (agent === "opencode" && isObj(j.mcp)) { const mcp = j.mcp as Json; return serverComponents(isObj(mcp.servers) ? mcp.servers : mcp, p, scope, "opencode"); }
  if (/\.claude\/settings(\.local)?\.json$/.test(p)) return claudeSettings(j, p, scope);
  if (/\.vscode\/mcp\.json$/.test(p)) return serverComponents(j.servers, p, scope, "vscode");
  if (base === ".claude.json") {
    // User file: global servers plus every project's own servers (the project path is kept as context, not as a secret).
    const out = serverComponents(j.mcpServers, p, scope, "claude_code");
    if (isObj(j.projects)) for (const [proj, cfg] of Object.entries(j.projects).slice(0, 100)) if (isObj(cfg)) for (const c of serverComponents(cfg.mcpServers, p, "project", "claude_code")) out.push({ ...c, detail: `project ${proj.split(/[\\/]/).slice(-2).join("/")}` });
    return out;
  }
  return serverComponents(j.mcpServers ?? j.servers, p, scope, agent);
}

/** Continue's config.yaml / .continue/mcpServers/*.yaml: `mcpServers:` list items with name/command/args/env/url. A small
 *  line-based reader; nothing else in the file is touched and unknown layouts yield no components rather than wrong ones. */
function continueYaml(text: string, path: string, scope: Component["scope"]): Component[] {
  type Cur = { name?: string; command?: string; args: string[]; url?: string; env: string[]; indent: number; pending?: "args" | "env"; pendingIndent: number };
  const out: Component[] = [];
  let inList = false; let cur: Cur | null = null;
  const unquote = (s: string) => s.trim().replace(/^["']|["']$/g, "");
  const flush = () => {
    if (!cur) return;
    if (cur.url) out.push({ kind: "mcp_server", name: cur.name ?? "mcp", path, scope, agent: "continue", transport: "http", urlHost: hostOf(cur.url), envKeys: cur.env, headerKeys: [] });
    else if (cur.command) out.push({ kind: "mcp_server", name: cur.name ?? cur.command, path, scope, agent: "continue", transport: "stdio", command: cur.command.split(/[\\/]/).pop(), package: stdioPackage(cur.command, cur.args), envKeys: cur.env, headerKeys: [] });
    cur = null;
  };
  const assign = (c: Cur, k: string, v: string, indent: number) => {
    c.pending = undefined;
    if (k === "name") c.name = unquote(v); else if (k === "command") c.command = unquote(v); else if (k === "url") c.url = unquote(v);
    else if (k === "args") { const inline = v.match(/^\[(.*)\]$/); if (inline) c.args = inline[1].split(",").map(unquote).filter(Boolean); else { c.pending = "args"; c.pendingIndent = indent; } }
    else if (k === "env") { c.pending = "env"; c.pendingIndent = indent; }
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "");
    if (!line.trim()) continue;
    if (/^mcpServers:\s*$/.test(line)) { inList = true; continue; }
    if (inList && /^\S/.test(line)) { flush(); inList = false; continue; }
    if (!inList) continue;
    const item = line.match(/^(\s*)-\s+(\w+):\s*(.*)$/);
    if (item) { flush(); cur = { args: [], env: [], indent: item[1].length, pendingIndent: 0 }; assign(cur, item[2], item[3], item[1].length); continue; }
    if (!cur) continue;
    const arr = line.match(/^(\s*)-\s*(.+)$/);
    if (arr && cur.pending === "args" && arr[1].length > cur.pendingIndent) { cur.args.push(unquote(arr[2])); continue; }
    const kv = line.match(/^(\s*)([\w.-]+):\s*(.*)$/);
    if (!kv) continue;
    if (cur.pending === "env" && kv[1].length > cur.pendingIndent) { if (/^[\w.-]{1,120}$/.test(kv[2])) cur.env.push(kv[2]); continue; }
    if (kv[1].length > cur.indent) assign(cur, kv[2], kv[3], kv[1].length);
  }
  flush();
  return out;
}

/* --------------------------------------------------------------- blast radius */

export type CredentialClass = "cloud" | "source_control" | "payments" | "database" | "ai_provider" | "messaging" | "secret";

const CRED_RULES: [RegExp, CredentialClass][] = [
  [/^(AWS_|AZURE_|ARM_|GOOGLE_|GCP_|GCLOUD|CLOUDFLARE_|DIGITALOCEAN|DO_TOKEN|VERCEL_|NETLIFY_|HEROKU_|FLY_)/i, "cloud"],
  [/^(GITHUB_|GH_|GITLAB_|GL_|BITBUCKET_|GIT_)/i, "source_control"],
  [/^(STRIPE_|PAYPAL_|BRAINTREE_|ADYEN_|SQUARE_)/i, "payments"],
  [/(DATABASE_URL|_DSN$|^POSTGRES|^PG|^MYSQL|^MONGO|^REDIS|^SUPABASE_|^NEON_|^PLANETSCALE|^SNOWFLAKE_|^BIGQUERY)/i, "database"],
  [/^(OPENAI_|ANTHROPIC_|GEMINI_|MISTRAL_|COHERE_|GROQ_|HF_|HUGGINGFACE)/i, "ai_provider"],
  [/^(SLACK_|DISCORD_|TWILIO_|SENDGRID_|RESEND_|MAILGUN_|POSTMARK_)/i, "messaging"],
  [/(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIAL|AUTH)/i, "secret"],
];

export function classifyCredential(name: string): CredentialClass | null {
  for (const [re, c] of CRED_RULES) if (re.test(name)) return c;
  return null;
}

export interface BlastInput {
  component: Component;
  /** From the component's verdict, when it resolved to one. */
  verdict?: { label: "verified" | "caution" | "blocked"; score: number } | null;
  trace?: { egressHosts: string[]; credentialPathsRead: string[]; memoryWrites: number } | null;
  /** Known vulnerabilities (OSV) in the package's latest version. */
  vulns?: { count: number; worst: string } | null;
}

export interface BlastRadius {
  level: "high" | "medium" | "low";
  /** One line each, most serious first. */
  reasons: string[];
  credentials: { name: string; class: CredentialClass }[];
  hosts: string[];
}

/**
 * What a component can reach if it misbehaves. Local processes (stdio servers,
 * hooks) run as the developer, so they start at medium; credentials handed to
 * them, a non-Verified verdict, or behaviour seen in the honeypot raise it.
 */
export function blastRadius({ component: c, verdict, trace, vulns }: BlastInput): BlastRadius {
  const reasons: string[] = [];
  const credentials = [...c.envKeys, ...c.headerKeys].map((name) => ({ name, class: classifyCredential(name) })).filter((x): x is { name: string; class: CredentialClass } => !!x.class);
  const hosts = new Set<string>();
  if (c.urlHost) hosts.add(c.urlHost);
  for (const h of trace?.egressHosts ?? []) hosts.add(h);
  let score = 0;
  const local = c.transport === "stdio" || c.kind === "hook";
  if (c.kind === "hook") { score += 2; reasons.push(`runs \`${c.command ?? "a command"}\` ${c.detail ?? "on agent events"}, as the developer`); }
  else if (local) { score += 2; reasons.push("runs on the developer's machine with their files, network and shell"); }
  if (c.kind === "skill" || c.kind === "plugin") { score += 1; reasons.push("adds instructions and scripts the agent will follow"); }
  const strong = credentials.filter((x) => x.class !== "secret");
  if (credentials.length) {
    score += strong.some((x) => ["cloud", "source_control", "payments", "database"].includes(x.class)) ? 3 : 2;
    reasons.unshift(`is handed ${credentials.length === 1 ? "a credential" : `${credentials.length} credentials`}: ${credentials.slice(0, 4).map((x) => x.name).join(", ")}${credentials.length > 4 ? ", …" : ""}`);
  }
  if (c.transport === "http" && c.urlHost) { score += 1; reasons.push(`sends the agent's tool calls and their data to ${c.urlHost}`); }
  if (verdict?.label === "blocked") { score += 4; reasons.unshift(`its verdict is Blocked (${verdict.score}/100)`); }
  else if (verdict?.label === "caution") { score += 1; reasons.push(`its verdict is Caution (${verdict.score}/100)`); }
  if (trace?.credentialPathsRead.length) { score += 3; reasons.unshift(`read ${trace.credentialPathsRead.slice(0, 2).join(", ")} in the honeypot`); }
  if (trace?.memoryWrites) { score += 2; reasons.push("wrote to the agent's memory or instruction files in the honeypot"); }
  if (vulns?.count) { const bad = vulns.worst === "critical" || vulns.worst === "high"; score += bad ? 2 : 1; reasons.push(`has ${vulns.count} known vulnerabilit${vulns.count === 1 ? "y" : "ies"} (OSV, worst ${vulns.worst})`); }
  if (c.kind === "instructions") reasons.push("is read by the agent as instructions on every session");
  if (!verdict && c.kind !== "instructions" && c.kind !== "hook") { score += 1; reasons.push(c.package || c.kind !== "mcp_server" ? "has no KillerSkills verdict yet" : "is not a registry package, so there is no verdict to check"); }
  const level = score >= 5 ? "high" : score >= 3 ? "medium" : "low";
  return { level, reasons, credentials, hosts: [...hosts].slice(0, 10) };
}
