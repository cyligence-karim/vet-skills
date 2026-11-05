/**
 * KillerSkills for VS Code, Cursor and Windsurf. When an agent config file is
 * open (.mcp.json, ~/.cursor/mcp.json, claude_desktop_config.json, .claude/
 * settings.json, .codex/config.toml, …), every MCP server, skill and plugin in
 * it gets a diagnostic with its verdict and a link to the trace; a credential
 * value pasted into the file gets an error by kind and line. Only names leave
 * the editor (the parser drops values and arguments); the value of a leaked
 * credential is never read back or sent.
 */
import * as vscode from "vscode";
import { analyzeText, isConfigFile, resolveQuery, type Located } from "./analyze";

type Verdict = { label: "verified" | "caution" | "blocked"; score: number; page: string; summary: string | null; vulns: number; benchTokens: number | null } | null;
const cache = new Map<string, { at: number; v: Verdict }>();
const TTL = 10 * 60_000;

function apiBase() { return vscode.workspace.getConfiguration("killerskills").get<string>("apiBase", "https://killerskills.ai").replace(/\/$/, ""); }

async function verdictFor(c: Located["c"]): Promise<Verdict> {
  const q = resolveQuery(c);
  if (!q) return null;
  const key = `${q.registry ?? ""}:${q.q}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL) return hit.v;
  let v: Verdict = null;
  try {
    const url = `${apiBase()}/api/v1/resolve?q=${encodeURIComponent(q.q)}${q.registry ? `&registry=${q.registry}` : ""}`;
    const r = await fetch(url, { headers: { "user-agent": "killerskills-vscode/0.1", "x-vs-surface": "ide" }, signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const d = (await r.json()) as { verdict?: { label: Verdict extends null ? never : NonNullable<Verdict>["label"]; score: number; summary?: string | null }; skill?: { page: string }; vulnerabilities?: { count: number } | null; benchmark?: { mcp?: { context_tokens: number } | null } | null };
      if (d.verdict && d.skill) v = { label: d.verdict.label, score: d.verdict.score, page: d.skill.page, summary: d.verdict.summary ?? null, vulns: d.vulnerabilities?.count ?? 0, benchTokens: d.benchmark?.mcp?.context_tokens ?? null };
    }
  } catch { v = null; }
  cache.set(key, { at: Date.now(), v });
  return v;
}

export function activate(ctx: vscode.ExtensionContext) {
  const diags = vscode.languages.createDiagnosticCollection("killerskills");
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 50);
  status.command = "killerskills.checkFile";
  ctx.subscriptions.push(diags, status);

  const check = async (doc: vscode.TextDocument) => {
    if (doc.uri.scheme !== "file" || !isConfigFile(doc.uri.fsPath)) { if (vscode.window.activeTextEditor?.document === doc) status.hide(); return; }
    const { components, secrets } = analyzeText(doc.uri.fsPath, doc.getText());
    const out: vscode.Diagnostic[] = [];
    for (const s of secrets) {
      const line = Math.max(0, s.line - 1);
      const d = new vscode.Diagnostic(doc.lineAt(line).range, `${s.label} committed in this file${s.keyName ? ` under "${s.keyName}"` : ""}. Revoke it at the provider and use an environment reference such as \${${s.keyName ?? "TOKEN"}}. (KillerSkills; the value is never read or sent.)`, vscode.DiagnosticSeverity.Error);
      d.source = "KillerSkills"; d.code = { value: "committed-credential", target: vscode.Uri.parse(`${apiBase()}/docs#secrets`) };
      out.push(d);
    }
    const flagUnvetted = vscode.workspace.getConfiguration("killerskills").get<boolean>("flagUnvetted", true);
    let caution = 0, blocked = 0;
    await Promise.all(components.map(async ({ c, line }) => {
      if (c.kind === "instructions" || c.kind === "hook" || c.kind === "secret" || c.kind === "lure") return;
      const range = doc.lineAt(Math.min(line, doc.lineCount - 1)).range;
      const keys = [...c.envKeys, ...c.headerKeys];
      if (c.kind === "mcp_server" && c.transport === "http") {
        const d = new vscode.Diagnostic(range, `${c.name}: hosted MCP server at ${c.urlHost ?? "a remote host"}${keys.length ? `, handed ${keys.join(", ")}` : ""}. No package to vet; the public repo scan probes it read-only.`, vscode.DiagnosticSeverity.Hint);
        d.source = "KillerSkills"; out.push(d); return;
      }
      const v = await verdictFor(c);
      if (!v) {
        if (!flagUnvetted || !resolveQuery(c)) return;
        const d = new vscode.Diagnostic(range, `${c.name}: no KillerSkills verdict yet${keys.length ? ` (holds ${keys.join(", ")})` : ""}. Run "vet-skills try ${c.package?.name ?? c.name}" to see what it does before trusting it.`, vscode.DiagnosticSeverity.Information);
        d.source = "KillerSkills"; d.code = { value: "unvetted", target: vscode.Uri.parse(`${apiBase()}/docs/cli#try`) }; out.push(d); return;
      }
      const sev = v.label === "blocked" ? vscode.DiagnosticSeverity.Error : v.label === "caution" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information;
      if (v.label === "blocked") blocked++; else if (v.label === "caution") caution++;
      const extras = [keys.length ? `holds ${keys.join(", ")}` : "", v.vulns ? `${v.vulns} known vulnerabilit${v.vulns === 1 ? "y" : "ies"} (OSV)` : "", v.benchTokens ? `≈${v.benchTokens.toLocaleString("en-US")} tokens of tool context per prompt` : ""].filter(Boolean);
      const d = new vscode.Diagnostic(range, `${c.name}: ${v.label.toUpperCase()} ${v.score}/100${v.summary ? ` — ${v.summary}` : ""}${extras.length ? ` · ${extras.join(" · ")}` : ""}`, sev);
      d.source = "KillerSkills"; d.code = { value: `${v.label} ${v.score}`, target: vscode.Uri.parse(`${apiBase()}${v.page}`) };
      out.push(d);
    }));
    diags.set(doc.uri, out);
    const n = components.filter((x) => x.c.kind === "mcp_server" || x.c.kind === "skill" || x.c.kind === "plugin").length;
    status.text = `$(shield) ${n} agent component${n === 1 ? "" : "s"}${blocked ? ` · ${blocked} blocked` : ""}${caution ? ` · ${caution} caution` : ""}${secrets.length ? ` · ${secrets.length} leaked value${secrets.length === 1 ? "" : "s"}` : ""}`;
    status.tooltip = "KillerSkills: verdicts for the MCP servers and skills in this file. Click to re-check.";
    status.show();
  };

  const timers = new Map<string, NodeJS.Timeout>();
  const debounced = (doc: vscode.TextDocument) => { const k = doc.uri.toString(); clearTimeout(timers.get(k)); timers.set(k, setTimeout(() => void check(doc), 600)); };

  ctx.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((d) => void check(d)),
    vscode.workspace.onDidChangeTextDocument((e) => debounced(e.document)),
    vscode.workspace.onDidCloseTextDocument((d) => diags.delete(d.uri)),
    vscode.window.onDidChangeActiveTextEditor((e) => { if (e) void check(e.document); else status.hide(); }),
    vscode.commands.registerCommand("killerskills.checkFile", () => { cache.clear(); const d = vscode.window.activeTextEditor?.document; if (d) void check(d); }),
    vscode.commands.registerCommand("killerskills.openBenchmarks", () => vscode.env.openExternal(vscode.Uri.parse(`${apiBase()}/benchmarks`))),
  );
  for (const d of vscode.workspace.textDocuments) void check(d);
}

export function deactivate() { /* nothing to release beyond subscriptions */ }
