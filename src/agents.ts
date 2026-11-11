/**
 * Windsurf (Cascade / Devin desktop) and Gemini CLI hooks. Both speak "JSON on stdin, exit 2 to block, stderr to the
 * agent", like Claude Code, with their own event names and field layouts. Each event is translated into the Claude
 * Code shape the existing checks understand (eval for installs, observe for runtime, prompt for intent), and a block
 * becomes exit 2 with the reason on stderr. Anything unexpected is allowed: a hook must never break the agent.
 *
 * Windsurf: ~/.codeium/windsurf/hooks.json  { hooks: { pre_run_command: [{ command }], … } }
 *   stdin: { agent_action_name, trajectory_id, tool_info: { command_line, cwd | file_path | mcp_server_name, mcp_tool_name, mcp_tool_arguments, mcp_result | user_prompt } }
 * Gemini CLI: ~/.gemini/settings.json  { hooks: { BeforeTool: [{ matcher, hooks: [{ type: "command", command }] }], … } }
 *   stdin: { session_id, hook_event_name, tool_name, tool_input, tool_response?: { llmContent }, prompt? }
 *   shell tool is run_shell_command { command }; MCP tools are mcp_<server>_<tool>; file reads read_file { file_path | absolute_path }
 * Grok CLI (Grok Build): ~/.grok/hooks/*.json  { hooks: { PreToolUse: [{ matcher, hooks: [{ type: "command", command, timeout }] }], … } }
 *   stdin: { hookEventName, sessionId, cwd, workspaceRoot, toolName, toolInput, … } (camelCase; Claude tool names Bash / Read are
 *   accepted in matchers and mapped, MCP tools are <server>__<tool>). PreToolUse is the only blocking event: stdout
 *   { "decision": "deny", "reason" } plus exit 2 denies; timeouts and malformed output are fail-open on Grok's side.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { AgentKind } from "./policy/index.js";
import { canariesIn, describeCanary, readCanaries } from "./canary.js";
import { captureStderr, hookEval } from "./hook.js";
import { observe, recordPrompt } from "./runtime.js";

export type AgentReply = { code: number; stderr: string };

/** A Claude-Code-shaped event plus what to do with it. */
type Translated = { kind: "prompt" | "pre_shell" | "pre_mcp" | "post" | "pre_read" | "ignore"; session: string; tool: string; input: unknown; response?: unknown; prompt?: string; filePath?: string };

export function translateWindsurf(ev: Record<string, unknown>): Translated {
  const info = (ev.tool_info ?? {}) as Record<string, unknown>;
  const session = String(ev.trajectory_id ?? "windsurf");
  switch (ev.agent_action_name) {
    case "pre_user_prompt": return { kind: "prompt", session, tool: "", input: null, prompt: typeof info.user_prompt === "string" ? info.user_prompt : "" };
    case "pre_run_command": return { kind: "pre_shell", session, tool: "Bash", input: { command: String(info.command_line ?? "") } };
    case "post_run_command": return { kind: "post", session, tool: "Bash", input: { command: String(info.command_line ?? "") }, response: info.output ?? info.result ?? null };
    case "pre_mcp_tool_use": return { kind: "pre_mcp", session, tool: mcpTool(info.mcp_server_name, info.mcp_tool_name), input: info.mcp_tool_arguments ?? {} };
    case "post_mcp_tool_use": return { kind: "post", session, tool: mcpTool(info.mcp_server_name, info.mcp_tool_name), input: info.mcp_tool_arguments ?? {}, response: info.mcp_result ?? null };
    case "pre_read_code": return { kind: "pre_read", session, tool: "Read", input: { file_path: String(info.file_path ?? "") }, filePath: String(info.file_path ?? "") };
    case "post_read_code": return { kind: "post", session, tool: "Read", input: { file_path: String(info.file_path ?? "") }, response: info.content ?? null };
    default: return { kind: "ignore", session, tool: "", input: null };
  }
}

export function translateGemini(ev: Record<string, unknown>): Translated {
  const session = String(ev.session_id ?? "gemini");
  const name = String(ev.tool_name ?? "");
  const input = (ev.tool_input ?? {}) as Record<string, unknown>;
  const tool = name === "run_shell_command" ? "Bash" : /^mcp_/.test(name) ? `mcp__${name.slice(4).replace(/_/, "__")}` : name === "read_file" || name === "read_many_files" ? "Read" : name === "web_fetch" ? "WebFetch" : name === "google_web_search" ? "WebSearch" : name;
  const claudeInput = tool === "Bash" ? { command: String(input.command ?? "") } : tool === "Read" ? { file_path: String(input.absolute_path ?? input.file_path ?? input.path ?? "") } : input;
  switch (ev.hook_event_name) {
    case "BeforeAgent": return { kind: "prompt", session, tool: "", input: null, prompt: typeof ev.prompt === "string" ? ev.prompt : "" };
    case "BeforeTool": return tool === "Bash" ? { kind: "pre_shell", session, tool, input: claudeInput } : tool.startsWith("mcp__") ? { kind: "pre_mcp", session, tool, input: claudeInput } : tool === "Read" ? { kind: "pre_read", session, tool, input: claudeInput, filePath: String((claudeInput as { file_path?: string }).file_path ?? "") } : { kind: "ignore", session, tool, input: claudeInput };
    case "AfterTool": { const r = ev.tool_response as { llmContent?: unknown; returnDisplay?: unknown } | undefined; return { kind: "post", session, tool, input: claudeInput, response: r?.llmContent ?? r?.returnDisplay ?? r ?? null }; }
    default: return { kind: "ignore", session, tool: "", input: null };
  }
}

/** Grok sends camelCase; a few builds send snake_case. Tool names follow Claude's for the built-ins and <server>__<tool> for MCP. */
export function translateGrok(ev: Record<string, unknown>): Translated {
  const session = String(ev.sessionId ?? ev.session_id ?? "grok");
  const event = String(ev.hookEventName ?? ev.hook_event_name ?? "");
  const name = String(ev.toolName ?? ev.tool_name ?? "");
  const input = (ev.toolInput ?? ev.tool_input ?? {}) as Record<string, unknown>;
  const lower = name.toLowerCase();
  const tool = lower === "bash" || lower === "shell" || lower === "run_command" || lower === "execute_command" || lower === "run_shell_command" ? "Bash"
    : lower === "read" || lower === "read_file" || lower === "view_file" ? "Read"
    : /^mcp__/.test(name) ? name
    : /^[A-Za-z0-9_-]+__[A-Za-z0-9_-]+$/.test(name) ? `mcp__${name.replace("__", "__")}` : name;
  const claudeInput = tool === "Bash" ? { command: String(input.command ?? input.cmd ?? "") } : tool === "Read" ? { file_path: String(input.file_path ?? input.path ?? input.absolute_path ?? input.filePath ?? "") } : input;
  switch (event) {
    case "UserPromptSubmit": return { kind: "prompt", session, tool: "", input: null, prompt: typeof ev.prompt === "string" ? ev.prompt : typeof ev.userPrompt === "string" ? ev.userPrompt : "" };
    case "PreToolUse": return tool === "Bash" ? { kind: "pre_shell", session, tool, input: claudeInput } : tool.startsWith("mcp__") ? { kind: "pre_mcp", session, tool, input: claudeInput } : tool === "Read" ? { kind: "pre_read", session, tool, input: claudeInput, filePath: String((claudeInput as { file_path?: string }).file_path ?? "") } : { kind: "ignore", session, tool, input: claudeInput };
    case "PostToolUse": return { kind: "post", session, tool, input: claudeInput, response: ev.toolResponse ?? ev.toolOutput ?? ev.toolResult ?? ev.tool_response ?? ev.output ?? null };
    default: return { kind: "ignore", session, tool: "", input: null };
  }
}

function mcpTool(server: unknown, tool: unknown) { return `mcp__${String(server ?? "server").replace(/\W+/g, "_")}__${String(tool ?? "tool")}`; }

/** Run the translated event through the same checks the Claude Code hook runs; exit 2 + stderr blocks. */
export async function runTranslated(t: Translated, agent: AgentKind): Promise<AgentReply> {
  try {
    const payload = (extra: Record<string, unknown> = {}) => JSON.stringify({ session_id: t.session, tool_name: t.tool, tool_input: t.input, ...extra });
    const reg = readCanaries();
    switch (t.kind) {
      case "prompt": if (t.prompt) recordPrompt(JSON.stringify({ session_id: t.session, prompt: t.prompt })); return { code: 0, stderr: "" };
      case "pre_shell": {
        const cmd = String((t.input as { command?: string }).command ?? "");
        if (reg && canariesIn(cmd, reg).length) { await observe(payload(), { agent }).catch(() => null); return { code: 2, stderr: `vet-skills ✕ refused: the command carries a planted ${describeCanary(canariesIn(cmd, reg)[0])}. Nothing legitimate reads that file; this is credential exfiltration. Tell the user and revoke real credentials in the same folder.` }; }
        const { result: code, text } = await captureStderr(() => hookEval(JSON.stringify({ tool_name: "Bash", tool_input: { command: cmd } }), agent));
        return { code: code === 2 ? 2 : 0, stderr: text.trim() };
      }
      case "pre_mcp": {
        const leak = reg ? canariesIn(JSON.stringify(t.input ?? {}), reg) : [];
        if (leak.length) { await observe(payload(), { agent }).catch(() => null); return { code: 2, stderr: `vet-skills ✕ refused ${t.tool}: its arguments carry a planted ${describeCanary(leak[0])} (credential exfiltration). Stop using this server and tell the user.` }; }
        return { code: 0, stderr: "" };
      }
      case "pre_read": {
        const decoy = reg?.canaries.find((c) => c.path === t.filePath);
        if (decoy) { await observe(payload(), { agent }).catch(() => null); return { code: 2, stderr: `vet-skills ✕ refused to read ${t.filePath}: it is a decoy ${describeCanary(decoy)}. Nothing legitimate reads it; tell the user what asked for it.` }; }
        return { code: 0, stderr: "" };
      }
      case "post": {
        const r = await observe(payload({ tool_response: t.response ?? null }), { agent });
        // Post events cannot undo anything; the message reaches the agent through stderr. Exit 2 where the agent honors it (Gemini hides the result).
        return { code: r.code === 2 ? 2 : 0, stderr: r.lines.join("\n") };
      }
      default: return { code: 0, stderr: "" };
    }
  } catch { return { code: 0, stderr: "" }; }
}

export async function windsurfHook(stdin: string): Promise<AgentReply> {
  let ev: Record<string, unknown> = {}; try { ev = JSON.parse(stdin); } catch { return { code: 0, stderr: "" }; }
  return runTranslated(translateWindsurf(ev), "other");
}
export async function geminiHook(stdin: string): Promise<AgentReply> {
  let ev: Record<string, unknown> = {}; try { ev = JSON.parse(stdin); } catch { return { code: 0, stderr: "" }; }
  return runTranslated(translateGemini(ev), "gemini_cli");
}

export async function grokHook(stdin: string): Promise<AgentReply & { stdout?: string }> {
  let ev: Record<string, unknown> = {}; try { ev = JSON.parse(stdin); } catch { return { code: 0, stderr: "" }; }
  const t = translateGrok(ev);
  const r = await runTranslated(t, "other");
  // Only PreToolUse can block, and only an explicit deny does; everything else is passive and stdout is ignored.
  if (r.code === 2 && t.kind !== "post") return { ...r, stdout: JSON.stringify({ decision: "deny", reason: r.stderr.split("\n")[0].slice(0, 400) }) };
  return { ...r, code: 0 };
}

export function installGrokHook(): { path: string; changed: boolean } {
  const dir = join(homedir(), ".grok", "hooks");
  const path = join(dir, "killerskills.json");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  let file: Record<string, unknown> = {};
  if (existsSync(path)) { try { file = JSON.parse(readFileSync(path, "utf8")); } catch { file = {}; } }
  const hooks = (file.hooks ??= {}) as Record<string, { matcher?: string; hooks: { type: string; command: string; timeout?: number }[] }[]>;
  let changed = false;
  const add = (event: string, matcher: string | undefined) => {
    const list = (hooks[event] ??= []);
    if (list.some((h) => h.hooks.some((x) => /vet-skills hook grok/.test(x.command)))) return;
    list.push({ ...(matcher ? { matcher } : {}), hooks: [{ type: "command", command: "vet-skills hook grok", timeout: 60 }] }); changed = true;
  };
  add("UserPromptSubmit", undefined);
  add("PreToolUse", undefined);
  add("PostToolUse", undefined);
  if (changed) writeFileSync(path, JSON.stringify(file, null, 2) + "\n");
  return { path, changed };
}

export function installWindsurfHook(): { path: string; changed: boolean } {
  const dir = join(homedir(), ".codeium", "windsurf");
  const path = join(dir, "hooks.json");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  let file: { hooks?: Record<string, { command?: string; powershell?: string; show_output?: boolean }[]> } = {};
  if (existsSync(path)) { try { file = JSON.parse(readFileSync(path, "utf8")); } catch { file = {}; } }
  const hooks = (file.hooks ??= {});
  let changed = false;
  for (const ev of ["pre_user_prompt", "pre_run_command", "post_run_command", "pre_mcp_tool_use", "post_mcp_tool_use", "pre_read_code"]) {
    const list = (hooks[ev] ??= []);
    if (list.some((h) => /vet-skills hook windsurf/.test(h.command ?? ""))) continue;
    list.push({ command: "vet-skills hook windsurf", show_output: false }); changed = true;
  }
  if (changed) writeFileSync(path, JSON.stringify(file, null, 2) + "\n");
  return { path, changed };
}

export function installGeminiHook(): { path: string; changed: boolean } {
  const dir = join(homedir(), ".gemini");
  const path = join(dir, "settings.json");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  let settings: Record<string, unknown> = {};
  if (existsSync(path)) { try { settings = JSON.parse(readFileSync(path, "utf8")); } catch { settings = {}; } }
  const hooks = (settings.hooks ??= {}) as Record<string, { matcher?: string; hooks: { type: string; command: string; name?: string; timeout?: number }[] }[]>;
  let changed = false;
  const add = (event: string, matcher: string | undefined) => {
    const list = (hooks[event] ??= []);
    if (list.some((h) => h.hooks.some((x) => /vet-skills hook gemini/.test(x.command)))) return;
    list.push({ ...(matcher ? { matcher } : {}), hooks: [{ type: "command", command: "vet-skills hook gemini", name: "killerskills", timeout: 60000 }] }); changed = true;
  };
  add("BeforeAgent", undefined);
  add("BeforeTool", "run_shell_command|read_file|read_many_files|mcp_.*");
  add("AfterTool", "run_shell_command|read_file|web_fetch|google_web_search|mcp_.*");
  if (changed) writeFileSync(path, JSON.stringify(settings, null, 2) + "\n");
  return { path, changed };
}
