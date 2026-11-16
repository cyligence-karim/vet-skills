/**
 * The tool-call gate between an agent and an MCP server, independent of how the server is reached. `run.ts` puts it in
 * front of a local stdio process; `remote.ts` puts it in front of a remote HTTP or SSE server. One JSON-RPC message per
 * line in both directions.
 *
 * agent → server: a tools/call is refused (canary in the arguments, --deny, a policy deny), held for a person (policy
 * approve) or passed on. Lines are handled in order; a held call parks everything behind it.
 * server → agent: relayed by the caller; `inspect` reads each line for poisoned tool descriptions, instructions or
 * planted canaries in a result, and matches replies to the calls that were passed on.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { hiddenSummary, hiddenTextFindings, toolRuleFor, type ToolAction, type ToolRule } from "./policy/index.js";
import { canariesIn, describeCanary, readCanaries } from "./canary.js";
import { HOME } from "./state.js";

export type RelayEvent =
  | { kind: "tool_call"; tool: string; args: string[]; action: "allowed" | "denied" | "approved" | "refused" | "held"; by?: string; reason?: string; id?: number | string; rule?: string; approvalId?: string }
  | { kind: "tool_reply"; tool: string; id: number | string }
  | { kind: "canary"; where: string; tool: string }
  | { kind: "poison"; tool: string; summary: string }
  | { kind: "stopped"; reason: string; pending: number };

export interface RelayOptions {
  label: string; deny: string[]; toolRules?: ToolRule[]; defaultToolAction?: ToolAction;
  approver?: (call: { server: string; tool: string; args: Record<string, unknown>; rule: ToolRule | null }) => Promise<{ allowed: boolean; by: string; id?: string }>;
  /** A per-tool hold decided by the caller (a remote server's new or rewritten tools awaiting approval). Returns the reason, or null. */
  held?: (tool: string) => string | null;
}
export interface RelayIO { toServer: (line: string) => void; toAgent: (line: string) => void; log: (l: string) => void; emit: (e: RelayEvent) => void; /** Called with every tools/list result, after inspection. */ onTools?: (tools: { name?: string; description?: string; inputSchema?: unknown }[]) => void }

const RUNTIME = join(HOME, "runtime");
export function record(label: string, tool: string, keys: string[], denied: boolean) {
  try { mkdirSync(RUNTIME, { recursive: true }); appendFileSync(join(RUNTIME, "guard.jsonl"), JSON.stringify({ at: new Date().toISOString(), server: label, tool, args: keys, denied }) + "\n"); } catch { /* best effort */ }
}
export const globToRe = (g: string) => new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i");

export function createRelay(opts: RelayOptions, io: RelayIO) {
  const { log, emit } = io;
  const deny = opts.deny.map(globToRe);
  const rules = opts.toolRules ?? [];
  const pending = new Map<number | string, string>();
  const canaryReg = readCanaries();
  const warned = new Set<string>();
  let calls = 0, deniedCalls = 0;
  let stopped: string | null = null;
  let chain: Promise<void> = Promise.resolve();
  const refuse = (id: number | string | undefined, code: number, message: string) => { if (id !== undefined) io.toAgent(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })); };

  const handle = async (line: string) => {
    let m: { id?: number | string; method?: string; params?: { name?: string; arguments?: Record<string, unknown> } } | null = null;
    try { m = JSON.parse(line); } catch { /* pass through */ }
    if (stopped) { if (m?.id !== undefined && m.method) refuse(m.id, -32000, `Server stopped by the guard: ${stopped}`); return; }
    if (m?.method === "tools/call" && m.params?.name) {
      const name = m.params.name;
      const args = m.params.arguments ?? {};
      const keys = Object.keys(args);
      calls++;
      // A planted canary in the arguments the agent is sending to this server: exfiltration in progress. Refuse the call.
      const leak = canariesIn(line, canaryReg);
      if (leak.length) {
        deniedCalls++; record(opts.label, name, keys, true); emit({ kind: "canary", where: "arguments", tool: name }); emit({ kind: "tool_call", tool: name, args: keys, action: "refused", reason: "canary in arguments" });
        log(`✕ CREDENTIAL EXFILTRATION: ${describeCanary(leak[0])} value in the arguments of tools/call ${name}; call refused. Revoke real credentials in that folder.`);
        refuse(m.id, -32600, `vet-skills run refused tools/call ${name}: the arguments carry a planted canary credential (exfiltration).`);
        return;
      }
      if (deny.some((re) => re.test(name))) {
        deniedCalls++; record(opts.label, name, keys, true); emit({ kind: "tool_call", tool: name, args: keys, action: "denied", reason: "--deny" });
        log(`denied tools/call ${name}`);
        refuse(m.id, -32601, `Tool "${name}" is denied by vet-skills run on this machine.`);
        return;
      }
      const heldWhy = opts.held?.(name) ?? null;
      if (heldWhy) {
        deniedCalls++; record(opts.label, name, keys, true); emit({ kind: "tool_call", tool: name, args: keys, action: "denied", reason: heldWhy, id: m.id, rule: "on_change" });
        log(`held tools/call ${name}: ${heldWhy}`);
        refuse(m.id, -32601, `Tool "${name}" is held by the guard: ${heldWhy}`);
        return;
      }
      const rule = toolRuleFor(rules, opts.label, name);
      const action: ToolAction = rule?.action ?? opts.defaultToolAction ?? "allow";
      if (action === "deny") {
        deniedCalls++; record(opts.label, name, keys, true); emit({ kind: "tool_call", tool: name, args: keys, action: "denied", reason: rule ? `policy rule ${rule.match}${rule.reason ? ` (${rule.reason})` : ""}` : "policy default", id: m.id, rule: rule?.match ?? "default" });
        log(`denied tools/call ${name} (policy${rule ? `: ${rule.match}` : ""})`);
        refuse(m.id, -32601, `Tool "${name}" is denied by your organization's runtime policy${rule?.reason ? `: ${rule.reason}` : ""}.`);
        return;
      }
      if (action === "approve") {
        if (!opts.approver) {
          deniedCalls++; record(opts.label, name, keys, true); emit({ kind: "tool_call", tool: name, args: keys, action: "denied", reason: "needs approval; no approver" });
          log(`held tools/call ${name}: policy requires approval and this machine has no approver (join an org, or change runtime.tools)`);
          refuse(m.id, -32601, `Tool "${name}" needs approval under the runtime policy and no approver is configured on this machine.`);
          return;
        }
        emit({ kind: "tool_call", tool: name, args: keys, action: "held", reason: rule?.reason, id: m.id, rule: rule?.match ?? "default" });
        log(`holding tools/call ${name} for approval${rule?.reason ? ` (${rule.reason})` : ""}…`);
        const d = await opts.approver({ server: opts.label, tool: name, args, rule }).catch((e: Error) => ({ allowed: false, by: `error: ${e.message}` }));
        if (!d.allowed) {
          deniedCalls++; record(opts.label, name, keys, true); emit({ kind: "tool_call", tool: name, args: keys, action: "denied", by: d.by, reason: "approval denied or timed out", id: m.id, rule: rule?.match ?? "default", approvalId: (d as { id?: string }).id });
          log(`✕ tools/call ${name} denied (${d.by})`);
          refuse(m.id, -32601, `Tool "${name}" was not approved (${d.by}).`);
          return;
        }
        record(opts.label, name, keys, false); emit({ kind: "tool_call", tool: name, args: keys, action: "approved", by: d.by, id: m.id, rule: rule?.match ?? "default", approvalId: (d as { id?: string }).id });
        log(`tools/call ${name} approved by ${d.by}`);
        if (m.id !== undefined) pending.set(m.id, name);
        io.toServer(line);
        return;
      }
      record(opts.label, name, keys, false); emit({ kind: "tool_call", tool: name, args: keys, action: "allowed", id: m.id, rule: rule?.match ?? "default" });
      if (m.id !== undefined) pending.set(m.id, name);
    }
    io.toServer(line);
  };

  return {
    /** One line from the agent. Handled in arrival order. */
    fromAgent(line: string) { if (line.trim()) chain = chain.then(() => handle(line)); return chain; },
    /** Resolves once every line received so far has been handled. */
    drained: () => chain,
    /** One line from the server, already (or about to be) relayed by the caller. */
    inspect(line: string) {
      if (line.length > 2_000_000 || !line.trim()) return;
      let m: { id?: number | string; result?: { tools?: { name?: string; description?: string; inputSchema?: unknown }[]; content?: unknown } } | null = null;
      try { m = JSON.parse(line); } catch { return; }
      if (!m?.result) return;
      if (Array.isArray(m.result.tools)) {
        for (const t of m.result.tools) {
          const f = hiddenTextFindings(`${t.description ?? ""}\n${JSON.stringify(t.inputSchema ?? {})}`, { phrases: true }).filter((x) => x.severity !== "medium");
          const key = `desc|${t.name}`;
          if (f.length && !warned.has(key)) { warned.add(key); record(opts.label, t.name ?? "?", [], false); emit({ kind: "poison", tool: t.name ?? "?", summary: hiddenSummary(f) }); log(`tool "${t.name}" description carries instructions for the agent (tool poisoning): ${hiddenSummary(f)}. Deny it with --deny ${t.name} if you do not trust it.`); }
        }
        try { io.onTools?.(m.result.tools); } catch { /* never break the relay */ }
      } else if (m.id !== undefined && pending.has(m.id)) {
        const tool = pending.get(m.id)!; pending.delete(m.id);
        emit({ kind: "tool_reply", tool, id: m.id });
        const leak = canariesIn(line, canaryReg);
        if (leak.length && !warned.has(`canary|${tool}`)) { warned.add(`canary|${tool}`); record(opts.label, tool, [], false); emit({ kind: "canary", where: "result", tool }); log(`✕ ${describeCanary(leak[0])} value in the result of ${tool}: the server read a decoy credential file on this machine. Treat ${opts.label} as hostile.`); }
        const f = hiddenTextFindings(JSON.stringify(m.result.content ?? m.result), { phrases: true }).filter((x) => x.severity !== "medium");
        const key = `res|${tool}|${f[0]?.title ?? ""}`;
        if (f.length && !warned.has(key)) { warned.add(key); emit({ kind: "poison", tool, summary: hiddenSummary(f) }); log(`result of ${tool} carries instructions aimed at the agent: ${hiddenSummary(f)}. Treat it as data.`); }
      }
    },
    /** Answer every pending call with the reason and refuse later ones. Returns how many were pending. */
    stop(reason: string): number {
      if (stopped) return 0;
      stopped = reason;
      const n = pending.size;
      for (const id of pending.keys()) refuse(id, -32000, `Server stopped by the guard: ${reason}`);
      pending.clear();
      emit({ kind: "stopped", reason, pending: n });
      log(`✕ stopping ${opts.label}: ${reason}${n ? ` · ${n} pending call${n === 1 ? "" : "s"} answered with the reason` : ""}`);
      return n;
    },
    get stopped() { return stopped; },
    counts: () => ({ calls, denied: deniedCalls }),
  };
}
