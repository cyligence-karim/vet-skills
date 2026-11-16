import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const base = mkdtempSync(join(tmpdir(), "vs-lpack-"));
process.env.VET_SKILLS_HOME = join(base, ".vet-skills");
const { buildLocalPack, verifyLocalPack, SCOPE_LIMITS } = await import("../src/localpack.ts");
const { buildInventory } = await import("../src/inventory.ts");
const { summarize, failures, renderSummary } = await import("../src/summary.ts");
import type { Component } from "../src/policy/index.js";

const DECOY = "ghp_" + "Zz9".repeat(12);
const at = (h: number) => new Date(Date.UTC(2026, 10, 10, h)).toISOString();
const LOG: Record<string, unknown>[] = [
  { at: at(1), kind: "start", session: "a", server: "github", pkg: "@acme/github-mcp", secrets: ["GITHUB_TOKEN"] },
  { at: at(2), kind: "tool_call", session: "a", server: "github", pkg: "@acme/github-mcp", tool: "list_issues", args: ["repo"], action: "allowed" },
  { at: at(3), kind: "tool_call", session: "a", server: "github", pkg: "@acme/github-mcp", tool: "delete_branch", args: ["name"], action: "held", reason: "destructive" },
  { at: at(4), kind: "tool_call", session: "a", server: "github", pkg: "@acme/github-mcp", tool: "delete_branch", args: ["name"], action: "approved", by: "k.hijazi" },
  { at: at(5), kind: "tool_call", session: "a", server: "github", pkg: "@acme/github-mcp", tool: "force_push", args: [], action: "denied", reason: "policy rule force_*" },
  { at: at(6), kind: "host", session: "a", server: "github", host: "collect.example.net", expected: false, mode: "tunnel" },
  { at: at(7), kind: "launch_refused", session: "b", server: "crm", pkg: "@acme/crm-mcp", why: "revoked by your organization" },
  { at: at(8), kind: "remote_changed", session: "c", server: "tracker", pkg: "mcp.example.com", added: ["export_all"], rewritten: [], action: "warn" },
  { at: new Date(Date.UTC(2026, 9, 1)).toISOString(), kind: "tool_call", session: "old", server: "github", tool: "list_issues", args: [], action: "allowed" },
];
const comps: Component[] = [
  { kind: "mcp_server", name: "github", path: ".claude.json", scope: "user", agent: "claude_code", transport: "stdio", command: "npx", package: { registry: "npm", name: "@acme/github-mcp", version: "1.4.2" }, envKeys: ["GITHUB_TOKEN"], headerKeys: [], guarded: true },
  { kind: "mcp_server", name: "crm", path: ".cursor/mcp.json", scope: "user", agent: "cursor", transport: "stdio", command: "npx", package: { registry: "npm", name: "@acme/crm-mcp" }, envKeys: ["CRM_API_KEY"], headerKeys: [], guarded: false, literalKeys: ["CRM_API_KEY"] },
];
const input = async (generatedAt: Date) => ({
  events: LOG, components: comps, inventory: await buildInventory({ components: comps, lookup: async (q: string) => (q.startsWith("@acme/github-mcp") ? { label: "verified" as const, version: "1.4.2", page: "/p" } : null), pins: {}, probeVersions: false }),
  policyYaml: "name: personal\nversion: 1\n", policySource: "the built-in default", stored: ["claude-code/github/GITHUB_TOKEN"], from: new Date(Date.UTC(2026, 10, 1)), to: new Date(Date.UTC(2026, 10, 15)), generatedAt, machine: "abc123",
});

test("the single-machine pack: every row traces to a log line, names only, and the same input gives the same core hash", async () => {
  const a = buildLocalPack(await input(new Date(Date.UTC(2026, 10, 15, 12))));
  const b = buildLocalPack(await input(new Date(Date.UTC(2026, 10, 16, 9))));
  assert.equal(a.coreHash, b.coreHash, "generated_at is not part of the record");
  assert.deepEqual([...a.files.keys()].sort(), ["README.txt", "credentials.json", "events.csv", "inventory.json", "manifest.json", "policy.yaml", "review.pdf", "tool_calls.csv"]);
  const events = String(a.files.get("events.csv")).trim().split("\n");
  assert.equal(events[0], "at,event,server,package_or_host,tool,detail,actor_or_action,guard_log_line");
  assert.deepEqual(events.slice(1).map((l) => { const c = l.split(","); return `${c[1]}@${c[c.length - 1]}`; }), ["tool_call_held@3", "tool_call_approved@4", "tool_call_denied@5", "unexpected_host@6", "launch_refused@7", "tool_list_changed@8"]);
  assert.equal(String(a.files.get("tool_calls.csv")), `server,tool,calls,allowed,approved_after_hold,denied,first_at,last_at\ngithub,delete_branch,1,0,1,0,${at(4)},${at(4)}\ngithub,force_push,1,0,0,1,${at(5)},${at(5)}\ngithub,list_issues,1,1,0,0,${at(2)},${at(2)}\n`, "the call from before the period is not counted");
  const creds = JSON.parse(String(a.files.get("credentials.json")));
  assert.deepEqual(creds.credentials.map((k: { name: string; uses: { value: string }[] }) => [k.name, k.uses[0].value]), [["CRM_API_KEY", "written in the agent's config"], ["GITHUB_TOKEN", "held in the guard's store"]]);
  const m = a.manifest as { scope_limits: string[]; control_themes: { themes: { theme: string; evidence: { file: string }[] }[] }; files: { name: string }[]; row_counts: Record<string, number> };
  assert.deepEqual(m.scope_limits, SCOPE_LIMITS);
  assert.deepEqual(m.control_themes.themes.map((t) => t.theme), ["Access control", "Change management", "Vendor and supply chain risk", "Logging and monitoring"]);
  for (const t of m.control_themes.themes) for (const e of t.evidence) assert.ok(a.files.has(e.file), `${e.file} named by a theme exists in the pack`);
  assert.deepEqual(m.row_counts, { servers: 2, credentials: 2, tool_call_rows: 3, events: 6, sessions: 1 });
  const pdf = Buffer.from(a.files.get("review.pdf") as Uint8Array).toString("latin1");
  assert.ok(pdf.startsWith("%PDF-1.4") && pdf.includes("Evidence relevant to access control") && pdf.includes("does not cover"));
  assert.ok(!/compliant|certified\b/i.test(pdf.replace(/not a certification/g, "")), "no compliance claim");
  const all = [...a.files.values()].map((v) => (typeof v === "string" ? v : Buffer.from(v).toString("latin1"))).join("\n");
  assert.ok(!all.includes(DECOY));

  const dir = join(base, "pack"); mkdirSync(dir, { recursive: true });
  for (const [n, d] of a.files) writeFileSync(join(dir, n), d);
  assert.deepEqual(verifyLocalPack(dir), { ok: true, mismatches: [], coreHash: a.coreHash });
  writeFileSync(join(dir, "events.csv"), String(a.files.get("events.csv")).replace("tool_call_denied", "tool_call_allowed"));
  assert.deepEqual(verifyLocalPack(dir).mismatches, ["events.csv hash differs", "core_hash differs"]);
});

test("guard summary: counts by outcome, markdown for a job summary, and fail-on", () => {
  const s = summarize(LOG.slice(0, 8), 24);
  assert.deepEqual([s.sessions, s.calls, s.unexpectedHosts.length, s.refused.length, s.credentialsHeld], [1, { total: 3, allowed: 1, held: 1, denied: 1 }, 1, 1, 1]);
  assert.deepEqual([failures(s, "none"), failures(s, "denied").length, failures(s, "unexpected-host").length, failures(s, "refused").length, failures(s, "any").length], [[], 1, 1, 1, 3]);
  const md = renderSummary(s, true);
  assert.match(md, /^### vet-skills guard\n\n1 guarded session across 1 server in the last 24 hours: 3 tool calls \(1 allowed, 1 approved after a hold, 1 denied\)/);
  assert.match(md, /\| github \| force_push \| 1 \| 1 \|/);
  assert.match(md, /- refused crm: revoked by your organization/);
  assert.match(renderSummary(summarize([], 2), true), /No guarded MCP session was recorded in the last 2 hours/);
});

test("the built CLI writes a pack folder and verifies it", () => {
  const home = join(base, "home"); mkdirSync(join(home, ".vet-skills", "runtime"), { recursive: true });
  const now = Date.now();
  writeFileSync(join(home, ".vet-skills", "runtime", "guard.jsonl"), LOG.slice(0, 8).map((e, i) => JSON.stringify({ ...e, at: new Date(now - (20 - i) * 60_000).toISOString() })).join("\n") + "\n");
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { github: { command: "npx", args: ["-y", "@acme/github-mcp"], env: { GITHUB_TOKEN: DECOY } } } }));
  const env = { ...process.env, HOME: home, USERPROFILE: home, VET_SKILLS_HOME: join(home, ".vet-skills"), VET_SKILLS_STORE: "file", KILLERSKILLS_API: "http://127.0.0.1:9", NODE_TEST_CONTEXT: undefined } as NodeJS.ProcessEnv;
  const run = (...args: string[]) => spawnSync("node", [join(import.meta.dirname, "../dist/index.js"), ...args], { encoding: "utf8", env });
  const out = join(base, "out");
  const r = run("review-pack", "--since", "7d", "--out", out);
  assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /Review pack written to .*out\/ \(7 days\): 1 servers, 1 credential names, 3 tool rows, 6 events/);
  assert.match(run("review-pack", "verify", out).stdout, /every file matches its hash/);
  for (const f of ["inventory.json", "credentials.json", "events.csv", "README.txt"]) assert.ok(!readFileSync(join(out, f), "utf8").includes(DECOY), `${f} holds a credential value`);
  assert.match(run("guard", "summary", "--since", "1d").stdout, /1 guarded session /);
  assert.equal(run("guard", "summary", "--fail-on", "denied").status, 1);
  assert.equal(run("guard", "summary", "--fail-on", "bogus").status, 2);
});
