#!/usr/bin/env node
/**
 * vet-skills — check agent skills and MCP servers before they run.
 *
 *   vet-skills check <skill>              dry-run the decision
 *   vet-skills install <skill>            check, then `npx skills add`
 *   vet-skills try <pkg|pypi:name|owner/repo|path> fetch it, run it in the honeypot, print everything it did and what it costs the agent
 *   vet-skills try <pkg|pypi:name|owner/repo|path>  fetch it, run it in the honeypot, print everything it did and what it costs the agent
  vet-skills run [--contain] [--deny t,glob*] [--net declared|hosts|off] [--secrets NAME=host,…] -- <cmd…>  guard a stdio MCP server: deny tools, pin its network, broker its secrets, log every call
  vet-skills detonate <path> [--publisher h] upload a local bundle to the sandbox and print its verdict
  vet-skills publish <path>             detonate and publish to your organization's private registry
 *   vet-skills why <skill>                last decision and the rule behind it
 *   vet-skills join <org> --token <t> [--email you@co] [--ci]   enroll this machine (or a CI runner, seat-free) in an org
 *   vet-skills leave                      back to the personal policy
 *   vet-skills policy show|set <file>     view or replace the local policy
 *   vet-skills block <skill> [--reason]   add to the personal block list
 *   vet-skills status                     org, policy version, last report, cache size
 *   vet-skills discover [--project] [--json] every MCP server, skill, plugin and hook configured on this machine
 *   vet-skills mcp                        run as an MCP server so agents can check skills themselves
  vet-skills telemetry on|off|status    anonymous usage + field signals (off for enrolled machines; VET_SKILLS_TELEMETRY=0 also works)
  vet-skills bug                        report a bug (opens the form with your CLI version and last decision filled in)
 *   vet-skills sync                       pull the org policy and apply pending removals
 *   vet-skills verify <skill|path>        check the signed verdict against what is on disk
 *   vet-skills lock                       pin every installed skill's hash + attestation in vet-skills.lock
 *   vet-skills verify --lock              offline: installed skills still match the lock and signatures verify
 *   vet-skills hook install [claude-code|cursor|codex|windsurf|gemini|all]   register the hooks for that agent (all = every one found)
 *   vet-skills hook eval                  (called by the agent) read hook JSON on stdin
  vet-skills runtime [allows|revoke <id>] what installed skills did in real sessions that the sandbox never saw; scoped allows
  vet-skills canary [install|remove]    decoy credential files on this machine; any sighting in a session is proof of exfiltration
 *   vet-skills hook observe               (called by the agent after each tool call) compare behavior with the sandbox trace
 *   vet-skills runtime                    deviations observed in real sessions this week
 */
import { parseArgs } from "node:util";
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { resolve, join, dirname, basename } from "node:path";
import { hostname, platform, userInfo } from "node:os";
import { createHash } from "node:crypto";
import { createInterface } from "node:readline";
import { parsePolicyYaml, serializePolicyYaml } from "./policy/index.js";
import { check, renderCheck, renderOutcome } from "./check.js";
import { enroll, report, detonate, publish, discoverReport, resolveSkill } from "./api.js";
import { discoverLocal } from "./discover.js";
import { fetchTarget, tarDir } from "./try.js";
import { guard, parseRunArgs } from "./run.js";
import { serveMcp } from "./mcp.js";
import { VERSION, API, HOME, readLog, readOrg, readPolicy, readToken, stateSummary, writeOrg, writePolicy, writeToken, appendLog, setTelemetry, telemetryEnabled } from "./state.js";
import { hookEval, installClaudeCodeHook, installCodexHook, installCursorHook } from "./hook.js";
import { cursorHook } from "./cursor.js";
import { geminiHook, installGeminiHook, installWindsurfHook, windsurfHook } from "./agents.js";
import type { AgentKind } from "./policy/index.js";
import { applyRemovals, sync } from "./sync.js";
import { fetchKeys, readLock, verifyLock, verifyOne, writeLock, LOCKFILE } from "./attest.js";
import { observe, pruneSessions, readDeviations, readAllows, recordPrompt, revokeAllow } from "./runtime.js";
import { plantCanaries, readCanaries, removeCanaries } from "./canary.js";
import { homedir } from "node:os";
import { c } from "./render.js";

// `run` owns everything after it (its own flags, then `--` and the server command); the shared parser never sees them.
const RUN_AT = process.argv.indexOf("run", 2);
const { values, positionals } = parseArgs({
  args: RUN_AT === 2 ? ["run"] : process.argv.slice(2),
  allowPositionals: true,
  options: {
    token: { type: "string" }, reason: { type: "string" }, org: { type: "string" }, yes: { type: "boolean", short: "y" }, lock: { type: "boolean" },
    json: { type: "boolean" }, ci: { type: "boolean" }, email: { type: "string" }, help: { type: "boolean", short: "h" }, project: { type: "boolean" }, quiet: { type: "boolean", short: "q" }, version: { type: "boolean", short: "v" }, agent: { type: "string" }, publisher: { type: "string" }, registry: { type: "string" },
  },
});
const [cmd, ...rest] = positionals;

async function ask(question: string, choices: string[]): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) => rl.question(question, (a) => { rl.close(); const k = a.trim().toLowerCase()[0]; res(choices.includes(k) ? k : choices[0]); }));
}

const USAGE = `vet-skills ${VERSION} — check agent skills and MCP servers before they run.

Get started:
  vet-skills hook install [claude-code|cursor|codex|windsurf|gemini|all]   install-time check + runtime observation for that agent (one time)
  vet-skills check <skill>              see the verdict for anything before installing it
  vet-skills join <org> --token <t>     enroll this machine in your team's policy (token from the dashboard)

  vet-skills check <skill>              dry-run the decision
  vet-skills install <skill>            check, then \`npx skills add\`
  vet-skills try <pkg|pypi:name|owner/repo|path>  fetch it, run it in the honeypot, print everything it did and what it costs the agent
  vet-skills detonate <path> [--publisher h] upload a local bundle to the sandbox and print its verdict
  vet-skills publish <path>             detonate and publish to your organization's private registry
  vet-skills why <skill>                last decision and the rule behind it
  vet-skills join <org> --token <t> [--email you@co] [--ci]   enroll this machine (or a CI runner, seat-free) in an org
  vet-skills leave                      back to the personal policy
  vet-skills policy show|set <file>     view or replace the local policy
  vet-skills block <skill> [--reason]   add to the personal block list
  vet-skills status                     org, policy version, last report, cache size
  vet-skills discover [--project] [--json] every MCP server, skill, plugin and hook on this machine, with verdicts
  vet-skills mcp                        run as an MCP server (check_skill, search_skills) for any agent
  vet-skills sync                       pull the org policy and apply pending removals
  vet-skills verify <skill|path>        check the signed verdict against what is on disk
  vet-skills lock                       pin every installed skill's hash + attestation in vet-skills.lock
  vet-skills verify --lock              offline: installed skills still match the lock and signatures verify
  vet-skills hook install [claude-code|cursor|codex|windsurf|gemini|all]   register the hooks for that agent (all = every one found)
  vet-skills hook eval                  (called by the agent) read hook JSON on stdin
  vet-skills runtime [allows|revoke <id>] what installed skills did in real sessions that the sandbox never saw; scoped allows
  vet-skills canary [install|remove]    decoy credential files on this machine; any sighting in a session is proof of exfiltration

Docs: https://killerskills.ai/docs/cli
`;
function usage() { process.stderr.write(USAGE); }

/** A yes/no question on a TTY (default yes; 30 s timeout = yes). Null when there is no terminal to ask. */
async function askYesNo(prompt: string): Promise<boolean | null> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return null;
  process.stdout.write(prompt);
  const answer = await new Promise<string>((res) => { const onData = (b: Buffer) => { process.stdin.off("data", onData); process.stdin.pause(); res(b.toString("utf8").trim()); }; process.stdin.resume(); process.stdin.once("data", onData); setTimeout(() => { process.stdin.off("data", onData); process.stdin.pause(); res(""); }, 30_000).unref(); });
  return !/^n/i.test(answer);
}
/** One question, once: whether this machine sends anonymous field signals. Non-interactive installs keep the default (on, opt-out). */
async function askTelemetry(): Promise<boolean | null> {
  if (existsSync(join(HOME, "telemetry"))) return null;
  return askYesNo("Send anonymous signals when a skill misbehaves (name, version, kind, tool; never content)? [Y/n] ");
}

async function main(): Promise<number> {
  if (values.version) { console.log(VERSION); return 0; }
  if (values.help || !cmd) { usage(); return cmd ? 0 : 1; }

  switch (cmd) {
    case "check": {
      if (!rest[0]) { usage(); return 1; }
      const r = await check(rest[0], { agentKind: values.agent as never, registry: values.registry });
      if (values.json) { console.log(JSON.stringify({ decision: r.decision, resolved: r.resolved, source: r.source, offline: r.offline }, null, 2)); return r.decision.decision === "block" ? 2 : 0; }
      process.stderr.write(renderCheck(r));
      console.log(renderOutcome(r));
      return r.decision.decision === "block" ? 2 : 0;
    }

    case "install": {
      if (!rest[0]) { usage(); return 1; }
      const r = await check(rest[0], { agentKind: values.agent as never });
      process.stderr.write(renderCheck(r));
      let proceed = false;
      let chosen: string | undefined;
      switch (r.decision.decision) {
        case "allow": case "observe": proceed = true; break;
        case "sandbox": proceed = true; chosen = "s"; break;
        case "approval_required": {
          if (values.yes) { chosen = "y"; break; }
          chosen = await ask(`Install anyway? ${c.muted("[y]es · [n]o · [s]andboxed (recommended) · [r]eport")} `, ["s", "y", "n", "r"]);
          if (chosen === "s") proceed = true;
          if (chosen === "y" && !readOrg()) proceed = true; // solo: the developer's call
          if (chosen === "r" && r.resolved) console.log(`https://killerskills.ai${r.resolved.skill.page}/${r.resolved.version.semver}`);
          break;
        }
        case "defer": case "block": proceed = false; break;
      }
      console.log(renderOutcome(r, chosen));
      if (!proceed) return r.decision.decision === "block" ? 2 : 1;
      const run = spawnSync("npx", ["-y", "skills", "add", rest[0]], { stdio: "inherit" });
      if (run.status === 0 && readOrg()) {
        await report({ installed: [{ name: r.resolved?.skill.name ?? rest[0], semver: r.resolved?.version.semver ?? null, artifact_hash: r.resolved?.version.artifact_hash ?? null, restrictions: r.decision.restrictions ?? null }], removed: [], hook_version: VERSION });
      }
      return run.status ?? 1;
    }

    case "run": {
      const parsed = parseRunArgs(process.argv.slice(RUN_AT + 1));
      if ("error" in parsed) { console.error(parsed.error); return 1; }
      return guard(parsed.cmd, parsed.opts);
    }

    case "try": {
      if (!rest[0]) { usage(); return 1; }
      process.stderr.write(`${c.muted("Fetching")} ${rest[0]} …\n`);
      const got = fetchTarget(rest[0]);
      if ("error" in got) { console.log(`${c.blocked("✗")} ${got.error}`); return 1; }
      try {
        const tgz = tarDir(got.dir);
        if (!(tgz instanceof Uint8Array)) { console.log(`${c.blocked("✗")} ${tgz.error}`); return 1; }
        process.stderr.write(`${c.muted("Running")} ${got.label} ${c.muted(`in the honeypot (${(tgz.length / 1024).toFixed(0)} KB; nothing runs on this machine)`)} …\n`);
        const res = await detonate(tgz, { publisher: values.publisher });
        if (!res.ok) { console.log(`${c.caution("!")} Run failed (${res.status ?? "offline"}): ${res.error}`); return 1; }
        const d = res.data;
        const paint = d.verdict.label === "verified" ? c.verified : d.verdict.label === "caution" ? c.caution : c.blocked;
        console.log(`\n${paint(d.verdict.label.toUpperCase())} ${c.bold(String(d.verdict.score))} ${c.muted(`· ${d.skill.name}@${d.skill.semver} · engine ${d.verdict.engine_version} · ${d.verdict.duration_ms} ms`)}`);
        if (d.verdict.overrides.length) console.log(`${c.blocked("overrides")} ${d.verdict.overrides.join(", ")}`);
        if (values.json) { console.log(JSON.stringify(d, null, 2)); return d.verdict.label === "blocked" ? 2 : 0; }
        const ev = (d.trace?.events ?? []).filter((e) => e.severity !== "none" || e.category === "network" || e.category === "filesystem" || e.category === "claimed");
        if (ev.length) {
          console.log(`\n${c.ink2("What it did")} ${c.muted("(t+ms · category · action)")}`);
          for (const e of ev.slice(0, 60)) {
            const tone = e.decoy_hit || e.severity === "critical" ? c.blocked : e.severity === "warn" ? c.caution : c.muted;
            console.log(`  ${String(e.t_ms).padStart(6)}  ${tone(e.category.padEnd(10))} ${e.action.padEnd(9)} ${e.target}${e.detail ? c.muted(`  ${e.detail.slice(0, 110)}`) : ""}${e.decoy_hit ? c.blocked(`  ← decoy ${e.decoy_hit}`) : ""}`);
          }
          if (ev.length > 60) console.log(c.muted(`  … ${ev.length - 60} more events on the verdict page`));
        }
        if (d.trace) {
          const undeclared = d.trace.egress_hosts.filter((h) => !h.declared).map((h) => h.host);
          console.log(`\n${c.ink2("Reached")}   ${undeclared.length ? c.blocked(undeclared.join(", ")) + c.muted(" (undeclared)") : c.muted("no undeclared hosts")}`);
          const cred = d.trace.files_read.filter((p) => /\.ssh|\.aws|\.npmrc|credentials|\.netrc|\.docker/.test(p));
          console.log(`${c.ink2("Read")}      ${cred.length ? c.blocked(cred.join(", ")) : c.muted(`${d.trace.files_read.length} file${d.trace.files_read.length === 1 ? "" : "s"}, no credential paths`)}`);
          if (d.trace.memory_writes.length) console.log(`${c.ink2("Wrote")}     ${c.blocked(d.trace.memory_writes.map((m) => m.file).join(", "))} ${c.muted("(agent memory / instruction files)")}`);
        }
        const b = d.benchmark;
        if (b) {
          console.log(`\n${c.ink2("Cost to your agent")}`);
          console.log(`  instructions loaded   ≈${b.instruction_tokens.toLocaleString("en-US")} tokens ${c.muted(`(${b.instruction_files} file${b.instruction_files === 1 ? "" : "s"}, ${b.bundle_files} in bundle)`)}`);
          if (b.mcp) console.log(`  tool list per prompt  ${b.mcp.tools ? `≈${b.mcp.context_tokens.toLocaleString("en-US")} tokens ${c.muted(`(${b.mcp.tools} tools, ${Math.round(b.mcp.context_tokens / Math.max(1, b.mcp.tools))} per tool${b.mcp.undocumented_tools ? `, ${b.mcp.undocumented_tools} undocumented` : ""})`)}` : c.muted("no tools/list reply")}\n  handshake             ${b.mcp.handshake_ms === null ? c.muted("no reply") : `${b.mcp.handshake_ms} ms`}`);
        }
        const crit = d.findings.filter((f) => f.severity === "critical" || f.severity === "high");
        if (crit.length) { console.log(`\n${c.ink2("Findings")}`); for (const f of crit.slice(0, 8)) console.log(`  ${c.muted(f.rule_id)} ${f.severity.padEnd(8)} ${f.title}`); if (crit.length > 8) console.log(c.muted(`  … ${crit.length - 8} more`)); }
        console.log(`\n${c.muted(`Full trace: ${API}${d.skill.page}`)}`);
        return d.verdict.label === "blocked" ? 2 : 0;
      } finally { got.cleanup(); }
    }

    case "detonate": {
      if (!rest[0]) { usage(); return 1; }
      const dir = resolve(rest[0]);
      if (!existsSync(join(dir, "SKILL.md")) && !existsSync(join(dir, "package.json"))) { console.log(`${c.blocked("✗")} ${dir} has no SKILL.md or package.json`); return 1; }
      const tar = spawnSync("tar", ["--exclude", "node_modules", "--exclude", ".git", "-czf", "-", "-C", dirname(dir), basename(dir)], { maxBuffer: 64 * 1024 * 1024 });
      if (tar.status !== 0) { console.log(`${c.blocked("✗")} tar failed: ${tar.stderr.toString().trim()}`); return 1; }
      process.stderr.write(`${c.muted("Detonating")} ${basename(dir)} ${c.muted(`(${(tar.stdout.length / 1024).toFixed(0)} KB)`)} …\n`);
      const res = await detonate(new Uint8Array(tar.stdout), { publisher: values.publisher });
      if (!res.ok) { console.log(`${c.caution("!")} Detonation failed (${res.status ?? "offline"}): ${res.error}`); return 1; }
      const d = res.data;
      const paint = d.verdict.label === "verified" ? c.verified : d.verdict.label === "caution" ? c.caution : c.blocked;
      console.log(`${paint(d.verdict.label.toUpperCase())} ${c.bold(String(d.verdict.score))} ${c.muted(`· ${d.skill.name}@${d.skill.semver} · engine ${d.verdict.engine_version} · ${d.verdict.duration_ms} ms`)}`);
      console.log(c.muted(`behavior ${d.verdict.components.behavior} · static ${d.verdict.components.static} · prompt ${d.verdict.components.prompt} · publisher ${d.verdict.components.publisher}`));
      if (d.verdict.overrides.length) console.log(`${c.blocked("overrides")} ${d.verdict.overrides.join(", ")}`);
      if (d.trace) {
        const undeclared = d.trace.egress_hosts.filter((h) => !h.declared).map((h) => h.host);
        if (undeclared.length) console.log(`${c.blocked("egress")}    ${undeclared.join(", ")} ${c.muted("(undeclared)")}`);
        if (d.trace.files_read.some((p) => /\.ssh|\.aws|\.npmrc|credentials/.test(p))) console.log(`${c.blocked("reads")}     credential paths`);
        if (d.trace.memory_writes.length) console.log(`${c.blocked("memory")}    writes ${d.trace.memory_writes.map((m) => m.file).join(", ")}`);
      }
      for (const f of d.findings.slice(0, 6)) console.log(`  ${c.muted(f.rule_id)} ${f.severity.padEnd(8)} ${f.title}`);
      if (d.findings.length > 6) console.log(c.muted(`  … ${d.findings.length - 6} more`));
      console.log(c.muted(`${API}${d.skill.page}`));
      return d.verdict.label === "blocked" ? 2 : 0;
    }

    case "publish": {
      if (!rest[0]) { usage(); return 1; }
      const org = readOrg();
      if (!org) { console.log(`${c.blocked("✗")} not enrolled in an organization. Run ${c.bold("vet-skills join <org> --token …")} first.`); return 1; }
      const dir = resolve(rest[0]);
      if (!existsSync(join(dir, "SKILL.md"))) { console.log(`${c.blocked("✗")} ${dir} has no SKILL.md (name and version come from its frontmatter)`); return 1; }
      const tar = spawnSync("tar", ["--exclude", "node_modules", "--exclude", ".git", "-czf", "-", "-C", dirname(dir), basename(dir)], { maxBuffer: 64 * 1024 * 1024 });
      if (tar.status !== 0) { console.log(`${c.blocked("✗")} tar failed: ${tar.stderr.toString().trim()}`); return 1; }
      process.stderr.write(`${c.muted("Publishing")} ${basename(dir)} ${c.muted(`to ${org.slug} (${(tar.stdout.length / 1024).toFixed(0)} KB) — detonating first …`)}\n`);
      const res = await publish(new Uint8Array(tar.stdout));
      if (!res.ok) { console.log(`${c.caution("!")} Publish failed (${res.status ?? "offline"}): ${res.error}`); return 1; }
      const d = res.data;
      const paint = d.verdict.label === "verified" ? c.verified : d.verdict.label === "caution" ? c.caution : c.blocked;
      console.log(`${paint(d.verdict.label.toUpperCase())} ${c.bold(String(d.verdict.score))} ${c.muted(`· ${d.skill.publisher}/${d.skill.name}@${d.skill.semver} · ${d.skill.created ? "published" : "re-detonated (same bytes already published)"} · ${d.verdict.duration_ms} ms`)}`);
      for (const f of d.findings.slice(0, 6)) console.log(`  ${c.muted(f.rule_id)} ${f.severity.padEnd(8)} ${f.title}`);
      if (d.findings.length > 6) console.log(c.muted(`  … ${d.findings.length - 6} more`));
      console.log(c.muted(`${API}/app/${org.slug}/registry  ·  ${API}${d.skill.page}`));
      console.log(c.muted(`Teammates install it with: vet-skills install ${org.slug}/${d.skill.name}`));
      return d.verdict.label === "blocked" ? 2 : 0;
    }

    case "why": {
      const log = readLog().filter((e) => !rest[0] || e.skill === rest[0] || `${e.skill}@${e.semver}` === rest[0]);
      const last = log.at(-1);
      if (!last) { console.log(c.muted(rest[0] ? `No decision recorded for ${rest[0]} in the last 30 days.` : "No decisions recorded yet.")); return 1; }
      console.log(`${c.ink2(`${last.skill}@${last.semver}`)} · ${last.at}`);
      console.log(`decision ${c.bold(last.decision)}${last.wouldBe && last.wouldBe !== last.decision ? c.muted(` (would be ${last.wouldBe})`) : ""} · policy ${last.policy}${last.offline ? c.caution(" · offline") : ""}`);
      console.log(`reason   ${last.reason}`);
      if (last.requestId) console.log(`request  ${last.requestId}`);
      return 0;
    }

    case "join": {
      const slug = rest[0] ?? values.org;
      if (!slug || !values.token) { console.error("usage: vet-skills join <org> --token <enroll token>"); return 1; }
      const machineId = createHash("sha256").update(`${hostname()}:${userInfo().username}`).digest("hex");
      const res = await enroll(slug, values.token, {
        developer_email: values.email, machine_id: machineId, machine_label: hostname(), agent_kind: values.agent ?? "other", hook_version: VERSION, os: platform(),
        installed: [], ci: values.ci === true,
      });
      if (!res.ok) { console.error(`${c.blocked("✕")} Could not join ${slug}: ${res.error}`); return 1; }
      writeToken(res.data.agent_token);
      writeOrg({ slug, agentId: res.data.agent_id, policyVersion: res.data.policy_version, enforcement: res.data.enforcement, joinedAt: new Date().toISOString() });
      writePolicy(res.data.policy_yaml);
      console.log(`${c.verified("✓")} Joined ${res.data.org.name} (${slug}) · policy v${res.data.policy_version} · ${res.data.enforcement} mode`);
      console.log(c.muted("This machine now reports skill names, versions, hashes, and decisions. Never code, prompts, or file contents."));
      return 0;
    }

    case "leave": {
      const org = readOrg();
      writeOrg(null); writeToken(null);
      writePolicy(serializePolicyYaml((await import("./policy/index.js")).SOLO_POLICY));
      console.log(org ? `${c.verified("✓")} Left ${org.slug}. Back to the personal policy.` : c.muted("Not joined to any org."));
      return 0;
    }

    case "policy": {
      const sub = rest[0] ?? "show";
      if (sub === "show") { const { policy, source } = readPolicy(); process.stderr.write(c.muted(`# source: ${source}\n`)); process.stdout.write(serializePolicyYaml(policy)); return 0; }
      if (sub === "set") {
        if (readOrg()) { console.error(`${c.blocked("✕")} This machine is joined to ${readOrg()!.slug}; the org policy is managed in the dashboard.`); return 1; }
        if (!rest[1]) { console.error("usage: vet-skills policy set <file.yaml>"); return 1; }
        const text = readFileSync(rest[1], "utf8");
        parsePolicyYaml(text); // validates
        writePolicy(text);
        console.log(`${c.verified("✓")} Personal policy updated.`);
        return 0;
      }
      usage(); return 1;
    }

    case "block": {
      if (!rest[0]) { usage(); return 1; }
      if (readOrg()) { console.log(c.muted(`Org block-lists are managed in the dashboard: killerskills.ai/app/${readOrg()!.slug}/policy`)); return 1; }
      const { policy } = readPolicy();
      const handle = rest[0].split("@")[0];
      if (!policy.publishers.block.includes(handle)) policy.publishers.block.push(handle);
      writePolicy(policy);
      appendLog({ at: new Date().toISOString(), skill: handle, semver: "*", hash: null, decision: "block", reason: values.reason ?? "blocked by user", policy: policy.name, offline: false });
      console.log(`${c.verified("✓")} ${handle} added to the personal block list${values.reason ? ` (${values.reason})` : ""}.`);
      return 0;
    }

    case "bug": {
      const last = readLog().at(-1);
      const qs = new URLSearchParams({ kind: "bug", source: "cli", cli_version: VERSION, ...(last ? { skill: `${last.skill}@${last.semver}`, decision: last.decision } : {}) });
      const url = `${API}/feedback?${qs}`;
      console.log(`Report a bug: ${url}`);
      const opener = platform() === "darwin" ? "open" : platform() === "win32" ? "start" : "xdg-open";
      spawnSync(opener, [url], { stdio: "ignore", shell: platform() === "win32" });
      return 0;
    }

    case "telemetry": {
      const sub = rest[0] ?? "status";
      if (sub === "on" || sub === "off") { setTelemetry(sub === "on"); console.log(`${c.verified("✓")} telemetry ${sub}`); return 0; }
      console.log(`telemetry ${telemetryEnabled() ? "on" : "off"} ${c.muted(readOrg() ? "(enrolled: decisions report to the org, not here)" : "(anonymous: skill, version, decision, agent type; never code, prompts or paths)")}`);
      return 0;
    }

    case "status": {
      const org = readOrg();
      const { policy, source } = readPolicy();
      const st = stateSummary();
      const last = readLog().at(-1);
      console.log(`vet-skills ${VERSION} · api ${API}`);
      console.log(`org      ${org ? `${org.slug} · agent ${org.agentId} · ${org.enforcement} mode · joined ${org.joinedAt.slice(0, 10)}` : c.muted("none (personal policy)")}`);
      console.log(`policy   ${policy.name} v${policy.version} ${c.muted(`(${source})`)} · min score ${policy.minScore} · caution → ${policy.cautionAction} · unknown → ${policy.unknownAction}`);
      console.log(`token    ${readToken() ? "present" : c.muted("none")}`);
      console.log(`cache    ${st.cacheEntries} verdicts · ${Math.round(st.cacheBytes / 1024)} KB · ${st.home}`);
      console.log(`last     ${last ? `${last.decision} ${last.skill}@${last.semver} · ${last.at}` : c.muted("no decisions yet")}`);
      if (org) {
        const res = await report({ installed: [], removed: [], hook_version: VERSION });
        if (res.ok) {
          if (res.data.policy_version !== org.policyVersion && res.data.policy_yaml) { writePolicy(res.data.policy_yaml); writeOrg({ ...org, policyVersion: res.data.policy_version, enforcement: res.data.enforcement }); console.log(`${c.verified("✓")} Policy updated to v${res.data.policy_version}`); }
          for (const a of res.data.pending_approvals) console.log(`approval ${a.skill} · ${a.status} · ${a.request_id}`);
          if (res.data.pending_removals.length) await applyRemovals(res.data.pending_removals, (l) => console.log(l));
        } else console.log(c.caution(`report failed: ${res.error}`));
      }
      return 0;
    }

    case "verify": {
      if (values.lock) {
        const lock = readLock();
        if (!lock) { console.log(c.caution(`no ${LOCKFILE} in ${process.cwd()}; run \`vet-skills lock\` first`)); return 1; }
        const rs = verifyLock(lock);
        for (const r of rs) console.log(`${r.ok ? c.verified("✓") : c.blocked("✗")} ${r.subject}  ${c.muted(r.detail)}`);
        const bad = rs.filter((r) => !r.ok).length;
        console.log(bad ? c.blocked(`${bad} of ${rs.length} failed`) : c.verified(`${rs.length} skill${rs.length === 1 ? "" : "s"} verified against ${LOCKFILE} (offline, ${lock.keys.length} pinned key${lock.keys.length === 1 ? "" : "s"})`));
        if (values.json) console.log(JSON.stringify(rs, null, 2));
        return bad ? 1 : 0;
      }
      if (!rest[0]) { console.log(c.caution("usage: vet-skills verify <skill>[@version] | <path> | --lock")); return 1; }
      const keys = await fetchKeys();
      if (!keys.length) console.log(c.caution(`could not fetch signing keys from ${API}/.well-known/killerskills-keys.json`));
      const r = await verifyOne(rest[0], keys);
      console.log(`${r.ok ? c.verified("✓ verified") : c.blocked("✗ not verified")} ${r.subject}\n  ${r.detail}`);
      if (values.json) console.log(JSON.stringify(r, null, 2));
      return r.ok ? 0 : 1;
    }

    case "lock": {
      const { file, lock, missing } = await writeLock();
      console.log(`${c.verified("✓")} wrote ${file}: ${lock.skills.length} skill${lock.skills.length === 1 ? "" : "s"}, ${lock.keys.length} signing key${lock.keys.length === 1 ? "" : "s"} pinned`);
      for (const s of lock.skills) console.log(`  ${s.attestation ? c.verified("✓") : c.caution("·")} ${s.name}  ${c.muted(s.verdict ? `${s.verdict.label} ${s.verdict.score}` : "no attestation (unscored or never crawled)")}`);
      if (missing.length) console.log(c.muted(`${missing.length} without an attestation are pinned by hash only; \`vet-skills verify --lock\` reports them.`));
      return 0;
    }

    case "canary": {
      const sub = rest[0] ?? "status";
      if (sub === "install" || sub === "plant") {
        const r = plantCanaries();
        for (const x of r.planted) console.log(`  ${x.path.replace(homedir(), "~")}  ${c.muted(x.kind.replace(/_/g, " "))}`);
        console.log(r.planted.length ? `${c.verified("✓")} ${r.planted.length} canary credential${r.planted.length === 1 ? "" : "s"} planted. They look like forgotten backups; nothing real reads them. If one ever shows up in what a skill sends or returns, the hook stops the session and tells you.` : c.muted("Nothing new to plant: every canary path already exists."));
        if (r.skipped.length) console.log(c.muted(`skipped (path already exists): ${r.skipped.map((p) => p.replace(homedir(), "~")).join(", ")}`));
        return 0;
      }
      if (sub === "remove") { const r = removeCanaries(); console.log(`${c.verified("✓")} ${r.removed} canary file${r.removed === 1 ? "" : "s"} removed`); return 0; }
      const reg = readCanaries();
      if (!reg?.canaries.length) { console.log(c.muted("No canary credentials on this machine. vet-skills canary install plants decoy credential files that only a thief would read; the hook turns any sighting into proof of exfiltration.")); return 0; }
      for (const x of reg.canaries) console.log(`${existsSync(x.path) ? c.verified("✓") : c.caution("!")} ${x.path.replace(homedir(), "~")}  ${c.muted(`${x.kind.replace(/_/g, " ")} · planted ${x.plantedAt.slice(0, 10)}${existsSync(x.path) ? "" : " · file missing"}`)}`);
      const hits = readDeviations(30).filter((d) => d.kind === "canary_exfil");
      console.log(hits.length ? `${c.blocked("✕")} ${hits.length} sighting${hits.length === 1 ? "" : "s"} in 30 days: ${hits.slice(-3).map((d) => `${d.at.slice(0, 16).replace("T", " ")} ${d.skill} ${d.detail}`).join("; ")}` : c.muted("No sighting in 30 days."));
      if (values.json) console.log(JSON.stringify({ canaries: reg.canaries.map((x) => ({ path: x.path, kind: x.kind, plantedAt: x.plantedAt, present: existsSync(x.path) })), sightings: hits }, null, 2));
      return 0;
    }

    case "runtime": {
      if (rest[0] === "allows" || rest[0] === "revoke") {
        if (rest[0] === "revoke") { const ok = rest[1] ? revokeAllow(rest[1]) : false; console.log(ok ? `${c.verified("✓")} allow ${rest[1]} revoked` : `no allow matches ${rest[1] ?? "(missing id)"}`); return ok ? 0 : 1; }
        const now = Date.now(); const all = readAllows().filter((a) => Date.parse(a.at) > now - 7 * 86_400_000);
        if (!all.length) { console.log(c.muted("No scoped allows in the last 7 days. A sensitive action is allowed only when your own actions this session explain it; each allow is scoped to (session, skill, resource) for 30 minutes.")); return 0; }
        for (const a of all) { const state = a.revoked ? c.muted("revoked") : Date.parse(a.expires) > now ? c.verified("active") : c.muted("expired"); console.log(`${c.ink2(a.id)}  ${a.at.slice(0, 16).replace("T", " ")}  ${state}  ${a.skill}  ${a.kind.replace(/_/g, " ")}  ${a.resource}  ${c.muted(a.reason)}`); }
        if (values.json) console.log(JSON.stringify(all, null, 2));
        return 0;
      }
      const ds = readDeviations(7);
      if (!ds.length) { console.log(c.muted("No deviations in the last 7 days: installed skills behaved the way the sandbox saw them (or no skill ran).")); return 0; }
      const by = new Map<string, typeof ds>();
      for (const d of ds) by.set(d.skill, [...(by.get(d.skill) ?? []), d]);
      for (const [skill, list] of by) {
        console.log(`${c.caution("⚠")} ${skill}${list[0].semver ? `@${list[0].semver}` : ""}  ${c.muted(`${list.length} deviation${list.length === 1 ? "" : "s"}${list[0].page ? ` · killerskills.ai${list[0].page}` : ""}`)}`);
        for (const d of list.slice(-6)) console.log(`   ${d.at.slice(0, 16).replace("T", " ")}  ${d.kind.replace("_", " ")}  ${d.detail}`);
      }
      if (values.json) console.log(JSON.stringify(ds, null, 2));
      return 0;
    }

    case "discover": {
      const comps = discoverLocal({ project: values.project ? process.cwd() : undefined });
      if (values.json) { console.log(JSON.stringify(comps, null, 2)); }
      else if (!values.quiet) {
        if (!comps.length) console.log(c.muted("No agent configuration found in the usual places (~/.claude.json, ~/.cursor/mcp.json, Claude Desktop, Windsurf, Gemini CLI, Codex, ~/.claude/skills)."));
        const runnable = comps.filter((x) => x.kind === "mcp_server" || x.kind === "skill");
        const verdicts = new Map<string, string>();
        await Promise.all(runnable.slice(0, 40).map(async (x) => {
          const q = x.package ? x.package.name.replace(/^@/, "") : x.name;
          const r = await resolveSkill(q, x.package?.registry);
          const v = r.ok ? r.data.verdict : null;
          verdicts.set(`${x.kind}|${x.name}`, v?.label ? `${v.label} ${v.score ?? ""}`.trim() : "not vetted");
        }));
        const lures = comps.filter((x) => x.kind === "lure"), secrets = comps.filter((x) => x.kind === "secret"), hidden = comps.filter((x) => x.kind === "instructions" && / \(hidden text\)$/.test(x.name));
        if (hidden.length) {
          console.log(`\n${c.blocked("✗ Hidden instructions")} in ${hidden.length} file${hidden.length === 1 ? "" : "s"} the agent reads (text you would not see, but the model does):`);
          for (const x of hidden) console.log(`  ${c.caution(x.path)}\n    ${c.muted((x.detail ?? "").split("; ").join("\n    "))}`);
        }
        if (lures.length) {
          console.log(`\n${c.blocked("✗ Installer lure")} in ${lures.length} installed skill folder${lures.length === 1 ? "" : "s"}. Do not run anything from these; remove the folder and, if you ran an installer from it, treat the machine as compromised.`);
          for (const x of lures) console.log(`  ${c.blocked(x.path)}\n    ${c.muted((x.detail ?? "").split("; ").join("\n    "))}`);
        }
        if (secrets.length) {
          console.log(`\n${c.blocked("✗ Credential values")} pasted into ${secrets.length} config file${secrets.length === 1 ? "" : "s"} (rotate them, then use an environment reference such as \${GITHUB_TOKEN}):`);
          for (const x of secrets) console.log(`  ${c.caution(x.path)}  ${c.muted(x.detail ?? "")}`);
        }
        const kinds: [string, string][] = [["mcp_server", "MCP servers"], ["skill", "Skills"], ["plugin", "Plugins"], ["hook", "Hooks"], ["instructions", "Instruction files"]];
        for (const [k, label] of kinds) {
          const list = comps.filter((x) => x.kind === k);
          if (!list.length) continue;
          console.log(`\n${label} (${list.length})`);
          for (const x of list) {
            const v = verdicts.get(`${x.kind}|${x.name}`);
            const tone = !v ? c.muted : v.startsWith("verified") ? c.verified : v.startsWith("blocked") ? c.blocked : c.caution;
            const what = x.package ? `${x.package.registry}:${x.package.name}` : x.urlHost ?? x.command ?? x.detail ?? "";
            const keys = x.envKeys.length || x.headerKeys.length ? c.muted(` · ${[...x.envKeys, ...x.headerKeys].slice(0, 4).join(", ")}`) : "";
            console.log(`  ${x.name.padEnd(28)} ${tone((v ?? "").padEnd(14))} ${c.muted(what)}${keys}  ${c.muted(x.path)}`);
          }
        }
      }
      if (readOrg()) {
        const r = await discoverReport(comps);
        if (r.ok) { if (!values.json) console.log(`\n${c.verified("✓")} ${r.data.components} component${r.data.components === 1 ? "" : "s"} reported to ${readOrg()!.slug} (names only) · ${API}${r.data.dashboard}`); }
        else { console.error(c.caution(`report failed: ${r.error}`)); return 1; }
      } else if (!values.json && !values.quiet) console.log(c.muted("\nNot enrolled: only the names above were looked up for their verdicts; no inventory was reported. `vet-skills join <org> --token <t>` reports it to your team's Discovery page."));
      return 0;
    }

    case "mcp": {
      await serveMcp();
      return 0;
    }

    case "sync": {
      if (!readOrg()) { console.log(c.muted("Not joined to an org; nothing to sync.")); return 0; }
      const r = await sync((l) => console.log(l));
      if (!r.ok) { console.log(c.caution(`sync failed: ${r.error}`)); return 1; }
      console.log(`${c.verified("✓")} in sync · ${r.removed} removal${r.removed === 1 ? "" : "s"} applied`);
      return 0;
    }

    case "hook": {
      const sub = rest[0];
      const agentFlag = (rest.includes("--agent") ? rest[rest.indexOf("--agent") + 1] : "claude_code") as AgentKind;
      if (sub === "eval") {
        const chunks: Buffer[] = [];
        for await (const ch of process.stdin) chunks.push(ch as Buffer);
        return hookEval(Buffer.concat(chunks).toString("utf8"), agentFlag);
      }
      if (sub === "cursor") {
        const chunks: Buffer[] = [];
        for await (const ch of process.stdin) chunks.push(ch as Buffer);
        const reply = await cursorHook(Buffer.concat(chunks).toString("utf8")).catch(() => ({}));
        process.stdout.write(JSON.stringify(reply) + "\n");
        if (Math.random() < 0.02) pruneSessions();
        return 0;
      }
      if (sub === "windsurf" || sub === "gemini") {
        const chunks: Buffer[] = [];
        for await (const ch of process.stdin) chunks.push(ch as Buffer);
        const r = await (sub === "windsurf" ? windsurfHook : geminiHook)(Buffer.concat(chunks).toString("utf8")).catch(() => ({ code: 0, stderr: "" }));
        if (r.stderr) process.stderr.write(r.stderr + "\n");
        if (Math.random() < 0.02) pruneSessions();
        return r.code;
      }
      if (sub === "observe") {
        const chunks: Buffer[] = [];
        for await (const ch of process.stdin) chunks.push(ch as Buffer);
        try {
          const r = await observe(Buffer.concat(chunks).toString("utf8"), { agent: agentFlag });
          for (const l of r.lines) process.stderr.write(l + "\n");
          if (Math.random() < 0.02) pruneSessions();
          return r.code;
        } catch { return 0; } // observation never breaks the agent
      }
      if (sub === "prompt") {
        const chunks: Buffer[] = [];
        for await (const ch of process.stdin) chunks.push(ch as Buffer);
        try { recordPrompt(Buffer.concat(chunks).toString("utf8")); } catch { /* never breaks the agent */ }
        return 0;
      }
      if (sub === "install") {
        const target = rest[1] ?? "claude-code";
        const targets = target === "all" ? ["claude-code", "cursor", "codex", "windsurf", "gemini"] : [target];
        for (const tg of targets) {
          if (tg === "claude-code") { const r = installClaudeCodeHook(); console.log(r.changed ? `${c.verified("✓")} Claude Code hook installed in ${r.path}` : c.muted(`Claude Code hook already present in ${r.path}`)); }
          else if (tg === "cursor") { const r = installCursorHook(); console.log(r.changed ? `${c.verified("✓")} Cursor hooks installed in ${r.path} (restart Cursor once)` : c.muted(`Cursor hooks already present in ${r.path}`)); }
          else if (tg === "codex") { const r = installCodexHook(); console.log(r.changed ? `${c.verified("✓")} Codex CLI hooks installed in ${r.path}` : c.muted(`Codex hooks already present in ${r.path}`)); }
          else if (tg === "windsurf") { const r = installWindsurfHook(); console.log(r.changed ? `${c.verified("✓")} Windsurf (Cascade) hooks installed in ${r.path}` : c.muted(`Windsurf hooks already present in ${r.path}`)); }
          else if (tg === "gemini") { const r = installGeminiHook(); console.log(r.changed ? `${c.verified("✓")} Gemini CLI hooks installed in ${r.path}` : c.muted(`Gemini CLI hooks already present in ${r.path}`)); }
          else { console.error(`Unknown agent ${tg}. Supported: claude-code, cursor, codex, windsurf, gemini, all.`); return 1; }
        }
        console.log(c.muted("Every install the agent makes (skills add, claude mcp add, npx …) is checked before it runs, what skills and MCP servers do in sessions is compared with their sandbox trace (vet-skills runtime), and a planted canary credential leaving the machine stops the session."));
        if (!readCanaries()?.canaries.length) {
          const yes = await askYesNo("Plant decoy credential files so the hook can prove exfiltration (vet-skills canary)? [Y/n] ");
          if (yes) { const r = plantCanaries(); console.log(c.muted(`${r.planted.length} canary credential${r.planted.length === 1 ? "" : "s"} planted (vet-skills canary to list or remove).`)); }
          else if (yes === false) console.log(c.muted("Skipped. Later: vet-skills canary install"));
        }
        if (!readOrg()) {
          const choice = await askTelemetry();
          if (choice !== null) setTelemetry(choice);
          console.log(c.muted(telemetryEnabled()
            ? "Anonymous signals on: when the hook sees a skill misbehave, it sends the skill name, version, kind of deviation and tool name (never content, hosts, paths or prompts) so the package is re-run in the honeypot for everyone. Schema: https://killerskills.ai/docs/cli#telemetry · off: vet-skills telemetry off"
            : "Anonymous signals off. Turn on: vet-skills telemetry on"));
        }
        return 0;
      }
      usage(); return 1;
    }

    default:
      console.error(`unknown command: ${cmd}`);
      usage();
      return 1;
  }
}

main().then((code) => process.exit(code), (e) => { console.error(e instanceof Error ? e.message : e); process.exit(1); });
