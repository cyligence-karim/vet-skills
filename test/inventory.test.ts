import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverLocal } from "../src/discover.ts";
import { buildInventory, componentsForSync, nextStep, renderInventory, renderReach } from "../src/inventory.ts";

const DECOY_GH = "ghp_" + "Kd9".repeat(12);
const DECOY_HEADER = "sk-decoy-" + "x7".repeat(20);

/** Three agents, six servers: stdio and remote, guarded and not, pinned and not, one with a pasted token. */
function machine() {
  const home = mkdtempSync(join(tmpdir(), "vs-inv-"));
  mkdirSync(join(home, ".cursor"), { recursive: true });
  mkdirSync(join(home, ".codex"), { recursive: true });
  mkdirSync(join(home, ".claude/skills/pdf-tools"), { recursive: true });
  writeFileSync(join(home, ".claude/skills/pdf-tools/SKILL.md"), "---\nname: pdf-tools\n---\n# pdf tools\n");
  const claude = { mcpServers: {
    github: { command: "/usr/local/bin/vet-skills", args: ["guard", "exec", "--server", "github", "--client", "claude-code", "--", "npx", "-y", "@modelcontextprotocol/server-github@2025.4.8"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: DECOY_GH } },
    supabase: { command: "npx", args: ["-y", "@supabase/mcp-server-supabase"], env: { SUPABASE_ACCESS_TOKEN: "${SUPABASE_ACCESS_TOKEN}" } },
    linear: { type: "sse", url: "https://mcp.linear.app/sse", headers: { Authorization: `Bearer ${DECOY_HEADER}` } },
  } };
  writeFileSync(join(home, ".claude.json"), JSON.stringify(claude));
  writeFileSync(join(home, ".cursor/mcp.json"), JSON.stringify({ mcpServers: {
    notion: { url: "https://mcp.notion.com/mcp" },
    local: { command: "node", args: ["/Users/dev/tools/server.js"] },
  } }));
  writeFileSync(join(home, ".codex/config.toml"), `[mcp_servers.fetch]\ncommand = "/usr/local/bin/vet-skills"\nargs = ["guard", "exec", "--server", "fetch", "--client", "codex", "--", "uvx", "mcp-server-fetch==1.2.0"]\n`);
  return home;
}

const lookup = async (q: string) => {
  if (q === "@modelcontextprotocol/server-github@2025.4.8") return { label: "verified" as const, version: "2025.4.8", page: "/skills/npm/server-github/2025.4.8" };
  if (q === "@supabase/mcp-server-supabase") return { label: "caution" as const, version: "0.16.1", page: "/skills/npm/mcp-server-supabase/0.16.1" };
  return null;
};

test("inventory lists every server of every agent with its transport and guarded status", async () => {
  const home = machine();
  const before = readFileSync(join(home, ".claude.json"), "utf8");
  const inv = await buildInventory({ home, lookup, pins: {}, probeVersions: false });
  assert.deepEqual(inv.agents.map((a) => a.agent), ["claude_code", "cursor", "codex"]);
  const all = inv.agents.flatMap((a) => a.servers);
  assert.equal(all.length, 6);
  const by = Object.fromEntries(all.map((s) => [s.name, s]));
  assert.deepEqual([by.github.transport, by.github.guarded, by.github.version, by.github.versionSource], ["stdio", true, "2025.4.8", "config"]);
  assert.deepEqual([by.supabase.transport, by.supabase.guarded, by.supabase.version], ["stdio", false, null]);
  assert.deepEqual([by.linear.transport, by.linear.guarded, by.linear.target], ["sse", false, "mcp.linear.app"]);
  assert.deepEqual([by.notion.transport, by.notion.target], ["http", "mcp.notion.com"]);
  assert.deepEqual([by.local.transport, by.local.guarded, by.local.package], ["stdio", false, null]);
  assert.deepEqual([by.fetch.transport, by.fetch.guarded, by.fetch.package, by.fetch.version], ["stdio", true, { registry: "pypi", name: "mcp-server-fetch" }, "1.2.0"]);
  // Verdicts: exact for a pinned version, "latest" when nothing says which version runs, none when the pinned version is unknown.
  assert.deepEqual(by.github.verdict, { label: "verified", version: "2025.4.8", page: "/skills/npm/server-github/2025.4.8", exact: true });
  assert.equal(by.supabase.verdict?.exact, false);
  assert.equal(by.fetch.verdict, null);
  assert.match(by.fetch.fixes.join("\n"), /no verdict for 1\.2\.0: run `vet-skills try mcp-server-fetch@1\.2\.0`/);
  assert.match(by.supabase.fixes.join("\n"), /run `vet-skills guard install`/);
  assert.match(by.linear.fixes.join("\n"), /remote server/);
  assert.deepEqual(by.github.plaintext, ["GITHUB_PERSONAL_ACCESS_TOKEN"]);
  assert.deepEqual(by.supabase.plaintext, [], "a ${REFERENCE} is not a value in the file");
  assert.deepEqual(by.linear.plaintext, ["Authorization"], "a literal bearer header counts even when no pattern knows the token");
  assert.deepEqual(inv.totals, { agents: 3, servers: 6, guarded: 2, not_guarded: 2, remote: 2, no_verdict: 1, blocked: 0, plaintext: 2, skills: 1 });
  assert.equal(inv.agents[0].skills[0].name, "pdf-tools");
  // Reach: each credential name, and every server handed it. Non-credential names (none here) are left out.
  assert.deepEqual(inv.credentials.map((k) => [k.name, k.uses.map((u) => `${u.agent}/${u.server}/${u.guarded ? "guarded" : "open"}${u.plaintext ? "/plaintext" : ""}`)]), [["Authorization", ["Claude Code/linear/open/plaintext"]], ["GITHUB_PERSONAL_ACCESS_TOKEN", ["Claude Code/github/guarded/plaintext"]], ["SUPABASE_ACCESS_TOKEN", ["Claude Code/supabase/open"]]]);
  assert.match(renderReach(inv), /GITHUB_PERSONAL_ACCESS_TOKEN/); assert.ok(!renderReach(inv).includes(DECOY_GH));
  assert.match(nextStep(inv), /vet-skills secrets migrate/);
  assert.equal(readFileSync(join(home, ".claude.json"), "utf8"), before, "read-only: the config is untouched");
});

test("no credential value appears in the table, the JSON or the sync payload", async () => {
  const home = machine();
  const comps = discoverLocal({ home });
  const inv = await buildInventory({ components: comps, lookup, pins: {}, probeVersions: false });
  const everything = [renderInventory(inv), JSON.stringify(inv), JSON.stringify(componentsForSync(comps, {}))].join("\n");
  for (const secret of [DECOY_GH, DECOY_HEADER, "/Users/dev/tools/server.js"]) assert.ok(!everything.includes(secret), `leaked ${secret.slice(0, 8)}`);
  assert.match(everything, /GITHUB_PERSONAL_ACCESS_TOKEN/);
  assert.match(everything, /Authorization/);
});

test("the version the guard last launched fills in for an unpinned package, in the table and in what is synced", async () => {
  const home = machine();
  const pins = { "npm:@supabase/mcp-server-supabase": { semver: "0.15.0" } };
  const seen: string[] = [];
  const inv = await buildInventory({ home, pins, probeVersions: false, lookup: async (q) => { seen.push(q); return q.endsWith("@0.15.0") ? { label: "verified" as const, version: "0.15.0", page: "/p" } : null; } });
  const supa = inv.agents[0].servers.find((s) => s.name === "supabase")!;
  assert.deepEqual([supa.version, supa.versionSource, supa.verdict?.exact], ["0.15.0", "last run", true]);
  assert.ok(seen.includes("@supabase/mcp-server-supabase@0.15.0"));
  const synced = componentsForSync(discoverLocal({ home }), pins).find((x) => x.name === "supabase")!;
  assert.equal(synced.package?.version, "0.15.0");
});

test("an empty machine gets a next step, not an empty table", async () => {
  const inv = await buildInventory({ components: [], lookup, pins: {}, probeVersions: false });
  assert.match(renderInventory(inv), /Nothing is configured yet/);
});

test("skills in other agents' directories are listed under the agent that reads them", async () => {
  const home = mkdtempSync(join(tmpdir(), "vs-inv-skills-"));
  const proj = mkdtempSync(join(tmpdir(), "vs-inv-proj-"));
  const put = (root: string, rel: string, name: string) => { mkdirSync(join(root, rel, name), { recursive: true }); writeFileSync(join(root, rel, name, "SKILL.md"), `---\nname: ${name}\ndescription: test\n---\n# ${name}\n`); };
  put(home, ".claude/skills", "pdf-tools"); put(home, ".agents/skills", "release-notes"); put(home, ".cursor/skills", "refactor"); put(home, ".gemini/skills", "triage");
  put(home, ".config/opencode/skills", "db-migrate"); put(home, ".codeium/windsurf/skills", "ui-review"); put(proj, ".kiro/skills", "spec-writer"); put(proj, ".agents/skills", "release-notes");
  const inv = await buildInventory({ home, project: proj, lookup: async (q) => (q === "pdf-tools" ? { label: "verified" as const, version: "1.0.0", page: "/p" } : null), pins: {}, probeVersions: false });
  const by = Object.fromEntries(inv.agents.map((a) => [a.agent, a.skills.map((s) => `${s.name}:${s.scope}:${s.verdict?.label ?? "none"}`)]));
  assert.deepEqual(by, {
    claude_code: ["pdf-tools:user:verified"], cursor: ["refactor:user:none"], windsurf: ["ui-review:user:none"], gemini_cli: ["triage:user:none"],
    kiro: ["spec-writer:project:none"], opencode: ["db-migrate:user:none"], shared_skills: ["release-notes:user:none", "release-notes:project:none"],
  });
  assert.equal(inv.totals.skills, 8);
  assert.match(renderInventory(inv), /Shared skills \(\.agents\/skills: Codex CLI, Cursor, Gemini CLI, Copilot, OpenCode, Cline, Amp, Zed\)/);
});
