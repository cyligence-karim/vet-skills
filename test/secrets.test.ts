import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const home = mkdtempSync(join(tmpdir(), "vs-secrets-home-"));
const vsHome = join(home, ".vet-skills");
process.env.VET_SKILLS_HOME = vsHome;
process.env.VET_SKILLS_BIN = "/opt/vet-skills/bin/vet-skills";
process.env.VET_SKILLS_STORE = "file";
const { SecretStore, resolveStoreRefs } = await import("../src/store.ts");
const { planMigration, applyMigration, prove, rewriteTomlEnv } = await import("../src/secrets.ts");
const { uninstallGuard } = await import("../src/guard.ts");
const { buildInventory } = await import("../src/inventory.ts");

const GH = "ghp_" + "Kd9".repeat(12);
const SENTRY = "sntrys_" + "a1B2".repeat(10);
const LINEAR = "lin_api_" + "Zq7".repeat(12);
const SHELL = "sk-" + "s3cr3t".repeat(6);
const all = [GH, SENTRY, LINEAR, SHELL];
const claudeCfg = join(home, ".claude.json"); const codexCfg = join(home, ".codex", "config.toml"); const cursorCfg = join(home, ".cursor", "mcp.json");
const allFiles = (dir: string): string[] => readdirSync(dir, { recursive: true, withFileTypes: true }).filter((f) => f.isFile()).map((f) => join(f.parentPath, f.name));

/** Three plaintext keys across two agents (the PRD's acceptance case), plus one referenced from the shell and one remote header. */
function machine() {
  mkdirSync(join(home, ".codex"), { recursive: true }); mkdirSync(join(home, ".cursor"), { recursive: true });
  writeFileSync(claudeCfg, JSON.stringify({ numStartups: 4, mcpServers: {
    github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: GH, GITHUB_HOST: "github.com" } },
    openai: { command: "npx", args: ["-y", "some-openai-mcp"], env: { OPENAI_API_KEY: "${OPENAI_API_KEY}" } },
    fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] },
  } }, null, 2));
  writeFileSync(codexCfg, `model = "o3"\n\n[mcp_servers.sentry]\ncommand = "npx"\nargs = ["-y", "@sentry/mcp-server"]\nenv = { SENTRY_AUTH_TOKEN = "${SENTRY}", SENTRY_HOST = "sentry.io" }\n\n[other]\nx = 1\n`);
  writeFileSync(cursorCfg, JSON.stringify({ mcpServers: { linear: { type: "http", url: "https://mcp.example.com/mcp", headers: { Authorization: `Bearer ${LINEAR}` } } } }, null, 2));
}

test("the store: values are read back, listed by name only, and the file backend keeps nothing in the clear", () => {
  const s = new SecretStore();
  assert.deepEqual(s.set("t/one/TOKEN", "v-123456789"), { ok: true, backend: "file" });
  assert.equal(s.get("t/one/TOKEN"), "v-123456789");
  assert.deepEqual(s.list().map((x) => [x.key, x.backend]), [["t/one/TOKEN", "file"]]);
  assert.ok(!readFileSync(join(vsHome, "guard", "secrets.json"), "utf8").includes("v-123456789"));
  const env: NodeJS.ProcessEnv = { A: "vs-store://t/one/TOKEN", B: "vs-store://t/none/X", C: "plain" };
  assert.deepEqual(resolveStoreRefs(env, s), { resolved: ["A"], missing: ["B"] });
  assert.deepEqual([env.A, env.B, env.C], ["v-123456789", undefined, "plain"]);
  assert.equal(s.delete("t/one/TOKEN"), true); assert.equal(s.get("t/one/TOKEN"), null);
  assert.equal(s.set("bad key", "x").ok, false);
  // A backend whose read-back does not match is not trusted: the value goes to the file backend instead.
  const calls: string[] = [];
  const flaky = new SecretStore({ dir: join(home, "flaky"), backend: "keychain", os: "darwin", exec: (cmd, args, input) => { calls.push(`${cmd} ${args.join(" ")}`); assert.ok(!args.join(" ").includes("hunter2-hunter2"), "the value is never in argv"); return args[0] === "-i" ? { status: 0, stdout: "", stderr: "" } : { status: 0, stdout: "something else\n", stderr: "" }; } });
  assert.deepEqual(flaky.set("k/a/B", "hunter2-hunter2"), { ok: true, backend: "file" });
  assert.ok(calls.some((c) => c.startsWith("/usr/bin/security -i")) && calls.some((c) => c.includes("find-generic-password")) && calls.some((c) => c.includes("delete-generic-password")));
  const good = new Map<string, string>();
  const kc = new SecretStore({ dir: join(home, "kc"), backend: "keychain", os: "darwin", exec: (_c, args, input) => { if (args[0] === "-i") { const m = input!.match(/-a "([^"]+)" .* -w "(.*)"\n$/)!; good.set(m[1], m[2]); return { status: 0, stdout: "", stderr: "" }; } if (args[0] === "find-generic-password") { const v = good.get(args[4]); return { status: v === undefined ? 44 : 0, stdout: v === undefined ? "" : `${v}\n`, stderr: "" }; } return { status: 0, stdout: "", stderr: "" }; } });
  assert.deepEqual(kc.set("k/a/B", "hunter2-hunter2"), { ok: true, backend: "keychain" });
  assert.equal(kc.get("k/a/B"), "hunter2-hunter2");
  assert.ok(!readFileSync(join(home, "kc", "secrets.json"), "utf8").includes("hunter2"), "the keychain backend keeps only the name in the index");
});

test("migrate then prove: three plaintext keys across two agents end with prove passing and every config still valid", () => {
  machine();
  const env = { OPENAI_API_KEY: SHELL } as NodeJS.ProcessEnv;
  const before = prove({ home, processes: [] });
  assert.equal(before.pass, false);
  assert.deepEqual(before.findings.map((f) => `${f.server}/${f.name}`).sort(), ["github/GITHUB_PERSONAL_ACCESS_TOKEN", "linear/Authorization", "sentry/SENTRY_AUTH_TOKEN"]);
  const plan = planMigration({ home, env });
  assert.deepEqual(plan.candidates.map((c) => `${c.client}/${c.server}/${c.name}:${c.from}`).sort(), ["claude-code/github/GITHUB_PERSONAL_ACCESS_TOKEN:env", "claude-code/openai/OPENAI_API_KEY:environment", "codex/sentry/SENTRY_AUTH_TOKEN:env", "cursor/linear/Authorization:header"]);
  assert.equal(plan.toGuard, 5);
  assert.ok(readFileSync(claudeCfg, "utf8").includes(GH), "planning writes nothing");
  assert.equal(new SecretStore().list().length, 0);

  const r = applyMigration({ home, env });
  assert.deepEqual([r.moved, r.guarded, r.failed], [4, 5, []]);
  const claude = JSON.parse(readFileSync(claudeCfg, "utf8"));
  assert.equal(claude.numStartups, 4, "the rest of the config is untouched");
  assert.deepEqual(claude.mcpServers.github.env, { GITHUB_PERSONAL_ACCESS_TOKEN: "vs-store://claude-code/github/GITHUB_PERSONAL_ACCESS_TOKEN", GITHUB_HOST: "github.com" });
  assert.equal(claude.mcpServers.openai.env.OPENAI_API_KEY, "vs-store://claude-code/openai/OPENAI_API_KEY");
  assert.deepEqual(claude.mcpServers.github.args.slice(0, 2), ["guard", "exec"], "a server holding a reference is under the guard");
  const toml = readFileSync(codexCfg, "utf8");
  assert.match(toml, /env = \{ SENTRY_AUTH_TOKEN = "vs-store:\/\/codex\/sentry\/SENTRY_AUTH_TOKEN", SENTRY_HOST = "sentry\.io" \}/);
  assert.match(toml, /\[other\]\nx = 1/);
  const store = new SecretStore();
  assert.deepEqual([store.get("claude-code/github/GITHUB_PERSONAL_ACCESS_TOKEN"), store.get("codex/sentry/SENTRY_AUTH_TOKEN"), store.get("cursor/linear/Authorization"), store.get("claude-code/openai/OPENAI_API_KEY")], [GH, SENTRY, `Bearer ${LINEAR}`, SHELL]);
  // No value is left in any config or in anything the guard wrote, backups included.
  for (const f of [claudeCfg, codexCfg, cursorCfg, ...allFiles(vsHome)]) { const text = readFileSync(f, "utf8"); for (const v of all) assert.ok(!text.includes(v), `${f} still holds a value`); }
  assert.ok(allFiles(join(vsHome, "guard", "backup")).length >= 3, "backups are kept");

  const after = prove({ home, processes: [{ pid: 4242, name: "claude", env: "PATH=/usr/bin\nTERM=xterm" }] });
  assert.deepEqual([after.pass, after.findings], [true, []]);
  assert.deepEqual([after.checked.configs, after.checked.servers, after.checked.processes, after.checked.stored], [3, 5, 1, 4]);
  assert.equal(planMigration({ home, env: {} }).candidates.length, 0, "nothing left to move");
});

test("prove names exactly where a value still lives: an agent's environment, a stale backup, a dangling reference", () => {
  const p = prove({ home, processes: [{ pid: 7, name: "claude", env: `PATH=/usr/bin\nOPENAI_API_KEY=${SHELL}\nGITHUB_PERSONAL_ACCESS_TOKEN=some-other-long-token` }] });
  assert.equal(p.pass, false);
  assert.deepEqual(p.findings.map((f) => [f.where, f.name]).sort(), [["process", "GITHUB_PERSONAL_ACCESS_TOKEN"], ["process", "OPENAI_API_KEY"]]);
  assert.ok(!JSON.stringify(p).includes(SHELL) && !JSON.stringify(p).includes("some-other-long-token"), "a finding never carries the value");
  writeFileSync(join(vsHome, "guard", "backup", "old-0.bak"), JSON.stringify({ mcpServers: { x: { command: "npx", env: { STRIPE_SECRET_KEY: "sk_live_" + "9".repeat(24) } } } }));
  new SecretStore().delete("codex/sentry/SENTRY_AUTH_TOKEN");
  const q = prove({ home, processes: [] });
  assert.deepEqual(q.findings.map((f) => [f.where, f.name, /not in the guard's store|old config backup/.test(f.detail)]).sort(), [["config", "SENTRY_AUTH_TOKEN", true], ["guard files", "STRIPE_SECRET_KEY", true]]);
  new SecretStore().set("codex/sentry/SENTRY_AUTH_TOKEN", SENTRY);
  rmSync(join(vsHome, "guard", "backup", "old-0.bak"));
});

test("inventory no longer reports migrated credentials as plaintext, and uninstall puts the values back", async () => {
  const inv = await buildInventory({ home, lookup: async () => null, pins: {}, probeVersions: false });
  assert.equal(inv.totals.plaintext, 0);
  assert.equal(inv.totals.not_guarded, 0);
  assert.deepEqual(inv.agents.flatMap((a) => a.servers).find((s) => s.name === "linear")!.guarded, true);
  uninstallGuard({ home });
  const linear = JSON.parse(readFileSync(cursorCfg, "utf8")).mcpServers.linear;
  assert.deepEqual(linear, { type: "http", url: "https://mcp.example.com/mcp", headers: { Authorization: `Bearer ${LINEAR}` } });
});

test("the built CLI: migrate --dry-run prints names and never a value; prove exits 1 with findings", () => {
  machine();
  const run = (...args: string[]) => spawnSync("node", [join(import.meta.dirname, "../dist/index.js"), ...args], { encoding: "utf8", env: { ...process.env, HOME: home, USERPROFILE: home, VET_SKILLS_HOME: vsHome, VET_SKILLS_STORE: "file", KILLERSKILLS_API: "http://127.0.0.1:9", NODE_TEST_CONTEXT: undefined } as NodeJS.ProcessEnv });
  const dry = run("secrets", "migrate", "--dry-run");
  assert.match(dry.stdout, /github · GITHUB_PERSONAL_ACCESS_TOKEN\s+written in ~\/\.claude\.json/);
  assert.match(dry.stdout, /→ vs-store:\/\/codex\/sentry\/SENTRY_AUTH_TOKEN/);
  for (const v of all) assert.ok(!dry.stdout.includes(v) && !dry.stderr.includes(v));
  const noTty = run("secrets", "migrate"); assert.equal(noTty.status, 2); assert.match(noTty.stderr, /re-run with --yes/);
  const pr = run("prove"); assert.equal(pr.status, 1); assert.match(pr.stdout, /^FAIL {2}\d+ places? where a credential still lives/); assert.match(pr.stdout, /Not checked: /);
  const yes = run("secrets", "migrate", "--yes"); assert.equal(yes.status, 0, yes.stdout + yes.stderr); assert.match(yes.stdout, /3 credentials moved/);
  const ok = run("prove", "--json"); const j = JSON.parse(ok.stdout); assert.equal(j.findings.filter((f: { where: string }) => f.where !== "process").length, 0, ok.stdout);
  assert.match(run("secrets", "list").stdout, /claude-code\/github\/GITHUB_PERSONAL_ACCESS_TOKEN\s+file/);
});

test("toml env rewrite handles inline tables and env sub-tables and leaves everything else alone", () => {
  const text = `[mcp_servers.a]\ncommand = "npx"\nenv = { API_KEY = "abc12345678", MODE = "x" }\n\n[mcp_servers.b.env]\nTOKEN = "tok12345678"\nREGION = "us"\n\n[profile]\nAPI_KEY = "untouched1234"\n`;
  const seen: string[] = [];
  const out = rewriteTomlEnv(text, (server, name) => { seen.push(`${server}.${name}`); return /KEY|TOKEN/.test(name) ? `ref:${server}` : null; });
  assert.deepEqual(seen, ["a.API_KEY", "a.MODE", "b.TOKEN", "b.REGION"]);
  assert.equal(out, `[mcp_servers.a]\ncommand = "npx"\nenv = { API_KEY = "ref:a", MODE = "x" }\n\n[mcp_servers.b.env]\nTOKEN = "ref:b"\nREGION = "us"\n\n[profile]\nAPI_KEY = "untouched1234"\n`);
});
