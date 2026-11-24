import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAgentConfig } from "../src/policy/discover.js";
import { buildRuleShield, compileShield, shieldCaution, leverWords, leversOf, narrows, parseShield, pinLaunch, renderShieldSnippet, serializeShield, shieldCommand, type ShieldEvidence, type SnippetFormat } from "../src/policy/shield.js";

const ev = (o: Partial<ShieldEvidence> = {}): ShieldEvidence => ({
  package: { registry: "npm", name: "@acme/mcp-files", semver: "2.4.1", artifact_hash: "sha256:aaa" }, verdictId: "vd_1", engineVersion: "1.9.2", coverage: "full", ranAt: "2026-11-24T00:00:00.000Z",
  egress: [{ host: "api.acme.dev", declared: true }, { host: "telemetry.other.io", declared: false }], surfaceHosts: ["api.acme.dev"], credentialFiles: ["~/.aws/credentials"],
  tools: ["read_file", "write_file", "delete_file", "acme/drop_table"], credentialEnv: [{ name: "ACME_TOKEN", host: "api.acme.dev" }, { name: "OTHER", host: null }],
  drift: { id: "pd_1", fromSemver: "2.4.0", fromArtifactHash: "sha256:bbb", summary: "2.4.1 contacts a new host it does not declare.", eligible: true }, ...o,
});

test("the same evidence gives the same bytes, and the bytes read back to the same shield", () => {
  const a = buildRuleShield(ev())!, b = buildRuleShield(ev({ tools: ["acme/drop_table", "delete_file", "write_file", "read_file"], egress: [...ev().egress].reverse() }))!;
  assert.equal(serializeShield(a), serializeShield(b));
  assert.deepEqual(parseShield(serializeShield(a)), a);
  assert.deepEqual(leversOf(a), ["pin", "net", "contain", "tools", "secrets"]);
  assert.equal(serializeShield(parseShield(serializeShield(a))), serializeShield(a));
});

test("each rule follows from the evidence", () => {
  const s = buildRuleShield(ev())!;
  assert.deepEqual(s.rules.net, { mode: "hosts", hosts: ["api.acme.dev"], reason: "contacted a host it does not declare; only the hosts it declares or names in its code stay reachable", evidence: "traces.egress_hosts declared=true, verdicts.credential_surface" });
  assert.equal(s.rules.contain?.enabled, true);
  assert.deepEqual(s.rules.tools?.map((t) => `${t.match}:${t.action}`), ["delete_file:deny", "drop_table:deny", "write_file:approve"]);
  assert.deepEqual(s.rules.secrets, [{ name: "ACME_TOKEN", host: "api.acme.dev", evidence: "verdicts.credential_surface" }]);
  assert.equal(s.rules.pin?.semver, "2.4.0");
  // No declared host on record: the network is closed and the shield says so. It is never left open silently.
  const closed = buildRuleShield(ev({ egress: [{ host: "x.io", declared: false }], surfaceHosts: [], drift: null }))!;
  assert.equal(closed.rules.net?.mode, "closed");
  // The CLI reads "--net off" as no limit, so a closed network must never compile to it.
  { const a = compileShield(closed).runArgs; assert.equal(a[a.indexOf("--net") + 1], "registry.npmjs.org"); assert.match(shieldCaution(closed)!, /nothing else/); assert.match(shieldCaution(buildRuleShield(ev())!)!, /names in its code/); assert.equal(shieldCaution(buildRuleShield(ev({ egress: [], surfaceHosts: [] }))!), null); }
  assert.match(closed.not_enforced[0], /only the package registry/);
  // Nothing recorded that calls for a rule: no shield.
  assert.equal(buildRuleShield(ev({ egress: [{ host: "api.acme.dev", declared: true }], credentialFiles: [], tools: ["read_file", "write_file"], drift: null })), null);
});

test("compiles onto flags the guard has, and pins the launch command", () => {
  const s = buildRuleShield(ev())!;
  assert.deepEqual(compileShield(s).runArgs, ["--contain", "--net", "registry.npmjs.org,api.acme.dev", "--deny", "delete_file,drop_table", "--secrets", "ACME_TOKEN=api.acme.dev"]);
  assert.deepEqual(compileShield(s).pin, { semver: "2.4.0", artifact_hash: "sha256:bbb" });
  assert.deepEqual(pinLaunch(["npx", "-y", "@acme/mcp-files@latest", "--root", "."], s), ["npx", "-y", "@acme/mcp-files@2.4.0", "--root", "."]);
  assert.deepEqual(pinLaunch(["uvx", "@acme/mcp-files"], s), ["uvx", "@acme/mcp-files==2.4.0"]);
  assert.deepEqual(pinLaunch(["node", "server.js"], s), ["node", "server.js"]);
  assert.equal(shieldCommand(["npx", "-y", "@acme/mcp-files"], s), "npx -y vet-skills run --contain --net registry.npmjs.org,api.acme.dev --deny delete_file,drop_table --secrets ACME_TOKEN=api.acme.dev -- npx -y @acme/mcp-files@2.4.0");
});

test("narrows: a built shield passes, and any widening is caught", () => {
  const e = ev(), s = buildRuleShield(e)!;
  assert.deepEqual(narrows(s, e), { ok: true, why: [] });
  const clone = () => parseShield(serializeShield(s));
  let x = clone(); x.rules.net!.hosts.push("evil.example"); assert.equal(narrows(x, e).ok, false);
  x = clone(); delete x.rules.contain; assert.equal(narrows(x, e).ok, false);
  x = clone(); delete x.rules.net; assert.equal(narrows(x, e).ok, false);
  x = clone(); x.rules.tools = x.rules.tools!.filter((t) => t.match !== "delete_file"); assert.equal(narrows(x, e).ok, false);
  x = clone(); x.rules.pin!.semver = "9.9.9"; assert.equal(narrows(x, e).ok, false);
  x = clone(); x.rules.secrets![0].host = "evil.example"; assert.equal(narrows(x, e).ok, false);
  x = clone(); x.package.artifact_hash = "sha256:zzz"; assert.equal(narrows(x, e).ok, false);
});

test("the reader is strict: unknown keys, an allow action, a bad host and a newer CLI requirement all throw", () => {
  const y = serializeShield(buildRuleShield(ev())!);
  assert.throws(() => parseShield(y.replace('drafted_by:', 'extra: "x"\ndrafted_by:')), /unknown key/);
  assert.throws(() => parseShield(y.replace('action: "deny"', 'action: "allow"')), /only deny or hold/);
  assert.throws(() => parseShield(y.replace('hosts: ["api.acme.dev"]', 'hosts: ["api.acme.dev/x?y"]')), /not a host/);
  assert.throws(() => parseShield(y.replace("killerskills.shield/v1", "killerskills.shield/v2")), /unsupported/);
  assert.throws(() => parseShield(y, { cliVersion: "0.15.9" }), /needs vet-skills/);
  assert.doesNotThrow(() => parseShield(y, { cliVersion: "0.16.0" }));
  assert.throws(() => parseShield("schema: killerskills.shield/v1\n"), /unquoted/);
});

test("snippets for every guard format parse back to the same server under the guard", () => {
  const s = buildRuleShield(ev())!;
  const wrap: Record<SnippetFormat, [string, (x: string) => string]> = {
    mcpServers: [".cursor/mcp.json", (x) => `{ "mcpServers": { ${x} } }`], "claude-json": [".claude.json", (x) => `{ "mcpServers": { ${x} } }`], vscode: [".vscode/mcp.json", (x) => `{ "servers": { ${x} } }`],
    amp: [".config/amp/settings.json", (x) => `{ "amp.mcpServers": { ${x} } }`], zed: [".config/zed/settings.json", (x) => `{ "context_servers": { ${x} } }`], opencode: [".config/opencode/opencode.json", (x) => `{ "mcp": { ${x} } }`], "codex-toml": [".codex/config.toml", (x) => x],
  };
  for (const [format, [path, around]] of Object.entries(wrap) as [SnippetFormat, [string, (x: string) => string]][]) {
    const text = around(renderShieldSnippet(format, "files", ["npx", "-y", "@acme/mcp-files"], s));
    const comps = parseAgentConfig(path, text, "user").filter((c) => c.kind === "mcp_server");
    assert.equal(comps.length, 1, `${format}: ${text}`);
    assert.equal(comps[0].name, "files", format);
    assert.ok(text.includes("vet-skills") && text.includes("@acme/mcp-files@2.4.0") && text.includes("--contain"), format);
    assert.ok(!/env|ACME_TOKEN=[^a]/.test(text.replace("ACME_TOKEN=api.acme.dev", "")), `${format} writes no env block`);
  }
});

test("lever words name no host, tool or package", () => {
  const words = leverWords(buildRuleShield(ev())!).join(" ");
  assert.ok(!/acme|delete_file|drop_table|api\./.test(words), words);
  assert.equal(leverWords(buildRuleShield(ev())!).length, 6);
});

test("a tool list alone never makes a shield, an expected launch keeps its registry, and deploy or send tools are held, not denied", () => {
  assert.equal(buildRuleShield(ev({ egress: [{ host: "api.acme.dev", declared: true }], credentialFiles: [], drift: null })), null);
  // The registry the launcher downloads from is never the "one declared host" and never counts as undeclared.
  assert.equal(buildRuleShield(ev({ egress: [{ host: "registry.npmjs.org", declared: false }], surfaceHosts: [], credentialFiles: [], drift: null })), null);
  const reg = buildRuleShield(ev({ egress: [{ host: "registry.npmjs.org", declared: true }, { host: "t.other.io", declared: false }], surfaceHosts: [], credentialFiles: [], drift: null }))!;
  assert.equal(reg.rules.net?.mode, "closed");
  const s = buildRuleShield(ev({ tools: ["deploy_folder", "send_email", "delete_site", "list_sites"] }))!;
  assert.deepEqual(s.rules.tools?.map((t) => `${t.match}:${t.action}`), ["delete_site:deny", "deploy_folder:approve", "send_email:approve"]);
  assert.ok(narrows(s, ev({ tools: ["deploy_folder", "send_email", "delete_site", "list_sites"] })).ok);
  const py = buildRuleShield(ev({ package: { registry: "pypi", name: "acme-mcp", semver: "1.0.0", artifact_hash: "sha256:ccc" }, drift: null }))!;
  assert.ok(compileShield(py).runArgs.includes("pypi.org,files.pythonhosted.org,api.acme.dev"));
});

test("narrows: a kept host may not cover a host the run flagged", () => {
  const e = ev({ egress: [{ host: "t.acme.dev", declared: false }], surfaceHosts: ["acme.dev"], credentialFiles: [], drift: null });
  const s = buildRuleShield(e)!;
  assert.equal(narrows(s, e).ok, false);
});

test("a pin with no host list to keep is the whole response: the earlier version keeps its network", () => {
  const e = ev({ egress: [{ host: "t.other.io", declared: false }], surfaceHosts: [], credentialFiles: [], tools: null, credentialEnv: [] });
  const s = buildRuleShield(e)!;
  assert.deepEqual(leversOf(s), ["pin"]);
  assert.ok(narrows(s, e).ok);
  assert.equal(shieldCommand(["npx", "-y", "@acme/mcp-files"], s), "npx -y vet-skills run -- npx -y @acme/mcp-files@2.4.0");
});
