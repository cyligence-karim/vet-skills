import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAgentConfig, isAgentConfigPath, stdioPackage, blastRadius, classifyCredential } from "../src/policy/index.ts";

test("finds agent config files in a repo tree", () => {
  for (const p of [".mcp.json", "svc/.cursor/mcp.json", ".claude/settings.json", ".claude/skills/pdf/SKILL.md", "CLAUDE.md", "apps/x/AGENTS.md", ".vscode/mcp.json", ".github/copilot-instructions.md", ".codex/config.toml"]) assert.ok(isAgentConfigPath(p), p);
  for (const p of ["README.md", "package.json", "src/mcp.json", "docs/CLAUDE.md.bak"]) assert.ok(!isAgentConfigPath(p), p);
});

test(".mcp.json: stdio and remote servers, names only, no secrets", () => {
  const text = JSON.stringify({ mcpServers: {
    github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github@1.2.0"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_REALSECRET" } },
    linear: { type: "http", url: "https://mcp.linear.app/sse?token=abc", headers: { Authorization: "Bearer xyz" } },
    fetch: { command: "uvx", args: ["mcp-server-fetch"] },
    local: { command: "node", args: ["./tools/server.js", "--key", "sk-live-1"] },
  } });
  const cs = parseAgentConfig(".mcp.json", text);
  assert.equal(cs.length, 4);
  const gh = cs.find((c) => c.name === "github")!;
  assert.deepEqual(gh.package, { registry: "npm", name: "@modelcontextprotocol/server-github" });
  assert.deepEqual(gh.envKeys, ["GITHUB_PERSONAL_ACCESS_TOKEN"]);
  const lin = cs.find((c) => c.name === "linear")!;
  assert.equal(lin.urlHost, "mcp.linear.app"); assert.deepEqual(lin.headerKeys, ["Authorization"]);
  assert.deepEqual(cs.find((c) => c.name === "fetch")!.package, { registry: "pypi", name: "mcp-server-fetch" });
  assert.equal(cs.find((c) => c.name === "local")!.package, undefined);
  const dump = JSON.stringify(cs);
  for (const secret of ["ghp_REALSECRET", "token=abc", "Bearer xyz", "sk-live-1", "./tools/server.js"]) assert.ok(!dump.includes(secret), `leaked ${secret}`);
});

test("claude settings: plugins and hooks; JSONC configs parse", () => {
  const s = parseAgentConfig(".claude/settings.json", JSON.stringify({ enabledPlugins: { "security-guidance@claude-plugins": true, "off@x": false }, hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "/usr/local/bin/guard --token=s3cret" }] }] } }));
  assert.deepEqual(s.map((c) => `${c.kind}:${c.name}`), ["plugin:security-guidance", "hook:PreToolUse"]);
  assert.ok(!JSON.stringify(s).includes("s3cret"));
  const v = parseAgentConfig(".vscode/mcp.json", `{\n // comment\n "servers": { "pw": { "command": "npx", "args": ["@playwright/mcp@latest"], }, },\n}`);
  assert.deepEqual(v[0].package, { registry: "npm", name: "@playwright/mcp" });
});

test("skills, instruction files, codex toml, ~/.claude.json projects", () => {
  assert.equal(parseAgentConfig(".claude/skills/pdf/SKILL.md", "---\nname: pdf-tools\ndescription: x\n---\nbody")[0].name, "pdf-tools");
  assert.equal(parseAgentConfig("CLAUDE.md", "be nice")[0].kind, "instructions");
  const t = parseAgentConfig(".codex/config.toml", `[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp"]\nenv = { DOCS_API_KEY = "x" }\n`);
  assert.deepEqual([t[0].name, t[0].package?.name, t[0].envKeys[0]], ["docs", "docs-mcp", "DOCS_API_KEY"]);
  const u = parseAgentConfig(".claude.json", JSON.stringify({ mcpServers: { a: { url: "https://a.example.com/mcp" } }, projects: { "/Users/k/code/app": { mcpServers: { b: { command: "uvx", args: ["b-mcp"] } } } } }), "user");
  assert.deepEqual(u.map((c) => `${c.name}:${c.scope}`), ["a:user", "b:project"]);
});

test("docker images and odd commands", () => {
  assert.deepEqual(stdioPackage("docker", ["run", "-i", "--rm", "-e", "TOKEN", "mcp/github:latest"]), { registry: "docker", name: "mcp/github" });
  assert.equal(stdioPackage("python", ["server.py"]), undefined);
});

test("blast radius ranks credentials, verdicts and honeypot behaviour", () => {
  const [gh] = parseAgentConfig(".mcp.json", JSON.stringify({ mcpServers: { gh: { command: "npx", args: ["-y", "x"], env: { AWS_SECRET_ACCESS_KEY: "v" } } } }));
  assert.equal(blastRadius({ component: gh, verdict: { label: "verified", score: 92 } }).level, "high");
  const [remote] = parseAgentConfig(".mcp.json", JSON.stringify({ mcpServers: { r: { url: "https://r.example.com" } } }));
  assert.equal(blastRadius({ component: remote, verdict: null }).level, "low");
  const [plain] = parseAgentConfig(".mcp.json", JSON.stringify({ mcpServers: { p: { command: "npx", args: ["p"] } } }));
  assert.equal(blastRadius({ component: plain, verdict: { label: "verified", score: 95 } }).level, "low");
  assert.equal(blastRadius({ component: plain, verdict: { label: "blocked", score: 12 } }).level, "high");
  assert.equal(classifyCredential("STRIPE_SECRET_KEY"), "payments");
  assert.equal(classifyCredential("LOG_LEVEL"), null);
});
