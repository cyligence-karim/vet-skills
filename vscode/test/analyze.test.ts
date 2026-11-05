import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeText, isConfigFile, parserPath, resolveQuery } from "../src/analyze.ts";

test("config files are recognised and mapped to the parser's paths", () => {
  assert.ok(isConfigFile("/home/me/project/.mcp.json"));
  assert.ok(isConfigFile("/Users/me/.cursor/mcp.json"));
  assert.ok(isConfigFile("/Users/me/Library/Application Support/Claude/claude_desktop_config.json"));
  assert.ok(!isConfigFile("/home/me/project/package.json"));
  assert.equal(parserPath("/Users/me/.cursor/mcp.json"), ".cursor/mcp.json");
  assert.equal(parserPath("/home/me/project/.mcp.json"), ".mcp.json");
});

test("components get the line they sit on; a pasted token is reported by kind and line, never by value", () => {
  const tok = "ghp_" + "Zq7".repeat(12);
  const text = `{\n  "mcpServers": {\n    "github": {\n      "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],\n      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${tok}" }\n    },\n    "linear": { "type": "http", "url": "https://mcp.linear.app/mcp" }\n  }\n}`;
  const r = analyzeText("/home/me/proj/.mcp.json", text);
  const gh = r.components.find((x) => x.c.name === "github")!;
  assert.equal(gh.line, 2);
  assert.deepEqual(resolveQuery(gh.c), { q: "modelcontextprotocol/server-github", registry: "npm" });
  assert.equal(r.components.find((x) => x.c.name === "linear")!.c.transport, "http");
  assert.equal(r.secrets.length, 1);
  assert.equal(r.secrets[0].line, 5);
  assert.ok(!JSON.stringify(r).includes(tok));
});
