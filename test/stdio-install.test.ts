import { test } from "node:test";
import assert from "node:assert/strict";
import { extractInstall, extractStdioPackage } from "../src/hook.js";

test("stdio MCP installs resolve to the package behind them", () => {
  assert.deepEqual(extractInstall("claude mcp add fs -- npx -y @modelcontextprotocol/server-filesystem /tmp"), { q: "modelcontextprotocol/server-filesystem", kind: "mcp", registry: "npm" });
  assert.deepEqual(extractInstall("claude mcp add git -s user -- uvx mcp-server-git@1.0 --repo x"), { q: "mcp-server-git", kind: "mcp", registry: "pypi" });
  assert.deepEqual(extractInstall("claude mcp add gh -- docker run -i --rm -e TOKEN mcp/github-official:latest"), { q: "github-official", kind: "mcp", registry: "docker" });
  assert.deepEqual(extractInstall("claude mcp add pg -- npx postgres-mcp@2"), { q: "postgres-mcp", kind: "mcp", registry: "npm" });
});

test("remote MCP and plugins keep their own forms", () => {
  assert.equal(extractStdioPackage("claude mcp add --transport http linear https://mcp.linear.app/sse"), null);
  assert.equal(extractInstall("claude mcp add --transport http linear https://mcp.linear.app/sse")?.kind, "mcp");
  assert.deepEqual(extractInstall("claude plugin install api-security-testing@claude-plugins-official"), { q: "api-security-testing", kind: "plugin", registry: "plugins" });
  assert.deepEqual(extractInstall("npx skills add anthropics/pdf"), { q: "anthropics/pdf", kind: "skill" });
});
