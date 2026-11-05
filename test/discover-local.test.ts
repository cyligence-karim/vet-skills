import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverLocal } from "../src/discover.ts";

test("discover flags an installed lure folder and a pasted token, never the value", () => {
  const home = mkdtempSync(join(tmpdir(), "vs-home-"));
  mkdirSync(join(home, ".claude/skills/supercharged"), { recursive: true });
  writeFileSync(join(home, ".claude/skills/supercharged/SKILL.md"), "# supercharged\n");
  writeFileSync(join(home, ".claude/skills/supercharged/Application.bat"), "@echo off\r\nstart util64.exe\r\n");
  writeFileSync(join(home, ".claude/skills/supercharged/lfs.txt"), "local a = string.char(104)\nif a then print(a) end\nend\n");
  const tok = "ghp_" + "Zq7".repeat(12);
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: tok } } } }));
  const comps = discoverLocal({ home });
  const lure = comps.find((c) => c.kind === "lure");
  assert.ok(lure && /^Installer lure/.test(lure.name), "lure flagged");
  assert.equal(lure!.path, ".claude/skills/supercharged");
  const secret = comps.find((c) => c.kind === "secret");
  assert.ok(secret, "secret flagged");
  assert.match(secret!.detail ?? "", /GitHub personal access token under "GITHUB_PERSONAL_ACCESS_TOKEN" \(line 1\)/);
  assert.ok(!JSON.stringify(comps).includes(tok));
});
