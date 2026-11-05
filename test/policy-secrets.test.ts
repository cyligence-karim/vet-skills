import { test } from "node:test";
import assert from "node:assert/strict";
import { findSecrets } from "../src/policy/secrets.ts";

test("committed credential values are found by format and by key, placeholders and references are not", () => {
  const text = JSON.stringify({ mcpServers: {
    github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_" + "A".repeat(36) } },
    gh2: { env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" } },
    ex: { env: { OPENAI_API_KEY: "sk-your-key-here" } },
    aws: { env: { AWS_ACCESS_KEY_ID: "AKIA" + "Q".repeat(16), AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1" } },
    pg: { env: { DATABASE_URL: "postgres://app:s3cretpass@db.internal:5432/prod" } },
    linear: { type: "http", url: "https://mcp.linear.app/mcp", headers: { Authorization: "Bearer lin_api_" + "x9".repeat(20) } },
  } }, null, 2);
  const f = findSecrets(".mcp.json", text);
  const kinds = f.map((x) => x.kind).sort();
  assert.ok(kinds.includes("github_token"), "ghp_");
  assert.ok(kinds.includes("aws_access_key"), "AKIA");
  assert.ok(kinds.includes("database_url"), "db url with password");
  assert.ok(kinds.includes("generic_bearer"), "Authorization: Bearer <value>");
  assert.ok(!f.some((x) => x.line === text.split("\n").findIndex((l) => l.includes("${GITHUB_TOKEN}")) + 1), "reference is not a secret");
  assert.ok(!f.some((x) => x.kind === "openai_key"), "placeholder is not a secret");
  for (const x of f) assert.ok(!("value" in x), "no value field");
  const json = JSON.stringify(f);
  assert.ok(!json.includes("AAAA") && !json.includes("s3cretpass") && !json.includes("x9x9"), "no secret bytes in findings");
});
