import { test } from "node:test";
import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync } from "node:crypto";
import { githubAppJwt, mint, secretsSpecFor } from "../src/exchange.ts";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = privateKey.export({ type: "pkcs1", format: "pem" }) as string;

test("exchange: the GitHub App JWT is RS256, 9 minutes, issued by the app", () => {
  const jwt = githubAppJwt("12345", pem, 1_800_000_000);
  const [h, p, sig] = jwt.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h, "base64url").toString()), { alg: "RS256", typ: "JWT" });
  const payload = JSON.parse(Buffer.from(p, "base64url").toString());
  assert.equal(payload.iss, "12345"); assert.equal(payload.exp - payload.iat, 600); assert.equal(payload.iat, 1_800_000_000 - 60);
  const v = createVerify("RSA-SHA256"); v.update(`${h}.${p}`);
  assert.ok(v.verify(publicKey, Buffer.from(sig, "base64url")));
});

test("exchange: github_app mints a scoped installation token and can revoke it", async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    if (String(url).endsWith("/access_tokens")) return new Response(JSON.stringify({ token: "ghs_short", expires_at: new Date(Date.now() + 3600_000).toISOString(), permissions: { contents: "read" }, repository_selection: "selected" }), { status: 201 });
    return new Response("", { status: 204 });
  }) as typeof fetch;
  const m = await mint({ var: "GITHUB_TOKEN", kind: "github_app", repositories: ["acme/api", "acme/web"], permissions: { contents: "read" } }, { VET_GITHUB_APP_ID: "1", VET_GITHUB_INSTALLATION_ID: "2", VET_GITHUB_APP_KEY: pem }, fakeFetch);
  assert.deepEqual(m.values, { GITHUB_TOKEN: "ghs_short" }); assert.equal(m.host, "api.github.com"); assert.match(m.scope, /2 repos · contents:read/);
  const body = JSON.parse(String(calls[0].init.body)); assert.deepEqual(body.repositories, ["api", "web"]); assert.deepEqual(body.permissions, { contents: "read" });
  assert.match(String((calls[0].init.headers as Record<string, string>).authorization), /^Bearer ey/);
  await m.revoke!();
  assert.equal(calls[1].url, "https://api.github.com/installation/token"); assert.equal(calls[1].init.method, "DELETE");
  assert.equal(secretsSpecFor([m]), "GITHUB_TOKEN=api.github.com");
  await assert.rejects(mint({ var: "GITHUB_TOKEN", kind: "github_app" }, {}, fakeFetch), /needs app_id/);
});

test("exchange: aws_sts without the CLI fails with a reason, never a crash", async () => {
  await assert.rejects(mint({ var: "AWS_ACCESS_KEY_ID", kind: "aws_sts", roleArn: "arn:aws:iam::1:role/x" }, { PATH: "/nonexistent" }), /aws sts assume-role failed/);
  await assert.rejects(mint({ var: "AWS_ACCESS_KEY_ID", kind: "aws_sts" }, {}), /needs role_arn/);
});

test("per_tool: the read variant of a GitHub App token lowers every permission to read, asking GitHub what the installation has when the policy names none", async () => {
  const bodies: Record<string, unknown>[] = []; const deleted: string[] = [];
  const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
    if (String(url).endsWith("/access_tokens")) { const b = JSON.parse(String(init?.body ?? "{}")); bodies.push(b); const n = bodies.length; return new Response(JSON.stringify({ token: `ghs_${n}`, expires_at: new Date(Date.now() + 3600_000).toISOString(), permissions: b.permissions ?? { contents: "write", issues: "write", metadata: "read" } }), { status: 201 }); }
    deleted.push(String((init?.headers as Record<string, string>).authorization)); return new Response("", { status: 204 });
  }) as typeof fetch;
  const env = { VET_GITHUB_APP_KEY: pem } as NodeJS.ProcessEnv;
  const named = await mint({ var: "GITHUB_TOKEN", kind: "github_app", appId: "1", installationId: "2", permissions: { contents: "write", pull_requests: "write" } }, env, fakeFetch, "read");
  assert.deepEqual(bodies[0].permissions, { contents: "read", pull_requests: "read" });
  assert.equal(named.access, "read");
  bodies.length = 0;
  const probed = await mint({ var: "GITHUB_TOKEN", kind: "github_app", appId: "1", installationId: "2" }, env, fakeFetch, "read");
  assert.equal(bodies.length, 2, "one token to learn the permissions, one read-only");
  assert.deepEqual(bodies[1].permissions, { contents: "read", issues: "read", metadata: "read" });
  assert.deepEqual(deleted, ["token ghs_1"], "the probe token is revoked at once");
  assert.equal(probed.values.GITHUB_TOKEN, "ghs_2");
  bodies.length = 0;
  await mint({ var: "GITHUB_TOKEN", kind: "github_app", appId: "1", installationId: "2", readPermissions: { issues: "read" } }, env, fakeFetch, "read");
  assert.deepEqual(bodies[0].permissions, { issues: "read" }, "the policy's own read_permissions win");
});
