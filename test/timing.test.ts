import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync, spawn } from "node:child_process";
import { createServer } from "node:http";

const posts: { headers: Record<string, unknown>; body: Record<string, unknown> }[] = [];
const api = createServer((req, res) => {
  let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => {
    if (req.url === "/api/v1/funnel" && req.method === "POST") posts.push({ headers: req.headers, body: JSON.parse(b || "{}") });
    res.setHeader("content-type", "application/json"); res.statusCode = req.url === "/api/v1/funnel" ? 200 : 404; res.end(JSON.stringify(req.url === "/api/v1/funnel" ? { ok: true } : { error: "not found" }));
  });
});
await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));
const port = (api.address() as { port: number }).port;
after(() => { api.closeAllConnections(); api.close(); });
const cli = join(import.meta.dirname, "../dist/index.js");
const envFor = (home: string, extra: Record<string, string> = {}) => ({ ...process.env, HOME: home, USERPROFILE: home, VET_SKILLS_HOME: join(home, ".vet-skills"), VET_SKILLS_STORE: "file", KILLERSKILLS_API: `http://127.0.0.1:${port}`, VET_SKILLS_TELEMETRY: undefined, DO_NOT_TRACK: undefined, NODE_TEST_CONTEXT: undefined, ...extra }) as NodeJS.ProcessEnv;
const NOTICE = /vet-skills measures one thing about setup, anonymously: the minutes from this first command to your first guarded session/;
/** A guarded session against a server that exits at once. */
const session = (home: string, extra: Record<string, string> = {}) => new Promise<string>((resolve) => {
  const c = spawn("node", [cli, "guard", "exec", "--server", "s", "--client", "test", "--", "node", "-e", "process.stdin.on('end',()=>process.exit(0));process.stdin.resume()"], { stdio: ["pipe", "ignore", "pipe"], env: envFor(home, extra) });
  let err = ""; c.stderr.on("data", (d) => (err += d)); setTimeout(() => c.stdin.end(), 1500); c.on("close", () => resolve(err));
});

test("a fresh install is told once, and its first guarded session reports minutes, OS and version with no client id", async () => {
  const home = mkdtempSync(join(tmpdir(), "vs-timing-"));
  const first = spawnSync("node", [cli, "policy", "show"], { encoding: "utf8", env: envFor(home) });
  assert.match(first.stderr, NOTICE); assert.match(first.stderr, /Opt out: vet-skills telemetry off/);
  assert.ok(!NOTICE.test(spawnSync("node", [cli, "policy", "show"], { encoding: "utf8", env: envFor(home) }).stderr), "said once");
  // Pretend the first command was seven minutes ago.
  const fr = join(home, ".vet-skills", "first-run"); const j = JSON.parse(readFileSync(fr, "utf8")); assert.equal(j.fresh, true);
  writeFileSync(fr, JSON.stringify({ at: new Date(Date.now() - 7 * 60_000).toISOString(), fresh: true }));
  posts.length = 0;
  await session(home); await new Promise((r) => setTimeout(r, 300));
  const mine = posts.filter((p) => p.body.kind === "first_guarded_session");
  assert.equal(mine.length, 1);
  assert.deepEqual(Object.keys(mine[0].body).sort(), ["kind", "minutes", "os", "version"]);
  assert.equal(mine[0].body.minutes, 7);
  assert.equal(mine[0].headers["x-vs-client"], undefined, "no client id rides along");
  await session(home); await new Promise((r) => setTimeout(r, 300));
  assert.equal(posts.filter((p) => p.body.kind === "first_guarded_session").length, 1, "reported once");
});

test("opted out, or not a fresh install: nothing is announced and nothing is sent", async () => {
  const off = mkdtempSync(join(tmpdir(), "vs-timing-off-"));
  assert.ok(!NOTICE.test(spawnSync("node", [cli, "policy", "show"], { encoding: "utf8", env: envFor(off, { VET_SKILLS_TELEMETRY: "0" }) }).stderr));
  posts.length = 0;
  await session(off, { VET_SKILLS_TELEMETRY: "0" }); await new Promise((r) => setTimeout(r, 300));
  assert.equal(posts.filter((p) => p.body.kind === "first_guarded_session").length, 0);
  assert.ok(existsSync(join(off, ".vet-skills", "guard", "first-session")), "marked, so turning telemetry on later does not report a stale number");
  // An install that already had state before this version: never timed.
  const old = mkdtempSync(join(tmpdir(), "vs-timing-old-")); mkdirSync(join(old, ".vet-skills"), { recursive: true }); writeFileSync(join(old, ".vet-skills", "id"), "existing-client-id\n");
  assert.ok(!NOTICE.test(spawnSync("node", [cli, "policy", "show"], { encoding: "utf8", env: envFor(old) }).stderr));
  assert.equal(JSON.parse(readFileSync(join(old, ".vet-skills", "first-run"), "utf8")).fresh, false);
  await session(old); await new Promise((r) => setTimeout(r, 300));
  assert.equal(posts.filter((p) => p.body.kind === "first_guarded_session").length, 0);
});
