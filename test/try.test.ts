import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fetchTarget, tarDir } from "../src/try.ts";

test("try: a local directory is used in place; an unknown npm name fails cleanly", () => {
  const d = mkdtempSync(join(tmpdir(), "vs-try-"));
  writeFileSync(join(d, "SKILL.md"), "---\nname: x\n---\n");
  const got = fetchTarget(d);
  assert.ok(!("error" in got) && got.registry === "local" && got.dir === d);
  const tgz = tarDir(d);
  assert.ok(tgz instanceof Uint8Array && tgz.length > 20);
  const bad = fetchTarget("npm:this-package-does-not-exist-killerskills-0000");
  assert.ok("error" in bad && /npm pack failed/.test(bad.error));
});
