import { test } from "node:test";
import assert from "node:assert/strict";

import { verifyZip } from "../src/org.ts";

// A bundle produced by the web generator (apps/web test fixture copied in CI); here we build a tiny one by hand with the same layout.
import { createHash } from "node:crypto";
import { crc32 } from "node:zlib";
const le16 = (n: number) => Buffer.from([n & 0xff, (n >> 8) & 0xff]); const le32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
function zip(files: { name: string; data: Buffer }[]): Buffer {
  const locals: Buffer[] = []; const centrals: Buffer[] = []; let off = 0;
  for (const f of files) { const name = Buffer.from(f.name); const crc = crc32(f.data) >>> 0; const l = Buffer.concat([le32(0x04034b50), le16(20), le16(0x0800), le16(0), le16(0), le16(0), le32(crc), le32(f.data.length), le32(f.data.length), le16(name.length), le16(0), name, f.data]); const c = Buffer.concat([le32(0x02014b50), le16(20), le16(20), le16(0x0800), le16(0), le16(0), le16(0), le32(crc), le32(f.data.length), le32(f.data.length), le16(name.length), le16(0), le16(0), le16(0), le16(0), le32(0), le32(off), name]); locals.push(l); centrals.push(c); off += l.length; }
  const cd = Buffer.concat(centrals); return Buffer.concat([...locals, cd, Buffer.concat([le32(0x06054b50), le16(0), le16(0), le16(files.length), le16(files.length), le32(cd.length), le32(off), le16(0)])]);
}
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

test("review verify: intact bundle passes, a changed record fails, acknowledgment must match the core hash", () => {
  const inv = Buffer.from("﻿record_id,package\r\ninst_1,npm:x\r\n"); const rules = Buffer.from("{}");
  const core = sha([`inventory.csv ${sha(inv)}`, `rules.json ${sha(rules)}`].join("\n"));
  const review = Buffer.from(JSON.stringify({ bound_to_core_hash: core }));
  const manifest = Buffer.from(JSON.stringify({ core_hash: core, files: [{ name: "inventory.csv", sha256: sha(inv) }, { name: "rules.json", sha256: sha(rules) }, { name: "review.json", sha256: sha(review) }] }));
  const good = zip([{ name: "inventory.csv", data: inv }, { name: "manifest.json", data: manifest }, { name: "review.json", data: review }, { name: "rules.json", data: rules }]);
  const v = verifyZip(good); assert.ok(v.ok, v.mismatches.join(",")); assert.equal(v.coreHash, core); assert.equal(v.acknowledgedHash, core);
  const bad = Buffer.from(good); bad[bad.indexOf(Buffer.from("npm:x")) + 4] = 0x79;
  const b = verifyZip(bad); assert.ok(!b.ok); assert.ok(b.mismatches.includes("inventory.csv hash differs")); assert.ok(b.mismatches.includes("core_hash differs"));
  const wrongAck = zip([{ name: "inventory.csv", data: inv }, { name: "manifest.json", data: Buffer.from(JSON.stringify({ core_hash: core, files: [{ name: "inventory.csv", sha256: sha(inv) }, { name: "rules.json", sha256: sha(rules) }] })) }, { name: "review.json", data: Buffer.from(JSON.stringify({ bound_to_core_hash: "0".repeat(64) })) }, { name: "rules.json", data: rules }]);
  const w = verifyZip(wrongAck); assert.ok(!w.ok); assert.ok(w.mismatches.some((m) => m.includes("acknowledgment")));
  assert.ok(!verifyZip(Buffer.from("not a zip")).ok);
});
