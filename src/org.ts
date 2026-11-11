/**
 * Organization commands for people, not hooks: review packs, approvals and the threat feed from the terminal. They use
 * this machine's enrollment token; the org role of the developer who enrolled it decides what is allowed, and every
 * decision made here is recorded with the identity source `cli:agent_token` (assigned, not authenticated).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { approvalDecideInstall, approvalDecideTool, approvalsPending, reviewPackCreate, reviewPackDownload, reviewPackGet, reviewPacks, reviewSetDisposition, threatsFeed, type ApiResult } from "./api.js";
import { readOrg } from "./state.js";
import { c, pad } from "./render.js";

const out = (s = "") => process.stdout.write(s + "\n");
const err = (s: string) => process.stderr.write(s + "\n");
function needOrg(): boolean { if (readOrg()) return true; err(`${c.blocked("✕")} this machine is not enrolled in an organization (vet-skills join <org> --token <t>).`); return false; }
function fail<T>(r: ApiResult<T>): r is { ok: false; status?: number; error: string; offline: boolean } { if (r.ok) return false; err(`${c.blocked("✕")} ${r.error}${r.status ? ` (${r.status})` : ""}`); return true; }
function flag(args: string[], name: string): string | null { const i = args.indexOf(`--${name}`); return i >= 0 && i + 1 < args.length && !args[i + 1].startsWith("--") ? args[i + 1] : null; }
const has = (args: string[], name: string) => args.includes(`--${name}`);
const day = (s: string | null | undefined) => (s ? s.slice(0, 10) : "—");

/* ------------------------------------------------------------------ review */

export async function reviewCmd(sub: string | undefined, args: string[]): Promise<number> {
  const json = has(args, "json");
  if (sub === "verify") return verifyCmd(args[0]);
  if (!needOrg()) return 1;
  if (!sub || sub === "list") {
    const r = await reviewPacks(); if (fail(r)) return 1;
    if (json) { out(JSON.stringify(r.data.packs, null, 2)); return 0; }
    if (!r.data.packs.length) { out(c.muted("No review packs yet. vet-skills review create --month YYYY-MM")); return 0; }
    out(`${pad("PACK", 36)} ${pad("V", 3)} ${pad("STATUS", 11)} ${pad("PERIOD", 25)} ${pad("CREATED", 22)} CORE HASH`);
    for (const p of r.data.packs) out(`${pad(p.pack_ref, 36)} ${pad(String(p.version), 3)} ${pad(tone(p.status), 11)} ${pad(`${day(p.period_start)} → ${day(p.period_end)}`, 25)} ${pad(`${day(p.created_at)} ${p.created_by}`, 22)} ${p.core_hash ? p.core_hash.slice(0, 16) + "…" : "—"}`);
    out(c.muted(`\nids: ${r.data.packs.map((p) => p.id).join(", ")}`));
    return 0;
  }
  if (sub === "create") {
    const month = flag(args, "month"); const start = flag(args, "from"); const end = flag(args, "to");
    if (!month && !(start && end)) { err("usage: vet-skills review create --month YYYY-MM | --from YYYY-MM-DD --to YYYY-MM-DD [--tz Area/City] [--pseudonymize-hosts] [--no-allows]"); return 2; }
    const r = await reviewPackCreate({ month: month ?? undefined, start: start ?? undefined, end: end ?? undefined, timezone: flag(args, "tz") ?? "UTC", pseudonymize_hosts: has(args, "pseudonymize-hosts"), include_allow_decisions: !has(args, "no-allows") });
    if (fail(r)) return 1;
    if (json) { out(JSON.stringify(r.data, null, 2)); return 0; }
    out(`${c.verified("✓")} draft ${c.bold(r.data.pack.pack_ref)} created for ${day(r.data.pack.period_start)} → ${day(r.data.pack.period_end)} (${r.data.pack.timezone})`);
    out(c.muted(`id ${r.data.pack.id} · vet-skills review show ${r.data.pack.id}`));
    return 0;
  }
  if (sub === "show") {
    const id = args[0]; if (!id) { err("usage: vet-skills review show <pack-id> [--json]"); return 2; }
    const r = await reviewPackGet(id); if (fail(r)) return 1;
    if (json) { out(JSON.stringify(r.data, null, 2)); return 0; }
    const p = r.data.pack;
    out(`${c.bold(p.pack_ref)} v${p.version} · ${tone(p.status)} · ${day(p.period_start)} → ${day(p.period_end)} (${p.timezone})${p.finalized_at ? ` · finalized ${day(p.finalized_at)} by ${p.finalized_by} (${p.finalized_identity_source})` : ""}`);
    const rc = r.data.row_counts;
    out(c.muted(`inventory ${rc["inventory.csv"] ?? 0} · sessions ${rc["sessions.csv"] ?? 0} · decisions ${rc["decisions.csv"] ?? 0} · approvals ${rc["approvals.csv"] ?? 0} · policy versions ${rc["policy_history.csv"] ?? 0} · changes ${rc["changes_and_revocations.csv"] ?? 0}`));
    if (p.core_hash) out(c.muted(`core hash ${p.core_hash}`));
    out(`\n${c.bold("Known gaps")}`); for (const g of r.data.known_gaps) out(`  · ${g}`);
    const undecided = r.data.exceptions.filter((e) => !e.disposition).length;
    out(`\n${c.bold("Exceptions")} ${r.data.exceptions.length} · ${undecided} undecided`);
    for (const e of r.data.exceptions) out(`  ${pad(e.id, 32)} ${pad(e.rule_id, 7)} ${pad(e.disposition ?? c.caution("undecided"), 22)} ${e.subject}`);
    if (r.data.exceptions.length) out(c.muted(`\nvet-skills review disposition ${p.id} <exception-id> accepted_exception|remediation_required|false_positive|insufficient_evidence [--owner h] [--by YYYY-MM-DD] [--note …]`));
    out(c.muted(`finalize from the dashboard: an admin's authenticated session binds the acknowledgment to the core hash.`));
    return 0;
  }
  if (sub === "disposition") {
    const [id, exc, disposition] = args; if (!id || !exc || !disposition) { err("usage: vet-skills review disposition <pack-id> <exception-id> <disposition> [--owner h] [--by YYYY-MM-DD] [--note …]"); return 2; }
    const r = await reviewSetDisposition(id, exc, { disposition: disposition === "clear" ? null : disposition, owner: flag(args, "owner"), target_date: flag(args, "by"), note: flag(args, "note") });
    if (fail(r)) return 1;
    out(`${c.verified("✓")} ${exc} → ${disposition}`); return 0;
  }
  if (sub === "download") {
    const id = args[0]; if (!id) { err("usage: vet-skills review download <pack-id> [--out file.zip]"); return 2; }
    const r = await reviewPackDownload(id); if (fail(r)) return 1;
    const target = resolve(flag(args, "out") ?? r.data.name);
    mkdirSync(dirname(target), { recursive: true }); writeFileSync(target, r.data.bytes);
    out(`${c.verified("✓")} ${target} (${r.data.bytes.length} bytes)`);
    const v = verifyZip(r.data.bytes);
    out(v.ok ? `${c.verified("✓")} manifest hashes verify · core ${v.coreHash?.slice(0, 16)}…` : `${c.blocked("✕")} verification failed: ${v.mismatches.join(", ")}`);
    return v.ok ? 0 : 1;
  }
  err("usage: vet-skills review [list|create|show|disposition|download|verify] …"); return 2;
}

function tone(st: string) { return st === "final" ? c.verified(st) : st === "superseded" ? c.muted(st) : c.caution(st); }

/* ---------------------------------------------------------------- verify */

/** Minimal STORE-zip reader for pack bundles (the generator writes no compression). */
function unzip(buf: Buffer): Map<string, Buffer> {
  const files = new Map<string, Buffer>(); let p = 0;
  while (p + 30 <= buf.length && buf.readUInt32LE(p) === 0x04034b50) {
    const method = buf.readUInt16LE(p + 8); const size = buf.readUInt32LE(p + 18); const nlen = buf.readUInt16LE(p + 26); const xlen = buf.readUInt16LE(p + 28);
    const name = buf.subarray(p + 30, p + 30 + nlen).toString("utf8"); const start = p + 30 + nlen + xlen;
    if (method !== 0) throw new Error(`${name}: compressed entries are not expected in a review pack`);
    files.set(name, Buffer.from(buf.subarray(start, start + size))); p = start + size;
  }
  return files;
}
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const CORE_EXCLUDED = new Set(["README.txt", "review.json", "review.pdf", "manifest.json"]);

export function verifyZip(buf: Buffer): { ok: boolean; coreHash: string | null; mismatches: string[]; files: number; acknowledgedHash: string | null } {
  let files: Map<string, Buffer>; try { files = unzip(buf); } catch (e) { return { ok: false, coreHash: null, mismatches: [(e as Error).message], files: 0, acknowledgedHash: null }; }
  const m = files.get("manifest.json"); if (!m) return { ok: false, coreHash: null, mismatches: ["manifest.json missing"], files: files.size, acknowledgedHash: null };
  let manifest: { files: { name: string; sha256: string }[]; core_hash: string }; try { manifest = JSON.parse(m.toString("utf8")); } catch { return { ok: false, coreHash: null, mismatches: ["manifest.json unreadable"], files: files.size, acknowledgedHash: null }; }
  const mismatches: string[] = [];
  for (const f of manifest.files) { const d = files.get(f.name); if (!d) mismatches.push(`${f.name} missing`); else if (sha256(d) !== f.sha256) mismatches.push(`${f.name} hash differs`); }
  const core = sha256(manifest.files.filter((f) => !CORE_EXCLUDED.has(f.name)).sort((a, b) => a.name.localeCompare(b.name)).map((f) => `${f.name} ${files.has(f.name) ? sha256(files.get(f.name)!) : "missing"}`).join("\n"));
  if (core !== manifest.core_hash) mismatches.push("core_hash differs");
  let ack: string | null = null; const rj = files.get("review.json"); if (rj) { try { ack = (JSON.parse(rj.toString("utf8")) as { bound_to_core_hash?: string }).bound_to_core_hash ?? null; } catch { /* absent */ } }
  if (ack && ack !== manifest.core_hash) mismatches.push("acknowledgment is bound to a different core hash");
  return { ok: mismatches.length === 0, coreHash: manifest.core_hash, mismatches, files: files.size, acknowledgedHash: ack };
}

async function verifyCmd(file: string | undefined): Promise<number> {
  if (!file) { err("usage: vet-skills review verify <pack.zip>   (no account needed)"); return 2; }
  const { readFileSync } = await import("node:fs");
  let buf: Buffer; try { buf = readFileSync(resolve(file)); } catch (e) { err(`${c.blocked("✕")} ${(e as Error).message}`); return 1; }
  const v = verifyZip(buf);
  out(`${v.files} files · core hash ${v.coreHash ?? "—"}`);
  if (v.acknowledgedHash) out(`reviewer acknowledgment bound to ${v.acknowledgedHash === v.coreHash ? c.verified("this core hash") : c.blocked("a different hash")}`); else out(c.muted("no reviewer acknowledgment (draft pack)"));
  out(v.ok ? `${c.verified("✓")} every file matches manifest.json; the records were not altered after generation` : `${c.blocked("✕")} ${v.mismatches.join("; ")}`);
  out(c.muted("Verification proves the bundle is intact, not that it is complete; read manifest.json#known_gaps."));
  return v.ok ? 0 : 1;
}

/* -------------------------------------------------------------- approvals */

export async function approvalsCmd(sub: string | undefined, args: string[]): Promise<number> {
  if (!needOrg()) return 1;
  const json = has(args, "json");
  if (!sub || sub === "list") {
    const r = await approvalsPending(); if (fail(r)) return 1;
    if (json) { out(JSON.stringify(r.data, null, 2)); return 0; }
    if (!r.data.install.length && !r.data.tool.length) { out(c.muted("Nothing pending.")); return 0; }
    if (r.data.install.length) { out(c.bold("Install requests")); for (const a of r.data.install) out(`  ${pad(a.id, 28)} ${pad(a.package, 44)} ${pad(a.kind, 10)} ${pad(a.requested_by, 16)} ${day(a.requested_at)}${a.suggestion ? c.muted(` · suggest ${a.suggestion}`) : ""}`); }
    if (r.data.tool.length) { out(c.bold("Held tool calls")); for (const t of r.data.tool) out(`  ${pad(t.id, 28)} ${pad(`${t.server}/${t.tool}`, 44)} ${pad(t.package ?? "", 30)} args ${t.arg_keys.join(",") || "—"} · expires ${t.expires_at.slice(11, 19)}Z`); }
    out(c.muted("\nvet-skills approvals approve|deny <id> [--team|--sandboxed]   (recorded as cli:agent_token, an assigned identity)"));
    return 0;
  }
  if (sub === "approve" || sub === "deny") {
    const id = args[0]; if (!id) { err(`usage: vet-skills approvals ${sub} <id> [--team|--sandboxed]`); return 2; }
    // Tool approvals are ULIDs issued by the guard; install requests are ULIDs too, so try the tool endpoint first and fall through on 404.
    const t = await approvalDecideTool(id, sub === "approve" ? "approved" : "denied");
    if (t.ok) { out(`${c.verified("✓")} tool call ${t.data.decision} · identity ${t.data.identity_source}`); return 0; }
    if (t.status !== 404) { fail(t); return 1; }
    const op = sub === "deny" ? "deny" : has(args, "team") ? "approve_team" : has(args, "sandboxed") ? "approve_sandboxed" : "approve_dev";
    const r = await approvalDecideInstall(id, op); if (fail(r)) return 1;
    out(`${c.verified("✓")} install request now ${r.data.status} · identity ${r.data.identity_source}`); return 0;
  }
  err("usage: vet-skills approvals [list|approve <id>|deny <id>]"); return 2;
}

/* ---------------------------------------------------------------- threats */

export async function threatsCmd(args: string[]): Promise<number> {
  const stix = has(args, "stix");
  const r = await threatsFeed(stix); if (fail(r)) return 1;
  if (stix || has(args, "json")) { out(typeof r.data === "string" ? r.data : JSON.stringify(r.data, null, 2)); return 0; }
  const d = r.data as { incidents?: { package: string; registry: string; semver: string | null; status: string; kinds?: string[]; opened_at?: string; closed_at?: string | null; observed?: string | null; verdict?: string | null }[] };
  const list = d.incidents ?? [];
  if (!list.length) { out(c.muted("No incidents in the feed.")); return 0; }
  for (const i of list.slice(0, 50)) out(`${pad(i.status === "confirmed" ? c.blocked(i.status) : c.muted(i.status), 20)} ${pad(`${i.package}${i.semver ? `@${i.semver}` : ""}`, 44)} ${pad(i.registry, 8)} ${day(i.opened_at)} ${(i.kinds ?? []).join(", ")}${i.observed ? c.muted(` · ${i.observed.slice(0, 80)}`) : ""}`);
  out(c.muted(`\n${list.length} incidents · --json for the full feed, --stix for STIX 2.1 · https://killerskills.ai/threats`));
  return 0;
}
