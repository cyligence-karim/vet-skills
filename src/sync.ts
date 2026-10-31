/**
 * Apply what the org asked of this machine: remove installs the dashboard
 * requested removal for, then confirm so the audit log closes the loop.
 * Skills installed by `npx skills add` live under ~/.claude/skills/<name> or
 * ./.claude/skills/<name>; anything we cannot find on disk is reported as
 * already gone rather than left pending forever.
 */
import { existsSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { confirmRemoval, report, type ReportResponse } from "./api.js";
import { readOrg } from "./state.js";

export function skillDirs(name: string): string[] {
  const bare = name.replace(/^.*\//, "").replace(/@.*$/, "");
  return [join(homedir(), ".claude", "skills", bare), join(process.cwd(), ".claude", "skills", bare), join(homedir(), ".claude", "plugins", bare)];
}

export async function applyRemovals(pending: ReportResponse["pending_removals"], log: (l: string) => void = () => {}): Promise<number> {
  let done = 0;
  // One confirm per removal request, even when it covers several installs on this machine.
  const byRequest = new Map<string, ReportResponse["pending_removals"]>();
  for (const r of pending) byRequest.set(r.removal_id, [...(byRequest.get(r.removal_id) ?? []), r]);
  for (const [removalId, items] of byRequest) {
    const detail: string[] = [];
    let failed = false;
    for (const it of items) {
      const dirs = skillDirs(it.skill).filter((d) => existsSync(d));
      if (!dirs.length) { detail.push(`${it.skill}: not on disk`); continue; }
      try { for (const d of dirs) rmSync(d, { recursive: true, force: true }); detail.push(`${it.skill}: removed ${dirs.join(", ")}`); }
      catch (e) { failed = true; detail.push(`${it.skill}: ${(e as Error).message}`); }
    }
    const res = await confirmRemoval(removalId, { status: failed ? "failed" : "confirmed", detail: detail.join("; ") });
    if (res.ok) { done += items.length; log(`${failed ? "!" : "✓"} ${items.map((i) => i.skill).join(", ")} ${failed ? "removal failed" : "removed"} (${removalId})`); }
    else log(`! could not confirm removal ${removalId}: ${res.error}`);
  }
  return done;
}

/** Report, pull policy, apply removals. Used by `vet-skills sync`, `status`, and the hook after each decision. */
export async function sync(log: (l: string) => void = () => {}): Promise<{ ok: boolean; removed: number; error?: string }> {
  const org = readOrg();
  if (!org) return { ok: false, removed: 0, error: "not joined" };
  const res = await report({ installed: [], removed: [], hook_version: undefined });
  if (!res.ok) return { ok: false, removed: 0, error: res.error };
  const removed = await applyRemovals(res.data.pending_removals, log);
  return { ok: true, removed };
}
