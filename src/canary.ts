/**
 * Canary credentials: the honeypot's trick, on the real machine.
 *
 * `vet-skills canary install` plants decoy credential files beside the real ones, in the places an infostealer or a
 * misbehaving skill sweeps (~/.ssh, ~/.aws, ~/.config/gh, ~/.npmrc) under names that look like forgotten backups.
 * Nothing real is touched: a canary is only ever written to a path that does not exist, and a real tool never reads
 * `credentials.old`. Each value is random and unique to this machine, registered in ~/.vet-skills/canaries.json (0600).
 *
 * The hook and the `run` guard then scan everything that leaves the agent (tool arguments, shell commands, fetch URLs,
 * MCP calls) and everything that comes back. A canary value showing up anywhere is proof of exfiltration, not a
 * heuristic: nothing legitimate has a reason to read, let alone send, a file nothing uses. The value itself is never
 * sent to KillerSkills; the kind of event is (`canary_exfil`), which is the strongest field signal there is.
 */
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { HOME } from "./state.js";

export interface Canary { path: string; kind: string; value: string; plantedAt: string; /** sha256 of the file as written, so removal never deletes a file someone changed */ sha256: string }
export interface CanaryRegistry { version: 1; machine: string; canaries: Canary[] }

const REGISTRY = () => join(HOME, "canaries.json");
const B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const rand = (n: number, alphabet = B62) => { const b = randomBytes(n); let s = ""; for (let i = 0; i < n; i++) s += alphabet[b[i] % alphabet.length]; return s; };
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** The decoys and where they go. `file` is relative to $HOME; `body` renders the file around the value. */
export const CANARY_SPECS: { kind: string; file: string; value: () => string; body: (v: string) => string }[] = [
  { kind: "aws_access_key", file: ".aws/credentials.old", value: () => `AKIA${rand(16, UPPER)}`, body: (v) => `[default]\naws_access_key_id = ${v}\naws_secret_access_key = ${rand(40)}\nregion = us-east-1\n` },
  { kind: "github_token", file: ".config/gh/hosts.yml.old", value: () => `ghp_${rand(36)}`, body: (v) => `github.com:\n    user: ${rand(8).toLowerCase()}\n    oauth_token: ${v}\n    git_protocol: https\n` },
  { kind: "npm_token", file: ".npmrc.old", value: () => `npm_${rand(36)}`, body: (v) => `//registry.npmjs.org/:_authToken=${v}\n` },
  { kind: "ssh_private_key", file: ".ssh/id_rsa_old", value: () => rand(64), body: (v) => `-----BEGIN OPENSSH PRIVATE KEY-----\n${chunk(Buffer.from(`openssh-key-v1\0${v}${rand(300)}`).toString("base64"), 70)}\n-----END OPENSSH PRIVATE KEY-----\n` },
  { kind: "env_file", file: ".env.old", value: () => `sk_live_${rand(32)}`, body: (v) => `STRIPE_SECRET_KEY=${v}\nDATABASE_URL=postgres://app:${rand(16)}@db.internal:5432/app\n` },
];
function chunk(s: string, n: number) { const out: string[] = []; for (let i = 0; i < s.length; i += n) out.push(s.slice(i, i + n)); return out.join("\n"); }

export function readCanaries(): CanaryRegistry | null {
  try { return JSON.parse(readFileSync(REGISTRY(), "utf8")) as CanaryRegistry; } catch { return null; }
}
function writeRegistry(r: CanaryRegistry) {
  if (!existsSync(HOME)) mkdirSync(HOME, { recursive: true, mode: 0o700 });
  writeFileSync(REGISTRY(), JSON.stringify(r, null, 2) + "\n", { mode: 0o600 });
}

/** Plant every canary whose path is free. Returns what was planted and what was skipped (path already exists). */
export function plantCanaries(home = homedir()): { planted: Canary[]; skipped: string[] } {
  const reg: CanaryRegistry = readCanaries() ?? { version: 1, machine: rand(12), canaries: [] };
  const planted: Canary[] = []; const skipped: string[] = [];
  for (const spec of CANARY_SPECS) {
    const path = join(home, spec.file);
    if (reg.canaries.some((c) => c.path === path) && existsSync(path)) continue;
    if (existsSync(path)) { skipped.push(path); continue; }
    const value = spec.value(); const body = spec.body(value);
    try {
      const dir = dirname(path);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeFileSync(path, body, { mode: 0o600, flag: "wx" });
    } catch { skipped.push(path); continue; }
    const c: Canary = { path, kind: spec.kind, value, plantedAt: new Date().toISOString(), sha256: createHash("sha256").update(body).digest("hex") };
    reg.canaries = [...reg.canaries.filter((x) => x.path !== path), c];
    planted.push(c);
  }
  writeRegistry(reg);
  return { planted, skipped };
}

/** Remove every planted file whose content is still ours, and forget them. */
export function removeCanaries(): { removed: number } {
  const reg = readCanaries(); if (!reg) return { removed: 0 };
  let removed = 0;
  for (const c of reg.canaries) {
    try { if (existsSync(c.path) && createHash("sha256").update(readFileSync(c.path)).digest("hex") === c.sha256) { unlinkSync(c.path); removed++; } } catch { /* leave it */ }
  }
  try { unlinkSync(REGISTRY()); } catch { /* none */ }
  return { removed };
}

/** Canary values present in `text` (any position, any encoding we can cheaply undo: raw, URL-encoded, base64). */
export function canariesIn(text: string, reg: CanaryRegistry | null = readCanaries()): Canary[] {
  if (!reg?.canaries.length || !text) return [];
  const hay = [text];
  try { hay.push(decodeURIComponent(text)); } catch { /* not url-encoded */ }
  // Base64 blobs (a key file pasted into a body): decode anything that looks like one and is long enough to hold a value.
  for (const m of text.matchAll(/[A-Za-z0-9+/=]{40,}/g)) { try { hay.push(Buffer.from(m[0], "base64").toString("utf8")); } catch { /* ignore */ } }
  const out: Canary[] = [];
  for (const c of reg.canaries) if (hay.some((h) => h.includes(c.value)) && !out.includes(c)) out.push(c);
  return out;
}

/** Where the match was seen, for the deviation detail: the file's kind and name, never the value. */
export function describeCanary(c: Canary, home = homedir()) {
  return `${c.kind.replace(/_/g, " ")} canary (${c.path.startsWith(home) ? "~" + c.path.slice(home.length) : c.path})`;
}
