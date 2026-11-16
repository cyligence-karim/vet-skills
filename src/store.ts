/**
 * The guard's credential store: where a real credential value lives once it has been taken out of an agent's config.
 *
 * Backends, picked per machine (override with VET_SKILLS_STORE=keychain|secret-service|dpapi|file):
 *   - macOS: the login keychain, through /usr/bin/security (the value is passed on stdin, never in argv);
 *   - Linux: the Secret Service (GNOME Keyring, KWallet) through `secret-tool`, when a session bus answers;
 *   - Windows: DPAPI (CurrentUser) through PowerShell, the protected blob kept in the store file;
 *   - everywhere else, and whenever one of those fails its own read-back: a file encrypted with AES-256-GCM under a key
 *     kept beside it, both 0600.
 *
 * What this is and is not: the value is out of the config files agents and tools read, and (keychain, Secret Service,
 * DPAPI) encrypted at rest under the user's login. It is not isolation from other processes of the same user: anything
 * that runs as you and goes looking can ask the same backend. The file fallback is protected by file permissions only.
 *
 * Every write is read back before it is reported as stored; callers rewrite a config only after that.
 */
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { platform } from "node:os";
import { join } from "node:path";
import { HOME } from "./state.js";

export type Backend = "keychain" | "secret-service" | "dpapi" | "file";
export const STORE_REF = "vs-store://";
export const isStoreRef = (v: unknown): v is string => typeof v === "string" && v.startsWith(STORE_REF);
export const refFor = (key: string) => `${STORE_REF}${key}`;
export const keyOfRef = (ref: string) => ref.slice(STORE_REF.length);

const SERVICE = "vet-skills";
type Exec = (cmd: string, args: string[], input?: string) => Pick<SpawnSyncReturns<string>, "status" | "stdout" | "stderr">;
const realExec: Exec = (cmd, args, input) => spawnSync(cmd, args, { input, encoding: "utf8", timeout: 15_000, windowsHide: true });

interface Index { v: 1; entries: Record<string, { backend: Backend; at: string; /** file and dpapi backends: the protected value */ blob?: string }> }

export interface StoreOptions { dir?: string; backend?: Backend; exec?: Exec; os?: NodeJS.Platform }

export class SecretStore {
  private dir: string; private exec: Exec; private os: NodeJS.Platform; private forced?: Backend;
  constructor(o: StoreOptions = {}) {
    this.dir = o.dir ?? join(HOME, "guard"); this.exec = o.exec ?? realExec; this.os = o.os ?? platform();
    const env = process.env.VET_SKILLS_STORE as Backend | undefined;
    this.forced = o.backend ?? (env && ["keychain", "secret-service", "dpapi", "file"].includes(env) ? env : undefined);
  }
  private get indexPath() { return join(this.dir, "secrets.json"); }
  private get keyPath() { return join(this.dir, "store.key"); }
  private readIndex(): Index { try { const j = JSON.parse(readFileSync(this.indexPath, "utf8")) as Index; if (j && j.v === 1 && j.entries) return j; } catch { /* none yet */ } return { v: 1, entries: {} }; }
  private writeIndex(ix: Index) { mkdirSync(this.dir, { recursive: true, mode: 0o700 }); writeFileSync(this.indexPath, JSON.stringify(ix, null, 2) + "\n", { mode: 0o600 }); try { chmodSync(this.indexPath, 0o600); } catch { /* windows */ } }

  /** The backend a new value would go to on this machine. */
  preferred(): Backend {
    if (this.forced) return this.forced;
    if (this.os === "darwin") return "keychain";
    if (this.os === "win32") return "dpapi";
    if (this.os === "linux" && process.env.DBUS_SESSION_BUS_ADDRESS && this.exec("secret-tool", ["--version"]).status === 0) return "secret-service";
    return "file";
  }

  private fileKey(): Buffer {
    try { const k = Buffer.from(readFileSync(this.keyPath, "utf8").trim(), "base64"); if (k.length === 32) return k; } catch { /* create */ }
    const k = randomBytes(32);
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    writeFileSync(this.keyPath, k.toString("base64") + "\n", { mode: 0o600 }); try { chmodSync(this.keyPath, 0o600); } catch { /* windows */ }
    return k;
  }
  private seal(value: string): string { const iv = randomBytes(12); const c = createCipheriv("aes-256-gcm", this.fileKey(), iv); const ct = Buffer.concat([c.update(value, "utf8"), c.final()]); return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64"); }
  private open(blob: string): string | null {
    try { const b = Buffer.from(blob, "base64"); const d = createDecipheriv("aes-256-gcm", this.fileKey(), b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8"); } catch { return null; }
  }

  private put(backend: Backend, key: string, value: string): { ok: boolean; blob?: string } {
    if (backend === "keychain") {
      // `security -i` reads commands from stdin, so the value is never in a process list.
      const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
      if (/[\r\n]/.test(value)) return { ok: false };
      return { ok: this.exec("/usr/bin/security", ["-i"], `add-generic-password -U -s ${q(SERVICE)} -a ${q(key)} -l ${q(`vet-skills: ${key}`)} -w ${q(value)}\n`).status === 0 };
    }
    if (backend === "secret-service") return { ok: this.exec("secret-tool", ["store", `--label=vet-skills: ${key}`, "service", SERVICE, "account", key], value).status === 0 };
    if (backend === "dpapi") {
      const r = this.exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Add-Type -AssemblyName System.Security; $v=[Console]::In.ReadToEnd(); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($v),$null,'CurrentUser'))"], value);
      const blob = String(r.stdout ?? "").trim();
      return r.status === 0 && blob ? { ok: true, blob } : { ok: false };
    }
    return { ok: true, blob: this.seal(value) };
  }
  private take(backend: Backend, key: string, blob?: string): string | null {
    if (backend === "keychain") { const r = this.exec("/usr/bin/security", ["find-generic-password", "-s", SERVICE, "-a", key, "-w"]); return r.status === 0 ? String(r.stdout).replace(/\r?\n$/, "") : null; }
    if (backend === "secret-service") { const r = this.exec("secret-tool", ["lookup", "service", SERVICE, "account", key]); return r.status === 0 && String(r.stdout).length ? String(r.stdout).replace(/\r?\n$/, "") : null; }
    if (backend === "dpapi") {
      if (!blob) return null;
      const r = this.exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Add-Type -AssemblyName System.Security; $b=[Console]::In.ReadToEnd().Trim(); [Console]::Out.Write([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($b),$null,'CurrentUser')))"], blob);
      return r.status === 0 ? String(r.stdout) : null;
    }
    return blob ? this.open(blob) : null;
  }
  private drop(backend: Backend, key: string) {
    if (backend === "keychain") this.exec("/usr/bin/security", ["delete-generic-password", "-s", SERVICE, "-a", key]);
    else if (backend === "secret-service") this.exec("secret-tool", ["clear", "service", SERVICE, "account", key]);
  }

  /** Store a value. Read back before it counts; a backend that fails its read-back is replaced by the file backend. */
  set(key: string, value: string): { ok: true; backend: Backend } | { ok: false; error: string } {
    if (!/^[\w.@/:~#-]{1,200}$/.test(key)) return { ok: false, error: `bad key: ${key}` };
    if (!value) return { ok: false, error: "empty value" };
    const ix = this.readIndex();
    for (const backend of [...new Set<Backend>([this.preferred(), "file"])]) {
      let res: { ok: boolean; blob?: string };
      try { res = this.put(backend, key, value); } catch { res = { ok: false }; }
      if (!res.ok) continue;
      let back: string | null = null;
      try { back = this.take(backend, key, res.blob); } catch { back = null; }
      if (back !== value) { try { this.drop(backend, key); } catch { /* nothing stored */ } continue; }
      const prev = ix.entries[key];
      if (prev && prev.backend !== backend) { try { this.drop(prev.backend, key); } catch { /* best effort */ } }
      ix.entries[key] = { backend, at: new Date().toISOString(), ...(res.blob ? { blob: res.blob } : {}) };
      this.writeIndex(ix);
      return { ok: true, backend };
    }
    return { ok: false, error: "no backend could store and read back the value" };
  }
  get(key: string): string | null { const e = this.readIndex().entries[key]; if (!e) return null; try { return this.take(e.backend, key, e.blob); } catch { return null; } }
  has(key: string): boolean { return !!this.readIndex().entries[key]; }
  delete(key: string): boolean { const ix = this.readIndex(); const e = ix.entries[key]; if (!e) return false; try { this.drop(e.backend, key); } catch { /* best effort */ } delete ix.entries[key]; this.writeIndex(ix); return true; }
  /** Names, backends and dates. Never values. */
  list(): { key: string; backend: Backend; at: string }[] { return Object.entries(this.readIndex().entries).map(([key, e]) => ({ key, backend: e.backend, at: e.at })).sort((a, b) => a.key.localeCompare(b.key)); }
  /** Every stored value, for the checks in `prove` (compared against files and environments, never printed). */
  values(): { key: string; value: string }[] { return this.list().map((e) => ({ key: e.key, value: this.get(e.key) })).filter((x): x is { key: string; value: string } => !!x.value); }
  get exists() { return existsSync(this.indexPath); }
}

/** Replace `vs-store://key` references in an environment with the stored values. Returns the names resolved and the ones missing. */
export function resolveStoreRefs(env: NodeJS.ProcessEnv, store = new SecretStore()): { resolved: string[]; missing: string[] } {
  const resolved: string[] = []; const missing: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    if (!isStoreRef(v)) continue;
    const val = store.get(keyOfRef(v));
    if (val === null) { missing.push(k); delete env[k]; } else { env[k] = val; resolved.push(k); }
  }
  return { resolved, missing };
}
