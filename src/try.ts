/**
 * `vet-skills try <target>`: fetch a skill or MCP server you have not installed
 * (npm package, PyPI package, GitHub repo or local path), run it in the
 * KillerSkills honeypot, and print what it did: every file it opened, every
 * host it contacted, the tools it exposes, and what it costs your agent. The
 * package never touches your machine beyond a temp directory that is deleted
 * afterwards; the run happens in the sandbox.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

export type Fetched = { dir: string; label: string; cleanup: () => void; registry: "npm" | "pypi" | "github" | "local" };

const sh = (cmd: string, args: string[], cwd?: string) => spawnSync(cmd, args, { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });

function onlyDir(root: string): string {
  const entries = readdirSync(root).filter((n) => !n.startsWith("."));
  const dirs = entries.filter((n) => statSync(join(root, n)).isDirectory());
  return dirs.length === 1 && entries.length === 1 ? join(root, dirs[0]) : root;
}

/** Resolve the target to a directory on disk. */
export function fetchTarget(target: string): Fetched | { error: string } {
  const t = target.trim();
  if (existsSync(t) && statSync(t).isDirectory()) return { dir: resolve(t), label: basename(resolve(t)), cleanup: () => {}, registry: "local" };
  const tmp = mkdtempSync(join(tmpdir(), "vet-skills-try-"));
  const cleanup = () => rmSync(tmp, { recursive: true, force: true });
  const gh = t.replace(/\.git$/, "").match(/^(?:https?:\/\/github\.com\/)?([\w.-]+)\/([\w.-]+)$/);
  if (/^pypi:/i.test(t)) {
    const name = t.replace(/^pypi:/i, "");
    const r = sh("pip", ["download", "--no-deps", "--no-build-isolation", "-d", tmp, name]);
    if (r.status !== 0) { const r2 = sh("pip3", ["download", "--no-deps", "-d", tmp, name]); if (r2.status !== 0) { cleanup(); return { error: `pip download failed: ${(r2.stderr || r.stderr).trim().split("\n").pop()}` }; } }
    const file = readdirSync(tmp).find((f) => /\.(whl|tar\.gz|zip)$/.test(f));
    if (!file) { cleanup(); return { error: "pip downloaded nothing" }; }
    const out = join(tmp, "pkg"); sh("mkdir", ["-p", out]);
    const x = /\.tar\.gz$/.test(file) ? sh("tar", ["-xzf", join(tmp, file), "-C", out]) : sh("unzip", ["-q", join(tmp, file), "-d", out]);
    if (x.status !== 0) { cleanup(); return { error: `could not extract ${file}` }; }
    return { dir: onlyDir(out), label: name, cleanup, registry: "pypi" };
  }
  if (gh && !/^@/.test(t) && !t.startsWith(".")) {
    const r = sh("git", ["clone", "--depth", "1", "--quiet", `https://github.com/${gh[1]}/${gh[2]}`, join(tmp, gh[2])], undefined);
    if (r.status !== 0) { cleanup(); return { error: `git clone failed: ${r.stderr.trim().split("\n").pop()}` }; }
    rmSync(join(tmp, gh[2], ".git"), { recursive: true, force: true });
    return { dir: join(tmp, gh[2]), label: `${gh[1]}/${gh[2]}`, cleanup, registry: "github" };
  }
  // npm: name or name@version; `npm pack` fetches the published tarball without running install scripts.
  const r = sh("npm", ["pack", t.replace(/^npm:/i, ""), "--pack-destination", tmp, "--silent", "--ignore-scripts"]);
  if (r.status !== 0) { cleanup(); return { error: `npm pack failed: ${r.stderr.trim().split("\n").filter(Boolean).pop() ?? "unknown package"}` }; }
  const tgz = readdirSync(tmp).find((f) => f.endsWith(".tgz"));
  if (!tgz) { cleanup(); return { error: "npm pack produced no tarball" }; }
  const out = join(tmp, "pkg"); sh("mkdir", ["-p", out]);
  sh("tar", ["-xzf", join(tmp, tgz), "-C", out]);
  return { dir: onlyDir(out), label: t.replace(/^npm:/i, ""), cleanup, registry: "npm" };
}

/** gzip the directory for upload, without node_modules or VCS metadata. */
export function tarDir(dir: string): Uint8Array | { error: string } {
  const r = spawnSync("tar", ["--exclude", "node_modules", "--exclude", ".git", "-czf", "-", "-C", dirname(dir), basename(dir)], { maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) return { error: `tar failed: ${r.stderr.toString().trim()}` };
  return new Uint8Array(r.stdout);
}
