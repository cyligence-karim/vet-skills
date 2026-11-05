/**
 * Installer-lure signals that need only a path, a hash or a small text file,
 * shared by the sandbox (full engine), the repo scanners and `vet-skills
 * discover` (installed skill folders on a laptop).
 */

/** SHA-256 of files from the Agent Lure Stealer campaign (Nov 2026, IOCs by Thomas Roccia / fr0gger). */
export const KNOWN_BAD_SHA256: Record<string, string> = {
  "53039bdeb3e155236dce324281f59846c2da7518a54859c409286aaff86d61a2": "messenger-codex-v2.6.zip (Agent Lure Stealer)",
  "bd2a6bff153d95ab3d94d7db4525c49c31f5c6f32ddbf8e7c466732b0a6eb071": "supercharged-claude-skills-v2.0.zip (Agent Lure Stealer)",
  "4f5c5ad522d8dba60e89c443e07d65c3ce373ef1a617d220d3b69a185c11dae2": "Application.bat launcher (SmartLoader)",
  "ce1e33483d353200a266b3bc383ccf500e5a760c6dcd8218747260f5bbe39509": "Launcher.cmd (SmartLoader)",
  "2a7afb187157a4052e5b9797d1d1c7ee807b2edeffef076a08b20b12e3dcf317": "lfs.txt obfuscated Lua (SmartLoader)",
  "8cede35b80b1deaf732c2b178d908f91b3e7a0c114d06dfae9075b8a9bf78b8f": "uix.txt obfuscated Lua (SmartLoader)",
  "7ad4b911d05a12f91ab27ba3baa351a56653ca099dda7ad87ee2b94f8cd018c9": "util64.exe LuaJIT runtime (SmartLoader)",
  "04d3c82782927330d56827ff551697666dbab4b3abf5b86bde492efdd142bc58": "lua51.dll LuaJIT runtime (SmartLoader)",
  "f3e34c9e36f3be065d80d456281d31dd1cc85eb4980db7fa8c1b0eb6f29c25d8": "luajit.exe LuaJIT runtime (SmartLoader)",
  "ad9da27f72bb7abbfcba92f9302d3467f5487814bb34bbf4b1573abcb56e4efc": "dist.lua second stage (SmartLoader)",
};

export const EXEC_EXT = /\.(exe|dll|scr|msi|com|pif|bat|cmd|vbs|vbe|jse|wsf|hta|lnk)$/i;
export const ARCHIVE_EXT = /\.(zip|7z|rar|tar\.gz|tgz|tar\.xz|gz|xz|iso|img|dmg|pkg)$/i;
export const LUAJIT_NAMES = /(^|\/)(lua51\.dll|luajit\.exe|lua5\.1\.dll|util64\.exe|lua\.exe)$/i;

export const looksLikeLua = (t: string) => /\b(local\s+\w+\s*=|loadstring\s*\(|load\s*\(\s*["']|string\.(char|byte|rep)\s*\(|\bgetfenv\b|\bsetfenv\b)/.test(t) && (t.match(/\bend\b/g) ?? []).length >= 2;
export const looksLikeScript = (t: string) => /^\s*(@echo off|<\?php|#!\/|powershell|cmd\s*\/c|certutil|bitsadmin|Set-MpPreference)/im.test(t);

export interface LocalFile { path: string; sha256?: string; text?: string | null; bytes?: number }
export interface LocalLureFinding { severity: "critical" | "high"; title: string; path: string }

/** Path, hash and small-text signals over files already on disk (no README reasoning; the CLI shows these per skill folder). */
export function localLureFindings(files: LocalFile[]): LocalLureFinding[] {
  const out: LocalLureFinding[] = [];
  for (const f of files) {
    const p = f.path.replace(/\\/g, "/");
    const base = p.split("/").pop() ?? p;
    const known = f.sha256 ? KNOWN_BAD_SHA256[f.sha256] : undefined;
    if (known) out.push({ severity: "critical", title: `Known malicious file: ${known}`, path: p });
    if (LUAJIT_NAMES.test(p)) out.push({ severity: "critical", title: "LuaJIT runtime inside a skill folder (SmartLoader pattern)", path: p });
    else if (EXEC_EXT.test(p)) out.push({ severity: "high", title: "Windows executable or launcher inside a skill folder", path: p });
    if (ARCHIVE_EXT.test(p)) out.push({ severity: "high", title: "Archive inside a skill folder", path: p });
    if (/(^|\/)\.claude\/hooks\//i.test(p) && (ARCHIVE_EXT.test(p) || EXEC_EXT.test(p))) out.push({ severity: "critical", title: "Payload under .claude/hooks", path: p });
    if (/\.txt$/i.test(base) && f.text) {
      if (looksLikeLua(f.text)) out.push({ severity: "critical", title: "Lua script disguised as a text file", path: p });
      else if (looksLikeScript(f.text)) out.push({ severity: "high", title: "Shell or batch script disguised as a text file", path: p });
    }
  }
  return out;
}
