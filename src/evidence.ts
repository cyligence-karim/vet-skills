/**
 * The part of a verdict a person actually needs before installing: what the run tested and did not test, what tripped
 * each finding (file, line, the matched text), what would make the finding go away, and a recommendation that follows
 * from the evidence rather than from the label. Shared by `check` and `try`.
 *
 * Never asks for a credential. When a server needs one, the advice is to give it to the server where it runs, through
 * `vet-skills run --secrets`, so it never enters the server's environment or any report.
 */
import { c, pad } from "./render.js";

export type Coverage = { level: "full" | "startup_only" | "install_failed" | "install_only"; summary: string; tested: string[]; untested: string[]; needs: string[] };
export type Finding = { rule_id: string; severity: string; title: string; detail: string; file?: string | null; line?: number | null; evidence?: string | null };
export type EgressHost = { host: string; declared: boolean; implied?: string };
export interface Evidence {
  label: "verified" | "caution" | "blocked";
  score: number;
  coverage: Coverage | null;
  egress: EgressHost[];
  filesRead: string[];
  memoryWrites: number;
  findings: Finding[];
  /** Hosts the package's identity implies (publisher domain); used to suggest a network pin. */
  impliedHosts?: string[];
  name: string;
}

const SEV = ["critical", "high", "medium", "low", "info"];

/** How to make a finding go away, per rule family and title. Honest about the informational ones. */
export function resolution(f: Finding): string {
  const t = f.title.toLowerCase();
  if (/cloud instance metadata/.test(t)) return "nothing short of removing it: reading the metadata address steals the VM's credentials";
  if (/raw (public )?ip/.test(t)) return "a host name in place of the address, or a declared network permission naming it";
  if (/private-network address/.test(t)) return "informational: a LAN or development target; check it is not reachable from where this runs";
  if (/network transport|sse\/http/.test(t)) return "informational for an MCP server: it speaks HTTP by design";
  if (/npx invocation/.test(t)) return "pin the package to an exact version, or vendor it";
  if (/file type combined with upload/.test(t)) return "read the referenced line: a file name next to an upload verb is a pattern, not proof; the honeypot's file and network trace says whether it happened";
  if (/pipe.*shell|curl.*sh|installer|lure/.test(t)) return "a reviewable install step (a pinned package or a committed script) instead of a download executed blind";
  if (/hidden|invisible|zero-width|homoglyph|collapsed|unicode/.test(t)) return "remove the hidden text; what the reader sees must be what the agent reads";
  if (/instruct|prompt injection|tool description/.test(t)) return "rewrite the text so it describes the tool instead of commanding the agent";
  if (/credential|secret|token|password/.test(t)) return "move the value to the environment and reference it by name";
  if (/sudo|elevated/.test(t)) return "an install that does not need root, or a documented reason it does";
  if (/base64|obfuscat|hex-encoded|eval/.test(t)) return "plain source for the same logic; obfuscation is only ever read as hiding something";
  if (/sensitive path/.test(t)) return "a documented reason to read that path, or a declared filesystem permission";
  if (/unpinned|auto-update|dynamic fetch/.test(t)) return "a pinned version or hash for what gets fetched";
  return "look at the referenced line; if the pattern is a false match, the maintainer can mark it as such from the verdict page";
}

/** Where a finding sits: file:line, plus the matched text when the API carried it. */
function where(f: Finding): string {
  const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.detail.split(" · ")[0];
  const ev = (f.evidence ?? "").replace(/\s+/g, " ").trim();
  return ev ? `${loc}  ${c.faint(ev.length > 110 ? ev.slice(0, 110) + "…" : ev)}` : loc;
}

export function recommendation(e: Evidence): { verdict: string; detail: string[] } {
  const undeclared = e.egress.filter((h) => !h.declared);
  const implied = e.egress.filter((h) => h.implied);
  const cred = e.filesRead.filter((p) => /\.ssh|\.aws|credentials|\.config\/gh|\.netrc|\.npmrc|\.docker/.test(p));
  const crit = e.findings.filter((f) => f.severity === "critical");
  const needs = e.coverage?.needs.filter((n) => /^[A-Z]/.test(n)) ?? [];
  const pinHosts = [...new Set([...implied.map((h) => h.implied!), ...(e.impliedHosts ?? [])])];
  const secretsFlag = needs.length && pinHosts.length ? `--secrets ${needs.map((n) => `${n}=${pinHosts[0].startsWith("api.") ? pinHosts[0] : `api.${pinHosts[0]}`}`).join(",")}` : "";
  const runLine = `vet-skills run${secretsFlag ? ` ${secretsFlag}` : " --net declared"} -- <the server's command>`;

  if (e.label === "blocked") return { verdict: "Do not install.", detail: [e.findings.some((f) => /lure|installer/i.test(f.title)) ? "The bundle has the installer-lure shape: a README that sends the reader to a committed archive. That is malware delivery whatever the honeypot saw." : undeclared.length || cred.length ? `The honeypot observed it ${[cred.length ? `read ${cred.join(", ")}` : "", undeclared.length ? `contact ${undeclared.map((h) => h.host).join(", ")}, which it never declared` : ""].filter(Boolean).join(" and ")}.` : "A critical finding or an override blocked it; the evidence is on the verdict page."] };
  if (cred.length && undeclared.length) return { verdict: "Do not install.", detail: [`It read ${cred.join(", ")} and reached ${undeclared.map((h) => h.host).join(", ")} in the same run. That is the exfiltration pattern, whatever the score says.`] };
  if (undeclared.length) return { verdict: "Install only if you know what these hosts are.", detail: [`It contacted ${undeclared.map((h) => h.host).join(", ")} without declaring it. If that is the vendor's own service, the maintainer can declare it (Propose a patch on the verdict page); if you cannot place it, do not install.`, `Pinning the network makes the question moot: ${c.ink2(`vet-skills run --net ${undeclared.map((h) => h.host).join(",")} -- …`)} lets exactly those hosts through and logs anything else.`] };
  if (e.coverage?.level === "install_failed") return { verdict: "Treat this as a static verdict.", detail: ["The honeypot could not install its dependencies, so the server never started; the label rests on static analysis and the publisher. Check the dependency install on your own machine before trusting the score, or run it under the guard:", c.ink2(runLine)] };
  if (e.coverage?.level === "startup_only") {
    const d = [`The honeypot ran it to startup${needs.length ? ` and it asked for ${needs.join(", ")}` : ""}; nothing it does with a real credential was observed. Static analysis found ${crit.length ? `${crit.length} critical finding${crit.length === 1 ? "" : "s"}` : "nothing critical"}${implied.length ? `, and it reached only ${implied.map((h) => h.host).join(", ")}, its publisher's own host` : ""}.`];
    d.push(needs.length
      ? `Reasonable to install with a scoped ${needs.join("/")}. Give the credential to the guard, not the server: ${c.ink2(runLine)} keeps the value out of the server's environment, injects it only into requests to ${pinHosts[0] ? pinHosts[0] : "the host you name"}, and refuses every other host. Never paste the credential into a chat, a ticket or a report.`
      : `Reasonable to install under the guard: ${c.ink2(runLine)} pins the network to what the honeypot saw and logs every call.`);
    return { verdict: needs.length ? "Install with a scoped credential, under the guard." : "Install under the guard.", detail: d };
  }
  if (!e.coverage) return { verdict: "Static verdict only; run it before trusting the label.", detail: [`Nothing has run yet: the ${e.label === "caution" ? "Caution" : "label"} comes from static findings and publisher trust alone. ${c.ink2(`vet-skills try ${e.name}`)} runs this exact version in the honeypot now, and the crawler's own run replaces this verdict when it completes.`] };
  if (e.label === "caution") return { verdict: "Install under the guard; read the findings first.", detail: [`The run was clean (${e.coverage.summary.replace(/\.$/, "")}); the Caution comes from static findings and publisher trust, listed above with what triggered each. ${c.ink2(runLine)} pins the network and logs every call.`] };
  return { verdict: "Reasonable to install.", detail: [`${e.coverage.summary} No undeclared hosts, no credential reads, no critical findings.${e.memoryWrites ? " It wrote agent memory files: read the trace before trusting it." : ""}`] };
}

/** The evidence block, as lines. */
export function renderEvidence(e: Evidence, opts: { maxFindings?: number } = {}): string[] {
  const lines: string[] = [];
  const cov = e.coverage;
  // Coverage comes first: it qualifies the label.
  if (cov) {
    const tone = cov.level === "full" ? c.verified : c.caution;
    lines.push(`${c.ink2("Coverage")}  ${tone(cov.summary)}`);
    lines.push(`  ${pad("tested", 11)} ${c.muted(cov.tested.join(" · "))}`);
    if (cov.untested.length) lines.push(`  ${pad("not tested", 11)} ${c.muted(cov.untested.join(" · "))}`);
    if (cov.needs.length) lines.push(`  ${pad("needs", 11)} ${c.muted(`${cov.needs.join(", ")} — give it to the guard with --secrets, never to a chat or a report`)}`);
  } else {
    lines.push(`${c.ink2("Coverage")}  ${c.caution("Static only; nothing was run.")} ${c.muted("The label rests on the code, the instruction files and the publisher. The honeypot run is queued for the next crawl cycle (within two hours); `vet-skills try` runs it now.")}`);
  }
  // Findings with what triggered them.
  const fs = [...e.findings].filter((f) => f.severity !== "info").sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
  const max = opts.maxFindings ?? 8;
  if (fs.length) {
    lines.push("");
    lines.push(`${c.ink2("Findings")}  ${c.muted(`${fs.length} static match${fs.length === 1 ? "" : "es"}; each shows the line that tripped it and what would resolve it`)}`);
    const shown = fs.slice(0, max);
    const seen = new Set<string>();
    for (const f of shown) {
      const sev = f.severity === "critical" || f.severity === "high" ? c.blocked(pad(f.severity, 8)) : f.severity === "medium" ? c.caution(pad(f.severity, 8)) : c.muted(pad(f.severity, 8));
      lines.push(`  ${c.muted(f.rule_id)} ${sev} ${f.title}`);
      lines.push(`      ${c.muted("at")}       ${where(f)}`);
      const key = resolution(f);
      if (!seen.has(key)) { seen.add(key); lines.push(`      ${c.muted("resolves")} ${c.muted(key)}`); }
    }
    if (fs.length > max) lines.push(c.muted(`  … ${fs.length - max} more on the verdict page`));
  }
  const r = recommendation(e);
  lines.push("");
  lines.push(`${c.ink2("Recommendation")}  ${c.bold(r.verdict)}`);
  for (const d of r.detail) lines.push(`  ${d}`);
  return lines;
}
