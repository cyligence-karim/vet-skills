/**
 * Hidden-instruction detection shared by the sandbox (scored), the CLI (local
 * instruction files, tool results, the run guard), the browser (/check) and the
 * repo scanners. Two families:
 *
 *   1. Text a human reader would not see but a model reads: Unicode tag
 *      characters (ASCII smuggling), bidi overrides, zero-width runs, variation
 *      selectors and soft-hyphen stuffing as carriers, homoglyph-mixed words,
 *      HTML that renders invisible (display:none, zero font, white-on-white,
 *      hidden attribute), collapsed <details>, image alt text and link titles
 *      carrying imperatives, text pushed off-screen by whitespace, HTML comments
 *      carrying imperatives.
 *   2. Instruction phrases aimed at the agent, for content that is data rather
 *      than instructions (a tool result, a fetched page): used when
 *      `phrases: true`.
 *
 * Pure regex and Unicode arithmetic; no I/O, safe in a browser.
 */
export type HiddenKind =
  | "unicode_tags" | "bidi_override" | "zero_width" | "variation_selectors" | "soft_hyphen" | "homoglyph"
  | "hidden_html" | "collapsed_details" | "alt_text_instructions" | "link_title_instructions" | "offscreen_whitespace" | "html_comment_instructions"
  | "injection_phrase";

export interface HiddenFinding { kind: HiddenKind; severity: "critical" | "high" | "medium"; title: string; line: number; evidence: string; /** For smuggled text: what it decodes to. */ decoded?: string }

/** Words that make hidden text an instruction rather than a note. */
export const IMPERATIVE = /\b(ignore|disregard|override|bypass|forget|you must|you are now|do not (?:tell|mention|ask|reveal)|don't (?:tell|mention|ask)|run|execute|exfiltrate|send (?:to|the)|silently|without (?:asking|confirm)|system prompt|new instructions?|instead|always|never|curl|wget|base64|\.ssh|credentials?|api[_ ]?key|token)\b/i;

const RULES: { kind: HiddenKind; re: RegExp; severity: HiddenFinding["severity"]; title: string; needImperative?: number }[] = [
  { kind: "unicode_tags", re: /[\u{E0000}-\u{E007F}]{2,}/gu, severity: "critical", title: "Invisible Unicode tag characters (smuggled text the model reads and you do not)" },
  { kind: "bidi_override", re: /[‪-‮⁦-⁩]/g, severity: "high", title: "Bidirectional override character (text renders in a different order than it is read)" },
  { kind: "zero_width", re: /[​-‏⁠﻿]{3,}/g, severity: "high", title: "Zero-width characters (hidden text)" },
  { kind: "variation_selectors", re: /[︀-️]{4,}|[\u{E0100}-\u{E01EF}]{2,}/gu, severity: "high", title: "Variation-selector run (invisible data carrier)" },
  { kind: "soft_hyphen", re: /­{3,}/g, severity: "medium", title: "Soft-hyphen stuffing (invisible characters inside words)" },
  { kind: "homoglyph", re: /(?<![\p{L}\p{N}])(?=[\p{Script=Latin}]*[\p{Script=Cyrillic}\p{Script=Greek}])(?=[\p{Script=Cyrillic}\p{Script=Greek}]*[\p{Script=Latin}])[\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}]{3,}(?![\p{L}\p{N}])/gu, severity: "high", title: "Latin word with Cyrillic or Greek look-alike letters (homoglyph)" },
  { kind: "hidden_html", re: /<(span|div|p|font|b|i|em|strong|small|sup|sub)\b[^>]*?(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white|#000(?:000)?|black|transparent)|\bhidden\b|aria-hidden=["']true)[^>]*>([\s\S]{0,800}?)<\/\1>/gi, severity: "critical", title: "HTML that renders invisible but is read by the agent", needImperative: 2 },
  { kind: "collapsed_details", re: /<details\b[^>]*>([\s\S]{0,1200}?)<\/details>/gi, severity: "high", title: "Collapsed <details> block carrying instructions", needImperative: 1 },
  { kind: "alt_text_instructions", re: /!\[([^\]]{24,})\]\(/g, severity: "high", title: "Image alt text carrying instructions", needImperative: 1 },
  { kind: "link_title_instructions", re: /\[[^\]]*\]\(\S+\s+["']([^"']{24,})["']\)|^\s*\[[^\]]+\]:\s*\S+\s+["']([^"']{24,})["']/gm, severity: "high", title: "Link title carrying instructions", needImperative: 1 },
  { kind: "offscreen_whitespace", re: /[^\S\n]{120,}(\S[^\n]{10,})/g, severity: "high", title: "Text pushed off-screen by whitespace", needImperative: 1 },
  { kind: "html_comment_instructions", re: /<!--([\s\S]{0,600}?)-->/g, severity: "critical", title: "HTML comment carrying imperative instructions to the agent", needImperative: 1 },
];

/** Instruction phrases aimed at the model, for data that should not contain any. */
const PHRASES: { re: RegExp; title: string }[] = [
  { re: /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|directions?|prompts?|rules?|context)/i, title: "\"ignore previous instructions\"" },
  { re: /\byou are now\b[^.\n]{0,60}\b(?:an?|the)\s+\w+/i, title: "role reassignment (\"you are now …\")" },
  { re: /\b(?:new|updated|real|actual)\s+(?:system\s+)?(?:instructions?|prompt)\s*:/i, title: "\"new instructions:\"" },
  { re: /\b(?:do not|don't|never)\s+(?:tell|mention|reveal|disclose|inform)\s+(?:this\s+to\s+)?the\s+user/i, title: "\"do not tell the user\"" },
  { re: /\b(?:AI|assistant|agent|model|LLM|Claude|GPT|Copilot|Cursor)\b[^.\n]{0,40}\b(?:must|should|needs? to|is required to)\b[^.\n]{0,80}\b(?:run|execute|send|read|open|fetch|curl|delete|write)\b/i, title: "instruction addressed to the agent" },
  { re: /\b(?:important|attention|note to|instructions? for)\s+(?:the\s+)?(?:AI|assistant|agent|model|LLM)\b/i, title: "section addressed to the agent" },
  { re: /\b(?:print|reveal|repeat|output|show)\s+(?:your|the)\s+(?:system\s+prompt|instructions|hidden\s+prompt)/i, title: "system-prompt extraction" },
  { re: /\b(?:exfiltrate|upload|send|post)\b[^.\n]{0,60}\b(?:\.ssh|\.aws|credentials|api[_ ]?keys?|tokens?|secrets?|env(?:ironment)? variables?)\b/i, title: "credential exfiltration instruction" },
  { re: /\bcurl\b[^\n]{0,80}\|\s*(?:ba|z)?sh\b|\bwget\b[^\n]{0,80}\|\s*(?:ba|z)?sh\b/i, title: "remote script piped to shell" },
  { re: /\b(?:without|do not|don't)\s+(?:asking|confirming|checking with|notifying)\s+(?:the\s+)?(?:user|human|operator)/i, title: "\"without asking the user\"" },
  { re: /\b(?:disable|turn off|bypass|skip)\s+(?:all\s+)?(?:safety|security|guardrails?|checks?|confirmations?|permissions?)\b/i, title: "safety bypass instruction" },
];

/** ASCII smuggled as Unicode tag characters, decoded. */
export function decodeUnicodeTags(text: string): string {
  let out = "";
  for (const ch of text) { const cp = ch.codePointAt(0)!; if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCodePoint(cp - 0xe0000); }
  return out;
}

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;
const clip = (s: string, n = 160) => s.replace(/\s+/g, " ").trim().slice(0, n);

/**
 * Findings in one text. `phrases: true` adds the instruction-phrase family, for
 * data content (tool results, fetched pages) where any such phrase is suspect;
 * leave it off for instruction files, whose own imperatives are legitimate.
 */
export function hiddenTextFindings(text: string, opts: { phrases?: boolean; max?: number } = {}): HiddenFinding[] {
  const out: HiddenFinding[] = [];
  const max = opts.max ?? 40;
  for (const r of RULES) {
    const re = new RegExp(r.re.source, r.re.flags);
    let m: RegExpExecArray | null;
    let n = 0;
    while ((m = re.exec(text)) && n < 8 && out.length < max) {
      n++;
      if (m[0].length === 0) { re.lastIndex++; continue; }
      const inner = r.needImperative ? (m[r.needImperative] ?? m[1] ?? m[2] ?? "") : "";
      if (r.needImperative && !IMPERATIVE.test(inner)) continue;
      const decoded = r.kind === "unicode_tags" ? decodeUnicodeTags(m[0]) : undefined;
      out.push({ kind: r.kind, severity: r.severity, title: r.title, line: lineOf(text, m.index), evidence: decoded ? `decodes to: ${clip(decoded)}` : clip(inner || m[0]), ...(decoded ? { decoded } : {}) });
    }
  }
  if (opts.phrases) {
    for (const p of PHRASES) {
      const m = p.re.exec(text);
      if (m && out.length < max) out.push({ kind: "injection_phrase", severity: "high", title: `Instruction aimed at the agent: ${p.title}`, line: lineOf(text, m.index), evidence: clip(text.slice(Math.max(0, m.index - 40), m.index + m[0].length + 60)) });
    }
  }
  return out;
}

/** One line a hook or guard can hand back to the agent. */
export function hiddenSummary(findings: HiddenFinding[]): string {
  const titles = [...new Set(findings.map((f) => f.title))];
  return `${findings.length} sign${findings.length === 1 ? "" : "s"} of instructions hidden from the reader: ${titles.slice(0, 3).join("; ")}${titles.length > 3 ? "; …" : ""}`;
}
