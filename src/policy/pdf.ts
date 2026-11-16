/**
 * A small PDF writer: text pages with Helvetica/Courier, word wrapping and simple tables, no dependency. Enough for a
 * readable review summary whose every statement cites a file and record id; not a layout engine.
 */
type Line = { text: string; font: "F1" | "F2" | "F3"; size: number; indent?: number; gapAfter?: number };

const PAGE_W = 595.28, PAGE_H = 841.89, MARGIN = 48, LINE_H = 1.32;
// Helvetica average glyph width ≈ 0.5em; Courier 0.6em. Good enough for wrapping.
const avg = (font: Line["font"], size: number) => size * (font === "F3" ? 0.6 : 0.5);

function esc(s: string) { return s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)").replace(/[^\x20-\x7e]/g, (c) => ({ "—": "-", "–": "-", "·": "*", "“": '"', "”": '"', "‘": "'", "’": "'", "…": "...", "→": "->", "✓": "OK", "✕": "X", "≤": "<=", "≥": ">=" } as Record<string, string>)[c] ?? "?"); }

function wrap(text: string, font: Line["font"], size: number, width: number): string[] {
  const maxChars = Math.max(10, Math.floor(width / avg(font, size)));
  const out: string[] = [];
  for (const para of text.split("\n")) {
    const words = para.split(/\s+/).filter(Boolean); let cur = "";
    for (const w of words) { if ((cur + " " + w).trim().length > maxChars && cur) { out.push(cur); cur = w; } else cur = (cur + " " + w).trim(); }
    out.push(cur);
  }
  return out;
}

export class Pdf {
  private lines: Line[] = [];
  title(t: string) { this.lines.push({ text: t, font: "F2", size: 17, gapAfter: 6 }); }
  h2(t: string) { this.lines.push({ text: t, font: "F2", size: 12, gapAfter: 3 }); }
  p(t: string, size = 9.5) { this.lines.push({ text: t, font: "F1", size, gapAfter: 4 }); }
  small(t: string) { this.lines.push({ text: t, font: "F1", size: 8, gapAfter: 3 }); }
  mono(t: string) { this.lines.push({ text: t, font: "F3", size: 8, gapAfter: 3 }); }
  banner(t: string) { this.lines.push({ text: t, font: "F2", size: 9, gapAfter: 6 }); }
  /** Rows rendered in Courier so columns align; widths in characters. */
  table(head: string[], rows: string[][], widths: number[]) {
    const fmt = (cells: string[]) => cells.map((c, i) => { const w = widths[i]; const s = c.length > w ? c.slice(0, w - 1) + "…" : c; return s.padEnd(w); }).join(" ");
    this.lines.push({ text: fmt(head), font: "F3", size: 7.5 });
    this.lines.push({ text: "-".repeat(widths.reduce((a, b) => a + b, 0) + widths.length - 1), font: "F3", size: 7.5 });
    for (const r of rows) this.lines.push({ text: fmt(r), font: "F3", size: 7.5 });
    this.lines.push({ text: "", font: "F1", size: 6, gapAfter: 4 });
  }
  build(): Uint8Array {
    const width = PAGE_W - 2 * MARGIN;
    const pages: string[][] = [[]]; let y = PAGE_H - MARGIN;
    const put = (s: string) => pages[pages.length - 1].push(s);
    for (const ln of this.lines) {
      const pieces = ln.font === "F3" ? [ln.text] : wrap(ln.text, ln.font, ln.size, width - (ln.indent ?? 0));
      for (const piece of pieces) {
        if (y - ln.size * LINE_H < MARGIN) { pages.push([]); y = PAGE_H - MARGIN; }
        y -= ln.size * LINE_H;
        put(`BT /${ln.font} ${ln.size} Tf ${MARGIN + (ln.indent ?? 0)} ${y.toFixed(2)} Td (${esc(piece)}) Tj ET`);
      }
      y -= ln.gapAfter ?? 0;
    }
    // Objects: 1 catalog, 2 pages, 3-5 fonts, then per page: page obj + content obj.
    const objs: string[] = [];
    const add = (s: string) => { objs.push(s); return objs.length; };
    const fontIds = [add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"), add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"), add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")];
    const pagesId = objs.length + 1; objs.push(""); // placeholder
    const pageIds: number[] = [];
    for (const content of pages) {
      const stream = content.join("\n");
      const cid = add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
      pageIds.push(add(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 ${fontIds[0]} 0 R /F2 ${fontIds[1]} 0 R /F3 ${fontIds[2]} 0 R >> >> /Contents ${cid} 0 R >>`));
    }
    objs[pagesId - 1] = `<< /Type /Pages /Kids [${pageIds.map((i) => `${i} 0 R`).join(" ")}] /Count ${pageIds.length} >>`;
    const catalogId = add(`<< /Type /Catalog /Pages ${pagesId} 0 R >>`);
    let out = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"; const offsets: number[] = [];
    objs.forEach((o, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
    const xref = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("") + `trailer\n<< /Size ${objs.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    // Every character is in the Latin-1 range (text is escaped to ASCII above), so one character is one byte.
    return Uint8Array.from(out, (ch) => ch.charCodeAt(0) & 0xff);
  }
}
