/** Terminal rendering that mirrors the CLI mockups' palette. Colors are off when not a TTY or NO_COLOR is set. */
const on = !!process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code: string) => (s: string) => (on ? `\x1b[${code}m${s}\x1b[0m` : s);
type RGB = readonly [number, number, number];
const rgb = ([r, g, b]: RGB) => `38;2;${r};${g};${b}`;
const bg = ([r, g, b]: RGB) => `48;2;${r};${g};${b}`;

const tones = {
  verified: [127, 184, 255], caution: [247, 198, 92], blocked: [255, 123, 128], lime: [200, 240, 75],
  ink2: [179, 188, 201], muted: [138, 148, 163], faint: [92, 102, 117], neutral: [179, 188, 201],
} as const satisfies Record<string, RGB>;
const bgs = { verified: [15, 36, 64], caution: [58, 42, 14], blocked: [58, 21, 24], neutral: [23, 27, 33], lime: [200, 240, 75] } as const satisfies Record<string, RGB>;

export const c = {
  verified: wrap(rgb(tones.verified)),
  caution: wrap(rgb(tones.caution)),
  blocked: wrap(rgb(tones.blocked)),
  lime: wrap(rgb(tones.lime)),
  ink2: wrap(rgb(tones.ink2)),
  muted: wrap(rgb(tones.muted)),
  faint: wrap(rgb(tones.faint)),
  bold: wrap("1"),
  pill: (s: string, tone: keyof typeof bgs) => (on ? `\x1b[1;${rgb(tones[tone === "lime" ? "lime" : tone])};${bg(bgs[tone])}m ${s} \x1b[0m` : `[${s}]`),
  score: (n: number, tone: keyof typeof tones) => wrap(`1;${rgb(tones[tone])}`)(String(n)),
  prompt: wrap(rgb(tones.lime)),
};

export function pad(s: string, n: number) {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

export function fmtInstalls(n: number) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 10_000) return `${Math.round(n / 1_000)}K`;
  return n.toLocaleString("en-US");
}
