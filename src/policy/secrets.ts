/**
 * Committed-secret detection for agent configuration files. Finds credential
 * VALUES that were pasted into .mcp.json, claude_desktop_config.json and
 * friends by their format. Only the kind, file and line are returned; the
 * value is never stored, logged or shown.
 */
export type SecretKind =
  | "github_token" | "github_app_token" | "gitlab_token" | "aws_access_key" | "openai_key" | "anthropic_key" | "google_api_key"
  | "slack_token" | "stripe_live_key" | "stripe_test_key" | "npm_token" | "pypi_token" | "sendgrid_key" | "twilio_key"
  | "hf_token" | "private_key" | "database_url" | "jwt" | "generic_bearer";

export interface SecretFinding { kind: SecretKind; label: string; file: string; line: number; /** A credential in a known key for it ("env": {"GITHUB_TOKEN": "ghp_…"}) vs. any string. */ keyName: string | null }

const RULES: { kind: SecretKind; label: string; re: RegExp }[] = [
  { kind: "github_token", label: "GitHub personal access token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { kind: "github_app_token", label: "GitHub fine-grained token", re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { kind: "gitlab_token", label: "GitLab personal access token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { kind: "aws_access_key", label: "AWS access key id", re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { kind: "anthropic_key", label: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{30,}\b/ },
  { kind: "openai_key", label: "OpenAI API key", re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b/ },
  { kind: "google_api_key", label: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: "slack_token", label: "Slack token", re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/ },
  { kind: "stripe_live_key", label: "Stripe live secret key", re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/ },
  { kind: "stripe_test_key", label: "Stripe test secret key", re: /\b(?:sk|rk)_test_[0-9A-Za-z]{20,}\b/ },
  { kind: "npm_token", label: "npm access token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { kind: "pypi_token", label: "PyPI API token", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b/ },
  { kind: "sendgrid_key", label: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { kind: "twilio_key", label: "Twilio API key", re: /\bSK[0-9a-f]{32}\b/ },
  { kind: "hf_token", label: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{30,}\b/ },
  { kind: "private_key", label: "Private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { kind: "database_url", label: "Database URL with password", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@"']+:[^\s@"']{4,}@[^\s"']+/i },
  { kind: "jwt", label: "JWT", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

/** Placeholders people leave in example configs; never a finding. */
const PLACEHOLDER = /(your|xxx+|example|placeholder|<[^>]+>|\$\{|\$[A-Z_]{3,}|\.\.\.|changeme|redacted|dummy|sample|insert|replace|todo|_here\b|\*{3,})/i;

/** Named keys whose string value is a credential regardless of format (a 40-char hex next to "token": is still a leak). */
const SENSITIVE_KEY = /(token|secret|password|passwd|api[_-]?key|apikey|private[_-]?key|access[_-]?key|auth(?:orization)?|credential|client[_-]?secret)/i;

function findKeyName(text: string, index: number): string | null {
  const before = text.slice(Math.max(0, index - 160), index);
  const m = [...before.matchAll(/"([A-Za-z0-9_.-]{2,64})"\s*:\s*"?[^"\n]*$/g)].pop() ?? [...before.matchAll(/([A-Za-z0-9_.-]{2,64})\s*=\s*"?[^"\n]*$/g)].pop();
  return m ? m[1] : null;
}

/** Committed credential values in one config file. */
export function findSecrets(path: string, text: string): SecretFinding[] {
  const out: SecretFinding[] = [];
  const seen = new Set<number>();
  const add = (kind: SecretKind, label: string, index: number, keyName: string | null) => {
    const line = text.slice(0, index).split("\n").length;
    if (seen.has(line)) return; // one finding per line: a ghp_ value under "token" is one leak, not two
    seen.add(line);
    out.push({ kind, label, file: path, line, keyName });
  };
  for (const r of RULES) {
    const re = new RegExp(r.re.source, r.re.flags.includes("g") ? r.re.flags : r.re.flags + "g");
    let m: RegExpExecArray | null;
    let n = 0;
    while ((m = re.exec(text)) && n < 20) {
      n++;
      const window = text.slice(Math.max(0, m.index - 40), m.index + m[0].length + 10);
      if (PLACEHOLDER.test(window) && r.kind !== "private_key") continue;
      add(r.kind, r.label, m.index, findKeyName(text, m.index));
    }
  }
  // "GITHUB_TOKEN": "<24+ chars that is not a placeholder or a ${REF}>" in env/headers blocks: a credential by position.
  const kv = /"([A-Za-z0-9_.-]{2,64})"\s*:\s*"([^"\n]{20,})"/g;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = kv.exec(text)) && n < 200) {
    n++;
    const [, key, raw] = m;
    if (!SENSITIVE_KEY.test(key)) continue;
    const val = raw.replace(/^(bearer|basic|token)\s+/i, "").trim();
    if (val.length < 20 || PLACEHOLDER.test(val) || /^\$|^https?:\/\//i.test(val) || /\s/.test(val)) continue;
    if (!/[A-Za-z]/.test(val) || !/[0-9]/.test(val)) continue;
    add("generic_bearer", `Credential value under "${key}"`, m.index, key);
  }
  return out;
}

export const SECRET_LABEL: Record<SecretKind, string> = Object.fromEntries(RULES.map((r) => [r.kind, r.label])) as Record<SecretKind, string>;
SECRET_LABEL.generic_bearer = "Credential value";
