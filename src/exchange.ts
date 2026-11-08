/**
 * Short-lived credentials. The broker already keeps the real value out of the server; this keeps a real value worth
 * stealing from existing at all. Before launch, the long-lived credential on the machine is exchanged for a scoped
 * token that lives minutes, the broker binds *that* to the vendor host, and at exit the token is revoked where the
 * vendor allows. A compromised server that somehow got the live value holds something dead within the hour.
 *
 *   github_app      JWT (RS256, the App's private key on this machine) → installation access token, scoped to the
 *                   repositories and permissions the policy names; 1 h lifetime (GitHub's); revoked at exit.
 *   aws_sts         `aws sts assume-role` with the policy's role, 900–3600 s, optional inline session policy.
 *   gcp_impersonate `gcloud auth print-access-token --impersonate-service-account`, ≤ 1 h.
 *
 * Nothing here is a credential store: the machine's own secrets (the App key, the AWS profile, gcloud's login) stay
 * where they are and are read only to mint.
 */
import { spawnSync } from "node:child_process";
import { createSign, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type { ExchangeRule } from "./policy/index.js";

export interface Minted {
  /** Variables to put in the environment the broker reads (then replaced by placeholders for the server). */
  values: Record<string, string>;
  /** Host the minted values are bound to. */
  host: string;
  expiresAt: Date;
  kind: ExchangeRule["kind"];
  scope: string;
  revoke?: () => Promise<void>;
}

const DEFAULT_HOST: Record<ExchangeRule["kind"], string> = { github_app: "api.github.com", aws_sts: "amazonaws.com", gcp_impersonate: "googleapis.com" };

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64url");

/** RS256 JWT for a GitHub App: iat 60 s in the past (clock skew), 9 min lifetime. */
export function githubAppJwt(appId: string, privateKeyPem: string, now = Math.floor(Date.now() / 1000)): string {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }));
  const signer = createSign("RSA-SHA256"); signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${b64url(signer.sign(privateKeyPem))}`;
}

async function mintGithub(rule: ExchangeRule, env: NodeJS.ProcessEnv, fetchFn: typeof fetch): Promise<Minted> {
  const appId = rule.appId ?? env.VET_GITHUB_APP_ID;
  const installationId = rule.installationId ?? env.VET_GITHUB_INSTALLATION_ID;
  const keyPem = env.VET_GITHUB_APP_KEY ?? (env.VET_GITHUB_APP_KEY_FILE && existsSync(env.VET_GITHUB_APP_KEY_FILE) ? readFileSync(env.VET_GITHUB_APP_KEY_FILE, "utf8") : null);
  if (!appId || !installationId || !keyPem) throw new Error(`github_app needs app_id, installation_id (policy or VET_GITHUB_APP_ID / VET_GITHUB_INSTALLATION_ID) and the App's private key in VET_GITHUB_APP_KEY_FILE on this machine`);
  const jwt = githubAppJwt(appId, keyPem);
  const body: Record<string, unknown> = {};
  if (rule.repositories?.length) body.repositories = rule.repositories.map((r) => r.split("/").pop());
  if (rule.permissions && Object.keys(rule.permissions).length) body.permissions = rule.permissions;
  const res = await fetchFn(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}/access_tokens`, { method: "POST", headers: { authorization: `Bearer ${jwt}`, accept: "application/vnd.github+json", "user-agent": "vet-skills-guard", "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`GitHub refused the installation token (${res.status}): ${(await res.text()).slice(0, 200)}`);
  const data = (await res.json()) as { token: string; expires_at: string; permissions?: Record<string, string>; repository_selection?: string };
  const scope = `${rule.repositories?.length ? `${rule.repositories.length} repo${rule.repositories.length === 1 ? "" : "s"}` : data.repository_selection ?? "installation"}${data.permissions ? ` · ${Object.entries(data.permissions).map(([k, v]) => `${k}:${v}`).join(" ")}` : ""}`;
  const token = data.token;
  return {
    values: { [rule.var]: token }, host: rule.host ?? DEFAULT_HOST.github_app, expiresAt: new Date(data.expires_at), kind: "github_app", scope,
    revoke: async () => { await fetchFn("https://api.github.com/installation/token", { method: "DELETE", headers: { authorization: `token ${token}`, accept: "application/vnd.github+json", "user-agent": "vet-skills-guard" } }).catch(() => null); },
  };
}

function mintAws(rule: ExchangeRule, env: NodeJS.ProcessEnv): Minted {
  if (!rule.roleArn) throw new Error("aws_sts needs role_arn in the policy");
  const duration = Math.min(3600, Math.max(900, rule.durationSeconds ?? 900));
  const args = ["sts", "assume-role", "--role-arn", rule.roleArn, "--role-session-name", `vet-skills-${randomBytes(4).toString("hex")}`, "--duration-seconds", String(duration), "--output", "json"];
  if (rule.sessionPolicy) args.push("--policy", rule.sessionPolicy);
  const r = spawnSync("aws", args, { encoding: "utf8", env, timeout: 20_000 });
  if (r.error || r.status !== 0) throw new Error(`aws sts assume-role failed: ${(r.stderr || r.error?.message || "").trim().slice(0, 300) || "is the AWS CLI installed and a profile configured?"}`);
  const c = (JSON.parse(r.stdout) as { Credentials: { AccessKeyId: string; SecretAccessKey: string; SessionToken: string; Expiration: string } }).Credentials;
  return { values: { AWS_ACCESS_KEY_ID: c.AccessKeyId, AWS_SECRET_ACCESS_KEY: c.SecretAccessKey, AWS_SESSION_TOKEN: c.SessionToken }, host: rule.host ?? DEFAULT_HOST.aws_sts, expiresAt: new Date(c.Expiration), kind: "aws_sts", scope: `${rule.roleArn.split("/").pop()} · ${duration}s${rule.sessionPolicy ? " · session policy" : ""}` };
}

function mintGcp(rule: ExchangeRule, env: NodeJS.ProcessEnv): Minted {
  if (!rule.serviceAccount) throw new Error("gcp_impersonate needs service_account in the policy");
  const lifetime = Math.min(3600, Math.max(300, rule.durationSeconds ?? 600));
  const args = ["auth", "print-access-token", `--impersonate-service-account=${rule.serviceAccount}`, `--lifetime=${lifetime}s`];
  if (rule.scopes?.length) args.push(`--scopes=${rule.scopes.join(",")}`);
  const r = spawnSync("gcloud", args, { encoding: "utf8", env, timeout: 20_000 });
  if (r.error || r.status !== 0) throw new Error(`gcloud impersonation failed: ${(r.stderr || r.error?.message || "").trim().slice(0, 300) || "is gcloud installed and logged in?"}`);
  return { values: { [rule.var]: r.stdout.trim() }, host: rule.host ?? DEFAULT_HOST.gcp_impersonate, expiresAt: new Date(Date.now() + lifetime * 1000), kind: "gcp_impersonate", scope: `${rule.serviceAccount} · ${lifetime}s` };
}

/** Mint for one rule. Throws with a one-line reason; the caller decides whether to fall back to the long-lived value. */
export async function mint(rule: ExchangeRule, env: NodeJS.ProcessEnv = process.env, fetchFn: typeof fetch = fetch): Promise<Minted> {
  if (rule.kind === "github_app") return mintGithub(rule, env, fetchFn);
  if (rule.kind === "aws_sts") return mintAws(rule, env);
  return mintGcp(rule, env);
}

/** `--secrets` spec for the minted values, so the broker binds them like any other credential. */
export function secretsSpecFor(m: Minted[]): string {
  return m.flatMap((x) => Object.keys(x.values).map((k) => `${k}=${x.host}`)).join(",");
}
