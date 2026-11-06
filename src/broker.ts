/**
 * Credential broker for `vet-skills run --secrets NAME=host[,NAME=host…]`.
 *
 * The server never sees the real value of a brokered secret. Its environment carries a placeholder; the guard holds
 * the value and substitutes it into requests the server makes to the host the secret is bound to, and nowhere else.
 * A placeholder sent anywhere else (another host, a tool result, a log) is worthless, and the guard reports it when
 * it can see it. So a server that would read GITHUB_TOKEN from its environment and post it to collect.evil.xyz posts
 * a random string, while its calls to api.github.com work exactly as before.
 *
 * How: the allow-list proxy terminates TLS for bound hosts with a certificate from a throwaway CA created for this
 * run (openssl; private key in a 0700 directory under ~/.vet-skills/runtime, deleted at exit). The server trusts
 * the CA through NODE_EXTRA_CA_CERTS / SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE, which cover Node, Python
 * (requests, httpx, urllib via SSL_CERT_FILE), curl, Go and Rust clients. Headers, the URL and bodies up to 4 MB are
 * rewritten; larger bodies pass through unchanged. Other hosts are tunneled opaquely as before.
 *
 * Secrets bound to a host that is not in the network allow-list are added to it: a brokered secret implies the host.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { rootCertificates } from "node:tls";
import { HOME } from "./state.js";

export interface SecretBinding { name: string; host: string; value: string; placeholder: string }

/** `GITHUB_TOKEN=api.github.com,SLACK_BOT_TOKEN=slack.com`; the value comes from the guard's own environment. */
export function parseSecrets(spec: string, env: NodeJS.ProcessEnv = process.env): { bindings: SecretBinding[]; missing: string[]; error?: string } {
  const bindings: SecretBinding[] = []; const missing: string[] = [];
  for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=([A-Za-z0-9.-]+)$/.exec(part);
    if (!m) return { bindings, missing, error: `--secrets: "${part}" is not NAME=host` };
    const value = env[m[1]];
    if (!value) { missing.push(m[1]); continue; }
    bindings.push({ name: m[1], host: m[2].toLowerCase(), value, placeholder: `vsk_${m[1].toLowerCase()}_${randomBytes(12).toString("hex")}` });
  }
  return { bindings, missing };
}

/** The server's environment: placeholders in place of values, and the run's CA where every common client looks. */
export function brokerEnv(bindings: SecretBinding[], caBundle: string, caOnly: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const b of bindings) out[b.name] = b.placeholder;
  // Node appends; the others replace, so they get the bundle (system roots + ours).
  out.NODE_EXTRA_CA_CERTS = caOnly;
  out.SSL_CERT_FILE = caBundle; out.REQUESTS_CA_BUNDLE = caBundle; out.CURL_CA_BUNDLE = caBundle; out.GIT_SSL_CAINFO = caBundle; out.DENO_CERT = caOnly; out.NODE_TLS_REJECT_UNAUTHORIZED = "1";
  return out;
}

/** Substitute placeholders for the secrets bound to `host` in a header/URL/body string; report others seen. */
export function substitute(text: string, host: string, bindings: SecretBinding[]): { text: string; used: SecretBinding[]; refused: SecretBinding[] } {
  const used: SecretBinding[] = []; const refused: SecretBinding[] = [];
  let out = text;
  for (const b of bindings) {
    if (!out.includes(b.placeholder)) continue;
    if (host === b.host || host.endsWith(`.${b.host}`)) { out = out.split(b.placeholder).join(b.value); used.push(b); }
    else refused.push(b);
  }
  return { text: out, used, refused };
}

/** A throwaway CA for one run, plus leaf certificates per host, all made with the system's openssl. */
export class RunCA {
  readonly dir: string;
  readonly caPem: string; readonly caBundle: string;
  private readonly caKey: string;
  private readonly leaves = new Map<string, { key: string; cert: string }>();
  private constructor(dir: string, caPem: string, caKey: string, caBundle: string) { this.dir = dir; this.caPem = caPem; this.caKey = caKey; this.caBundle = caBundle; }

  static create(): RunCA {
    if (spawnSync("openssl", ["version"], { stdio: "ignore" }).status !== 0) throw new Error("openssl is not installed; --secrets needs it to issue the run's certificates");
    const dir = join(HOME, "runtime", `broker-${process.pid}-${randomBytes(4).toString("hex")}`);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const key = join(dir, "ca.key"), pem = join(dir, "ca.pem");
    run(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", pem, "-days", "2", "-subj", `/CN=vet-skills run broker ${randomBytes(4).toString("hex")}`, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
    const bundle = join(dir, "ca-bundle.pem");
    writeFileSync(bundle, rootCertificates.join("\n") + "\n" + readFileSync(pem, "utf8"), { mode: 0o600 });
    return new RunCA(dir, pem, key, bundle);
  }

  /** Key and certificate for `host`, issued on first use. */
  leaf(host: string): { key: string; cert: string } {
    const have = this.leaves.get(host); if (have) return have;
    const safe = host.replace(/[^a-z0-9.-]/gi, "_");
    const key = join(this.dir, `${safe}.key`), csr = join(this.dir, `${safe}.csr`), cert = join(this.dir, `${safe}.pem`), ext = join(this.dir, `${safe}.ext`);
    const san = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? `IP:${host}` : `DNS:${host}`;
    writeFileSync(ext, `subjectAltName=${san}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n`);
    run(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", csr, "-subj", `/CN=${host}`]);
    run(["x509", "-req", "-in", csr, "-CA", this.caPem, "-CAkey", this.caKey, "-CAcreateserial", "-out", cert, "-days", "2", "-extfile", ext]);
    const out = { key: readFileSync(key, "utf8"), cert: readFileSync(cert, "utf8") };
    this.leaves.set(host, out);
    return out;
  }

  /** Delete every key and certificate of the run. */
  wipe() { try { rmSync(this.dir, { recursive: true, force: true }); } catch { /* best effort */ } }
}

function run(args: string[]) {
  const r = spawnSync("openssl", args, { stdio: ["ignore", "ignore", "pipe"] });
  if (r.status !== 0) throw new Error(`openssl ${args[0]} failed: ${r.stderr?.toString().trim().split("\n").pop() ?? r.status}`);
}
