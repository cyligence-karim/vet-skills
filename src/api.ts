/** HTTP client for the verdict API and the org API. Every call is fail-open: errors return `null` plus a reason. */
import { API, VERSION, clientId, readOrg, readToken, type ResolveResponse } from "./state.js";

export type ApiResult<T> = { ok: true; data: T; etag?: string } | { ok: false; status?: number; error: string; offline: boolean };

async function call<T>(path: string, init: RequestInit = {}, timeoutMs = 8000): Promise<ApiResult<T>> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${API}${path}`, {
      ...init,
      signal: ctrl.signal,
      headers: { accept: "application/json", "content-type": "application/json", "x-vs-client": clientId(), "user-agent": `vet-skills/${VERSION}`, ...(init.headers ?? {}) },
    });
    const text = await res.text();
    const data = text ? (JSON.parse(text) as T) : (null as T);
    if (!res.ok) return { ok: false, status: res.status, error: (data as { error?: string })?.error ?? res.statusText, offline: res.status >= 500 };
    return { ok: true, data, etag: res.headers.get("etag") ?? undefined };
  } catch (e) {
    return { ok: false, error: (e as Error).message, offline: true };
  } finally {
    clearTimeout(t);
  }
}

export function resolveSkill(q: string, registry?: string, surface?: "mcp") {
  const qs = new URLSearchParams({ q });
  if (registry) qs.set("registry", registry);
  // The agent token (when enrolled) lets resolve answer for the org's private registry.
  return call<ResolveResponse>(`/api/v1/resolve?${qs}`, { headers: { ...orgHeaders(), ...(surface ? { "x-vs-surface": surface } : {}) } });
}

export function verdictByHash(hash: string, etag?: string) {
  return call<ResolveResponse>(`/api/v1/verdicts/${hash}`, { headers: etag ? { "if-none-match": `"${etag}"` } : {} });
}

function orgHeaders(): Record<string, string> {
  const token = readToken();
  return token ? { authorization: `Bearer ${token}` } : {};
}

export type EnrollResponse = { agent_id: string; agent_token: string; policy_yaml: string; policy_version: number; enforcement: "observe" | "enforce"; org: { slug: string; name: string } };

export function enroll(slug: string, enrollToken: string, body: Record<string, unknown>) {
  return call<EnrollResponse>(`/api/v1/orgs/${slug}/enroll`, { method: "POST", body: JSON.stringify(body), headers: { authorization: `Bearer ${enrollToken}` } }, 8000);
}

export type EvaluateResponse = {
  decision: "allow" | "sandbox" | "approval_required" | "block" | "defer" | "observe";
  would_be: string; reason: string; restrictions?: Record<string, unknown>; approval_request_id?: string; job_id?: string; policy_version: number; last_safe_version?: { semver: string; score: number } | null;
};

export function evaluateRemote(body: Record<string, unknown>) {
  const org = readOrg();
  if (!org) return Promise.resolve<ApiResult<EvaluateResponse>>({ ok: false, error: "not joined", offline: false });
  return call<EvaluateResponse>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/evaluate`, { method: "POST", body: JSON.stringify(body), headers: orgHeaders() });
}

export type ReportResponse = { policy_version: number; policy_yaml?: string; enforcement: "observe" | "enforce"; require_guard?: boolean; pending_removals: { removal_id: string; install_id: string; skill: string }[]; pending_approvals: { request_id: string; status: string; skill: string }[] };

export function report(body: Record<string, unknown>) {
  const org = readOrg();
  if (!org) return Promise.resolve<ApiResult<ReportResponse>>({ ok: false, error: "not joined", offline: false });
  return call<ReportResponse>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/report`, { method: "POST", body: JSON.stringify(body), headers: orgHeaders() }, 8000);
}

/** Runtime deviations observed in a session (enrolled machines only). */
export function runtimeReport(body: { events: { skill: string; semver: string | null; kind: string; detail: string; tool: string; at: string; session: string | null; allowed?: boolean; context?: string | null }[] }) {
  const org = readOrg();
  if (!org) return Promise.resolve<ApiResult<{ ok: true }>>({ ok: false, error: "not joined", offline: false });
  return call<{ ok: true }>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/runtime`, { method: "POST", body: JSON.stringify(body), headers: orgHeaders() }, 6000);
}

/** One guarded MCP server session (or a progress snapshot of one), from `vet-skills guard exec` on an enrolled machine. */
export interface GuardSessionReport {
  session: string; server: string; client: string; pkg: string | null; registry: string | null; semver: string | null;
  started: string; ended: string | null; final: boolean; exit_code: number | null; machine: string; cwd_hash: string | null;
  hosts: { host: string; port: number; mode: string; expected: boolean; first_seen_here: boolean }[];
  tools: { tool: string; calls: number; denied: number; approved: number }[];
  secrets: { name: string; host: string; refused: boolean; exchange?: { kind: string; scope: string; expires: string } }[];
  canary: boolean; poison: string[]; launch: "ran" | "refused" | "warned"; launch_reason: string | null;
  guard_version: string; policy_version: number | null;
  /** Per-call decisions (deny/held always; allow folded per tool and minute). Key names only. */
  decisions?: { tool: string; outcome: "allow" | "deny" | "held"; rule: string; at: string; count: number; reply_observed: boolean | null; approval_id: string | null; disposition: string | null; arg_keys: string[] }[];
}
export function guardReport(body: GuardSessionReport) {
  const org = readOrg();
  if (!org) return Promise.resolve<ApiResult<{ ok: true; alerts?: { kind: string; detail: string }[] }>>({ ok: false, error: "not joined", offline: false });
  return call<{ ok: true; alerts?: { kind: string; detail: string }[] }>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/guard`, { method: "POST", body: JSON.stringify(body), headers: orgHeaders() }, 6000);
}
/** Anonymous field sighting from a machine not in an org: package, version, hosts and whether anything refused. Nothing about the user, the server label, the tools or the arguments. */
export function guardSighting(body: { pkg: string; registry: string | null; semver: string | null; hosts: { host: string; expected: boolean }[]; placeholder_refused: boolean; canary: boolean; guard_version: string; os: string }) {
  return call<{ ok: true }>(`/api/v1/runtime/sightings`, { method: "POST", body: JSON.stringify(body) }, 6000);
}
/** Before launching: is this version flagged across the network? `revoked` refuses; `under_review` warns. */
export function launchCheck(pkg: string, semver: string | null, registry?: string | null) {
  const qs = new URLSearchParams({ pkg }); if (semver) qs.set("semver", semver); if (registry) qs.set("registry", registry);
  return call<{ state: "clear" | "under_review" | "revoked"; reason: string | null; page: string | null; sightings?: { installs: number; hosts: number } }>(`/api/v1/runtime/launch-check?${qs}`, { headers: orgHeaders() }, 3000);
}
/** Approval of a held tool call (enrolled machines): create, then poll until decided or the deadline passes. */
export function approvalCreate(body: { server: string; pkg: string | null; semver: string | null; tool: string; arg_keys: string[]; arg_preview: string; reason: string | null; session: string; timeout_seconds: number }) {
  const org = readOrg();
  if (!org) return Promise.resolve<ApiResult<{ id: string; url: string }>>({ ok: false, error: "not joined", offline: false });
  return call<{ id: string; url: string }>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/tool-approvals`, { method: "POST", body: JSON.stringify(body), headers: orgHeaders() }, 6000);
}
export function approvalPoll(id: string) {
  const org = readOrg();
  if (!org) return Promise.resolve<ApiResult<{ status: "pending" | "approved" | "denied" | "expired"; by: string | null }>>({ ok: false, error: "not joined", offline: false });
  return call<{ status: "pending" | "approved" | "denied" | "expired"; by: string | null }>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/tool-approvals/${id}`, { headers: orgHeaders() }, 6000);
}

/** One-time activation signal when the guard is installed on a machine: counts and client names, nothing else. Telemetry opt-out applies. */
export function funnelGuardInstall(body: { servers: number; clients: string[]; version: string; os: string }) {
  return call<{ ok: true }>(`/api/v1/funnel`, { method: "POST", body: JSON.stringify({ kind: "guard_install", ...body }) }, 4000);
}

export function confirmRemoval(removalId: string, body: { status: "confirmed" | "failed"; detail?: string }) {
  const org = readOrg();
  if (!org) return Promise.resolve<ApiResult<{ ok: boolean }>>({ ok: false, error: "not joined", offline: false });
  return call<{ ok: boolean }>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/removals/${removalId}/confirm`, { method: "POST", body: JSON.stringify(body), headers: orgHeaders() });
}

export interface DetonateResponse {
  verdict: { id: string; score: number; label: "verified" | "caution" | "blocked"; components: { behavior: number; static: number; prompt: number; publisher: number }; overrides: string[]; engine_version: string; scenarios_run: number; duration_ms: number };
  findings: { rule_id: string; severity: string; title: string; detail: string; file?: string | null; line?: number | null; evidence?: string | null }[];
  trace: { events?: { t_ms: number; scenario: string; category: string; action: string; target: string; detail: string; severity: string; decoy_hit?: string | null }[]; egress_hosts: { host: string; declared: boolean; implied?: string }[]; files_read: string[]; memory_writes: { file: string }[]; tool_shadowing: { tool: string }[]; coverage?: { level: "full" | "startup_only" | "install_failed" | "install_only"; summary: string; tested: string[]; untested: string[]; needs: string[] } | null } | null;
  credentials?: import("./state.js").CredentialSurface | null;
  benchmark?: { instruction_tokens: number; instruction_files: number; bundle_files: number; bundle_bytes: number; mcp: { handshake_ms: number | null; tools: number; context_tokens: number; description_chars_avg: number; undocumented_tools: number } | null } | null;
  skill: { name: string; semver: string; artifact_hash: string; registry: string; publisher: string; page: string; report?: string };
}
export interface PublishResponse {
  verdict: { id: string; score: number; label: "verified" | "caution" | "blocked"; engine_version: string; scenarios_run: number; duration_ms: number };
  findings: { rule_id: string; severity: string; title: string; detail: string }[];
  skill: { name: string; semver: string; artifact_hash: string; registry: string; publisher: string; page: string; created: boolean };
}
/** Publish a gzipped bundle to the enrolled org's private registry (detonated first). */
export function publish(tgz: Uint8Array) {
  const org = readOrg();
  if (!org) return Promise.resolve({ ok: false as const, status: 0, error: "not enrolled in an organization (vet-skills join <org> --token …)", offline: false });
  return call<PublishResponse>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/publish`, { method: "POST", body: new Blob([tgz as BlobPart]), headers: { "content-type": "application/gzip", ...orgHeaders() } }, 180_000);
}

/** Upload a gzipped bundle for synchronous detonation. Generous timeout: a run takes seconds, not milliseconds. */
export function detonate(tgz: Uint8Array, opts: { publisher?: string } = {}) {
  const q = new URLSearchParams();
  return call<DetonateResponse>(`/api/v1/detonate?${q}`, { method: "POST", body: new Blob([tgz as BlobPart]), headers: { "content-type": "application/gzip", ...(opts.publisher ? { "x-vs-publisher": opts.publisher } : {}) } }, 180_000);
}

/** Fire-and-forget anonymous telemetry; short timeout so the hook never waits on it. */
export function sendTelemetry(body: Record<string, unknown>) {
  return call<{ ok: boolean }>("/api/v1/telemetry", { method: "POST", body: JSON.stringify(body) }, 1500);
}

/** Fire-and-forget anonymous field signal (runtime deviation kind per skill/version/tool); never detail text. */
export function sendFieldSignal(events: { skill: string; semver: string | null; kind: string; tool: string | null; agent_kind: string; hook_version: string; os: string }[]) {
  return call<{ ok: boolean }>("/api/v1/telemetry/field", { method: "POST", body: JSON.stringify({ events }) }, 1500);
}

/** What `vet-skills discover` found on this machine (names only; enrolled machines only). */
export function discoverReport(components: unknown[]) {
  const org = readOrg();
  if (!org) return Promise.resolve<ApiResult<{ ok: true; components: number; dashboard: string }>>({ ok: false, error: "not joined", offline: false });
  return call<{ ok: true; components: number; dashboard: string }>(`/api/v1/orgs/${org.slug}/agents/${org.agentId}/discover`, { method: "POST", body: JSON.stringify({ components }), headers: orgHeaders() }, 15000);
}

/** The public repo scan, for installs that point straight at GitHub (no registry verdict exists for those). */
export type RepoScan = { ok: true; repo: string; page: string; headline: string; installer_lure: boolean; lure_reasons: string[]; summary: { total: number; high: number; credentials: number; unvetted: number } };
export function scanGithubRepo(owner: string, repo: string) {
  return call<RepoScan>(`/api/v1/scan/github/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {}, 25000);
}
