/**
 * Control themes: where in a review pack a reviewer finds evidence relevant to a common control area. This is a map for
 * orientation. It names files and what each records; it does not say a control is designed well, operating, or met, and
 * it is not tied to any one framework's numbering.
 */
export interface ControlTheme { id: string; theme: string; evidence: { file: string; records: string }[] }
export const THEME_NOTE = "Evidence relevant to a theme is what the guard recorded that a reviewer may want to read for that area. Whether a control is met is the organization's and its auditor's judgment; this pack makes no such statement and is not a certification.";

/** The organization pack (schema arp-1.x). */
export const ORG_PACK_THEMES: ControlTheme[] = [
  { id: "access", theme: "Access control", evidence: [
    { file: "inventory.csv", records: "which agent tools each device has, their owner and how the owner is attributed" },
    { file: "sessions.csv", records: "which servers ran, the credential variables they were handed (names) and the hosts they reached" },
    { file: "decisions.csv", records: "tool calls the guard allowed, held or denied, by tool and argument names" },
    { file: "approvals.csv", records: "who approved or denied a held call or install, when, and through which channel" },
  ] },
  { id: "change", theme: "Change management", evidence: [
    { file: "policy_history.csv", records: "each policy version in force, when it took effect and who published it" },
    { file: "changes_and_revocations.csv", records: "revocations, policy changes and other governance changes, with actor and time" },
    { file: "approvals.csv", records: "held updates and tool-list changes, and who released them" },
    { file: "audit_events.csv", records: "the hash-chained audit trail the rows above were taken from" },
  ] },
  { id: "supply_chain", theme: "Vendor and supply chain risk", evidence: [
    { file: "inventory.csv", records: "package and version in use, the policy decision for it and its approval status" },
    { file: "exceptions.csv", records: "review items raised by fixed rules, such as a version in use with a blocked verdict or none" },
    { file: "changes_and_revocations.csv", records: "versions and remote hosts revoked during the period" },
  ] },
  { id: "logging", theme: "Logging and monitoring", evidence: [
    { file: "sessions.csv", records: "every guarded session reported, with its launch outcome" },
    { file: "decisions.csv", records: "per-call decisions, and whether a server reply was observed" },
    { file: "manifest.json", records: "what was collected, what was redacted, and the known gaps in the period" },
  ] },
];

/** The single-developer pack written by `vet-skills review-pack` (schema arp-local-1.0). */
export const LOCAL_PACK_THEMES: ControlTheme[] = [
  { id: "access", theme: "Access control", evidence: [
    { file: "inventory.json", records: "every MCP server each agent is configured with, guarded or not, and the credential names it is handed" },
    { file: "credentials.json", records: "for each credential name, the servers handed it and whether the value is held by the guard or written in a config" },
    { file: "tool_calls.csv", records: "tool calls by server and tool, and how many were allowed, approved after a hold or denied" },
  ] },
  { id: "change", theme: "Change management", evidence: [
    { file: "policy.yaml", records: "the policy in force on this machine when the pack was made, and where it came from" },
    { file: "events.csv", records: "held and warned updates, changed tool lists, refused launches and revocations, each with its time and log line" },
  ] },
  { id: "supply_chain", theme: "Vendor and supply chain risk", evidence: [
    { file: "inventory.json", records: "package, version and KillerSkills verdict for each server, and servers with no verdict" },
    { file: "events.csv", records: "launches refused because a version was blocked or revoked" },
  ] },
  { id: "logging", theme: "Logging and monitoring", evidence: [
    { file: "events.csv", records: "every hold, denial, refusal and change the guard recorded, with the line of the log it came from" },
    { file: "manifest.json", records: "the period, the files with their hashes, and what this pack does not cover" },
  ] },
];
