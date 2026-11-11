# vet-skills

Check agent skills and MCP servers before they run. Verdicts come from
[KillerSkills](https://killerskills.ai); the policy is yours or your org's.

```
npm i -g vet-skills                          # the CLI (Node 20+)
vet-skills guard install                     # every MCP server in Claude Code, Cursor, Windsurf, Codex, Gemini CLI, Grok CLI, Claude Desktop runs under the guard
vet-skills hook install all                  # Claude Code, Cursor, Codex, Windsurf, Gemini CLI, Grok CLI: install check, runtime observation, canaries
vet-skills check <skill>                     # or just ask before you add one
vet-skills publish ./my-skill                # org members: detonate + list in the private registry
```

## The guard: every MCP server, every time (0.8)

An MCP server is third-party code running on your machine with your tokens in
its environment. `vet-skills guard install` rewrites the MCP configs of Claude
Code, Claude Desktop, Cursor, Windsurf, Gemini CLI, Codex and Grok CLI so every stdio
server starts as `vet-skills guard exec … -- <original command>`. The agent
talks to the guard; the guard talks to the server. On every launch:

- **Credentials become placeholders.** The variables the package's verdict
  names as credentials are replaced in the server's environment; the real
  value is injected only into requests to the vendor's own hosts. A
  placeholder sent anywhere else is logged as an exfiltration attempt and the
  value never left the guard. No configuration: the binding comes from the
  package's own code (`--secrets NAME=host` still overrides it).
- **Every host is recorded.** Observe mode by default; the first time a
  version reaches a host that neither its verdict, its code nor an earlier
  session on this machine named, you are told on stderr. Policy
  `runtime.new_host: block` refuses it instead.
- **Flagged versions do not start.** A Blocked verdict, a confirmed incident
  or a revocation (by KillerSkills, or by your organization) is refused at
  launch with the reason: the kill switch reaches every guard at its next start.
- **Tool calls follow rules.** Policy `runtime.tools`: `allow`, `deny` or
  `approve` (held for a decision in the org's Runtime page or Slack; later
  calls queue behind it in order).
- **The session is written down** in `~/.vet-skills/runtime/guard.jsonl`:
  hosts, tool names and argument *keys* (never values), brokered and refused
  secrets, exit. Enrolled machines report it to the org's Runtime page; others,
  with telemetry on, send an anonymous sighting (package, version, hosts) that
  feeds the public "observed in the field" section and the honeypot re-run queue.

```
$ vet-skills guard install
✓ claude-code: supabase, github, filesystem now run under the guard (~/.claude.json)
✓ cursor: github now run under the guard (~/.cursor/mcp.json)
  claude-code: notion-remote skipped — remote server (http/sse); the guard wraps stdio servers
$ vet-skills guard status
$ vet-skills guard uninstall                 # originals back (also kept in ~/.vet-skills/guard/backup)
```

**Short-lived credentials** (`runtime.exchange` in the policy): instead of
brokering the long-lived value, the guard trades it before launch for a scoped
token that lives minutes — a GitHub App installation token (repositories and
permissions from the policy), an AWS STS role session (`aws sts assume-role`),
or a GCP impersonated access token (`gcloud`) — binds that to the vendor host,
renews it in long sessions and revokes it at exit where the vendor allows. The
server holds a placeholder for a credential that is dead within the hour. The
App key, AWS profile and gcloud login stay on the machine and are only read to mint.

Limits, stated: remote (http/sse) servers are not wrapped; a client that
ignores `HTTPS_PROXY` is not seen by the proxy; a client that pins certificates
is tunnelled opaquely after its first refused handshake, so placeholders sent to
that host cannot be inspected. The guard says so on stderr when either happens.

## Use it as an MCP server

Give any agent the verdicts directly, so it checks a skill or MCP server before
installing it and can pick a verified alternative. Read-only, no account, no API key.
Tools: `check_skill` (verdict, score, what the sandbox saw, top findings, last safe
version) and `search_skills` (the index by keyword, with verdicts).

**Claude Code**

```
claude mcp add killerskills -- npx -y vet-skills mcp
```

**Cursor**: `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project)

```json
{
  "mcpServers": {
    "killerskills": { "command": "npx", "args": ["-y", "vet-skills", "mcp"] }
  }
}
```

**Claude Desktop**: Settings → Developer → Edit Config (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "killerskills": { "command": "npx", "args": ["-y", "vet-skills", "mcp"] }
  }
}
```

**VS Code**: `.vscode/mcp.json`

```json
{
  "servers": {
    "killerskills": { "type": "stdio", "command": "npx", "args": ["-y", "vet-skills", "mcp"] }
  }
}
```

**Windsurf**: `~/.codeium/windsurf/mcp_config.json`, same `mcpServers` block as Cursor.
**Codex**: `~/.codex/config.toml`

```toml
[mcp_servers.killerskills]
command = "npx"
args = ["-y", "vet-skills", "mcp"]
```

Then ask your agent: *"Before you add that MCP server, check it with KillerSkills."*
Requires Node 20+. Index: 24,000+ skills and MCP servers from skills.sh, ClawHub,
npm, PyPI, the Docker MCP Catalog and Claude Code plugin marketplaces, each run in a
honeypot sandbox. Browse them at [killerskills.ai](https://killerskills.ai/?utm_source=npm&utm_medium=readme&utm_campaign=cli).

## Try it before you install it

```
vet-skills try @acme/crm-mcp            # npm package (or name@version)
vet-skills try pypi:some-mcp-server     # PyPI package
vet-skills try owner/repo               # GitHub repository
vet-skills try ./my-skill               # local directory
```

Fetches the package into a temp directory (never installed), runs it in the
KillerSkills honeypot, and prints what it did: every host it contacted, every
credential path it touched, the tools it exposes, and what it costs your agent
(instruction tokens; for MCP servers the handshake time and the prompt context of
its tool list). Exit code 2 when the run is Blocked.

## Injection in what comes back

The same hook that observes tool calls reads what `WebFetch`, `WebSearch`, `Read`,
`Bash`, `Grep` and every MCP tool return. When the content carries instructions
aimed at the agent ("ignore previous instructions", "do not tell the user", a hidden
HTML comment, invisible Unicode tag characters, a script piped to a shell), the hook
tells the agent before its next step, logs it, and reports the kind of finding to
your org when enrolled. Nothing from the content leaves the machine. `vet-skills
discover` applies the same rules to CLAUDE.md, AGENTS.md, MEMORY.md and every
installed SKILL.md; `vet-skills run` applies them to a live server's tool list and
results.

## Run it with restrictions

```
claude mcp add crm -- npx -y vet-skills run --net declared --deny "delete_*" -- npx -y @acme/crm-mcp
```

`vet-skills run` sits between the agent and a stdio MCP server. Denied tools are
answered with an error and never reach the server; every tool call is logged
(tool name and argument names only); `--net declared` points the server's
`HTTPS_PROXY` at a local allow-list proxy limited to the hosts its verdict saw it
declare (`--net host1,host2` to choose). When the install hook blocks a stdio
server, it prints this command as the alternative. Clients that ignore
`HTTPS_PROXY` are not network-contained, and the guard says so at start.

Add `--contain` (0.7.9) to put the server in an OS sandbox as well: on macOS
`sandbox-exec`, on Linux `bwrap` (bubblewrap). The project directory, `/tmp`
and the package caches stay writable; the rest of `$HOME` is read-only and
credential directories (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.kube`,
`~/.docker`, keychains, agent config folders, …) are not readable at all. On
macOS the sandbox also forbids every outbound connection except the local
proxy. Undeclared hosts get a fast, logged `403`, so a telemetry call fails
harmlessly and the tool keeps working; the exit summary counts them. Windows:
use WSL. Where neither sandbox is available the guard runs without it and says so.

```
claude mcp add crm -- npx -y vet-skills run --contain --net declared -- npx -y @acme/crm-mcp
```

### Credential broker: `--secrets` (0.7.13)

Most MCP servers need an API key in their environment, and a server that reads
`GITHUB_TOKEN` to call GitHub can just as easily post it somewhere else. With
`--secrets NAME=host[,NAME=host…]` the server never gets the value: its
environment holds a placeholder, the guard keeps the real value, and the
guard's proxy puts it into requests to the bound host only. A placeholder sent
anywhere else is a random string, and the guard reports the attempt (`✕ sent the
GITHUB_TOKEN placeholder to collect.evil.xyz`) and records it as a deviation.

```
GITHUB_TOKEN=ghp_… vet-skills run --secrets GITHUB_TOKEN=api.github.com -- npx -y @acme/github-mcp
```

How: the proxy terminates TLS for the allowed hosts with a certificate from a
throwaway CA made for that run (`openssl`, keys in a 0700 directory, deleted at
exit). The server trusts it through `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO`, which cover Node,
Python, curl, Go and Rust clients. Headers, the URL and bodies up to 4 MB are
rewritten. `--secrets` implies a network pin to the bound hosts (add `--net` to
widen it). A client that pins certificates will refuse the run's CA; use `--net`
without `--secrets` for that one.

## Canary credentials: proof, not a heuristic

```
vet-skills canary install
```

Plants decoy credential files beside the real ones (`~/.aws/credentials.old`,
`~/.config/gh/hosts.yml.old`, `~/.npmrc.old`, `~/.ssh/id_rsa_old`, `~/.env.old`),
only where no file exists, with random values kept in `~/.vet-skills/canaries.json`.
Nothing legitimate reads a forgotten backup, so a canary value showing up in
anything the agent sends or a tool returns is exfiltration by construction. The
hook stops the session and names the file kind (never the value); `vet-skills run`
refuses the call. `vet-skills canary` lists them, `canary remove` deletes only files
whose contents are still exactly what it wrote.

## Allowed because you asked for it

Not every credential read is an attack. The hook keeps a per-session intent
record: the hosts and paths you named in a prompt (extracted by a
`UserPromptSubmit` hook; the prompt itself is never stored) and the ones your
own tool calls touched. A skill's sensitive action that matches an entry from
the last 30 minutes is allowed with a one-line notice and recorded as a scoped
allow (this session, this skill, this resource, 30 minutes); the same action
with nothing to explain it is held and the agent is told to ask you.

```
vet-skills runtime allows        # scoped allows this week, with the reason
vet-skills runtime revoke <id>   # revoke one now
```

Policy `context:` turns this off per kind (`credential_read: hold`). No model
judges intent: the rule is the match, and it is printed.

## See what is already configured

```
vet-skills discover            # every MCP server, skill, plugin and hook on this machine, with verdicts
```

Reads Claude Code, Cursor, Windsurf, Claude Desktop, Gemini CLI, Codex and Grok CLI configs
locally. Each server and skill name is looked up for its verdict; nothing else leaves
the machine. When you are enrolled in an org, the list of names is also reported to
your team's Discovery page. Environment values, arguments and file contents never are.

It also inspects each installed skill folder for the installer-lure shape (a committed
ZIP or `.bat`, a LuaJIT runtime, Lua saved as `.txt`, files matching the Agent Lure
Stealer IOCs) and flags credential values pasted into config files, by kind and line
only; the value itself is never printed or sent.

## What it does

Every `skills add`, `claude plugin install`, and `claude mcp add` is resolved to
an artifact hash, looked up, and evaluated against your policy before it runs:

```
$ vet-skills check deploy-helper
Resolving deploy-helper …
vet-skills 0.7.8 · policy acme/default-strict

 BLOCKED  14/100 deploy-helper@2.3.1 · devtools-cloud · 4,210 installs

Observed in sandbox (3 scenarios, 38s):
  ✕ network    telemetry-cdn.xyz — undeclared
  ✕ memory     wrote agent memory (1)
  ✕ filesystem reads ~/.ssh/id_ed25519, ~/.aws/credentials, ~/.npmrc
  ! tools      shadows github.create_pr

Policy acme/default-strict:
  ✕ publisher blocked      devtools-cloud is on the block list

✕ Blocked deploy-helper@2.3.1 · publisher devtools-cloud is blocked by policy
Pin instead: deploy-helper@2.2.4 (score 88)
```

### Coverage, findings, recommendation (0.7.14)

Every verdict now says what the honeypot actually exercised before you read the
label. The label line carries a qualifier when the run was partial (`VERIFIED 85
· startup only`), and the report ends with three blocks:

```
Coverage  Started with a decoy SUPABASE_ACCESS_TOKEN and answered initialize; the tool list did not come back. Authenticated tool behavior not tested.
  tested      server startup with a tagged decoy in SUPABASE_ACCESS_TOKEN · MCP initialize · every file read, file written and host contacted by what ran
  not tested  the tool list · what the tools do when called with a real credential
  needs       SUPABASE_ACCESS_TOKEN — give it to the guard with --secrets, never to a chat or a report

Findings  15 static matches; each shows the line that tripped it and what would resolve it
  AST04 medium   MCP server using network transport (SSE/HTTP)
      at       dist/chunk-7LBYXIBL.js:1  …createMcpServer as cs}from"@supabase/mcp-utils"…
      resolves informational for an MCP server: it speaks HTTP by design

Recommendation  Install with a scoped credential, under the guard.
  vet-skills run --secrets SUPABASE_ACCESS_TOKEN=supabase.com -- <the server's command>
```

Coverage levels: **full** (the server answered `tools/list`, or an agent task
ran), **startup only** (the server exited before answering, usually asking for a
credential; it is launched once more with a tagged decoy in that variable, and
the trace shows where the decoy went), **not started** (its dependencies failed
to install), **install only**, and **static only** (nothing has run yet; the
crawler's run replaces the verdict within a cycle, `vet-skills try` runs it now).
The recommendation follows from the evidence, not the label; it never asks for a
credential.

Decisions: **allow**, **sandbox** (install with restrictions), **approval required**
(the install waits for a reviewer), **block** (with the last safe version named),
**defer** (unscored: run it in the honeypot first), **observe** (org enforcement off; logged only).

## Fail-open

If the verdict API is unreachable and nothing is cached, the policy's `offline`
rule applies. The default is `allow` with a warning: an outage on our side never
stops your work. Set `offline: block` in your policy to fail closed.

## Solo vs. org

Solo: a personal policy in `~/.vet-skills/policy.yaml` (`vet-skills policy show`).
Nothing is sent except verdict lookups (skill name, version, hash) and an anonymous
client id.

Org: `vet-skills join <org> --token <enroll token> --email you@company.com`
switches to the org policy. From then on the hook also reports installed skill
names, versions, hashes, and decisions to your org dashboard. Never code,
prompts, environment variables, or file contents. `vet-skills leave` reverts.

## Commands

| Command | What it does |
| --- | --- |
| `check <skill>` | Dry-run the decision. Exit 2 when blocked. |
| `try <pkg\|pypi:name\|owner/repo\|path>` | Fetch it, run it in the honeypot, print what it did and what it costs the agent. |
| `run [--contain] [--deny t,glob*] [--net declared\|hosts\|off] [--secrets NAME=host,…] -- <cmd…>` | Guard a stdio MCP server: deny tools, pin its network, broker its secrets, log every call. |
| `guard install \| uninstall \| status [--project]` | Wrap (or unwrap) every stdio MCP server in the agents' configs so it runs under the guard with the runtime policy; status shows sessions, hosts, held calls. |
| `guard exec --server <n> --client <a> [--secrets …] -- <cmd…>` | Called from the rewritten configs: one server under the guard (verdict lookup, launch check, brokered credentials, host baseline, tool rules, session report). |
| `install <skill>` | Check, then `npx skills add`. Prompts on caution. |
| `detonate <skill\|path>` | Force a sandbox run. |
| `why <skill>` | Last decision and the rule behind it. |
| `join <org> --token <t> --email <e>` / `leave` | Org mode on / off. |
| `policy show` / `policy set <file>` | Personal policy. |
| `block <skill> [--reason]` | Personal block list. |
| `status` | Org, policy version, cache, pending approvals; syncs policy. |
| `discover [--project] [--json]` | Inventory agent config on this machine; report names to the org when enrolled. |
| `mcp` | Run as an MCP server over stdio (`check_skill`, `search_skills`). |
| `hook install [claude-code \| cursor \| codex \| windsurf \| gemini \| all]` | Registers the hooks for that agent (`~/.claude/settings.json`, `~/.cursor/hooks.json`, `~/.codex/hooks.json`, `~/.codeium/windsurf/hooks.json`, `~/.gemini/settings.json`). |
| `hook windsurf`, `hook gemini`, `hook grok` | Called by Windsurf (Cascade) / Gemini CLI / Grok CLI on each event; exit 2 blocks (Grok also gets a `{"decision":"deny"}` line on stdout), the reason goes to the agent. |
| `hook eval` | Called by the agent; reads hook JSON on stdin. |

Environment: `KILLERSKILLS_API` (default `https://killerskills.ai`),
`VET_SKILLS_HOME` (default `~/.vet-skills`), `NO_COLOR`.
