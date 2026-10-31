# vet-skills

Check agent skills and MCP servers before they run. Verdicts come from
[KillerSkills](https://killerskills.ai); the policy is yours or your org's.

```
npm i -g vet-skills                          # the CLI (Node 20+)
vet-skills hook install claude-code          # intercept every install in Claude Code
vet-skills check <skill>                     # or just ask before you add one
vet-skills publish ./my-skill                # org members: detonate + list in the private registry
```

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
Requires Node 20+. Index: 16,000+ skills and MCP servers from skills.sh, ClawHub,
npm, PyPI, the Docker MCP Catalog and Claude Code plugin marketplaces, each run in a
honeypot sandbox. Browse them at [killerskills.ai](https://killerskills.ai/?utm_source=npm&utm_medium=readme&utm_campaign=cli).

## See what is already configured

```
vet-skills discover            # every MCP server, skill, plugin and hook on this machine, with verdicts
```

Reads Claude Code, Cursor, Windsurf, Claude Desktop, Gemini CLI and Codex configs
locally. Only names leave the machine, and only when you are enrolled in an org.

## What it does

Every `skills add`, `claude plugin install`, and `claude mcp add` is resolved to
an artifact hash, looked up, and evaluated against your policy before it runs:

```
$ vet-skills check deploy-helper
Resolving deploy-helper …
vet-skills 0.7.2 · policy acme/default-strict

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

Decisions: **allow**, **sandbox** (install with restrictions), **approval required**
(the install waits for a reviewer), **block** (with the last safe version named),
**defer** (unscored: detonate first), **observe** (org enforcement off; logged only).

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
| `install <skill>` | Check, then `npx skills add`. Prompts on caution. |
| `detonate <skill\|path>` | Force a sandbox run. |
| `why <skill>` | Last decision and the rule behind it. |
| `join <org> --token <t> --email <e>` / `leave` | Org mode on / off. |
| `policy show` / `policy set <file>` | Personal policy. |
| `block <skill> [--reason]` | Personal block list. |
| `status` | Org, policy version, cache, pending approvals; syncs policy. |
| `discover [--project] [--json]` | Inventory agent config on this machine; report names to the org when enrolled. |
| `mcp` | Run as an MCP server over stdio (`check_skill`, `search_skills`). |
| `hook install claude-code` | Registers the PreToolUse hook in `~/.claude/settings.json`. |
| `hook eval` | Called by the agent; reads hook JSON on stdin. |

Environment: `KILLERSKILLS_API` (default `https://killerskills.ai`),
`VET_SKILLS_HOME` (default `~/.vet-skills`), `NO_COLOR`.
