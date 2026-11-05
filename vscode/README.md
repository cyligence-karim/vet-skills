# KillerSkills for VS Code, Cursor and Windsurf

Open `.mcp.json`, `~/.cursor/mcp.json`, Claude Desktop's `claude_desktop_config.json`,
`.claude/settings.json` or `.codex/config.toml` and every MCP server, skill and plugin
in it gets its KillerSkills verdict inline: Verified / Caution / Blocked with the
score, what the sandbox saw, known vulnerabilities (OSV) and the prompt context its
tool list costs. A credential value pasted into the file is flagged by kind and
line. The status bar shows the count for the open file.

Only names leave the editor: the parser drops environment values, header values,
arguments and URL paths before anything is looked up. The value of a leaked
credential is never read back or sent.

Commands: **KillerSkills: Check this config**, **KillerSkills: Open MCP server benchmarks**.
Setting `killerskills.apiBase` points the extension at a self-hosted verdict cache.

Built from the open-source [vet-skills](https://github.com/cyligence-karim/vet-skills)
parser. Verdicts and methodology: https://killerskills.ai/scenarios
