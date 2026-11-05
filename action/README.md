# KillerSkills GitHub Action

Fails a pull request when a skill or MCP server the repository uses is blocked by KillerSkills (or by your organization's policy).

```yaml
name: vet-skills
on: [pull_request]
jobs:
  vet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - uses: cyligence-karim/vet-skills/action@main
        with:
          fail-on: approval_required          # block | approval_required | sandbox
          org: acme                           # optional: evaluate against your org policy
          org-token: ${{ secrets.KS_ORG_TOKEN }}
```

Without `skills`, the action checks every `.claude/skills/*/SKILL.md` and `skills/*/SKILL.md` directory by name, plus every `url` in `.mcp.json`. Pass an explicit list to override:

```yaml
        with:
          skills: |
            deploy-helper@1.4.0
            https://skills.sh/anthropics/pdf
            https://mcp.example.com/sse
```

Each run writes a verdict table to the job summary, annotates the PR with warnings and errors, and exposes `blocked` and `report` outputs.
