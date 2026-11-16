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

## Guard: run an agent's MCP servers under the guard in a job

Two more actions cover agents that run in CI. `action/guard` goes before the agent: it installs `vet-skills`, applies your
org's policy (or a policy file) and puts the MCP servers in the repository's configs under the guard. `action/guard-summary`
goes after: it writes what the guard recorded to the job summary and can fail the job.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: cyligence-karim/vet-skills/action/guard@main
    with:
      org: acme                                # optional; CI runners use no seat
      org-token: ${{ secrets.KS_ORG_TOKEN }}
      # policy: .github/agent-policy.yaml      # or a policy file, with no org
  - run: claude -p "triage the new issues" --mcp-config .mcp.json
  - uses: cyligence-karim/vet-skills/action/guard-summary@main
    if: always()
    with:
      fail-on: denied                          # denied | unexpected-host | refused | any | none
```

`action/guard` inputs: `version` (npm version, or `none` when vet-skills is already on PATH), `org`, `org-token`,
`policy`, `project` (default `true`), `working-directory`, `remote` (default `true`: bridge remote servers that carry a
credential header). `action/guard-summary` inputs: `since` (default `6h`), `fail-on` (default `none`).

A tool rule with `action: approve` waits for a person; for unattended jobs prefer `deny`. The workflow in
`.github/workflows/guard-ci.yml` exercises both actions on every push to this repository.
