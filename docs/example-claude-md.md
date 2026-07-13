# Example CLAUDE.md snippet for your own project

Copy the block below into your project's `CLAUDE.md` (or append it to an
existing one) so Claude Code knows to use vibe-audit's `scan_code` tool
proactively before a push.

```markdown
## Security scanning before push

This project uses vibe-audit (an MCP tool) to catch security mistakes before
they get pushed or deployed.

- Before suggesting or running `git push` (or a deployment), offer to run the
  `scan_code` tool and summarize the results in plain language: how many
  issues were found, split by severity, and a short list of the critical/high
  ones with their one-line fix.
- Do not block the push. Inform the user of what was found, especially
  critical and high severity findings, and let them decide whether to fix
  first or push anyway. The default behavior is advisory, not enforced.
- Exception: if the user has explicitly asked for a "strict" mode (e.g. "never
  let me push with critical issues"), then respect that and refuse to proceed
  until they're addressed or the user overrides you explicitly in that moment.
- If the user asks you to fix the findings, use each finding's location,
  recommendation, and code snippet to apply a targeted fix, then suggest
  re-running the scan to confirm.
```
