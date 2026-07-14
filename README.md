# vibe-audit

A local security scanner for vibe-coded projects, apps built with AI coding
assistants (Claude, Cursor, etc). It catches the kind of security mistakes an
AI assistant can introduce without anyone noticing: hardcoded API keys,
disabled Row Level Security, wide-open CORS, missing security headers, and
more, before you `git push` or deploy.

It ships as both a **CLI** and an **MCP server** you can wire into Claude
Code, so Claude can scan your project and summarize the findings in plain
language as part of your normal workflow.

## ⚠️ Legal disclaimer

**Only scan projects, domains, or servers that you own or have explicit
authorization to test.** The dynamic scanner (`scan-url`) sends real HTTP
requests to the target. Scanning a system you don't own or don't have
permission to test may violate the Computer Fraud and Abuse Act (US), the
Computer Misuse Act (UK), similar laws elsewhere, or a service's terms of
use. You are solely responsible for how you use this tool. This disclaimer
is also printed every time you run the CLI. The `--probe-database` flag
prints an additional warning before it runs, since it sends extra requests
to your database's REST API (still read-only, see below).

## What it checks

### Mode 1: `scan-code` (static, local project directory)

- **Hardcoded secrets**: Stripe live keys, AWS access keys, Google API keys,
  GitHub tokens, Slack tokens/webhooks, PEM private key blocks, database
  connection strings with embedded credentials.
- **`.gitignore` gaps**: missing `.gitignore`, or sensitive files present in
  the project (`.env`, `*.pem`, `*.key`, cloud credential files) that aren't
  actually covered by it.
- **Database rules**: Supabase/Postgres migrations (`supabase/migrations/*.sql`)
  that create a table without a matching `ENABLE ROW LEVEL SECURITY`, and
  `firestore.rules` files with unconditional `allow ...: if true` rules.
- **Dangerous CORS config**: Express `cors()` / FastAPI `CORSMiddleware` (or
  raw headers) combining a wildcard/any origin with credentials enabled.
- **Risky code patterns**: `eval()`, the `Function` constructor, disabled TLS
  verification (`verify=False`, `rejectUnauthorized: false`,
  <!-- vibe-audit-ignore: this line documents the trigger phrase itself -->
  `NODE_TLS_REJECT_UNAUTHORIZED=0`), hardcoded debug mode, and SQL built by
  string concatenation/interpolation instead of parameterized queries.
- **Vulnerable dependencies**: wraps `npm audit` and (if installed)
  `pip-audit` for whichever manifests are present.

### Mode 2: `scan-url` (dynamic, a running URL)

- **Missing security headers**: CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options.
- **CORS**: wildcard or arbitrary-origin reflection combined with
  `Access-Control-Allow-Credentials: true`.
- **Cookies** missing `Secure`, `HttpOnly`, or `SameSite`.
- **Exposed sensitive files**: `.env`, `.git/config`, `.git/HEAD`, config
  backups, etc, with a baseline check against a random nonexistent path so
  a single-page app that returns 200 for every route doesn't flood you with
  false positives.
- **Client-side secrets**: the same secret patterns as mode 1, scanned
  against the rendered HTML and same-origin JS bundles.
- **Supabase RLS probe** (opt-in, `--probe-database` only): detects a
  Supabase project URL + anon key in client-side code, then sends read-only
  `GET` requests to a fixed list of common table names
  (`users`, `profiles`, `customers`, `accounts`, `orders`, `messages`,
  `leads`) to check whether RLS actually blocks anonymous access. Never
  writes, updates, or deletes anything, and never prints row contents, only
  whether access succeeded.

`scan-project` runs mode 1 and (if a URL is given) mode 2, and merges the
results into one report.

### Built-in limitations (by design)

- CORS/secret detection is regex/heuristic-based, not a full AST parse,
  this keeps the dependency footprint small but can occasionally miss an
  unusual code shape or produce a rare false positive.
- `scan-code` only looks at root-level `package.json` /
  `requirements.txt`/`pyproject.toml`/`Pipfile` for dependency auditing (no
  monorepo/workspace traversal yet).
- `.gitignore` matching is a simplified glob matcher, not full gitignore
  semantics (no nested negation rules, for example).

### Suppressing a false positive

If a specific line is a genuine false positive (or intentionally demonstrates
a pattern, e.g. in docs or tests), add `vibe-audit-ignore` anywhere in a
comment on that line or the line above it, same convention as
`eslint-disable-line`. This suppresses every finding on that line.

## Installation

Run it directly with `npx`, no install required:

```bash
npx vibe-audit-security scan-code .
```

### Adding it to Claude Code as an MCP server

```bash
claude mcp add vibe-audit -- npx vibe-audit-security mcp
```

This registers three tools (`scan_code`, `scan_url`, `scan_project`) that
Claude Code can call directly in conversation. See
[Using it from Claude Code](#using-it-from-claude-code) below for how to make
Claude use it proactively before a push.

### Installing as a Claude Code plugin

```bash
/plugin marketplace add ShadowwMaliqua/vibe-audit-security
/plugin install vibe-audit-security@vibe-audit-security-marketplace
```

This installs the MCP server the same way as the `claude mcp add` command
above, packaged as a plugin.

## Usage

```bash
# Scan the current directory's source code
vibe-audit scan-code .

# Scan a running app (only targets you own/are authorized to test)
vibe-audit scan-url http://localhost:3000

# Scan both and merge into one report
vibe-audit scan-project . --url http://localhost:3000

# Also probe Supabase RLS read-only (prints an extra warning first)
vibe-audit scan-url https://your-app.example.com --probe-database
```

Common options (available on all three `scan-*` commands):

| Option | Description |
|---|---|
| `-f, --format <json\|markdown\|pdf\|all>` | Which report file(s) to write (default: `all`) |
| `-o, --out <dir>` | Directory to write reports into (default: `.`) |
| `-s, --severity-threshold <critical\|high\|medium\|low\|info>` | Prints an advisory push/no-push recommendation based on this threshold |
| `--probe-database` | (`scan-url`/`scan-project` only) opt-in, read-only Supabase RLS probe |

Every scan writes `vibe-audit-report.json`, `vibe-audit-report.md`, and/or
`vibe-audit-report.pdf` depending on `--format`. The PDF includes a cover
page with a score (0–100) and letter grade (A–F), a color-coded summary by
severity, and one section per finding, sorted worst-first, with every
secret masked, a plain-language description, and a concrete recommendation.

**Exit codes**: `0` normally, `2` if any *critical* finding was found (for
use in a pre-commit hook or CI gate if you want one, this isn't wired up by
default), `1` on an error (e.g. an SSRF-blocked target).

## Using it from Claude Code

Once added as an MCP server, copy this into your own project's `CLAUDE.md`
(the full version is in [`docs/example-claude-md.md`](docs/example-claude-md.md)):

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
- Exception: if the user has explicitly asked for a "strict" mode, respect
  that instead.
```

The default behavior is intentionally advisory: Claude informs and
recommends, it never categorically refuses to help you push. You stay the
decision-maker, unless you've explicitly told it otherwise.

## Security posture of vibe-audit itself

Since this tool scans other people's projects, it needs to be trustworthy:

- **SSRF guard**: `scan-url` resolves DNS once, validates every returned
  address (blocking RFC1918 private ranges, loopback, link-local, and cloud
  metadata endpoints like `169.254.169.254`), and connects only to that
  validated address (never a second, independent DNS lookup) to close the
  classic DNS-rebinding TOCTOU gap. Every redirect hop is re-validated the
  same way (never followed automatically). `localhost`/`127.0.0.1` are
  allowed only when explicitly targeted.
- **GET/HEAD only, always**: no scan ever sends a write request. The
  Supabase RLS probe only reads, and never returns row contents in a report.
- **Secrets are always masked** before they can appear in any report or log,
  see `core/mask_secret.ts`, exercised by dedicated tests.
- **Strict timeouts and response size caps** on every outgoing request.
- CI runs [Gitleaks](https://github.com/gitleaks/gitleaks) on every push/PR,
  plus `npm audit`, build, and the full test suite.

## Development

```bash
npm install
npm run typecheck
npm run build
npm test
npm run dev -- scan-code .   # run from source via tsx, no build needed
```

See [`CLAUDE.md`](CLAUDE.md) for the architecture and conventions used in
this repo.

## License

MIT, see [LICENSE](LICENSE).
