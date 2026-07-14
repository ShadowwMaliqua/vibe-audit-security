# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

vibe-audit is a local security scanner (CLI + MCP server) for projects built
with AI coding assistants. It has two scan modes:

- **scan-code**: static analysis of a local project directory (secrets,
  `.gitignore` gaps, missing Supabase/Postgres RLS, permissive Firestore
  rules, dangerous CORS config, risky code patterns, vulnerable dependencies).
- **scan-url**: dynamic HTTP scan of a running URL (missing security headers,
  CORS, insecure cookies, exposed sensitive files, client-side secrets, an
  opt-in read-only Supabase RLS probe).

`scan-project` runs both and merges the results. All three are exposed as
CLI subcommands (`vibe-audit scan-code|scan-url|scan-project`) and as MCP
tools (`scan_code`, `scan_url`, `scan_project`) via `vibe-audit mcp`.

## Architecture

```
src/core/          scanning engine, no dependency on the CLI or MCP SDK
  types.ts           Finding / ScanResult / Severity types
  mask_secret.ts      secret masking, used everywhere a secret could leak
  ssrf_guard.ts        IP classification + DNS-rebinding-safe validation
  safe_fetch.ts         GET/HEAD-only fetch wrapper enforcing the SSRF guard
  fs_walk.ts             directory traversal + capped text file reading
  scoring.ts               score/grade + severity sort, shared by all modes
  secret_patterns.ts        secret regexes shared by static + dynamic scanners
  text_location.ts           file:line helpers shared by static scanners
  suppress.ts                 inline `vibe-audit-ignore` suppression check
  scan_code.ts / scan_url.ts / scan_project.ts   mode orchestrators
  scanners/static/*    mode 1 scanners
  scanners/dynamic/*   mode 2 scanners
  report/               json.ts, markdown.ts, pdf.ts, summary.ts, write.ts

src/cli/            commander-based CLI, thin wrapper around core
src/mcp_server/      MCP tools, thin wrapper around core, same core calls as the CLI
```

**Rule: the CLI and the MCP server must never reimplement scanning logic.**
Both only call into `src/core`. If you need new behavior, add it to core and
call it from both entry points.

## Conventions that matter here

- **`secrets.ts` and `dangerous_patterns.ts` inevitably match on their own
  pattern-description text** (e.g. the string `"Use of eval()"` contains the
  literal substring `eval(`). Use the `// vibe-audit-ignore` inline
  suppression convention (`core/suppress.ts`) on the affected line rather
  than reworking the wording, see the existing annotations in
  `dangerous_patterns.ts` for the pattern. Prefer rewording first if it's
  easy (e.g. avoiding an uppercase SQL keyword in an unrelated sentence);
  reach for the suppression comment when rewording would hurt clarity.
- **Every secret must be masked before it reaches a Finding.** Use
  `maskSecret`/`maskInText` from `core/mask_secret.ts`. Never put a raw
  secret in `evidence`, `codeBefore`, `codeAfter`, or any report output.
  There are tests (`tests/integration/*.test.ts`) that assert specific raw
  fixture secrets never appear in generated reports, keep that invariant.
- **Test fixtures must not contain realistic-looking secrets.** GitHub's
  push protection blocks pushes containing strings that match known
  credential formats regardless of how obviously fake they look (a
  repeated-character `sk_live_XXXX...` still trips it). Build fake secrets
  via string concatenation in test source (e.g. `` `sk_live_${"X".repeat(24)}` ``)
  rather than a literal, and prefer vendor-published placeholders (e.g. AWS's
  own `AKIAIOSFODNN7EXAMPLE`) in committed fixture files.
- **All network access in the dynamic scanners goes through `safeFetch`**
  (`core/safe_fetch.ts`), never a raw `fetch`. It enforces GET/HEAD only, a
  timeout, a response size cap, and SSRF validation on every redirect hop
  (redirects are followed manually, revalidating the new host each time,
  never `redirect: "follow"`).
- **The Supabase RLS probe never runs unless `probeDatabase`/`--probe-database`
  is explicitly set**, and it never returns actual row contents in a
  finding, only whether anonymous access succeeded.
- Static scanners receive a `StaticScanContext` (`rootDir` + a pre-walked
  `files` list from `fs_walk.ts`); dynamic scanners receive a
  `DynamicScanContext` (`baseUrl` + `probeDatabase`). Add a new scanner by
  matching one of these two signatures and registering it in
  `scan_code.ts` / `scan_url.ts`.
- Every `Finding` needs both a short, LLM-actionable `shortAction` and a
  longer `description`, the MCP tools and the CLI summary both rely on
  `shortAction` being genuinely one line and directly actionable.
- **Findings are advisory, never enforced.** The CLI/MCP `severity_threshold`
  option only adds a `recommendation` field (`push_not_recommended` /
  `ok_to_push`); nothing in this tool blocks a push. Keep new behavior
  consistent with that: inform, don't gate, unless a feature is explicitly
  designed as an opt-in strict mode.
- No em dashes in user-facing strings or docs (finding text, CLI/MCP output,
  markdown), use commas, colons, or parentheses instead.
- **The npm package and GitHub repo are named `vibe-audit-security`**, not
  `vibe-audit` (that name was already taken on npm by an unrelated package).
  The CLI command and the `vibe-audit-ignore` suppression comment keep the
  shorter `vibe-audit` name, `package.json` declares both as `bin` entries
  so `npx vibe-audit-security ...` resolves correctly.
- **`.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`** make
  this installable as a Claude Code plugin (`/plugin marketplace add
  <owner>/<repo>`). In `marketplace.json`, use `"source": {"source": "url",
  "url": "https://github.com/..."}` for the plugin source, not `"source":
  "github"` with a `repo` field, the `github` source type clones over SSH
  and fails for anyone without SSH keys configured for GitHub. Run `claude
  plugin validate .` after editing either file.

## Commands

```bash
npm run typecheck   # tsc --noEmit
npm run build       # tsc -> dist/
npm test            # vitest run (unit + integration)
npm run dev -- scan-code .   # run the CLI from source via tsx, no build needed
```

To run a single test file: `npx vitest run tests/unit/secrets.test.ts`.

## Testing

- `tests/unit/`, one file per core module/scanner.
- `tests/integration/`, runs the full `scanCode` pipeline (and report
  generation) against `tests/fixtures/vulnerable-project` (deliberately
  insecure, do not "fix" it, the tests assert these findings are detected)
  and `tests/fixtures/clean-project` (must produce zero critical/high
  findings).
- When adding a scanner or a new secret/dangerous pattern, add a unit test
  with a minimal inline snippet, not just fixture coverage.
- After changing anything in `scanners/static/`, regenerate
  `examples/sample-report.md` by running `scanCode` against
  `tests/fixtures/vulnerable-project` and writing the markdown output (see
  git history for the throwaway-script pattern used previously), so the
  README-linked example stays in sync.

## MCP server

`src/mcp_server/server.ts` registers three tools (`src/mcp_server/tools/*`)
on an `McpServer` over stdio. To test it locally without a full MCP client,
run `node dist/cli/index.js mcp` and speak JSON-RPC over stdin/stdout
(`initialize` → `notifications/initialized` → `tools/list` /
`tools/call`).

## Security posture of this repo

This tool scans other people's projects, so it has to be trustworthy itself:
no secrets in the repo (CI runs Gitleaks on every push/PR, see
`.gitleaks.toml` for the allowlist covering the intentionally-fake fixture
secrets), `npm audit` in CI, and the SSRF guard is unit-tested against
private/loopback/link-local/cloud-metadata ranges. Keep dependencies
minimal, see the technical decisions in the README before adding a new one.

The tool prints a legal disclaimer on every CLI invocation (only scan
targets you own or are authorized to test) and an extra warning before
`--probe-database` runs. Don't remove or weaken either.
