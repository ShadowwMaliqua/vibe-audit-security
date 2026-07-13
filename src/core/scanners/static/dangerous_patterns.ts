import path from "node:path";
import { readTextFileCapped } from "../../fs_walk.js";
import { isLineSuppressed } from "../../suppress.js";
import { lineNumberAt, lineTextAt } from "../../text_location.js";
import type { Finding, Severity, StaticScanner } from "../../types.js";

interface DangerousPattern {
  id: string;
  title: string;
  severity: Severity;
  regex: RegExp;
  shortAction: string;
  description: string;
  recommendation: string;
  /** Restrict this pattern to matching file extensions; omit to check all files. */
  fileExtensions?: RegExp;
}

const JS_EXT = /\.(js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_EXT = /\.py$/i;
const SQL_KEYWORDS = "(?:SELECT|INSERT|UPDATE|DELETE)";

const DANGEROUS_PATTERNS: DangerousPattern[] = [
  {
    // vibe-audit-ignore: this whole block *describes* eval()/new Function() in
    // plain English for the report — it inevitably contains the literal
    // substrings its own regex looks for.
    id: "eval-usage",
    title: "Use of eval()", // vibe-audit-ignore
    severity: "high",
    regex: /\beval\s*\(/g,
    shortAction: "Replace eval() with a safe alternative (JSON.parse, a proper parser, etc.)", // vibe-audit-ignore
    description:
      "eval() executes arbitrary strings as code. If any part of the evaluated string can be influenced by " + // vibe-audit-ignore
      "user input, this is a direct route to remote code execution.",
    recommendation: "Avoid eval() entirely. Use JSON.parse for data, or a proper parser for anything more complex.", // vibe-audit-ignore
    fileExtensions: JS_EXT,
  },
  {
    id: "new-function-usage",
    title: "Use of the Function constructor",
    severity: "high",
    regex: /\bnew\s+Function\s*\(/g,
    shortAction: "Avoid constructing functions from strings at runtime",
    description:
      "new Function(...) compiles a string into executable code, just like eval(). It carries the same risk " + // vibe-audit-ignore
      "if any input reaches it.",
    recommendation:
      "Avoid building functions from dynamic strings; use regular function declarations or a safe interpreter " +
      "for user-defined logic.",
    fileExtensions: JS_EXT,
  },
  {
    id: "tls-verify-disabled-python",
    title: "TLS certificate verification disabled (verify=False)",
    severity: "critical",
    regex: /\bverify\s*=\s*False\b/g,
    shortAction: "Remove verify=False so TLS certificates are actually checked",
    description:
      "This code disables TLS certificate verification for outgoing HTTPS requests, making the connection " +
      "vulnerable to man-in-the-middle attacks.",
    recommendation:
      "Remove verify=False (or set it to True / a CA bundle path). If this was added to work around a " +
      "certificate problem, fix the certificate instead.",
    fileExtensions: PY_EXT,
  },
  {
    id: "tls-reject-unauthorized-disabled",
    // vibe-audit-ignore: describes its own trigger phrase in plain English.
    title: "TLS certificate verification disabled (rejectUnauthorized: false)", // vibe-audit-ignore
    severity: "critical",
    regex: /rejectUnauthorized\s*:\s*false/gi,
    shortAction: "Remove rejectUnauthorized: false so TLS certificates are actually checked", // vibe-audit-ignore
    description:
      "This disables TLS certificate validation for outgoing HTTPS requests in Node.js, making the connection " +
      "vulnerable to man-in-the-middle attacks.",
    recommendation: "Remove this option (the secure default) or fix the underlying certificate issue instead.",
    fileExtensions: JS_EXT,
  },
  {
    id: "tls-reject-unauthorized-env",
    title: "NODE_TLS_REJECT_UNAUTHORIZED disabled globally",
    severity: "critical",
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/g,
    // vibe-audit-ignore: describes its own trigger phrase in plain English.
    shortAction: "Remove the NODE_TLS_REJECT_UNAUTHORIZED=0 override", // vibe-audit-ignore
    description:
      "Setting NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate verification for the entire Node.js " + // vibe-audit-ignore
      "process, not just one request.",
    recommendation: "Remove this environment variable override; fix the actual certificate problem instead.",
  },
  {
    id: "debug-mode-hardcoded-python",
    title: "Debug mode hardcoded to True",
    severity: "high",
    regex: /\b(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True)\b/g,
    shortAction: "Drive DEBUG from an environment variable and default it to False",
    description:
      "Debug mode is hardcoded on. In frameworks like Flask/Django, debug mode can expose stack traces, " +
      "source code, and in some configurations an interactive debugger that allows remote code execution if " +
      "reachable in production.",
    recommendation:
      'Load DEBUG from an environment variable (e.g. os.environ.get("DEBUG") == "true") and make sure ' +
      "production deployments default to False.",
    fileExtensions: PY_EXT,
  },
  {
    id: "debug-mode-hardcoded-generic",
    title: "Debug mode hardcoded to true",
    severity: "medium",
    regex: /\bdebug\s*:\s*true\b/gi,
    shortAction: "Drive debug mode from configuration/environment instead of hardcoding true",
    description:
      "Debug mode is hardcoded to true in configuration. This can leak verbose errors, stack traces, or " +
      "internal state if this code path runs in production.",
    recommendation: "Make debug mode configurable via an environment variable and default to false outside local development.",
    fileExtensions: /\.(js|jsx|ts|tsx|mjs|cjs|json|ya?ml|yml)$/i,
  },
  {
    id: "sql-injection-js-template",
    title: "SQL query built with string interpolation",
    severity: "critical",
    // Case-sensitive on purpose: real embedded SQL is conventionally written in
    // uppercase (SELECT/INSERT/...), which avoids matching ordinary English
    // sentences that happen to contain words like "update" or "select".
    regex: new RegExp(`\`[^\`]*\\b${SQL_KEYWORDS}\\b[^\`]*\\$\\{[^}]+\\}[^\`]*\``, "g"),
    shortAction: "Use a parameterized query instead of interpolating values into SQL",
    description:
      "A SQL statement is built using a template literal with an interpolated value. If any part of that " +
      "value comes from user input, this is a classic SQL injection vulnerability.",
    recommendation:
      "Use parameterized queries / prepared statements (e.g. your driver's placeholder syntax) instead of " +
      "building SQL strings by hand.",
    fileExtensions: JS_EXT,
  },
  {
    id: "sql-injection-js-concat",
    title: "SQL query built with string concatenation",
    severity: "critical",
    regex: new RegExp(`['"]\\s*${SQL_KEYWORDS}\\b[^'"]*['"]\\s*\\+`, "g"),
    shortAction: "Use a parameterized query instead of concatenating values into SQL",
    description:
      "A SQL statement is assembled with string concatenation. If any concatenated part comes from user " +
      "input, this is a classic SQL injection vulnerability.",
    recommendation: "Use parameterized queries / prepared statements instead of building SQL strings by hand.",
    fileExtensions: JS_EXT,
  },
  {
    id: "sql-injection-python-fstring",
    title: "SQL query built with an f-string",
    severity: "critical",
    regex: new RegExp(`f["'][^"']*\\b${SQL_KEYWORDS}\\b[^"']*\\{[^}]+\\}[^"']*["']`, "g"),
    shortAction: "Use a parameterized query instead of an f-string for SQL",
    description:
      "A SQL statement is built with an f-string. If any interpolated value comes from user input, this is a " +
      "classic SQL injection vulnerability.",
    recommendation:
      "Use your database driver's parameterized query syntax (e.g. cursor.execute(query, params)) instead of " +
      "an f-string.",
    fileExtensions: PY_EXT,
  },
  {
    id: "sql-injection-python-percent",
    title: "SQL query built with % string formatting",
    severity: "high",
    regex: new RegExp(`["'][^"']*\\b${SQL_KEYWORDS}\\b[^"']*["']\\s*%\\s*`, "g"),
    shortAction: "Use a parameterized query instead of % formatting for SQL",
    description:
      "A SQL statement is built with % string formatting. If any formatted value comes from user input, this " +
      "is a classic SQL injection vulnerability.",
    recommendation: "Use your database driver's parameterized query syntax instead of % formatting.",
    fileExtensions: PY_EXT,
  },
];

/** Scans for eval/Function, disabled TLS verification, hardcoded debug mode, and SQL built by string-munging. */
export const scanDangerousPatterns: StaticScanner = async (ctx) => {
  const findings: Finding[] = [];

  for (const relPath of ctx.files) {
    const applicable = DANGEROUS_PATTERNS.filter(
      (pattern) => !pattern.fileExtensions || pattern.fileExtensions.test(relPath),
    );
    if (applicable.length === 0) continue;

    const content = await readTextFileCapped(path.join(ctx.rootDir, relPath));
    if (!content) continue;
    const lines = content.split("\n");

    for (const pattern of applicable) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        const line = lineNumberAt(content, match.index);
        if (isLineSuppressed(lines, line)) {
          if (match[0].length === 0) regex.lastIndex += 1;
          continue;
        }
        findings.push({
          id: `${pattern.id}-${relPath}-${line}`,
          title: pattern.title,
          severity: pattern.severity,
          category: "dangerous-patterns",
          shortAction: pattern.shortAction,
          description: pattern.description,
          recommendation: pattern.recommendation,
          location: relPath,
          line,
          codeBefore: lineTextAt(content, match.index),
        });
        if (match[0].length === 0) regex.lastIndex += 1;
      }
    }
  }

  return findings;
};
