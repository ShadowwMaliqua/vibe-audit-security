const IGNORE_MARKER = "vibe-audit-ignore";

/**
 * Inline suppression, the same convention as `eslint-disable-line`: put
 * `vibe-audit-ignore` anywhere in a comment on the flagged line (or the
 * line right above it) to suppress every finding on that line. Useful both
 * for genuine false positives and for code that intentionally demonstrates
 * a pattern (docs, the scanner's own pattern definitions, test fixtures).
 */
export function isLineSuppressed(lines: string[], lineNumber: number): boolean {
  const current = lines[lineNumber - 1] ?? "";
  const previous = lines[lineNumber - 2] ?? "";
  return current.includes(IGNORE_MARKER) || previous.includes(IGNORE_MARKER);
}
