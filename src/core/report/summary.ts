import type { ScanResult, Severity } from "../types.js";

/**
 * A trimmed-down, LLM-friendly view of a ScanResult: a one-line headline, a
 * short list of the most important findings (each with a shortAction), and
 * (when a severity threshold is supplied) an explicit push/no-push
 * recommendation. This is what the MCP tools return (and what the CLI can
 * print) so an assistant summarizing results in a conversation doesn't have
 * to parse the full finding list itself.
 */
export interface FindingSummary {
  id: string;
  title: string;
  severity: Severity;
  shortAction: string;
  location?: string;
  line?: number;
}

export interface ScanSummary {
  headline: string;
  score: number;
  grade: string;
  countsBySeverity: Record<Severity, number>;
  topFindings: FindingSummary[];
  /** Only set when a severityThreshold was provided, a recommendation, never an enforced block. */
  recommendation?: "push_not_recommended" | "ok_to_push";
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function buildScanSummary(result: ScanResult, severityThreshold?: Severity, maxTopFindings = 10): ScanSummary {
  const { countsBySeverity, findings, score, grade } = result;
  const total = findings.length;

  const parts: string[] = [];
  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    if (countsBySeverity[severity] > 0) parts.push(`${countsBySeverity[severity]} ${severity}`);
  }
  const breakdown = parts.length > 0 ? ` (${parts.join(", ")})` : "";
  const headline =
    total === 0
      ? `No security issues found. Score ${score}/100 (grade ${grade}).`
      : `Found ${total} issue${total === 1 ? "" : "s"}${breakdown}. Score ${score}/100 (grade ${grade}).`;

  const summary: ScanSummary = {
    headline,
    score,
    grade,
    countsBySeverity,
    topFindings: findings.slice(0, maxTopFindings).map((f) => {
      const entry: FindingSummary = {
        id: f.id,
        title: f.title,
        severity: f.severity,
        shortAction: f.shortAction,
      };
      if (f.location !== undefined) entry.location = f.location;
      if (f.line !== undefined) entry.line = f.line;
      return entry;
    }),
  };

  if (severityThreshold) {
    const thresholdRank = SEVERITY_RANK[severityThreshold];
    const meetsThreshold = findings.some((f) => SEVERITY_RANK[f.severity] <= thresholdRank);
    summary.recommendation = meetsThreshold ? "push_not_recommended" : "ok_to_push";
  }

  return summary;
}
