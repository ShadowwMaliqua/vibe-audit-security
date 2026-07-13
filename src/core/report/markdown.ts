import type { Finding, ScanResult, Severity } from "../types.js";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "🔴 Critical",
  high: "🟠 High",
  medium: "🟡 Medium",
  low: "🔵 Low",
  info: "⚪ Info",
};

function findingSection(finding: Finding, index: number): string {
  const lines: string[] = [];
  lines.push(`### ${index}. ${finding.title}`);
  lines.push("");
  lines.push(`**Severity:** ${SEVERITY_LABEL[finding.severity]}  `);
  lines.push(`**Category:** ${finding.category}  `);
  if (finding.location) {
    lines.push(`**Location:** \`${finding.location}${finding.line ? `:${finding.line}` : ""}\`  `);
  }
  lines.push("");
  lines.push(finding.description);
  lines.push("");
  if (finding.evidence) {
    lines.push(`**Evidence (masked):** \`${finding.evidence}\``);
    lines.push("");
  }
  if (finding.codeBefore) {
    lines.push("```");
    lines.push(finding.codeBefore);
    lines.push("```");
    lines.push("");
  }
  lines.push(`**Recommendation:** ${finding.recommendation}`);
  lines.push("");
  return lines.join("\n");
}

/** Human-readable Markdown report, findings sorted worst-first (assumes result.findings is already sorted). */
export function toMarkdown(result: ScanResult): string {
  const lines: string[] = [];
  lines.push("# vibe-audit security report");
  lines.push("");
  lines.push(`**Target:** ${result.meta.target}  `);
  lines.push(`**Mode:** ${result.meta.mode}  `);
  lines.push(`**Date:** ${new Date(result.meta.finishedAt).toISOString().slice(0, 10)}  `);
  lines.push(`**Score:** ${result.score}/100 (Grade ${result.grade})  `);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    lines.push(`| ${SEVERITY_LABEL[severity]} | ${result.countsBySeverity[severity]} |`);
  }
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No issues found.");
    return lines.join("\n");
  }

  lines.push("## Findings");
  lines.push("");
  result.findings.forEach((finding, i) => lines.push(findingSection(finding, i + 1)));

  return lines.join("\n");
}
