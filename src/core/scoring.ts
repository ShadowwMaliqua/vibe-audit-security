import type { Finding, Severity } from "./types.js";
import { SEVERITIES } from "./types.js";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 30,
  high: 15,
  medium: 7,
  low: 3,
  info: 0,
};

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

/** 100 minus a weighted deduction per finding, floored at 0. */
export function computeScore(countsBySeverity: Record<Severity, number>): number {
  const deduction = SEVERITIES.reduce(
    (sum, severity) => sum + SEVERITY_WEIGHTS[severity] * countsBySeverity[severity],
    0,
  );
  return Math.max(0, 100 - deduction);
}

export function computeGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
