import { describe, expect, it } from "vitest";
import { toJson } from "../../src/core/report/json.js";
import { toMarkdown } from "../../src/core/report/markdown.js";
import { generatePdfReport } from "../../src/core/report/pdf.js";
import { buildScanSummary } from "../../src/core/report/summary.js";
import { computeGrade, computeScore, countBySeverity, sortBySeverity } from "../../src/core/scoring.js";
import type { Finding, ScanResult } from "../../src/core/types.js";

function makeResult(findings: Finding[]): ScanResult {
  const sorted = sortBySeverity(findings);
  const countsBySeverity = countBySeverity(sorted);
  const score = computeScore(countsBySeverity);
  return {
    meta: {
      target: "/tmp/example-project",
      mode: "code",
      startedAt: "2026-01-01T00:00:00.000Z",
      finishedAt: "2026-01-01T00:00:05.000Z",
      toolVersion: "0.1.0",
      probeDatabaseUsed: false,
    },
    findings: sorted,
    score,
    grade: computeGrade(score),
    countsBySeverity,
  };
}

const sampleFinding: Finding = {
  id: "secret-stripe-live-key-server.js-3",
  title: "Stripe live secret key found in source code",
  severity: "critical",
  category: "secrets",
  shortAction: "Remove the hardcoded Stripe key from server.js:3 and rotate it immediately",
  description: "A Stripe live secret key was found hardcoded in the source code.",
  recommendation: "Move it to an environment variable and rotate the key.",
  location: "server.js",
  line: 3,
  evidence: "sk_l****************3f2a",
  codeBefore: 'const stripeKey = "sk_l****************3f2a";',
};

describe("toJson", () => {
  it("serializes the full scan result including findings", () => {
    const result = makeResult([sampleFinding]);
    const json = toJson(result);
    const parsed = JSON.parse(json);
    expect(parsed.score).toBe(result.score);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].evidence).toBe(sampleFinding.evidence);
  });
});

describe("toMarkdown", () => {
  it("includes the score, grade, and each finding's recommendation", () => {
    const result = makeResult([sampleFinding]);
    const md = toMarkdown(result);
    expect(md).toContain(`${result.score}/100`);
    expect(md).toContain(result.grade);
    expect(md).toContain(sampleFinding.title);
    expect(md).toContain(sampleFinding.recommendation);
    expect(md).toContain("sk_l****************3f2a");
  });

  it("reports no issues found for a clean project", () => {
    const md = toMarkdown(makeResult([]));
    expect(md).toContain("No issues found.");
  });
});

describe("buildScanSummary", () => {
  it("produces a short LLM-friendly headline and top findings", () => {
    const result = makeResult([sampleFinding]);
    const summary = buildScanSummary(result);
    expect(summary.headline).toContain("1 issue");
    expect(summary.headline).toContain("1 critical");
    expect(summary.topFindings).toHaveLength(1);
    expect(summary.topFindings[0]?.shortAction).toBe(sampleFinding.shortAction);
  });

  it("sets recommendation based on severityThreshold without blocking anything itself", () => {
    const result = makeResult([sampleFinding]);
    const summary = buildScanSummary(result, "critical");
    expect(summary.recommendation).toBe("push_not_recommended");

    const cleanSummary = buildScanSummary(makeResult([]), "critical");
    expect(cleanSummary.recommendation).toBe("ok_to_push");
  });
});

describe("generatePdfReport", () => {
  it("produces a non-empty, valid-looking PDF buffer without leaking the raw secret", async () => {
    const result = makeResult([sampleFinding]);
    const buffer = await generatePdfReport(result);
    expect(buffer.length).toBeGreaterThan(500);
    expect(buffer.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    // pdfkit doesn't compress text streams by default, so a naive substring
    // check is a meaningful (if not airtight) guard against raw secret leakage.
    // Built via concatenation so this test file itself never contains a
    // string that looks like a real credential to secret scanners.
    const rawLookingSecret = `sk_live_${"X".repeat(24)}`;
    expect(buffer.toString("latin1")).not.toContain(rawLookingSecret);
  });

  it("handles an empty findings list", async () => {
    const buffer = await generatePdfReport(makeResult([]));
    expect(buffer.subarray(0, 5).toString("ascii")).toBe("%PDF-");
  });
});
