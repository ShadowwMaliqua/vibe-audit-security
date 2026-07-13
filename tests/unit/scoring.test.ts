import { describe, expect, it } from "vitest";
import { computeGrade, computeScore, countBySeverity } from "../../src/core/scoring.js";
import type { Finding } from "../../src/core/types.js";

function finding(severity: Finding["severity"]): Finding {
  return {
    id: `f-${severity}`,
    title: "test",
    severity,
    category: "secrets",
    shortAction: "fix it",
    description: "test finding",
    recommendation: "do the thing",
  };
}

describe("scoring", () => {
  it("gives a perfect score with no findings", () => {
    const counts = countBySeverity([]);
    expect(computeScore(counts)).toBe(100);
    expect(computeGrade(100)).toBe("A");
  });

  it("deducts more for critical than for low severity findings", () => {
    const criticalScore = computeScore(countBySeverity([finding("critical")]));
    const lowScore = computeScore(countBySeverity([finding("low")]));
    expect(criticalScore).toBeLessThan(lowScore);
  });

  it("never goes below zero", () => {
    const counts = countBySeverity(Array.from({ length: 20 }, () => finding("critical")));
    expect(computeScore(counts)).toBe(0);
    expect(computeGrade(0)).toBe("F");
  });

  it("maps score ranges to the expected letter grades", () => {
    expect(computeGrade(95)).toBe("A");
    expect(computeGrade(80)).toBe("B");
    expect(computeGrade(65)).toBe("C");
    expect(computeGrade(45)).toBe("D");
    expect(computeGrade(10)).toBe("F");
  });
});
