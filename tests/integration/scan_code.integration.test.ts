import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanCode } from "../../src/core/scan_code.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VULNERABLE_PROJECT = path.join(__dirname, "..", "fixtures", "vulnerable-project");
const CLEAN_PROJECT = path.join(__dirname, "..", "fixtures", "clean-project");

describe("scanCode on the vulnerable fixture", () => {
  it("detects every deliberately planted issue", async () => {
    const result = await scanCode(VULNERABLE_PROJECT);
    const ids = result.findings.map((f) => f.id);
    const categories = new Set(result.findings.map((f) => f.category));

    expect(result.findings.some((f) => f.id.startsWith("secret-stripe-live-key"))).toBe(true);
    expect(result.findings.some((f) => f.id.startsWith("secret-db-connection-string"))).toBe(true);
    expect(ids).toContain("gitignore-uncovered-env-file-.env");
    expect(ids).toContain("db-rls-missing-profiles");
    expect(ids).toContain("db-rls-missing-orders");
    expect(result.findings.some((f) => f.id.startsWith("firestore-allow-true"))).toBe(true);
    expect(result.findings.some((f) => f.id.startsWith("cors-wildcard-credentials"))).toBe(true);
    expect(result.findings.some((f) => f.id.startsWith("eval-usage"))).toBe(true);
    expect(result.findings.some((f) => f.id.startsWith("sql-injection-js-concat"))).toBe(true);
    expect(result.findings.some((f) => f.id.startsWith("sql-injection-python-fstring"))).toBe(true);
    expect(result.findings.some((f) => f.id.startsWith("tls-verify-disabled-python"))).toBe(true);
    expect(result.findings.some((f) => f.id.startsWith("debug-mode-hardcoded-python"))).toBe(true);

    expect(categories.has("secrets")).toBe(true);
    expect(categories.has("gitignore")).toBe(true);
    expect(categories.has("database-rules")).toBe(true);
    expect(categories.has("cors")).toBe(true);
    expect(categories.has("dangerous-patterns")).toBe(true);

    expect(result.countsBySeverity.critical).toBeGreaterThan(0);
    expect(result.grade).toBe("F");
    expect(result.score).toBe(0);
  });

  it("never leaks a raw secret value in any finding", async () => {
    const result = await scanCode(VULNERABLE_PROJECT);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("51H8x9J2eZvKYlo2CJ9x8FAKEKEYFORTESTINGONLY");
    expect(serialized).not.toContain("SuperSecretPass123");
    expect(serialized).not.toContain("AKIAFAKEKEY1234EXAMPLE");
  });

  it("sorts findings worst severity first", async () => {
    const result = await scanCode(VULNERABLE_PROJECT);
    const ranks = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const severities = result.findings.map((f) => ranks[f.severity]);
    const sorted = [...severities].sort((a, b) => a - b);
    expect(severities).toEqual(sorted);
  });
});

describe("scanCode on the clean fixture", () => {
  it("reports no critical or high severity findings", async () => {
    const result = await scanCode(CLEAN_PROJECT);
    const criticalOrHigh = result.findings.filter((f) => f.severity === "critical" || f.severity === "high");
    expect(criticalOrHigh).toEqual([]);
  });
});
