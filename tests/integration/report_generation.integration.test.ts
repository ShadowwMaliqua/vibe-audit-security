import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { toJson } from "../../src/core/report/json.js";
import { toMarkdown } from "../../src/core/report/markdown.js";
import { generatePdfReport } from "../../src/core/report/pdf.js";
import { scanCode } from "../../src/core/scan_code.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VULNERABLE_PROJECT = path.join(__dirname, "..", "fixtures", "vulnerable-project");

const RAW_SECRETS = ["51H8x9J2eZvKYlo2CJ9x8FAKEKEYFORTESTINGONLY", "SuperSecretPass123", "AKIAFAKEKEY1234EXAMPLE"];

describe("report generation on the vulnerable fixture", () => {
  it("produces a JSON report with the expected findings and no raw secrets", async () => {
    const result = await scanCode(VULNERABLE_PROJECT);
    const json = toJson(result);
    const parsed = JSON.parse(json);

    expect(parsed.findings.length).toBeGreaterThan(0);
    expect(parsed.grade).toBe("F");
    for (const secret of RAW_SECRETS) {
      expect(json).not.toContain(secret);
    }
  });

  it("produces a Markdown report with the expected findings and no raw secrets", async () => {
    const result = await scanCode(VULNERABLE_PROJECT);
    const md = toMarkdown(result);

    expect(md).toContain("Stripe live secret key");
    expect(md).toContain("Row Level Security");
    expect(md).toContain("CORS allows any origin");
    for (const secret of RAW_SECRETS) {
      expect(md).not.toContain(secret);
    }
  });

  it("produces a non-empty PDF report with no raw secrets embedded", async () => {
    const result = await scanCode(VULNERABLE_PROJECT);
    const buffer = await generatePdfReport(result);

    expect(buffer.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    expect(buffer.length).toBeGreaterThan(1000);
    const asText = buffer.toString("latin1");
    for (const secret of RAW_SECRETS) {
      expect(asText).not.toContain(secret);
    }
  });
});
