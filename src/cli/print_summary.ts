import type { ScanSummary } from "../core/report/summary.js";
import type { ReportFormat } from "../core/report/write.js";

/** Console summary shared by every scan command — kept out of core since it's presentation, not scanning logic. */
export function printSummary(summary: ScanSummary, written: Partial<Record<ReportFormat, string>>): void {
  console.log(summary.headline);

  if (summary.topFindings.length > 0) {
    console.log("");
    for (const finding of summary.topFindings) {
      const where = finding.location ? ` (${finding.location}${finding.line ? `:${finding.line}` : ""})` : "";
      console.log(`  [${finding.severity.toUpperCase()}] ${finding.title}${where}`);
      console.log(`    -> ${finding.shortAction}`);
    }
  }

  if (summary.recommendation) {
    console.log("");
    console.log(
      `Recommendation: ${summary.recommendation === "push_not_recommended" ? "push not recommended yet" : "ok to push"}`,
    );
  }

  const writtenEntries = Object.entries(written);
  if (writtenEntries.length > 0) {
    console.log("");
    console.log("Reports written:");
    for (const [format, filePath] of writtenEntries) {
      console.log(`  ${format}: ${filePath}`);
    }
  }
}
