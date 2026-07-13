import { scanCode } from "../../core/scan_code.js";
import { buildScanSummary } from "../../core/report/summary.js";
import { writeReportFiles, type ReportFormat } from "../../core/report/write.js";
import type { Severity } from "../../core/types.js";
import { printDisclaimer } from "../disclaimer.js";
import { printSummary } from "../print_summary.js";

export interface ScanCodeCliOptions {
  path: string;
  format: string;
  out: string;
  severityThreshold?: Severity;
}

export function resolveFormats(format: string): ReportFormat[] {
  if (format === "all") return ["json", "markdown", "pdf"];
  if (format === "json" || format === "markdown" || format === "pdf") return [format];
  throw new Error(`Unknown format "${format}". Use one of: json, markdown, pdf, all.`);
}

/** Returns the process exit code: 2 if any critical finding was found, 0 otherwise. */
export async function runScanCodeCommand(options: ScanCodeCliOptions): Promise<number> {
  printDisclaimer();
  console.error(`Scanning ${options.path} for hardcoded secrets, missing RLS, dangerous patterns...`);

  const result = await scanCode(options.path);
  const formats = resolveFormats(options.format);
  const written = await writeReportFiles(result, options.out, formats);
  const summary = buildScanSummary(result, options.severityThreshold);

  console.log("");
  printSummary(summary, written);

  return result.countsBySeverity.critical > 0 ? 2 : 0;
}
