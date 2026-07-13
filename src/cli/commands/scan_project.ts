import { scanProject } from "../../core/scan_project.js";
import { buildScanSummary } from "../../core/report/summary.js";
import { writeReportFiles } from "../../core/report/write.js";
import type { Severity } from "../../core/types.js";
import { printDisclaimer, printProbeDatabaseWarning } from "../disclaimer.js";
import { printSummary } from "../print_summary.js";
import { resolveFormats } from "./scan_code.js";

export interface ScanProjectCliOptions {
  path: string;
  url?: string;
  format: string;
  out: string;
  severityThreshold?: Severity;
  probeDatabase: boolean;
}

export async function runScanProjectCommand(options: ScanProjectCliOptions): Promise<number> {
  printDisclaimer();
  if (options.probeDatabase) {
    printProbeDatabaseWarning();
  }
  console.error(
    `Scanning ${options.path}${options.url ? ` and ${options.url}` : ""} (mode 1${options.url ? " + mode 2" : ""})...`,
  );

  const result = await scanProject({
    projectPath: options.path,
    ...(options.url !== undefined ? { url: options.url } : {}),
    probeDatabase: options.probeDatabase,
  });
  const formats = resolveFormats(options.format);
  const written = await writeReportFiles(result, options.out, formats);
  const summary = buildScanSummary(result, options.severityThreshold);

  console.log("");
  printSummary(summary, written);

  return result.countsBySeverity.critical > 0 ? 2 : 0;
}
