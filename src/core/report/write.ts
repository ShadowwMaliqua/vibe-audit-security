import fs from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "../types.js";
import { generatePdfReport } from "./pdf.js";
import { toJson } from "./json.js";
import { toMarkdown } from "./markdown.js";

export type ReportFormat = "json" | "markdown" | "pdf";

const BASE_NAME = "vibe-audit-report";
const EXTENSION: Record<ReportFormat, string> = { json: "json", markdown: "md", pdf: "pdf" };

/**
 * Writes the requested report formats to `outDir` under a fixed
 * "vibe-audit-report.*" name. Shared by the CLI and the MCP server so
 * neither reimplements file writing.
 */
export async function writeReportFiles(
  result: ScanResult,
  outDir: string,
  formats: ReportFormat[],
): Promise<Partial<Record<ReportFormat, string>>> {
  await fs.mkdir(outDir, { recursive: true });
  const written: Partial<Record<ReportFormat, string>> = {};

  for (const format of formats) {
    const filePath = path.join(outDir, `${BASE_NAME}.${EXTENSION[format]}`);
    if (format === "json") {
      await fs.writeFile(filePath, toJson(result));
    } else if (format === "markdown") {
      await fs.writeFile(filePath, toMarkdown(result));
    } else {
      await fs.writeFile(filePath, await generatePdfReport(result));
    }
    written[format] = filePath;
  }

  return written;
}
