import { scanCode } from "./scan_code.js";
import { scanUrl } from "./scan_url.js";
import { computeGrade, computeScore, countBySeverity, sortBySeverity } from "./scoring.js";
import type { Finding, ScanResult } from "./types.js";

const TOOL_VERSION = "0.1.0";

export interface ScanProjectOptions {
  projectPath?: string;
  url?: string;
  probeDatabase?: boolean;
  toolVersion?: string;
}

/**
 * Runs scan-code and/or scan-url (whichever targets are provided) and
 * merges the results into a single report. This never re-implements
 * scanning logic itself — it only calls scanCode/scanUrl and combines
 * their output, so CLI and MCP stay thin wrappers around the same core.
 */
export async function scanProject(options: ScanProjectOptions): Promise<ScanResult> {
  if (!options.projectPath && !options.url) {
    throw new Error("scanProject requires at least one of projectPath or url");
  }

  const startedAt = new Date().toISOString();
  const findings: Finding[] = [];
  const targets: string[] = [];
  let probeDatabaseUsed = false;

  if (options.projectPath) {
    const codeResult = await scanCode(options.projectPath, {
      ...(options.toolVersion !== undefined ? { toolVersion: options.toolVersion } : {}),
    });
    findings.push(...codeResult.findings);
    targets.push(codeResult.meta.target);
  }

  if (options.url) {
    const urlResult = await scanUrl(options.url, {
      ...(options.probeDatabase !== undefined ? { probeDatabase: options.probeDatabase } : {}),
      ...(options.toolVersion !== undefined ? { toolVersion: options.toolVersion } : {}),
    });
    findings.push(...urlResult.findings);
    targets.push(urlResult.meta.target);
    probeDatabaseUsed = urlResult.meta.probeDatabaseUsed;
  }

  const countsBySeverity = countBySeverity(findings);
  const score = computeScore(countsBySeverity);

  return {
    meta: {
      target: targets.join(" + "),
      mode: "project",
      startedAt,
      finishedAt: new Date().toISOString(),
      toolVersion: options.toolVersion ?? TOOL_VERSION,
      probeDatabaseUsed,
    },
    findings: sortBySeverity(findings),
    score,
    grade: computeGrade(score),
    countsBySeverity,
  };
}
