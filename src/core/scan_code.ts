import path from "node:path";
import { scanCorsConfig } from "./scanners/static/cors_config.js";
import { scanDangerousPatterns } from "./scanners/static/dangerous_patterns.js";
import { scanDbRules } from "./scanners/static/db_rules.js";
import { scanDependencies } from "./scanners/static/dependency_audit.js";
import { scanGitignore } from "./scanners/static/gitignore_check.js";
import { scanSecrets } from "./scanners/static/secrets.js";
import { computeGrade, computeScore, countBySeverity, sortBySeverity } from "./scoring.js";
import type { Finding, ScanResult, StaticScanContext, StaticScanner } from "./types.js";
import { walkDirectory } from "./fs_walk.js";

const STATIC_SCANNERS: StaticScanner[] = [
  scanSecrets,
  scanGitignore,
  scanDbRules,
  scanCorsConfig,
  scanDangerousPatterns,
  scanDependencies,
];

const TOOL_VERSION = "0.1.0";

export interface ScanCodeOptions {
  toolVersion?: string;
}

/** Runs every static (mode 1) scanner against a local project directory. */
export async function scanCode(rootDirInput: string, options: ScanCodeOptions = {}): Promise<ScanResult> {
  const rootDir = path.resolve(rootDirInput);
  const startedAt = new Date().toISOString();

  const files = await walkDirectory(rootDir);
  const ctx: StaticScanContext = { rootDir, files };

  const findings: Finding[] = [];
  for (const scanner of STATIC_SCANNERS) {
    findings.push(...(await scanner(ctx)));
  }

  const countsBySeverity = countBySeverity(findings);
  const score = computeScore(countsBySeverity);

  return {
    meta: {
      target: rootDir,
      mode: "code",
      startedAt,
      finishedAt: new Date().toISOString(),
      toolVersion: options.toolVersion ?? TOOL_VERSION,
      probeDatabaseUsed: false,
    },
    findings: sortBySeverity(findings),
    score,
    grade: computeGrade(score),
    countsBySeverity,
  };
}
