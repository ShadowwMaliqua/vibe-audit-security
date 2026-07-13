import { scanClientSecrets } from "./scanners/dynamic/client_secrets.js";
import { scanExposedFiles } from "./scanners/dynamic/exposed_files.js";
import { scanHttpHeaders } from "./scanners/dynamic/http_headers.js";
import { scanSupabaseRls } from "./scanners/dynamic/supabase_rls.js";
import { computeGrade, computeScore, countBySeverity, sortBySeverity } from "./scoring.js";
import { resolveAndValidateHost } from "./ssrf_guard.js";
import type { DynamicScanContext, DynamicScanner, Finding, ScanResult } from "./types.js";

const DYNAMIC_SCANNERS: DynamicScanner[] = [scanHttpHeaders, scanExposedFiles, scanClientSecrets, scanSupabaseRls];

const TOOL_VERSION = "0.1.0";

export interface ScanUrlOptions {
  probeDatabase?: boolean;
  toolVersion?: string;
}

function dynamicScannerErrorFinding(scannerName: string, err: unknown): Finding {
  return {
    id: `dynamic-scanner-error-${scannerName}-${Date.now()}`,
    title: `A scan step could not complete (${scannerName})`,
    severity: "info",
    category: "scan-error",
    shortAction: "No action needed unless this repeats — informational only",
    description: `One of the dynamic scan steps failed to complete: ${err instanceof Error ? err.message : String(err)}`,
    recommendation: "Re-run the scan; if it persists, the target may be blocking automated requests or is unreachable.",
  };
}

/**
 * Runs every dynamic (mode 2) scanner against a live URL. Validates the
 * target up front (SsrfBlockedError propagates immediately, since there is
 * no point running any scanner against a target we refuse to contact); each
 * individual scanner's own failures are caught and turned into a low-noise
 * informational finding so one broken probe doesn't abort the whole scan.
 */
export async function scanUrl(targetUrl: string, options: ScanUrlOptions = {}): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const parsed = new URL(targetUrl);
  await resolveAndValidateHost(parsed.hostname);

  const ctx: DynamicScanContext = {
    baseUrl: parsed.toString(),
    probeDatabase: options.probeDatabase ?? false,
  };

  const findings: Finding[] = [];
  for (const scanner of DYNAMIC_SCANNERS) {
    try {
      findings.push(...(await scanner(ctx)));
    } catch (err) {
      findings.push(dynamicScannerErrorFinding(scanner.name || "unknown", err));
    }
  }

  const countsBySeverity = countBySeverity(findings);
  const score = computeScore(countsBySeverity);

  return {
    meta: {
      target: ctx.baseUrl,
      mode: "url",
      startedAt,
      finishedAt: new Date().toISOString(),
      toolVersion: options.toolVersion ?? TOOL_VERSION,
      probeDatabaseUsed: ctx.probeDatabase,
    },
    findings: sortBySeverity(findings),
    score,
    grade: computeGrade(score),
    countsBySeverity,
  };
}
