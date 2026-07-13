import { safeFetch } from "../../safe_fetch.js";
import type { DynamicScanner, Finding, Severity } from "../../types.js";

const CANDIDATE_PATHS = [
  ".env",
  ".env.local",
  ".git/config",
  ".git/HEAD",
  ".DS_Store",
  "docker-compose.yml",
  "config.php.bak",
  "wp-config.php.bak",
  "backup.sql",
  ".aws/credentials",
  "id_rsa",
];

function severityFor(candidatePath: string): Severity {
  if (candidatePath.startsWith(".env") || candidatePath.includes("credentials") || candidatePath === "id_rsa") {
    return "critical";
  }
  if (candidatePath.startsWith(".git/")) return "high";
  return "medium";
}

function fileExplanation(candidatePath: string): string {
  if (candidatePath.startsWith(".env")) {
    return "Environment files typically contain API keys, database passwords, and other secrets.";
  }
  if (candidatePath.startsWith(".git/")) {
    return (
      "Exposing .git lets an attacker reconstruct the entire source code history, including anything ever " +
      "committed — even files that were later deleted."
    );
  }
  if (candidatePath.includes("credentials")) {
    return "This file typically contains cloud provider credentials.";
  }
  if (candidatePath === "id_rsa") {
    return "This looks like a private SSH key.";
  }
  return "Depending on its contents, this file could reveal configuration details, credentials, or internal infrastructure information.";
}

/** Within 5% length of the baseline "definitely missing" response = likely a false positive (SPA catch-all). */
function looksLikeBaseline(length: number, baselineLength: number): boolean {
  if (baselineLength === 0) return length === 0;
  return Math.abs(length - baselineLength) / baselineLength < 0.05;
}

/**
 * Probes a fixed list of commonly-sensitive paths under the target URL.
 * Establishes a baseline against a random nonexistent path first, so a SPA
 * that returns 200 for every route doesn't generate a wall of false
 * positives.
 */
export const scanExposedFiles: DynamicScanner = async (ctx) => {
  const findings: Finding[] = [];
  const base = new URL(ctx.baseUrl);

  const noncePath = `/__vibe_audit_nonexistent_${Math.random().toString(36).slice(2)}__`;
  let baseline: { status: number; length: number } | null = null;
  try {
    const nonceRes = await safeFetch(new URL(noncePath, base).toString(), { method: "GET" });
    baseline = { status: nonceRes.status, length: nonceRes.bodyText.length };
  } catch {
    baseline = null;
  }

  for (const candidate of CANDIDATE_PATHS) {
    const targetUrl = new URL(candidate, base).toString();
    let res;
    try {
      res = await safeFetch(targetUrl, { method: "GET" });
    } catch {
      continue;
    }

    if (res.status !== 200) continue;
    if (res.bodyText.trim().length === 0) continue;
    if (baseline && baseline.status === res.status && looksLikeBaseline(res.bodyText.length, baseline.length)) {
      continue;
    }

    findings.push({
      id: `exposed-file-${candidate.replace(/[^a-zA-Z0-9]/g, "-")}`,
      title: `Sensitive file publicly accessible: ${candidate}`,
      severity: severityFor(candidate),
      category: "exposed-files",
      shortAction: `Block public access to ${candidate} (remove it from the web root or add a server rule)`,
      description: `A GET request to ${candidate} returned HTTP ${res.status} with content, meaning this file is publicly reachable. ${fileExplanation(candidate)}`,
      recommendation:
        "Remove this file from the publicly served directory, or add a web server / reverse proxy rule that blocks access to it.",
      location: targetUrl,
    });
  }

  return findings;
};
