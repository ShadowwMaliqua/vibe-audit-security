import { maskSecret } from "../../mask_secret.js";
import { safeFetch } from "../../safe_fetch.js";
import { findSecrets } from "../../secret_patterns.js";
import type { DynamicScanner, Finding } from "../../types.js";

const MAX_SCRIPTS = 5;
const SCRIPT_SRC_RE = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;

export interface ClientSideResources {
  html: string;
  scripts: { url: string; text: string }[];
}

/**
 * Fetches the page HTML plus a handful of same-origin JS bundles it
 * references. Shared with supabase_rls.ts so we only fetch the page once
 * per scan. Cross-origin scripts (CDNs, analytics, ...) are skipped, both
 * to respect the SSRF guard's intent and to avoid scanning third-party code.
 */
export async function fetchClientSideResources(baseUrl: string): Promise<ClientSideResources> {
  const base = new URL(baseUrl);
  const htmlRes = await safeFetch(baseUrl, { method: "GET" });
  const html = htmlRes.bodyText;

  const scriptUrls: string[] = [];
  for (const match of html.matchAll(SCRIPT_SRC_RE)) {
    const src = match[1];
    if (!src) continue;
    let resolved: URL;
    try {
      resolved = new URL(src, base);
    } catch {
      continue;
    }
    if (resolved.hostname !== base.hostname) continue;
    scriptUrls.push(resolved.toString());
    if (scriptUrls.length >= MAX_SCRIPTS) break;
  }

  const scripts: { url: string; text: string }[] = [];
  for (const url of scriptUrls) {
    try {
      const scriptRes = await safeFetch(url, { method: "GET" });
      scripts.push({ url, text: scriptRes.bodyText });
    } catch {
      // A single unreachable script shouldn't abort the whole scan.
    }
  }

  return { html, scripts };
}

/**
 * Runs the same secret patterns as the static scanner (secrets.ts) against
 * the rendered HTML and same-origin JS bundles, anything shipped to the
 * browser is visible to every visitor.
 */
export const scanClientSecrets: DynamicScanner = async (ctx) => {
  const findings: Finding[] = [];
  const { html, scripts } = await fetchClientSideResources(ctx.baseUrl);

  const sources: { label: string; text: string }[] = [
    { label: "the page HTML", text: html },
    ...scripts.map((s) => ({ label: s.url, text: s.text })),
  ];

  for (const source of sources) {
    for (const detection of findSecrets(source.text)) {
      findings.push({
        id: `client-secret-${detection.patternId}-${detection.index}-${findings.length}`,
        title: `${detection.label} exposed in client-side code`,
        severity: detection.severity,
        category: "client-secrets",
        shortAction: `Remove the ${detection.label} from ${source.label} and rotate it, it is visible to every visitor`,
        description: `A value matching the pattern for a ${detection.label} was found in ${source.label}. Anything shipped to the browser is visible to every visitor, including this secret.`,
        recommendation:
          "Never ship server-side secrets to the client. Move this to a backend-only environment variable, and rotate the exposed credential.",
        location: source.label,
        evidence: maskSecret(detection.match),
      });
    }
  }

  return findings;
};
