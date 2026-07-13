import { maskSecret } from "../../mask_secret.js";
import { safeFetch } from "../../safe_fetch.js";
import type { DynamicScanner, Finding } from "../../types.js";
import { fetchClientSideResources } from "./client_secrets.js";

const SUPABASE_URL_RE = /https:\/\/[a-z0-9-]+\.supabase\.co/i;
const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;

const COMMON_TABLES = ["users", "profiles", "customers", "accounts", "orders", "messages", "leads"];

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const segment = token.split(".")[1];
  if (!segment) return null;
  try {
    const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(normalized, "base64").toString("utf-8");
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Read-only Supabase RLS check, disabled unless the caller explicitly opts
 * in via ctx.probeDatabase (--probe-database on the CLI). Only ever issues
 * GET requests, and never surfaces actual row contents in a finding — just
 * whether anonymous access to a common table name succeeded.
 */
export const scanSupabaseRls: DynamicScanner = async (ctx) => {
  const findings: Finding[] = [];
  const { html, scripts } = await fetchClientSideResources(ctx.baseUrl);
  const combinedText = [html, ...scripts.map((s) => s.text)].join("\n");

  const urlMatch = combinedText.match(SUPABASE_URL_RE);
  if (!urlMatch) return findings;
  const supabaseUrl = urlMatch[0];

  let anonKey: string | null = null;
  for (const jwtMatch of combinedText.matchAll(JWT_RE)) {
    const payload = decodeJwtPayload(jwtMatch[0]);
    if (payload?.["role"] === "anon") {
      anonKey = jwtMatch[0];
      break;
    }
  }
  if (!anonKey) return findings;

  if (!ctx.probeDatabase) {
    findings.push({
      id: "supabase-detected-not-probed",
      title: "Supabase project detected (RLS not probed)",
      severity: "info",
      category: "supabase-rls",
      shortAction:
        "Re-run with --probe-database (only on projects you own) to check whether RLS actually blocks anonymous access",
      description:
        `A Supabase project (${supabaseUrl}) and a public anon key were found in the client-side code. This ` +
        "is expected — Supabase anon keys are meant to be public — but it only stays safe if Row Level " +
        "Security is correctly enabled on every table.",
      recommendation:
        "Run vibe-audit scan-url with --probe-database on a project you own to perform a read-only check of common table names.",
      location: supabaseUrl,
      evidence: maskSecret(anonKey),
    });
    return findings;
  }

  for (const table of COMMON_TABLES) {
    const endpoint = `${supabaseUrl}/rest/v1/${table}?select=*&limit=1`;
    let res;
    try {
      res = await safeFetch(endpoint, {
        method: "GET",
        headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` },
      });
    } catch {
      continue;
    }
    if (res.status !== 200) continue;

    let rowCount = 0;
    try {
      const parsed: unknown = JSON.parse(res.bodyText);
      if (Array.isArray(parsed)) rowCount = parsed.length;
    } catch {
      continue;
    }
    if (rowCount === 0) continue;

    findings.push({
      id: `supabase-rls-open-${table}`,
      title: `Table "${table}" is readable by anyone with the public anon key`,
      severity: "critical",
      category: "supabase-rls",
      shortAction: `Enable Row Level Security and restrict anonymous reads on "${table}"`,
      description:
        `An anonymous, read-only request to "${table}" returned data. This means Row Level Security is ` +
        "either disabled on this table or its policy allows anonymous reads. Row contents are never shown " +
        "in this report — only the fact that access succeeded.",
      recommendation: `Run "ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;" and add a policy that only allows the intended users to read rows.`,
      location: endpoint,
    });
  }

  return findings;
};
