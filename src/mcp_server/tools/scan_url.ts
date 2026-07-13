import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { buildScanSummary } from "../../core/report/summary.js";
import { writeReportFiles, type ReportFormat } from "../../core/report/write.js";
import { scanUrl } from "../../core/scan_url.js";

const SEVERITY_ENUM = z.enum(["critical", "high", "medium", "low", "info"]);
const FORMAT_ENUM = z.enum(["json", "markdown", "pdf", "all"]);

function resolveFormats(format: z.infer<typeof FORMAT_ENUM>): ReportFormat[] {
  return format === "all" ? ["json", "markdown", "pdf"] : [format];
}

export function registerScanUrlTool(server: McpServer): void {
  server.registerTool(
    "scan_url",
    {
      title: "Scan a live URL for security issues",
      description:
        "Scans a running URL (localhost, staging, or production) for missing security headers " +
        "(Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options), " +
        "dangerous CORS configuration, cookies missing Secure/HttpOnly/SameSite, publicly exposed sensitive " +
        "files (.env, .git/, config backups), and secrets leaked in client-side HTML/JS. Only ever sends " +
        "GET/HEAD requests, and refuses to contact private, loopback, link-local, or cloud-metadata IP " +
        "ranges (localhost/127.0.0.1 is allowed only when explicitly targeted). " +
        "Only scan a URL the user owns or has explicitly said they are authorized to test.",
      inputSchema: {
        url: z.string().url().describe("URL to scan, e.g. http://localhost:3000 or a deployed URL the user owns"),
        severity_threshold: SEVERITY_ENUM.optional().describe(
          "If set, the response includes an explicit (advisory only, never enforced) push recommendation " +
            "based on whether any finding meets or exceeds this severity.",
        ),
        format: FORMAT_ENUM.default("all").describe("Which report file format(s) to write to disk"),
        out_dir: z.string().default(".").describe("Directory to write report files into"),
        probe_database: z
          .boolean()
          .default(false)
          .describe(
            "Only set this to true if the user has explicitly confirmed, in this conversation, that they own " +
              "the Supabase project being scanned. When true, sends additional read-only GET requests to a " +
              "fixed list of common table names against the detected Supabase REST API to check whether Row " +
              "Level Security blocks anonymous access — it never writes, updates, or deletes data, and never " +
              "returns row contents in the report. Do not set this automatically without explicit confirmation.",
          ),
      },
    },
    async ({ url, severity_threshold, format, out_dir, probe_database }) => {
      const result = await scanUrl(url, { probeDatabase: probe_database });
      const written = await writeReportFiles(result, out_dir, resolveFormats(format));
      const summary = buildScanSummary(result, severity_threshold);

      const payload = {
        summary: summary.headline,
        score: result.score,
        grade: result.grade,
        countsBySeverity: result.countsBySeverity,
        recommendation: summary.recommendation,
        findings: result.findings,
        reportFiles: written,
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
    },
  );
}
