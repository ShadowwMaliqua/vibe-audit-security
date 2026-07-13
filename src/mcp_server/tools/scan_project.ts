import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { buildScanSummary } from "../../core/report/summary.js";
import { writeReportFiles, type ReportFormat } from "../../core/report/write.js";
import { scanProject } from "../../core/scan_project.js";

const SEVERITY_ENUM = z.enum(["critical", "high", "medium", "low", "info"]);
const FORMAT_ENUM = z.enum(["json", "markdown", "pdf", "all"]);

function resolveFormats(format: z.infer<typeof FORMAT_ENUM>): ReportFormat[] {
  return format === "all" ? ["json", "markdown", "pdf"] : [format];
}

export function registerScanProjectTool(server: McpServer): void {
  server.registerTool(
    "scan_project",
    {
      title: "Scan a project's source code and (optionally) its deployed URL",
      description:
        "Runs scan_code against a local project directory and, if a URL is given, also runs scan_url " +
        "against it, then merges the results into one report. Use this before a git push or deployment when " +
        "the project is also already running somewhere you can reach (e.g. localhost during dev, or a " +
        "staging URL you own) — it gives the most complete picture in a single call.",
      inputSchema: {
        path: z.string().default(".").describe("Path to the local project directory to scan"),
        url: z.string().url().optional().describe("Optional URL to also scan; only use one the user owns or is authorized to test"),
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
            "Only relevant when url is set. Only set this to true if the user has explicitly confirmed, in " +
              "this conversation, that they own the Supabase project being scanned. Read-only; never set it " +
              "automatically without explicit confirmation.",
          ),
      },
    },
    async ({ path, url, severity_threshold, format, out_dir, probe_database }) => {
      const result = await scanProject({
        projectPath: path,
        ...(url !== undefined ? { url } : {}),
        probeDatabase: probe_database,
      });
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
