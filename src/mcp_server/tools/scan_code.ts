import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { buildScanSummary } from "../../core/report/summary.js";
import { writeReportFiles, type ReportFormat } from "../../core/report/write.js";
import { scanCode } from "../../core/scan_code.js";

const SEVERITY_ENUM = z.enum(["critical", "high", "medium", "low", "info"]);
const FORMAT_ENUM = z.enum(["json", "markdown", "pdf", "all"]);

function resolveFormats(format: z.infer<typeof FORMAT_ENUM>): ReportFormat[] {
  return format === "all" ? ["json", "markdown", "pdf"] : [format];
}

export function registerScanCodeTool(server: McpServer): void {
  server.registerTool(
    "scan_code",
    {
      title: "Scan project source code for security issues",
      description:
        "Scans a local project's source code for the security mistakes an AI coding assistant can silently " +
        "introduce: hardcoded secrets (API keys, tokens, database credentials), missing or incomplete " +
        ".gitignore coverage for sensitive files, Supabase/Postgres tables created without Row Level " +
        "Security, Firestore rules that allow unrestricted access, dangerous CORS configuration (wildcard " +
        "origin + credentials), risky code patterns (eval, disabled TLS certificate verification, SQL built " +
        "by string concatenation, hardcoded debug mode), and known-vulnerable dependencies. " +
        "Use this tool BEFORE suggesting or running `git push` or a deployment, so issues are caught while " +
        "still local. The response includes, per finding, a short actionable fix (shortAction) in addition " +
        "to the full description — summarize the short list first and offer to apply fixes.",
      inputSchema: {
        path: z.string().default(".").describe("Path to the project directory to scan"),
        severity_threshold: SEVERITY_ENUM.optional().describe(
          "If set, the response includes an explicit (advisory only, never enforced) push recommendation " +
            "based on whether any finding meets or exceeds this severity.",
        ),
        format: FORMAT_ENUM.default("all").describe("Which report file format(s) to write to disk"),
        out_dir: z.string().default(".").describe("Directory to write report files into"),
      },
    },
    async ({ path, severity_threshold, format, out_dir }) => {
      const result = await scanCode(path);
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
