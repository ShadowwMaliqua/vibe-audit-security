#!/usr/bin/env node
import { Command, Option } from "commander";
import { SsrfBlockedError } from "../core/ssrf_guard.js";
import { runMcpCommand } from "./commands/mcp.js";
import { runScanCodeCommand } from "./commands/scan_code.js";
import { runScanProjectCommand } from "./commands/scan_project.js";
import { runScanUrlCommand } from "./commands/scan_url.js";

const SEVERITY_CHOICES = ["critical", "high", "medium", "low", "info"] as const;
const FORMAT_CHOICES = ["json", "markdown", "pdf", "all"] as const;

type Severity = (typeof SEVERITY_CHOICES)[number];

interface CommonScanOptions {
  format: string;
  out: string;
  severityThreshold?: Severity;
}

function formatOption(): Option {
  return new Option("-f, --format <format>", "report format").choices(FORMAT_CHOICES).default("all");
}

function outOption(): Option {
  return new Option("-o, --out <dir>", "directory to write reports into").default(".");
}

function severityThresholdOption(): Option {
  return new Option(
    "-s, --severity-threshold <severity>",
    "if set, prints a push/no-push recommendation based on this threshold",
  ).choices(SEVERITY_CHOICES);
}

function probeDatabaseOption(): Option {
  return new Option(
    "--probe-database",
    "also send read-only requests to a detected Supabase project's REST API to check whether RLS blocks " +
      "anonymous access on common table names. Only use on projects you own.",
  ).default(false);
}

async function runAndExit(fn: () => Promise<number>): Promise<void> {
  try {
    process.exitCode = await fn();
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      console.error(`Blocked: ${err.message}`);
    } else {
      console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }
    process.exitCode = 1;
  }
}

const program = new Command();

program
  .name("vibe-audit")
  .description(
    "Security scanner for vibe-coded projects: catches the mistakes an AI coding assistant can silently " +
      "introduce (hardcoded secrets, disabled RLS, open CORS, missing security headers) before you push.",
  )
  .version("0.1.0");

program
  .command("scan-code")
  .description(
    "Scan a local project directory: hardcoded secrets, .gitignore gaps, missing Row Level Security, " +
      "dangerous CORS config, risky code patterns, and vulnerable dependencies. Run this before any git push or deploy.",
  )
  .argument("[path]", "path to the project to scan", ".")
  .addOption(formatOption())
  .addOption(outOption())
  .addOption(severityThresholdOption())
  .action((path: string, opts: CommonScanOptions) => {
    void runAndExit(() =>
      runScanCodeCommand({
        path,
        format: opts.format,
        out: opts.out,
        ...(opts.severityThreshold !== undefined ? { severityThreshold: opts.severityThreshold } : {}),
      }),
    );
  });

program
  .command("scan-url")
  .description(
    "Scan a live URL: missing security headers, open CORS, insecure cookies, exposed sensitive files, and " +
      "secrets leaked in client-side code. Only scan targets you own or are authorized to test.",
  )
  .argument("<url>", "URL to scan, e.g. http://localhost:3000 or https://your-app.example.com")
  .addOption(formatOption())
  .addOption(outOption())
  .addOption(severityThresholdOption())
  .addOption(probeDatabaseOption())
  .action((url: string, opts: CommonScanOptions & { probeDatabase: boolean }) => {
    void runAndExit(() =>
      runScanUrlCommand({
        url,
        format: opts.format,
        out: opts.out,
        probeDatabase: opts.probeDatabase,
        ...(opts.severityThreshold !== undefined ? { severityThreshold: opts.severityThreshold } : {}),
      }),
    );
  });

program
  .command("scan-project")
  .description("Run scan-code and (if --url is given) scan-url, and merge the results into one report.")
  .argument("[path]", "path to the local project to scan", ".")
  .option("-u, --url <url>", "URL to also scan")
  .addOption(formatOption())
  .addOption(outOption())
  .addOption(severityThresholdOption())
  .addOption(probeDatabaseOption())
  .action((path: string, opts: CommonScanOptions & { url?: string; probeDatabase: boolean }) => {
    void runAndExit(() =>
      runScanProjectCommand({
        path,
        format: opts.format,
        out: opts.out,
        probeDatabase: opts.probeDatabase,
        ...(opts.url !== undefined ? { url: opts.url } : {}),
        ...(opts.severityThreshold !== undefined ? { severityThreshold: opts.severityThreshold } : {}),
      }),
    );
  });

program
  .command("mcp")
  .description("Start the vibe-audit MCP server on stdio, for use with `claude mcp add`.")
  .action(() => {
    void runMcpCommand();
  });

program.parseAsync(process.argv);
