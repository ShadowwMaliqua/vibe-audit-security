import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import type { Finding, Severity, StaticScanner } from "../../types.js";

const execFileAsync = promisify(execFile);
const AUDIT_TIMEOUT_MS = 30000;
const MAX_BUFFER = 10 * 1024 * 1024;

interface ExecError extends Error {
  stdout?: string;
  code?: string | number;
}

const NPM_SEVERITY_MAP: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
  info: "info",
};

function parseNpmAuditJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return findings;
  }
  const vulnerabilities = (parsed as { vulnerabilities?: Record<string, unknown> })?.vulnerabilities;
  if (!vulnerabilities || typeof vulnerabilities !== "object") return findings;

  for (const [pkgName, rawInfo] of Object.entries(vulnerabilities)) {
    const info = rawInfo as {
      severity?: string;
      range?: string;
      fixAvailable?: unknown;
      via?: Array<string | { title?: string }>;
    };
    const severity = NPM_SEVERITY_MAP[info.severity ?? ""] ?? "medium";
    const range = info.range ?? "unknown range";
    const fixAvailable = Boolean(info.fixAvailable);
    const via = Array.isArray(info.via)
      ? info.via
          .filter((v): v is { title?: string } => typeof v === "object" && v !== null)
          .map((v) => v.title)
          .filter((t): t is string => Boolean(t))
      : [];

    findings.push({
      id: `npm-audit-${pkgName}`,
      title: `Vulnerable dependency: ${pkgName}`,
      severity,
      category: "dependencies",
      shortAction: fixAvailable
        ? `Run "npm audit fix" (or update ${pkgName}) to resolve known vulnerabilities`
        : `Update or replace "${pkgName}" (${range}); no automatic fix is currently available`,
      description: `The npm package "${pkgName}" (${range}) has known security vulnerabilities${
        via.length > 0 ? `: ${via.join(", ")}` : "."
      }`,
      recommendation: fixAvailable
        ? "Run `npm audit fix` (or `npm audit fix --force` after reviewing breaking changes), then re-scan."
        : "Check whether a newer version fixes the vulnerability, or consider an alternative package.",
      location: "package.json",
    });
  }
  return findings;
}

async function runNpmAudit(rootDir: string): Promise<Finding[]> {
  try {
    const { stdout } = await execFileAsync("npm", ["audit", "--json"], {
      cwd: rootDir,
      timeout: AUDIT_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });
    return parseNpmAuditJson(stdout);
  } catch (err) {
    const execErr = err as ExecError;
    if (typeof execErr.stdout === "string" && execErr.stdout.trim().startsWith("{")) {
      // npm audit exits non-zero when vulnerabilities are found; JSON is still on stdout.
      return parseNpmAuditJson(execErr.stdout);
    }
    return [
      {
        id: "npm-audit-failed",
        title: "Could not run npm audit",
        severity: "info",
        category: "dependencies",
        shortAction: "Run `npm audit` manually to check for known-vulnerable dependencies",
        description:
          'vibe-audit tried to run "npm audit --json" in this project but it failed or produced no usable ' +
          `output (${execErr.message}). This can happen if npm isn't installed, there is no lockfile, or ` +
          "there's no network access.",
        recommendation: "Run npm audit manually and address any reported vulnerabilities.",
      },
    ];
  }
}

function parsePipAuditJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return findings;
  }
  const dependencies = Array.isArray(parsed)
    ? parsed
    : (parsed as { dependencies?: unknown[] })?.dependencies;
  if (!Array.isArray(dependencies)) return findings;

  for (const rawDep of dependencies) {
    const dep = rawDep as {
      name?: string;
      version?: string;
      vulns?: Array<{ id?: string; fix_versions?: string[] }>;
      vulnerabilities?: Array<{ id?: string; fix_versions?: string[] }>;
    };
    const vulns = dep.vulns ?? dep.vulnerabilities;
    if (!Array.isArray(vulns) || vulns.length === 0) continue;

    for (const vuln of vulns) {
      findings.push({
        id: `pip-audit-${dep.name}-${vuln.id ?? "unknown"}`,
        title: `Vulnerable dependency: ${dep.name} (${vuln.id ?? "unknown advisory"})`,
        severity: "high",
        category: "dependencies",
        shortAction: `Update "${dep.name}" past the vulnerable version ${dep.version ?? ""}`.trim(),
        description: `The Python package "${dep.name}"${dep.version ? ` (${dep.version})` : ""} has a known vulnerability${
          vuln.id ? ` (${vuln.id})` : ""
        }.`,
        recommendation: vuln.fix_versions?.length
          ? `Upgrade to ${vuln.fix_versions.join(" or ")}.`
          : "Check for a patched release or consider an alternative package.",
        location: "requirements.txt",
      });
    }
  }
  return findings;
}

async function runPipAudit(rootDir: string): Promise<Finding[]> {
  try {
    const { stdout } = await execFileAsync("pip-audit", ["-f", "json"], {
      cwd: rootDir,
      timeout: AUDIT_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });
    return parsePipAuditJson(stdout);
  } catch (err) {
    const execErr = err as ExecError;
    if (typeof execErr.stdout === "string" && execErr.stdout.trim().startsWith("[")) {
      return parsePipAuditJson(execErr.stdout);
    }
    if (execErr.code === "ENOENT") {
      return [
        {
          id: "pip-audit-not-installed",
          title: "pip-audit is not installed",
          severity: "info",
          category: "dependencies",
          shortAction: "Install pip-audit (pip install pip-audit) to check Python dependencies for known vulnerabilities",
          description:
            "This project has Python dependency files, but pip-audit is not available, so vibe-audit could not " +
            "check them for known vulnerabilities.",
          recommendation: "Install pip-audit and run it as part of your workflow (or CI).",
        },
      ];
    }
    return [
      {
        id: "pip-audit-failed",
        title: "Could not run pip-audit",
        severity: "info",
        category: "dependencies",
        shortAction: "Run pip-audit manually to check for known-vulnerable Python dependencies",
        description: `vibe-audit tried to run pip-audit but it failed (${execErr.message}).`,
        recommendation: "Run pip-audit manually and address any reported vulnerabilities.",
      },
    ];
  }
}

const PYTHON_DEP_FILES = new Set(["requirements.txt", "pyproject.toml", "Pipfile"]);

/**
 * Wraps `npm audit` / `pip-audit` for whichever dependency manifests are
 * present at the project root (no monorepo/workspace traversal yet).
 */
export const scanDependencies: StaticScanner = async (ctx) => {
  const findings: Finding[] = [];
  const rootLevelFiles = new Set(ctx.files.filter((f) => !f.includes(path.sep)));

  if (rootLevelFiles.has("package.json")) {
    findings.push(...(await runNpmAudit(ctx.rootDir)));
  }

  const hasPythonDeps = [...rootLevelFiles].some((f) => PYTHON_DEP_FILES.has(f));
  if (hasPythonDeps) {
    findings.push(...(await runPipAudit(ctx.rootDir)));
  }

  return findings;
};
