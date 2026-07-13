import path from "node:path";
import { readTextFileCapped } from "../../fs_walk.js";
import type { Finding, StaticScanner } from "../../types.js";

interface SensitiveRule {
  id: string;
  label: string;
  test: (relPath: string) => boolean;
}

const SAFE_SUFFIX_RE = /\.(example|sample|template|dist|test)$/i;

const SENSITIVE_RULES: SensitiveRule[] = [
  {
    id: "env-file",
    label: "environment file",
    test: (relPath) => {
      const base = path.basename(relPath);
      if (SAFE_SUFFIX_RE.test(base)) return false;
      return base === ".env" || /^\.env\.[^.]+$/.test(base);
    },
  },
  {
    id: "private-key-file",
    label: "private key file",
    test: (relPath) => {
      const base = path.basename(relPath);
      return /\.(pem|key|pfx|p12)$/i.test(base) || /^id_(rsa|dsa|ecdsa|ed25519)$/.test(base);
    },
  },
  {
    id: "cloud-credentials-file",
    label: "cloud credentials file",
    test: (relPath) => {
      const base = path.basename(relPath).toLowerCase();
      return base === "credentials.json" || base === "credentials" || base.includes("serviceaccount");
    },
  },
];

/** Converts a simplified glob (only `*` is treated as a wildcard) to a RegExp. */
function globToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .split("*")
    .map((part) => part.replace(/[.+^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`);
}

/**
 * Simplified, non-exhaustive .gitignore matcher: good enough to catch the
 * common "*.env", ".env", "*.pem" style entries this scanner cares about.
 * It does not implement full gitignore semantics (nested negation,
 * directory-only anchors, etc).
 */
function isCoveredByGitignore(relPath: string, gitignoreLines: string[]): boolean {
  const basename = path.basename(relPath);
  const posixPath = relPath.split(path.sep).join("/");

  for (const raw of gitignoreLines) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;

    const pattern = line.replace(/^\//, "").replace(/\/$/, "");
    const regex = globToRegExp(pattern);

    if (regex.test(basename) || regex.test(posixPath)) return true;

    if (!pattern.includes("/")) {
      const segments = posixPath.split("/");
      if (segments.some((segment) => regex.test(segment))) return true;
    }
  }
  return false;
}

/**
 * Checks that .gitignore exists and actually excludes the sensitive files
 * that are physically present in the project (.env, key files, cloud
 * credential JSON). Flags both a missing .gitignore and any sensitive file
 * it fails to cover.
 */
export const scanGitignore: StaticScanner = async (ctx) => {
  const findings: Finding[] = [];

  const gitignoreContent = await readTextFileCapped(path.join(ctx.rootDir, ".gitignore"), 200_000);

  if (gitignoreContent === null) {
    findings.push({
      id: "gitignore-missing",
      title: "No .gitignore file found",
      severity: "high",
      category: "gitignore",
      shortAction: "Add a .gitignore that excludes .env, key files, and other credentials before committing",
      description:
        "This project has no .gitignore file. Without one, any file you create — including .env, private " +
        "keys, or cloud credential files — can be committed and pushed by accident.",
      recommendation:
        "Create a .gitignore at the project root covering at least: .env, .env.*, *.pem, *.key, *.p12, " +
        "*.pfx, credentials.json, serviceAccountKey.json.",
    });
  }

  const gitignoreLines = (gitignoreContent ?? "").split("\n");

  for (const relPath of ctx.files) {
    if (relPath === ".gitignore") continue;

    for (const rule of SENSITIVE_RULES) {
      if (!rule.test(relPath)) continue;

      const covered = gitignoreContent !== null && isCoveredByGitignore(relPath, gitignoreLines);
      if (covered) continue;

      findings.push({
        id: `gitignore-uncovered-${rule.id}-${relPath}`,
        title: `Sensitive file not excluded by .gitignore: ${relPath}`,
        severity: "critical",
        category: "gitignore",
        shortAction: `Add "${path.basename(relPath)}" (or a matching pattern) to .gitignore before committing`,
        description:
          `"${relPath}" looks like a ${rule.label}, but it is not covered by any .gitignore rule. If this ` +
          "repository is committed as-is, this file — and any secret inside it — will be pushed to version control.",
        recommendation:
          `Add an entry covering this file to .gitignore (for example "${path.basename(relPath)}" or a ` +
          "matching pattern), then remove it from git history if it was already committed.",
        location: relPath,
      });
    }
  }

  return findings;
};
