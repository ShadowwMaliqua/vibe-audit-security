import path from "node:path";
import { readTextFileCapped } from "../../fs_walk.js";
import { maskInText, maskSecret } from "../../mask_secret.js";
import { findSecrets } from "../../secret_patterns.js";
import { isLineSuppressed } from "../../suppress.js";
import { lineNumberAt, lineTextAt } from "../../text_location.js";
import type { Finding, StaticScanner } from "../../types.js";

const SKIP_SUFFIXES = [".min.js", ".map", "-lock.json", ".lock"];
// Files whose name signals "this is a template, not a real config" (e.g. the
// .env.example every project is expected to commit) are never flagged: their
// whole purpose is to show the shape of a secret with an obviously fake value.
const TEMPLATE_FILE_RE = /\.(example|sample|template|dist)(\.[^.]+)?$/i;

/**
 * Scans every text file in the project for hardcoded secrets matching known
 * provider formats (Stripe, AWS, Google, GitHub, Slack, PEM keys, DB
 * connection strings). See core/secret_patterns.ts for the pattern list,
 * shared with the dynamic client-side secret scanner.
 */
export const scanSecrets: StaticScanner = async (ctx) => {
  const findings: Finding[] = [];

  for (const relPath of ctx.files) {
    if (SKIP_SUFFIXES.some((suffix) => relPath.endsWith(suffix))) continue;
    if (TEMPLATE_FILE_RE.test(path.basename(relPath))) continue;

    const content = await readTextFileCapped(path.join(ctx.rootDir, relPath));
    if (!content) continue;
    const lines = content.split("\n");

    for (const detection of findSecrets(content)) {
      const line = lineNumberAt(content, detection.index);
      if (isLineSuppressed(lines, line)) continue;
      const lineText = lineTextAt(content, detection.index);
      findings.push({
        id: `secret-${detection.patternId}-${relPath}-${line}`,
        title: `${detection.label} found in source code`,
        severity: detection.severity,
        category: "secrets",
        shortAction: `Remove the hardcoded ${detection.label} from ${relPath}:${line} and rotate it immediately`,
        description:
          `A value matching the pattern for a ${detection.label} was found hardcoded in the source code. ` +
          "If this file is ever committed to version control, the secret is compromised the moment it is " +
          "pushed — even if the file is deleted afterwards, it stays in git history.",
        recommendation:
          "Move this value to an environment variable (loaded via .env, which must stay in .gitignore) or a " +
          "secrets manager, and rotate/revoke the exposed credential now since it may already be compromised.",
        location: relPath,
        line,
        evidence: maskSecret(detection.match),
        codeBefore: maskInText(lineText, detection.match),
      });
    }
  }

  return findings;
};
