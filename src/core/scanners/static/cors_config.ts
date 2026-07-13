import path from "node:path";
import { readTextFileCapped } from "../../fs_walk.js";
import { lineNumberAt } from "../../text_location.js";
import type { Finding, StaticScanner } from "../../types.js";

const RELEVANT_FILE_RE = /\.(js|jsx|ts|tsx|mjs|cjs|py)$/i;
const CORS_CALL_RE = /\bcors\s*\(/g; // Express `cors` npm package
const CORS_MIDDLEWARE_CTOR_RE = /CORSMiddleware\s*\(/g; // raw Starlette: CORSMiddleware(app, ...)
const ADD_MIDDLEWARE_RE = /add_middleware\s*\(/g; // FastAPI: app.add_middleware(CORSMiddleware, ...)

/**
 * Extracts the text between a call's opening `(` (index just past it) and
 * its matching closing `)`, tracking nesting depth. Used to isolate a
 * cors({...}) / CORSMiddleware(...) argument block for inspection, since we
 * don't want a full AST parser as a dependency.
 */
function extractBalancedCall(content: string, openParenIndex: number): string | null {
  let depth = 1;
  let i = openParenIndex;
  while (i < content.length && depth > 0) {
    if (content[i] === "(") depth++;
    else if (content[i] === ")") depth--;
    i++;
  }
  return depth === 0 ? content.slice(openParenIndex, i - 1) : null;
}

function looksWildcardOrigin(block: string): boolean {
  return (
    /origin\s*:\s*(['"]\*['"]|true)/.test(block) ||
    /allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]/.test(block) ||
    /allow_origin_regex\s*=\s*['"].*\.\*.*['"]/.test(block)
  );
}

function looksCredentialsTrue(block: string): boolean {
  return /credentials\s*:\s*true/.test(block) || /allow_credentials\s*=\s*True\b/.test(block);
}

function hasRawWildcardCredentials(content: string): boolean {
  const wildcardHeader =
    /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/.test(content) ||
    /setHeader\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]\s*\)/.test(content);
  const credentialsHeader = /Access-Control-Allow-Credentials['"]?\s*[,:]\s*['"]?true['"]?/i.test(content);
  return wildcardHeader && credentialsHeader;
}

/**
 * Heuristic (regex-based, not a full parser) scan for Express `cors()` and
 * FastAPI `CORSMiddleware` configurations — and raw header juggling — that
 * combine a wildcard/any origin with credentials enabled.
 */
export const scanCorsConfig: StaticScanner = async (ctx) => {
  const findings: Finding[] = [];

  for (const relPath of ctx.files.filter((p) => RELEVANT_FILE_RE.test(p))) {
    const content = await readTextFileCapped(path.join(ctx.rootDir, relPath));
    if (!content) continue;

    let flaggedThisFile = false;

    for (const callRegex of [CORS_CALL_RE, CORS_MIDDLEWARE_CTOR_RE, ADD_MIDDLEWARE_RE]) {
      callRegex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = callRegex.exec(content)) !== null) {
        const block = extractBalancedCall(content, callRegex.lastIndex);
        if (!block) continue;
        // app.add_middleware(...) is used for many middleware types; only
        // treat it as a CORS config when it actually references CORSMiddleware.
        if (callRegex === ADD_MIDDLEWARE_RE && !/CORSMiddleware/.test(block)) continue;

        if (looksWildcardOrigin(block) && looksCredentialsTrue(block)) {
          const line = lineNumberAt(content, match.index);
          findings.push({
            id: `cors-wildcard-credentials-${relPath}-${line}`,
            title: "CORS allows any origin together with credentials",
            severity: "critical",
            category: "cors",
            shortAction: `Restrict the origin allowlist in ${relPath}:${line} instead of using a wildcard with credentials enabled`,
            description:
              "This CORS configuration combines a wildcard/any origin with credentials enabled. Browsers " +
              "already forbid this combination for real credentialed requests, so servers that accept it " +
              "typically end up reflecting the request's Origin header — which lets any website read " +
              "authenticated responses from this API on behalf of a logged-in visitor.",
            recommendation:
              'List explicit allowed origins (e.g. your production domain and localhost for dev) instead of ' +
              '"*" or reflecting the request Origin, and only enable credentials for those explicit origins.',
            location: relPath,
            line,
            codeBefore: block.length > 300 ? `${block.slice(0, 300)}...` : block,
          });
          flaggedThisFile = true;
        }
      }
    }

    if (!flaggedThisFile && hasRawWildcardCredentials(content)) {
      findings.push({
        id: `cors-raw-header-wildcard-credentials-${relPath}`,
        title: "CORS headers set manually with wildcard origin and credentials",
        severity: "critical",
        category: "cors",
        shortAction: `Stop setting Access-Control-Allow-Origin to "*" alongside Access-Control-Allow-Credentials: true in ${relPath}`,
        description:
          "This file sets the Access-Control-Allow-Origin header to a wildcard while also enabling " +
          "Access-Control-Allow-Credentials. This combination effectively lets any website make authenticated " +
          "requests to this endpoint on behalf of a logged-in user.",
        recommendation:
          'Set Access-Control-Allow-Origin to a specific, validated origin (never "*") whenever credentials are involved.',
        location: relPath,
      });
    }
  }

  return findings;
};
