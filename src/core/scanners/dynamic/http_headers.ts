import { safeFetch } from "../../safe_fetch.js";
import type { DynamicScanner, Finding, Severity } from "../../types.js";

interface SecurityHeaderCheck {
  header: string;
  displayName: string;
  severity: Severity;
  shortAction: string;
  description: string;
  recommendation: string;
}

const SECURITY_HEADER_CHECKS: SecurityHeaderCheck[] = [
  {
    header: "content-security-policy",
    displayName: "Content-Security-Policy",
    severity: "medium",
    shortAction: "Add a Content-Security-Policy header",
    description:
      "No Content-Security-Policy header was found. CSP is one of the strongest defenses against XSS: " +
      "without it, the browser will happily execute any script an attacker manages to inject.",
    recommendation:
      "Add a Content-Security-Policy header restricting script/style/connect sources to your own domain and " +
      "known third parties.",
  },
  {
    header: "strict-transport-security",
    displayName: "Strict-Transport-Security",
    severity: "medium",
    shortAction: "Add a Strict-Transport-Security (HSTS) header",
    description:
      "No Strict-Transport-Security header was found. Without it, a visit over an unsecured network could be " +
      "silently downgraded from HTTPS to plain HTTP by an attacker in the middle.",
    recommendation:
      "Add Strict-Transport-Security: max-age=63072000; includeSubDomains once you're confident HTTPS works everywhere.",
  },
  {
    header: "x-frame-options",
    displayName: "X-Frame-Options",
    severity: "low",
    shortAction: "Add an X-Frame-Options header (or a CSP frame-ancestors directive)",
    description:
      "No X-Frame-Options header was found, so this page can be embedded in a hidden iframe on another site " +
      "(clickjacking).",
    recommendation: "Add X-Frame-Options: DENY (or SAMEORIGIN), or a CSP frame-ancestors directive.",
  },
  {
    header: "x-content-type-options",
    displayName: "X-Content-Type-Options",
    severity: "low",
    shortAction: "Add X-Content-Type-Options: nosniff",
    description:
      "No X-Content-Type-Options header was found. Some older browsers try to guess ('sniff') a response's " +
      "content type, which has historically enabled certain XSS attacks.",
    recommendation: "Add X-Content-Type-Options: nosniff.",
  },
];

function missingCookieExplanation(missing: string[]): string {
  const parts: string[] = [];
  if (missing.includes("Secure")) {
    parts.push("without Secure, the cookie can be sent over plain HTTP and intercepted on the network");
  }
  if (missing.includes("HttpOnly")) {
    parts.push("without HttpOnly, JavaScript (including an injected XSS payload) can read this cookie");
  }
  if (missing.includes("SameSite")) {
    parts.push("without SameSite, the cookie may be sent along with cross-site requests, which can enable CSRF");
  }
  return `${parts.join("; ")}.`;
}

function checkCookies(headers: Headers, baseUrl: string): Finding[] {
  const findings: Finding[] = [];
  const getSetCookie = (headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  const setCookieHeaders = typeof getSetCookie === "function" ? getSetCookie.call(headers) : [];

  for (const cookieStr of setCookieHeaders) {
    const parts = cookieStr.split(";").map((s) => s.trim());
    const nameValue = parts[0] ?? "";
    const cookieName = nameValue.split("=")[0] || "unknown";
    const attrs = parts.slice(1).map((a) => a.toLowerCase());

    const missing: string[] = [];
    if (!attrs.includes("secure")) missing.push("Secure");
    if (!attrs.includes("httponly")) missing.push("HttpOnly");
    if (!attrs.some((a) => a.startsWith("samesite"))) missing.push("SameSite");
    if (missing.length === 0) continue;

    findings.push({
      id: `cookie-missing-flags-${cookieName}`,
      title: `Cookie "${cookieName}" is missing ${missing.join(", ")}`,
      severity: missing.includes("Secure") || missing.includes("HttpOnly") ? "high" : "medium",
      category: "cookies",
      shortAction: `Set ${missing.join(", ")} on the "${cookieName}" cookie`,
      description: `The cookie "${cookieName}" is missing: ${missing.join(", ")}, ${missingCookieExplanation(missing)}`,
      recommendation: "Set the missing attribute(s), e.g. `Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax`.",
      location: baseUrl,
    });
  }

  return findings;
}

function corsFinding(baseUrl: string, observedOrigin: string): Finding {
  return {
    id: "cors-dynamic-wildcard-credentials",
    title: "CORS allows any origin together with credentials",
    severity: "critical",
    category: "cors",
    shortAction:
      "Restrict Access-Control-Allow-Origin to a fixed allowlist instead of allowing/reflecting any origin with credentials enabled",
    description:
      `This endpoint responded with Access-Control-Allow-Origin: ${observedOrigin} while also sending ` +
      "Access-Control-Allow-Credentials: true. That combination lets any website make authenticated requests " +
      "to this API on behalf of a visitor who is logged in.",
    recommendation: "Only echo back a small, explicit allowlist of trusted origins, and only enable credentials for those.",
    location: baseUrl,
  };
}

async function checkCorsReflection(baseUrl: string): Promise<Finding[]> {
  const probeOrigin = "https://vibe-audit-cors-probe.invalid";
  let res;
  try {
    res = await safeFetch(baseUrl, { method: "GET", headers: { Origin: probeOrigin } });
  } catch {
    return [];
  }

  const allowOrigin = res.headers.get("access-control-allow-origin");
  const allowCredentials = (res.headers.get("access-control-allow-credentials") ?? "").toLowerCase();
  const credentialsEnabled = allowCredentials === "true";

  if (!credentialsEnabled || !allowOrigin) return [];
  if (allowOrigin === "*") return [corsFinding(baseUrl, "*")];
  if (allowOrigin === probeOrigin) return [corsFinding(baseUrl, "a reflected, arbitrary origin")];
  return [];
}

/** Checks missing security headers, insecure cookie flags, and CORS origin-reflection with credentials. */
export const scanHttpHeaders: DynamicScanner = async (ctx) => {
  const findings: Finding[] = [];
  const res = await safeFetch(ctx.baseUrl, { method: "GET" });

  for (const check of SECURITY_HEADER_CHECKS) {
    if (res.headers.has(check.header)) continue;
    findings.push({
      id: `http-header-missing-${check.header}`,
      title: `Missing security header: ${check.displayName}`,
      severity: check.severity,
      category: "http-headers",
      shortAction: check.shortAction,
      description: check.description,
      recommendation: check.recommendation,
      location: ctx.baseUrl,
    });
  }

  findings.push(...checkCookies(res.headers, ctx.baseUrl));
  findings.push(...(await checkCorsReflection(ctx.baseUrl)));

  return findings;
};
