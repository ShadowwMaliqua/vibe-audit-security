import type { Severity } from "./types.js";

/**
 * Known-format secret patterns, shared between the static source scanner
 * (secrets.ts) and the dynamic client-side scanner (client_secrets.ts) so
 * both modes flag exactly the same kinds of leaks.
 */
export interface SecretPattern {
  id: string;
  label: string;
  severity: Severity;
  regex: RegExp;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "stripe-live-key",
    label: "Stripe live secret key",
    severity: "critical",
    regex: /sk_live_[0-9a-zA-Z]{20,}/g,
  },
  {
    id: "aws-access-key-id",
    label: "AWS access key ID",
    severity: "critical",
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "google-api-key",
    label: "Google API key",
    severity: "high",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    id: "github-token",
    label: "GitHub token",
    severity: "critical",
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  },
  {
    id: "slack-token",
    label: "Slack token",
    severity: "high",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  },
  {
    id: "slack-webhook",
    label: "Slack incoming webhook URL",
    severity: "high",
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
  },
  {
    id: "pem-private-key",
    label: "PEM private key",
    severity: "critical",
    regex:
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/g,
  },
  {
    id: "db-connection-string",
    label: "database connection string with embedded credentials",
    severity: "critical",
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'/]+:[^@\s"'/]+@[^\s"'/]+/g,
  },
];

export interface DetectedSecret {
  patternId: string;
  label: string;
  severity: Severity;
  match: string;
  index: number;
}

/** Runs every known secret pattern against `text` and returns all matches. */
export function findSecrets(text: string): DetectedSecret[] {
  const found: DetectedSecret[] = [];
  for (const pattern of SECRET_PATTERNS) {
    const flags = pattern.regex.flags.includes("g") ? pattern.regex.flags : `${pattern.regex.flags}g`;
    const regex = new RegExp(pattern.regex.source, flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      found.push({
        patternId: pattern.id,
        label: pattern.label,
        severity: pattern.severity,
        match: match[0],
        index: match.index,
      });
      if (match[0].length === 0) regex.lastIndex += 1;
    }
  }
  return found;
}
