export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * A single security issue detected by a scanner.
 *
 * `shortAction` and `description` are kept separate on purpose: shortAction is
 * meant to be read directly by an LLM summarizing results in a conversation,
 * while `description` is the fuller, plain-language explanation for reports.
 */
export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  shortAction: string;
  description: string;
  recommendation: string;
  location?: string;
  line?: number;
  /** Always pre-masked via maskSecret before being set here. Never raw. */
  evidence?: string;
  codeBefore?: string;
  codeAfter?: string;
  references?: string[];
}

export type FindingCategory =
  | "secrets"
  | "gitignore"
  | "database-rules"
  | "cors"
  | "dependencies"
  | "dangerous-patterns"
  | "http-headers"
  | "cookies"
  | "exposed-files"
  | "client-secrets"
  | "supabase-rls"
  | "scan-error";

export type ScanMode = "code" | "url" | "project";

export interface ScanMeta {
  target: string;
  mode: ScanMode;
  startedAt: string;
  finishedAt: string;
  toolVersion: string;
  probeDatabaseUsed: boolean;
}

export interface ScanResult {
  meta: ScanMeta;
  findings: Finding[];
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  countsBySeverity: Record<Severity, number>;
}

export interface StaticScanContext {
  /** Absolute path to the project root being scanned. */
  rootDir: string;
  /** Paths relative to rootDir, produced by fs_walk. */
  files: string[];
}

export type StaticScanner = (ctx: StaticScanContext) => Promise<Finding[]> | Finding[];

export interface DynamicScanContext {
  /** Validated, SSRF-checked base URL. */
  baseUrl: string;
  probeDatabase: boolean;
}

export type DynamicScanner = (ctx: DynamicScanContext) => Promise<Finding[]>;
