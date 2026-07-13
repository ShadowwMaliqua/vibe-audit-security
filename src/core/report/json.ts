import type { ScanResult } from "../types.js";

/** Structured JSON report, used for the --format json CLI output and as the basis for MCP tool responses. */
export function toJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
