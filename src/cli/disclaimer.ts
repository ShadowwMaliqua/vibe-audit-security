const DISCLAIMER = `vibe-audit — security scanner for vibe-coded projects

Only scan projects, domains, or servers that you own or are explicitly
authorized to test. Running scan-url against a target you do not control may
violate laws (e.g. unauthorized-access statutes) or terms of service. You are
responsible for how you use this tool.`;

const PROBE_DATABASE_WARNING = `--probe-database will send additional read-only HTTP GET requests to the
target's Supabase REST API (a fixed list of common table names) to check
whether Row Level Security actually blocks anonymous access. It still only
performs GET requests and never modifies data — but only run this against a
Supabase project you own or are explicitly authorized to test.`;

/** Printed to stderr on every CLI invocation, so stdout stays clean for machine-readable output. */
export function printDisclaimer(): void {
  console.error(DISCLAIMER);
  console.error("");
}

export function printProbeDatabaseWarning(): void {
  console.error(PROBE_DATABASE_WARNING);
  console.error("");
}
