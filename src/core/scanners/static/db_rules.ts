import path from "node:path";
import { readTextFileCapped } from "../../fs_walk.js";
import { lineNumberAt } from "../../text_location.js";
import type { Finding, StaticScanner } from "../../types.js";

const CREATE_TABLE_RE =
  /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?(?:public\.)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?/gi;
const ENABLE_RLS_RE =
  /ALTER\s+TABLE\s+(?:ONLY\s+)?"?(?:public\.)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
const FIRESTORE_ALLOW_TRUE_RE = /allow\s+[a-zA-Z,\s]+:\s*if\s+true\s*;/gi;

function isSupabaseMigration(relPath: string): boolean {
  const posix = relPath.split(path.sep).join("/");
  return /(^|\/)supabase\/migrations\/[^/]+\.sql$/i.test(posix);
}

/**
 * Two independent checks:
 *  - Supabase/Postgres migrations: tables created without a matching
 *    "ENABLE ROW LEVEL SECURITY" anywhere in the migration set.
 *  - firestore.rules: rules that grant unconditional access ("if true").
 */
export const scanDbRules: StaticScanner = async (ctx) => {
  const findings: Finding[] = [];

  const migrationFiles = ctx.files.filter(isSupabaseMigration);
  if (migrationFiles.length > 0) {
    const createdTables = new Map<string, { file: string; line: number }>();
    const rlsEnabledTables = new Set<string>();

    for (const relPath of migrationFiles) {
      const content = await readTextFileCapped(path.join(ctx.rootDir, relPath), 5_000_000);
      if (!content) continue;

      for (const match of content.matchAll(CREATE_TABLE_RE)) {
        const table = match[1]?.toLowerCase();
        if (!table || createdTables.has(table)) continue;
        createdTables.set(table, { file: relPath, line: lineNumberAt(content, match.index ?? 0) });
      }
      for (const match of content.matchAll(ENABLE_RLS_RE)) {
        const table = match[1]?.toLowerCase();
        if (table) rlsEnabledTables.add(table);
      }
    }

    for (const [table, loc] of createdTables) {
      if (rlsEnabledTables.has(table)) continue;
      findings.push({
        id: `db-rls-missing-${table}`,
        title: `Table "${table}" created without Row Level Security`,
        severity: "critical",
        category: "database-rules",
        shortAction: `Enable RLS on "${table}" (ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY) and add policies`,
        description:
          `Migration "${loc.file}" creates a table named "${table}", but no migration enables Row Level ` +
          "Security on it. On Supabase, a table without RLS is readable and writable by anyone holding the " +
          "public anon API key, regardless of who owns the row.",
        recommendation:
          `Add "ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;" plus explicit policies for the operations ` +
          "you actually want to allow (select/insert/update/delete), in a migration.",
        location: loc.file,
        line: loc.line,
      });
    }
  }

  const firestoreRulesFiles = ctx.files.filter((relPath) => path.basename(relPath) === "firestore.rules");
  for (const relPath of firestoreRulesFiles) {
    const content = await readTextFileCapped(path.join(ctx.rootDir, relPath), 2_000_000);
    if (!content) continue;

    for (const match of content.matchAll(FIRESTORE_ALLOW_TRUE_RE)) {
      const line = lineNumberAt(content, match.index ?? 0);
      const snippet = match[0].trim();
      findings.push({
        id: `firestore-allow-true-${relPath}-${line}`,
        title: "Firestore rule allows unrestricted access",
        severity: "critical",
        category: "database-rules",
        shortAction: `Replace "${snippet}" in ${relPath}:${line} with a rule that checks authentication/ownership`,
        description:
          `"${relPath}" contains a rule that unconditionally allows access ("${snippet}"). Any client, ` +
          "including unauthenticated ones, can read and/or write this data.",
        recommendation:
          'Scope the rule to authenticated, authorized requests, e.g. ' +
          '"allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;".',
        location: relPath,
        line,
        codeBefore: snippet,
      });
    }
  }

  return findings;
};
