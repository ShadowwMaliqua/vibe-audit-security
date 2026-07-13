import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanDbRules } from "../../src/core/scanners/static/db_rules.js";
import type { StaticScanContext } from "../../src/core/types.js";

describe("scanDbRules", () => {
  let rootDir: string;

  beforeEach(async () => {
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibe-audit-dbrules-"));
  });

  afterEach(async () => {
    await fs.rm(rootDir, { recursive: true, force: true });
  });

  async function writeFile(relPath: string, content: string): Promise<void> {
    const abs = path.join(rootDir, relPath);
    await fs.mkdir(path.dirname(abs), { recursive: true });
    await fs.writeFile(abs, content);
  }

  it("flags a table created without a matching ENABLE ROW LEVEL SECURITY", async () => {
    await writeFile(
      "supabase/migrations/0001_init.sql",
      "CREATE TABLE public.profiles (id uuid PRIMARY KEY, email text);",
    );
    const ctx: StaticScanContext = {
      rootDir,
      files: ["supabase/migrations/0001_init.sql"],
    };
    const findings = await scanDbRules(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("db-rls-missing-profiles");
    expect(findings[0]?.severity).toBe("critical");
  });

  it("does not flag a table that enables RLS in the same migration set", async () => {
    await writeFile(
      "supabase/migrations/0001_init.sql",
      "CREATE TABLE public.profiles (id uuid PRIMARY KEY);\n" +
        "ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;",
    );
    const ctx: StaticScanContext = { rootDir, files: ["supabase/migrations/0001_init.sql"] };
    const findings = await scanDbRules(ctx);
    expect(findings).toHaveLength(0);
  });

  it("finds RLS enabled in a later migration file covering an earlier CREATE TABLE", async () => {
    await writeFile("supabase/migrations/0001_init.sql", "CREATE TABLE orders (id serial PRIMARY KEY);");
    await writeFile("supabase/migrations/0002_rls.sql", "ALTER TABLE orders ENABLE ROW LEVEL SECURITY;");
    const ctx: StaticScanContext = {
      rootDir,
      files: ["supabase/migrations/0001_init.sql", "supabase/migrations/0002_rls.sql"],
    };
    const findings = await scanDbRules(ctx);
    expect(findings).toHaveLength(0);
  });

  it("flags an unconditional allow rule in firestore.rules", async () => {
    await writeFile(
      "firestore.rules",
      "rules_version = '2';\nservice cloud.firestore {\n  match /{document=**} {\n    allow read, write: if true;\n  }\n}",
    );
    const ctx: StaticScanContext = { rootDir, files: ["firestore.rules"] };
    const findings = await scanDbRules(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.category).toBe("database-rules");
  });

  it("does not flag scoped firestore rules", async () => {
    await writeFile(
      "firestore.rules",
      "match /users/{userId} {\n  allow read, write: if request.auth != null && request.auth.uid == userId;\n}",
    );
    const ctx: StaticScanContext = { rootDir, files: ["firestore.rules"] };
    const findings = await scanDbRules(ctx);
    expect(findings).toHaveLength(0);
  });
});
