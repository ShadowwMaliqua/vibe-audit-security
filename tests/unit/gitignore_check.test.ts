import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanGitignore } from "../../src/core/scanners/static/gitignore_check.js";
import type { StaticScanContext } from "../../src/core/types.js";

describe("scanGitignore", () => {
  let rootDir: string;

  beforeEach(async () => {
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibe-audit-gitignore-"));
  });

  afterEach(async () => {
    await fs.rm(rootDir, { recursive: true, force: true });
  });

  async function writeFile(relPath: string, content: string): Promise<void> {
    const abs = path.join(rootDir, relPath);
    await fs.mkdir(path.dirname(abs), { recursive: true });
    await fs.writeFile(abs, content);
  }

  it("flags a missing .gitignore", async () => {
    const ctx: StaticScanContext = { rootDir, files: [] };
    const findings = await scanGitignore(ctx);
    expect(findings.some((f) => f.id === "gitignore-missing")).toBe(true);
  });

  it("flags a .env file not covered by an existing .gitignore", async () => {
    await writeFile(".gitignore", "node_modules/\ndist/\n");
    await writeFile(".env", "SECRET=whatever");
    const ctx: StaticScanContext = { rootDir, files: [".gitignore", ".env"] };
    const findings = await scanGitignore(ctx);
    expect(findings.some((f) => f.id.startsWith("gitignore-uncovered-env-file"))).toBe(true);
    expect(findings.every((f) => f.severity === "critical" || f.id === "gitignore-missing")).toBe(true);
  });

  it("does not flag a .env file that is properly gitignored", async () => {
    await writeFile(".gitignore", ".env\n.env.*\n");
    await writeFile(".env", "SECRET=whatever");
    const ctx: StaticScanContext = { rootDir, files: [".gitignore", ".env"] };
    const findings = await scanGitignore(ctx);
    expect(findings).toHaveLength(0);
  });

  it("does not flag .env.example even without a matching gitignore rule", async () => {
    await writeFile(".gitignore", "node_modules/\n");
    await writeFile(".env.example", "SECRET=fake");
    const ctx: StaticScanContext = { rootDir, files: [".gitignore", ".env.example"] };
    const findings = await scanGitignore(ctx);
    expect(findings).toHaveLength(0);
  });

  it("flags a private key file that isn't ignored", async () => {
    await writeFile(".gitignore", "node_modules/\n");
    await writeFile("id_rsa", "fake-key-content");
    const ctx: StaticScanContext = { rootDir, files: [".gitignore", "id_rsa"] };
    const findings = await scanGitignore(ctx);
    expect(findings.some((f) => f.id.startsWith("gitignore-uncovered-private-key-file"))).toBe(true);
  });
});
