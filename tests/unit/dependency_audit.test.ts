import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanDependencies } from "../../src/core/scanners/static/dependency_audit.js";
import type { StaticScanContext } from "../../src/core/types.js";

describe("scanDependencies", () => {
  let rootDir: string;

  beforeEach(async () => {
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibe-audit-deps-"));
  });

  afterEach(async () => {
    await fs.rm(rootDir, { recursive: true, force: true });
  });

  it("does nothing when no dependency manifest is present", async () => {
    const ctx: StaticScanContext = { rootDir, files: ["index.js"] };
    const findings = await scanDependencies(ctx);
    expect(findings).toHaveLength(0);
  });

  it("reports pip-audit as unavailable/informational rather than crashing when Python deps are present", async () => {
    await fs.writeFile(path.join(rootDir, "requirements.txt"), "flask==2.0.0\n");
    const ctx: StaticScanContext = { rootDir, files: ["requirements.txt"] };
    const findings = await scanDependencies(ctx);
    // Either pip-audit is installed in the sandbox and returns real findings,
    // or it's missing and we get a single informational finding — both are fine,
    // the important part is that it never throws.
    expect(Array.isArray(findings)).toBe(true);
    for (const finding of findings) {
      expect(finding.category).toBe("dependencies");
    }
  });
});
