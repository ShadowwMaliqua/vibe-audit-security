import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanCorsConfig } from "../../src/core/scanners/static/cors_config.js";
import type { StaticScanContext } from "../../src/core/types.js";

describe("scanCorsConfig", () => {
  let rootDir: string;

  beforeEach(async () => {
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibe-audit-cors-"));
  });

  afterEach(async () => {
    await fs.rm(rootDir, { recursive: true, force: true });
  });

  async function writeFile(relPath: string, content: string): Promise<void> {
    const abs = path.join(rootDir, relPath);
    await fs.mkdir(path.dirname(abs), { recursive: true });
    await fs.writeFile(abs, content);
  }

  it("flags Express cors() with wildcard origin and credentials", async () => {
    await writeFile(
      "server.js",
      "app.use(cors({ origin: '*', credentials: true }));",
    );
    const ctx: StaticScanContext = { rootDir, files: ["server.js"] };
    const findings = await scanCorsConfig(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
  });

  it("does not flag Express cors() with an explicit origin allowlist", async () => {
    await writeFile(
      "server.js",
      "app.use(cors({ origin: ['https://example.com'], credentials: true }));",
    );
    const ctx: StaticScanContext = { rootDir, files: ["server.js"] };
    const findings = await scanCorsConfig(ctx);
    expect(findings).toHaveLength(0);
  });

  it("flags FastAPI CORSMiddleware with wildcard origin and credentials", async () => {
    await writeFile(
      "main.py",
      "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)",
    );
    const ctx: StaticScanContext = { rootDir, files: ["main.py"] };
    const findings = await scanCorsConfig(ctx);
    expect(findings).toHaveLength(1);
  });

  it("flags raw wildcard header combined with credentials header", async () => {
    await writeFile(
      "server.js",
      "res.setHeader('Access-Control-Allow-Origin', '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
    );
    const ctx: StaticScanContext = { rootDir, files: ["server.js"] };
    const findings = await scanCorsConfig(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toContain("cors-raw-header-wildcard-credentials");
  });
});
