import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanDangerousPatterns } from "../../src/core/scanners/static/dangerous_patterns.js";
import type { StaticScanContext } from "../../src/core/types.js";

describe("scanDangerousPatterns", () => {
  let rootDir: string;

  beforeEach(async () => {
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibe-audit-danger-"));
  });

  afterEach(async () => {
    await fs.rm(rootDir, { recursive: true, force: true });
  });

  async function writeFile(relPath: string, content: string): Promise<void> {
    const abs = path.join(rootDir, relPath);
    await fs.mkdir(path.dirname(abs), { recursive: true });
    await fs.writeFile(abs, content);
  }

  it("flags eval()", async () => {
    await writeFile("app.js", 'const result = eval(userInput);');
    const findings = await scanDangerousPatterns({ rootDir, files: ["app.js"] } as StaticScanContext);
    expect(findings.some((f) => f.id.startsWith("eval-usage"))).toBe(true);
  });

  it("flags verify=False in Python", async () => {
    await writeFile("client.py", "requests.get(url, verify=False)");
    const findings = await scanDangerousPatterns({ rootDir, files: ["client.py"] } as StaticScanContext);
    expect(findings.some((f) => f.id.startsWith("tls-verify-disabled-python"))).toBe(true);
    expect(findings[0]?.severity).toBe("critical");
  });

  it("flags rejectUnauthorized: false", async () => {
    await writeFile("client.js", "https.request(url, { rejectUnauthorized: false })");
    const findings = await scanDangerousPatterns({ rootDir, files: ["client.js"] } as StaticScanContext);
    expect(findings.some((f) => f.id.startsWith("tls-reject-unauthorized-disabled"))).toBe(true);
  });

  it("flags SQL built with a JS template literal", async () => {
    await writeFile("db.js", "const q = `SELECT * FROM users WHERE id = ${userId}`;");
    const findings = await scanDangerousPatterns({ rootDir, files: ["db.js"] } as StaticScanContext);
    expect(findings.some((f) => f.id.startsWith("sql-injection-js-template"))).toBe(true);
  });

  it("flags SQL built with a Python f-string", async () => {
    await writeFile("db.py", 'query = f"SELECT * FROM users WHERE id = {user_id}"');
    const findings = await scanDangerousPatterns({ rootDir, files: ["db.py"] } as StaticScanContext);
    expect(findings.some((f) => f.id.startsWith("sql-injection-python-fstring"))).toBe(true);
  });

  it("flags hardcoded DEBUG = True in Python", async () => {
    await writeFile("settings.py", "DEBUG = True");
    const findings = await scanDangerousPatterns({ rootDir, files: ["settings.py"] } as StaticScanContext);
    expect(findings.some((f) => f.id.startsWith("debug-mode-hardcoded-python"))).toBe(true);
  });

  it("does not flag parameterized queries", async () => {
    await writeFile("db.js", 'client.query("SELECT * FROM users WHERE id = $1", [userId]);');
    const findings = await scanDangerousPatterns({ rootDir, files: ["db.js"] } as StaticScanContext);
    expect(findings).toHaveLength(0);
  });
});
