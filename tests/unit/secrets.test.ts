import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanSecrets } from "../../src/core/scanners/static/secrets.js";
import type { StaticScanContext } from "../../src/core/types.js";

describe("scanSecrets", () => {
  let rootDir: string;

  beforeEach(async () => {
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibe-audit-secrets-"));
  });

  afterEach(async () => {
    await fs.rm(rootDir, { recursive: true, force: true });
  });

  async function writeFile(relPath: string, content: string): Promise<void> {
    const abs = path.join(rootDir, relPath);
    await fs.mkdir(path.dirname(abs), { recursive: true });
    await fs.writeFile(abs, content);
  }

  it("detects a hardcoded Stripe live key and masks it in the report", async () => {
    await writeFile("server.js", 'const stripeKey = "sk_live_51H8x9J2eZvKYlo2CJ9x8ExampleKeyLooksReal";');
    const ctx: StaticScanContext = { rootDir, files: ["server.js"] };
    const findings = await scanSecrets(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.category).toBe("secrets");
    expect(findings[0]?.evidence).not.toContain("51H8x9J2eZvKYlo2CJ9x8ExampleKeyLooksReal");
    expect(findings[0]?.codeBefore).not.toContain("sk_live_51H8x9J2eZvKYlo2CJ9x8ExampleKeyLooksReal");
  });

  it("detects an AWS access key ID", async () => {
    await writeFile(".env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n");
    const ctx: StaticScanContext = { rootDir, files: [".env"] };
    const findings = await scanSecrets(ctx);
    expect(findings.some((f) => f.id.startsWith("secret-aws-access-key-id"))).toBe(true);
  });

  it("detects a PEM private key block", async () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----";
    await writeFile("keys/id_rsa.txt", pem);
    const ctx: StaticScanContext = { rootDir, files: ["keys/id_rsa.txt"] };
    const findings = await scanSecrets(ctx);
    expect(findings.some((f) => f.id.startsWith("secret-pem-private-key"))).toBe(true);
  });

  it("detects a database connection string with embedded credentials", async () => {
    await writeFile("config.py", 'DATABASE_URL = "postgres://admin:s3cr3tPass@db.example.com:5432/prod"');
    const ctx: StaticScanContext = { rootDir, files: ["config.py"] };
    const findings = await scanSecrets(ctx);
    expect(findings.some((f) => f.id.startsWith("secret-db-connection-string"))).toBe(true);
  });

  it("does not flag clean files", async () => {
    await writeFile("index.js", 'console.log("hello world");');
    const ctx: StaticScanContext = { rootDir, files: ["index.js"] };
    const findings = await scanSecrets(ctx);
    expect(findings).toHaveLength(0);
  });
});
