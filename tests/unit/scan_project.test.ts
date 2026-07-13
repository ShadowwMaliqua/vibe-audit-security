import fs from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanProject } from "../../src/core/scan_project.js";

describe("scanProject", () => {
  let rootDir: string | undefined;
  let server: http.Server | undefined;

  afterEach(async () => {
    if (rootDir) await fs.rm(rootDir, { recursive: true, force: true });
    if (server) await new Promise<void>((resolve) => server?.close(() => resolve()));
    rootDir = undefined;
    server = undefined;
  });

  it("throws when neither projectPath nor url is given", async () => {
    await expect(scanProject({})).rejects.toThrow();
  });

  it("merges code and url findings into a single mode:project result", async () => {
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibe-audit-project-"));
    await fs.writeFile(path.join(rootDir, "server.js"), 'const key = "sk_live_XXXXXXXXXXXXXXXXXXXXXXXX";');

    server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("hi");
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const address = server.address() as AddressInfo;
    const url = `http://127.0.0.1:${address.port}`;

    const result = await scanProject({ projectPath: rootDir, url });

    expect(result.meta.mode).toBe("project");
    expect(result.findings.some((f) => f.category === "secrets")).toBe(true);
    expect(result.findings.some((f) => f.category === "http-headers")).toBe(true);
  });
});
