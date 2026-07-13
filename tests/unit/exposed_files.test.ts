import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { scanExposedFiles } from "../../src/core/scanners/dynamic/exposed_files.js";
import type { DynamicScanContext } from "../../src/core/types.js";

let server: http.Server | undefined;

async function startServer(handler: http.RequestListener): Promise<string> {
  server = http.createServer(handler);
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  }
});

describe("scanExposedFiles", () => {
  it("flags a real exposed .env file on an otherwise 404 server", async () => {
    const baseUrl = await startServer((req, res) => {
      if (req.url === "/.env") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("DB_PASSWORD=supersecret\nAPI_KEY=xyz1234567890\n");
        return;
      }
      res.writeHead(404);
      res.end("Not Found");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanExposedFiles(ctx);
    expect(findings.some((f) => f.id === "exposed-file--env")).toBe(true);
    const finding = findings.find((f) => f.id === "exposed-file--env");
    expect(finding?.severity).toBe("critical");
  });

  it("does not flag anything when nothing sensitive is exposed", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(404);
      res.end("Not Found");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanExposedFiles(ctx);
    expect(findings).toHaveLength(0);
  });

  it("does not flag a SPA catch-all that returns 200 with the same shell for every path", async () => {
    const appShell = "<html><body><div id=\"root\"></div></body></html>".repeat(3);
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(appShell);
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanExposedFiles(ctx);
    expect(findings).toHaveLength(0);
  });
});
