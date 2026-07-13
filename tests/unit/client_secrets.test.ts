import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { scanClientSecrets } from "../../src/core/scanners/dynamic/client_secrets.js";
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

describe("scanClientSecrets", () => {
  it("finds a secret embedded directly in the HTML", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end('<html><body><script>window.KEY="sk_live_51H8x9J2eZvKYlo2CJ9x8ExampleKeyLooksReal"</script></body></html>');
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanClientSecrets(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.evidence).not.toContain("51H8x9J2eZvKYlo2CJ9x8ExampleKeyLooksReal");
  });

  it("follows a same-origin script and finds a secret inside it", async () => {
    const baseUrl = await startServer((req, res) => {
      if (req.url === "/bundle.js") {
        res.writeHead(200, { "Content-Type": "application/javascript" });
        res.end('const AWS_KEY = "AKIAABCDEFGHIJKLMNOP";');
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end('<html><head><script src="/bundle.js"></script></head><body></body></html>');
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanClientSecrets(ctx);
    expect(findings.some((f) => f.id.includes("aws-access-key-id"))).toBe(true);
  });

  it("does not fetch cross-origin scripts", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end('<html><head><script src="https://cdn.example.com/analytics.js"></script></head><body></body></html>');
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanClientSecrets(ctx);
    expect(findings).toHaveLength(0);
  });

  it("returns no findings for clean pages", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html><body>Hello</body></html>");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanClientSecrets(ctx);
    expect(findings).toHaveLength(0);
  });
});
