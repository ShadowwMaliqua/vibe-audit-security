import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { scanHttpHeaders } from "../../src/core/scanners/dynamic/http_headers.js";
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

describe("scanHttpHeaders", () => {
  it("flags all missing security headers on a bare response", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("hi");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanHttpHeaders(ctx);

    const headerFindingIds = findings.filter((f) => f.category === "http-headers").map((f) => f.id);
    expect(headerFindingIds).toContain("http-header-missing-content-security-policy");
    expect(headerFindingIds).toContain("http-header-missing-strict-transport-security");
    expect(headerFindingIds).toContain("http-header-missing-x-frame-options");
    expect(headerFindingIds).toContain("http-header-missing-x-content-type-options");
  });

  it("does not flag headers that are present", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, {
        "Content-Type": "text/plain",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
      });
      res.end("hi");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanHttpHeaders(ctx);
    expect(findings.filter((f) => f.category === "http-headers")).toHaveLength(0);
  });

  it("flags a cookie missing Secure/HttpOnly/SameSite", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Set-Cookie": "session=abc123; Path=/" });
      res.end("hi");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanHttpHeaders(ctx);
    const cookieFinding = findings.find((f) => f.category === "cookies");
    expect(cookieFinding).toBeDefined();
    expect(cookieFinding?.severity).toBe("high");
  });

  it("does not flag a properly-flagged cookie", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax" });
      res.end("hi");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanHttpHeaders(ctx);
    expect(findings.filter((f) => f.category === "cookies")).toHaveLength(0);
  });

  it("flags CORS wildcard origin combined with credentials", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
      });
      res.end("hi");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanHttpHeaders(ctx);
    expect(findings.some((f) => f.id === "cors-dynamic-wildcard-credentials")).toBe(true);
  });

  it("flags CORS reflecting an arbitrary Origin with credentials enabled", async () => {
    const baseUrl = await startServer((req, res) => {
      const origin = req.headers.origin ?? "";
      res.writeHead(200, {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
      });
      res.end("hi");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanHttpHeaders(ctx);
    expect(findings.some((f) => f.id === "cors-dynamic-wildcard-credentials")).toBe(true);
  });
});
