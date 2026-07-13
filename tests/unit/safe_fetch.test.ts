import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { safeFetch } from "../../src/core/safe_fetch.js";
import { SsrfBlockedError } from "../../src/core/ssrf_guard.js";

describe("safeFetch", () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      if (req.url === "/redirect-once") {
        res.writeHead(302, { Location: "/ok" });
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Type": "text/plain", "X-Test": "1" });
      res.end("hello from test server");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("fetches an explicit loopback target successfully", async () => {
    const result = await safeFetch(`${baseUrl}/ok`);
    expect(result.status).toBe(200);
    expect(result.bodyText).toContain("hello from test server");
  });

  it("follows redirects while re-validating each hop", async () => {
    const result = await safeFetch(`${baseUrl}/redirect-once`);
    expect(result.status).toBe(200);
    expect(result.finalUrl).toContain("/ok");
  });

  it("rejects POST-like usage; only GET/HEAD are allowed", async () => {
    // @ts-expect-error intentionally passing a disallowed method
    await expect(safeFetch(`${baseUrl}/ok`, { method: "POST" })).rejects.toThrow(SsrfBlockedError);
  });

  it("blocks requests to private IPs even though the target is technically reachable", async () => {
    await expect(safeFetch("http://10.0.0.5:80/")).rejects.toThrow(SsrfBlockedError);
  });

  it("blocks the cloud metadata endpoint", async () => {
    await expect(safeFetch("http://169.254.169.254/latest/meta-data/")).rejects.toThrow(
      SsrfBlockedError,
    );
  });
});
