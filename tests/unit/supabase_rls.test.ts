import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { scanSupabaseRls } from "../../src/core/scanners/dynamic/supabase_rls.js";
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

function fakeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.fakesignature`;
}

describe("scanSupabaseRls", () => {
  it("returns nothing when no Supabase URL is present", async () => {
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html><body>Hello</body></html>");
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanSupabaseRls(ctx);
    expect(findings).toHaveLength(0);
  });

  it("returns nothing when only a service_role key is present (never probes with it)", async () => {
    const key = fakeJwt({ role: "service_role", ref: "abcprojects" });
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body><script>const url="https://abcprojects.supabase.co"; const key="${key}";</script></body></html>`);
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanSupabaseRls(ctx);
    expect(findings).toHaveLength(0);
  });

  it("reports detection without probing when probeDatabase is false", async () => {
    const key = fakeJwt({ role: "anon", ref: "abcprojects" });
    const baseUrl = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body><script>const url="https://abcprojects.supabase.co"; const key="${key}";</script></body></html>`);
    });
    const ctx: DynamicScanContext = { baseUrl, probeDatabase: false };
    const findings = await scanSupabaseRls(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("supabase-detected-not-probed");
    expect(findings[0]?.severity).toBe("info");
    expect(findings[0]?.evidence).not.toContain(key);
  });
});
