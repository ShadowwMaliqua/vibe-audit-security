import { describe, expect, it } from "vitest";
import {
  SsrfBlockedError,
  classifyIp,
  isExplicitLocalHostname,
  resolveAndValidateHost,
} from "../../src/core/ssrf_guard.js";

describe("classifyIp", () => {
  it("classifies RFC1918 private ranges", () => {
    expect(classifyIp("10.0.0.5")).toBe("private");
    expect(classifyIp("172.16.5.1")).toBe("private");
    expect(classifyIp("172.31.255.255")).toBe("private");
    expect(classifyIp("192.168.1.1")).toBe("private");
  });

  it("classifies loopback addresses", () => {
    expect(classifyIp("127.0.0.1")).toBe("loopback");
    expect(classifyIp("127.10.20.30")).toBe("loopback");
    expect(classifyIp("::1")).toBe("loopback");
  });

  it("classifies link-local and the cloud metadata endpoint", () => {
    expect(classifyIp("169.254.1.1")).toBe("link-local");
    expect(classifyIp("169.254.169.254")).toBe("cloud-metadata");
  });

  it("classifies IPv6 unique-local and link-local ranges", () => {
    expect(classifyIp("fc00::1")).toBe("private");
    expect(classifyIp("fd12:3456::1")).toBe("private");
    expect(classifyIp("fe80::1")).toBe("link-local");
  });

  it("unwraps IPv4-mapped IPv6 addresses", () => {
    expect(classifyIp("::ffff:10.0.0.5")).toBe("private");
    expect(classifyIp("::ffff:8.8.8.8")).toBe("public");
  });

  it("classifies public addresses as public", () => {
    expect(classifyIp("8.8.8.8")).toBe("public");
    expect(classifyIp("1.1.1.1")).toBe("public");
  });

  it("classifies CGNAT and reserved test ranges as non-public", () => {
    expect(classifyIp("100.64.0.1")).toBe("private");
    expect(classifyIp("192.0.2.10")).toBe("reserved");
    expect(classifyIp("0.0.0.5")).toBe("reserved");
  });
});

describe("isExplicitLocalHostname", () => {
  it("recognizes localhost and loopback literals", () => {
    expect(isExplicitLocalHostname("localhost")).toBe(true);
    expect(isExplicitLocalHostname("LOCALHOST")).toBe(true);
    expect(isExplicitLocalHostname("127.0.0.1")).toBe(true);
    expect(isExplicitLocalHostname("127.5.5.5")).toBe(true);
    expect(isExplicitLocalHostname("::1")).toBe(true);
  });

  it("does not treat other private hosts as explicit local", () => {
    expect(isExplicitLocalHostname("10.0.0.5")).toBe(false);
    expect(isExplicitLocalHostname("192.168.1.1")).toBe(false);
    expect(isExplicitLocalHostname("example.com")).toBe(false);
    expect(isExplicitLocalHostname("169.254.169.254")).toBe(false);
  });
});

describe("resolveAndValidateHost", () => {
  it("allows explicit loopback targets", async () => {
    const result = await resolveAndValidateHost("127.0.0.1");
    expect(result.address).toBe("127.0.0.1");
  });

  it("allows localhost by name", async () => {
    const result = await resolveAndValidateHost("localhost");
    expect(["127.0.0.1", "::1"]).toContain(result.address);
  });

  it("allows public IP literals", async () => {
    const result = await resolveAndValidateHost("1.1.1.1");
    expect(result.address).toBe("1.1.1.1");
  });

  it("blocks private RFC1918 targets even when not loopback", async () => {
    await expect(resolveAndValidateHost("10.0.0.5")).rejects.toThrow(SsrfBlockedError);
    await expect(resolveAndValidateHost("192.168.1.1")).rejects.toThrow(SsrfBlockedError);
  });

  it("blocks the cloud metadata endpoint", async () => {
    await expect(resolveAndValidateHost("169.254.169.254")).rejects.toThrow(SsrfBlockedError);
  });

  it("blocks link-local addresses", async () => {
    await expect(resolveAndValidateHost("169.254.1.1")).rejects.toThrow(SsrfBlockedError);
  });

  it("does not relax the block for non-loopback addresses just because hostname text mentions local", () => {
    // "localhost.evil.com" is not the literal hostname "localhost" and must
    // never be treated as an explicit local target.
    expect(isExplicitLocalHostname("localhost.evil.com")).toBe(false);
  });
});
