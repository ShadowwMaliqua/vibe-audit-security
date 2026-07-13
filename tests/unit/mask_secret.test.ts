import { describe, expect, it } from "vitest";
import { maskInText, maskSecret } from "../../src/core/mask_secret.js";

describe("maskSecret", () => {
  it("never returns the raw value", () => {
    // Built via concatenation (not a literal) so this test file itself never
    // contains a string that looks like a real credential to secret scanners.
    const secret = `sk_live_${"X".repeat(24)}`;
    const masked = maskSecret(secret);
    expect(masked).not.toBe(secret);
    expect(masked).not.toContain(secret.slice(4, -4));
  });

  it("keeps a short prefix and suffix for long secrets", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const masked = maskSecret(secret);
    expect(masked.startsWith("AKIA")).toBe(true);
    expect(masked.endsWith("MPLE")).toBe(true);
    expect(masked).toContain("*");
  });

  it("fully masks short values instead of leaking them", () => {
    const masked = maskSecret("abcd1234");
    expect(masked).toBe("*".repeat(8));
  });

  it("returns an empty string for empty input", () => {
    expect(maskSecret("")).toBe("");
    expect(maskSecret("   ")).toBe("");
  });

  it("is deterministic and stable across calls", () => {
    const secret = "ghp_1234567890abcdefghijklmnopqrstuvwx";
    expect(maskSecret(secret)).toBe(maskSecret(secret));
  });
});

describe("maskInText", () => {
  it("replaces every occurrence of the secret inside a larger string", () => {
    // Built via concatenation (not a literal) so this test file itself never
    // contains a string that looks like a real credential to secret scanners.
    const secret = `sk_live_${"X".repeat(24)}`;
    const text = `const stripeKey = "${secret}"; // do not commit`;
    const sanitized = maskInText(text, secret);
    expect(sanitized).not.toContain(secret);
    expect(sanitized).toContain("****");
  });

  it("returns text unchanged when secret is empty", () => {
    expect(maskInText("hello world", "")).toBe("hello world");
  });
});
