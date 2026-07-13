import { describe, expect, it } from "vitest";
import { isLineSuppressed } from "../../src/core/suppress.js";

describe("isLineSuppressed", () => {
  it("is false when no marker is present", () => {
    const lines = ['const key = "sk_live_example";', "other line"];
    expect(isLineSuppressed(lines, 1)).toBe(false);
  });

  it("is true when the marker is on the same line", () => {
    const lines = ['const key = "sk_live_example"; // vibe-audit-ignore'];
    expect(isLineSuppressed(lines, 1)).toBe(true);
  });

  it("is true when the marker is on the line above", () => {
    const lines = ["// vibe-audit-ignore", 'const key = "sk_live_example";'];
    expect(isLineSuppressed(lines, 2)).toBe(true);
  });

  it("does not suppress unrelated lines", () => {
    const lines = ["// vibe-audit-ignore", 'const key = "sk_live_example";', 'const other = "sk_live_other";'];
    expect(isLineSuppressed(lines, 3)).toBe(false);
  });
});
