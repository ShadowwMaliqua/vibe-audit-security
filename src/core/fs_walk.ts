import fs from "node:fs/promises";
import path from "node:path";

const DEFAULT_EXCLUDED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "out",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
  ".cache",
  ".turbo",
  "target",
  "vendor",
  ".pytest_cache",
  ".mypy_cache",
]);

export interface WalkOptions {
  /** Safety cap so a huge or unusual tree cannot make the scan run forever. */
  maxFiles?: number;
  excludedDirs?: Set<string>;
}

/**
 * Recursively lists files under rootDir, pruning noisy/irrelevant
 * directories (node_modules, .git, build output, venvs, ...) before
 * descending into them rather than filtering after the fact.
 */
export async function walkDirectory(rootDir: string, options: WalkOptions = {}): Promise<string[]> {
  const maxFiles = options.maxFiles ?? 20000;
  const excludedDirs = options.excludedDirs ?? DEFAULT_EXCLUDED_DIRS;
  const results: string[] = [];

  async function walk(currentDir: string): Promise<void> {
    if (results.length >= maxFiles) return;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (results.length >= maxFiles) return;
      if (entry.isSymbolicLink()) continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (excludedDirs.has(entry.name)) continue;
        await walk(fullPath);
      } else if (entry.isFile()) {
        results.push(path.relative(rootDir, fullPath));
      }
    }
  }

  await walk(rootDir);
  return results;
}

const BINARY_PROBE_BYTES = 512;

/** Heuristic: a chunk containing a NUL byte is treated as binary content. */
function looksBinary(buffer: Buffer): boolean {
  const probeLength = Math.min(buffer.length, BINARY_PROBE_BYTES);
  for (let i = 0; i < probeLength; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

const DEFAULT_MAX_READ_BYTES = 2 * 1024 * 1024; // 2 MB

/**
 * Reads a file as UTF-8 text, skipping binaries and oversized files
 * (returns null in both cases) so scanners never choke on lockfiles,
 * images, or multi-GB logs.
 */
export async function readTextFileCapped(
  absPath: string,
  maxBytes: number = DEFAULT_MAX_READ_BYTES,
): Promise<string | null> {
  let stat;
  try {
    stat = await fs.stat(absPath);
  } catch {
    return null;
  }
  if (!stat.isFile() || stat.size === 0 || stat.size > maxBytes) return null;

  let buffer: Buffer;
  try {
    buffer = await fs.readFile(absPath);
  } catch {
    return null;
  }
  if (looksBinary(buffer)) return null;
  return buffer.toString("utf-8");
}
