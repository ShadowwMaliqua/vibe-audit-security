import type { Dispatcher } from "undici";
import { Agent, fetch as undiciFetch } from "undici";
import type { ValidatedAddress } from "./ssrf_guard.js";
import { SsrfBlockedError, resolveAndValidateHost } from "./ssrf_guard.js";

export const DEFAULT_TIMEOUT_MS = 8000;
export const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB
const MAX_REDIRECTS = 5;
const ALLOWED_METHODS = new Set(["GET", "HEAD"]);

export interface SafeFetchOptions {
  method?: "GET" | "HEAD";
  headers?: Record<string, string>;
  timeoutMs?: number;
  maxBodyBytes?: number;
}

export interface SafeFetchResult {
  ok: boolean;
  status: number;
  headers: Headers;
  /** Final URL after following (and re-validating) redirects. */
  finalUrl: string;
  bodyText: string;
  truncated: boolean;
}

type NodeLookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | { address: string; family: number }[],
  family?: number,
) => void;

/**
 * Builds a dns.lookup-compatible function that always returns the single,
 * already-validated address — regardless of what the system resolver would
 * say. This is what makes the SSRF check TOCTOU-safe: the socket can only
 * ever connect to the address we inspected, never to a fresh DNS answer.
 */
function makeGuardedLookup(validated: ValidatedAddress) {
  return (
    _hostname: string,
    optionsOrCallback: unknown,
    maybeCallback?: NodeLookupCallback,
  ): void => {
    let callback = maybeCallback;
    let options: { all?: boolean } = {};
    if (typeof optionsOrCallback === "function") {
      callback = optionsOrCallback as NodeLookupCallback;
    } else if (optionsOrCallback && typeof optionsOrCallback === "object") {
      options = optionsOrCallback as { all?: boolean };
    }
    if (!callback) return;
    if (options.all) {
      callback(null, [{ address: validated.address, family: validated.family }]);
    } else {
      callback(null, validated.address, validated.family);
    }
  };
}

async function readBodyWithLimit(
  body: ReadableStream<Uint8Array> | null,
  limit: number,
): Promise<{ text: string; truncated: boolean }> {
  if (!body) return { text: "", truncated: false };
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > limit) {
        const alreadyTaken = total - value.byteLength;
        const remaining = limit - alreadyTaken;
        if (remaining > 0) chunks.push(Buffer.from(value.slice(0, remaining)));
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock?.();
  }
  return { text: Buffer.concat(chunks).toString("utf-8"), truncated };
}

/**
 * SSRF-guarded fetch. GET/HEAD only, strict timeout, capped response size,
 * and every redirect hop is independently resolved and re-validated before
 * being followed (redirect: "manual" + a manual loop, never automatic).
 */
export async function safeFetch(
  inputUrl: string,
  opts: SafeFetchOptions = {},
): Promise<SafeFetchResult> {
  const method = opts.method ?? "GET";
  if (!ALLOWED_METHODS.has(method)) {
    throw new SsrfBlockedError(`Method ${method} is not allowed; vibe-audit only sends GET/HEAD`);
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBodyBytes = opts.maxBodyBytes ?? MAX_BODY_BYTES;

  let currentUrl: URL;
  try {
    currentUrl = new URL(inputUrl);
  } catch {
    throw new SsrfBlockedError(`Invalid URL: ${inputUrl}`);
  }

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!["http:", "https:"].includes(currentUrl.protocol)) {
      throw new SsrfBlockedError(`Unsupported protocol: ${currentUrl.protocol}`);
    }

    const validated = await resolveAndValidateHost(currentUrl.hostname);
    const agent = new Agent({
      connect: { lookup: makeGuardedLookup(validated) as never },
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await undiciFetch(currentUrl, {
        method,
        ...(opts.headers ? { headers: opts.headers } : {}),
        redirect: "manual",
        dispatcher: agent as unknown as Dispatcher,
        signal: controller.signal,
      });

      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const location = res.headers.get("location");
        if (!location) {
          throw new SsrfBlockedError(`Redirect (${res.status}) without a Location header`);
        }
        currentUrl = new URL(location, currentUrl);
        continue;
      }

      const { text, truncated } = await readBodyWithLimit(res.body, maxBodyBytes);
      return {
        ok: res.ok,
        status: res.status,
        headers: res.headers,
        finalUrl: currentUrl.toString(),
        bodyText: text,
        truncated,
      };
    } finally {
      clearTimeout(timer);
      await agent.close();
    }
  }

  throw new SsrfBlockedError(`Too many redirects (> ${MAX_REDIRECTS}) while fetching ${inputUrl}`);
}
