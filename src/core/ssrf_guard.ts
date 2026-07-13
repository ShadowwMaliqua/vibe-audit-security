import dns from "node:dns";
import net from "node:net";

/**
 * Network guard rail for the dynamic scanner (scan-url mode). Blocks requests
 * to private/internal/cloud-metadata addresses so the tool cannot be turned
 * into an SSRF proxy against the machine running it or its local network.
 *
 * Design goal: avoid a DNS-rebinding TOCTOU. We resolve the hostname exactly
 * once, validate every returned address, and the caller (safe_fetch) must
 * connect using that already-validated address rather than resolving again.
 */

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfBlockedError";
  }
}

export type IpClassification =
  | "loopback"
  | "private"
  | "link-local"
  | "cloud-metadata"
  | "reserved"
  | "public";

const AWS_IMDS_V6 = "fd00:ec2::254";

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8) | n;
  }
  return value >>> 0;
}

function inRange(intIp: number, base: string, prefix: number): boolean {
  const baseInt = ipv4ToInt(base);
  if (baseInt === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (intIp & mask) === (baseInt & mask);
}

function classifyIpv4(ip: string): IpClassification {
  const intIp = ipv4ToInt(ip);
  if (intIp === null) return "reserved";

  if (inRange(intIp, "127.0.0.0", 8)) return "loopback";
  if (inRange(intIp, "169.254.0.0", 16)) {
    // 169.254.169.254 is the AWS/GCP/Azure metadata endpoint; the whole
    // link-local range is blocked anyway, but we tag it explicitly so
    // reports can call it out by name.
    return ip === "169.254.169.254" ? "cloud-metadata" : "link-local";
  }
  if (inRange(intIp, "10.0.0.0", 8)) return "private";
  if (inRange(intIp, "172.16.0.0", 12)) return "private";
  if (inRange(intIp, "192.168.0.0", 16)) return "private";
  if (inRange(intIp, "100.64.0.0", 10)) return "private"; // CGNAT
  if (inRange(intIp, "0.0.0.0", 8)) return "reserved";
  if (inRange(intIp, "192.0.0.0", 24)) return "reserved"; // IETF protocol assignments
  if (inRange(intIp, "192.0.2.0", 24)) return "reserved"; // TEST-NET-1
  if (inRange(intIp, "198.18.0.0", 15)) return "reserved"; // benchmarking
  if (inRange(intIp, "198.51.100.0", 24)) return "reserved"; // TEST-NET-2
  if (inRange(intIp, "203.0.113.0", 24)) return "reserved"; // TEST-NET-3
  if (inRange(intIp, "224.0.0.0", 4)) return "reserved"; // multicast
  if (inRange(intIp, "240.0.0.0", 4)) return "reserved"; // reserved/broadcast

  return "public";
}

function classifyIpv6(ip: string): IpClassification {
  const normalized = ip.toLowerCase();

  if (normalized === "::1") return "loopback";
  if (normalized === AWS_IMDS_V6) return "cloud-metadata";

  // IPv4-mapped / IPv4-compatible addresses: unwrap and classify as IPv4.
  const mappedMatch = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mappedMatch?.[1]) return classifyIpv4(mappedMatch[1]);

  if (normalized.startsWith("fe80:")) return "link-local";
  // Unique local addresses (fc00::/7): first byte 0xfc or 0xfd.
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return "private";

  return "public";
}

export function classifyIp(ip: string): IpClassification {
  if (net.isIPv4(ip)) return classifyIpv4(ip);
  if (net.isIPv6(ip)) return classifyIpv6(ip);
  return "reserved";
}

/**
 * True when the user's original input literally targets the local loopback
 * (by name or address), the one case where loopback is allowed. This does
 * NOT relax checks on any other private/internal range: if a hostname like
 * "localhost" somehow resolves to a non-loopback address (e.g. via a
 * tampered /etc/hosts), that address is still blocked by resolveAndValidateHost.
 */
export function isExplicitLocalHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "localhost") return true;
  if (normalized === "::1") return true;
  if (net.isIPv4(normalized)) {
    return inRange(ipv4ToInt(normalized) ?? -1, "127.0.0.0", 8);
  }
  return false;
}

export interface ValidatedAddress {
  address: string;
  family: 4 | 6;
}

export interface ValidatedHost {
  address: string;
  family: 4 | 6;
  allAddresses: ValidatedAddress[];
}

/**
 * Resolves `hostname` and validates every returned address against the
 * blocklist above. Throws SsrfBlockedError if any resolved address (or the
 * hostname itself, when it is already a literal IP) is disallowed.
 *
 * Returns the validated address to connect to (first result) plus the full
 * list, so callers can pin the exact address used for both validation and
 * connection.
 */
export async function resolveAndValidateHost(hostname: string): Promise<ValidatedHost> {
  const explicitLocal = isExplicitLocalHostname(hostname);

  let records: dns.LookupAddress[];
  if (net.isIP(hostname)) {
    records = [{ address: hostname, family: net.isIPv6(hostname) ? 6 : 4 }];
  } else {
    try {
      records = await dns.promises.lookup(hostname, { all: true, verbatim: true });
    } catch (err) {
      throw new SsrfBlockedError(
        `Could not resolve host "${hostname}": ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  if (records.length === 0) {
    throw new SsrfBlockedError(`Host "${hostname}" did not resolve to any address`);
  }

  const validated: ValidatedAddress[] = [];
  for (const record of records) {
    const classification = classifyIp(record.address);
    const allowed =
      classification === "public" || (explicitLocal && classification === "loopback");
    if (!allowed) {
      throw new SsrfBlockedError(
        `Blocked target "${hostname}" -> ${record.address} (${classification}). ` +
          `vibe-audit refuses to send requests to private, loopback, link-local or ` +
          `cloud-metadata addresses unless you explicitly target localhost/127.0.0.1.`,
      );
    }
    validated.push({ address: record.address, family: record.family === 6 ? 6 : 4 });
  }

  const first = validated[0];
  if (!first) {
    throw new SsrfBlockedError(`Host "${hostname}" did not resolve to any allowed address`);
  }

  return { address: first.address, family: first.family, allAddresses: validated };
}
