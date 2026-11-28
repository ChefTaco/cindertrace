import { getConnInfo } from "@hono/node-server/conninfo";
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import type { Context } from "hono";
import {
  normalizeIpAddress as normalizeForwardedAddress,
  resolveClientAddress as resolveForwardedClient,
} from "@hivemagnus/hive-common/rate-limit";
import { normalizeIpAddress } from "./ip.js";

/**
 * Client address for login throttling, rate limits and audit records.
 *
 * Browsers reach the API through a proxy: the Compose `gateway`, or Hive's ingress in
 * suite mode. Both append the address they received the request from to
 * X-Forwarded-For. The header is read only when the socket peer is a configured trusted
 * proxy (CINDERTRACE_TRUSTED_PROXIES), from the right, skipping further trusted
 * proxies, so an address a caller wrote into the header itself is never used unless
 * every hop after it is trusted.
 *
 * CINDERTRACE_TRUSTED_PROXIES is a comma- or space-separated list of IP addresses,
 * CIDR ranges, host names (resolved through DNS, such as the Compose service `gateway`)
 * and the keyword `loopback`. Unset, it is `loopback`; `none` trusts no proxy.
 *
 * The header walk itself is hive-common's `/rate-limit` `resolveClientAddress()`.
 * Its trusted-proxy set is synchronous and takes no host names, so the trust of
 * each address it may consult is settled here first (host names through DNS).
 */
export const DEFAULT_TRUSTED_PROXIES = "loopback";
const MAX_FORWARDED_HOPS = 32;
const HOST_TTL_MS = 30_000;
const HOST_MISS_RETRY_MS = 5_000;
const HOST_NAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

type Resolver = (host: string) => Promise<string[]>;
type HostEntry = { addresses: Set<string>; at: number; pending?: Promise<void> };
export type TrustedProxies = {
  trusts(address: string): Promise<boolean>;
};

const defaultResolver: Resolver = async (host) =>
  (await lookup(host, { all: true, verbatim: true })).map((entry) =>
    normalizeIpAddress(entry.address),
  );

function family(address: string): "ipv4" | "ipv6" | null {
  const version = isIP(address);
  return version === 4 ? "ipv4" : version === 6 ? "ipv6" : null;
}

/** Parse the list; throws on an entry that is not an address, range, host name or keyword. */
export function parseTrustedProxies(
  value: string | undefined,
  resolver: Resolver = defaultResolver,
  now: () => number = Date.now,
): TrustedProxies {
  const blocks = new BlockList();
  const hosts = new Map<string, HostEntry>();
  const tokens = (value ?? DEFAULT_TRUSTED_PROXIES)
    .split(/[\s,]+/)
    .map((token) => token.trim())
    .filter(Boolean);
  for (const token of tokens) {
    if (token === "none") continue;
    if (token === "loopback") {
      blocks.addSubnet("127.0.0.0", 8, "ipv4");
      blocks.addAddress("::1", "ipv6");
      continue;
    }
    const [base = "", prefix, extra] = token.split("/");
    const kind = family(normalizeIpAddress(base));
    if (kind && prefix === undefined) {
      blocks.addAddress(normalizeIpAddress(base), kind);
      continue;
    }
    if (kind && extra === undefined && /^\d{1,3}$/.test(prefix ?? "")) {
      const bits = Number(prefix);
      if (bits <= (kind === "ipv4" ? 32 : 128)) {
        blocks.addSubnet(normalizeIpAddress(base), bits, kind);
        continue;
      }
    }
    if (prefix === undefined && HOST_NAME.test(token) && !/^[\d.]+$/.test(token)) {
      hosts.set(token.toLowerCase(), { addresses: new Set(), at: -Infinity });
      continue;
    }
    throw new Error(
      "CINDERTRACE_TRUSTED_PROXIES entries must be IP addresses, CIDR ranges, host names, loopback or none",
    );
  }

  async function refresh(host: string, entry: HostEntry): Promise<void> {
    entry.pending ??= resolver(host)
      .then((addresses) => {
        entry.addresses = new Set(addresses);
      })
      .catch(() => {
        entry.addresses = new Set();
      })
      .finally(() => {
        entry.at = now();
        entry.pending = undefined;
      });
    await entry.pending;
  }

  return {
    async trusts(raw) {
      const address = normalizeIpAddress(raw);
      const kind = family(address);
      if (!kind) return false;
      if (blocks.check(address, kind)) return true;
      for (const [host, entry] of hosts) {
        const age = now() - entry.at;
        // A container restart can change the proxy's address: look again on a miss.
        if (age > HOST_TTL_MS || (!entry.addresses.has(address) && age > HOST_MISS_RETRY_MS))
          await refresh(host, entry);
        if (entry.addresses.has(address)) return true;
      }
      return false;
    },
  };
}

let cached: { value: string | undefined; proxies: TrustedProxies } | undefined;
export function trustedProxies(env: NodeJS.ProcessEnv = process.env): TrustedProxies {
  const value = env["CINDERTRACE_TRUSTED_PROXIES"];
  if (!cached || cached.value !== value)
    cached = { value, proxies: parseTrustedProxies(value) };
  return cached.proxies;
}

/** The Node socket peer, or "" outside the Node adapter (tests using app.request). */
export function socketPeerAddress(c: Context): string {
  try {
    return normalizeIpAddress(getConnInfo(c).remote.address ?? "");
  } catch {
    return "";
  }
}

/**
 * Resolve the client from the socket peer and, behind a trusted proxy, X-Forwarded-For.
 * "" when the socket peer is not known.
 */
export async function resolveClientAddress(
  peer: string,
  forwardedFor: string | undefined,
  proxies: TrustedProxies,
): Promise<string> {
  // hive-common reads the peer, then hops from the right up to the first one that is
  // not a trusted proxy (or not an address); only those addresses need a verdict.
  const trusted = new Set<string>();
  const vouches = async (raw: string | undefined): Promise<boolean> => {
    const address = normalizeForwardedAddress(raw);
    if (address === undefined || !(await proxies.trusts(address))) return false;
    trusted.add(address);
    return true;
  };
  if ((await vouches(peer)) && forwardedFor) {
    const hops = forwardedFor.split(",");
    for (let index = hops.length - 1, read = 0; index >= 0 && read < MAX_FORWARDED_HOPS; index--, read++)
      if (!(await vouches(hops[index]))) break;
  }
  const client = resolveForwardedClient({
    peer,
    forwardedFor,
    maxHops: MAX_FORWARDED_HOPS,
    trusted: {
      has: (address) => trusted.has(normalizeForwardedAddress(address) ?? ""),
      entries: [...trusted],
    },
  });
  return client.decision === "unknown_peer" ? "" : client.address;
}

export async function clientAddress(
  c: Context,
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  return resolveClientAddress(
    socketPeerAddress(c),
    c.req.header("x-forwarded-for"),
    trustedProxies(env),
  );
}
