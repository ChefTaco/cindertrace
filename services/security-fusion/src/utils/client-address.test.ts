import { expect, it, vi } from "vitest";
import { parseTrustedProxies, resolveClientAddress } from "./client-address.js";

it("trusts only loopback by default and refuses malformed entries", async () => {
  const proxies = parseTrustedProxies(undefined);
  expect(await proxies.trusts("127.0.0.1")).toBe(true);
  expect(await proxies.trusts("::ffff:127.0.0.5")).toBe(true);
  expect(await proxies.trusts("::1")).toBe(true);
  expect(await proxies.trusts("10.0.0.1")).toBe(false);
  expect(await parseTrustedProxies("none").trusts("127.0.0.1")).toBe(false);
  for (const bad of ["10.0.0.0/33", "10.0.0.1/8/1", "*", "1.2.3.4:80", "999.1.1.1"])
    expect(() => parseTrustedProxies(bad)).toThrow(/CINDERTRACE_TRUSTED_PROXIES/);
});

it("ignores X-Forwarded-For unless the socket peer is a trusted proxy", async () => {
  const proxies = parseTrustedProxies("172.18.0.0/16, 2001:db8::/32");
  expect(await resolveClientAddress("198.51.100.4", "203.0.113.9", proxies)).toBe("198.51.100.4");
  expect(await resolveClientAddress("172.18.0.5", "203.0.113.9", proxies)).toBe("203.0.113.9");
  expect(await resolveClientAddress("2001:db8::5", "203.0.113.9", proxies)).toBe("203.0.113.9");
  expect(await resolveClientAddress("172.18.0.5", undefined, proxies)).toBe("172.18.0.5");
  expect(await resolveClientAddress("", "203.0.113.9", proxies)).toBe("");
});

it("reads the header from the right and never past an untrusted hop", async () => {
  const proxies = parseTrustedProxies("172.18.0.0/16 192.0.2.10");
  // A caller-written prefix stays ignored: the gateway appended the real peer.
  expect(await resolveClientAddress("172.18.0.5", "203.0.113.9, 198.51.100.4", proxies)).toBe("198.51.100.4");
  // An outer trusted proxy is skipped, so its client is used.
  expect(await resolveClientAddress("172.18.0.5", "203.0.113.9, 198.51.100.4, 192.0.2.10", proxies)).toBe("198.51.100.4");
  // Malformed hops stop the walk at the last address a trusted proxy vouched for.
  expect(await resolveClientAddress("172.18.0.5", "nonsense, 192.0.2.10", proxies)).toBe("192.0.2.10");
  expect(await resolveClientAddress("172.18.0.5", "::ffff:198.51.100.4", proxies)).toBe("198.51.100.4");
});

it("resolves host names such as the Compose gateway service and looks again on a miss", async () => {
  let clock = 0;
  const resolver = vi
    .fn()
    .mockResolvedValueOnce(["172.18.0.5"])
    .mockResolvedValueOnce(["172.18.0.9"]);
  const proxies = parseTrustedProxies("gateway", resolver, () => clock);
  expect(await resolveClientAddress("172.18.0.5", "198.51.100.4", proxies)).toBe("198.51.100.4");
  expect(resolver).toHaveBeenCalledWith("gateway");
  // The gateway restarted with a new address.
  clock = 6_000;
  expect(await resolveClientAddress("172.18.0.9", "198.51.100.4", proxies)).toBe("198.51.100.4");
  expect(await proxies.trusts("172.18.0.5")).toBe(false);
  expect(resolver).toHaveBeenCalledTimes(2);
  const failing = parseTrustedProxies("gateway", vi.fn().mockRejectedValue(Error("no DNS")));
  expect(await resolveClientAddress("172.18.0.5", "198.51.100.4", failing)).toBe("172.18.0.5");
});
