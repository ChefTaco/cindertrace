import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createAuthProtection } from "./throttling.js";

function memoryStore() {
  const counts = new Map<string, number>();
  let concurrent = 0;
  const store = {
    eval: vi.fn(async (script: string, keyCount: number, ...args: Array<string | number>) => {
      if (keyCount === 3)
        return args.slice(0, 3).map((key) => {
          const next = (counts.get(String(key)) ?? 0) + 1;
          counts.set(String(key), next);
          return next;
        });
      if (script.includes("INCR")) {
        if (concurrent >= Number(args[1])) return 0;
        return ++concurrent;
      }
      return --concurrent;
    }),
    del: vi.fn(async () => undefined),
  };
  return { store, sleep: vi.fn(async () => undefined) };
}
async function attempts(total: number) {
  const { store, sleep } = memoryStore();
  const begin = createAuthProtection(store, sleep);
  const allowed: boolean[] = [];
  for (let index = 0; index < total; index++) {
    const permit = await begin("198.51.100.1", "alice@example.com");
    allowed.push(permit.allowed);
    await permit.release();
  }
  return { allowed, sleep };
}
beforeEach(() => vi.stubEnv("SESSION_SECRET", "s".repeat(64)));
afterEach(() => vi.unstubAllEnvs());

it("refuses the sixth attempt for one source and account by default", async () => {
  const { allowed, sleep } = await attempts(6);
  expect(allowed).toEqual([true, true, true, true, true, false]);
  expect(sleep).toHaveBeenCalledTimes(5);
});

it("keeps the default limit when explicitly off", async () => {
  vi.stubEnv("RELAX_AUTH_LIMITS", "false");
  const { allowed } = await attempts(6);
  expect(allowed[5]).toBe(false);
});

it("allows repeated failures without delay when relaxed", async () => {
  vi.stubEnv("RELAX_AUTH_LIMITS", "true");
  const { allowed, sleep } = await attempts(50);
  expect(allowed.every(Boolean)).toBe(true);
  expect(sleep).not.toHaveBeenCalled();
});

it("still throttles beyond the relaxed ceiling", async () => {
  vi.stubEnv("RELAX_AUTH_LIMITS", "true");
  const { allowed } = await attempts(10_001);
  expect(allowed[9_999]).toBe(true);
  expect(allowed[10_000]).toBe(false);
});

it("still bounds concurrent password checks when relaxed", async () => {
  vi.stubEnv("RELAX_AUTH_LIMITS", "true");
  const { store, sleep } = memoryStore();
  const begin = createAuthProtection(store, sleep);
  const permits = [];
  for (let index = 0; index < 257; index++)
    permits.push(await begin("198.51.100.1", "alice@example.com"));
  expect(permits[255]?.allowed).toBe(true);
  expect(permits[256]?.allowed).toBe(false);
  expect(permits[256]?.retryAfterSeconds).toBe(1);
});
