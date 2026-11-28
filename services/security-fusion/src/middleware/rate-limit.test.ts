import { serve, type ServerType } from "@hono/node-server";
import { Hono } from "hono";
import type { AddressInfo } from "node:net";
import { afterEach, expect, it, vi } from "vitest";
import { createRateLimiter } from "@hivemagnus/hive-common/rate-limit";
import { rateLimitMiddleware, redisRateLimitStore } from "./rate-limit.js";

let server: ServerType | undefined;
afterEach(async () => {
  vi.unstubAllEnvs();
  await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
  server = undefined;
});

/** A real socket, so the peer address is the loopback connection the test makes. */
async function listen(app: Hono): Promise<string> {
  return new Promise((resolve) => {
    server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, (info: AddressInfo) =>
      resolve(`http://127.0.0.1:${info.port}`),
    );
  });
}

function limitedApp(store = createRateLimiter({ limit: 1, windowMs: 60_000 })) {
  const app = new Hono();
  app.use("*", rateLimitMiddleware({ store, failClosed: true }));
  app.get("/ping", (c) => c.text("ok"));
  return app;
}

const get = (base: string, forwardedFor?: string) =>
  fetch(`${base}/ping`, { headers: forwardedFor ? { "x-forwarded-for": forwardedFor } : {} });

it("gives two forwarded clients behind a trusted proxy their own budgets", async () => {
  // Regression: every browser reaches the API from the gateway; keyed on the gateway's
  // address, one client's requests used up everyone's budget.
  vi.stubEnv("CINDERTRACE_TRUSTED_PROXIES", "loopback");
  const base = await listen(limitedApp());
  expect((await get(base, "198.51.100.4")).status).toBe(200);
  const refused = await get(base, "198.51.100.4");
  expect(refused.status).toBe(429);
  expect(refused.headers.get("retry-after")).toBe("60");
  expect(await refused.json()).toEqual({
    error: "RATE_LIMITED",
    message: "Too many requests. Please try again later.",
  });
  expect((await get(base, "203.0.113.9")).status).toBe(200);
  // A caller-written prefix does not buy a fresh bucket: the proxy appended the real client.
  expect((await get(base, "192.0.2.77, 198.51.100.4")).status).toBe(429);
});

it("ignores X-Forwarded-For from a peer that is not a trusted proxy", async () => {
  vi.stubEnv("CINDERTRACE_TRUSTED_PROXIES", "192.0.2.10");
  const base = await listen(limitedApp());
  expect((await get(base, "198.51.100.4")).status).toBe(200);
  // Another claimed client from the same untrusted peer is the same client.
  expect((await get(base, "203.0.113.9")).status).toBe(429);
  expect((await get(base)).status).toBe(429);
});

it("counts every request in the Redis window, refused ones included, and keys it as before", async () => {
  const sets = new Map<string, number[]>();
  const keys: string[] = [];
  const pipeline = () => {
    const ops: Array<() => [Error | null, unknown]> = [];
    const chain = {
      zremrangebyscore(key: string, _min: string, max: number) {
        ops.push(() => {
          sets.set(key, (sets.get(key) ?? []).filter((score) => score > max));
          return [null, 0];
        });
        return chain;
      },
      zadd(key: string, score: number) {
        keys.push(key);
        ops.push(() => {
          sets.set(key, [...(sets.get(key) ?? []), score]);
          return [null, 1];
        });
        return chain;
      },
      zremrangebyrank(key: string, start: number, stop: number) {
        ops.push(() => {
          const scores = sets.get(key) ?? [];
          const to = stop < 0 ? scores.length + stop : stop;
          const removed = Math.max(0, to - start + 1);
          sets.set(key, scores.slice(removed));
          return [null, removed];
        });
        return chain;
      },
      zcard(key: string) {
        ops.push(() => [null, sets.get(key)?.length ?? 0]);
        return chain;
      },
      pexpire() {
        ops.push(() => [null, 1]);
        return chain;
      },
      exec: async () => ops.map((op) => op()),
    };
    return chain;
  };
  const store = redisRateLimitStore({
    windowMs: 60_000,
    max: 2,
    keyPrefix: "rl",
    redis: () => ({ pipeline }),
  });
  const outcomes = [];
  for (let index = 0; index < 5; index++) outcomes.push((await store.consume("198.51.100.4")).allowed);
  expect(outcomes).toEqual([true, true, false, false, false]);
  // Refused requests stay in the window, but the set keeps only the newest max + 1 of them.
  expect(sets.get("cindertrace-rl:198.51.100.4")).toHaveLength(3);
  expect(new Set(keys)).toEqual(new Set(["cindertrace-rl:198.51.100.4"]));
  expect((await store.consume("203.0.113.9")).allowed).toBe(true);
});

it("answers 503 on a sensitive route when the store fails, and lets other routes through", async () => {
  const failing = {
    consume: async () => {
      throw new Error("connection refused");
    },
  };
  vi.stubEnv("NODE_ENV", "production");
  const closed = new Hono();
  closed.use("*", rateLimitMiddleware({ store: failing, failClosed: true }));
  closed.get("/ping", (c) => c.text("ok"));
  const refused = await closed.request("/ping");
  expect(refused.status).toBe(503);
  expect(await refused.json()).toMatchObject({ error: "RATE_LIMIT_UNAVAILABLE" });
  const open = new Hono();
  open.use("*", rateLimitMiddleware({ store: failing }));
  open.get("/ping", (c) => c.text("ok"));
  expect((await open.request("/ping")).status).toBe(200);
});

it("treats a Redis command error or a discarded pipeline as unavailable: 503 on a sensitive route", async () => {
  vi.stubEnv("NODE_ENV", "production");
  const replies: Array<Array<[Error | null, unknown]> | null> = [
    [[null, 0], [null, 1], [null, 0], [new Error("WRONGTYPE Operation against a key holding the wrong kind of value"), null], [null, 1]],
    null,
  ];
  for (const reply of replies) {
    const chain = {
      zremrangebyscore: () => chain,
      zadd: () => chain,
      zremrangebyrank: () => chain,
      zcard: () => chain,
      pexpire: () => chain,
      exec: async () => reply,
    };
    const store = redisRateLimitStore({ windowMs: 60_000, max: 5, keyPrefix: "rl", redis: () => ({ pipeline: () => chain }) });
    const app = new Hono();
    app.use("*", rateLimitMiddleware({ store, failClosed: true }));
    app.get("/ping", (c) => c.text("ok"));
    const response = await app.request("/ping");
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: "RATE_LIMIT_UNAVAILABLE" });
  }
});
