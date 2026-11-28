import type { MiddlewareHandler } from "hono";
import { Redis } from "ioredis";
import { HiveError } from "@hivemagnus/hive-common/errors";
import {
  addressKey,
  createRedisSlidingWindowStore,
  enforceRateLimit,
  type RateLimitStore,
  type SlidingWindowRedis,
} from "@hivemagnus/hive-common/rate-limit";
import { incMetric } from "../routes/metrics.js";
import { clientAddress } from "../utils/client-address.js";

const REDIS_URL = process.env["REDIS_URL"] ?? "redis://127.0.0.1:6379";
const REDIS_PREFIX = process.env["REDIS_PREFIX"] ?? "cindertrace-";

let _redis: Redis | null = null;
let lastRateLimitError: string | null = null;
let lastRateLimitErrorAt: string | null = null;

function getRedis(): Redis {
  if (!_redis) {
    _redis = new Redis(REDIS_URL, {
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    });
    _redis.connect().catch(() => {
      // silently fail — rate limiter becomes permissive when Redis is unavailable
    });
  }
  return _redis;
}

/**
 * The Redis sliding window (hive-common `createRedisSlidingWindowStore()`): every request in the
 * last `windowMs` counts, refused ones included, so a client that keeps retrying stays refused,
 * and a refusal's Retry-After is the whole window. Shared by every API process and kept across
 * restarts; each key's sorted set keeps at most `max + 1` entries. Keys stay
 * `<REDIS_PREFIX><keyPrefix>:<client key>`. Throws when Redis cannot be reached or answers a
 * command with an error or an unreadable reply, which the middleware treats as unavailable.
 */
export function redisRateLimitStore(opts: {
  windowMs: number;
  max: number;
  keyPrefix: string;
  redis?: () => SlidingWindowRedis;
}): RateLimitStore {
  return createRedisSlidingWindowStore({
    redis: opts.redis ?? getRedis,
    windowMs: opts.windowMs,
    max: opts.max,
    keyPrefix: `${REDIS_PREFIX}${opts.keyPrefix}:`,
    retryAfter: "window",
  });
}

/**
 * Per-client rate limit on hive-common `/rate-limit` (`enforceRateLimit()` over the
 * Redis sliding window above). Keyed by client address: the socket peer, or the X-Forwarded-For
 * client when the peer is a trusted proxy (CINDERTRACE_TRUSTED_PROXIES, see
 * utils/client-address.ts), so callers behind the gateway or Hive's ingress get their
 * own budgets. IPv6 clients are keyed per address. Falls through (allows) if Redis is
 * unavailable, unless failClosed is set.
 *
 * @param opts.windowMs  Time window in milliseconds (default: 60_000 = 1 minute)
 * @param opts.max       Maximum requests per window (default: 100)
 * @param opts.keyPrefix Redis key prefix segment (default: 'rl')
 */
export function rateLimitMiddleware(
  opts: {
    windowMs?: number;
    max?: number;
    keyPrefix?: string;
    failClosed?: boolean;
    /** Tests: the store to spend from instead of Redis. */
    store?: RateLimitStore;
  } = {},
): MiddlewareHandler {
  const windowMs = opts.windowMs ?? 60_000;
  const store =
    opts.store ??
    redisRateLimitStore({
      windowMs,
      max: opts.max ?? 100,
      keyPrefix: opts.keyPrefix ?? "rl",
    });

  return async (c, next) => {
    // Browsers arrive through the gateway or Hive's ingress; a caller-written
    // forwarding header is read only past a configured trusted proxy.
    const ip = (await clientAddress(c)) || "unknown-peer";

    try {
      await enforceRateLimit(store, addressKey(ip, { ipv6PrefixLength: 128 }));
    } catch (error) {
      if (HiveError.is(error, "rate_limited")) {
        c.header("Retry-After", error.headers?.["retry-after"] ?? String(Math.ceil(windowMs / 1000)));
        return c.json(
          {
            error: "RATE_LIMITED",
            message: "Too many requests. Please try again later.",
          },
          429,
        );
      }
      lastRateLimitError = "Redis unavailable for rate limiting";
      lastRateLimitErrorAt = new Date().toISOString();
      incMetric("rateLimiterFailures");
      if (opts.failClosed && process.env["NODE_ENV"] !== "test") {
        return c.json(
          {
            error: "RATE_LIMIT_UNAVAILABLE",
            message: "Rate limiter is unavailable for this sensitive endpoint.",
          },
          503,
        );
      }
      // Redis unavailable — fail open only for non-critical routes and tests.
    }

    return next();
  };
}

export function getRateLimitHealth(): {
  status: "pass" | "warn";
  message: string;
  lastErrorAt: string | null;
} {
  return {
    status: lastRateLimitError ? "warn" : "pass",
    message:
      lastRateLimitError ?? "rate limiter available or not yet exercised",
    lastErrorAt: lastRateLimitErrorAt,
  };
}

export async function redisReady(): Promise<void> { await getRedis().ping(); }
export async function closeRateLimitRedis(): Promise<void> { if (_redis) { await _redis.quit(); _redis = null; } }
