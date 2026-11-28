import { externalEvent } from "./parsers.js";
import {
  parseBoundedJson,
  type BoundedFetchResult,
} from "./runtime-security.js";
import type { SecurityFusionEvent } from "@cindertrace/contracts";
import {
  collectorTokenProvider,
  type ServiceTokenProvider,
} from "./service-tokens.js";

/** The scopes of Hive's public `security-exporter` client. */
export const HIVE_SECURITY_SCOPE = "iam:audit:read router:security-events:read";

/** `<iam>/api/v1`, accepting a base that already ends in `/api/v1`. */
export function hiveIamApi(iamUrl: string): string {
  const base = iamUrl.replace(/\/$/, "");
  return base.endsWith("/api/v1") ? base : base + "/api/v1";
}

/**
 * The Hive `security-exporter` client-credentials token, from hive-common's
 * service token provider at `<HIVE_IAM_SECURITY_URL>/api/v1/oauth/token`.
 * The token URL must be HTTPS; anything else stops the collector at startup.
 */
export function hiveTokenProvider(options: {
  iamUrl: string;
  clientId: string;
  secret: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}): ServiceTokenProvider {
  let tokenUrl: string;
  try {
    tokenUrl = new URL(hiveIamApi(options.iamUrl) + "/oauth/token").href;
  } catch {
    throw new Error("HIVE_IAM_SECURITY_URL must be an HTTPS URL");
  }
  try {
    return collectorTokenProvider(
      {
        tokenUrl,
        clientId: options.clientId,
        clientSecret: options.secret,
        scope: HIVE_SECURITY_SCOPE,
        ...(options.fetch ? { fetch: options.fetch } : {}),
        ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
      },
      (status) => `Hive OAuth HTTP ${status}`,
    );
  } catch (error) {
    if (error instanceof TypeError && /tokenUrl/.test(error.message))
      throw new Error(
        "HIVE_IAM_SECURITY_URL must be an HTTPS URL without credentials or a fragment",
      );
    throw error;
  }
}

type Checkpoint = { version: 1; iamThrough?: string; routerCursor?: string };
export async function collectHiveSecurity(options: {
  iamUrl: string;
  tokens: ServiceTokenProvider;
  routerUrl?: string;
  checkpoint?: string;
  now?: Date;
  request: (
    url: string | URL,
    init?: RequestInit,
  ) => Promise<BoundedFetchResult>;
  enqueue: (event: SecurityFusionEvent | null) => boolean;
}): Promise<string> {
  const { request, enqueue } = options;
  let prior: Checkpoint = { version: 1 };
  if (options.checkpoint) {
    if (options.checkpoint.startsWith("{")) {
      prior = JSON.parse(options.checkpoint) as Checkpoint;
      if (
        prior.version !== 1 ||
        (prior.iamThrough && !Number.isFinite(Date.parse(prior.iamThrough))) ||
        (prior.routerCursor && typeof prior.routerCursor !== "string")
      )
        throw new Error("Unsupported Hive checkpoint");
    } else prior.routerCursor = options.checkpoint;
  }
  const now = options.now ?? new Date(),
    end = now.toISOString();
  const start =
    prior.iamThrough ?? new Date(now.getTime() - 15 * 60000).toISOString();
  const api = hiveIamApi(options.iamUrl);
  // The token is cached between polls; a refused one is replaced and retried once.
  const authorized = async (url: string | URL): Promise<BoundedFetchResult> => {
    for (let attempt = 0; ; attempt++) {
      const token = await options.tokens.token();
      const result = await request(url, {
        headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      });
      if (result.response.status !== 401 || attempt > 0) return result;
      options.tokens.invalidate();
    }
  };
  for (let page = 1; ; page++) {
    if (page > 100)
      throw new Error(
        "Hive audit backlog exceeds one bounded poll; checkpoint held",
      );
    const url = new URL(api + "/audit");
    url.search = new URLSearchParams({
      limit: "200",
      page: String(page),
      from: start,
      to: end,
    }).toString();
    const result = await authorized(url);
    if (!result.response.ok)
      throw new Error(`Hive audit HTTP ${result.response.status}`);
    const body = parseBoundedJson<{
      events?: Record<string, unknown>[];
      total?: number;
    }>(result.body, "Hive audit");
    if (
      !Array.isArray(body.events) ||
      !Number.isSafeInteger(body.total) ||
      body.total! < 0 ||
      body.events.length > 200
    )
      throw new Error("Hive audit response is incomplete");
    for (const row of body.events)
      if (
        !enqueue(
          externalEvent("hive", {
            ...row,
            eventType: `hive.iam.${String(row["eventType"] ?? "audit")}`,
          }),
        )
      )
        throw new Error("Hive audit queue full; checkpoint held");
    if (page * 200 >= body.total!) break;
    if (!body.events.length)
      throw new Error(
        "Hive audit pagination made no progress; checkpoint held",
      );
  }
  const next: Checkpoint = { ...prior, iamThrough: end };
  if (options.routerUrl) {
    for (let recovery = 0; recovery < 2; recovery++) {
      const url = new URL(options.routerUrl);
      url.searchParams.set("limit", "500");
      if (next.routerCursor) url.searchParams.set("cursor", next.routerCursor);
      const result = await authorized(url);
      if (result.response.status === 410 && recovery === 0) {
        const body = parseBoundedJson<{
          earliest_available_cursor?: string;
          earliest_available_sequence?: number;
        }>(result.body, "Hive Router cursor");
        const cursor =
          body.earliest_available_cursor ??
          (Number.isSafeInteger(body.earliest_available_sequence)
            ? String(body.earliest_available_sequence! - 1)
            : null);
        if (!cursor)
          throw new Error(
            "Hive Router expired checkpoint has no recovery cursor",
          );
        next.routerCursor = cursor;
        continue;
      }
      if (!result.response.ok)
        throw new Error(`Hive Router HTTP ${result.response.status}`);
      const body = parseBoundedJson<{
        events?: Record<string, unknown>[];
        nextCursor?: string | null;
      }>(result.body, "Hive Router");
      if (!Array.isArray(body.events))
        throw new Error("Hive Router response is incomplete");
      for (const row of body.events)
        if (!enqueue(externalEvent("hive", row)))
          throw new Error("Hive Router queue full; checkpoint held");
      if (body.nextCursor) next.routerCursor = body.nextCursor;
      break;
    }
  }
  return JSON.stringify(next);
}
