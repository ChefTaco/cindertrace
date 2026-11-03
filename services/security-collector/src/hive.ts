import { externalEvent } from "./parsers.js";
import {
  parseBoundedJson,
  type BoundedFetchResult,
} from "./runtime-security.js";
import type { SecurityFusionEvent } from "@cindertrace/contracts";
type Checkpoint = { version: 1; iamThrough?: string; routerCursor?: string };
export async function collectHiveSecurity(options: {
  iamUrl: string;
  clientId: string;
  secret: string;
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
  const base = options.iamUrl.replace(/\/$/, "");
  const tokenResponse = await request(base + "/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: options.clientId,
      client_secret: options.secret,
      scope: "iam:audit:read router:security-events:read",
    }),
  });
  if (!tokenResponse.response.ok)
    throw new Error(`Hive OAuth HTTP ${tokenResponse.response.status}`);
  const token = parseBoundedJson<{ access_token?: string }>(
    tokenResponse.body,
    "Hive OAuth",
  ).access_token;
  if (!token) throw new Error("Hive OAuth response is incomplete");
  const headers = {
    authorization: `Bearer ${token}`,
    accept: "application/json",
  };
  for (let page = 1; ; page++) {
    if (page > 100)
      throw new Error(
        "Hive audit backlog exceeds one bounded poll; checkpoint held",
      );
    const url = new URL(base + "/api/v1/audit");
    url.search = new URLSearchParams({
      limit: "200",
      page: String(page),
      from: start,
      to: end,
    }).toString();
    const result = await request(url, { headers });
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
      const result = await request(url, { headers });
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
