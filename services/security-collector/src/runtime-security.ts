import {
  securityFusionEventSchema,
  type SecurityFusionEvent,
} from "@cindertrace/contracts";

const DEFAULT_HTTP_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const DEFAULT_MAX_QUEUE_EVENTS = 10_000;

const OTHER_SECRET_NAMES = [
  "API_SECRET",
  "JWT_SECRET",
  "MAGNUS_SECRET",
  "NODE_MANAGER_SECRET",
  "CREDENTIAL_ROTATION_KEY",
  "AUDIT_HMAC_SECRET",
  "RESULT_SIGNING_SECRET",
  "LOG_INGEST_SIGNING_SECRET",
  "A2A_SHARED_SECRET",
  "AGENT_DISCOVERY_SECRET",
  "SECURITY_FUSION_RECEIPT_SIGNING_KEY",
  "METRICS_TOKEN",
  "WEBHOOK_ENCRYPTION_KEY",
  "HIVE_IAM_SECURITY_CLIENT_SECRET",
  "HIVE_SECURITY_EXPORT_TOKEN",
  "CHATTERMOST_SECURITY_EXPORT_TOKEN",
  "TAILSCALE_SECURITY_TOKEN",
  "LOKI_READ_TOKEN",
] as const;

export interface SecurityCollectorRuntimeConfig {
  ingestSecret: string;
  lokiSourcesEnabled: boolean;
  httpTimeoutMs: number;
  maxResponseBytes: number;
  maxQueueEvents: number;
}

function boundedInteger(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(
      `${name} must be an integer between ${minimum} and ${maximum}`,
    );
  }
  return value;
}

/** Validate every guard before the collector opens sockets or starts timers. */
export function readSecurityCollectorRuntimeConfig(
  env: NodeJS.ProcessEnv = process.env,
): SecurityCollectorRuntimeConfig {
  const ingestSecret = env["SECURITY_FUSION_INGEST_SECRET"] ?? "";
  if (ingestSecret.length < 32) {
    throw new Error(
      "SECURITY_FUSION_INGEST_SECRET must be a dedicated secret of at least 32 characters",
    );
  }
  for (const name of OTHER_SECRET_NAMES) {
    const other = env[name];
    if (other && other === ingestSecret) {
      throw new Error(
        `SECURITY_FUSION_INGEST_SECRET must be distinct from ${name}`,
      );
    }
  }
  const https = (name: string) => {
    const value = env[name];
    if (value && new URL(value).protocol !== "https:")
      throw new Error(`${name} requires HTTPS`);
  };
  for (const name of [
    "HIVE_IAM_SECURITY_URL",
    "HIVE_SECURITY_EXPORT_URL",
    "CHATTERMOST_SECURITY_EXPORT_URL",
    "LOKI_URL",
  ])
    https(name);
  if (env["HIVE_SECURITY_EXPORT_TOKEN"])
    throw new Error(
      "Hive static export credentials are retired; use scoped OAuth client credentials",
    );
  if (
    (env["HIVE_IAM_SECURITY_URL"] ||
      env["HIVE_SECURITY_EXPORT_URL"] ||
      env["HIVE_IAM_SECURITY_CLIENT_SECRET"]) &&
    (!env["HIVE_IAM_SECURITY_URL"] || !env["HIVE_IAM_SECURITY_CLIENT_SECRET"])
  )
    throw new Error(
      "Hive export requires its IAM URL and scoped OAuth client credential",
    );
  if (
    Boolean(env["CHATTERMOST_SECURITY_EXPORT_URL"]) !==
    Boolean(env["CHATTERMOST_SECURITY_EXPORT_TOKEN"])
  )
    throw new Error(
      "Mattermost export URL and scoped token must be configured together",
    );
  if (env["TAILSCALE_SECURITY_TOKEN"] && !env["TAILSCALE_TAILNET"])
    throw new Error("Tailscale API polling requires an explicit tailnet");
  if (
    env["LOKI_URL"] &&
    (!env["LOKI_READ_TOKEN"] || env["LOKI_READ_TOKEN"].length < 40)
  )
    throw new Error("Loki requires its dedicated read credential");
  if (env["LOKI_QUERY"]?.trim() && !env["LOKI_URL"])
    throw new Error("A Loki source query requires its HTTPS URL");
  return {
    ingestSecret,
    // UI audit uses the same transport, with its own source-specific query.
    lokiSourcesEnabled: Boolean(env["LOKI_URL"] && env["LOKI_QUERY"]?.trim()),
    httpTimeoutMs: boundedInteger(
      env,
      "SECURITY_FUSION_HTTP_TIMEOUT_MS",
      DEFAULT_HTTP_TIMEOUT_MS,
      1_000,
      120_000,
    ),
    maxResponseBytes: boundedInteger(
      env,
      "SECURITY_FUSION_MAX_RESPONSE_BYTES",
      DEFAULT_MAX_RESPONSE_BYTES,
      1_024,
      16 * 1_048_576,
    ),
    maxQueueEvents: boundedInteger(
      env,
      "SECURITY_FUSION_QUEUE_MAX_EVENTS",
      DEFAULT_MAX_QUEUE_EVENTS,
      100,
      100_000,
    ),
  };
}

/** Per-event limits the ingest API enforces. One event outside them fails its whole batch. */
export const INGEST_MAX_EVENT_BYTES = 32_768;
export const INGEST_MAX_NESTING_DEPTH = 8;
/** Room for the `observationCount` attribute the queue adds to a repeated event. */
const EVENT_BYTE_HEADROOM = 64;

function nestingExceeds(value: unknown, depth: number): boolean {
  if (depth > INGEST_MAX_NESTING_DEPTH) return true;
  if (value === null || typeof value !== "object") return false;
  return Object.values(value).some((item) => nestingExceeds(item, depth + 1));
}

/**
 * Why the ingest API would refuse this event, or null when it is admissible.
 * The API answers such an event by refusing the batch that carries it, and a
 * refused batch is retried, so one such event would block every later event.
 * The reason names fields and limits only, never event content.
 */
export function ingestRejection(event: SecurityFusionEvent): string | null {
  const parsed = securityFusionEventSchema.safeParse(event);
  if (!parsed.success)
    return `invalid ${[
      ...new Set(
        parsed.error.issues.map((issue) => String(issue.path[0] ?? "event")),
      ),
    ].join(", ")}`;
  if (nestingExceeds(event, 1))
    return `nesting deeper than ${INGEST_MAX_NESTING_DEPTH} levels`;
  if (
    Buffer.byteLength(JSON.stringify(event), "utf8") >
    INGEST_MAX_EVENT_BYTES - EVENT_BYTE_HEADROOM
  )
    return `larger than ${INGEST_MAX_EVENT_BYTES} bytes`;
  return null;
}

export type QueueResult = "accepted" | "duplicate" | "seen" | "full";

/**
 * A bounded, deduplicating in-memory buffer. Failed batches are restored at
 * the front while newer queued events are evicted, so retry can never grow the
 * process beyond its configured memory boundary.
 */
export class BoundedSecurityEventQueue {
  readonly #items: SecurityFusionEvent[] = [];
  readonly #queued = new Map<string, SecurityFusionEvent>();
  readonly #seen = new Map<string, true>();

  public constructor(
    readonly maxEvents: number,
    readonly maxSeenEvents = Math.max(maxEvents * 2, 20_000),
  ) {
    if (!Number.isSafeInteger(maxEvents) || maxEvents < 1) {
      throw new Error("maxEvents must be a positive integer");
    }
  }

  public get size(): number {
    return this.#items.length;
  }

  public enqueue(event: SecurityFusionEvent): QueueResult {
    const existing = this.#queued.get(event.eventId);
    if (existing) {
      const count = Number(existing.attributes["observationCount"] ?? 1) + 1;
      existing.attributes = { ...existing.attributes, observationCount: count };
      return "duplicate";
    }
    if (this.#seen.has(event.eventId)) return "seen";
    if (this.#items.length >= this.maxEvents) return "full";
    this.#items.push(event);
    this.#queued.set(event.eventId, event);
    this.#remember(event.eventId);
    return "accepted";
  }

  public take(limit: number, maxBytes = Infinity): SecurityFusionEvent[] {
    let count = 0,
      bytes = 2;
    while (count < Math.min(limit, this.#items.length)) {
      const nextBytes =
        Buffer.byteLength(JSON.stringify(this.#items[count])) + (count ? 1 : 0);
      if (bytes + nextBytes > maxBytes) break;
      bytes += nextBytes;
      count++;
    }
    const events = this.#items.splice(0, count);
    for (const event of events) this.#queued.delete(event.eventId);
    return events;
  }

  public requeueFront(
    events: readonly SecurityFusionEvent[],
  ): SecurityFusionEvent[] {
    const candidates = events.filter(
      (event) => !this.#queued.has(event.eventId),
    );
    const restore = candidates.slice(0, this.maxEvents);
    const dropped: SecurityFusionEvent[] = candidates.slice(this.maxEvents);
    while (this.#items.length + restore.length > this.maxEvents) {
      const displaced = this.#items.pop();
      if (!displaced) break;
      this.#queued.delete(displaced.eventId);
      dropped.push(displaced);
    }
    this.#items.unshift(...restore);
    for (const event of restore) {
      this.#queued.set(event.eventId, event);
      this.#remember(event.eventId);
    }
    return dropped;
  }

  public snapshot(): readonly SecurityFusionEvent[] {
    return [...this.#items];
  }

  #remember(eventId: string): void {
    this.#seen.set(eventId, true);
    while (this.#seen.size > this.maxSeenEvents) {
      const oldest = this.#seen.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#seen.delete(oldest);
    }
  }
}

/** Return the in-flight promise instead of starting overlapping work. */
export function singleFlight<T>(operation: () => Promise<T>): () => Promise<T> {
  let active: Promise<T> | null = null;
  return () => {
    if (active) return active;
    active = operation().finally(() => {
      active = null;
    });
    return active;
  };
}

export interface BoundedFetchOptions {
  timeoutMs: number;
  maxResponseBytes: number;
  fetchImpl?: typeof fetch;
}

export interface BoundedFetchResult {
  response: Response;
  body: Uint8Array;
}

export async function readResponseBodyBounded(
  response: Response,
  maxResponseBytes: number,
): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (
      !Number.isSafeInteger(parsed) ||
      parsed < 0 ||
      parsed > maxResponseBytes
    ) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error(`response exceeded ${maxResponseBytes} byte limit`);
    }
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxResponseBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error(`response exceeded ${maxResponseBytes} byte limit`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function boundedFetch(
  input: string | URL,
  init: RequestInit,
  options: BoundedFetchOptions,
): Promise<BoundedFetchResult> {
  const timeoutSignal = AbortSignal.timeout(options.timeoutMs);
  const signal = init.signal
    ? AbortSignal.any([init.signal, timeoutSignal])
    : timeoutSignal;
  const response = await (options.fetchImpl ?? fetch)(input, {
    ...init,
    signal,
  });
  const body = await readResponseBodyBounded(
    response,
    options.maxResponseBytes,
  );
  return { response, body };
}

export function parseBoundedJson<T>(body: Uint8Array, label: string): T {
  if (body.byteLength === 0)
    throw new Error(`${label} returned an empty response`);
  try {
    return JSON.parse(new TextDecoder().decode(body)) as T;
  } catch (error) {
    throw new Error(`${label} returned invalid JSON`, { cause: error });
  }
}

/** Never start source reads before durable checkpoints have been recovered. */
export function checkpointedPoll(
  hydrate: () => Promise<void>,
  poll: () => Promise<void>,
): () => Promise<void> {
  let ready = false;
  return async () => {
    if (!ready) {
      await hydrate();
      ready = true;
    }
    await poll();
  };
}
