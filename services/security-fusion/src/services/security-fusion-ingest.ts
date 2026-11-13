import { createHash } from "node:crypto";
import {
  securityFusionSourceSchema,
  type SecurityFusionSource,
} from "@cindertrace/contracts";
import { HttpError } from "../middleware/error-handler.js";

export const SECURITY_FUSION_MAX_BATCH_BYTES = 262_144;
export const SECURITY_FUSION_MAX_EVENT_BYTES = 32_768;
export const SECURITY_FUSION_MAX_EVENTS = 100;
export const SECURITY_FUSION_MAX_NESTING_DEPTH = 8;
/**
 * Earliest event time ingest accepts. Zero times such as `0001-01-01T00:00:00Z`
 * (the Go and .NET zero value) and the Unix epoch fall below it.
 */
export const SECURITY_FUSION_EARLIEST_OBSERVED_AT = "2000-01-01T00:00:00.000Z";
/** How far past receipt an event time may be, to allow for sender clock skew. */
export const SECURITY_FUSION_MAX_FUTURE_SKEW_MS = 60 * 60_000;

/** One event a batch could not store. The rest of the batch is still ingested. */
export interface RejectedSecurityFusionEvent {
  index: number;
  eventId: string;
  status: 400;
  code: "INGEST_TIMESTAMP_OUT_OF_RANGE";
  message: string;
}

/**
 * Rejects an event whose `observedAt` is a zero, implausibly old or far-future
 * time. Correlation looks back 15 minutes from `observedAt`, so a zero time
 * would underflow the database's date range and fail the whole batch.
 */
export function observedAtRejection(
  event: { eventId: string; observedAt: string },
  index: number,
  receivedAt: Date,
): RejectedSecurityFusionEvent | null {
  const observedAt = Date.parse(event.observedAt);
  if (
    Number.isFinite(observedAt) &&
    observedAt >= Date.parse(SECURITY_FUSION_EARLIEST_OBSERVED_AT) &&
    observedAt <= receivedAt.getTime() + SECURITY_FUSION_MAX_FUTURE_SKEW_MS
  )
    return null;
  return {
    index,
    eventId: event.eventId,
    status: 400,
    code: "INGEST_TIMESTAMP_OUT_OF_RANGE",
    message: `observedAt must be no earlier than ${SECURITY_FUSION_EARLIEST_OBSERVED_AT} and no more than ${SECURITY_FUSION_MAX_FUTURE_SKEW_MS / 60_000} minutes after receipt`,
  };
}

export interface CollectorCredential {
  collectorId: string;
  secret: string;
  allowedSources: SecurityFusionSource[];
  displayName: string;
  schemaVersion: "1.0";
  dataClassification: string;
}

function sources(value: unknown): SecurityFusionSource[] {
  const candidates = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean)
      : [];
  const parsed = securityFusionSourceSchema
    .array()
    .min(1)
    .safeParse(candidates);
  if (!parsed.success)
    throw new Error(
      "collector allowedSources must contain recognized Security Fusion sources",
    );
  return [...new Set(parsed.data)];
}

export function configuredCollectorCredentials(
  env: NodeJS.ProcessEnv = process.env,
): Map<string, CollectorCredential> {
  const credentials = new Map<string, CollectorCredential>();
  const encoded = env["SECURITY_FUSION_COLLECTOR_CREDENTIALS_JSON"];
  if (encoded) {
    const value = JSON.parse(encoded) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(
        "SECURITY_FUSION_COLLECTOR_CREDENTIALS_JSON must be an object",
      );
    }
    for (const [collectorId, raw] of Object.entries(value)) {
      if (!/^[a-zA-Z0-9._:-]{1,160}$/u.test(collectorId)) {
        throw new Error(
          "collector IDs must be 1-160 safe identifier characters",
        );
      }
      const config =
        typeof raw === "string"
          ? { secret: raw }
          : (raw as Record<string, unknown>);
      if (
        !config ||
        typeof config !== "object" ||
        typeof config["secret"] !== "string" ||
        config["secret"].length < 16
      ) {
        throw new Error(
          `collector ${collectorId} must have a secret of at least 16 characters`,
        );
      }
      credentials.set(collectorId, {
        collectorId,
        secret: config["secret"],
        allowedSources: sources(
          config["allowedSources"] ?? securityFusionSourceSchema.options,
        ),
        displayName:
          typeof config["displayName"] === "string"
            ? config["displayName"]
            : collectorId,
        schemaVersion: "1.0",
        dataClassification:
          typeof config["dataClassification"] === "string"
            ? config["dataClassification"]
            : "restricted",
      });
    }
  }

  const legacySecret = env["SECURITY_FUSION_INGEST_SECRET"];
  if (legacySecret) {
    const collectorId =
      env["SECURITY_FUSION_COLLECTOR_ID"] ?? "magnus-security-collector";
    if (
      !/^[a-zA-Z0-9._:-]{1,160}$/u.test(collectorId) ||
      legacySecret.length < 16
    ) {
      throw new Error("legacy collector ID or credential is invalid");
    }
    if (!credentials.has(collectorId)) {
      credentials.set(collectorId, {
        collectorId,
        secret: legacySecret,
        allowedSources: sources(
          env["SECURITY_FUSION_COLLECTOR_ALLOWED_SOURCES"] ??
            securityFusionSourceSchema.options,
        ),
        displayName: collectorId,
        schemaVersion: "1.0",
        dataClassification:
          env["SECURITY_FUSION_DATA_CLASSIFICATION"] ?? "restricted",
      });
    }
  }
  return credentials;
}

export function collectorCredentialFingerprint(secret: string): string {
  return createHash("sha256").update(secret).digest("hex").slice(0, 16);
}

function assertDepth(value: unknown, depth: number): void {
  if (depth > SECURITY_FUSION_MAX_NESTING_DEPTH) {
    throw new HttpError(
      400,
      "INGEST_NESTING_TOO_DEEP",
      "Event nesting exceeds the permitted depth",
    );
  }
  if (Array.isArray(value)) {
    for (const item of value) assertDepth(item, depth + 1);
  } else if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) assertDepth(item, depth + 1);
  }
}

export function validateSecurityFusionBatchEnvelope(
  value: unknown,
  rawBytes: number,
): void {
  if (rawBytes > SECURITY_FUSION_MAX_BATCH_BYTES) {
    throw new HttpError(
      413,
      "PAYLOAD_TOO_LARGE",
      "Security Fusion batch exceeds the byte limit",
    );
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return;
  const events = (value as Record<string, unknown>)["events"];
  if (!Array.isArray(events)) return;
  if (events.length > SECURITY_FUSION_MAX_EVENTS) {
    throw new HttpError(
      400,
      "INGEST_EVENT_LIMIT",
      `A batch may contain at most ${SECURITY_FUSION_MAX_EVENTS} events`,
    );
  }
  for (const event of events) {
    assertDepth(event, 1);
    if (
      Buffer.byteLength(JSON.stringify(event), "utf8") >
      SECURITY_FUSION_MAX_EVENT_BYTES
    ) {
      throw new HttpError(
        400,
        "INGEST_EVENT_TOO_LARGE",
        "An individual event exceeds the byte limit",
      );
    }
  }
}
