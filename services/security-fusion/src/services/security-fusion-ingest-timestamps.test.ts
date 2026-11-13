import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SecurityFusionEvent } from "@cindertrace/contracts";

type Row = Record<string, any>;
const compound = new Set(["type_canonical", "source_canonical", "eventId_entityId", "caseId_entityId"]);
function matches(row: Row, where: Row = {}): boolean {
  return Object.entries(where).every(([key, expected]) => {
    if (compound.has(key)) return matches(row, expected);
    if (expected && typeof expected === "object" && "in" in expected) return expected.in.includes(row[key]);
    if (expected && typeof expected === "object" && "contains" in expected)
      return String(row[key]).includes(expected.contains);
    return row[key] === expected;
  });
}

/** In-memory entity tables; every other model records its calls and returns empty defaults. */
function fakeDb() {
  let sequence = 0;
  const tables: Record<string, Row[]> = {
    securityFusionEntity: [],
    securityFusionEntityAlias: [],
    securityFusionEventEntity: [],
    securityFusionCaseEntity: [],
  };
  const calls: Array<{ model: string; method: string; args: any }> = [];
  const table = (model: string) => {
    const rows = tables[model]!;
    return {
      findUnique: async ({ where }: Row) => rows.find((row) => matches(row, where)) ?? null,
      findFirst: async ({ where }: Row) => rows.find((row) => matches(row, where)) ?? null,
      findMany: async ({ where, take }: Row = {}) =>
        rows.filter((row) => matches(row, where)).slice(0, take ?? Infinity),
      count: async ({ where }: Row = {}) => rows.filter((row) => matches(row, where)).length,
      upsert: async ({ where, create, update }: Row) => {
        const row = rows.find((item) => matches(item, where));
        if (row) return Object.assign(row, update);
        const created = { id: `${model}-${++sequence}`, ...create };
        rows.push(created);
        return created;
      },
    };
  };
  const generic = (model: string) =>
    new Proxy(
      {},
      {
        get: (_target, method: string) => async (args: any) => {
          calls.push({ model, method, args });
          if (method === "findMany") {
            const gte = args?.where?.observedAt?.gte;
            if (gte instanceof Date && gte.getUTCFullYear() < 1)
              throw Object.assign(new Error("date/time field value out of range"), { code: "22008" });
            return [];
          }
          if (method === "count") return 0;
          if (method === "findUnique" && model === "securityFusionCase" && args?.select)
            return { evidenceAcceptedCount: 0 };
          if (method === "findUnique" || method === "findFirst") return null;
          return { id: `${model}-${++sequence}`, ...(args?.create ?? args?.data ?? {}) };
        },
      },
    );
  const models: Record<string, unknown> = Object.fromEntries(
    Object.keys(tables).map((model) => [model, table(model)]),
  );
  const db: any = new Proxy(
    {},
    {
      get: (_target, prop: string) =>
        prop === "$transaction"
          ? async (fn: (tx: unknown) => unknown) => fn(db)
          : prop === "$queryRaw"
            ? async () => []
            : (models[prop] ??= generic(prop)),
    },
  );
  return { db, tables, calls };
}

let current = fakeDb();
vi.mock("../db/index.js", () => ({ getDb: () => current.db }));

const { ingestSecurityFusionBatch } = await import("./security-fusion-service.js");
const {
  observedAtRejection,
  SECURITY_FUSION_EARLIEST_OBSERVED_AT,
  SECURITY_FUSION_MAX_FUTURE_SKEW_MS,
} = await import("./security-fusion-ingest.js");

beforeEach(() => {
  current = fakeDb();
});

const receivedAt = new Date("2026-11-12T10:00:00.000Z");
const peerEvent = (id: string, observedAt: string): SecurityFusionEvent => ({
  schemaVersion: "1.0",
  eventId: `event-${id}`,
  source: "tailscale",
  sourceEventId: `peer-${id}`,
  kind: "tailscale.peer.online",
  observedAt,
  severity: "info",
  confidence: 0.9,
  summary: "peer-a is online on the tailnet",
  entities: [{ type: "host", value: "peer-a" }],
  attributes: {},
  evidence: [],
});
const batch = (events: SecurityFusionEvent[]) => ({
  schemaVersion: "1.0" as const,
  collectorId: "test-collector",
  sentAt: receivedAt.toISOString(),
  events,
});

describe("observedAt bounds", () => {
  it("accepts recent, backfilled and slightly skewed times", () => {
    for (const observedAt of [
      "2026-11-12T09:59:00.000Z",
      "2026-11-12T09:59:00+02:00",
      SECURITY_FUSION_EARLIEST_OBSERVED_AT,
      new Date(receivedAt.getTime() + SECURITY_FUSION_MAX_FUTURE_SKEW_MS).toISOString(),
    ])
      expect(observedAtRejection({ eventId: "e", observedAt }, 0, receivedAt)).toBeNull();
  });

  it("rejects zero, epoch and far-future times as a per-event 400", () => {
    for (const observedAt of [
      "0001-01-01T00:00:00Z",
      "0001-01-01T00:00:00.000Z",
      "1970-01-01T00:00:00Z",
      "1999-12-31T23:59:59.999Z",
      new Date(receivedAt.getTime() + SECURITY_FUSION_MAX_FUTURE_SKEW_MS + 1).toISOString(),
      "9999-12-31T23:59:59Z",
    ])
      expect(observedAtRejection({ eventId: "e", observedAt }, 3, receivedAt)).toMatchObject({
        index: 3,
        eventId: "e",
        status: 400,
        code: "INGEST_TIMESTAMP_OUT_OF_RANGE",
      });
  });
});

describe("batch ingest with an out-of-range event", () => {
  it("stores the valid events and reports the zero-time event instead of failing the batch", async () => {
    const result = await ingestSecurityFusionBatch(
      batch([
        peerEvent("before", "2026-11-12T09:58:00.000Z"),
        peerEvent("zero", "0001-01-01T00:00:00Z"),
        peerEvent("after", "2026-11-12T09:59:00.000Z"),
      ]),
      receivedAt,
    );
    expect(result.stored).toBe(2);
    expect(result.duplicates).toBe(0);
    expect(result.rejected).toEqual([
      expect.objectContaining({ index: 1, eventId: "event-zero", status: 400, code: "INGEST_TIMESTAMP_OUT_OF_RANGE" }),
    ]);
    const created = current.calls
      .filter((call) => call.model === "securityFusionEvent" && call.method === "create")
      .map((call) => call.args.data.eventId);
    expect(created).toEqual(["event-before", "event-after"]);
  });

  it("returns 202-style results when every event is rejected", async () => {
    const result = await ingestSecurityFusionBatch(batch([peerEvent("epoch", "1970-01-01T00:00:00Z")]), receivedAt);
    expect(result).toMatchObject({ stored: 0, duplicates: 0, caseIds: [] });
    expect(result.rejected).toHaveLength(1);
    expect(current.calls.some((call) => call.model === "securityFusionSourceState")).toBe(false);
  });
});
