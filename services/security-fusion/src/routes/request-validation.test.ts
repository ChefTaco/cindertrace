import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { SignJWT } from "jose";

const fixture = vi.hoisted(() => ({
  nonceError: undefined as unknown,
  nonces: [] as Array<{ nonce: string; expiresAt: Date }>,
  eventTake: undefined as unknown,
  caseUpdateError: undefined as unknown,
  caseUpdates: [] as Array<Record<string, unknown>>,
  activity: [] as Array<{ detailJson: string }>,
}));
vi.mock("../db/index.js", () => {
  const db = {
    $transaction: async (fn: (tx: unknown) => unknown) => fn(db),
    securityFusionCollector: {
      findUnique: async () => null,
      upsert: async () => ({}),
      update: async () => ({}),
    },
    securityFusionNonce: {
      create: async ({ data }: { data: { nonce: string; expiresAt: Date } }) => {
        if (fixture.nonceError) throw fixture.nonceError;
        fixture.nonces.push(data);
      },
    },
    securityFusionSourceState: { findMany: async () => [] },
    securityFusionEvent: {
      findMany: async ({ take }: { take: unknown }) => {
        fixture.eventTake = take;
        return [];
      },
    },
    securityFusionCase: {
      update: async ({ data }: { data: Record<string, unknown> }) => {
        if (fixture.caseUpdateError) throw fixture.caseUpdateError;
        fixture.caseUpdates.push(data);
        return { id: "case-1", ...data };
      },
    },
    securityFusionCaseActivity: {
      create: async ({ data }: { data: { detailJson: string } }) => {
        fixture.activity.push(data);
      },
    },
  };
  return { getDb: () => db };
});
vi.mock("../services/audit-service.js", () => ({
  logAuditEvent: vi.fn(),
  queryAuditEvents: vi.fn(),
  sanitizeDetails: (value: unknown) => value,
}));

import { errorHandler } from "../middleware/error-handler.js";
import {
  boundedQueryInteger,
  securityFusionIngestSignature,
  securityFusionRouter,
} from "./security-fusion.js";

const app = new Hono();
app.onError(errorHandler);
app.route("/api/v1/security-fusion", securityFusionRouter);

const consoleSecret = "c".repeat(40);
const collectorSecret = "collector-fixture-".repeat(2);
async function adminToken(): Promise<string> {
  return new SignJWT({ userId: "admin-1", role: "ADMIN" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("cindertrace-console")
    .setAudience("cindertrace-api")
    .setIssuedAt()
    .setExpirationTime("60s")
    .sign(new TextEncoder().encode(consoleSecret));
}
function checkpoints(nonce: string, timestamp = new Date().toISOString()) {
  return app.request("/api/v1/security-fusion/ingest/checkpoints", {
    headers: {
      "x-security-collector-id": "collector-a",
      "x-security-timestamp": timestamp,
      "x-security-nonce": nonce,
      "x-security-signature": securityFusionIngestSignature(
        collectorSecret,
        "collector-a",
        timestamp,
        nonce,
        "",
      ),
    },
  });
}
async function patchCase(body: string) {
  return app.request("/api/v1/security-fusion/cases/case-1", {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${await adminToken()}`,
      "content-type": "application/json",
    },
    body,
  });
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.stubEnv("SECURITY_CONSOLE_TOKEN_SECRET", consoleSecret);
  vi.stubEnv(
    "SECURITY_FUSION_COLLECTOR_CREDENTIALS_JSON",
    JSON.stringify({ "collector-a": { secret: collectorSecret } }),
  );
  Object.assign(fixture, {
    nonceError: undefined,
    nonces: [],
    eventTake: undefined,
    caseUpdateError: undefined,
    caseUpdates: [],
    activity: [],
  });
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

it("reports a reused ingest nonce as a replay", async () => {
  fixture.nonceError = Object.assign(new Error("unique"), { code: "P2002" });
  const response = await checkpoints("nonce-replayed");
  expect(response.status).toBe(409);
  expect((await response.json()).error.code).toBe("INGEST_REPLAY");
});

it("does not report an ingest storage failure as a replay", async () => {
  fixture.nonceError = new Error("connection terminated");
  const response = await checkpoints("nonce-storage-failure");
  expect(response.status).toBe(500);
  expect((await response.json()).error.code).toBe("INTERNAL_ERROR");
});

it("keeps an ingest nonce for as long as its signed timestamp stays acceptable", async () => {
  const ahead = new Date(Date.now() + 4 * 60_000);
  expect((await checkpoints("nonce-clock-ahead", ahead.toISOString())).status).toBe(200);
  // The request stays inside the five minute skew until `ahead + 5 min`.
  expect(fixture.nonces[0]!.expiresAt.getTime()).toBeGreaterThanOrEqual(
    ahead.getTime() + 5 * 60_000,
  );
  const behind = new Date(Date.now() - 4 * 60_000);
  expect((await checkpoints("nonce-clock-behind", behind.toISOString())).status).toBe(200);
  expect(fixture.nonces[1]!.expiresAt.getTime()).toBeGreaterThanOrEqual(
    Date.now() + 5 * 60_000 - 1_000,
  );
});

it("bounds query integers and falls back for values that are not numbers", () => {
  expect(boundedQueryInteger(undefined, 100, 1, 250)).toBe(100);
  expect(boundedQueryInteger("", 100, 1, 250)).toBe(100);
  expect(boundedQueryInteger("abc", 100, 1, 250)).toBe(100);
  expect(boundedQueryInteger("Infinity", 100, 1, 250)).toBe(100);
  expect(boundedQueryInteger("0", 100, 1, 250)).toBe(1);
  expect(boundedQueryInteger("12.9", 100, 1, 250)).toBe(12);
  expect(boundedQueryInteger("9999", 100, 1, 250)).toBe(250);
});

it("serves the event list when the limit is not a number", async () => {
  const response = await app.request("/api/v1/security-fusion/events?limit=abc", {
    headers: { Authorization: `Bearer ${await adminToken()}` },
  });
  expect(response.status).toBe(200);
  expect(fixture.eventTake).toBe(100);
});

it("rejects a case update that is not JSON or names an unknown status", async () => {
  for (const body of ["{not json", "null", '{"status":"closed"}', '{"status":["resolved"]}', '{"assignedTo":7}']) {
    const response = await patchCase(body);
    expect(response.status, body).toBe(400);
    expect((await response.json()).error.code).toBe("VALIDATION_ERROR");
  }
  expect(fixture.caseUpdates).toEqual([]);
});

it("records only the validated fields of a case update", async () => {
  const response = await patchCase(
    JSON.stringify({ status: "triage", assignedTo: "analyst-1", padding: "x".repeat(4096) }),
  );
  expect(response.status).toBe(200);
  expect(fixture.caseUpdates).toEqual([
    { status: "triage", resolvedAt: null, assignedTo: "analyst-1" },
  ]);
  expect(fixture.activity.map((row) => JSON.parse(row.detailJson))).toEqual([
    { status: "triage", assignedTo: "analyst-1" },
  ]);
});

it("closes a case as a false positive and leaves the status alone when it is empty", async () => {
  expect((await patchCase('{"status":"false_positive"}')).status).toBe(200);
  expect(fixture.caseUpdates[0]!["resolvedAt"]).toBeInstanceOf(Date);
  expect(fixture.activity[0]!.detailJson).toContain('"status":"false_positive"');
  expect((await patchCase('{"status":"","assignedTo":null}')).status).toBe(200);
  expect(fixture.caseUpdates[1]).toEqual({ assignedTo: null });
});

it("answers 404 for an update to a case that does not exist", async () => {
  fixture.caseUpdateError = Object.assign(new Error("missing"), { code: "P2025" });
  const response = await patchCase('{"status":"triage"}');
  expect(response.status).toBe(404);
  expect((await response.json()).error.code).toBe("NOT_FOUND");
});
