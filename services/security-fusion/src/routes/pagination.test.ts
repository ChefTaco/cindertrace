import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { encodeCursor } from "@hivemagnus/hive-common/events";

const state = vi.hoisted(() => ({
  queryRaw: vi.fn(),
  cases: vi.fn(),
  events: vi.fn(),
  entities: vi.fn(),
  evidence: vi.fn(),
  receipts: vi.fn(),
  resolve: vi.fn(),
}));
vi.mock("../db/index.js", () => ({
  getDb: () => ({
    $queryRaw: state.queryRaw,
    securityFusionCase: { findMany: state.cases },
    securityFusionEvent: { findMany: state.events },
    securityFusionEntity: { findMany: state.entities },
    securityFusionEvidence: { findMany: state.evidence },
    securityFusionDeletionReceipt: { findMany: state.receipts },
    securityFusionReceiptChainHead: { findUnique: async () => null },
  }),
}));
vi.mock("../services/security-fusion-service.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../services/security-fusion-service.js")>()),
  resolveCaseFilterEntityIds: state.resolve,
}));
vi.mock("../browser-auth/sessions.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../browser-auth/sessions.js")>()),
  browserAuthEnabled: () => true,
  browserSessions: async () => ({
    verify: async (cookie: string) =>
      cookie === "local-admin" ? { userId: "admin", username: "admin", role: "ADMIN", iat: 0, exp: 0 } : null,
  }),
}));
const { securityFusionRouter } = await import("./security-fusion.js");
const { errorHandler } = await import("../middleware/error-handler.js");

function get(path: string) {
  const app = new Hono();
  app.onError(errorHandler);
  app.route("/api/v1/security-fusion", securityFusionRouter);
  return app.request("/api/v1/security-fusion" + path, { headers: { cookie: "cindertrace_session=local-admin" } });
}
const at = (n: number) => new Date(Date.UTC(2026, 10, 20, 12, 0, 0, 0) - n * 1000);
const caseRow = (n: number) => ({
  id: "case-" + String(100 - n).padStart(3, "0"), fingerprint: "f", title: "t", status: "new", severity: "high",
  confidence: 0.5, summary: "s", recommendedInvestigationJson: "[]", evidenceStepsJson: "[]",
  firstSeenAt: at(n), lastSeenAt: at(n), archivedAt: null,
});
beforeEach(() => {
  vi.stubEnv("CINDERTRACE_BROWSER_AUTH_ENABLED", "true");
  for (const mock of Object.values(state)) mock.mockReset();
});
afterEach(() => vi.unstubAllEnvs());

it("pages cases newest first with a cursor that resumes strictly after the last row", async () => {
  state.cases.mockResolvedValueOnce([0, 1, 2].map(caseRow));
  const first = await get("/cases?limit=2");
  expect(first.status).toBe(200);
  const body = await first.json();
  expect(body.data.map((row: { id: string }) => row.id)).toEqual(["case-100", "case-099"]);
  expect(state.cases.mock.calls[0]![0]).toMatchObject({
    take: 3,
    orderBy: [{ lastSeenAt: "desc" }, { id: "desc" }],
  });
  expect(typeof body.nextCursor).toBe("string");
  state.cases.mockResolvedValueOnce([caseRow(2)]);
  const second = await (await get("/cases?limit=2&cursor=" + body.nextCursor)).json();
  expect(second.nextCursor).toBeNull();
  expect(state.cases.mock.calls[1]![0].where.OR).toEqual([
    { lastSeenAt: { lt: at(1) } },
    { lastSeenAt: at(1), id: { lt: "case-099" } },
  ]);
});

it("keeps the default page size and reports the last page", async () => {
  state.cases.mockResolvedValueOnce([caseRow(0)]);
  const body = await (await get("/cases")).json();
  expect(state.cases.mock.calls[0]![0].take).toBe(101);
  expect(body.nextCursor).toBeNull();
});

it("applies the cursor inside the entity-filtered case query", async () => {
  state.resolve.mockResolvedValue(["entity-1"]);
  state.queryRaw.mockResolvedValue([{ id: "case-099" }]);
  state.cases.mockResolvedValue([caseRow(1)]);
  const cursor = encodeCursor({ at: at(0).toISOString(), id: "case-100" });
  const response = await get(`/cases?entityType=host&entity=node-a&limit=1&cursor=${cursor}`);
  expect(response.status).toBe(200);
  const sql = state.queryRaw.mock.calls[0]!;
  expect(sql[0].join("?")).toMatch(/ORDER BY c."lastSeenAt" DESC, c."id" DESC/);
  expect(sql.slice(1)).toEqual(expect.arrayContaining([at(0).toISOString(), "case-100", 2]));
});

it("pages events, entities, evidence and deletion receipts", async () => {
  const row = (n: number, field: string) => ({ id: "row-" + (9 - n), [field]: at(n), aliasesJson: "[]" });
  state.events.mockResolvedValue([row(0, "observedAt"), row(1, "observedAt")]);
  state.entities.mockResolvedValue([row(0, "lastSeenAt"), row(1, "lastSeenAt")]);
  state.evidence.mockResolvedValue([row(0, "preservedAt"), row(1, "preservedAt")]);
  state.receipts.mockResolvedValue([{ id: "r-9", chainSequence: 9 }, { id: "r-8", chainSequence: 8 }]);
  for (const [path, mock, field] of [
    ["/events", state.events, "observedAt"],
    ["/entities", state.entities, "lastSeenAt"],
    ["/evidence", state.evidence, "preservedAt"],
    ["/deletion-receipts", state.receipts, "chainSequence"],
  ] as const) {
    const body = await (await get(path + "?limit=1")).json();
    expect(body.nextCursor, path).toEqual(expect.any(String));
    expect(mock.mock.calls[0]![0]).toMatchObject({ take: 2, orderBy: [{ [field]: "desc" }, { id: "desc" }] });
    await get(path + "?limit=1&cursor=" + body.nextCursor);
    const where = mock.mock.calls[1]![0].where;
    expect(where.OR[1].id, path).toEqual({ lt: path === "/deletion-receipts" ? "r-9" : "row-9" });
  }
  expect((await (await get("/deletion-receipts?limit=1")).json()).data.receipts).toHaveLength(1);
});

it("refuses a tampered or mismatched cursor", async () => {
  for (const path of [
    "/cases?cursor=not-a-cursor",
    "/cases?cursor=" + encodeCursor({ at: "yesterday", id: "x" }),
    "/deletion-receipts?cursor=" + encodeCursor({ at: at(0).toISOString(), id: "x" }),
    "/events?cursor=" + encodeCursor({ at: at(0).toISOString() }),
  ]) {
    const response = await get(path);
    expect(response.status, path).toBe(400);
    expect((await response.json()).error.code).toBe("INVALID_CURSOR");
  }
});
