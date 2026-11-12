import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { Hono } from "hono";
import { SignJWT } from "jose";
import { validateHiveEvent } from "@hivemagnus/hive-common/contracts";

const state = vi.hoisted(() => ({
  activity: vi.fn(),
  approvals: vi.fn(),
}));
const caseRow = { id: "case-1", title: "Credential abuse on app-1", severity: "high" };
vi.mock("../db/index.js", () => ({
  getDb: () => ({
    securityFusionCaseActivity: { findMany: state.activity },
    securityFusionActionApproval: { findMany: state.approvals },
    securityFusionCase: { findMany: async () => [caseRow] },
    securityFusionAction: { findMany: async () => [] },
    securityFusionApprovalDecision: { findMany: async () => [] },
    securityFusionCaseEntity: { findMany: async () => [{ caseId: "case-1", entityId: "entity-1" }] },
    securityFusionEntity: {
      findMany: async () => [{ id: "entity-1", canonical: "actor:scout", aliasesJson: '["magnus-node:node-a"]' }],
    },
  }),
}));

const { hiveEventsRouter } = await import("./hive-events.js");
const { errorHandler } = await import("../middleware/error-handler.js");

async function token(role: string) {
  return new SignJWT({ userId: `user-${role.toLowerCase()}`, role })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("cindertrace-console")
    .setAudience("cindertrace-api")
    .setIssuedAt()
    .setExpirationTime("60s")
    .sign(new TextEncoder().encode("x".repeat(64)));
}

function app() {
  const server = new Hono();
  server.onError(errorHandler);
  server.route("/api/v1/hive", hiveEventsRouter);
  return server;
}

async function get(path: string, authorization?: string) {
  return app().request(`/api/v1/hive${path}`, {
    headers: authorization ? { Authorization: authorization } : {},
  });
}

beforeEach(() => {
  vi.stubEnv("SECURITY_CONSOLE_TOKEN_SECRET", "x".repeat(64));
  const opened = {
    id: "activity-1",
    caseId: "case-1",
    kind: "case.opened",
    detailJson: "{}",
    createdAt: new Date(Date.now() - 60_000),
  };
  state.activity.mockImplementation(async (args: { where: { AND: Array<Record<string, unknown>> } }) =>
    "gte" in (args.where.AND[1]!["createdAt"] as object) ? [opened] : [],
  );
  state.approvals.mockResolvedValue([]);
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.clearAllMocks();
});

describe("GET /api/v1/hive/events", () => {
  it("requires a session", async () => {
    expect((await get("/events")).status).toBe(401);
    expect((await get("/events", "Bearer not-a-token")).status).toBe(401);
  });

  it("applies the case-read role rules", async () => {
    expect((await get("/events", `Bearer ${await token("VIEWER")}`)).status).toBe(403);
    for (const role of ["OPERATOR", "ADMIN"]) {
      const response = await get("/events", `Bearer ${await token(role)}`);
      expect(response.status).toBe(200);
      const body = (await response.json()) as { data: unknown[]; nextCursor: string | null };
      expect(body.nextCursor).toBeNull();
      expect(body.data).toHaveLength(1);
      for (const event of body.data) expect(validateHiveEvent(event, { strict: true }).ok).toBe(true);
      expect(body.data[0]).toMatchObject({
        id: "cindertrace:case:case-1:opened",
        type: "case.opened",
        severity: "warning",
        subject: { actorId: "scout", nodeId: "node-a" },
        link: { product: "cindertrace", path: "/security-fusion/cases/case-1" },
      });
    }
  });

  it("refuses endpoint-scoped service credentials", async () => {
    const secret = "read-plugin-token";
    vi.stubEnv(
      "SECURITY_PLUGIN_READ_DIGESTS_JSON",
      JSON.stringify({ plugin: createHash("sha256").update(secret).digest("hex") }),
    );
    expect((await get("/events", `Bearer ${secret}`)).status).toBe(403);
  });

  it("bounds limit and rejects malformed cursors", async () => {
    const auth = `Bearer ${await token("OPERATOR")}`;
    for (const query of ["limit=0", "limit=-1", "limit=abc", "limit=1&limit=2", "after=%2A%2A", "after=e30"])
      expect((await get(`/events?${query}`, auth)).status, query).toBe(400);
    expect((await get("/events?limit=200", auth)).status).toBe(200);
    expect((await get("/events?limit=5000", auth)).status).toBe(200);
    // The store is asked for limit + 1 rows, capped at 200 + 1.
    const takes = state.activity.mock.calls.map(([args]) => (args as { take: number }).take);
    expect(Math.max(...takes.filter((take) => take < 1000))).toBe(201);
  });

  it("asks the database only for served activity kinds", async () => {
    await get("/events", `Bearer ${await token("ADMIN")}`);
    const where = (state.activity.mock.calls[0]![0] as { where: { AND: Array<Record<string, unknown>> } }).where.AND[0];
    expect(JSON.stringify(where)).toContain('"kind":"case.updated"');
    expect(JSON.stringify(where)).toContain('\\"status\\":\\"resolved\\"');
    expect(JSON.stringify(where)).not.toContain("evidence.merged");
  });
});
