import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { Hono } from "hono";
import { SignJWT } from "jose";

const state = vi.hoisted(() => ({
  queryRaw: vi.fn(),
  caseFindMany: vi.fn(),
  resolve: vi.fn(),
}));
vi.mock("../db/index.js", () => ({
  getDb: () => ({
    $queryRaw: state.queryRaw,
    securityFusionCase: { findMany: state.caseFindMany },
  }),
}));
vi.mock("../services/security-fusion-service.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../services/security-fusion-service.js")>()),
  resolveCaseFilterEntityIds: state.resolve,
}));
vi.mock("../middleware/oathweave.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../middleware/oathweave.js")>()),
  oathweaveAuthentication: async (token: string) =>
    token === "oathweave-operator"
      ? { userId: "linked-operator", email: "", role: "OPERATOR", iat: 0, exp: 0 }
      : token === "oathweave-viewer"
        ? { userId: "linked-viewer", email: "", role: "VIEWER", iat: 0, exp: 0 }
        : undefined,
}));
vi.mock("../browser-auth/sessions.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../browser-auth/sessions.js")>()),
  browserAuthEnabled: () => true,
  browserSessions: async () => ({
    verify: async (cookie: string) =>
      cookie === "local-operator"
        ? { userId: "local-operator", username: "operator", role: "OPERATOR", iat: 0, exp: 0 }
        : cookie === "local-viewer"
          ? { userId: "local-viewer", username: "viewer", role: "VIEWER", iat: 0, exp: 0 }
          : null,
  }),
}));

const { securityFusionRouter } = await import("./security-fusion.js");

const caseRow = {
  id: "case-1",
  fingerprint: "f",
  title: "security observation · node-a",
  status: "new",
  severity: "high",
  confidence: 0.8,
  summary: "synthetic",
  recommendedInvestigationJson: '["check"]',
  evidenceStepsJson: "[]",
  firstSeenAt: new Date("2026-11-12T10:00:00.000Z"),
  lastSeenAt: new Date("2026-11-12T10:00:00.000Z"),
  archivedAt: null,
};

async function consoleToken(role: string) {
  return new SignJWT({ userId: "user", role })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("cindertrace-console")
    .setAudience("cindertrace-api")
    .setIssuedAt()
    .setExpirationTime("60s")
    .sign(new TextEncoder().encode("x".repeat(64)));
}

function request(query: string, headers: Record<string, string>) {
  const app = new Hono();
  app.onError((error, c) =>
    c.json(
      { error: { code: (error as any).code, message: error.message } },
      (error as any).status ?? 500,
    ),
  );
  app.route("/api/v1/security-fusion", securityFusionRouter);
  return app.request(`/api/v1/security-fusion/cases${query}`, { headers });
}

beforeEach(() => {
  vi.stubEnv("SECURITY_CONSOLE_TOKEN_SECRET", "x".repeat(64));
  vi.stubEnv("CINDERTRACE_BROWSER_AUTH_ENABLED", "true");
  state.queryRaw.mockReset().mockResolvedValue([{ id: "case-1" }]);
  state.caseFindMany.mockReset().mockResolvedValue([caseRow]);
  state.resolve.mockReset().mockResolvedValue(["entity-1"]);
});
afterEach(() => vi.unstubAllEnvs());

describe("GET /cases entity filter", () => {
  it("keeps today's unfiltered response", async () => {
    const response = await request("?status=new", { Authorization: `Bearer ${await consoleToken("OPERATOR")}` });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({
      success: true,
      data: [
        {
          id: "case-1",
          fingerprint: "f",
          title: "security observation · node-a",
          status: "new",
          severity: "high",
          confidence: 0.8,
          summary: "synthetic",
          firstSeenAt: "2026-11-12T10:00:00.000Z",
          lastSeenAt: "2026-11-12T10:00:00.000Z",
          archivedAt: null,
          recommendedInvestigation: ["check"],
          evidenceSteps: [],
        },
      ],
    });
    expect(state.queryRaw).not.toHaveBeenCalled();
    expect(state.resolve).not.toHaveBeenCalled();
    expect(state.caseFindMany.mock.calls[0]![0]).toEqual({
      where: { status: "new", archivedAt: null },
      orderBy: { lastSeenAt: "desc" },
      take: 100,
    });
  });

  it("returns cases linked to the resolved entities, in the same shape", async () => {
    const response = await request("?entityType=agent&entity=actor%3Alead&archived=true", {
      Authorization: `Bearer ${await consoleToken("OPERATOR")}`,
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.data.map((row: { id: string }) => row.id)).toEqual(["case-1"]);
    expect(state.resolve).toHaveBeenCalledWith("agent", "actor:lead");
    const [strings, ...values] = state.queryRaw.mock.calls[0]!;
    expect((strings as string[]).join("?")).toContain('"security_fusion_case_entities"');
    expect(values).toContainEqual(["entity-1"]);
    expect(values).toContain(true);
    expect(state.caseFindMany.mock.calls[0]![0].where).toEqual({
      archivedAt: { not: null },
      id: { in: ["case-1"] },
    });
  });

  it("returns an empty list without touching cases when nothing matches", async () => {
    state.resolve.mockResolvedValue([]);
    const response = await request("?entityType=host&entity=unknown", {
      Authorization: `Bearer ${await consoleToken("OPERATOR")}`,
    });
    expect(await response.json()).toEqual({ success: true, data: [] });
    expect(state.queryRaw).not.toHaveBeenCalled();
    expect(state.caseFindMany).not.toHaveBeenCalled();
  });

  it.each([
    "?entityType=agent",
    "?entity=actor%3Alead",
    "?entityType=robot&entity=x",
    "?entityType=agent&entity=lead",
    "?entityType=agent&entity=actor%3ANOT_VALID",
    "?entityType=host&entity=",
    `?entityType=host&entity=${"x".repeat(513)}`,
  ])("rejects invalid filter %s", async (query) => {
    const response = await request(query, { Authorization: `Bearer ${await consoleToken("ADMIN")}` });
    expect(response.status).toBe(400);
    expect((await response.json()).error.code).toBe("INVALID_ENTITY_FILTER");
    expect(state.resolve).not.toHaveBeenCalled();
  });
});

describe("GET /cases entity filter authorization", () => {
  const query = "?entityType=agent&entity=agent-ref%3Anode-1~lead";

  it("allows console operators and admins and refuses viewers", async () => {
    for (const role of ["OPERATOR", "ADMIN"])
      expect((await request(query, { Authorization: `Bearer ${await consoleToken(role)}` })).status).toBe(200);
    expect((await request(query, { Authorization: `Bearer ${await consoleToken("VIEWER")}` })).status).toBe(403);
    expect((await request(query, {})).status).toBe(401);
  });

  it("applies Oathweave-linked roles", async () => {
    expect((await request(query, { Authorization: "Bearer oathweave-operator" })).status).toBe(200);
    expect((await request(query, { Authorization: "Bearer oathweave-viewer" })).status).toBe(403);
  });

  it("applies local login session roles", async () => {
    expect((await request(query, { Cookie: "cindertrace_session=local-operator" })).status).toBe(200);
    expect((await request(query, { Cookie: "cindertrace_session=local-viewer" })).status).toBe(403);
    expect((await request(query, { Cookie: "cindertrace_session=revoked" })).status).toBe(401);
  });

  it("accepts endpoint-scoped read credentials", async () => {
    const token = "synthetic-read-credential";
    vi.stubEnv(
      "SECURITY_PLUGIN_READ_DIGESTS_JSON",
      JSON.stringify({ reader: createHash("sha256").update(token).digest("hex") }),
    );
    expect((await request(query, { Authorization: `Bearer ${token}` })).status).toBe(200);
  });
});
