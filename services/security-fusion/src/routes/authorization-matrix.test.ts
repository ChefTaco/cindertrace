import { afterEach, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { SignJWT } from "jose";
// A sentinel proves authorization reached the real handler without accessing production state.
vi.mock("../db/index.js", () => ({
  getDb: () => {
    throw Object.assign(new Error("handler reached"), { status: 299 });
  },
}));
import { securityFusionRouter } from "./security-fusion.js";
const reads = [
  "/lab",
  "/lab/runs/id",
  "/lab/runs/id/comparison",
  "/overview",
  "/sources",
  "/source-registry",
  "/events",
  "/entities",
  "/entities/id",
  "/cases",
  "/cases/id",
  "/policies",
];
const evidence = ["/evidence", "/deletion-receipts", "/audit"];
const mutations = [
  ["POST", "/lab/runs/id/advance"],
  ["POST", "/lab/runs/id/complete"],
  ["PATCH", "/cases/id"],
  ["POST", "/cases/id/investigations"],
  ["POST", "/cases/id/assurance/exposure"],
  ["POST", "/cases/id/assurance/investigation"],
  ["POST", "/cases/id/assurance/review"],
  ["POST", "/cases/id/assurance/closure"],
  ["POST", "/cases/id/evidence/event/preserve"],
  ["POST", "/cases/id/actions/preview"],
  ["POST", "/actions/id/request"],
  ["POST", "/actions/id/cancel"],
];
const admin = [
  "/lab/runs",
  "/lab/runs/id/restart",
  "/lab/runs/id/simulations/simulation/decision",
  "/source-registry/id/revoke",
  "/actions/id/release",
];
const nativeApproval = ["/actions/id/approve", "/actions/id/reject"];
const bridge = [["GET", "/approval-plans"], ["GET", "/approval-plans/id"], ["POST", "/approval-decisions"]];
const endpoints = [
  ...reads.map((path) => ["GET", path, "read"]),
  ["POST", "/cases/id/assurance/exposure/preview", "read"],
  ...evidence.map((path) => ["GET", path, "admin"]),
  ...mutations.map(([method, path]) => [method!, path!, "mutate"]),
  ...admin.map((path) => ["POST", path, "admin"]),
  ...nativeApproval.map((path) => ["POST", path, "admin"]),
  ...bridge.map(([method, path]) => [method!, path!, "bridge"]),
];
afterEach(() => vi.unstubAllEnvs());
for (const role of ["VIEWER", "OPERATOR", "ADMIN"]) {
  it.each(endpoints)(`${role} %s %s (%s)`, async (method, path, category) => {
    vi.stubEnv("CINDERTRACE_LAB_ENABLED", path.startsWith("/lab") ? "true" : "false");
    vi.stubEnv("MAGNUS_RESPONSE_URL", "https://magnus.example.com/api/v1/security-integration/response");
    vi.stubEnv("MAGNUS_RESPONSE_SECRET", "test-bridge-secret-".repeat(3));
    vi.stubEnv("SECURITY_CONSOLE_TOKEN_SECRET", "x".repeat(64));
    const token = await new SignJWT({ userId: "user", role })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("cindertrace-console")
      .setAudience("cindertrace-api")
      .setIssuedAt()
      .setExpirationTime("60s")
      .sign(new TextEncoder().encode("x".repeat(64)));
    const app = new Hono();
    app.onError((error, c) =>
      c.json({ error: error.message }, (error as any).status ?? 500),
    );
    app.route("/api/v1/security-fusion", securityFusionRouter);
    const response = await app.request("/api/v1/security-fusion" + path, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      ...(method === "GET"
        ? {}
        : { body: JSON.stringify({ confirmed: true, planSha256: "a".repeat(64), previewSha256: "b".repeat(64) }) }),
    });
    const allowed =
      (category === "read" && role !== "VIEWER") ||
      role === "ADMIN" ||
      (category === "mutate" && role === "OPERATOR");
    if (!allowed || (category === "bridge" && (role !== "ADMIN" || method === "POST"))) expect(response.status).toBe(403);
    else {
      expect([200, 299, 400, 404]).toContain(response.status);
      if (response.status === 404)
        expect(await response.text()).not.toBe("404 Not Found");
    }
  });
}
it("covers every authenticated endpoint class in the router", () => {
  const actual = securityFusionRouter.routes.filter(
    (r) => r.method !== "ALL" && !r.path.startsWith("/ingest"),
  );
  for (const route of actual)
    expect(
      endpoints.some(
        ([method, path]) =>
          method === route.method &&
          path ===
            route.path.replace(":simulationId", "simulation").replace(":eventId", "event").replaceAll(":id", "id"),
      ),
    ).toBe(true);
});

it('rejects an oversized exposure preview body before reaching the assessment', async () => {
  const token = 'read-token-for-preview';
  const digest = (await import('node:crypto')).createHash('sha256').update(token).digest('hex');
  vi.stubEnv('SECURITY_PLUGIN_READ_DIGESTS_JSON', JSON.stringify({ aegis: digest }));
  const app = new Hono();
  app.route('/api/v1/security-fusion', securityFusionRouter);
  const response = await app.request('/api/v1/security-fusion/cases/id/assurance/exposure/preview', {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ padding: 'x'.repeat(65_536) }),
  });
  expect(response.status).toBe(413);
  expect(await response.json()).toMatchObject({ error: { code: 'PAYLOAD_TOO_LARGE' } });
});
