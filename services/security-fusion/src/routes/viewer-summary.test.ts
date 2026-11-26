import { afterEach, expect, it, vi } from "vitest";
import { Hono } from "hono";
const state = vi.hoisted(() => ({ cases: vi.fn(), role: "VIEWER" }));
vi.mock("../db/index.js", () => ({
  getDb: () => ({
    securityFusionCase: { findMany: state.cases, groupBy: async () => [{ severity: "high", _count: { id: 3 } }] },
    securityFusionSourceState: { findMany: async () => [] },
  }),
}));
vi.mock("../browser-auth/sessions.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../browser-auth/sessions.js")>()),
  browserAuthEnabled: () => true,
  browserSessions: async () => ({ verify: async () => ({ userId: "u", username: "u", role: state.role, iat: 0, exp: 0 }) }),
}));
const { securityFusionRouter } = await import("./security-fusion.js");
const { securityBrowserResponseSchema } = await import("@cindertrace/contracts/browser");
const { errorHandler } = await import("../middleware/error-handler.js");
afterEach(() => vi.unstubAllEnvs());
it("serves a VIEWER the overview counts without case titles", async () => {
  vi.stubEnv("CINDERTRACE_BROWSER_AUTH_ENABLED", "true");
  state.cases.mockResolvedValue([]);
  const app = new Hono();
  app.onError(errorHandler);
  app.route("/api/v1/security-fusion", securityFusionRouter);
  const get = (path: string) => app.request("/api/v1/security-fusion" + path, { headers: { cookie: "cindertrace_session=s" } });
  const body = await (await get("/overview")).json();
  expect(body.data.openCases).toEqual([]);
  expect(body.data.bySeverity).toEqual([{ severity: "high", _count: { id: 3 } }]);
  expect(state.cases).not.toHaveBeenCalled();
  securityBrowserResponseSchema("security-fusion/overview").parse(body);
  expect((await get("/cases")).status).toBe(403);
  state.role = "OPERATOR";
  await get("/overview");
  expect(state.cases).toHaveBeenCalledOnce();
});
