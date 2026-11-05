import { afterEach, expect, it, vi } from "vitest";
import { Hono } from "hono";
const verify = vi.hoisted(() => vi.fn());
vi.mock("./sessions.js", async (original) => ({
  ...(await original<typeof import("./sessions.js")>()),
  browserSessions: async () => ({ verify }),
}));
import { authMiddleware, getUser } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import type { AppVariables } from "../types/index.js";
afterEach(() => {
  vi.unstubAllEnvs();
  verify.mockReset();
});
it("authenticates native cookies independently, rejects mutation origins and fails closed on revocation/storage errors", async () => {
  vi.stubEnv("CINDERTRACE_BROWSER_AUTH_ENABLED", "true");
  vi.stubEnv("DASHBOARD_PUBLIC_ORIGIN", "https://console.example.com");
  const app = new Hono<AppVariables>();
  app.onError(errorHandler);
  app.use("*", authMiddleware);
  app.get("/resource", (c) => c.json({ userId: getUser(c).userId }));
  app.post("/resource", (c) => c.json({ ok: true }));
  verify.mockResolvedValue({
    username: "admin",
    userId: "synthetic-local-account",
    role: "ADMIN",
    iat: 1,
    exp: 9999999999,
  });
  const cookie = { Cookie: "cindertrace_session=obviously-fake-session" };
  expect((await app.request("/resource", { headers: cookie })).status).toBe(
    200,
  );
  expect(
    (await app.request("/resource", { method: "POST", headers: cookie }))
      .status,
  ).toBe(403);
  expect(
    (
      await app.request("/resource", {
        method: "POST",
        headers: { ...cookie, Origin: "https://console.example.com" },
      })
    ).status,
  ).toBe(200);
  verify.mockResolvedValueOnce(null);
  expect((await app.request("/resource", { headers: cookie })).status).toBe(
    401,
  );
  verify.mockRejectedValueOnce(Error("private Redis diagnostics"));
  const failure = await app.request("/resource", { headers: cookie });
  expect(failure.status).toBe(503);
  expect(await failure.text()).not.toContain("private Redis");
});
