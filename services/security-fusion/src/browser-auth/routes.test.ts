import { afterEach, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { browserAuthRouter } from "./routes.js";
import { exactBrowserOrigin } from "./origin.js";
import { BrowserSessions } from "./sessions.js";
import { createAuthProtection } from "./throttling.js";
const env = {
  CINDERTRACE_BROWSER_AUTH_ENABLED: "true",
  DASHBOARD_PUBLIC_ORIGIN: "https://console.example.com",
  DASHBOARD_ADMIN_USERNAME: "admin",
  DASHBOARD_ADMIN_PASSWORD: "obviously-fake-password",
  SESSION_SECRET: "s".repeat(64),
};
afterEach(() => vi.unstubAllEnvs());
function fixture() {
  const create = vi.fn().mockResolvedValue("obviously-fake-session"),
    verify = vi.fn().mockResolvedValue(null),
    revoke = vi.fn().mockResolvedValue(undefined),
    audit = vi.fn().mockResolvedValue(undefined),
    release = vi.fn().mockResolvedValue(undefined),
    clearSuccessfulPair = vi.fn().mockResolvedValue(undefined);
  const admission = vi
    .fn()
    .mockResolvedValue({
      allowed: true,
      retryAfterSeconds: 0,
      sourceLabel: "source-hash",
      usernameLabel: "username-hash",
      pairLabel: "pair-hash",
      release,
      clearSuccessfulPair,
    });
  const app = new Hono().route(
    "/auth",
    browserAuthRouter({
      env,
      sessions: async () =>
        ({ create, verify, revoke }) as unknown as BrowserSessions,
      admission,
      audit,
    }),
  );
  return { app, create, verify, revoke, audit, admission, release };
}
const login = (
  app: Hono,
  origin = "https://console.example.com",
  password = "obviously-fake-password",
) =>
  app.request("/auth/login", {
    method: "POST",
    headers: {
      Origin: origin,
      "Content-Type": "application/json",
      "X-Forwarded-For": "198.51.100.1",
      "X-Real-IP": "198.51.100.2",
    },
    body: JSON.stringify({ username: "admin", password }),
  });
it("requires an exact HTTPS origin and never trusts caller forwarding addresses for authentication admission", async () => {
  for (const value of [
    "https://console.example.com/",
    "https://console.example.com.attacker.example",
    "null",
    undefined,
  ])
    expect(exactBrowserOrigin(value, env)).toBe(false);
  const f = fixture();
  expect((await login(f.app, "https://attacker.example")).status).toBe(403);
  expect(f.admission).not.toHaveBeenCalled();
  const response = await login(f.app);
  expect(response.status).toBe(200);
  expect(f.admission).toHaveBeenCalledWith("unverified", "admin");
  const cookie = response.headers.get("set-cookie")!;
  expect(cookie).toContain("cindertrace_session=");
  for (const flag of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"])
    expect(cookie).toContain(flag);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(f.audit.mock.calls.flat().join(" ")).not.toContain(
    "obviously-fake-password",
  );
});
it("denies invalid credentials and admission outages without creating a session", async () => {
  const f = fixture();
  expect((await login(f.app, undefined, "wrong")).status).toBe(401);
  expect(f.create).not.toHaveBeenCalled();
  expect(f.release).toHaveBeenCalledOnce();
  f.admission.mockRejectedValueOnce(Error("Private Redis diagnostics"));
  const result = await login(f.app);
  expect(result.status).toBe(503);
  expect(await result.text()).not.toContain("Private");
  expect(f.create).not.toHaveBeenCalled();
});
it("does not clear a cookie when durable revocation fails, and rejects an oversized streamed body", async () => {
  const f = fixture();
  f.verify.mockResolvedValue({
    username: "admin",
    sessionId: "synthetic-id",
    role: "ADMIN",
  });
  f.revoke.mockRejectedValueOnce(Error("unavailable"));
  const result = await f.app.request("/auth/logout", {
    method: "POST",
    headers: {
      Origin: env.DASHBOARD_PUBLIC_ORIGIN,
      Cookie: "cindertrace_session=obviously-fake-session",
    },
  });
  expect(result.status).toBe(503);
  expect(result.headers.get("set-cookie")).toBeNull();
  const oversized = await f.app.request("/auth/login", {
    method: "POST",
    headers: { Origin: env.DASHBOARD_PUBLIC_ORIGIN },
    body: "a".repeat(4097),
  });
  expect(oversized.status).toBe(413);
  expect(f.admission).not.toHaveBeenCalled();
});
it("preserves durable rate and concurrency protections and fails closed on storage outage", async () => {
  vi.stubEnv("SESSION_SECRET", "s".repeat(64));
  const store = {
      eval: vi
        .fn()
        .mockResolvedValueOnce(1)
        .mockResolvedValueOnce([2, 2, 6])
        .mockResolvedValueOnce(0),
      del: vi.fn().mockResolvedValue(1),
    },
    sleep = vi.fn().mockResolvedValue(undefined);
  const begin = createAuthProtection(store, sleep);
  const permit = await begin("198.51.100.1", "Admin");
  expect(permit.allowed).toBe(false);
  expect(permit.retryAfterSeconds).toBe(900);
  expect(sleep).toHaveBeenCalledWith(4000);
  await permit.release();
  expect(store.eval).toHaveBeenCalledTimes(3);
  const broken = createAuthProtection(
    { eval: vi.fn().mockRejectedValue(Error("offline")), del: vi.fn() },
    sleep,
  );
  await expect(broken("source", "user")).rejects.toThrow();
});
