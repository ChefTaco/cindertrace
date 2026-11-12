import { afterEach, expect, it, vi } from "vitest";
import { app } from "./server.js";

afterEach(() => vi.unstubAllEnvs());

it("publishes only a boolean relaxed authentication limits state", async () => {
  const body = async () => (await app.request("/health")).json();
  expect(await body()).toEqual({
    success: true,
    service: "cindertrace-api",
    authLimitsRelaxed: false,
  });
  vi.stubEnv("RELAX_AUTH_LIMITS", "true");
  expect(await body()).toEqual({
    success: true,
    service: "cindertrace-api",
    authLimitsRelaxed: true,
  });
});

it("serves suite-standard liveness without touching dependencies", async () => {
  const response = await app.request("/health/live");
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    status: "live",
    service: "cindertrace-api",
  });
  expect(response.headers.get("cache-control")).toBe("no-store");
});

it("reports readiness per dependency without exposing error text", async () => {
  vi.stubEnv("DATABASE_URL", "");
  vi.stubEnv("REDIS_URL", "");
  const response = await app.request("/health/ready");
  expect([200, 503]).toContain(response.status);
  const body = await response.json();
  expect(Object.keys(body.checks).sort()).toEqual(["database", "redis"]);
  for (const check of Object.values(body.checks) as { error?: string }[])
    if (check.error) expect(["timeout", "failed"]).toContain(check.error);
});

it("echoes a safe inbound request id and generates one otherwise", async () => {
  const echoed = await app.request("/health", {
    headers: { "x-request-id": "synthetic-request-1" },
  });
  expect(echoed.headers.get("x-request-id")).toBe("synthetic-request-1");
  const correlated = await app.request("/health", {
    headers: { "x-correlation-id": "synthetic-correlation-1" },
  });
  expect(correlated.headers.get("x-request-id")).toBe("synthetic-correlation-1");
  const generated = await app.request("/health", {
    headers: { "x-request-id": "unsafe id\twith spaces" },
  });
  expect(generated.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
});

it("keeps the existing error body while echoing the request id", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const response = await app.request("/api/v1/security-fusion/cases", {
    headers: { "x-request-id": "synthetic-request-2" },
  });
  expect(response.headers.get("x-request-id")).toBe("synthetic-request-2");
  expect(response.status).toBe(401);
  expect(await response.json()).toEqual({
    success: false,
    error: { code: "UNAUTHORIZED", message: "Invalid or expired security token" },
  });
});
