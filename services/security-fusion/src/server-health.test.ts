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
