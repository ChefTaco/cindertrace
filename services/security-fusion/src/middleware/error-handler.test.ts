import { Hono } from "hono";
import { afterEach, expect, it, vi } from "vitest";
import { errorHandler, HttpError } from "./error-handler.js";
afterEach(() => vi.restoreAllMocks());
it("does not expose internal exception contents or log credential-bearing query strings", async () => {
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  const app = new Hono();
  app.onError(errorHandler);
  app.get("/test", () => {
    throw new Error("private diagnostic and supplied credential");
  });
  const response = await app.request("/test?token=fixture-sensitive-query");
  expect(response.status).toBe(500);
  expect(await response.json()).toMatchObject({
    error: {
      code: "INTERNAL_ERROR",
      message: "Security service request failed",
    },
  });
  expect(JSON.stringify(log.mock.calls)).not.toMatch(
    /private diagnostic|supplied credential|fixture-sensitive-query/,
  );
});
it("retains actionable bounded policy errors", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const app = new Hono();
  app.onError(errorHandler);
  app.get("/test", () => {
    throw new HttpError(409, "APPROVAL_EXPIRED", "Create a fresh approval");
  });
  const response = await app.request("/test");
  expect(response.status).toBe(409);
  expect(await response.json()).toMatchObject({
    error: { code: "APPROVAL_EXPIRED", message: "Create a fresh approval" },
  });
});
