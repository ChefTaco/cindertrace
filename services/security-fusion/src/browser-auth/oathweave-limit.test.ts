import { expect, it, vi } from "vitest";

const limiter = vi.hoisted(() => vi.fn());
vi.mock("../middleware/rate-limit.js", () => ({
  rateLimitMiddleware: (options: { max: number }) => {
    limiter(options.max);
    return async (_c: unknown, next: () => Promise<void>) => next();
  },
}));
const { oathweaveBrowserRouter } = await import("./oathweave-routes.js");

it("raises the sign-in exchange limit only when relaxed", () => {
  oathweaveBrowserRouter({ env: {} });
  expect(limiter).toHaveBeenLastCalledWith(30);
  oathweaveBrowserRouter({ env: { RELAX_AUTH_LIMITS: "false" } });
  expect(limiter).toHaveBeenLastCalledWith(30);
  oathweaveBrowserRouter({ env: { RELAX_AUTH_LIMITS: "true" } });
  expect(limiter).toHaveBeenLastCalledWith(10_000);
});
