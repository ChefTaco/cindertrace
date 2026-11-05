import { expect, it } from "vitest";
import { authLimitsRelaxed, relaxedAuthLimitsWarning } from "./auth-limits.js";

it("is on only for the exact value", () => {
  expect(authLimitsRelaxed({})).toBe(false);
  expect(authLimitsRelaxed({ RELAX_AUTH_LIMITS: "false" })).toBe(false);
  expect(authLimitsRelaxed({ RELAX_AUTH_LIMITS: "yes" })).toBe(false);
  expect(authLimitsRelaxed({ RELAX_AUTH_LIMITS: "true" })).toBe(true);
});

it("names the mode in the startup warning", () => {
  expect(relaxedAuthLimitsWarning()).toContain("RELAX_AUTH_LIMITS=true");
});
