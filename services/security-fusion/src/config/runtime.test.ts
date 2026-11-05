import { expect, it } from "vitest";
import { validateRuntimeConfig } from "./runtime.js";
const core = {
  DATABASE_URL: "postgresql://fixture@localhost/cindertrace_test_core",
  REDIS_URL: "redis://localhost:6379",
  SECURITY_CONSOLE_TOKEN_SECRET: "fixture-console-secret-".repeat(3),
  AUDIT_HMAC_SECRET: "fixture-audit-secret-".repeat(3),
};
it("starts the security core without Magnus, Hive, or node credentials", () => {
  expect(() => validateRuntimeConfig(core)).not.toThrow();
});
it("requires only the secrets belonging to enabled write and ingestion capabilities", () => {
  expect(() =>
    validateRuntimeConfig({ ...core, SECURITY_WRITES_ENABLED: "true" }),
  ).toThrow("receipt signing key");
  expect(() =>
    validateRuntimeConfig({ ...core, SECURITY_INGEST_ENABLED: "true" }),
  ).toThrow("collector credentials");
  expect(() =>
    validateRuntimeConfig({
      ...core,
      SECURITY_WRITES_ENABLED: "false",
      SECURITY_INGEST_ENABLED: "false",
    }),
  ).not.toThrow();
});
it("refuses execution configuration without a complete dedicated bridge", () => {
  expect(() =>
    validateRuntimeConfig({ ...core, SECURITY_DISPATCH_ENABLED: "true" }),
  ).toThrow(/bridge/);
  expect(() =>
    validateRuntimeConfig({
      ...core,
      MAGNUS_RESPONSE_URL: "https://magnus.example.com/response",
    }),
  ).toThrow(/together/);
});
it("rejects secret reuse across browser, audit, and execution purposes", () => {
  expect(() =>
    validateRuntimeConfig({
      ...core,
      MAGNUS_RESPONSE_URL: "https://magnus.example.com/response",
      MAGNUS_RESPONSE_SECRET: core.SECURITY_CONSOLE_TOKEN_SECRET,
    }),
  ).toThrow(/distinct/);
});
it("accepts only exact relaxed authentication limit values", () => {
  for (const value of [undefined, "", "true", "false"])
    expect(() =>
      validateRuntimeConfig({ ...core, RELAX_AUTH_LIMITS: value }),
    ).not.toThrow();
  for (const value of ["yes", "1", "TRUE"])
    expect(() =>
      validateRuntimeConfig({ ...core, RELAX_AUTH_LIMITS: value }),
    ).toThrow("RELAX_AUTH_LIMITS");
});
