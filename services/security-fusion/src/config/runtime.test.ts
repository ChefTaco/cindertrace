import { expect, it } from "vitest";
import { validateRuntimeConfig } from "./runtime.js";
const core = {
  DATABASE_URL: "postgresql://fixture@localhost/cindertrace_test_core",
  REDIS_URL: "redis://localhost:6379",
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
      MAGNUS_RESPONSE_SECRET: core.AUDIT_HMAC_SECRET,
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
it("no longer requires the retired console token secret", () => {
  expect(() => validateRuntimeConfig(core)).not.toThrow();
  // Installations that still set it keep starting; the value is ignored.
  expect(() => validateRuntimeConfig({ ...core, SECURITY_CONSOLE_TOKEN_SECRET: "x".repeat(64) })).not.toThrow();
});
it("accepts the new setting names and refuses disagreeing legacy names", () => {
  const browser = {
    ...core,
    CINDERTRACE_BROWSER_AUTH_ENABLED: "true",
    SESSION_SECRET: "fixture-session-secret-".repeat(3),
    CINDERTRACE_ADMIN_USERNAME: "admin",
    CINDERTRACE_ADMIN_PASSWORD: "fixture-password",
  };
  expect(() => validateRuntimeConfig({ ...browser, CINDERTRACE_PUBLIC_ORIGIN: "https://ui.example.com" })).not.toThrow();
  expect(() => validateRuntimeConfig({ ...browser, DASHBOARD_PUBLIC_ORIGIN: "https://ui.example.com" })).not.toThrow();
  expect(() =>
    validateRuntimeConfig({
      ...browser,
      CINDERTRACE_PUBLIC_ORIGIN: "https://ui.example.com",
      DASHBOARD_PUBLIC_ORIGIN: "https://other.example.com",
    }),
  ).toThrow(/disagree/);
});
it("accepts local approval under its new and legacy names only", () => {
  for (const mode of [undefined, "local", "console", "external"])
    expect(() => validateRuntimeConfig({ ...core, SECURITY_APPROVAL_MODE: mode })).not.toThrow();
  expect(() => validateRuntimeConfig({ ...core, SECURITY_APPROVAL_MODE: "externel" })).toThrow(/SECURITY_APPROVAL_MODE/);
});
