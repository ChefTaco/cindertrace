import { afterEach, expect, it, vi } from "vitest";
import {
  applyRehearsalGuards,
  REHEARSAL_DISABLED_FLAGS,
  securityWritesEnabled,
} from "./rehearsal.js";
import { responseConfigured } from "./runtime.js";
afterEach(() => vi.unstubAllEnvs());
it("forces restored dispatch, retention, ingestion, notifications and writes off for an isolated rehearsal", () => {
  const env: NodeJS.ProcessEnv = {
    HIVE_REHEARSAL: "true",
    MAGNUS_RESPONSE_URL: "https://magnus.example.com",
    MAGNUS_RESPONSE_SECRET: "obviously-fake-long-response-secret",
  };
  for (const name of REHEARSAL_DISABLED_FLAGS) env[name] = "true";
  applyRehearsalGuards(env);
  for (const name of REHEARSAL_DISABLED_FLAGS) expect(env[name]).toBe("false");
  expect(securityWritesEnabled(env)).toBe(false);
  expect(responseConfigured(env)).toBe(false);
  expect(() => applyRehearsalGuards({ HIVE_REHEARSAL: "yes" })).toThrow();
});
it("fences direct dispatcher, inventory and retention entrypoints even when restored enable flags remain true", async () => {
  vi.stubEnv("HIVE_REHEARSAL", "true");
  for (const name of REHEARSAL_DISABLED_FLAGS) vi.stubEnv(name, "true");
  vi.stubEnv("MAGNUS_INVENTORY_URL", "https://magnus.example.com/inventory");
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const {
    dispatchSecurityFusionOutbox,
    startSecurityFusionOutboxDispatcher,
    stopSecurityFusionOutboxDispatcher,
  } = await import("../services/security-fusion-outbox.js");
  const { syncTargets } = await import("../services/targets.js");
  const { startSecurityFusionRetention, stopSecurityFusionRetention } =
    await import("../services/security-fusion-service.js");
  vi.useFakeTimers();
  expect(await dispatchSecurityFusionOutbox()).toBe(0);
  await syncTargets();
  startSecurityFusionOutboxDispatcher();
  startSecurityFusionRetention();
  expect(vi.getTimerCount()).toBe(0);
  expect(fetch).not.toHaveBeenCalled();
  stopSecurityFusionOutboxDispatcher();
  stopSecurityFusionRetention();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
