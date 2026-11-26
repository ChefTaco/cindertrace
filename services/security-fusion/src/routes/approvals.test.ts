import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Hono } from "hono";

const state = vi.hoisted(() => ({
  decide: vi.fn(),
  append: vi.fn(),
  dispatch: vi.fn(),
  outboxRow: { status: "pending", remoteCommandId: null as string | null },
  activity: vi.fn(),
  session: { userId: "admin-1", username: "admin", role: "ADMIN", iat: Math.floor(Date.now() / 1000), exp: 0 } as Record<string, unknown>,
}));
vi.mock("../services/approval-decisions.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../services/approval-decisions.js")>()),
  decideAsAdmin: state.decide,
}));
vi.mock("../services/audit-service.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../services/audit-service.js")>();
  return { ...real, logAuditEvent: state.append };
});
vi.mock("../services/security-fusion-outbox.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../services/security-fusion-outbox.js")>()),
  dispatchSecurityFusionOutbox: state.dispatch,
}));
vi.mock("../db/index.js", () => {
  const db = {
    securityFusionAction: {
      findUnique: async () => ({ id: "a1", kind: "host_isolation", caseId: "c1" }),
      updateMany: async () => ({ count: 1 }),
    },
    securityFusionCommandOutbox: {
      create: async () => ({ id: "o1" }),
      findUnique: async () => ({ id: "o1", ...state.outboxRow }),
    },
    securityFusionCaseActivity: { create: state.activity },
  };
  return { getDb: () => ({ ...db, $transaction: (fn: (tx: typeof db) => unknown) => fn(db) }) };
});
vi.mock("../browser-auth/sessions.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../browser-auth/sessions.js")>()),
  browserAuthEnabled: () => true,
  browserSessions: async () => ({ verify: async () => state.session }),
}));
const { securityFusionRouter } = await import("./security-fusion.js");
const { errorHandler } = await import("../middleware/error-handler.js");
const { renderMetrics } = await import("./metrics.js");
const { approvalPolicy, requireDistinctApprover, requireRecentAuthentication } = await import("../config/approval-policy.js");

function post(path: string, body?: unknown) {
  const app = new Hono();
  app.onError(errorHandler);
  app.route("/api/v1/security-fusion", securityFusionRouter);
  return app.request("/api/v1/security-fusion" + path, {
    method: "POST",
    headers: { cookie: "cindertrace_session=s", origin: "https://ui.example.com", "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
}
const exact = { confirmed: true, planSha256: "a".repeat(64), previewSha256: "b".repeat(64) };
beforeEach(() => {
  vi.stubEnv("CINDERTRACE_BROWSER_AUTH_ENABLED", "true");
  vi.stubEnv("CINDERTRACE_PUBLIC_ORIGIN", "https://ui.example.com");
  vi.stubEnv("DASHBOARD_PUBLIC_ORIGIN", "https://ui.example.com");
  state.decide.mockReset().mockResolvedValue({ id: "d1", actionId: "a1", executionId: "e1" });
  state.append.mockReset().mockResolvedValue(undefined);
  state.dispatch.mockReset().mockResolvedValue(0);
  state.activity.mockReset().mockResolvedValue({});
  state.outboxRow = { status: "pending", remoteCommandId: null };
  state.session = { userId: "admin-1", username: "admin", role: "ADMIN", iat: Math.floor(Date.now() / 1000), exp: 0 };
});
afterEach(() => vi.unstubAllEnvs());

it("returns the committed decision when the audit append fails, and counts the failure", async () => {
  state.append.mockRejectedValue(new Error("disk full"));
  const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const before = Number(/security_fusion_audit_append_failures (\d+)/.exec(renderMetrics())?.[1] ?? NaN);
  expect(before).toBeGreaterThanOrEqual(0);
  const response = await post("/actions/a1/approve", exact);
  expect(response.status).toBe(200);
  expect((await response.json()).data.executionId).toBe("e1");
  expect(Number(/security_fusion_audit_append_failures (\d+)/.exec(renderMetrics())![1])).toBe(before + 1);
  expect(errors.mock.calls.join(" ")).toContain("security_fusion.action.admin_approve");
  expect(errors.mock.calls.join(" ")).not.toContain("disk full");
  errors.mockRestore();
});

it("reports the dispatched release command once the dispatcher has run", async () => {
  state.dispatch.mockImplementation(async () => {
    await new Promise((resolve) => setTimeout(resolve, 20));
    state.outboxRow = { status: "dispatched", remoteCommandId: "cmd-7" };
    return 1;
  });
  const response = await post("/actions/a1/release");
  expect(response.status).toBe(202);
  expect((await response.json()).data).toEqual({ id: "a1", status: "releasing", commandId: "cmd-7" });
  expect(JSON.parse(state.activity.mock.calls[0]![0].data.detailJson).commandId).toBe("cmd-7");
});

it("reports a release as pending when the dispatcher does not finish in time", async () => {
  const { settleWithin } = await import("./security-fusion.js");
  const started = Date.now();
  await settleWithin(new Promise(() => undefined), 30);
  expect(Date.now() - started).toBeLessThan(1000);
  await settleWithin(Promise.reject(new Error("bridge down")), 1000);
  state.dispatch.mockRejectedValue(new Error("bridge down"));
  expect((await (await post("/actions/a1/release")).json()).data.status).toBe("release_pending");
});

it("requires a recent sign-in to approve when step-up is configured", async () => {
  vi.stubEnv("SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS", "300");
  state.session = { ...state.session, iat: Math.floor(Date.now() / 1000) - 3600 };
  const stale = await post("/actions/a1/approve", exact);
  expect(stale.status).toBe(401);
  expect((await stale.json()).error.code).toBe("REAUTHENTICATION_REQUIRED");
  expect(state.decide).not.toHaveBeenCalled();
  // Rejecting never needs step-up.
  expect((await post("/actions/a1/reject", exact)).status).toBe(200);
  state.session = { ...state.session, iat: Math.floor(Date.now() / 1000) - 10 };
  expect((await post("/actions/a1/approve", exact)).status).toBe(200);
});

it("validates the approval policy settings and applies the two-person rule", () => {
  expect(approvalPolicy({})).toEqual({ distinctApprover: false });
  expect(approvalPolicy({ SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS: "900", SECURITY_APPROVAL_DISTINCT_APPROVER: "true" }))
    .toEqual({ maxAuthAgeSeconds: 900, distinctApprover: true });
  for (const bad of [{ SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS: "30" }, { SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS: "1h" },
    { SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS: "90000" }, { SECURITY_APPROVAL_DISTINCT_APPROVER: "yes" }])
    expect(() => approvalPolicy(bad)).toThrow();
  const user = { userId: "u", email: "", role: "ADMIN" as const, iat: 0, exp: 0 };
  // An identity without a known sign-in time fails closed.
  expect(() => requireRecentAuthentication(user, { maxAuthAgeSeconds: 60, distinctApprover: false })).toThrow(/Sign in again/);
  expect(() => requireRecentAuthentication(user, { distinctApprover: false })).not.toThrow();
  const policy = { distinctApprover: true };
  expect(() => requireDistinctApprover("u", ["u", "v"], policy)).toThrow(/Another administrator/);
  expect(() => requireDistinctApprover("u", ["v", "w"], policy)).not.toThrow();
  expect(() => requireDistinctApprover("u", ["u"], { distinctApprover: false })).not.toThrow();
});
