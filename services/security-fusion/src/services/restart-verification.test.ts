import { afterEach, beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  health: vi.fn(),
  update: vi.fn(),
  activity: vi.fn(),
  action: {} as any,
}));
vi.mock("./targets.js", () => ({
  agentHealth: mocks.health,
  validateActionTarget: vi.fn(),
}));
vi.mock("../db/index.js", () => ({
  getDb: () => ({
    securityFusionAction: {
      findMany: async () => [mocks.action],
      updateMany: mocks.update,
    },
    securityExecution: {
      findUnique: async () => ({
        id: "command",
        completedAt: new Date("2026-09-17T10:00:00Z"),
      }),
    },
    securityTarget: {
      findUniqueOrThrow: async () => ({ baseUrl: "https://node" }),
    },
    $transaction: async (f: any) =>
      f({
        securityFusionAction: { updateMany: mocks.update },
        securityFusionCaseActivity: { create: mocks.activity },
      }),
  }),
}));
import { reconcileRestartVerification } from "./security-fusion-outbox.js";
beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-09-17T10:05:00Z"));
  mocks.action = {
    id: "action",
    nodeId: "node",
    caseId: "case",
    serviceName: "nginx.service",
    verificationDeadline: new Date("2026-09-17T10:03:00Z"),
  };
  mocks.update.mockResolvedValue({ count: 1 });
});
afterEach(() => vi.useRealTimers());
it("succeeds after five minutes of verifier downtime when service is active", async () => {
  mocks.health.mockResolvedValue({
    services: [{ name: "nginx", status: "active" }],
  });
  await reconcileRestartVerification();
  expect(mocks.health).toHaveBeenCalledOnce();
  expect(mocks.update).toHaveBeenCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({ status: "succeeded" }),
    }),
  );
});
it.each(["inactive", "unreachable"])(
  "records verification_timeout for %s after deadline",
  async (mode) => {
    if (mode === "unreachable")
      mocks.health.mockRejectedValue(new Error("offline"));
    else
      mocks.health.mockResolvedValue({
        services: [{ name: "nginx", status: mode }],
      });
    await reconcileRestartVerification();
    expect(
      JSON.parse(mocks.update.mock.calls[0]![0].data.resultJson).reason,
    ).toBe("verification_timeout");
    expect(
      JSON.parse(mocks.activity.mock.calls[0]![0].data.detailJson).reason,
    ).toBe("verification_timeout");
  },
);
it("keeps verifying before the durable deadline", async () => {
  vi.setSystemTime(new Date("2026-09-17T10:01:00Z"));
  mocks.health.mockResolvedValue({ services: [] });
  await reconcileRestartVerification();
  expect(mocks.update).not.toHaveBeenCalled();
});
