import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
const db = {
  securityFusionCommandOutbox: {
    findMany: vi.fn(),
    updateMany: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(),
  },
  securityFusionAction: {
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
  },
  securityFusionApprovalDecision: { findUnique: vi.fn() },
  securityFusionActionApproval: { findUnique: vi.fn() },
  securityExecution: { create: vi.fn(), updateMany: vi.fn() },
  securityFusionCaseActivity: { create: vi.fn() },
  $transaction: vi.fn(),
};
let actionFixture: any;
let decisionFixture: any;
let approvalFixture: any;
vi.mock("../db/index.js", () => ({ getDb: () => db }));
vi.mock("./targets.js", () => ({
  validateActionTarget: vi
    .fn()
    .mockResolvedValue({ id: "n", baseUrl: "https://node.example:4100" }),
  agentHealth: vi.fn(),
}));
import { dispatchSecurityFusionOutbox } from "./security-fusion-outbox.js";
import { createContainmentPlan } from "./senti-containment-approval.js";
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv("SECURITY_DISPATCH_ENABLED", "true");
  vi.stubEnv("SECURITY_WRITES_ENABLED", "true");
  vi.stubEnv(
    "MAGNUS_RESPONSE_URL",
    "https://magnus.example.com/api/v1/security-integration/response",
  );
  vi.stubEnv("MAGNUS_RESPONSE_SECRET", "test-bridge-secret-".repeat(3));
  db.$transaction.mockImplementation(async (f) => f(db));
  db.securityFusionCommandOutbox.updateMany.mockResolvedValue({ count: 1 });
  db.securityFusionAction.findMany.mockResolvedValue([]);
  actionFixture = {
    id: "a",
    caseId: "c",
    nodeId: "n",
    kind: "service_restart",
    serviceName: "fixture.service",
    isolationMinutes: null,
    rationale: "bounded fixture",
    rollbackPlan: "restore and verify",
    previewSha256: "c".repeat(64),
    status: "dispatch_pending",
    approvalExpiresAt: new Date(Date.now() + 10 * 60_000),
    approvedBy: "telegram:" + "a".repeat(64),
  };
  const plan = createContainmentPlan(
    actionFixture,
    actionFixture.approvalExpiresAt,
  );
  const { plan_sha256: planSha256, ...storedPlan } = plan;
  db.securityFusionAction.findUnique.mockImplementation(
    async () => actionFixture,
  );
  decisionFixture = {
    id: "decision-1",
    actorId: actionFixture.approvedBy,
    previewSha256: actionFixture.previewSha256,
    assertionVersion: 2,
    decision: "approve",
    proposalId: "containment:a",
    proposalRevision: 1,
    executionId: "00000000-0000-4000-8000-000000000001",
    planSha256,
    actorBindingSha256: "a".repeat(64),
    decidedAt: new Date(Date.now() - 1000),
    expiresAt: new Date(Date.now() + 5 * 60_000),
  };
  db.securityFusionApprovalDecision.findUnique.mockImplementation(
    async () => decisionFixture,
  );
  approvalFixture = {
    actionId: "a",
    previewSha256: actionFixture.previewSha256,
    planRevision: 1,
    planJson: JSON.stringify(storedPlan),
    status: "approved",
    planSha256,
    expiresAt: actionFixture.approvalExpiresAt,
  };
  db.securityFusionActionApproval.findUnique.mockImplementation(
    async () => approvalFixture,
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});
describe("one-shot dispatch", () => {
  it("marks ambiguous network completion unknown and does not retry", async () => {
    const row = {
      id: "o",
      actionId: "a",
      operation: "execute",
      actorId: "telegram:" + "a".repeat(64),
      approvalExecutionId: "00000000-0000-4000-8000-000000000001",
      remoteCommandId: "cmd",
    };
    db.securityFusionCommandOutbox.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([row])
      .mockResolvedValue([]);
    db.securityFusionCommandOutbox.findUnique.mockResolvedValue(row);
    const send = vi
      .fn()
      .mockRejectedValue(new Error("socket reset after submission"));
    vi.stubGlobal("fetch", send);
    await dispatchSecurityFusionOutbox();
    await dispatchSecurityFusionOutbox();
    expect(send).toHaveBeenCalledTimes(1);
    expect(db.securityFusionAction.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ status: "unknown" }),
      }),
    );
  });
  it("blocks legacy execute records without a product approval decision", async () => {
    const row = {
      id: "legacy",
      actionId: "a",
      operation: "execute",
      actorId: "admin",
    };
    db.securityFusionCommandOutbox.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([row]);
    db.securityFusionCommandOutbox.findUnique.mockResolvedValue(row);
    db.securityFusionApprovalDecision.findUnique.mockResolvedValue(null);
    const send = vi.fn();
    vi.stubGlobal("fetch", send);
    await dispatchSecurityFusionOutbox();
    expect(send).not.toHaveBeenCalled();
    expect(db.securityFusionCommandOutbox.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: "failed",
          lastError: "Execute blocked: no matching durable approval",
        }),
      }),
    );
  });
  it.each([
    [
      "changed target",
      () => {
        actionFixture = { ...actionFixture, nodeId: "other" };
      },
    ],
    [
      "changed execution binding",
      () => {
        decisionFixture = {
          ...decisionFixture,
          executionId: "other-execution",
        };
      },
    ],
    [
      "expired permission",
      () => {
        decisionFixture = {
          ...decisionFixture,
          decidedAt: new Date(Date.now() - 120000),
          expiresAt: new Date(Date.now() - 60000),
        };
      },
    ],
  ])("blocks execute with %s", async (_label, mutate) => {
    const row = {
      id: "mismatch",
      actionId: "a",
      operation: "execute",
      actorId: "telegram:" + "a".repeat(64),
      approvalExecutionId: "00000000-0000-4000-8000-000000000001",
    };
    mutate();
    db.securityFusionCommandOutbox.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([row]);
    db.securityFusionCommandOutbox.findUnique.mockResolvedValue(row);
    const send = vi.fn();
    vi.stubGlobal("fetch", send);
    await dispatchSecurityFusionOutbox();
    expect(send).not.toHaveBeenCalled();
    expect(db.securityFusionCommandOutbox.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ status: "failed" }),
      }),
    );
  });
  it("preserves unconditional emergency release without an approval decision", async () => {
    const row = {
      id: "release",
      actionId: "a",
      operation: "release",
      actorId: "admin",
    };
    db.securityFusionCommandOutbox.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([row]);
    db.securityFusionCommandOutbox.findUnique.mockResolvedValue(row);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("bounded fixture")),
    );
    await dispatchSecurityFusionOutbox();
    expect(db.securityFusionApprovalDecision.findUnique).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("never resubmits a command when a process died holding a dispatch lease", async () => {
    const row = { id: "o", actionId: "a", remoteCommandId: "cmd" };
    db.securityFusionCommandOutbox.findMany
      .mockResolvedValueOnce([row])
      .mockResolvedValueOnce([]);
    db.securityFusionCommandOutbox.findUnique.mockResolvedValue(row);
    const send = vi.fn();
    vi.stubGlobal("fetch", send);
    await dispatchSecurityFusionOutbox();
    expect(send).not.toHaveBeenCalled();
    expect(db.securityExecution.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ status: "unknown" }),
      }),
    );
  });
});
