import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
const state = vi.hoisted(() => ({
  action: null as any,
  approval: null as any,
  prior: null as any,
  actionUpdates: 0,
  approvalUpdates: 0,
  outboxes: 0,
}));
const db = vi.hoisted(() => ({
  $executeRaw: vi.fn(),
  securityFusionApprovalDecision: { create: vi.fn() },
  securityFusionCaseActivity: { create: vi.fn() },
  securityFusionTelegramDecision: {
    findUnique: vi.fn(async () => state.prior),
    create: vi.fn(async ({ data }: any) => {
      state.prior = data;
      return data;
    }),
  },
  securityFusionAction: {
    findUnique: vi.fn(async () => state.action),
    findMany: vi.fn(),
    updateMany: vi.fn(async () => {
      state.actionUpdates++;
      return { count: 1 };
    }),
  },
  securityFusionActionApproval: {
    findUnique: vi.fn(async () => state.approval),
    findMany: vi.fn(),
    updateMany: vi.fn(async () => {
      state.approvalUpdates++;
      return { count: 1 };
    }),
  },
  securityFusionCommandOutbox: {
    create: vi.fn(async () => {
      state.outboxes++;
      return { id: "outbox-1" };
    }),
  },
  $transaction: vi.fn(async (fn: any) => fn(db)),
}));
vi.mock("../db/index.js", () => ({ getDb: () => db }));
import { approvalPayloadCanonical } from "../security/senti-approval.js";
import {
  createContainmentPlan,
  recordContainmentApproval,
  validateStoredContainmentPlan,
} from "./senti-containment-approval.js";

const actor = "a".repeat(64);
let privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
function assertion(
  plan: ReturnType<typeof createContainmentPlan>,
  decision: "approve" | "reject" = "approve",
) {
  const now = Date.now();
  const payload = {
    version: 2 as const,
    proposal_id: plan.plan_id,
    proposal_revision: plan.revision,
    plan_sha256: plan.plan_sha256,
    decision,
    decision_id: "decision-1",
    decided_at: now,
    expires_at: Math.min(plan.expires_at, now + 60_000),
    actor_binding_sha256: actor,
    execution_id: decision === "approve" ? "execution-1" : null,
  };
  return {
    payload,
    signature: sign(
      null,
      Buffer.from(
        "magnus.senti-approval.v2\n" + approvalPayloadCanonical(payload),
      ),
      privateKey,
    ).toString("base64url"),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  state.prior = null;
  state.actionUpdates = 0;
  state.approvalUpdates = 0;
  state.outboxes = 0;
  const keys = generateKeyPairSync("ed25519");
  privateKey = keys.privateKey;
  vi.stubEnv(
    "SENTI_APPROVAL_PUBLIC_KEY_B64",
    keys.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
  );
  vi.stubEnv("SENTI_TELEGRAM_ACTOR_SHA256", actor);
  state.action = {
    id: "action-1",
    caseId: "case-1",
    nodeId: "node-1",
    kind: "host_isolation",
    serviceName: null,
    isolationMinutes: 15,
    rationale: "active compromise",
    rollbackPlan: "automatic release",
    previewSha256: "c".repeat(64),
    status: "pending_approval",
    approvalExpiresAt: new Date(Date.now() + 300_000),
  };
  const plan = createContainmentPlan(
    state.action,
    state.action.approvalExpiresAt,
  );
  const { plan_sha256, ...view } = plan;
  state.approval = {
    actionId: state.action.id,
    previewSha256: state.action.previewSha256,
    planRevision: 1,
    planJson: JSON.stringify(view),
    planSha256: plan_sha256,
    status: "pending",
    expiresAt: state.action.approvalExpiresAt,
  };
});
afterEach(() => vi.unstubAllEnvs());

describe("Senti containment decision", () => {
  it("binds the exact plan and consumes approval into one outbox operation once", async () => {
    const plan = validateStoredContainmentPlan(state.action, state.approval);
    const signed = assertion(plan);
    const first = await recordContainmentApproval(signed);
    expect(first).toMatchObject({
      decision: "approve",
      execution_id: "execution-1",
      replay: false,
      outbox_id: "outbox-1",
    });
    expect([
      state.actionUpdates,
      state.approvalUpdates,
      state.outboxes,
    ]).toEqual([1, 1, 1]);
    const replay = await recordContainmentApproval(signed);
    expect(replay).toMatchObject({
      replay: true,
      execution_id: "execution-1",
      outbox_id: null,
    });
    expect(state.outboxes).toBe(1);
  });
  it("rejects a changed stored plan before state transition or dispatch", async () => {
    const signed = assertion(
      validateStoredContainmentPlan(state.action, state.approval),
    );
    state.action = { ...state.action, previewSha256: "d".repeat(64) };
    await expect(recordContainmentApproval(signed)).rejects.toThrow(
      "current immutable containment plan",
    );
    expect([
      state.actionUpdates,
      state.approvalUpdates,
      state.outboxes,
    ]).toEqual([0, 0, 0]);
  });
  it("records rejection without creating a dispatch outbox", async () => {
    const result = await recordContainmentApproval(
      assertion(
        validateStoredContainmentPlan(state.action, state.approval),
        "reject",
      ),
    );
    expect(result).toMatchObject({
      decision: "reject",
      execution_id: null,
      outbox_id: null,
    });
    expect(state.outboxes).toBe(0);
  });
});
