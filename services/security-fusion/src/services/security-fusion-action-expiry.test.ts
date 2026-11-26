import { beforeEach, expect, it, vi } from "vitest";

type Row = { id: string; caseId: string; status: string; createdAt: Date; approvalExpiresAt: Date | null };
const state = vi.hoisted(() => ({
  actions: new Map<string, any>(),
  approvals: new Map<string, string>(),
  activity: [] as any[],
  audit: [] as any[],
}));
const db = {
  $executeRaw: vi.fn(async () => 0),
  $transaction: vi.fn(async (fn: (tx: unknown) => unknown) => fn(db)),
  securityFusionAction: {
    findMany: vi.fn(async () => [...state.actions.values()].map((row: Row) => ({ id: row.id }))),
    findUnique: vi.fn(async ({ where }: any) => state.actions.get(where.id) ?? null),
    updateMany: vi.fn(async ({ where, data }: any) => {
      const row = state.actions.get(where.id);
      if (!row || row.status !== where.status) return { count: 0 };
      Object.assign(row, data);
      return { count: 1 };
    }),
  },
  securityFusionActionApproval: {
    updateMany: vi.fn(async ({ where, data }: any) => {
      if (state.approvals.get(where.actionId) !== where.status) return { count: 0 };
      state.approvals.set(where.actionId, data.status);
      return { count: 1 };
    }),
  },
  securityFusionCaseActivity: { create: vi.fn(async ({ data }: any) => state.activity.push(data)) },
};
vi.mock("../db/index.js", () => ({ getDb: () => db }));
vi.mock("./audit-service.js", () => ({ auditCommitted: vi.fn(async (entry: unknown) => state.audit.push(entry)) }));
import {
  ACTION_APPROVAL_TTL_MS,
  cancelSecurityFusionAction,
  expireStaleSecurityFusionActions,
} from "./security-fusion-action-expiry.js";

const now = new Date("2026-11-26T12:00:00Z");
const ago = (ms: number) => new Date(now.getTime() - ms);
function action(id: string, status: string, createdAt: Date, approvalExpiresAt: Date | null = null) {
  state.actions.set(id, { id, caseId: "case-1", status, createdAt, approvalExpiresAt, approvalTokenHash: "h" });
  if (status === "pending_approval") state.approvals.set(id, "pending");
}
beforeEach(() => {
  vi.clearAllMocks();
  state.actions.clear();
  state.approvals.clear();
  state.activity.length = 0;
  state.audit.length = 0;
});

it("cancels lapsed previews and approval requests, and leaves live or executed actions alone", async () => {
  action("old-preview", "previewed", ago(ACTION_APPROVAL_TTL_MS + 1));
  action("new-preview", "previewed", ago(60_000));
  action("lapsed-request", "pending_approval", ago(ACTION_APPROVAL_TTL_MS + 5), ago(1));
  action("live-request", "pending_approval", ago(60_000), new Date(now.getTime() + 60_000));
  action("sent", "dispatch_pending", ago(ACTION_APPROVAL_TTL_MS * 10), ago(ACTION_APPROVAL_TTL_MS * 9));

  expect(await expireStaleSecurityFusionActions(now)).toBe(2);
  const status = (id: string) => state.actions.get(id).status;
  expect(status("old-preview")).toBe("cancelled");
  expect(status("lapsed-request")).toBe("cancelled");
  expect(state.actions.get("lapsed-request").approvalTokenHash).toBeNull();
  expect(state.approvals.get("lapsed-request")).toBe("expired");
  expect([status("new-preview"), status("live-request"), status("sent")]).toEqual([
    "previewed",
    "pending_approval",
    "dispatch_pending",
  ]);
  expect(state.approvals.get("live-request")).toBe("pending");
  expect(state.activity.map((row) => [row.kind, JSON.parse(row.detailJson).actionId])).toEqual([
    ["containment.expired", "old-preview"],
    ["containment.expired", "lapsed-request"],
  ]);
  expect(state.audit.map((row) => row.action)).toEqual([
    "security_fusion.action.expire",
    "security_fusion.action.expire",
  ]);
});

it("cancels by operator atomically with case activity and an audit entry", async () => {
  action("request", "pending_approval", ago(60_000), new Date(now.getTime() + 60_000));
  action("sent", "dispatch_pending", ago(60_000));
  expect(await cancelSecurityFusionAction("request", "operator-1", now)).toMatchObject({ id: "request", from: "pending_approval" });
  expect(state.approvals.get("request")).toBe("cancelled");
  expect(state.activity).toEqual([
    expect.objectContaining({ kind: "containment.cancelled", actorId: "operator-1" }),
  ]);
  expect(state.audit).toEqual([
    expect.objectContaining({ action: "security_fusion.action.cancel", actorId: "operator-1", targetId: "request" }),
  ]);
  expect(db.$transaction).toHaveBeenCalledTimes(1);
  expect(await cancelSecurityFusionAction("sent", "operator-1", now)).toBeNull();
  expect(await cancelSecurityFusionAction("missing", "operator-1", now)).toBeNull();
  expect(state.actions.get("sent").status).toBe("dispatch_pending");
  expect(state.audit).toHaveLength(1);
});
