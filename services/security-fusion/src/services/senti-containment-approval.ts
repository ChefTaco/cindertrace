import { randomBytes } from "node:crypto";
import { getDb } from "../db/index.js";
import { HttpError } from "../middleware/error-handler.js";
import {
  approvalDigest,
  requireFreshApproval,
  verifySentiApproval,
} from "../security/senti-approval.js";

type Action = {
  id: string;
  caseId: string;
  nodeId: string;
  kind: string;
  serviceName: string | null;
  isolationMinutes: number | null;
  rationale: string;
  rollbackPlan: string;
  previewSha256: string;
  status: string;
  approvalExpiresAt: Date | null;
};
type Approval = {
  actionId: string;
  previewSha256: string;
  planRevision: number;
  planJson: string | null;
  planSha256: string | null;
  status: string;
  expiresAt: Date;
};

const PLAN_FIELDS = [
  "plan_id",
  "revision",
  "action",
  "targets",
  "steps",
  "risk",
  "rollback",
  "evidence",
  "expires_at",
] as const;

function actionId(planId: string) {
  const match = /^containment:([a-zA-Z0-9][a-zA-Z0-9_-]{0,127})$/.exec(planId);
  if (!match)
    throw new HttpError(
      400,
      "PLAN_TYPE_UNAVAILABLE",
      "Select an existing Security Fusion containment plan",
    );
  return match[1]!;
}

export function createContainmentPlan(action: Action, expiresAt: Date) {
  if (!["service_restart", "host_isolation"].includes(action.kind))
    throw new HttpError(
      409,
      "INVALID_PLAN",
      "Security action is not an approved containment type",
    );
  const operation =
    action.kind === "service_restart"
      ? `Restart allowlisted service ${action.serviceName ?? "(missing)"}`
      : `Isolate the host for ${action.isolationMinutes ?? 15} minutes`;
  if (action.kind === "service_restart" && !action.serviceName)
    throw new HttpError(
      409,
      "INVALID_PLAN",
      "Service restart plan has no service target",
    );
  const view = {
    plan_id: `containment:${action.id}`,
    revision: 1,
    action: `security.containment.${action.kind}`,
    targets: [action.nodeId],
    steps: [
      operation,
      `Scope: node ${action.nodeId}`,
      `Rationale: ${action.rationale}`,
      action.kind === "service_restart"
        ? "Verify service health and a fresh node heartbeat after the one-shot restart."
        : "Verify isolation, retain the automatic release timer, and confirm recovery after release.",
    ],
    risk:
      action.kind === "service_restart"
        ? "The service will be interrupted and in-memory work may be lost. Dependent clients may fail until health returns."
        : "The node will lose ordinary network reachability. Dependent services may be unavailable until automatic release.",
    rollback: action.rollbackPlan,
    evidence: [
      `security-case:${action.caseId}`,
      `security-action:${action.id}`,
      `preview-sha256:${action.previewSha256}`,
    ],
    expires_at: expiresAt.getTime(),
  };
  return { ...view, plan_sha256: approvalDigest(view) };
}

export function validateStoredContainmentPlan(
  action: Action,
  approval: Approval,
) {
  let stored: unknown;
  try {
    stored = approval.planJson ? JSON.parse(approval.planJson) : null;
  } catch {
    throw new HttpError(
      409,
      "INVALID_PLAN",
      "Stored containment plan is invalid",
    );
  }
  const expected = createContainmentPlan(action, approval.expiresAt);
  if (
    !stored ||
    typeof stored !== "object" ||
    Array.isArray(stored) ||
    Object.keys(stored).length !== PLAN_FIELDS.length ||
    PLAN_FIELDS.some(
      (key) => !Object.hasOwn(stored as Record<string, unknown>, key),
    ) ||
    approval.planRevision !== 1 ||
    approval.previewSha256 !== action.previewSha256 ||
    approval.planSha256 !== expected.plan_sha256 ||
    approval.planJson !==
      JSON.stringify(
        Object.fromEntries(PLAN_FIELDS.map((key) => [key, expected[key]])),
      )
  )
    throw new HttpError(
      409,
      "APPROVAL_PLAN_CHANGED",
      "Approval does not match the current immutable containment plan",
    );
  return expected;
}

export async function listContainmentApprovalPlans() {
  const db = getDb();
  const actions = await db.securityFusionAction.findMany({
    where: {
      status: "pending_approval",
      approvalExpiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: "desc" },
    take: 40,
  });
  if (!actions.length) return { plans: [] };
  const approvals = await db.securityFusionActionApproval.findMany({
    where: {
      actionId: { in: actions.map((row) => row.id) },
      status: "pending",
      expiresAt: { gt: new Date() },
    },
  });
  const byAction = new Map(approvals.map((row) => [row.actionId, row]));
  const plans = [];
  for (const action of actions) {
    const approval = byAction.get(action.id);
    if (!approval) continue;
    try {
      plans.push(validateStoredContainmentPlan(action, approval));
    } catch (error) {
      if (!(error instanceof HttpError)) throw error;
    }
    if (plans.length === 20) break;
  }
  return { plans };
}

export async function getContainmentApprovalPlan(planId: string) {
  const id = actionId(planId);
  const [action, approval] = await Promise.all([
    getDb().securityFusionAction.findUnique({ where: { id } }),
    getDb().securityFusionActionApproval.findUnique({
      where: { actionId: id },
    }),
  ]);
  if (!action || !approval)
    throw new HttpError(404, "NOT_FOUND", "Containment plan not found");
  if (action.status !== "pending_approval" || approval.status !== "pending")
    throw new HttpError(
      409,
      "PLAN_ALREADY_HANDLED",
      "Containment plan is no longer awaiting permission",
    );
  if (approval.expiresAt.getTime() <= Date.now())
    throw new HttpError(
      409,
      "PLAN_EXPIRED",
      "Create a fresh containment proposal",
    );
  return validateStoredContainmentPlan(action, approval);
}

export async function recordContainmentApproval(raw: unknown) {
  const { payload: p, assertionSha256 } = verifySentiApproval(raw);
  const id = actionId(p.proposal_id);
  const result = await getDb().$transaction(async (db) => {
    await db.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`senti-containment:${p.proposal_id}`}, 0))`;
    const prior =
      p.version === 4
        ? null
        : await db.securityFusionTelegramDecision.findUnique({
            where: { proposalId: p.proposal_id },
          });
    if (prior) {
      if (
        prior.decisionId !== p.decision_id ||
        prior.assertionSha256 !== assertionSha256
      )
        throw new HttpError(
          409,
          "APPROVAL_CONFLICT",
          "Containment plan already has a different decision",
        );
      return {
        decision_id: prior.decisionId,
        proposal_id: prior.proposalId,
        decision: prior.decision,
        execution_id: prior.executionId,
        accepted: true,
        replay: true,
        outbox_id: null,
      };
    }
    requireFreshApproval(p);
    const [action, approval] = await Promise.all([
      db.securityFusionAction.findUnique({ where: { id } }),
      db.securityFusionActionApproval.findUnique({ where: { actionId: id } }),
    ]);
    if (
      !action ||
      !approval ||
      action.status !== "pending_approval" ||
      approval.status !== "pending" ||
      approval.expiresAt.getTime() <= Date.now()
    )
      throw new HttpError(
        409,
        "PLAN_ALREADY_HANDLED",
        "Containment plan is not awaiting permission",
      );
    const plan = validateStoredContainmentPlan(action, approval);
    if (
      p.proposal_revision !== plan.revision ||
      p.plan_sha256 !== plan.plan_sha256 ||
      p.expires_at > plan.expires_at
    )
      throw new HttpError(
        409,
        "APPROVAL_PLAN_CHANGED",
        "Approval does not match the current immutable containment plan",
      );
    const actor = `${p.version === 4 ? "external" : p.version === 3 ? p.source_channel : "telegram"}:${p.actor_binding_sha256}`;
    const decidedAt = new Date(p.decided_at);
    const nextStatus =
      p.decision === "approve" ? "dispatch_pending" : "rejected";
    const actionTransition = await db.securityFusionAction.updateMany({
      where: {
        id,
        status: "pending_approval",
        previewSha256: action.previewSha256,
        approvalExpiresAt: { gt: new Date() },
      },
      data: {
        status: nextStatus,
        approvedBy: actor,
        approvalTokenHash: null,
        ...(p.decision === "approve" ? { executedAt: decidedAt } : {}),
      },
    });
    const approvalTransition = await db.securityFusionActionApproval.updateMany(
      {
        where: {
          actionId: id,
          status: "pending",
          previewSha256: action.previewSha256,
          planSha256: plan.plan_sha256,
          expiresAt: { gt: new Date() },
        },
        data: {
          status: p.decision === "approve" ? "approved" : "rejected",
          decidedBy: actor,
          decidedAt,
          tokenHash: approvalDigest(randomBytes(32).toString("hex")),
        },
      },
    );
    if (actionTransition.count !== 1 || approvalTransition.count !== 1)
      throw new HttpError(
        409,
        "APPROVAL_ALREADY_USED",
        "Containment permission has already been consumed or changed",
      );
    if (p.version !== 4)
      await db.securityFusionTelegramDecision.create({
        data: {
          decisionId: p.decision_id,
          actionId: id,
          proposalId: p.proposal_id,
          proposalRevision: p.proposal_revision,
          assertionVersion: p.version,
          planSha256: p.plan_sha256,
          decision: p.decision,
          assertionSha256,
          actorBindingSha256: p.actor_binding_sha256,
          executionId: p.execution_id,
          decidedAt,
          expiresAt: new Date(p.expires_at),
        },
      });
    await db.securityFusionApprovalDecision.create({
      data: {
        id: p.decision_id,
        actionId: id,
        source: "external",
        decision: p.decision,
        actorId: actor,
        planSha256: p.plan_sha256,
        previewSha256: action.previewSha256,
        executionId: p.execution_id,
        decidedAt,
        expiresAt: new Date(p.expires_at),
      },
    });
    await db.securityFusionCaseActivity.create({
      data: {
        caseId: action.caseId,
        kind: `containment.external_${p.decision}`,
        actorId: actor,
        detailJson: JSON.stringify({
          decisionId: p.decision_id,
          assertionSha256,
          planSha256: p.plan_sha256,
          executionId: p.execution_id,
        }),
      },
    });
    const outbox =
      p.decision === "approve"
        ? await db.securityFusionCommandOutbox.create({
            data: {
              actionId: id,
              operation: "execute",
              actorId: actor,
              approvalExecutionId: p.execution_id,
            },
          })
        : null;
    return {
      decision_id: p.decision_id,
      proposal_id: p.proposal_id,
      decision: p.decision,
      execution_id: p.execution_id,
      accepted: true,
      replay: false,
      outbox_id: outbox?.id ?? null,
    };
  });
  return result;
}
