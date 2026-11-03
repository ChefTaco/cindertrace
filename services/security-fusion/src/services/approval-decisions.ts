import { randomUUID } from "node:crypto";
import { z } from "zod";
import { getDb } from "../db/index.js";
import { HttpError } from "../middleware/error-handler.js";
import { validateStoredContainmentPlan } from "./senti-containment-approval.js";
import { responseConfigured } from "../config/runtime.js";
export const adminDecisionSchema = z
  .object({
    planSha256: z.string().regex(/^[a-f0-9]{64}$/),
    previewSha256: z.string().regex(/^[a-f0-9]{64}$/),
    confirmed: z.literal(true),
  })
  .strict();
export async function decideAsAdmin(
  actionId: string,
  actorId: string,
  decision: "approve" | "reject",
  raw: unknown,
) {
  if (process.env["SECURITY_APPROVAL_MODE"] === "external")
    throw new HttpError(
      403,
      "EXTERNAL_APPROVAL_REQUIRED",
      "This installation requires its external approval channel",
    );
  if (decision === "approve" && !responseConfigured())
    throw new HttpError(
      503,
      "RESPONSE_UNCONFIGURED",
      "Magnus response is not configured",
    );
  const parsed = adminDecisionSchema.safeParse(raw);
  if (!parsed.success)
    throw new HttpError(
      400,
      "CONFIRMATION_REQUIRED",
      "Confirm the exact plan and preview digests",
    );
  const body = parsed.data;
  return getDb().$transaction(async (db) => {
    await db.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`cindertrace-approval:${actionId}`}, 0))`;
    const [action, approval] = await Promise.all([
      db.securityFusionAction.findUnique({ where: { id: actionId } }),
      db.securityFusionActionApproval.findUnique({ where: { actionId } }),
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
        "APPROVAL_ALREADY_USED",
        "Approval is expired or already handled",
      );
    const plan = validateStoredContainmentPlan(action, approval);
    if (
      plan.plan_sha256 !== body.planSha256 ||
      action.previewSha256 !== body.previewSha256
    )
      throw new HttpError(
        409,
        "APPROVAL_PLAN_CHANGED",
        "Review the exact current response plan",
      );
    const id = randomUUID(),
      executionId = decision === "approve" ? randomUUID() : null;
    const transitioned = await db.securityFusionAction.updateMany({
      where: {
        id: actionId,
        status: "pending_approval",
        previewSha256: body.previewSha256,
        approvalExpiresAt: { gt: new Date() },
      },
      data: {
        status: decision === "approve" ? "dispatch_pending" : "rejected",
        approvedBy: actorId,
        approvalTokenHash: null,
      },
    });
    const consumed = await db.securityFusionActionApproval.updateMany({
      where: {
        actionId,
        status: "pending",
        planSha256: body.planSha256,
        expiresAt: { gt: new Date() },
      },
      data: {
        status: decision === "approve" ? "approved" : "rejected",
        decidedBy: actorId,
        decidedAt: new Date(),
        tokenHash: "",
      },
    });
    if (transitioned.count !== 1 || consumed.count !== 1)
      throw new HttpError(
        409,
        "APPROVAL_ALREADY_USED",
        "Approval was consumed concurrently",
      );
    await db.securityFusionApprovalDecision.create({
      data: {
        id,
        actionId,
        source: "console",
        decision,
        actorId,
        planSha256: body.planSha256,
        previewSha256: body.previewSha256,
        executionId,
        expiresAt: approval.expiresAt,
      },
    });
    await db.securityFusionCaseActivity.create({
      data: {
        caseId: action.caseId,
        kind: `containment.admin_${decision}`,
        actorId,
        detailJson: JSON.stringify({
          decisionId: id,
          planSha256: plan.plan_sha256,
          executionId,
        }),
      },
    });
    if (executionId)
      await db.securityFusionCommandOutbox.create({
        data: {
          actionId,
          operation: "execute",
          actorId,
          approvalExecutionId: executionId,
        },
      });
    return { id, actionId, decision, executionId };
  });
}
