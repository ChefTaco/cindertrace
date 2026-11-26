import { getDb } from "../db/index.js";
import { auditCommitted } from "./audit-service.js";
import { securityFusionActionSources } from "./security-fusion-actions.js";

/** Lifetime of a preview and of an approval request (the preview's own expiresAt). */
export const ACTION_APPROVAL_TTL_MS = 10 * 60_000;
export const SYSTEM_ACTOR = "system:cindertrace";
const SWEEP_BATCH = 100;

type Db = ReturnType<typeof getDb>;
type Tx = Parameters<Parameters<Db["$transaction"]>[0]>[0];
type Cancelled = { id: string; caseId: string; from: string };

/**
 * Move one unexecuted action to `cancelled` with its approval row and a case activity in
 * one transaction. Returns null when the action is not (or no longer) cancellable.
 */
async function cancelInTransaction(
  tx: Tx,
  actionId: string,
  reason: "cancelled" | "expired",
  actorId: string,
  now: Date,
): Promise<Cancelled | null> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`cindertrace-approval:${actionId}`}, 0))`;
  const action = await tx.securityFusionAction.findUnique({ where: { id: actionId } });
  const sources: readonly string[] = securityFusionActionSources("cancelled");
  if (!action || !sources.includes(action.status)) return null;
  if (reason === "expired" && !expired(action, now)) return null;
  const from = action.status;
  const moved = await tx.securityFusionAction.updateMany({
    where: { id: actionId, status: from },
    data: { status: "cancelled", approvalTokenHash: null },
  });
  if (moved.count !== 1) return null;
  await tx.securityFusionActionApproval.updateMany({
    where: { actionId, status: "pending" },
    data: { status: reason, decidedAt: now },
  });
  await tx.securityFusionCaseActivity.create({
    data: {
      caseId: action.caseId,
      kind: `containment.${reason}`,
      actorId,
      detailJson: JSON.stringify({ actionId, from }),
    },
  });
  return { id: actionId, caseId: action.caseId, from };
}

function expired(
  action: { status: string; createdAt: Date; approvalExpiresAt: Date | null },
  now: Date,
): boolean {
  if (action.status === "pending_approval")
    return (action.approvalExpiresAt?.getTime() ?? action.createdAt.getTime() + ACTION_APPROVAL_TTL_MS) <= now.getTime();
  return action.status === "previewed" && action.createdAt.getTime() + ACTION_APPROVAL_TTL_MS <= now.getTime();
}

async function audit(row: Cancelled, reason: "cancelled" | "expired", actorId: string) {
  await auditCommitted({
    action: `security_fusion.action.${reason === "expired" ? "expire" : "cancel"}`,
    actorId,
    targetType: "security-action",
    targetId: row.id,
    details: { caseId: row.caseId, from: row.from },
  });
}

/** Operator cancellation: atomic state change, then the audit entry. */
export async function cancelSecurityFusionAction(
  actionId: string,
  actorId: string,
  now = new Date(),
): Promise<Cancelled | null> {
  const row = await getDb().$transaction((tx) =>
    cancelInTransaction(tx, actionId, "cancelled", actorId, now),
  );
  if (row) await audit(row, "cancelled", actorId);
  return row;
}

/**
 * Cancel previews and approval requests whose ten-minute lifetime has passed. Nothing in
 * these states has been sent to Magnus, so cancelling cannot lose an execution; it
 * stops abandoned plans from lingering (and from blocking an upgrade).
 */
export async function expireStaleSecurityFusionActions(now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - ACTION_APPROVAL_TTL_MS);
  const stale = await getDb().securityFusionAction.findMany({
    where: {
      OR: [
        { status: "pending_approval", approvalExpiresAt: { lte: now } },
        { status: "pending_approval", approvalExpiresAt: null, createdAt: { lte: cutoff } },
        { status: "previewed", createdAt: { lte: cutoff } },
      ],
    },
    select: { id: true },
    orderBy: { createdAt: "asc" },
    take: SWEEP_BATCH,
  });
  let count = 0;
  for (const { id } of stale) {
    const row = await getDb().$transaction((tx) =>
      cancelInTransaction(tx, id, "expired", SYSTEM_ACTOR, now),
    );
    if (!row) continue;
    count++;
    await audit(row, "expired", SYSTEM_ACTOR).catch(() =>
      console.error("[cindertrace] audit append failed for an expired action"),
    );
  }
  return count;
}
