import {isRehearsal} from "../config/rehearsal.js";
import { randomUUID } from "node:crypto";
import { magnusRequest, type ResponseRequest } from "@cindertrace/integrations";
import { responseConfigured } from "../config/runtime.js";
import { getDb } from "../db/index.js";
import { validateActionTarget, agentHealth } from "./targets.js";
import { incMetric } from "../routes/metrics.js";
import { validateStoredContainmentPlan } from "./senti-containment-approval.js";

let busy = false;
export async function dispatchSecurityFusionOutbox(): Promise<number> {
  if (
    isRehearsal() || busy ||
    process.env["SECURITY_WRITES_ENABLED"] !== "true" ||
    process.env["SECURITY_DISPATCH_ENABLED"] !== "true" ||
    !responseConfigured()
  )
    return 0;
  busy = true;
  try {
    const db = getDb();
    // A prior process may have died after sending. Never repeat a possibly executed command.
    const expired = await db.securityFusionCommandOutbox.findMany({
      where: { status: "dispatching", leaseExpiresAt: { lt: new Date() } },
    });
    for (const row of expired)
      await finish(
        row.id,
        row.actionId,
        "unknown",
        "Dispatch lease expired; execution may have occurred",
      );
    const rows = await db.securityFusionCommandOutbox.findMany({
      where: { status: "pending" },
      orderBy: { createdAt: "asc" },
      take: 20,
    });
    for (const row of rows) {
      const action = await db.securityFusionAction.findUnique({
        where: { id: row.actionId },
      });
      if (!action) {
        await db.securityFusionCommandOutbox.update({
          where: { id: row.id },
          data: { status: "failed", lastError: "Action missing" },
        });
        continue;
      }
      const [decision, approval] = await Promise.all([
        row.operation === "execute"
          ? db.securityFusionApprovalDecision.findUnique({
              where: { actionId: action.id },
            })
          : Promise.resolve(null),
        row.operation === "execute"
          ? db.securityFusionActionApproval.findUnique({
              where: { actionId: action.id },
            })
          : Promise.resolve(null),
      ]);
      let plan: ReturnType<typeof validateStoredContainmentPlan> | undefined;
      try {
        if (approval) plan = validateStoredContainmentPlan(action, approval);
      } catch {
        /* changed plans stay blocked */
      }
      if (row.operation === "execute") {
        const approved =
          action.status === "dispatch_pending" &&
          decision?.decision === "approve" &&
          Boolean(decision.executionId) &&
          row.approvalExecutionId === decision.executionId &&
          decision.planSha256 === plan?.plan_sha256 &&
          decision.previewSha256 === action.previewSha256 &&
          approval?.status === "approved" &&
          decision.expiresAt.getTime() > Date.now() &&
          decision.decidedAt.getTime() < decision.expiresAt.getTime() &&
          decision.expiresAt.getTime() <= (plan?.expires_at ?? 0) &&
          decision.actorId === action.approvedBy &&
          row.actorId === action.approvedBy;
        if (!approved) {
          await finish(
            row.id,
            row.actionId,
            "failed",
            "Execute blocked: no matching durable approval",
          );
          continue;
        }
      }
      let node;
      try {
        node = await validateActionTarget(action, row.operation === "release");
      } catch {
        await finish(
          row.id,
          row.actionId,
          "failed",
          "Target readiness or policy check failed before dispatch",
        );
        continue;
      }
      const commandId =
        row.operation === "execute" ? decision!.executionId! : randomUUID();
      const claim = await db.$transaction(async (tx) => {
        const changed = await tx.securityFusionCommandOutbox.updateMany({
          where: { id: row.id, status: "pending" },
          data: {
            status: "dispatching",
            remoteCommandId: commandId,
            leaseExpiresAt: new Date(Date.now() + 180000),
            attempts: { increment: 1 },
          },
        });
        if (!changed.count) return false;
        await tx.securityExecution.create({
          data: {
            id: commandId,
            actionId: action.id,
            operation: row.operation,
            nodeId: node.id,
            status: "started",
          },
        });
        await tx.securityFusionAction.update({
          where: { id: action.id },
          data: {
            status: row.operation === "release" ? "releasing" : "executing",
          },
        });
        return true;
      });
      if (!claim) continue;
      try {
        const request: ResponseRequest = {
          version: 1,
          executionId: commandId,
          actionId: action.id,
          caseId: action.caseId,
          operation: row.operation === "release" ? "release" : "execute",
          nodeId: node.id,
          kind: action.kind as ResponseRequest["kind"],
          serviceName: action.serviceName,
          isolationMinutes: action.isolationMinutes,
          previewSha256: action.previewSha256,
          planSha256: plan?.plan_sha256 ?? action.previewSha256,
          approvalId:
            row.operation === "execute" ? decision!.id : `release:${row.id}`,
          approvedBy: row.actorId,
          expiresAt:
            row.operation === "execute"
              ? decision!.expiresAt.getTime()
              : Date.now() + 600000,
        };
        // One POST only. A lost response leaves an unknown effect, never a replay.
        const result = (await magnusRequest("/execute", request)) as {
          commandId: string;
          actionId: string;
          nodeId: string;
          operation: string;
          planSha256: string;
          exitCode: number;
          receiptSha256: string;
        };
        if (
          result.commandId !== commandId ||
          result.actionId !== action.id ||
          result.nodeId !== node.id ||
          result.operation !== row.operation ||
          result.planSha256 !== request.planSha256 ||
          !Number.isInteger(result.exitCode) ||
          !/^[a-f0-9]{64}$/.test(result.receiptSha256)
        )
          throw new Error("Unbound execution receipt");
        const status =
          result.exitCode !== 0
            ? "failed"
            : row.operation === "release"
              ? "released"
              : action.kind === "service_restart"
                ? "verifying"
                : "succeeded";
        await db.$transaction([
          db.securityExecution.update({
            where: { id: commandId },
            data: {
              status: result.exitCode === 0 ? "completed" : "failed",
              completedAt: new Date(),
              resultJson: JSON.stringify(result),
            },
          }),
          db.securityFusionCommandOutbox.update({
            where: { id: row.id },
            data: {
              status: "dispatched",
              dispatchedAt: new Date(),
              leaseExpiresAt: null,
            },
          }),
          db.securityFusionAction.update({
            where: { id: action.id },
            data: {
              status,
              verificationDeadline:
                status === "verifying" ? new Date(Date.now() + 180000) : null,
              resultJson: JSON.stringify({
                commandId,
                exitCode: result.exitCode,
                ...(result.exitCode !== 0
                  ? {
                      reason:
                        action.kind === "service_restart"
                          ? "restart_command_failed"
                          : "command_failed",
                    }
                  : {}),
              }),
            },
          }),
          db.securityFusionCaseActivity.create({
            data: {
              caseId: action.caseId,
              kind: `containment.${status}`,
              actorId: row.actorId,
              detailJson: JSON.stringify({
                actionId: action.id,
                commandId,
                exitCode: result.exitCode,
                ...(result.exitCode !== 0
                  ? {
                      reason:
                        action.kind === "service_restart"
                          ? "restart_command_failed"
                          : "command_failed",
                    }
                  : {}),
              }),
            },
          }),
        ]);
      } catch {
        await finish(
          row.id,
          action.id,
          "unknown",
          "No verified result; execution may have occurred. Review target before a new approval.",
        );
      }
    }
    await reconcileRestartVerification();
    return rows.length;
  } finally {
    busy = false;
  }
}
async function finish(
  outboxId: string,
  actionId: string,
  status: "failed" | "unknown",
  reason: string,
) {
  const db = getDb();
  await db.$transaction(async (tx) => {
    const outbox = await tx.securityFusionCommandOutbox.findUnique({
      where: { id: outboxId },
    });
    const action = await tx.securityFusionAction.findUnique({
      where: { id: actionId },
    });
    if (!outbox || !action) return;
    const updated = await tx.securityFusionCommandOutbox.updateMany({
      where: { id: outboxId, status: { in: ["pending", "dispatching"] } },
      data: { status, lastError: reason, leaseExpiresAt: null },
    });
    if (!updated.count) return;
    await tx.securityFusionAction.update({
      where: { id: actionId },
      data: {
        status,
        resultJson: JSON.stringify({
          reason,
          commandId: outbox.remoteCommandId,
        }),
      },
    });
    if (outbox.remoteCommandId)
      await tx.securityExecution.updateMany({
        where: { id: outbox.remoteCommandId },
        data: { status, resultJson: JSON.stringify({ reason }) },
      });
    await tx.securityFusionCaseActivity.create({
      data: {
        caseId: action.caseId,
        kind: `containment.${status}`,
        actorId: "system:dispatcher",
        detailJson: JSON.stringify({ reason, actionId }),
      },
    });
  });
  incMetric(status === "unknown" ? "unknownOutcomes" : "dispatchFailures");
}
export async function reconcileRestartVerification(): Promise<void> {
  const db = getDb();
  for (const action of await db.securityFusionAction.findMany({
    where: { status: "verifying", kind: "service_restart" },
    take: 100,
  })) {
    const execution = await db.securityExecution.findUnique({
      where: {
        actionId_operation: { actionId: action.id, operation: "execute" },
      },
    });
    let status = "verifying";
    // Always consult current health, even after a verifier outage exceeded the deadline.
    try {
      const node = await db.securityTarget.findUniqueOrThrow({
        where: { id: action.nodeId },
      });
      const health = await agentHealth(node.baseUrl);
      if (
        health.services.some(
          (s) =>
            s.name?.replace(/\.service$/, "") ===
              action.serviceName?.replace(/\.service$/, "") &&
            s.status === "active",
        )
      )
        status = "succeeded";
    } catch {
      /* bounded health failure is evaluated against the persisted deadline */
    }
    if (
      status !== "succeeded" &&
      (!action.verificationDeadline ||
        Date.now() >= action.verificationDeadline.getTime())
    )
      status = "failed";
    const reason =
      status === "failed" ? "verification_timeout" : "service_active";
    if (status !== "verifying")
      await db.$transaction(async (tx) => {
        const changed = await tx.securityFusionAction.updateMany({
          where: { id: action.id, status: "verifying" },
          data: {
            status,
            resultJson: JSON.stringify({
              commandId: execution?.id,
              serviceVerified: status === "succeeded",
              reason,
              verificationDeadline: action.verificationDeadline?.toISOString(),
              verifiedAt: new Date().toISOString(),
            }),
          },
        });
        if (changed.count)
          await tx.securityFusionCaseActivity.create({
            data: {
              caseId: action.caseId,
              kind: `containment.${status}`,
              actorId: "system:verification",
              detailJson: JSON.stringify({
                actionId: action.id,
                reason,
                verificationDeadline:
                  action.verificationDeadline?.toISOString(),
              }),
            },
          });
      });
  }
}
let timer: ReturnType<typeof setInterval> | undefined;
export function startSecurityFusionOutboxDispatcher(): void {
  if(isRehearsal()||timer)return;
  timer = setInterval(() => {
    void dispatchSecurityFusionOutbox().catch(() =>
      incMetric("dispatcherErrors"),
    );
  }, 2000);
  timer.unref();
}
export function stopSecurityFusionOutboxDispatcher(): void {
  if (timer) clearInterval(timer);
  timer=undefined;
}
