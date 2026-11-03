ALTER TABLE "security_fusion_action_approvals"
  ADD COLUMN "planRevision" INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN "planJson" TEXT,
  ADD COLUMN "planSha256" TEXT;

ALTER TABLE "security_fusion_command_outbox"
  ADD COLUMN "approvalExecutionId" TEXT;

CREATE TABLE "security_fusion_telegram_decisions" (
  "id" TEXT NOT NULL,
  "decisionId" TEXT NOT NULL,
  "actionId" TEXT NOT NULL,
  "proposalId" TEXT NOT NULL,
  "proposalRevision" INTEGER NOT NULL,
  "assertionVersion" INTEGER NOT NULL,
  "planSha256" TEXT NOT NULL,
  "decision" TEXT NOT NULL,
  "assertionSha256" TEXT NOT NULL,
  "actorBindingSha256" TEXT NOT NULL,
  "executionId" TEXT,
  "decidedAt" TIMESTAMP(3) NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "security_fusion_telegram_decisions_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "security_fusion_telegram_decisions_decisionId_key"
  ON "security_fusion_telegram_decisions"("decisionId");
CREATE UNIQUE INDEX "security_fusion_telegram_decisions_actionId_key"
  ON "security_fusion_telegram_decisions"("actionId");
CREATE UNIQUE INDEX "security_fusion_telegram_decisions_proposalId_key"
  ON "security_fusion_telegram_decisions"("proposalId");
CREATE UNIQUE INDEX "security_fusion_telegram_decisions_executionId_key"
  ON "security_fusion_telegram_decisions"("executionId");
CREATE INDEX "security_fusion_telegram_decisions_expiresAt_idx"
  ON "security_fusion_telegram_decisions"("expiresAt");

-- An execute admitted by the retired console-token path has no Telegram v2
-- decision and must never cross the new boundary after restart. Unknown rows
-- are quarantined as blocked while preserving an explicit warning that they may
-- already have executed; pending rows are blocked before dispatch can restart.
UPDATE "security_fusion_command_outbox"
SET "status" = 'blocked',
    "lastError" = 'Legacy execute quarantined: no durable Telegram v2 decision'
WHERE "operation" = 'execute' AND "status" = 'pending';

UPDATE "security_fusion_command_outbox"
SET "status" = 'blocked',
    "lastError" = 'Legacy unknown execute quarantined: execution may have occurred; do not retry'
WHERE "operation" = 'execute' AND "status" = 'unknown';
