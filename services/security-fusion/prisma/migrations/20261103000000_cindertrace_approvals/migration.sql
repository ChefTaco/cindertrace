CREATE TABLE "security_fusion_approval_decisions" (
 "id" TEXT NOT NULL PRIMARY KEY, "actionId" TEXT NOT NULL, "source" TEXT NOT NULL,
 "decision" TEXT NOT NULL, "actorId" TEXT NOT NULL, "planSha256" TEXT NOT NULL,
 "previewSha256" TEXT NOT NULL, "executionId" TEXT, "decidedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "expiresAt" TIMESTAMP(3) NOT NULL
);
CREATE UNIQUE INDEX "security_fusion_approval_decisions_actionId_key" ON "security_fusion_approval_decisions"("actionId");
CREATE UNIQUE INDEX "security_fusion_approval_decisions_executionId_key" ON "security_fusion_approval_decisions"("executionId");
