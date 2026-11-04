CREATE TABLE "security_fusion_lab_runs" (
  "id" TEXT PRIMARY KEY, "caseId" TEXT NOT NULL, "activeSlot" TEXT,
  "status" TEXT NOT NULL DEFAULT 'active', "stage" INTEGER NOT NULL DEFAULT 1,
  "scenarioVersion" INTEGER NOT NULL DEFAULT 1, "rubricVersion" INTEGER NOT NULL DEFAULT 1,
  "scenarioSha256" TEXT NOT NULL, "rubricSha256" TEXT NOT NULL,
  "evidenceSha256" TEXT NOT NULL, "evidenceIdsJson" TEXT NOT NULL DEFAULT '[]',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP, "updatedAt" TIMESTAMP(3) NOT NULL
);
CREATE UNIQUE INDEX "security_fusion_lab_runs_caseId_key" ON "security_fusion_lab_runs"("caseId");
CREATE UNIQUE INDEX "security_fusion_lab_runs_activeSlot_key" ON "security_fusion_lab_runs"("activeSlot");
CREATE TABLE "security_fusion_lab_checkpoints" (
  "id" TEXT PRIMARY KEY, "runId" TEXT NOT NULL, "investigationId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL, "stage" INTEGER NOT NULL, "evidenceSha256" TEXT NOT NULL,
  "evidenceIdsJson" TEXT NOT NULL, "assessmentJson" TEXT NOT NULL, "evaluationJson" TEXT NOT NULL,
  "authorId" TEXT NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX "security_fusion_lab_checkpoints_investigationId_key" ON "security_fusion_lab_checkpoints"("investigationId");
CREATE UNIQUE INDEX "security_fusion_lab_checkpoints_runId_revision_key" ON "security_fusion_lab_checkpoints"("runId", "revision");
CREATE INDEX "security_fusion_lab_checkpoints_runId_stage_idx" ON "security_fusion_lab_checkpoints"("runId", "stage");
CREATE TABLE "security_fusion_lab_simulations" (
  "id" TEXT PRIMARY KEY, "runId" TEXT NOT NULL, "revision" INTEGER NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'pending', "planJson" TEXT NOT NULL, "planSha256" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL, "decidedBy" TEXT, "decidedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "security_fusion_lab_simulations_runId_status_idx" ON "security_fusion_lab_simulations"("runId", "status");
