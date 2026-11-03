-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "security_fusion_events" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "sourceEventId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3) NOT NULL,
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "severity" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "summary" TEXT NOT NULL,
    "attributesJson" TEXT NOT NULL DEFAULT '{}',
    "integritySha256" TEXT NOT NULL,
    "collectorId" TEXT NOT NULL,

    CONSTRAINT "security_fusion_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_entities" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "canonical" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "aliasesJson" TEXT NOT NULL DEFAULT '[]',
    "firstSeenAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_fusion_entities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_event_entities" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,

    CONSTRAINT "security_fusion_event_entities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_entity_aliases" (
    "id" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "canonical" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_fusion_entity_aliases_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_cases" (
    "id" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'new',
    "severity" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "summary" TEXT NOT NULL,
    "recommendedInvestigationJson" TEXT NOT NULL DEFAULT '[]',
    "evidenceStepsJson" TEXT NOT NULL DEFAULT '[]',
    "assignedTo" TEXT,
    "firstSeenAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "resolvedAt" TIMESTAMP(3),
    "archivedAt" TIMESTAMP(3),
    "evidenceAcceptedCount" INTEGER NOT NULL DEFAULT 0,
    "evidenceTruncatedCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_fusion_cases_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_case_events" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL DEFAULT 'builtin-security-fusion',
    "confidenceContribution" DOUBLE PRECISION NOT NULL DEFAULT 0,

    CONSTRAINT "security_fusion_case_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_case_entities" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,

    CONSTRAINT "security_fusion_case_entities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_case_relationships" (
    "id" TEXT NOT NULL,
    "fromCaseId" TEXT NOT NULL,
    "toCaseId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "rationaleJson" TEXT NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_fusion_case_relationships_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_rule_versions" (
    "id" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "definitionJson" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_fusion_rule_versions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_case_activity" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "detailJson" TEXT NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_fusion_case_activity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_evidence" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "eventId" TEXT,
    "sourceLocator" TEXT NOT NULL,
    "mediaType" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "storagePath" TEXT NOT NULL,
    "preservedBy" TEXT NOT NULL,
    "preservedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "byteSize" INTEGER NOT NULL DEFAULT 0,
    "integrityStatus" TEXT NOT NULL DEFAULT 'verified',
    "quarantinedAt" TIMESTAMP(3),
    "quarantineReason" TEXT,

    CONSTRAINT "security_fusion_evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_source_state" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'unknown',
    "checkpoint" TEXT,
    "lastEventAt" TIMESTAMP(3),
    "lastSuccessAt" TIMESTAMP(3),
    "lastErrorAt" TIMESTAMP(3),
    "lastError" TEXT,
    "rejectedCount" INTEGER NOT NULL DEFAULT 0,
    "truncatedCount" INTEGER NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_fusion_source_state_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_deletion_receipts" (
    "id" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceIdHash" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "bytesDeleted" INTEGER NOT NULL DEFAULT 0,
    "detailJson" TEXT NOT NULL DEFAULT '{}',
    "receiptSha256" TEXT NOT NULL,
    "previousReceiptSha256" TEXT,
    "chainSequence" INTEGER NOT NULL,
    "chainVersion" INTEGER NOT NULL DEFAULT 2,
    "deletedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_fusion_deletion_receipts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_receipt_chain_heads" (
    "id" TEXT NOT NULL,
    "headSha256" TEXT,
    "chainSequence" INTEGER NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_fusion_receipt_chain_heads_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_collectors" (
    "id" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "credentialFingerprint" TEXT NOT NULL,
    "allowedSourcesJson" TEXT NOT NULL DEFAULT '[]',
    "schemaVersion" TEXT NOT NULL DEFAULT '1.0',
    "dataClassification" TEXT NOT NULL DEFAULT 'restricted',
    "status" TEXT NOT NULL DEFAULT 'active',
    "lastReceiptAt" TIMESTAMP(3),
    "lastSuccessAt" TIMESTAMP(3),
    "lastErrorAt" TIMESTAMP(3),
    "lastError" TEXT,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_fusion_collectors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_nonces" (
    "nonce" TEXT NOT NULL,
    "collectorId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_fusion_nonces_pkey" PRIMARY KEY ("nonce")
);

-- CreateTable
CREATE TABLE "security_fusion_investigations" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "authorId" TEXT NOT NULL,
    "draftJson" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_fusion_investigations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_actions" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "nodeId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "serviceName" TEXT,
    "isolationMinutes" INTEGER,
    "rationale" TEXT NOT NULL,
    "rollbackPlan" TEXT NOT NULL,
    "previewJson" TEXT NOT NULL,
    "previewSha256" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'previewed',
    "requestedBy" TEXT NOT NULL,
    "approvedBy" TEXT,
    "approvalTokenHash" TEXT,
    "approvalExpiresAt" TIMESTAMP(3),
    "executedAt" TIMESTAMP(3),
    "resultJson" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_fusion_actions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_action_approvals" (
    "id" TEXT NOT NULL,
    "actionId" TEXT NOT NULL,
    "previewSha256" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "requestedBy" TEXT NOT NULL,
    "decidedBy" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "decidedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_fusion_action_approvals_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_command_outbox" (
    "id" TEXT NOT NULL,
    "actionId" TEXT NOT NULL,
    "operation" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "remoteCommandId" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "leaseExpiresAt" TIMESTAMP(3),
    "lastError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "dispatchedAt" TIMESTAMP(3),

    CONSTRAINT "security_fusion_command_outbox_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_fusion_deliveries" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "revisionKey" TEXT NOT NULL,
    "channel" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "externalId" TEXT,
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_fusion_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_targets" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "baseUrl" TEXT NOT NULL,
    "tags" TEXT NOT NULL,
    "metadata" TEXT NOT NULL,
    "syncedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_targets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_executions" (
    "id" TEXT NOT NULL,
    "actionId" TEXT NOT NULL,
    "operation" TEXT NOT NULL,
    "nodeId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "resultJson" TEXT NOT NULL DEFAULT '{}',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "security_executions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_events_eventId_key" ON "security_fusion_events"("eventId");

-- CreateIndex
CREATE INDEX "security_fusion_events_observedAt_idx" ON "security_fusion_events"("observedAt");

-- CreateIndex
CREATE INDEX "security_fusion_events_source_observedAt_idx" ON "security_fusion_events"("source", "observedAt");

-- CreateIndex
CREATE INDEX "security_fusion_events_kind_observedAt_idx" ON "security_fusion_events"("kind", "observedAt");

-- CreateIndex
CREATE INDEX "security_fusion_events_severity_observedAt_idx" ON "security_fusion_events"("severity", "observedAt");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_events_source_sourceEventId_key" ON "security_fusion_events"("source", "sourceEventId");

-- CreateIndex
CREATE INDEX "security_fusion_entities_lastSeenAt_idx" ON "security_fusion_entities"("lastSeenAt");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_entities_type_canonical_key" ON "security_fusion_entities"("type", "canonical");

-- CreateIndex
CREATE INDEX "security_fusion_event_entities_entityId_idx" ON "security_fusion_event_entities"("entityId");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_event_entities_eventId_entityId_key" ON "security_fusion_event_entities"("eventId", "entityId");

-- CreateIndex
CREATE INDEX "security_fusion_entity_aliases_entityId_idx" ON "security_fusion_entity_aliases"("entityId");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_entity_aliases_source_canonical_key" ON "security_fusion_entity_aliases"("source", "canonical");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_cases_fingerprint_key" ON "security_fusion_cases"("fingerprint");

-- CreateIndex
CREATE INDEX "security_fusion_cases_status_severity_lastSeenAt_idx" ON "security_fusion_cases"("status", "severity", "lastSeenAt");

-- CreateIndex
CREATE INDEX "security_fusion_cases_archivedAt_lastSeenAt_idx" ON "security_fusion_cases"("archivedAt", "lastSeenAt");

-- CreateIndex
CREATE INDEX "security_fusion_case_events_eventId_idx" ON "security_fusion_case_events"("eventId");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_case_events_caseId_eventId_key" ON "security_fusion_case_events"("caseId", "eventId");

-- CreateIndex
CREATE INDEX "security_fusion_case_entities_entityId_idx" ON "security_fusion_case_entities"("entityId");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_case_entities_caseId_entityId_key" ON "security_fusion_case_entities"("caseId", "entityId");

-- CreateIndex
CREATE INDEX "security_fusion_case_relationships_toCaseId_idx" ON "security_fusion_case_relationships"("toCaseId");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_case_relationships_fromCaseId_toCaseId_kind_key" ON "security_fusion_case_relationships"("fromCaseId", "toCaseId", "kind");

-- CreateIndex
CREATE INDEX "security_fusion_rule_versions_enabled_idx" ON "security_fusion_rule_versions"("enabled");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_rule_versions_ruleId_version_key" ON "security_fusion_rule_versions"("ruleId", "version");

-- CreateIndex
CREATE INDEX "security_fusion_case_activity_caseId_createdAt_idx" ON "security_fusion_case_activity"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "security_fusion_evidence_caseId_preservedAt_idx" ON "security_fusion_evidence"("caseId", "preservedAt");

-- CreateIndex
CREATE INDEX "security_fusion_evidence_sha256_idx" ON "security_fusion_evidence"("sha256");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_source_state_source_key" ON "security_fusion_source_state"("source");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_deletion_receipts_receiptSha256_key" ON "security_fusion_deletion_receipts"("receiptSha256");

-- CreateIndex
CREATE INDEX "security_fusion_deletion_receipts_resourceType_deletedAt_idx" ON "security_fusion_deletion_receipts"("resourceType", "deletedAt");

-- CreateIndex
CREATE INDEX "security_fusion_deletion_receipts_deletedAt_idx" ON "security_fusion_deletion_receipts"("deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_deletion_receipts_chainSequence_key" ON "security_fusion_deletion_receipts"("chainSequence");

-- CreateIndex
CREATE INDEX "security_fusion_collectors_status_lastReceiptAt_idx" ON "security_fusion_collectors"("status", "lastReceiptAt");

-- CreateIndex
CREATE INDEX "security_fusion_nonces_expiresAt_idx" ON "security_fusion_nonces"("expiresAt");

-- CreateIndex
CREATE INDEX "security_fusion_investigations_caseId_createdAt_idx" ON "security_fusion_investigations"("caseId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_investigations_caseId_revision_key" ON "security_fusion_investigations"("caseId", "revision");

-- CreateIndex
CREATE INDEX "security_fusion_actions_caseId_createdAt_idx" ON "security_fusion_actions"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "security_fusion_actions_status_approvalExpiresAt_idx" ON "security_fusion_actions"("status", "approvalExpiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_action_approvals_actionId_key" ON "security_fusion_action_approvals"("actionId");

-- CreateIndex
CREATE INDEX "security_fusion_action_approvals_expiresAt_idx" ON "security_fusion_action_approvals"("expiresAt");

-- CreateIndex
CREATE INDEX "security_fusion_command_outbox_status_nextAttemptAt_idx" ON "security_fusion_command_outbox"("status", "nextAttemptAt");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_command_outbox_actionId_operation_key" ON "security_fusion_command_outbox"("actionId", "operation");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_command_outbox_remoteCommandId_key" ON "security_fusion_command_outbox"("remoteCommandId");

-- CreateIndex
CREATE UNIQUE INDEX "security_fusion_deliveries_revisionKey_key" ON "security_fusion_deliveries"("revisionKey");

-- CreateIndex
CREATE INDEX "security_fusion_deliveries_caseId_createdAt_idx" ON "security_fusion_deliveries"("caseId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "security_executions_actionId_operation_key" ON "security_executions"("actionId", "operation");
