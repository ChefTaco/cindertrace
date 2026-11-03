CREATE TABLE "security_fusion_assurance_packets" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "actorId" TEXT NOT NULL,
    "inputSha256" TEXT NOT NULL,
    "caseStateSha256" TEXT NOT NULL,
    "packetJson" TEXT NOT NULL,
    "packetSha256" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "security_fusion_assurance_packets_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "security_fusion_assurance_packets_packetSha256_idx"
ON "security_fusion_assurance_packets"("packetSha256");

CREATE UNIQUE INDEX "security_fusion_assurance_packets_caseId_kind_revision_key"
ON "security_fusion_assurance_packets"("caseId", "kind", "revision");

CREATE INDEX "security_fusion_assurance_packets_caseId_kind_createdAt_idx"
ON "security_fusion_assurance_packets"("caseId", "kind", "createdAt");
