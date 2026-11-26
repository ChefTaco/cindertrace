-- Additive: what the last poll of a source read (suite audit exports report it).
ALTER TABLE "security_fusion_source_state" ADD COLUMN "lastPollAt" TIMESTAMP(3);
ALTER TABLE "security_fusion_source_state" ADD COLUMN "lastPollRecords" INTEGER;
ALTER TABLE "security_fusion_source_state" ADD COLUMN "lastPollPages" INTEGER;
