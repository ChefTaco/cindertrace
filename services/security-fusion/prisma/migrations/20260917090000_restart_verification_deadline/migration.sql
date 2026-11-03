ALTER TABLE "security_fusion_actions" ADD COLUMN "verificationDeadline" TIMESTAMP(3);
UPDATE "security_fusion_actions" a SET "verificationDeadline" = COALESCE(e."completedAt", a."updatedAt") + interval '180 seconds'
FROM "security_executions" e WHERE e."actionId" = a.id AND e.operation = 'execute' AND a.status = 'verifying';
UPDATE "security_fusion_actions" SET "verificationDeadline" = "updatedAt" + interval '180 seconds' WHERE status = 'verifying' AND "verificationDeadline" IS NULL;
