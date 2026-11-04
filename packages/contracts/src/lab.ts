import { z } from 'zod';

const identity = z.string().min(1).max(160);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
export const labClaimSchema = z.enum([
  'failures_observed', 'automation_explains_failures', 'account_compromised',
  'all_activity_benign', 'unauthorized_privilege_change', 'suspicious_egress',
]);
export const labStageSchema = z.number().int().min(1).max(3);
export const labContainmentSchema = z.object({
  kind: z.enum(['none', 'host_isolation', 'credential_rotation']),
  targetId: z.string().max(160),
  evidenceIds: z.array(identity).max(10),
  rationale: z.string().min(1).max(1200),
}).strict();
export const labAssessmentSchema = z.object({
  runId: identity,
  stage: labStageSchema,
  previousRevision: z.number().int().min(0),
  evidenceSha256: digest,
  compromiseConfidence: z.number().min(0).max(100),
  confidenceRationale: z.string().min(1).max(2000),
  assertions: z.array(z.object({
    claimId: labClaimSchema,
    disposition: z.enum(['asserted', 'hypothesis', 'retracted']),
    evidenceIds: z.array(identity).max(10),
  }).strict()).max(6).refine(items => new Set(items.map(x => x.claimId)).size === items.length, 'Duplicate claim'),
  containment: labContainmentSchema,
}).strict();
export const labTransitionSchema = z.object({ stage: labStageSchema, evidenceSha256: digest }).strict();
export const labDecisionSchema = z.object({
  decision: z.enum(['approve', 'reject']), confirmed: z.literal(true), planSha256: digest,
}).strict();
export const labEvaluationSchema = z.object({
  assertedCount: z.number().int(), supportedCount: z.number().int(),
  tentativeCount: z.number().int(), retractedCount: z.number().int(),
  unsupportedClaims: z.array(z.object({ claimId: labClaimSchema, reason: z.string() })),
  coverage: z.object({ supported: z.number().int(), available: z.number().int() }),
  containment: z.object({ unnecessary: z.boolean(), reason: z.string() }),
  confidenceDelta: z.number().nullable(),
});
export const labCheckpointSchema = z.object({
  investigationId: identity, revision: z.number().int(), stage: labStageSchema,
  authorId: z.string(), createdAt: z.string(), evidenceSha256: digest,
  evidenceIds: z.array(identity), assessment: labAssessmentSchema, evaluation: labEvaluationSchema.nullable(),
});
export const labSimulationPlanSchema = z.object({
  simulated: z.literal(true), runId: identity, stage: labStageSchema,
  revision: z.number().int(), evidenceSha256: digest,
  containment: labContainmentSchema, expiresAt: z.string(),
  effect: z.string(), risk: z.literal('high'), rollback: z.string(),
});
export const labSimulationSchema = z.object({
  id: identity, status: z.enum(['pending', 'approved_simulated', 'rejected', 'invalidated', 'expired']),
  planSha256: digest, plan: labSimulationPlanSchema, decidedBy: z.string().nullable(),
});
export const labRunSchema = z.object({
  id: identity, caseId: identity, status: z.enum(['active', 'completed', 'abandoned']),
  stage: labStageSchema, scenarioVersion: z.literal(1), rubricVersion: z.literal(1),
  scenarioSha256: digest, rubricSha256: digest, createdAt: z.string(),
  stageTitle: z.string(), evidenceSha256: digest,
  events: z.array(z.object({
    id: identity, kind: z.string(), summary: z.string(), observedAt: z.string(),
    attributes: z.record(z.string(), z.unknown()),
  })),
  targets: z.array(z.object({ id: identity, type: z.enum(['host', 'account']), label: z.string() })),
  claims: z.array(z.object({ id: labClaimSchema, label: z.string() })),
  latestRevision: z.number().int(), checkpoints: z.array(labCheckpointSchema),
  simulations: z.array(labSimulationSchema), canAdmin: z.boolean(),
});
export const labComparisonSchema = z.object({
  runId: identity, rubricVersion: z.literal(1), checkpoints: z.array(labCheckpointSchema),
  deltas: z.array(z.object({ revision: z.number().int(), unsupportedClaims: z.number().int(), unnecessaryContainment: z.number().int() })),
  teachingNotes: z.array(z.string()),
});
export type LabAssessment = z.infer<typeof labAssessmentSchema>;
export type LabEvaluation = z.infer<typeof labEvaluationSchema>;
export type LabRun = z.infer<typeof labRunSchema>;
export type LabComparison = z.infer<typeof labComparisonSchema>;
export type LabCheckpoint = z.infer<typeof labCheckpointSchema>;
export type LabSimulation = z.infer<typeof labSimulationSchema>;
export type LabTransition = z.infer<typeof labTransitionSchema>;
export type LabDecision = z.infer<typeof labDecisionSchema>;

export const labStatusSchema = z.object({
  enabled: z.boolean(), canAdmin: z.boolean(),
  runs: z.array(z.object({id: identity, caseId: identity, status: z.enum(['active', 'completed', 'abandoned']), stage: labStageSchema, createdAt: z.string()})).max(100),
});
export type LabStatus = z.infer<typeof labStatusSchema>;
