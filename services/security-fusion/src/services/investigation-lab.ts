import { randomUUID } from 'node:crypto';
import {
  labAssessmentSchema, labCheckpointSchema, labComparisonSchema, labRunSchema,
  labSimulationPlanSchema, labSimulationSchema,
  type LabDecision, type LabTransition, type SecurityFusionInvestigationDraft,
} from '@cindertrace/contracts';
import { getDb, type Prisma } from '../db/index.js';
import { HttpError } from '../middleware/error-handler.js';
import { sanitizeDetails } from './audit-service.js';
import { canonicalJson, sha256 } from './security-fusion-service.js';
import { evaluateLab, labClaims, labEvents, labTargets, labTeachingNotes, stageTitles, LAB_RUBRIC_SHA256, LAB_SCENARIO_SHA256 } from './investigation-lab-scenario.js';

type Tx = Prisma.TransactionClient;
type Run = Prisma.SecurityFusionLabRunGetPayload<Record<string, never>>;
const conflict = (message: string): never => { throw new HttpError(409, 'LAB_CONFLICT', message); };
export function requireLab() {
  if (process.env['CINDERTRACE_LAB_ENABLED'] !== 'true') throw new HttpError(404, 'NOT_FOUND', 'Lab is not enabled');
}
function pin(run: Run) {
  if (run.scenarioVersion !== 1 || run.rubricVersion !== 1 || run.scenarioSha256 !== LAB_SCENARIO_SHA256 || run.rubricSha256 !== LAB_RUBRIC_SHA256)
    conflict('This run requires its pinned scenario and rubric version.');
}
async function lockCase(tx: Tx, caseId: string) {
  const rows = await tx.$queryRaw<Array<{ id: string }>>`SELECT "id" FROM "security_fusion_cases" WHERE "id" = ${caseId} FOR UPDATE`;
  if (!rows.length) throw new HttpError(404, 'NOT_FOUND', 'Security case not found');
}
async function lockRun(tx: Tx, id: string) {
  const found = await tx.securityFusionLabRun.findUnique({ where: { id } });
  if (!found) throw new HttpError(404, 'NOT_FOUND', 'Lab run not found');
  await lockCase(tx, found.caseId);
  await tx.$queryRaw`SELECT "id" FROM "security_fusion_lab_runs" WHERE "id" = ${id} FOR UPDATE`;
  const run = await tx.securityFusionLabRun.findUniqueOrThrow({ where: { id } });
  pin(run);
  return run;
}
async function invalidate(tx: Tx, runId: string) {
  await tx.securityFusionLabSimulation.updateMany({ where: { runId, status: 'pending' }, data: { status: 'invalidated' } });
}
async function activity(tx: Tx, caseId: string, actorId: string, kind: string, detail: unknown) {
  await tx.securityFusionCaseActivity.create({ data: { caseId, actorId, kind, detailJson: canonicalJson(detail) } });
}
async function releaseStage(tx: Tx, run: Run, stage: number, actorId: string) {
  const ids: string[] = JSON.parse(run.evidenceIdsJson);
  for (const event of labEvents(run.id, stage, run.createdAt)) {
    const attributes = sanitizeDetails(event.attributes);
    await tx.securityFusionEvent.create({ data: {
      id: event.eventId, eventId: event.eventId, source: event.source, sourceEventId: event.sourceEventId,
      collectorId: `lab:${run.id}`, kind: event.kind, observedAt: new Date(event.observedAt),
      severity: event.severity, confidence: event.confidence, summary: event.summary,
      attributesJson: JSON.stringify(attributes), integritySha256: sha256(canonicalJson({ ...event, attributes })),
    } });
    await tx.securityFusionCaseEvent.create({ data: { caseId: run.caseId, eventId: event.eventId, ruleId: 'synthetic-lab-v1', confidenceContribution: event.confidence } });
    for (const target of labTargets(run.id)) {
      await tx.securityFusionEventEntity.create({ data: { eventId: event.eventId, entityId: target.id } });
    }
    ids.push(event.eventId);
  }
  const rows = await tx.securityFusionEvent.findMany({ where: { id: { in: ids } }, orderBy: { id: 'asc' }, select: { id: true, integritySha256: true } });
  const evidenceSha256 = sha256(canonicalJson(rows));
  const updated = await tx.securityFusionLabRun.update({ where: { id: run.id }, data: { stage, evidenceIdsJson: JSON.stringify(ids), evidenceSha256 } });
  await tx.securityFusionCase.update({ where: { id: run.caseId }, data: { lastSeenAt: new Date(), evidenceAcceptedCount: ids.length } });
  await activity(tx, run.caseId, actorId, 'lab.evidence_released', { runId: run.id, stage, evidenceSha256 });
  return updated;
}
async function createRun(tx: Tx, actorId: string) {
  const id = randomUUID(), caseId = `lab-case:${id}`;
  const now = new Date();
  await tx.securityFusionCase.create({ data: { id: caseId, fingerprint: `synthetic-lab:${id}`, title: 'Login investigation · app-1.example.com', summary: 'Synthetic investigation lab. Follow the evidence as it arrives.', severity: 'high', confidence: 0.88, firstSeenAt: now, lastSeenAt: now, recommendedInvestigationJson: JSON.stringify(['Separate observations from hypotheses.', 'Cite evidence and explain changes in confidence.']) } });
  for (const target of labTargets(id)) {
    await tx.securityFusionEntity.create({ data: { id: target.id, type: target.type, canonical: target.id, label: target.label, firstSeenAt: now, lastSeenAt: now } });
    await tx.securityFusionCaseEntity.create({ data: { caseId, entityId: target.id } });
  }
  const run = await tx.securityFusionLabRun.create({ data: { id, caseId, activeSlot: 'active', scenarioSha256: LAB_SCENARIO_SHA256, rubricSha256: LAB_RUBRIC_SHA256, evidenceSha256: sha256('[]') } });
  return releaseStage(tx, run, 1, actorId);
}
export async function startLab(actorId: string, restartId?: string) {
  requireLab();
  return getDb().$transaction(async tx => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(1128877644)`;
    const active = await tx.securityFusionLabRun.findUnique({ where: { activeSlot: 'active' } });
    if (restartId) {
      const prior = await lockRun(tx, restartId);
      if (active && active.id !== prior.id) conflict('Another run is active. Resume that run.');
      await invalidate(tx, prior.id);
      if (prior.status === 'active') {
        await tx.securityFusionLabRun.update({ where: { id: prior.id }, data: { status: 'abandoned', activeSlot: null } });
        await tx.securityFusionCase.update({ where: { id: prior.caseId }, data: { status: 'resolved', resolvedAt: new Date() } });
      }
      await activity(tx, prior.caseId, actorId, 'lab.restarted', { runId: prior.id });
    } else if (active) return { id: active.id, caseId: active.caseId };
    const run = await createRun(tx, actorId);
    return { id: run.id, caseId: run.caseId };
  });
}
export async function listLabRuns() {
  requireLab();
  return getDb().securityFusionLabRun.findMany({ orderBy: { createdAt: 'desc' }, take: 100, select: { id: true, caseId: true, status: true, stage: true, createdAt: true } });
}
export async function readLab(id: string, canAdmin: boolean) {
  requireLab();
  return getDb().$transaction(async tx => {
    const run = await lockRun(tx, id);
    const ids: string[] = JSON.parse(run.evidenceIdsJson);
    const events = await tx.securityFusionEvent.findMany({ where: { id: { in: ids } }, orderBy: { observedAt: 'asc' } });
    const checkpoints = await tx.securityFusionLabCheckpoint.findMany({ where: { runId: id }, orderBy: { revision: 'asc' } });
    const simulations = await tx.securityFusionLabSimulation.findMany({ where: { runId: id }, orderBy: { createdAt: 'asc' } });
    return labRunSchema.parse({ ...run, createdAt: run.createdAt.toISOString(), stageTitle: stageTitles[run.stage - 1],
      events: events.map(row => ({ ...row, observedAt: row.observedAt.toISOString(), attributes: JSON.parse(row.attributesJson) })),
      targets: labTargets(id), claims: labClaims(run.stage), latestRevision: checkpoints.at(-1)?.revision ?? 0,
      checkpoints: checkpoints.map(row => labCheckpointSchema.parse({ ...row, createdAt: row.createdAt.toISOString(), evidenceIds: JSON.parse(row.evidenceIdsJson), assessment: JSON.parse(row.assessmentJson), evaluation: run.status === 'completed' ? JSON.parse(row.evaluationJson) : null })),
      simulations: simulations.map(row => labSimulationSchema.parse({ ...row, status: row.status === 'pending' && row.expiresAt.getTime() <= Date.now() ? 'expired' : row.status, plan: JSON.parse(row.planJson) })), canAdmin,
    });
  });
}
export async function transitionLab(id: string, input: LabTransition, actorId: string, complete: boolean) {
  requireLab();
  return getDb().$transaction(async tx => {
    const run = await lockRun(tx, id);
    // A retry can observe the completed transition but cannot advance again.
    if (complete && run.status === 'completed' && input.stage === 3 && input.evidenceSha256 === run.evidenceSha256) return { id, stage: 3, status: 'completed' };
    if (!complete && run.status === 'active' && run.stage === input.stage + 1) {
      const saved = await tx.securityFusionLabCheckpoint.findFirst({ where: { runId: id, stage: input.stage, evidenceSha256: input.evidenceSha256 } });
      if (saved) return { id, stage: run.stage, status: run.status };
    }
    if (run.status !== 'active' || run.stage !== input.stage || run.evidenceSha256 !== input.evidenceSha256) conflict('Evidence changed. Reload the run before continuing.');
    const saved = await tx.securityFusionLabCheckpoint.findFirst({ where: { runId: id, stage: run.stage, evidenceSha256: run.evidenceSha256 } });
    if (!saved) conflict('Save an investigation revision for the current evidence first.');
    if (complete !== (run.stage === 3)) conflict(run.stage === 3 ? 'Complete the final stage.' : 'Reveal the next stage before completing.');
    await invalidate(tx, id);
    if (complete) {
      await tx.securityFusionLabRun.update({ where: { id }, data: { status: 'completed', activeSlot: null } });
      await tx.securityFusionCase.update({ where: { id: run.caseId }, data: { status: 'resolved', resolvedAt: new Date() } });
      await activity(tx, run.caseId, actorId, 'lab.completed', { runId: id });
      return { id, stage: 3, status: 'completed' };
    }
    const next = await releaseStage(tx, run, run.stage + 1, actorId);
    await invalidate(tx, id);
    return { id, stage: next.stage, status: next.status };
  });
}
export async function saveLabAwareInvestigation(caseId: string, authorId: string, draft: SecurityFusionInvestigationDraft) {
  return getDb().$transaction(async tx => {
    await lockCase(tx, caseId);
    const run = await tx.securityFusionLabRun.findUnique({ where: { caseId } });
    const latest = await tx.securityFusionInvestigation.findFirst({ where: { caseId }, orderBy: { revision: 'desc' } });
    if (!run && draft.lab) throw new HttpError(400, 'VALIDATION_ERROR', 'Lab assessment requires a lab case');
    if (run) {
      requireLab(); pin(run);
      const assessment = draft.lab && labAssessmentSchema.parse(draft.lab);
      if (!assessment) throw new HttpError(400, 'VALIDATION_ERROR', 'This case requires a structured lab assessment');
      if (run.status !== 'active' || assessment.runId !== run.id || assessment.stage !== run.stage || assessment.evidenceSha256 !== run.evidenceSha256 || assessment.previousRevision !== (latest?.revision ?? 0)) conflict('Investigation is stale. Reload the current evidence and revision.');
      const ids: string[] = JSON.parse(run.evidenceIdsJson);
      const citations = [...assessment.assertions.flatMap(x => x.evidenceIds), ...assessment.containment.evidenceIds];
      if (citations.some(id => !ids.includes(id))) throw new HttpError(400, 'INVALID_CITATION', 'Citations must reference released evidence from this run');
      const claims = new Set(labClaims(run.stage).map(x => x.id));
      if (assessment.assertions.some(x => !claims.has(x.claimId))) throw new HttpError(400, 'INVALID_CLAIM', 'Claim is not available at this stage');
      if ((latest?.revision ?? 0) >= 100) conflict('This run has reached its 100 revision limit. Start a fresh run.');
      const previous = latest ? JSON.parse(latest.draftJson) as SecurityFusionInvestigationDraft : undefined;
      const evaluation = evaluateLab(assessment, previous?.lab?.compromiseConfidence ?? null);
      const row = await tx.securityFusionInvestigation.create({ data: { caseId, authorId, revision: (latest?.revision ?? 0) + 1, draftJson: JSON.stringify(draft) } });
      await tx.securityFusionLabCheckpoint.create({ data: { runId: run.id, investigationId: row.id, revision: row.revision, stage: run.stage, evidenceSha256: run.evidenceSha256, evidenceIdsJson: run.evidenceIdsJson, assessmentJson: JSON.stringify(assessment), evaluationJson: JSON.stringify(evaluation), authorId } });
      await invalidate(tx, run.id);
      if (assessment.containment.kind !== 'none') {
        const expiresAt = new Date(Date.now() + 600000);
        const plan = labSimulationPlanSchema.parse({ simulated: true, runId: run.id, stage: run.stage, revision: row.revision, evidenceSha256: run.evidenceSha256, containment: assessment.containment, expiresAt: expiresAt.toISOString(),
          effect: assessment.containment.kind === 'host_isolation' ? 'Simulate 15-minute isolation of the affected host' : 'Simulate rotation of the affected account credential',
          risk: 'high', rollback: 'Simulation only: no host or account changes occur; no rollback is needed'  });
        const planJson = canonicalJson(plan);
        await tx.securityFusionLabSimulation.create({ data: { runId: run.id, revision: row.revision, planJson, planSha256: sha256(planJson), expiresAt } });
      }
      await activity(tx, caseId, authorId, 'lab.investigation_saved', { runId: run.id, revision: row.revision, evidenceSha256: run.evidenceSha256 });
      return row;
    }
    return tx.securityFusionInvestigation.create({ data: { caseId, authorId, revision: (latest?.revision ?? 0) + 1, draftJson: JSON.stringify(draft) } });
  });
}
export async function decideLabSimulation(runId: string, id: string, input: LabDecision, actorId: string) {
  requireLab();
  return getDb().$transaction(async tx => {
    const run = await lockRun(tx, runId);
    const row = await tx.securityFusionLabSimulation.findFirst({ where: { id, runId } });
    if (!row) throw new HttpError(404, 'NOT_FOUND', 'Simulation not found');
    const latest = await tx.securityFusionLabCheckpoint.findFirst({ where: { runId }, orderBy: { revision: 'desc' } });
    if (run.status !== 'active' || row.status !== 'pending' || row.expiresAt.getTime() <= Date.now() || row.revision !== latest?.revision || row.planSha256 !== input.planSha256 || row.planSha256 !== sha256(row.planJson)) conflict('The exact simulated plan is unavailable, changed, consumed or expired.');
    const plan = labSimulationPlanSchema.parse(JSON.parse(row.planJson));
    if (plan.runId !== runId || plan.revision !== row.revision || plan.expiresAt !== row.expiresAt.toISOString() || Date.parse(plan.expiresAt) <= Date.now() || plan.stage !== run.stage || plan.evidenceSha256 !== run.evidenceSha256) conflict('Evidence changed. Request a new simulated plan.');
    const status = input.decision === 'approve' ? 'approved_simulated' : 'rejected';
    const claimed = await tx.securityFusionLabSimulation.updateMany({ where: { id, runId, status: 'pending', expiresAt: { gt: new Date() } }, data: { status, decidedBy: actorId, decidedAt: new Date() } });
    if (claimed.count !== 1) conflict('Simulation has already been decided.');
    await activity(tx, run.caseId, actorId, 'lab.simulation_decided', { runId, id, status, planSha256: input.planSha256, simulated: true });
    return { id, status, simulated: true };
  });
}
export async function compareLab(id: string, canAdmin: boolean) {
  const run = await readLab(id, canAdmin);
  if (run.status !== 'completed') conflict('Complete all three stages to reveal the comparison.');
  return labComparisonSchema.parse({ runId: id, rubricVersion: 1, checkpoints: run.checkpoints,
    deltas: run.checkpoints.map((row, index) => ({ revision: row.revision,
      unsupportedClaims: row.evaluation!.unsupportedClaims.length - (run.checkpoints[index - 1]?.evaluation?.unsupportedClaims.length ?? 0),
      unnecessaryContainment: Number(row.evaluation!.containment.unnecessary) - Number(run.checkpoints[index - 1]?.evaluation?.containment.unnecessary ?? false) })),
    teachingNotes: labTeachingNotes,
  });
}
