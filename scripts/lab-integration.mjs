// Real database/API regression coverage. Never run against operational data.
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SignJWT } from 'jose';
const database = process.env.CINDERTRACE_TEST_DATABASE_URL ?? '';
if (!/^cindertrace_test_lab_[a-z0-9_]+$/.test(new URL(database).pathname.slice(1))) throw new Error('A disposable cindertrace_test_lab_* database is required');
process.env.DATABASE_URL = database;
const state = '/state/lab-integration-' + randomUUID();
mkdirSync(state, {recursive: true, mode: 0o700});
Object.assign(process.env, {CINDERTRACE_LAB_ENABLED: 'true', SECURITY_WRITES_ENABLED: 'true', SECURITY_INGEST_ENABLED: 'false', SECURITY_DISPATCH_ENABLED: 'false', SECURITY_NOTIFICATIONS_ENABLED: 'false', SECURITY_FUSION_EVIDENCE_DIR: state + '/evidence', AUDIT_LOG_DIR: state + '/audit', SECURITY_FUSION_RECEIPT_CHAIN_EXPORT: state + '/receipts.jsonl'});
writeFileSync(state + '/receipts.jsonl', '', {mode: 0o600});
const root = resolve(import.meta.dirname, '..');
execFileSync(process.execPath, ['scripts/apply-migrations.mjs'], {cwd: resolve(root, 'services/security-fusion'), stdio: 'pipe'});
const read = randomBytes(32).toString('hex'), draftToken = randomBytes(32).toString('hex'), control = randomBytes(32).toString('hex');
const hash = value => createHash('sha256').update(value).digest('hex');
Object.assign(process.env, {SECURITY_PLUGIN_READ_DIGESTS_JSON: JSON.stringify({fixture: hash(read)}), SECURITY_PLUGIN_DRAFT_TOKEN_SHA256: hash(draftToken), SECURITY_PLUGIN_LAB_CONTROL_TOKEN_SHA256: hash(control)});
const {app} = await import('../services/security-fusion/dist/server.js');
const {getDb, disconnectDb} = await import('../services/security-fusion/dist/db/index.js');
const {CindertraceClient} = await import('../packages/integrations/dist/index.js');
const db = getDb();
const jwt = role => new SignJWT({userId: 'fixture-' + role.toLowerCase(), role}).setProtectedHeader({alg: 'HS256'}).setIssuer('cindertrace-console').setAudience('cindertrace-api').setIssuedAt().setExpirationTime('60s').sign(new TextEncoder().encode(process.env.SECURITY_CONSOLE_TOKEN_SECRET));
const admin = await jwt('ADMIN'), operator = await jwt('OPERATOR'), viewer = await jwt('VIEWER');
const request = (path, method = 'GET', body, token = admin) => app.request('/api/v1/security-fusion' + path, {method, headers: {authorization: 'Bearer ' + token, 'content-type': 'application/json'}, ...(body === undefined ? {} : {body: JSON.stringify(body)})});
let checks = 0;
async function expectStatus(path, method, body, token, status) { const response = await request(path, method, body, token); assert.equal(response.status, status, `${method} ${path}: ${await response.clone().text()}`); checks++; return response; }
const client = new CindertraceClient({url: 'https://fixture.example.com', readToken: read, draftToken, labControlToken: control, fetchImpl: (url, init) => app.request(new URL(url).pathname, init)});
try {
  await db.securityFusionReceiptChainHead.upsert({where: {id: 'security-fusion'}, create: {id: 'security-fusion', chainSequence: 0}, update: {}});
  await expectStatus('/lab', 'GET', undefined, viewer, 403);
  await expectStatus('/lab/runs', 'POST', {}, operator, 403);
  await expectStatus('/lab/runs', 'POST', {}, read, 403);
  await expectStatus('/lab/runs', 'POST', {}, control, 403);
  const started = (await (await expectStatus('/lab/runs', 'POST', {}, admin, 201)).json()).data;
  const again = (await (await request('/lab/runs', 'POST', {})).json()).data;
  assert.equal(started.id, again.id);
  const id = started.id;
  let run = await client.labRun(id);
  assert.equal(run.events.length, 1);
  assert(!JSON.stringify(run).includes('interactive-9'));
  await expectStatus(`/lab/runs/${id}/comparison`, 'GET', undefined, read, 409);
  const transition = () => ({stage: run.stage, evidenceSha256: run.evidenceSha256});
  await expectStatus(`/lab/runs/${id}/advance`, 'POST', transition(), control, 409);
  const draft = (changes = {}) => ({summary: 'Synthetic investigator reasoning.', hypotheses: ['Credential abuse or expected automation'], prioritizedChecks: ['Verify the session origin'], proposedActions: [], evidenceSteps: [], lab: {runId: id, stage: run.stage, previousRevision: run.latestRevision, evidenceSha256: run.evidenceSha256, compromiseConfidence: 65, confidenceRationale: 'Suspicious failures need corroboration.', assertions: [{claimId: 'account_compromised', disposition: 'asserted', evidenceIds: [run.events[0].id]}], containment: {kind: 'none', targetId: '', evidenceIds: [], rationale: 'Investigate first.'}, ...changes}});
  await expectStatus(`/cases/${run.caseId}/investigations`, 'POST', {...draft(), lab: undefined}, draftToken, 400);
  await expectStatus(`/cases/${run.caseId}/investigations`, 'POST', draft({assertions: [{claimId: 'account_compromised', disposition: 'asserted', evidenceIds: [`lab:${id}:privilege`]}]}), draftToken, 400);
  await expectStatus(`/cases/${run.caseId}/investigations`, 'POST', draft({assertions: [{claimId: 'account_compromised', disposition: 'asserted', evidenceIds: ['another-run-event']}]}), draftToken, 400);
  const early = {kind: 'host_isolation', targetId: run.targets[0].id, evidenceIds: [run.events[0].id], rationale: 'Synthetic premature containment proposal.'};
  const submitted = draft({containment: early});
  const races = await Promise.all([request(`/cases/${run.caseId}/investigations`, 'POST', submitted, draftToken), request(`/cases/${run.caseId}/investigations`, 'POST', submitted, draftToken)]);
  assert.deepEqual(races.map(x => x.status).sort(), [201, 409]); checks++;
  run = await client.labRun(id);
  assert.equal(run.checkpoints.length, 1);
  assert.equal(run.checkpoints[0].evaluation, null);
  let sim = run.simulations.at(-1);
  const decisionPath = () => `/lab/runs/${id}/simulations/${sim.id}/decision`;
  const decision = () => ({decision: 'approve', confirmed: true, planSha256: sim.planSha256});
  for (const token of [operator, read, draftToken, control]) await expectStatus(decisionPath(), 'POST', decision(), token, 403);
  await expectStatus(decisionPath(), 'POST', {...decision(), planSha256: '0'.repeat(64)}, admin, 409);
  await expectStatus(decisionPath(), 'POST', decision(), admin, 200);
  await expectStatus(decisionPath(), 'POST', decision(), admin, 409);
  await client.draftInvestigation(run.caseId, draft({containment: early})); run = await client.labRun(id); sim = run.simulations.at(-1);
  await db.securityFusionLabSimulation.update({where: {id: sim.id}, data: {expiresAt: new Date(Date.now() - 1000)}});
  await expectStatus(decisionPath(), 'POST', decision(), admin, 409);
  await client.draftInvestigation(run.caseId, draft({containment: early})); run = await client.labRun(id); sim = run.simulations.at(-1);
  await client.draftInvestigation(run.caseId, draft()); run = await client.labRun(id);
  await expectStatus(decisionPath(), 'POST', decision(), admin, 409);
  const old = transition();
  const advances = await Promise.all([client.advanceLab(id, old), client.advanceLab(id, old)]);
  assert.equal(advances.length, 2); checks++;
  run = await client.labRun(id); assert.equal(run.stage, 2); assert.equal(run.events.length, 2);
  await expectStatus(`/lab/runs/${id}/advance`, 'POST', {...old, evidenceSha256: '0'.repeat(64)}, control, 409);
  const stale = draft({previousRevision: 0}); await expectStatus(`/cases/${run.caseId}/investigations`, 'POST', stale, draftToken, 409);
  await client.draftInvestigation(run.caseId, draft({compromiseConfidence: 20, confidenceRationale: 'The approved change explains retries, but not all possible account activity.', assertions: [
    {claimId: 'automation_explains_failures', disposition: 'asserted', evidenceIds: run.events.map(x => x.id)},
    {claimId: 'account_compromised', disposition: 'retracted', evidenceIds: run.events.map(x => x.id)},
  ]})); run = await client.labRun(id);
  // Inject a mid-release storage failure: both observations and stage must roll back.
  let writes = 0;
  // A PostgreSQL trigger also covers the transaction client used by the service.
  await db.$executeRawUnsafe(`CREATE FUNCTION lab_fixture_interrupt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind = 'endpoint.session.privilege_change' THEN RAISE EXCEPTION 'fixture interrupted release'; END IF; RETURN NEW; END $$`);
  await db.$executeRawUnsafe(`CREATE TRIGGER lab_fixture_interrupt BEFORE INSERT ON security_fusion_events FOR EACH ROW EXECUTE FUNCTION lab_fixture_interrupt()`);
  try { await expectStatus(`/lab/runs/${id}/advance`, 'POST', transition(), control, 500); writes = await db.securityFusionEvent.count({where: {collectorId: `lab:${id}`}}); }
  finally { await db.$executeRawUnsafe('DROP TRIGGER lab_fixture_interrupt ON security_fusion_events'); await db.$executeRawUnsafe('DROP FUNCTION lab_fixture_interrupt()'); }
  assert.equal(writes, 2); assert.equal((await client.labRun(id)).stage, 2); checks++;
  await client.advanceLab(id, transition()); run = await client.labRun(id);
  assert.equal(run.events.length, 5); assert.equal(run.stage, 3);
  await expectStatus(`/lab/runs/${id}/complete`, 'POST', transition(), control, 409);
  const finalEvidence = run.events.filter(x => ['endpoint.authentication.success', 'endpoint.session.privilege_change', 'endpoint.session.outbound'].includes(x.kind)).map(x => x.id);
  await client.draftInvestigation(run.caseId, draft({compromiseConfidence: 90, confidenceRationale: 'The separate session and unauthorized grant corroborate compromise independently of the explained retries.', assertions: [
    {claimId: 'account_compromised', disposition: 'asserted', evidenceIds: finalEvidence},
    {claimId: 'unauthorized_privilege_change', disposition: 'asserted', evidenceIds: finalEvidence},
    {claimId: 'suspicious_egress', disposition: 'asserted', evidenceIds: finalEvidence},
  ], containment: {...early, evidenceIds: finalEvidence, rationale: 'Review isolation of the affected host based on the separate session activity.'}})); run = await client.labRun(id); sim = run.simulations.at(-1);
  const decisionRaces = await Promise.all([request(decisionPath(), 'POST', decision()), request(decisionPath(), 'POST', decision())]);
  assert.deepEqual(decisionRaces.map(x => x.status).sort(), [200, 409]); checks++;
  await client.completeLab(id, transition()); await client.completeLab(id, transition());
  const comparison = await client.compareLab(id);
  assert.equal(comparison.checkpoints[0].evaluation.unsupportedClaims.length, 1);
  assert.equal(comparison.checkpoints[0].evaluation.containment.unnecessary, true);
  assert.equal(comparison.checkpoints.at(-1).evaluation.unsupportedClaims.length, 0);
  assert.equal(comparison.checkpoints.at(-1).evaluation.containment.unnecessary, false);
  assert.equal(comparison.checkpoints.at(-2).evaluation.confidenceDelta, -45);
  assert.equal(comparison.checkpoints.at(-1).evaluation.confidenceDelta, 70);
  assert.equal(await db.securityFusionCommandOutbox.count(), 0); assert.equal(await db.securityFusionAction.count(), 0); assert.equal(await db.securityFusionSourceState.count(), 0); checks += 7;
  const detail = (await (await request(`/cases/${run.caseId}`)).json()).data;
  assert.equal(detail.labRunId, id);
  await expectStatus(`/cases/${run.caseId}/evidence/${run.events[0].id}/preserve`, 'POST', undefined, operator, 201);
  await expectStatus(`/cases/${run.caseId}/investigations`, 'POST', draft(), draftToken, 409);
  const restarted = (await (await expectStatus(`/lab/runs/${id}/restart`, 'POST', {}, admin, 201)).json()).data;
  assert.notEqual(restarted.id, id); assert.equal((await client.labRun(id)).status, 'completed');
  assert.equal((await client.labRun(restarted.id)).events.length, 1);
  const legacy = await db.securityFusionCase.create({data: {fingerprint: randomUUID(), title: 'Synthetic legacy case', severity: 'low', confidence: 0.5, summary: 'Fixture', firstSeenAt: new Date(), lastSeenAt: new Date()}});
  const {lab: _lab, ...legacyDraft} = draft();
  await expectStatus(`/cases/${legacy.id}/investigations`, 'POST', legacyDraft, draftToken, 201);
  if (process.env.CINDERTRACE_LAB_RECOVERY_TEST === 'true') {
    execFileSync(process.execPath, ['scripts/recovery-integration.mjs'], {
      cwd: root, encoding: 'utf8', stdio: 'pipe',
      env: {...process.env, CINDERTRACE_RECOVERY_TEST_CONFIRM: 'disposable-installation'},
    });
    checks++;
  }
  process.env.CINDERTRACE_LAB_ENABLED = 'false';
  await expectStatus(`/lab/runs/${id}`, 'GET', undefined, read, 404);
  assert.equal((await (await request('/lab')).json()).data.enabled, false);
  console.log(JSON.stringify({labIntegration: 'passed', checks, revisions: comparison.checkpoints.length, releasedEvents: 5, zeroDispatch: true, unchangedSourceHealth: true}));
} finally {
  await disconnectDb();
  const {closeRateLimitRedis} = await import('../services/security-fusion/dist/middleware/rate-limit.js');
  await closeRateLimitRedis();
}
