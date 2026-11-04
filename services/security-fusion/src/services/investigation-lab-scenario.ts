/** Server-only scenario and rubric. Never import into the console or contracts. */
import { securityFusionEventSchema, type LabAssessment, type LabEvaluation } from '@cindertrace/contracts';
import { canonicalJson, sha256 } from './security-fusion-service.js';

const definitions = [
  { key: 'failures', stage: 1, kind: 'endpoint.authentication.failure', summary: 'Twelve failed logins for the application account from the automation runner.', attributes: { failedAttempts: 12, origin: 'runner.example.com', account: 'operator@example.com', session: 'automation-retries', firstMinute: 0, lastMinute: 2 } },
  { key: 'change', stage: 2, kind: 'endpoint.authentication.change_record', summary: 'Approved automation change CHG-104 left a stale credential reference. Its retries match the failed login times and runner.', attributes: { changeId: 'CHG-104', approved: true, origin: 'runner.example.com', session: 'automation-retries', retryMinutes: [0, 1, 2], scope: 'Automation retries only; does not establish account safety.' } },
  { key: 'session', stage: 3, kind: 'endpoint.authentication.success', summary: 'A separate successful session used the same application account from an unrecognized device.', attributes: { account: 'operator@example.com', session: 'interactive-9', origin: 'unrecognized-device.example.com', automation: false } },
  { key: 'privilege', stage: 3, kind: 'endpoint.session.privilege_change', summary: 'Session interactive-9 added an administrator grant outside approved changes. The account owner denies initiating it.', attributes: { session: 'interactive-9', approved: false, ownerConfirmedUnauthorized: true, change: 'administrator grant added' } },
  { key: 'egress', stage: 3, kind: 'endpoint.session.outbound', summary: 'Session interactive-9 initiated outbound transfer to an unapproved destination from the application host.', attributes: { session: 'interactive-9', destination: 'transfer.example.net', approved: false, bytes: 48000000, contentKnown: false } },
] as const;
export const LAB_SCENARIO_SHA256 = sha256(canonicalJson({ version: 1, definitions }));
const rubric = {
  failures_observed: ['failures'], automation_explains_failures: ['failures', 'change'],
  account_compromised: ['session', 'privilege'], all_activity_benign: [],
  unauthorized_privilege_change: ['session', 'privilege'], suspicious_egress: ['session', 'egress'],
} satisfies Record<LabAssessment['assertions'][number]['claimId'], readonly string[]>;
export const LAB_RUBRIC_SHA256 = sha256(canonicalJson({ version: 1, rubric, containment: 'stage3-session-privilege-egress-matching-target', benignClaimUnsupported: true }));
export const stageTitles = ['Suspicious login', 'Benign explanation', 'Corroborating activity'] as const;
const labels: Record<LabAssessment['assertions'][number]['claimId'], string> = {
  failures_observed: 'Repeated authentication failures occurred',
  automation_explains_failures: 'Approved automation explains the failed logins',
  account_compromised: 'The application account is compromised',
  all_activity_benign: 'All account activity is benign',
  unauthorized_privilege_change: 'An unauthorized privilege change occurred',
  suspicious_egress: 'The separate session performed suspicious outbound activity',
};
export function labClaims(stage: number) {
  return Object.entries(labels).filter(([id]) => stage >= 3 || !['unauthorized_privilege_change', 'suspicious_egress'].includes(id))
    .filter(([id]) => stage >= 2 || id !== 'automation_explains_failures')
    .map(([id, label]) => ({ id: id as keyof typeof labels, label }));
}
export function labTargets(runId: string) {
  return [
    { id: `lab:${runId}:host`, type: 'host' as const, label: 'app-1.example.com' },
    { id: `lab:${runId}:account`, type: 'account' as const, label: 'operator@example.com' },
  ];
}
export function labEvents(runId: string, stage: number, startedAt: Date) {
  return definitions.filter(x => x.stage === stage).map((item, index) => {
    const eventId = `lab:${runId}:${item.key}`;
    return securityFusionEventSchema.parse({
      schemaVersion: '1.0', eventId, sourceEventId: eventId, source: 'wazuh', kind: item.kind,
      observedAt: new Date(startedAt.getTime() + (stage * 3 + index - 12) * 60000).toISOString(),
      severity: stage === 2 ? 'info' : 'high', confidence: 0.94, summary: item.summary,
      entities: labTargets(runId).map(target => ({ type: target.type, value: target.id, label: target.label })),
      attributes: { ...item.attributes, synthetic: true, labRunId: runId }, evidence: [],
    });
  });
}
export function evaluateLab(assessment: LabAssessment, previousConfidence: number | null): LabEvaluation {
  const has = (ids: string[], keys: readonly string[]) => keys.length > 0 && keys.every(key => definitions.find(x => x.key === key)!.stage <= assessment.stage && ids.includes(`lab:${assessment.runId}:${key}`));
  const asserted = assessment.assertions.filter(x => x.disposition === 'asserted');
  const unsupportedClaims = asserted.filter(x => !has(x.evidenceIds, rubric[x.claimId])).map(x => ({
    claimId: x.claimId,
    reason: x.claimId === 'all_activity_benign' ? 'Explaining retries does not establish that all account activity is benign.' : 'The cited released evidence does not establish this assertion.',
  }));
  const available = Object.values(rubric).filter(keys => keys.length > 0 && keys.every(key => definitions.find(x => x.key === key)!.stage <= assessment.stage)).length;
  const containment = assessment.containment;
  const matchingTarget = containment.targetId === `lab:${assessment.runId}:${containment.kind === 'host_isolation' ? 'host' : 'account'}`;
  const justified = assessment.stage === 3 && matchingTarget && has(containment.evidenceIds, containment.kind === 'host_isolation' ? ['session', 'privilege', 'egress'] : ['session', 'privilege']);
  return {
    assertedCount: asserted.length, supportedCount: asserted.length - unsupportedClaims.length, unsupportedClaims,
    tentativeCount: assessment.assertions.filter(x => x.disposition === 'hypothesis').length,
    retractedCount: assessment.assertions.filter(x => x.disposition === 'retracted').length,
    coverage: { supported: asserted.length - unsupportedClaims.length, available },
    containment: { unnecessary: containment.kind !== 'none' && !justified,
      reason: containment.kind === 'none' ? (assessment.stage === 3 ? 'No containment requested; corroboration now supports a scoped response review.' : 'Containment deferred while compromise remains uncorroborated.') : justified ? 'Corroborating session activity supports review of this scoped response.' : 'Containment lacks corroborating citations or targets the wrong entity for this effect.' },
    confidenceDelta: previousConfidence === null ? null : assessment.compromiseConfidence - previousConfidence,
  };
}
export const labTeachingNotes = [
  'Failed logins establish an observation, not successful compromise. Keep operational explanations open.',
  'The approved automation record explains those retries. It neither explains another session nor proves the account safe.',
  'The separate session, unauthorized grant and outbound activity corroborate compromise. The outbound record does not prove what data was transferred.',
  'Judge each revision using evidence available then. A later compromise does not retroactively justify early containment.',
  'Confidence values are investigator judgments. Only structured assertions and containment choices are scored; prose is unscored.',
];
