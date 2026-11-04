import { describe, expect, it } from 'vitest';
import type { LabAssessment } from '@cindertrace/contracts';
import { evaluateLab, labClaims, labEvents } from './investigation-lab-scenario.js';
const runId = 'fixture-run';
const ids = (...keys: string[]) => keys.map(key => `lab:${runId}:${key}`);
const base: LabAssessment = {
  runId, stage: 1, previousRevision: 0, evidenceSha256: 'a'.repeat(64),
  compromiseConfidence: 55, confidenceRationale: 'Failures warrant checking both abuse and automation.',
  assertions: [], containment: {kind: 'none', targetId: '', evidenceIds: [], rationale: 'Investigate first.'},
};
describe('stage-aware fixed lab rubric', () => {
  it('shows empty coverage without rewarding an empty investigation', () => {
    expect(evaluateLab(base, null)).toMatchObject({assertedCount: 0, supportedCount: 0, coverage: {supported: 0, available: 1}, confidenceDelta: null});
  });
  it('scores assertions separately from hypotheses and retractions', () => {
    const result = evaluateLab({...base, assertions: [
      {claimId: 'failures_observed', disposition: 'asserted', evidenceIds: ids('failures')},
      {claimId: 'account_compromised', disposition: 'hypothesis', evidenceIds: ids('failures')},
      {claimId: 'all_activity_benign', disposition: 'retracted', evidenceIds: []},
    ]}, 70);
    expect(result).toMatchObject({assertedCount: 1, supportedCount: 1, tentativeCount: 1, retractedCount: 1, unsupportedClaims: [], confidenceDelta: -15});
  });
  it('does not treat a citation as support merely because it exists', () => {
    expect(evaluateLab({...base, assertions: [{claimId: 'account_compromised', disposition: 'asserted', evidenceIds: ids('failures')}]}, null).unsupportedClaims).toHaveLength(1);
    expect(evaluateLab({...base, assertions: [{claimId: 'account_compromised', disposition: 'asserted', evidenceIds: ids('session', 'privilege')}]}, null).unsupportedClaims).toHaveLength(1);
  });
  it('accepts the benign explanation without concluding all activity is safe', () => {
    const result = evaluateLab({...base, stage: 2, assertions: [
      {claimId: 'automation_explains_failures', disposition: 'asserted', evidenceIds: ids('failures', 'change')},
      {claimId: 'all_activity_benign', disposition: 'asserted', evidenceIds: ids('failures', 'change')},
    ]}, null);
    expect(result.supportedCount).toBe(1);
    expect(result.unsupportedClaims[0]?.claimId).toBe('all_activity_benign');
  });
  it('does not retroactively justify early containment and checks effect-specific scope', () => {
    const containment = {kind: 'host_isolation' as const, targetId: `lab:${runId}:host`, evidenceIds: ids('session', 'privilege', 'egress'), rationale: 'Review scoped isolation.'};
    expect(evaluateLab({...base, containment}, null).containment.unnecessary).toBe(true);
    expect(evaluateLab({...base, stage: 3, containment}, null).containment.unnecessary).toBe(false);
    expect(evaluateLab({...base, stage: 3, containment: {...containment, targetId: `lab:${runId}:account`}}, null).containment.unnecessary).toBe(true);
    expect(evaluateLab({...base, stage: 3, containment: {...containment, evidenceIds: ids('session')}}, null).containment.unnecessary).toBe(true);
    expect(evaluateLab({...base, stage: 3, containment: {...containment, kind: 'credential_rotation', targetId: `lab:${runId}:account`, evidenceIds: ids('session', 'privilege')}}, null).containment.unnecessary).toBe(false);
  });
  it('does not disclose future evidence in the released stage catalogue', () => {
    expect(labEvents(runId, 1, new Date()).map(x => x.eventId)).toEqual(ids('failures'));
    expect(labEvents(runId, 2, new Date()).map(x => x.eventId)).toEqual(ids('change'));
    expect(labClaims(1).map(x => x.id)).not.toContain('suspicious_egress');
    expect(labEvents('another-run', 1, new Date())[0]?.eventId).not.toBe(ids('failures')[0]);
  });
});
