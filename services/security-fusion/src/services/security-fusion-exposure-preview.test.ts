import { describe, expect, it, vi } from 'vitest';

const writes = vi.fn(() => { throw new Error('preview attempted a database transaction'); });
const db = {
  securityFusionCase: { findUnique: vi.fn(async () => ({ id: 'case-1', status: 'open', severity: 'high', confidence: 0.8, lastSeenAt: new Date('2026-09-28T00:00:00Z') })) },
  securityFusionCaseEvent: { findMany: vi.fn(async () => []) },
  securityFusionCaseEntity: { findMany: vi.fn(async () => []) },
  securityFusionAction: { findMany: vi.fn(async () => []) },
  securityFusionSourceState: { findMany: vi.fn(async () => []) },
  securityFusionEvent: { findMany: vi.fn(async () => []) },
  securityFusionEntity: { findMany: vi.fn(async () => []) },
  securityFusionEventEntity: { findMany: vi.fn(async () => []) },
  securityTarget: { findMany: vi.fn(async () => [{ id: 'node-1', name: 'table', hostname: 'table.example',
    tags: '[]', metadata: '{"services":["affected.service"]}', syncedAt: new Date() }]) },
  $transaction: writes,
};
vi.mock('../db/index.js', () => ({ getDb: () => db }));

import { digest, previewExposureAssessment } from './security-fusion-assurance.js';

describe('read-only exposure preview', () => {
  it('returns the owning assessment and digests without appending an assurance revision or case activity', async () => {
    const input = { advisory: { id: 'CVE-2026-1234', title: 'Dated publisher notice', severity: 'high',
      publishedAt: '2026-09-27T00:00:00Z', sha256: 'a'.repeat(64), evidence: [{ source: 'publisher',
        reference: 'https://publisher.example/advisory', sha256: 'b'.repeat(64), observedAt: '2026-09-27T01:00:00Z' }] },
    selectors: { hostnames: [], serviceNames: ['affected'], tags: [], metadataEquals: {} } };
    const result = await previewExposureAssessment('case-1', input);
    expect(result).toMatchObject({ caseId: 'case-1', persisted: false, packet: {
      kind: 'exposure', counts: { affected: 1, notAffected: 0, unknown: 0 },
      systems: [{ nodeId: 'node-1', conclusion: 'affected', actualSeverity: 'high' }] } });
    expect(result.inputSha256).toBe(digest(input));
    expect(result.packetSha256).toBe(digest(result.packet));
    expect(writes).not.toHaveBeenCalled();
    expect(db.securityTarget.findMany).toHaveBeenCalledWith({ orderBy: { id: 'asc' }, take: 501 });
  });
});
