import { expect, it } from 'vitest';
import { hiveAuditRecordSchema, securityFusionSourceSchema } from './index.js';

const record = {
  id: 'hiveskills:audit:42',
  product: 'hiveskills',
  occurredAt: '2026-11-12T10:00:00Z',
  action: 'release.promote',
  outcome: 'success',
  actor: { type: 'user', id: 'user-1' },
  target: { type: 'skill', id: 'skill-1' },
  subject: {},
  details: { from: 'beta', to: 'stable' },
};

it('adds the suite audit sources', () => {
  for (const source of ['hivemem', 'hiveskills', 'ardentstudio', 'embermend'])
    expect(securityFusionSourceSchema.parse(source)).toBe(source);
});

it('parses HiveAuditRecord v1 and rejects mismatched or oversized records', () => {
  expect(hiveAuditRecordSchema.parse(record)).toEqual(record);
  expect(hiveAuditRecordSchema.safeParse({ ...record, id: 'hivemem:audit:42' }).success).toBe(false);
  expect(hiveAuditRecordSchema.safeParse({ ...record, action: 'Release.Promote' }).success).toBe(false);
  expect(hiveAuditRecordSchema.safeParse({ ...record, details: { nested: { a: 1 } } }).success).toBe(false);
  expect(hiveAuditRecordSchema.safeParse({ ...record, details: { big: 'x'.repeat(4100) } }).success).toBe(false);
  expect(hiveAuditRecordSchema.parse({ ...record, extra: true })).not.toHaveProperty('extra');
});
