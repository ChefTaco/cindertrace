import { z } from 'zod';

/** Suite products whose audit Cindertrace pulls from `GET <api>/v1/audit/export`. */
export const hiveAuditProductSchema = z.enum(['hivemem', 'hiveskills', 'ardentstudio', 'embermend']);
export type HiveAuditProduct = z.infer<typeof hiveAuditProductSchema>;

const optionalText = (max: number) => z.string().min(1).max(max).optional();
const scalar = z.union([z.string(), z.number(), z.boolean(), z.null()]);
const MAX_DETAILS_BYTES = 4096;

/**
 * HiveAuditRecord v1, as served by each product's audit export. Unknown fields
 * are stripped so an additive product change does not stop collection.
 */
export const hiveAuditRecordSchema = z.object({
  id: z.string().regex(/^(hivemem|hiveskills|ardentstudio|embermend):audit:[A-Za-z0-9._:-]{1,200}$/),
  product: hiveAuditProductSchema,
  occurredAt: z.string().datetime({ offset: true }),
  action: z.string().max(160).regex(/^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/),
  outcome: z.enum(['success', 'failure']),
  actor: z.object({
    type: z.enum(['user', 'service', 'agent', 'system']),
    id: z.string().min(1).max(512),
    issuer: z.string().max(512).optional(),
    displayName: z.string().max(256).optional(),
  }),
  target: z.object({ type: optionalText(160), id: optionalText(512) }).optional(),
  subject: z.object({
    actorId: optionalText(256),
    agentRef: optionalText(257),
    nodeId: optionalText(128),
  }).optional(),
  details: z.record(z.string(), scalar).default({})
    .refine((details) => new TextEncoder().encode(JSON.stringify(details)).length <= MAX_DETAILS_BYTES, 'details exceed 4 KB'),
}).superRefine((record, context) => {
  if (!record.id.startsWith(`${record.product}:audit:`))
    context.addIssue({ code: 'custom', path: ['id'], message: 'id must start with <product>:audit:' });
});
export type HiveAuditRecord = z.infer<typeof hiveAuditRecordSchema>;

/** One page of `GET <api>/v1/audit/export?after=&limit=`. `nextCursor` is the last record's cursor; `null` only with empty `data` (caught up). */
export const hiveAuditExportPageSchema = z.object({
  data: z.array(z.unknown()).max(200),
  nextCursor: z.string().min(1).max(2000).nullable(),
});
