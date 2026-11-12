import { z } from 'zod';
import { labAssessmentSchema } from './lab.js';
export * from './lab.js';
export * from './hive-audit.js';

export const securityFusionSourceSchema = z.enum([
  'unifi_dns',
  'unifi_ids',
  'netflow',
  'wazuh',
  'tailscale',
  'magnus',
  'hive',
  'chattermost',
  'magnus_ui',
  'aegis_ui',
  'security_console',
  'cindertrace_ui',
  'mattermost',
  'hivemem',
  'hiveskills',
  'ardentstudio',
  'embermend',
]);
export const securityFusionSeveritySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export const securityFusionEntityTypeSchema = z.enum(['user', 'host', 'device', 'ip', 'service', 'account', 'domain', 'agent']);
export const securityFusionCaseStatusSchema = z.enum([
  'new', 'triage', 'investigating', 'contained', 'monitoring', 'resolved', 'false_positive',
]);

/** HiveMem-format agent (actor) ID. */
export const agentActorIdSchema = z.string().regex(/^[a-z0-9_-]{2,32}$/);
/** Magnus node ID; `~` separates it from the profile in an agent reference. */
export const magnusNodeIdSchema = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/);
/** Ardent profile ID on a Magnus node. */
export const agentProfileIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
/** `<magnusNodeId>~<profile>`. */
export const agentRefSchema = z.string().regex(/^[A-Za-z0-9._-]{1,128}~[A-Za-z0-9_-]{1,64}$/);

export type AgentEntityValue =
  | { kind: 'actor'; actorId: string; value: string }
  | { kind: 'agent-ref'; agentRef: string; nodeId: string; profile: string; value: string }
  | { kind: 'magnus-node'; nodeId: string; value: string };

export const agentEntityValue = {
  actor: (actorId: string) => `actor:${actorId}`,
  agentRef: (agentRef: string) => `agent-ref:${agentRef}`,
  magnusNode: (nodeId: string) => `magnus-node:${nodeId}`,
} as const;

/**
 * Parse an `agent` entity value. The canonical form is `actor:<actorId>`;
 * `agent-ref:<nodeId>~<profile>` and `magnus-node:<nodeId>` are aliases.
 * Values are exact: actor IDs are lowercase by format and Magnus/Ardent IDs keep their case.
 */
export function parseAgentEntityValue(raw: string): AgentEntityValue | null {
  const value = raw.trim();
  const separator = value.indexOf(':');
  if (separator < 0) return null;
  const prefix = value.slice(0, separator);
  const rest = value.slice(separator + 1);
  if (prefix === 'actor' && agentActorIdSchema.safeParse(rest).success)
    return { kind: 'actor', actorId: rest, value };
  if (prefix === 'agent-ref' && agentRefSchema.safeParse(rest).success) {
    const [nodeId, profile] = rest.split('~') as [string, string];
    return { kind: 'agent-ref', agentRef: rest, nodeId, profile, value };
  }
  if (prefix === 'magnus-node' && magnusNodeIdSchema.safeParse(rest).success)
    return { kind: 'magnus-node', nodeId: rest, value };
  return null;
}

export const securityFusionEntityRefSchema = z.object({
  type: securityFusionEntityTypeSchema,
  value: z.string().min(1).max(512),
  label: z.string().min(1).max(160).optional(),
}).superRefine((ref, context) => {
  if (ref.type !== 'agent') return;
  const parsed = parseAgentEntityValue(ref.value);
  // An agent entity names an agent: a canonical actor ID, or a node profile reference.
  if (!parsed || parsed.kind === 'magnus-node')
    context.addIssue({
      code: 'custom',
      path: ['value'],
      message: 'agent entity value must be actor:<actorId> or agent-ref:<nodeId>~<profile>',
    });
});

/** Query for cases involving one entity: `GET /cases?entityType=&entity=`. Both or neither. */
export const securityFusionCaseEntityFilterSchema = z.object({
  entityType: securityFusionEntityTypeSchema,
  entity: z.string().trim().min(1).max(512),
}).superRefine((filter, context) => {
  if (filter.entityType === 'agent' && !parseAgentEntityValue(filter.entity))
    context.addIssue({
      code: 'custom',
      path: ['entity'],
      message: 'agent entity must be actor:<actorId>, agent-ref:<nodeId>~<profile> or magnus-node:<nodeId>',
    });
});
export type SecurityFusionCaseEntityFilter = z.infer<typeof securityFusionCaseEntityFilterSchema>;

export const securityFusionEventSchema = z.object({
  schemaVersion: z.literal('1.0'),
  eventId: z.string().min(1).max(160),
  source: securityFusionSourceSchema,
  sourceEventId: z.string().min(1).max(512),
  kind: z.string().min(1).max(160),
  observedAt: z.string().datetime({ offset: true }),
  severity: securityFusionSeveritySchema,
  confidence: z.number().min(0).max(1),
  summary: z.string().min(1).max(2000),
  entities: z.array(securityFusionEntityRefSchema).max(32).default([]),
  attributes: z.record(z.string(), z.unknown()).default({}),
  evidence: z.array(z.object({
    sourceLocator: z.string().max(1000),
    mediaType: z.string().max(120).default('application/json'),
    snapshot: z.record(z.string(), z.unknown()).optional(),
  })).max(16).default([]),
});

export const securityFusionEventBatchSchema = z.object({
  schemaVersion: z.literal('1.0'),
  collectorId: z.string().min(1).max(160),
  sentAt: z.string().datetime({ offset: true }),
  events: z.array(securityFusionEventSchema).min(1).max(100),
  checkpoints: z.partialRecord(securityFusionSourceSchema, z.string().max(2000)).optional(),
});

export const securityFusionSourceStatusSchema = z.enum([
  'unconfigured',
  'configured',
  'healthy',
  'degraded',
  'error',
]);

export const securityFusionSourceReportSchema = z.object({
  schemaVersion: z.literal('1.0'),
  collectorId: z.string().min(1).max(160),
  sentAt: z.string().datetime({ offset: true }),
  sources: z.array(z.object({
    source: securityFusionSourceSchema,
    status: securityFusionSourceStatusSchema,
    lastEventAt: z.string().datetime({ offset: true }).optional(),
    checkpoint: z.string().max(2000).optional(),
    error: z.string().max(500).optional(),
  })).min(1).max(securityFusionSourceSchema.options.length),
});

export const securityFusionInvestigationDraftSchema = z.object({
  lab: labAssessmentSchema.optional(),
  summary: z.string().min(1).max(4000),
  hypotheses: z.array(z.string().min(1).max(1000)).max(12),
  prioritizedChecks: z.array(z.string().min(1).max(1000)).max(20),
  proposedActions: z.array(z.object({
    kind: z.enum(['service_restart', 'host_isolation', 'credential_rotation', 'network_block', 'other']),
    description: z.string().min(1).max(1200),
    risk: z.enum(['low', 'medium', 'high', 'critical']),
    reversible: z.boolean(),
    requiresApproval: z.literal(true),
    executable: z.literal(false),
  })).max(12),
  evidenceSteps: z.array(z.string().min(1).max(1000)).max(20),
});

export const securityFusionContainmentPreviewSchema = z.object({
  caseId: z.string().min(1),
  nodeId: z.string().min(1),
  kind: z.enum(['service_restart', 'host_isolation']),
  serviceName: z.string().regex(/^[a-zA-Z0-9@_.-]+$/).optional(),
  isolationMinutes: z.number().int().min(1).max(30).optional(),
  rationale: z.string().min(10).max(2000),
}).superRefine((value, context) => {
  if (value.kind === 'service_restart' && !value.serviceName) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['serviceName'], message: 'serviceName is required for service restart' });
  }
});

export type SecurityFusionSource = z.infer<typeof securityFusionSourceSchema>;
export type SecurityFusionSeverity = z.infer<typeof securityFusionSeveritySchema>;
export type SecurityFusionEntityRef = z.infer<typeof securityFusionEntityRefSchema>;
export type SecurityFusionEvent = z.infer<typeof securityFusionEventSchema>;
export type SecurityFusionEventBatch = z.infer<typeof securityFusionEventBatchSchema>;
export type SecurityFusionSourceStatus = z.infer<typeof securityFusionSourceStatusSchema>;
export type SecurityFusionSourceReport = z.infer<typeof securityFusionSourceReportSchema>;
export type SecurityFusionInvestigationDraft = z.infer<typeof securityFusionInvestigationDraftSchema>;
export type SecurityFusionContainmentPreview = z.infer<typeof securityFusionContainmentPreviewSchema>;


/** Minimal read-only target export; fleet registration remains on Magnus. */
export const securityInventoryTargetSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  hostname: z.string().min(1),
  baseUrl: z
    .string()
    .url()
    .refine(
      (value) => new URL(value).protocol === "https:",
      "Agent TLS required",
    ),
  tags: z.string(),
  metadata: z.string(),
});
export const securityInventoryExportSchema = z.object({
  data: z.array(securityInventoryTargetSchema).max(10000),
});
export type SecurityInventoryTarget = z.infer<
  typeof securityInventoryTargetSchema
>;
export type SecurityInventoryExport = z.infer<
  typeof securityInventoryExportSchema
>;


export function canonicalSecuritySource(source: string): string {
  return source === "aegis_ui" || source === "cindertrace_ui" ? "security_console" : source === "chattermost" ? "mattermost" : source;
}

export * from "./browser-auth.js";
