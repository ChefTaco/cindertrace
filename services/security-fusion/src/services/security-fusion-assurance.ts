import { createHash } from "node:crypto";
import { z } from "zod";
import { getDb, type Prisma } from "../db/index.js";
import { HttpError } from "../middleware/error-handler.js";
import { agentHealth, readyTarget } from "./targets.js";

const id = z.string().min(1).max(200);
const sha256 = z.string().regex(/^[a-f0-9]{64}$/u);
const boundedText = z.string().min(1).max(1200);
const eventIds = z.array(id).max(50);
const evidenceRef = z.object({
  source: z.string().min(1).max(80),
  reference: z.string().min(1).max(500),
  sha256,
  observedAt: z.string().datetime({ offset: true }),
}).strict();

export const exposureRequestSchema = z.object({
  advisory: z.object({
    id,
    title: z.string().min(1).max(500),
    severity: z.enum(["info", "low", "medium", "high", "critical"]),
    publishedAt: z.string().datetime({ offset: true }),
    sha256,
    evidence: z.array(evidenceRef).min(1).max(20),
  }).strict(),
  selectors: z.object({
    hostnames: z.array(z.string().min(1).max(253)).max(100).default([]),
    serviceNames: z.array(z.string().min(1).max(200)).max(100).default([]),
    tags: z.array(z.string().min(1).max(100)).max(100).default([]),
    metadataEquals: z.record(z.string().min(1).max(100), z.union([
      z.string().max(500), z.number().finite(), z.boolean(),
    ])).default({}),
  }).strict().refine((value) =>
    value.hostnames.length + value.serviceNames.length + value.tags.length
      + Object.keys(value.metadataEquals).length > 0,
  "At least one exact affected selector is required"),
}).strict();

export const investigationRequestSchema = z.object({
  hypotheses: z.array(z.object({
    id,
    statement: boundedText,
    confidence: z.number().min(0).max(1),
    supportingEventIds: eventIds,
    contraryEventIds: eventIds,
    nextCheck: boundedText,
  }).strict().superRefine((value, context) => {
    const overlap = value.supportingEventIds.filter((item) => value.contraryEventIds.includes(item));
    if (overlap.length) context.addIssue({ code: z.ZodIssueCode.custom, message: "An event cannot be both supporting and contrary evidence" });
  })).min(1).max(12),
  collectionLimits: z.array(boundedText).min(1).max(20),
  nextChecks: z.array(boundedText).min(1).max(20),
}).strict();

export const reviewRequestSchema = z.object({
  candidate: z.object({
    kind: z.enum(["plugin", "tool", "provider", "skill", "release"]),
    name: z.string().min(1).max(200),
    version: z.string().min(1).max(100),
    sourceSha256: sha256,
    changedCapabilities: z.array(boundedText).min(1).max(40),
    authorityChanges: z.array(boundedText).max(20),
    dataFlows: z.array(boundedText).max(40),
    testEvidence: z.array(evidenceRef).min(1).max(40),
  }).strict(),
  findings: z.array(z.object({
    id,
    severity: z.enum(["info", "low", "medium", "high", "critical"]),
    reachablePath: z.string().min(10).max(1600),
    evidenceReferences: z.array(z.string().min(1).max(500)).min(1).max(20),
    mitigation: z.string().min(1).max(1600),
    mitigationEvidence: z.array(z.string().min(1).max(500)).max(20),
    status: z.enum(["open", "mitigated", "accepted_risk", "not_reproducible"]),
  }).strict()).max(40),
}).strict();

export const closureRequestSchema = z.object({
  nodeId: id,
  serviceName: z.string().regex(/^[A-Za-z0-9@_.-]{1,200}$/u),
  symptomEventIds: eventIds.min(1),
  recoveryEventIds: eventIds.min(1),
  residualRisks: z.array(boundedText).max(20),
  summary: z.string().min(1).max(2000),
}).strict();

type Target = { id: string; name: string; hostname: string; tags: string; metadata: string; syncedAt: Date };
type CaseEvent = { id: string; source: string; observedAt: Date; integritySha256: string; severity: string; hostCanonicals?: string[] };
type SourceState = { source: string; status: string; lastSuccessAt: Date | null };
type EvidenceDb = ReturnType<typeof getDb> | Prisma.TransactionClient;

export function canonicalJson(value: unknown): string {
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
}

export function digest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function parsedObject(value: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown> : null;
  } catch { return null; }
}

function parsedStrings(value: string): string[] | null {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) && parsed.every((item) => typeof item === "string") ? parsed : null;
  } catch { return null; }
}

export function buildExposurePacket(
  raw: z.infer<typeof exposureRequestSchema>, targets: Target[], hostEvidence: Set<string>, now = new Date(),
) {
  const input = exposureRequestSchema.parse(raw);
  const wantedHosts = new Set(input.selectors.hostnames.map((item) => item.toLowerCase()));
  const wantedServices = new Set(input.selectors.serviceNames.map((item) => item.toLowerCase().replace(/\.service$/u, "")));
  const wantedTags = new Set(input.selectors.tags.map((item) => item.toLowerCase()));
  const systems = targets.map((target) => {
    const tags = parsedStrings(target.tags);
    const metadata = parsedObject(target.metadata);
    const ageSeconds = Math.max(0, Math.floor((now.getTime() - target.syncedAt.getTime()) / 1000));
    const fresh = ageSeconds <= 86_400;
    const facts: string[] = [];
    if (wantedHosts.has(target.hostname.toLowerCase()) || wantedHosts.has(target.name.toLowerCase())) facts.push("hostname");
    if (tags) for (const tag of tags) if (wantedTags.has(tag.toLowerCase())) facts.push(`tag:${tag}`);
    const services = metadata && Array.isArray(metadata["services"])
      ? metadata["services"].filter((item): item is string => typeof item === "string") : [];
    for (const service of services) if (wantedServices.has(service.toLowerCase().replace(/\.service$/u, ""))) facts.push(`service:${service}`);
    if (metadata) for (const [key, value] of Object.entries(input.selectors.metadataEquals))
      if (metadata[key] === value) facts.push(`metadata:${key}`);
    const serviceInventoryMissing = wantedServices.size > 0
      && (!metadata || !Array.isArray(metadata["services"])
        || !metadata["services"].every((item) => typeof item === "string"));
    const malformed = tags === null || metadata === null || serviceInventoryMissing;
    const conclusion = !fresh || malformed ? "unknown" : facts.length ? "affected" : "not_affected";
    const telemetry = hostEvidence.has(target.hostname.toLowerCase()) || hostEvidence.has(target.name.toLowerCase());
    // Missing telemetry means exploit activity is uncorroborated; it does not
    // reduce a confirmed or still-unknown advisory impact rating.
    const actualSeverity = conclusion === "not_affected" ? "info" : input.advisory.severity;
    return {
      nodeId: target.id, hostname: target.hostname, inventorySyncedAt: target.syncedAt.toISOString(),
      inventoryAgeSeconds: ageSeconds, conclusion, actualSeverity, matchedFacts: facts.sort(),
      telemetryCorroborated: telemetry,
      evidence: conclusion === "unknown"
        ? [!fresh ? "magnus-inventory-stale" : "magnus-inventory-malformed"]
        : ["magnus-inventory", ...(telemetry ? ["security-fusion-case-telemetry"] : [])],
    };
  });
  return {
    version: "1.0", kind: "exposure", advisory: input.advisory,
    inventoryAuthority: "magnus", telemetryAuthority: "security-fusion",
    disposition: targets.length === 0 ? "unknown" : "assessed",
    inventoryCoverage: targets.length === 0 ? "unavailable" : "bounded_complete",
    systems, counts: {
      affected: systems.filter((item) => item.conclusion === "affected").length,
      notAffected: systems.filter((item) => item.conclusion === "not_affected").length,
      unknown: systems.filter((item) => item.conclusion === "unknown").length,
    },
  };
}

export function buildInvestigationPacket(
  raw: z.infer<typeof investigationRequestSchema>, events: CaseEvent[], sourceStates: SourceState[], now = new Date(),
) {
  const input = investigationRequestSchema.parse(raw);
  const eventMap = new Map(events.map((event) => [event.id, event]));
  for (const hypothesis of input.hypotheses) for (const eventId of [...hypothesis.supportingEventIds, ...hypothesis.contraryEventIds])
    if (!eventMap.has(eventId)) throw new HttpError(400, "UNLINKED_EVIDENCE", "Hypothesis evidence is not linked to this case");
  const sourceGaps = sourceStates.filter((source) => source.status !== "healthy"
    || !source.lastSuccessAt || now.getTime() - source.lastSuccessAt.getTime() > 300_000)
    .map((source) => ({ source: source.source, status: source.status,
      lastSuccessAt: source.lastSuccessAt?.toISOString() ?? null }));
  return {
    version: "1.0", kind: "investigation", hypotheses: input.hypotheses.map((hypothesis) => ({
      ...hypothesis,
      supportingEvidence: hypothesis.supportingEventIds.map((eventId) => ({ eventId, integritySha256: eventMap.get(eventId)!.integritySha256 })),
      contraryEvidence: hypothesis.contraryEventIds.map((eventId) => ({ eventId, integritySha256: eventMap.get(eventId)!.integritySha256 })),
    })),
    collectionLimits: input.collectionLimits,
    telemetryGaps: sourceGaps,
    nextChecks: input.nextChecks,
    conclusionRule: "Missing, stale or degraded telemetry remains a gap and never proves no incident",
  };
}

export function buildReviewPacket(raw: z.infer<typeof reviewRequestSchema>) {
  const input = reviewRequestSchema.parse(raw);
  const unresolved = input.findings.filter((finding) => finding.status === "open");
  const blocking = unresolved.filter((finding) => ["high", "critical"].includes(finding.severity));
  const needsChanges = unresolved.filter((finding) => ["low", "medium"].includes(finding.severity));
  return {
    version: "1.0", kind: "targeted_review", candidate: input.candidate,
    findings: input.findings,
    decision: blocking.length ? "block" : needsChanges.length ? "changes_required" : "approve",
    concreteFindingCount: input.findings.length,
    authority: "review only; this packet grants no runtime, provider, approval or deployment authority",
  };
}

export function buildClosurePacket(args: {
  request: z.infer<typeof closureRequestSchema>;
  events: CaseEvent[];
  sourceStates: SourceState[];
  actionStates: Array<{ id: string; status: string; resultJson: string | null }>;
  target: Target;
  directHealth: unknown;
  serviceStatus: string;
  caseStateSha256: string;
  now?: Date;
}) {
  const request = closureRequestSchema.parse(args.request);
  const now = args.now ?? new Date();
  const byId = new Map(args.events.map((event) => [event.id, event]));
  const symptoms = request.symptomEventIds.map((eventId) => byId.get(eventId));
  const recovery = request.recoveryEventIds.map((eventId) => byId.get(eventId));
  if (symptoms.some((event) => !event) || recovery.some((event) => !event))
    throw new HttpError(400, "UNLINKED_EVIDENCE", "Closure evidence is not linked to this case");
  const targetAliases = new Set([args.target.id, args.target.name, args.target.hostname]
    .map((value) => value.toLowerCase()));
  if ([...symptoms, ...recovery].some((event) =>
    !event!.hostCanonicals?.some((value) => targetAliases.has(value.toLowerCase()))))
    throw new HttpError(409, "EVIDENCE_TARGET_MISMATCH", "Symptom and recovery evidence must bind to the direct recovery target");
  const latestSymptom = Math.max(...symptoms.map((event) => event!.observedAt.getTime()));
  const earliestRecovery = Math.min(...recovery.map((event) => event!.observedAt.getTime()));
  if (earliestRecovery <= latestSymptom)
    throw new HttpError(409, "RECOVERY_NOT_NEWER", "Recovery evidence must postdate the original symptom");
  const recoveryAgeMs = now.getTime() - Math.max(...recovery.map((event) => event!.observedAt.getTime()));
  if (recoveryAgeMs < 0 || recoveryAgeMs > 300_000)
    throw new HttpError(409, "RECOVERY_STALE", "Recovery telemetry is older than five minutes");
  const recoverySources = new Set(recovery.map((event) => event!.source));
  const sourceReceipts: Array<{ source: string; status: string; lastSuccessAt: string }> = [];
  for (const source of recoverySources) {
    const state = args.sourceStates.find((item) => item.source === source);
    const sourceAgeMs = state?.lastSuccessAt ? now.getTime() - state.lastSuccessAt.getTime() : null;
    if (!state || state.status !== "healthy" || sourceAgeMs === null
        || sourceAgeMs < 0 || sourceAgeMs > 300_000)
      throw new HttpError(409, "SOURCE_NOT_FRESH", "Recovery source is not fresh and healthy");
    sourceReceipts.push({ source, status: state.status, lastSuccessAt: state.lastSuccessAt!.toISOString() });
  }
  const unsettled = args.actionStates.filter((action) =>
    !["succeeded", "released", "failed", "cancelled", "rejected"].includes(action.status));
  if (unsettled.length) throw new HttpError(409, "ACTION_UNSETTLED", "A response action remains pending, running or unknown");
  if (args.serviceStatus !== "active")
    throw new HttpError(409, "DIRECT_RECOVERY_FAILED", "Direct target health does not prove the required service is active");
  return {
    version: "1.0", kind: "closure", disposition: "verified",
    nodeId: request.nodeId, hostname: args.target.hostname, serviceName: request.serviceName ?? null,
    summary: request.summary,
    originalSymptoms: symptoms.map((event) => ({ id: event!.id, observedAt: event!.observedAt.toISOString(),
      sha256: event!.integritySha256, hostCanonicals: [...event!.hostCanonicals!].sort() })),
    recoveryEvidence: recovery.map((event) => ({ id: event!.id, observedAt: event!.observedAt.toISOString(),
      sha256: event!.integritySha256, hostCanonicals: [...event!.hostCanonicals!].sort() })),
    recoverySources: sourceReceipts.sort((left, right) => left.source.localeCompare(right.source)),
    directRecovery: { checkedAt: now.toISOString(), inventorySyncedAt: args.target.syncedAt.toISOString(),
      serviceStatus: args.serviceStatus, evidenceSha256: digest(args.directHealth) },
    actionReceipts: args.actionStates.map((action) => ({ id: action.id, status: action.status,
      resultSha256: digest(action.resultJson ?? null) })),
    residualRisks: request.residualRisks,
    caseStateSha256: args.caseStateSha256,
    closureRule: "A command receipt or restart alone is insufficient; linked fresh recovery telemetry and direct target health are both required",
  };
}

async function caseEvidence(caseId: string, db: EvidenceDb = getDb()) {
  const [caseRow, links, entityLinks, actions, sources] = await Promise.all([
    db.securityFusionCase.findUnique({ where: { id: caseId } }),
    db.securityFusionCaseEvent.findMany({ where: { caseId }, select: { eventId: true } }),
    db.securityFusionCaseEntity.findMany({ where: { caseId }, select: { entityId: true } }),
    db.securityFusionAction.findMany({ where: { caseId }, orderBy: { id: "asc" }, select: { id: true, status: true, resultJson: true, updatedAt: true } }),
    db.securityFusionSourceState.findMany(),
  ]);
  if (!caseRow) throw new HttpError(404, "NOT_FOUND", "Security case not found");
  const [events, entities] = await Promise.all([
    db.securityFusionEvent.findMany({ where: { id: { in: links.map((link) => link.eventId) } }, orderBy: { id: "asc" },
      select: { id: true, source: true, observedAt: true, integritySha256: true, severity: true } }),
    db.securityFusionEntity.findMany({ where: { id: { in: entityLinks.map((link) => link.entityId) } },
      select: { id: true, type: true, canonical: true } }),
  ]);
  const eventEntityLinks = await db.securityFusionEventEntity.findMany({
    where: { eventId: { in: events.map((event) => event.id) } },
    orderBy: [{ eventId: "asc" }, { entityId: "asc" }],
    select: { eventId: true, entityId: true },
  });
  const hostByEntityId = new Map(entities.filter((entity) => entity.type === "host")
    .map((entity) => [entity.id, entity.canonical]));
  const boundEvents = events.map((event) => ({ ...event, hostCanonicals: eventEntityLinks
    .filter((link) => link.eventId === event.id)
    .map((link) => hostByEntityId.get(link.entityId))
    .filter((value): value is string => Boolean(value)).sort() }));
  const caseStateSha256 = digest({ case: { id: caseRow.id, status: caseRow.status, severity: caseRow.severity,
    confidence: caseRow.confidence, lastSeenAt: caseRow.lastSeenAt }, events: boundEvents, actions });
  return { caseRow, events: boundEvents, entities, actions, sources, caseStateSha256 };
}

async function persistPacket(caseId: string, kind: string, actorId: string, input: unknown, packet: unknown, caseStateSha256: string) {
  const db = getDb();
  return db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT "id" FROM "security_fusion_cases" WHERE "id" = ${caseId} FOR UPDATE`;
    const prior = await tx.securityFusionAssurancePacket.findFirst({ where: { caseId, kind }, orderBy: { revision: "desc" } });
    const packetSha256 = digest(packet);
    const row = await tx.securityFusionAssurancePacket.create({ data: {
      caseId, kind, actorId, revision: (prior?.revision ?? 0) + 1,
      inputSha256: digest(input), caseStateSha256, packetJson: canonicalJson(packet), packetSha256,
    } });
    await tx.securityFusionCaseActivity.create({ data: { caseId, kind: `assurance.${kind}`,
      actorId, detailJson: canonicalJson({ packetId: row.id, revision: row.revision, packetSha256 }) } });
    return { ...row, packet, packetJson: undefined };
  });
}

function parseRequest<T extends z.ZodTypeAny>(schema: T, raw: unknown): z.output<T> {
  const parsed = schema.safeParse(raw);
  if (!parsed.success)
    throw new HttpError(400, "VALIDATION_ERROR", parsed.error.issues.map((issue) => issue.message).join("; "));
  return parsed.data;
}

export async function createExposureAssessment(caseId: string, actorId: string, raw: unknown) {
  const { input, packet, caseStateSha256 } = await exposureAssessment(caseId, raw);
  return persistPacket(caseId, "exposure", actorId, input, packet, caseStateSha256);
}

async function exposureAssessment(caseId: string, raw: unknown) {
  const input = parseRequest(exposureRequestSchema, raw);
  const evidence = await caseEvidence(caseId);
  const targets = await getDb().securityTarget.findMany({ orderBy: { id: "asc" }, take: 501 });
  if (targets.length > 500) throw new HttpError(409, "INVENTORY_TRUNCATED", "Magnus inventory exceeds the bounded assessment size");
  const hosts = new Set(evidence.entities.filter((entity) => entity.type === "host").map((entity) => entity.canonical.toLowerCase()));
  const packet = buildExposurePacket(input, targets, hosts);
  return { input, packet, caseStateSha256: evidence.caseStateSha256 };
}

/** Compute the owning-service assessment without creating a packet, revision, or case activity. */
export async function previewExposureAssessment(caseId: string, raw: unknown) {
  const { input, packet, caseStateSha256 } = await exposureAssessment(caseId, raw);
  return { caseId, persisted: false as const, inputSha256: digest(input), caseStateSha256,
    packetSha256: digest(packet), packet };
}

export async function createInvestigationPacket(caseId: string, actorId: string, raw: unknown) {
  const input = parseRequest(investigationRequestSchema, raw);
  const evidence = await caseEvidence(caseId);
  const packet = buildInvestigationPacket(input, evidence.events, evidence.sources);
  return persistPacket(caseId, "investigation", actorId, input, packet, evidence.caseStateSha256);
}

export async function createTargetedReview(caseId: string, actorId: string, raw: unknown) {
  const input = parseRequest(reviewRequestSchema, raw);
  const evidence = await caseEvidence(caseId);
  const packet = buildReviewPacket(input);
  return persistPacket(caseId, "targeted_review", actorId, input, packet, evidence.caseStateSha256);
}

export async function createVerifiedClosure(caseId: string, actorId: string, raw: unknown) {
  const request = parseRequest(closureRequestSchema, raw);
  const evidence = await caseEvidence(caseId);
  const target = await readyTarget(request.nodeId);
  const caseHosts = new Set(evidence.entities.filter((entity) => entity.type === "host")
    .map((entity) => entity.canonical.toLowerCase()));
  if (![target.id, target.name, target.hostname].some((value) => caseHosts.has(value.toLowerCase())))
    throw new HttpError(409, "TARGET_NOT_LINKED", "Direct recovery target is not linked to this security case");
  const directHealth = await agentHealth(target.baseUrl);
  const normalized = request.serviceName?.replace(/\.service$/u, "");
  const serviceStatus = normalized === "wazuh-agent" && directHealth.wazuh
    ? directHealth.wazuh.installed ? directHealth.wazuh.serviceStatus : "unknown"
    : directHealth.services.find((service) => service.name?.replace(/\.service$/u, "") === normalized)?.status ?? "unknown";
  const packet = buildClosurePacket({ request, events: evidence.events, sourceStates: evidence.sources,
    actionStates: evidence.actions, target, directHealth, serviceStatus, caseStateSha256: evidence.caseStateSha256 });
  return persistPacket(caseId, "closure", actorId, request, packet, evidence.caseStateSha256);
}

export function validateStoredClosure(
  row: { caseStateSha256: string; createdAt: Date; packetJson: string; packetSha256: string } | null,
  caseStateSha256: string, now = new Date(),
) {
  const ageMs = row ? now.getTime() - row.createdAt.getTime() : Number.POSITIVE_INFINITY;
  if (!row || row.caseStateSha256 !== caseStateSha256 || ageMs < 0 || ageMs > 600_000)
    throw new HttpError(409, "VERIFIED_CLOSURE_REQUIRED", "Resolution requires a current direct-recovery closure packet for the unchanged case state");
  let packet: { disposition?: string; caseStateSha256?: string };
  try { packet = JSON.parse(row.packetJson) as typeof packet; }
  catch { throw new HttpError(409, "VERIFIED_CLOSURE_REQUIRED", "Closure packet integrity or disposition is invalid"); }
  if (packet.disposition !== "verified" || packet.caseStateSha256 !== caseStateSha256
      || digest(packet) !== row.packetSha256)
    throw new HttpError(409, "VERIFIED_CLOSURE_REQUIRED", "Closure packet integrity or disposition is invalid");
  return row;
}

export async function requireCurrentVerifiedClosure(caseId: string, db: EvidenceDb = getDb()) {
  const evidence = await caseEvidence(caseId, db);
  const row = await db.securityFusionAssurancePacket.findFirst({ where: { caseId, kind: "closure" }, orderBy: { revision: "desc" } });
  return validateStoredClosure(row, evidence.caseStateSha256);
}

export async function resolveCaseWithVerifiedClosure(
  caseId: string, actorId: string, assignedTo?: string | null,
) {
  try {
    return await getDb().$transaction(async (tx) => {
      await tx.$queryRaw`SELECT "id" FROM "security_fusion_cases" WHERE "id" = ${caseId} FOR UPDATE`;
      await requireCurrentVerifiedClosure(caseId, tx);
      const row = await tx.securityFusionCase.update({ where: { id: caseId }, data: {
        status: "resolved", resolvedAt: new Date(),
        ...(assignedTo !== undefined ? { assignedTo } : {}),
      } });
      await tx.securityFusionCaseActivity.create({ data: { caseId, kind: "case.updated", actorId,
        detailJson: JSON.stringify({ status: "resolved", ...(assignedTo !== undefined ? { assignedTo } : {}) }) } });
      return row;
    }, { isolationLevel: "Serializable" });
  } catch (error) {
    if ((error as { code?: string }).code === "P2034")
      throw new HttpError(409, "CASE_CHANGED", "Case state changed during resolution; reread it before another request");
    throw error;
  }
}
