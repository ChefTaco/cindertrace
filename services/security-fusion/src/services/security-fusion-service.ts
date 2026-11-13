import {isRehearsal,securityWritesEnabled} from "../config/rehearsal.js";
import {
  failureWindow,
  uiSource,
  sourceInterpretations,
  entityInterpretations,
  UI_LOGIN_THRESHOLD,
  UI_LOGIN_WINDOW_MS,
} from "./ui-login-rule.js";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type {
  SecurityFusionEvent,
  SecurityFusionEventBatch,
  SecurityFusionInvestigationDraft,
} from "@cindertrace/contracts";
import { getDb } from "../db/index.js";
import { HttpError } from "../middleware/error-handler.js";
import { incMetric } from "../routes/metrics.js";
import {
  observedAtRejection,
  type RejectedSecurityFusionEvent,
} from "./security-fusion-ingest.js";
import { sanitizeDetails } from "./audit-service.js";
import {
  appendDeletionReceipts,
  exportReceiptChainHead,
  type DeletionReceiptInput,
} from "./security-fusion-receipt-chain.js";
import { ensurePrivateEvidenceDirectory } from "./security-fusion-evidence-integrity.js";
import {
  agentIdentityFromAttributes,
  derivedMagnusAgentEntity,
  resolveAgentEntityIds,
  upsertAgentEntity,
  type AgentIdentity,
} from "./agent-entities.js";

const severityRank: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
const sourceTrust: Record<string, number> = {
  unifi_dns: 0.72,
  unifi_ids: 0.9,
  netflow: 0.75,
  wazuh: 0.94,
  tailscale: 0.9,
  magnus: 0.88,
  magnus_ui: 0.95,
  aegis_ui: 0.95,
  security_console: 0.95,
  cindertrace_ui: 0.95,
  mattermost: 0.86,
  hive: 0.9,
  chattermost: 0.86,
  hivemem: 0.9,
  hiveskills: 0.9,
  ardentstudio: 0.9,
  embermend: 0.9,
};

const MAGNUS_SOURCE_STATE_TOUCH_INTERVAL_MS = 60_000;
let lastMagnusSourceStateTouchAt = 0;

export const SECURITY_FUSION_RETENTION_POLICY = {
  eventDays: 90,
  caseArchiveDays: 365,
  archiveGraceDays: 30,
  evidenceDays: 365,
  deletionReceiptDays: 2555,
  maxCaseEvents: 1_000,
  maxCaseEntities: 250,
  maxCaseRelationships: 50,
  maxPreservedEvidence: 100,
  maxPreservedEvidenceBytes: 8 * 1024 * 1024,
  maxSingleEvidenceBytes: 64 * 1024,
} as const;

export function evaluateSecurityFusionEvidenceAdmission(
  currentCount: number,
  currentBytes: number,
  nextBytes: number,
): "accepted" | "count_limit" | "byte_limit" {
  if (currentCount >= SECURITY_FUSION_RETENTION_POLICY.maxPreservedEvidence) {
    return "count_limit";
  }
  if (
    currentBytes + nextBytes >
    SECURITY_FUSION_RETENTION_POLICY.maxPreservedEvidenceBytes
  ) {
    return "byte_limit";
  }
  return "accepted";
}

export function boundSecurityFusionRelationships<T>(
  rows: T[],
  limit = SECURITY_FUSION_RETENTION_POLICY.maxCaseRelationships,
): { rows: T[]; truncated: boolean } {
  return { rows: rows.slice(0, limit), truncated: rows.length > limit };
}

function rank(severity: string): number {
  return severityRank[severity] ?? 0;
}

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalEntity(type: string, value: string): string {
  // Agent values are exact: actor IDs are lowercase by format; node and profile IDs keep their case.
  if (type === "agent") return value.trim();
  const normalized = value.trim().toLowerCase();
  return type === "domain" ? normalized.replace(/\.$/, "") : normalized;
}

/** Agent entities join cases; they anchor a case only when the event names nothing else. */
export function correlationAnchor(
  entities: SecurityFusionEvent["entities"],
): SecurityFusionEvent["entities"][number] | undefined {
  const sorted = [...entities].sort((a, b) =>
    `${a.type}:${a.value}`.localeCompare(`${b.type}:${b.value}`),
  );
  return sorted.find((entity) => entity.type !== "agent") ?? sorted[0];
}

/** Entity IDs for `GET /cases?entityType=&entity=`, using the same normalization as ingest. */
export async function resolveCaseFilterEntityIds(
  type: string,
  value: string,
): Promise<string[]> {
  if (type === "agent") return resolveAgentEntityIds(value);
  const rows = await getDb().securityFusionEntity.findMany({
    where: {
      type,
      canonical: { in: entityInterpretations(type, canonicalEntity(type, value)) },
    },
    select: { id: true },
    take: 100,
  });
  return rows.map((row) => row.id);
}

export function correlationFamily(
  event: SecurityFusionEvent,
  relatedSources: Set<string>,
): string | null {
  const kind = event.kind.toLowerCase();
  if (uiSource(event.source) && kind !== "auth.login_failed.threshold")
    return null;
  if (
    (event.source === "hive" ||
      ["chattermost", "mattermost"].includes(event.source)) &&
    (event.source === "hive"
      ? relatedSources.has("chattermost") || relatedSources.has("mattermost")
      : relatedSources.has("hive"))
  )
    return "cross-service-authentication";
  if (
    (event.source === "unifi_ids" && relatedSources.has("wazuh")) ||
    (event.source === "wazuh" && relatedSources.has("unifi_ids"))
  )
    return "ids-endpoint-intrusion";
  if (
    kind.includes("auth") ||
    kind.includes("login") ||
    kind.includes("session")
  )
    return "credential-abuse";
  if (kind.includes("dns") || kind.includes("flow")) {
    return rank(event.severity) >= rank("medium") || relatedSources.has("wazuh")
      ? "suspicious-dns-egress"
      : null;
  }
  if (kind.includes("ids") || kind.includes("ips"))
    return "ids-endpoint-intrusion";
  if (
    kind.includes("wazuh") ||
    kind.includes("tamper") ||
    kind.includes("drift")
  )
    return "endpoint-integrity";
  if (kind.includes("heartbeat") && rank(event.severity) >= rank("medium"))
    return "endpoint-integrity";
  if (kind.includes("tailscale")) return "tailnet-access";
  return rank(event.severity) >= rank("high") ? "security-observation" : null;
}

function investigationFor(family: string): {
  checks: string[];
  evidence: string[];
} {
  const commonEvidence = [
    "Preserve the normalized event set and source locators before source retention expires.",
    "Record timestamps, entity aliases, and integrity hashes in the case evidence manifest.",
  ];
  if (family === "credential-abuse")
    return {
      checks: [
        "Verify the affected account and source identity.",
        "Compare Hive and ChatterMost sessions with Tailscale device ownership.",
        "Review nearby Wazuh authentication findings.",
      ],
      evidence: commonEvidence,
    };
  if (family === "suspicious-dns-egress")
    return {
      checks: [
        "Confirm the client-to-IP mapping at the observation time.",
        "Compare DNS, IPFIX, and UniFi IDS signatures.",
        "Check the endpoint in Wazuh before proposing isolation.",
      ],
      evidence: commonEvidence,
    };
  return {
    checks: [
      "Verify host liveness and configuration drift.",
      "Review Wazuh findings and recent approved fleet operations.",
      "Establish whether the observation is expected maintenance.",
    ],
    evidence: commonEvidence,
  };
}

function caseDomain(family: string): string {
  return [
    "credential-abuse",
    "cross-service-authentication",
    "tailnet-access",
  ].includes(family)
    ? "identity-access"
    : "network-endpoint";
}

async function notifyChatterMost(
  caseId: string,
  revisionKey: string,
  message: string,
): Promise<void> {
  if (isRehearsal() || process.env["SECURITY_NOTIFICATIONS_ENABLED"] !== "true") return;
  const baseUrl = process.env["SECURITY_FUSION_CHATTERMOST_URL"]?.replace(
    /\/$/u,
    "",
  );
  const token = process.env["SECURITY_FUSION_CHATTERMOST_BOT_TOKEN"];
  const channelId = process.env["SECURITY_FUSION_CHATTERMOST_CHANNEL_ID"];
  if (!baseUrl || !token || !channelId) return;
  let delivery;
  try {
    delivery = await getDb().securityFusionDelivery.create({
      data: {
        caseId,
        revisionKey,
        channel: "chattermost:security-fusion",
        status: "sending",
      },
    });
  } catch (error) {
    if (
      typeof error === "object" &&
      error &&
      "code" in error &&
      error.code === "P2002"
    )
      return;
    throw error;
  }
  try {
    const response = await fetch(`${baseUrl}/api/v4/posts`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ channel_id: channelId, message }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok)
      throw new Error(`ChatterMost returned ${response.status}`);
    const body = (await response.json()) as { id?: string };
    await getDb().securityFusionDelivery.update({
      where: { id: delivery.id },
      data: { status: "delivered", externalId: body.id ?? null },
    });
  } catch (error) {
    await getDb().securityFusionDelivery.update({
      where: { id: delivery.id },
      data: {
        status: "failed",
        error: error instanceof Error ? error.message : String(error),
      },
    });
  }
}

async function upsertEntity(
  eventId: string,
  observedAt: Date,
  ref: SecurityFusionEvent["entities"][number],
  identity: AgentIdentity | null = null,
): Promise<string> {
  if (ref.type === "agent")
    return upsertAgentEntity(eventId, observedAt, ref, identity);
  const db = getDb();
  const aliases = entityInterpretations(
    ref.type,
    canonicalEntity(ref.type, ref.value),
  );
  const existing =
    aliases.length > 1
      ? await db.securityFusionEntity.findFirst({
          where: { type: ref.type, canonical: { in: aliases } },
          orderBy: { firstSeenAt: "asc" },
        })
      : null;
  const canonical = existing?.canonical ?? aliases[0]!;
  const row = await db.securityFusionEntity.upsert({
    where: { type_canonical: { type: ref.type, canonical } },
    create: {
      type: ref.type,
      canonical,
      label: ref.label ?? ref.value,
      aliasesJson: JSON.stringify([ref.value]),
      firstSeenAt: observedAt,
      lastSeenAt: observedAt,
    },
    update: { label: ref.label ?? ref.value, lastSeenAt: observedAt },
  });
  await db.securityFusionEventEntity.upsert({
    where: { eventId_entityId: { eventId, entityId: row.id } },
    create: { eventId, entityId: row.id },
    update: {},
  });
  await db.securityFusionEntityAlias.upsert({
    where: {
      source_canonical: {
        source: "normalized",
        canonical: `${ref.type}:${canonical}`,
      },
    },
    create: {
      entityId: row.id,
      source: "normalized",
      value: ref.value,
      canonical: `${ref.type}:${canonical}`,
      firstSeenAt: observedAt,
      lastSeenAt: observedAt,
    },
    update: { entityId: row.id, value: ref.value, lastSeenAt: observedAt },
  });
  return row.id;
}

async function correlate(
  event: SecurityFusionEvent,
  storedId: string,
  entityIds: string[],
): Promise<string | null> {
  const windowStart = new Date(Date.parse(event.observedAt) - 15 * 60_000);
  const relatedLinks =
    entityIds.length === 0
      ? []
      : await getDb().securityFusionEventEntity.findMany({
          where: { entityId: { in: entityIds } },
          orderBy: { id: "desc" },
          take: SECURITY_FUSION_RETENTION_POLICY.maxCaseRelationships + 1,
          select: { eventId: true },
        });
  const boundedExpansion = boundSecurityFusionRelationships(relatedLinks);
  const relationshipExpansionTruncated = boundedExpansion.truncated;
  if (relationshipExpansionTruncated)
    incMetric("securityFusionRelationshipTruncated");
  const boundedRelatedLinks = boundedExpansion.rows;
  const related =
    boundedRelatedLinks.length === 0
      ? []
      : await getDb().securityFusionEvent.findMany({
          where: {
            id: { in: boundedRelatedLinks.map((link) => link.eventId) },
            observedAt: { gte: windowStart, lte: new Date(event.observedAt) },
          },
          select: { source: true },
        });
  const family = correlationFamily(
    event,
    new Set(related.map((item) => item.source)),
  );
  if (!family) return null;
  const anchor = correlationAnchor(event.entities);
  const anchorAliases = anchor
    ? entityInterpretations(
        anchor.type,
        canonicalEntity(anchor.type, anchor.value),
      )
    : sourceInterpretations(event.source);
  const fingerprints = anchorAliases.map((value) =>
    sha256(
      `${caseDomain(family)}|${anchor ? `${anchor.type}:${value}` : value}`,
    ),
  );
  const guidance = investigationFor(family);
  const trustAdjusted = Math.min(
    1,
    event.confidence * (sourceTrust[event.source] ?? 0.7),
  );
  const existing = (
    await Promise.all(
      fingerprints.map((fingerprint) =>
        getDb().securityFusionCase.findUnique({ where: { fingerprint } }),
      ),
    )
  ).find(Boolean);
  const fingerprint = existing?.fingerprint ?? fingerprints[0]!;
  const caseRow = await getDb().securityFusionCase.upsert({
    where: { fingerprint },
    create: {
      fingerprint,
      title: `${family.replaceAll("-", " ")} · ${anchor?.label ?? anchor?.value ?? event.source}`,
      severity: event.severity,
      confidence: trustAdjusted,
      summary: event.summary,
      recommendedInvestigationJson: JSON.stringify(guidance.checks),
      evidenceStepsJson: JSON.stringify(guidance.evidence),
      firstSeenAt: new Date(event.observedAt),
      lastSeenAt: new Date(event.observedAt),
    },
    update: {
      status:
        existing && ["resolved", "false_positive"].includes(existing.status)
          ? "new"
          : existing?.status,
      severity:
        existing && rank(existing.severity) > rank(event.severity)
          ? existing.severity
          : event.severity,
      confidence: Math.min(
        1,
        Math.max(existing?.confidence ?? 0, trustAdjusted) +
          (existing ? 0.05 : 0),
      ),
      lastSeenAt: new Date(
        Math.max(
          existing?.lastSeenAt.getTime() ?? 0,
          Date.parse(event.observedAt),
        ),
      ),
      archivedAt: null,
    },
  });
  const reopened =
    existing && ["resolved", "false_positive"].includes(existing.status);
  const escalated = existing && rank(event.severity) > rank(existing.severity);
  const accepted = await getDb().$transaction(async (tx) => {
    await tx.$queryRaw`SELECT "id" FROM "security_fusion_cases" WHERE "id" = ${caseRow.id} FOR UPDATE`;
    const lockedCase = await tx.securityFusionCase.findUnique({
      where: { id: caseRow.id },
      select: { evidenceAcceptedCount: true },
    });
    if (
      !lockedCase ||
      lockedCase.evidenceAcceptedCount >=
        SECURITY_FUSION_RETENTION_POLICY.maxCaseEvents
    ) {
      if (lockedCase) {
        await tx.securityFusionCase.update({
          where: { id: caseRow.id },
          data: { evidenceTruncatedCount: { increment: 1 } },
        });
      }
      await tx.securityFusionSourceState.upsert({
        where: { source: event.source },
        create: {
          id: event.source,
          source: event.source,
          status: "configured",
          truncatedCount: 1,
        },
        update: { truncatedCount: { increment: 1 } },
      });
      return false;
    }
    await tx.securityFusionCaseEvent.create({
      data: {
        caseId: caseRow.id,
        eventId: storedId,
        ruleId: uiSource(event.source)
          ? "ui-login-failures"
          : "builtin-security-fusion",
        confidenceContribution: trustAdjusted,
      },
    });
    const entityCount = await tx.securityFusionCaseEntity.count({
      where: { caseId: caseRow.id },
    });
    const remainingEntitySlots = Math.max(
      0,
      SECURITY_FUSION_RETENTION_POLICY.maxCaseEntities - entityCount,
    );
    for (const entityId of entityIds.slice(0, remainingEntitySlots)) {
      await tx.securityFusionCaseEntity.upsert({
        where: { caseId_entityId: { caseId: caseRow.id, entityId } },
        create: { caseId: caseRow.id, entityId },
        update: {},
      });
    }
    await tx.securityFusionCase.update({
      where: { id: caseRow.id },
      data: { evidenceAcceptedCount: { increment: 1 } },
    });
    await tx.securityFusionCaseActivity.create({
      data: {
        caseId: caseRow.id,
        kind: !existing
          ? "case.opened"
          : reopened
            ? "case.reopened"
            : escalated
              ? "case.escalated"
              : "evidence.merged",
        actorId: "system:security-fusion",
        detailJson: JSON.stringify({
          eventId: storedId,
          family,
          confidenceContribution: trustAdjusted,
          previousSeverity: existing?.severity ?? null,
          relationshipExpansionTruncated,
        }),
      },
    });
    return true;
  });
  if (accepted) incMetric("securityFusionEvidenceAccepted");
  else incMetric("securityFusionEvidenceTruncated");
  if (
    rank(caseRow.severity) >= rank("high") &&
    (!existing || reopened || escalated)
  ) {
    const transition = !existing
      ? "opened"
      : reopened
        ? "reopened"
        : "escalated";
    await notifyChatterMost(
      caseRow.id,
      `${caseRow.id}:${transition}:${caseRow.severity}:${caseRow.lastSeenAt.toISOString()}`,
      `**Security Fusion ${caseRow.severity.toUpperCase()} case ${transition}**\n${caseRow.title}\n${caseRow.summary}\nCase: ${caseRow.id}`,
    );
  }
  return caseRow.id;
}

async function correlateUiLogin(
  event: SecurityFusionEvent,
  storedId: string,
  entityIds: string[],
): Promise<string | null> {
  if (event.kind !== "auth.login_failed") return null;
  if (
    await getDb().securityFusionCaseEvent.findFirst({
      where: { eventId: storedId },
    })
  )
    return null;
  const accountIndex = event.entities.findIndex(
    (ref) => ref.type === "account",
  );
  if (accountIndex < 0) return null;
  const links = await getDb().securityFusionEventEntity.findMany({
    where: { entityId: entityIds[accountIndex] },
    orderBy: { id: "desc" },
    take: 1000,
    select: { eventId: true },
  });
  const at = Date.parse(event.observedAt);
  const rows = await getDb().securityFusionEvent.findMany({
    where: {
      id: { in: links.map((x) => x.eventId) },
      source: { in: sourceInterpretations(event.source) },
      kind: "auth.login_failed",
      observedAt: {
        gte: new Date(at - UI_LOGIN_WINDOW_MS),
        lte: new Date(at + UI_LOGIN_WINDOW_MS),
      },
    },
    orderBy: { observedAt: "asc" },
  });
  const window = failureWindow(rows, storedId);
  if (window.length < UI_LOGIN_THRESHOLD) return null;
  const linked = await getDb().securityFusionCaseEvent.findMany({
    where: { eventId: { in: window.map((row) => row.id) } },
    select: { eventId: true },
  });
  const alreadyLinked = new Set(linked.map((row) => row.eventId));
  let caseId: string | null = null;
  for (const row of window)
    if (!alreadyLinked.has(row.id))
      caseId = await correlate(
        {
          ...event,
          eventId: row.eventId,
          observedAt: row.observedAt.toISOString(),
          kind: "auth.login_failed.threshold",
          severity: "high",
          summary: `${window.length} failed ${event.source === "magnus_ui" ? "Magnus" : "Cindertrace"} UI logins for the same account and source within 15 minutes.`,
        },
        row.id,
        entityIds,
      );
  return caseId;
}

export async function ingestSecurityFusionBatch(
  batch: SecurityFusionEventBatch,
  receivedAt: Date = new Date(),
): Promise<{
  stored: number;
  duplicates: number;
  rejected: RejectedSecurityFusionEvent[];
  caseIds: string[];
}> {
  const db = getDb();
  const definition = canonicalJson({
    families: [
      "credential-abuse",
      "suspicious-dns-egress",
      "ids-endpoint-intrusion",
      "endpoint-integrity",
      "tailnet-access",
      "cross-service-authentication",
    ],
    windowMinutes: 15,
    fingerprint: "family+canonical-anchor",
  });
  await db.securityFusionRuleVersion.upsert({
    where: {
      ruleId_version: { ruleId: "builtin-security-fusion", version: 1 },
    },
    create: {
      ruleId: "builtin-security-fusion",
      version: 1,
      definitionJson: definition,
      sha256: sha256(definition),
    },
    update: {},
  });
  const uiDefinition = JSON.stringify({
    threshold: UI_LOGIN_THRESHOLD,
    windowMs: UI_LOGIN_WINDOW_MS,
    groupBy: "application+method+account+source",
    failuresOnly: true,
  });
  await db.securityFusionRuleVersion.upsert({
    where: { ruleId_version: { ruleId: "ui-login-failures", version: 1 } },
    create: {
      ruleId: "ui-login-failures",
      version: 1,
      definitionJson: uiDefinition,
      sha256: sha256(uiDefinition),
    },
    update: {},
  });
  let stored = 0;
  let duplicates = 0;
  const rejected: RejectedSecurityFusionEvent[] = [];
  const caseIds = new Set<string>();
  for (const [index, event] of batch.events.entries()) {
    const rejection = observedAtRejection(event, index, receivedAt);
    if (rejection) {
      rejected.push(rejection);
      incMetric("ingestEventsRejected");
      continue;
    }
    const sanitized = {
      ...event,
      attributes: sanitizeDetails(event.attributes),
    };
    const integritySha256 = sha256(canonicalJson(sanitized));
    let row;
    let replay = false;
    try {
      row = await db.securityFusionEvent.create({
        data: {
          eventId: event.eventId,
          source: event.source,
          sourceEventId: event.sourceEventId,
          kind: event.kind,
          observedAt: new Date(event.observedAt),
          severity: event.severity,
          confidence: event.confidence,
          summary: event.summary,
          attributesJson: JSON.stringify(sanitized.attributes),
          integritySha256,
          collectorId: batch.collectorId,
        },
      });
    } catch (error) {
      if (
        typeof error === "object" &&
        error &&
        "code" in error &&
        error.code === "P2002"
      ) {
        duplicates += 1;
        replay = true;
        if (!uiSource(event.source)) continue;
        // A crash after event persistence must not prevent correlation on replay.
        row = await db.securityFusionEvent.findUniqueOrThrow({
          where: {
            source_sourceEventId: {
              source: event.source,
              sourceEventId: event.sourceEventId,
            },
          },
        });
      } else throw error;
    }
    if (!replay) stored += 1;
    const entityIds: string[] = [];
    const identity = agentIdentityFromAttributes(event.attributes);
    const derivedAgent = derivedMagnusAgentEntity(event);
    for (const ref of derivedAgent ? [...event.entities, derivedAgent] : event.entities)
      entityIds.push(await upsertEntity(row.id, row.observedAt, ref, identity));
    const caseId = uiSource(event.source)
      ? await correlateUiLogin(event, row.id, entityIds)
      : await correlate(event, row.id, entityIds);
    if (caseId) caseIds.add(caseId);
    await db.securityFusionSourceState.upsert({
      where: { source: event.source },
      create: {
        id: event.source,
        source: event.source,
        status: "healthy",
        lastEventAt: row.observedAt,
        lastSuccessAt: new Date(),
      },
      update: {
        status: "healthy",
        lastEventAt: row.observedAt,
        lastSuccessAt: new Date(),
        lastError: null,
      },
    });
  }
  for (const [source, checkpoint] of Object.entries(batch.checkpoints ?? {})) {
    await db.securityFusionSourceState.upsert({
      where: { source },
      create: { id: source, source, status: "configured", checkpoint },
      update: { checkpoint },
    });
  }
  return { stored, duplicates, rejected, caseIds: [...caseIds] };
}

export function isSecurityRelevantServiceStatus(
  status: string | undefined,
): boolean {
  return status === "failed" || status === "inactive";
}

export async function ingestMagnusServiceHealth(
  nodeId: string,
  nodeName: string,
  services: Array<{ name?: string; status?: string }>,
): Promise<void> {
  const observedAt = new Date();
  const db = getDb();
  if (
    observedAt.getTime() - lastMagnusSourceStateTouchAt >=
    MAGNUS_SOURCE_STATE_TOUCH_INTERVAL_MS
  ) {
    // Heartbeats arrive from the whole fleet every 30 seconds. Source state is
    // fleet-wide, so touching the same row for every node only creates row-lock
    // and vacuum churn without improving its freshness signal.
    lastMagnusSourceStateTouchAt = observedAt.getTime();
    try {
      await db.securityFusionSourceState.upsert({
        where: { source: "magnus" },
        create: {
          id: "magnus",
          source: "magnus",
          status: "healthy",
          lastSuccessAt: observedAt,
        },
        update: {
          status: "healthy",
          lastSuccessAt: observedAt,
          lastErrorAt: null,
          lastError: null,
        },
      });
    } catch (error) {
      lastMagnusSourceStateTouchAt = 0;
      throw error;
    }
  }
  const degraded = services.filter(
    (service) =>
      service.name && isSecurityRelevantServiceStatus(service.status),
  );
  if (degraded.length === 0) return;
  const day = observedAt.toISOString().slice(0, 10);
  const candidates = degraded.slice(0, 50).map((service) => {
    const sourceEventId = `${nodeId}:${service.name}:${service.status}:${day}`;
    return { service, sourceEventId };
  });
  const existing = await db.securityFusionEvent.findMany({
    where: {
      source: "magnus",
      sourceEventId: {
        in: candidates.map(({ sourceEventId }) => sourceEventId),
      },
    },
    select: { sourceEventId: true },
  });
  const existingIds = new Set(existing.map((event) => event.sourceEventId));
  const unseen = candidates.filter(
    ({ sourceEventId }) => !existingIds.has(sourceEventId),
  );
  if (unseen.length === 0) return;
  await ingestSecurityFusionBatch({
    schemaVersion: "1.0",
    collectorId: "magnus-control-api",
    sentAt: observedAt.toISOString(),
    events: unseen.map(({ service, sourceEventId }) => {
      return {
        schemaVersion: "1.0",
        eventId: sha256(`magnus:${sourceEventId}`),
        source: "magnus",
        sourceEventId,
        kind: "magnus.service.health",
        observedAt: observedAt.toISOString(),
        severity: service.status === "failed" ? "high" : "medium",
        confidence: 0.88,
        summary: `${service.name} reported ${service.status} on ${nodeName}`,
        entities: [
          { type: "host", value: nodeName },
          { type: "service", value: service.name!, label: service.name! },
        ],
        attributes: { nodeId, serviceStatus: service.status },
        evidence: [
          {
            sourceLocator: `magnus-heartbeat:${nodeId}:${day}`,
            mediaType: "application/json",
          },
        ],
      };
    }),
  });
}

export async function saveInvestigation(
  caseId: string,
  authorId: string,
  draft: SecurityFusionInvestigationDraft,
) {
  const { saveLabAwareInvestigation } = await import("./investigation-lab.js");
  return saveLabAwareInvestigation(caseId, authorId, draft);
}

export async function preserveEvidence(
  caseId: string,
  eventId: string,
  actorId: string,
) {
  const [event, caseLink] = await Promise.all([
    getDb().securityFusionEvent.findUnique({ where: { id: eventId } }),
    getDb().securityFusionCaseEvent.findUnique({
      where: { caseId_eventId: { caseId, eventId } },
      select: { id: true },
    }),
  ]);
  if (!event || !caseLink) {
    incMetric("securityFusionEvidenceRejected");
    throw new HttpError(404, "NOT_FOUND", "Security case evidence not found");
  }
  const payload = canonicalJson({
    eventId: event.eventId,
    source: event.source,
    sourceEventId: event.sourceEventId,
    kind: event.kind,
    observedAt: event.observedAt.toISOString(),
    severity: event.severity,
    confidence: event.confidence,
    summary: event.summary,
    attributes: JSON.parse(event.attributesJson),
    integritySha256: event.integritySha256,
  });
  const digest = sha256(payload);
  const byteSize = Buffer.byteLength(payload, "utf8");
  if (byteSize > SECURITY_FUSION_RETENTION_POLICY.maxSingleEvidenceBytes) {
    incMetric("securityFusionEvidenceRejected");
    throw new HttpError(
      413,
      "EVIDENCE_TOO_LARGE",
      "Preserved evidence exceeds the per-artifact byte limit",
    );
  }
  const base = resolve(
    process.env["SECURITY_FUSION_EVIDENCE_DIR"] ??
      "./state/security-fusion/evidence",
  );
  const dir = join(base, digest.slice(0, 2));
  await ensurePrivateEvidenceDirectory(dir);
  const evidenceId = randomUUID();
  const target = join(dir, `${digest}.${evidenceId}.json`);
  const temporary = `${target}.${randomBytes(6).toString("hex")}.partial`;
  await writeFile(temporary, payload, { encoding: "utf8", mode: 0o600 });
  const staged = await readFile(temporary, "utf8");
  if (sha256(staged) !== digest) {
    await unlink(temporary).catch(() => undefined);
    throw new Error("EVIDENCE_HASH_MISMATCH");
  }
  let promoted = false;
  try {
    const row = await getDb().$transaction(async (tx) => {
      await tx.$queryRaw`SELECT "id" FROM "security_fusion_cases" WHERE "id" = ${caseId} FOR UPDATE`;
      const [existing, count, bytes] = await Promise.all([
        tx.securityFusionEvidence.findFirst({
          where: { caseId, eventId },
          select: { id: true },
        }),
        tx.securityFusionEvidence.count({ where: { caseId } }),
        tx.securityFusionEvidence.aggregate({
          where: { caseId },
          _sum: { byteSize: true },
        }),
      ]);
      if (existing) {
        throw new HttpError(
          409,
          "EVIDENCE_ALREADY_PRESERVED",
          "This event is already preserved for the case",
        );
      }
      const admission = evaluateSecurityFusionEvidenceAdmission(
        count,
        bytes._sum.byteSize ?? 0,
        byteSize,
      );
      if (admission !== "accepted") {
        throw new HttpError(
          409,
          "EVIDENCE_CASE_LIMIT",
          "The case has reached its preserved-evidence ceiling",
        );
      }
      await rename(temporary, target);
      promoted = true;
      const created = await tx.securityFusionEvidence.create({
        data: {
          id: evidenceId,
          caseId,
          eventId,
          sourceLocator: `${event.source}:${event.sourceEventId}`,
          mediaType: "application/json",
          sha256: digest,
          storagePath: target,
          preservedBy: actorId,
          expiresAt: new Date(
            Date.now() +
              SECURITY_FUSION_RETENTION_POLICY.evidenceDays * 24 * 60 * 60_000,
          ),
          byteSize,
        },
      });
      await tx.securityFusionCaseActivity.create({
        data: {
          caseId,
          kind: "evidence.preserved",
          actorId,
          detailJson: JSON.stringify({
            evidenceId: created.id,
            eventId,
            sha256: digest,
            sourceLocator: created.sourceLocator,
            byteSize,
          }),
        },
      });
      return created;
    });
    incMetric("securityFusionEvidenceAccepted");
    return row;
  } catch (error) {
    await unlink(promoted ? target : temporary).catch(() => undefined);
    incMetric("securityFusionEvidenceRejected");
    throw error;
  }
}

type EvidenceForDeletion = {
  id: string;
  caseId: string;
  sha256: string;
  storagePath: string;
  byteSize: number;
};

function deletionReceiptData(
  resourceType: string,
  resourceId: string,
  reason: string,
  outcome: string,
  bytesDeleted: number,
  detail: Record<string, unknown>,
  deletedAt: Date,
): DeletionReceiptInput {
  const resourceIdHash = sha256(resourceId);
  const detailJson = canonicalJson(detail);
  return {
    resourceType,
    resourceIdHash,
    reason,
    outcome,
    bytesDeleted,
    detailJson,
    deletedAt,
  };
}

async function deleteEvidenceWithReceipts(
  evidenceRows: EvidenceForDeletion[],
  reason: string,
  deletedAt: Date,
): Promise<number> {
  if (evidenceRows.length === 0) return 0;
  const receipts: DeletionReceiptInput[] = [];
  for (const evidence of evidenceRows) {
    let outcome = "deleted";
    try {
      await unlink(evidence.storagePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT")
        outcome = "already_missing";
      else throw error;
    }
    receipts.push(
      deletionReceiptData(
        "evidence",
        evidence.id,
        reason,
        outcome,
        evidence.byteSize,
        {
          caseIdHash: sha256(evidence.caseId),
          contentSha256: evidence.sha256,
        },
        deletedAt,
      ),
    );
  }
  const head = await getDb().$transaction(async (tx) => {
    await tx.securityFusionEvidence.deleteMany({
      where: { id: { in: evidenceRows.map((row) => row.id) } },
    });
    return appendDeletionReceipts(tx, receipts);
  });
  await exportReceiptChainHead(head);
  incMetric("securityFusionEvidenceDeleted", evidenceRows.length);
  return evidenceRows.length;
}

async function deleteArchivedCase(
  caseId: string,
  archivedAt: Date,
  deletedAt: Date,
): Promise<void> {
  const db = getDb();
  const [evidence, oldActions, counts] = await Promise.all([
    db.securityFusionEvidence.findMany({
      where: { caseId },
      select: {
        id: true,
        caseId: true,
        sha256: true,
        storagePath: true,
        byteSize: true,
      },
    }),
    db.securityFusionAction.findMany({
      where: { caseId },
      select: { id: true },
    }),
    Promise.all([
      db.securityFusionCaseEvent.count({ where: { caseId } }),
      db.securityFusionCaseEntity.count({ where: { caseId } }),
      db.securityFusionCaseActivity.count({ where: { caseId } }),
      db.securityFusionInvestigation.count({ where: { caseId } }),
      db.securityFusionAction.count({ where: { caseId } }),
      db.securityFusionCaseRelationship.count({
        where: { OR: [{ fromCaseId: caseId }, { toCaseId: caseId }] },
      }),
    ]),
  ]);
  await deleteEvidenceWithReceipts(evidence, "case_retention", deletedAt);
  const actionIds = oldActions.map((row) => row.id);
  const receipt = deletionReceiptData(
    "case",
    caseId,
    "archive_grace_expired",
    "deleted",
    evidence.reduce((sum, row) => sum + row.byteSize, 0),
    {
      archivedAt: archivedAt.toISOString(),
      childCounts: {
        events: counts[0],
        entities: counts[1],
        activity: counts[2],
        investigations: counts[3],
        actions: counts[4],
        relationships: counts[5],
        evidence: evidence.length,
      },
    },
    deletedAt,
  );
  const head = await db.$transaction(async (tx) => {
    await tx.securityFusionCaseRelationship.deleteMany({
      where: { OR: [{ fromCaseId: caseId }, { toCaseId: caseId }] },
    });
    await tx.securityFusionCaseActivity.deleteMany({ where: { caseId } });
    const labRuns = await tx.securityFusionLabRun.findMany({ where: { caseId }, select: { id: true } });
    const runIds = labRuns.map(row => row.id);
    await tx.securityFusionLabSimulation.deleteMany({ where: { runId: { in: runIds } } });
    await tx.securityFusionLabCheckpoint.deleteMany({ where: { runId: { in: runIds } } });
    await tx.securityFusionLabRun.deleteMany({ where: { caseId } });
    await tx.securityFusionInvestigation.deleteMany({ where: { caseId } });
    await tx.securityFusionCaseEntity.deleteMany({ where: { caseId } });
    await tx.securityFusionCaseEvent.deleteMany({ where: { caseId } });
    await tx.securityFusionDelivery.deleteMany({ where: { caseId } });
    await tx.securityFusionCommandOutbox.deleteMany({
      where: { actionId: { in: actionIds } },
    });
    await tx.securityFusionActionApproval.deleteMany({
      where: { actionId: { in: actionIds } },
    });
    await tx.securityFusionAction.deleteMany({ where: { caseId } });
    await tx.securityFusionCase.delete({ where: { id: caseId } });
    return appendDeletionReceipts(tx, [receipt]);
  });
  await exportReceiptChainHead(head);
  incMetric("securityFusionCasesDeleted");
}

async function compactOverfullSecurityFusionCases(
  compactedAt: Date,
): Promise<number> {
  const db = getDb();
  const overfullCases = await db.$queryRaw<
    Array<{ caseId: string; count: number }>
  >`
    SELECT "caseId", COUNT(*)::int AS count
    FROM "security_fusion_case_events"
    GROUP BY "caseId"
    HAVING COUNT(*) > ${SECURITY_FUSION_RETENTION_POLICY.maxCaseEvents}
  `;
  let truncated = 0;
  for (const caseRow of overfullCases) {
    const excessLinks = await db.$queryRaw<
      Array<{ id: string; eventId: string }>
    >`
      SELECT ce."id", ce."eventId"
      FROM "security_fusion_case_events" ce
      JOIN "security_fusion_events" e ON e."id" = ce."eventId"
      WHERE ce."caseId" = ${caseRow.caseId}
      ORDER BY e."observedAt" DESC, ce."id" DESC
      OFFSET ${SECURITY_FUSION_RETENTION_POLICY.maxCaseEvents}
    `;
    if (excessLinks.length === 0) continue;
    const excessActivity = await db.$queryRaw<Array<{ id: string }>>`
      SELECT "id"
      FROM "security_fusion_case_activity"
      WHERE "caseId" = ${caseRow.caseId}
        AND "kind" = 'evidence.merged'
      ORDER BY "createdAt" ASC, "id" ASC
      LIMIT ${excessLinks.length}
    `;
    const linkIds = excessLinks.map((row) => row.id);
    const activityIds = excessActivity.map((row) => row.id);
    const receipt = deletionReceiptData(
      "case_evidence_links",
      `${caseRow.caseId}:${linkIds.sort().join(":")}`,
      "per_case_ceiling_compaction",
      "truncated",
      0,
      {
        caseIdHash: sha256(caseRow.caseId),
        linksDeleted: linkIds.length,
        activitiesDeleted: activityIds.length,
        retainedCeiling: SECURITY_FUSION_RETENTION_POLICY.maxCaseEvents,
      },
      compactedAt,
    );
    const head = await db.$transaction(async (tx) => {
      await tx.securityFusionCaseActivity.deleteMany({
        where: { id: { in: activityIds } },
      });
      await tx.securityFusionCaseEvent.deleteMany({
        where: { id: { in: linkIds } },
      });
      await tx.securityFusionCase.update({
        where: { id: caseRow.caseId },
        data: {
          evidenceAcceptedCount: SECURITY_FUSION_RETENTION_POLICY.maxCaseEvents,
          evidenceTruncatedCount: { increment: linkIds.length },
        },
      });
      return appendDeletionReceipts(tx, [receipt]);
    });
    await exportReceiptChainHead(head);
    truncated += linkIds.length;
  }
  incMetric("securityFusionEvidenceTruncated", truncated);
  return truncated;
}

export async function purgeSecurityFusion(now = new Date()): Promise<{
  events: number;
  evidence: number;
  truncatedEvidence: number;
  archivedCases: number;
  deletedCases: number;
  receipts: number;
}> {
  if(isRehearsal())return {events:0,evidence:0,truncatedEvidence:0,archivedCases:0,deletedCases:0,receipts:0};
  const eventCutoff = new Date(
    now.getTime() -
      SECURITY_FUSION_RETENTION_POLICY.eventDays * 24 * 60 * 60_000,
  );
  const caseArchiveCutoff = new Date(
    now.getTime() -
      SECURITY_FUSION_RETENTION_POLICY.caseArchiveDays * 24 * 60 * 60_000,
  );
  const caseDeleteCutoff = new Date(
    now.getTime() -
      SECURITY_FUSION_RETENTION_POLICY.archiveGraceDays * 24 * 60 * 60_000,
  );
  const receiptCutoff = new Date(
    now.getTime() -
      SECURITY_FUSION_RETENTION_POLICY.deletionReceiptDays * 24 * 60 * 60_000,
  );
  const [oldEvents, expiredEvidence, casesToDelete] = await Promise.all([
    getDb().securityFusionEvent.findMany({
      where: { ingestedAt: { lt: eventCutoff } },
      select: { id: true },
    }),
    getDb().securityFusionEvidence.findMany({
      where: { expiresAt: { lt: now } },
      select: {
        id: true,
        caseId: true,
        sha256: true,
        storagePath: true,
        byteSize: true,
      },
    }),
    getDb().securityFusionCase.findMany({
      where: { archivedAt: { lt: caseDeleteCutoff } },
      select: { id: true, archivedAt: true },
    }),
  ]);
  const truncatedEvidence = await compactOverfullSecurityFusionCases(now);
  const evidenceDeleted = await deleteEvidenceWithReceipts(
    expiredEvidence,
    "evidence_retention",
    now,
  );
  for (const caseRow of casesToDelete) {
    if (caseRow.archivedAt)
      await deleteArchivedCase(caseRow.id, caseRow.archivedAt, now);
  }
  const eventIds = oldEvents.map((row) => row.id);
  const eventReceipt =
    eventIds.length === 0
      ? null
      : deletionReceiptData(
          "event_batch",
          eventIds.sort().join(":"),
          "event_retention",
          "deleted",
          0,
          { count: eventIds.length, cutoff: eventCutoff.toISOString() },
          now,
        );
  const archiveResult = await getDb().securityFusionCase.updateMany({
    where: { archivedAt: null, lastSeenAt: { lt: caseArchiveCutoff } },
    data: { archivedAt: now },
  });
  incMetric("securityFusionCasesArchived", archiveResult.count);
  const transactionResult = await getDb().$transaction(async (tx) => {
    await tx.securityFusionCaseEvent.deleteMany({
      where: { eventId: { in: eventIds } },
    });
    await tx.securityFusionEventEntity.deleteMany({
      where: { eventId: { in: eventIds } },
    });
    await tx.securityFusionEvent.deleteMany({
      where: { id: { in: eventIds } },
    });
    await tx.securityFusionNonce.deleteMany({
      where: { expiresAt: { lt: now } },
    });
    const receiptDeletionResult =
      await tx.securityFusionDeletionReceipt.deleteMany({
        where: { deletedAt: { lt: receiptCutoff } },
      });
    const head = await appendDeletionReceipts(
      tx,
      eventReceipt ? [eventReceipt] : [],
    );
    return { receiptDeletionResult, head };
  });
  await exportReceiptChainHead(transactionResult.head);
  return {
    events: eventIds.length,
    evidence: evidenceDeleted,
    truncatedEvidence,
    archivedCases: archiveResult.count,
    deletedCases: casesToDelete.length,
    receipts: transactionResult.receiptDeletionResult.count,
  };
}

let retentionTimer: ReturnType<typeof setInterval> | null = null;

export function startSecurityFusionRetention(): void {
  if (retentionTimer || !securityWritesEnabled()) return;
  void purgeSecurityFusion().catch((error: unknown) =>
    console.error("[security-fusion] retention failed", error),
  );
  retentionTimer = setInterval(() => {
    if (!securityWritesEnabled()) return;
    void purgeSecurityFusion().catch((error: unknown) =>
      console.error("[security-fusion] retention failed", error),
    );
  }, 60 * 60_000);
  retentionTimer.unref();
}

export function stopSecurityFusionRetention(): void {
  if (retentionTimer) clearInterval(retentionTimer);
  retentionTimer = null;
}
