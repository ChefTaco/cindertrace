import {
  agentActorIdSchema,
  agentEntityValue,
  agentProfileIdSchema,
  agentRefSchema,
  magnusNodeIdSchema,
  parseAgentEntityValue,
  type AgentEntityValue,
  type SecurityFusionEntityRef,
  type SecurityFusionEvent,
} from "@cindertrace/contracts";
import { getDb } from "../db/index.js";
import { HttpError } from "../middleware/error-handler.js";

/** Alias rows that map an agent reference to the agent entity it belongs to. */
export const AGENT_REF_ALIAS_SOURCE = "agent-ref";
const MAX_AGENT_ALIASES = 64;
const MAX_FILTER_ENTITIES = 100;

export interface AgentIdentity {
  actorId?: string;
  agentRef?: string;
  nodeId?: string;
}

function attribute(
  attributes: Record<string, unknown>,
  key: string,
  schema: { safeParse(value: unknown): { success: boolean } },
): string | undefined {
  const value = attributes[key];
  return typeof value === "string" && schema.safeParse(value).success
    ? value
    : undefined;
}

/**
 * Agent identity an event states in its attributes: `actorId`, `agentRef`, or
 * `nodeId` with `profile`. Values are used exactly as sent; nothing is derived,
 * and a conflicting node and agent reference yields no agent reference.
 */
export function agentIdentityFromAttributes(
  attributes: Record<string, unknown>,
): AgentIdentity | null {
  const actorId = attribute(attributes, "actorId", agentActorIdSchema);
  const nodeId = attribute(attributes, "nodeId", magnusNodeIdSchema);
  const profile = attribute(attributes, "profile", agentProfileIdSchema);
  const sentRef = attribute(attributes, "agentRef", agentRefSchema);
  const composed = nodeId && profile ? `${nodeId}~${profile}` : undefined;
  let agentRef = sentRef ?? composed;
  if (
    (sentRef && composed && sentRef !== composed) ||
    (agentRef && nodeId && !agentRef.startsWith(`${nodeId}~`))
  )
    agentRef = undefined;
  if (!actorId && !agentRef) return null;
  const node = nodeId ?? agentRef?.slice(0, agentRef.indexOf("~"));
  return {
    ...(actorId ? { actorId } : {}),
    ...(agentRef ? { agentRef } : {}),
    ...(node ? { nodeId: node } : {}),
  };
}

/**
 * The `agent` entity Cindertrace attaches to a Magnus event that states an agent
 * identity and does not already name an agent entity.
 */
export function derivedMagnusAgentEntity(
  event: Pick<SecurityFusionEvent, "source" | "entities" | "attributes">,
): SecurityFusionEntityRef | null {
  if (event.source !== "magnus") return null;
  if (event.entities.some((entity) => entity.type === "agent")) return null;
  const identity = agentIdentityFromAttributes(event.attributes);
  if (!identity) return null;
  return {
    type: "agent",
    value: identity.actorId
      ? agentEntityValue.actor(identity.actorId)
      : agentEntityValue.agentRef(identity.agentRef!),
  };
}

/** Aliases an agent entity gains from one event. Attribute identity applies only to the same agent. */
export function agentAliasesFor(
  value: AgentEntityValue,
  identity: AgentIdentity | null,
): string[] {
  const aliases: string[] = [];
  let agentRef: string | undefined;
  let nodeId: string | undefined;
  if (value.kind === "agent-ref") {
    agentRef = value.agentRef;
    nodeId = value.nodeId;
  } else if (value.kind === "actor" && identity?.actorId === value.actorId) {
    agentRef = identity.agentRef;
    nodeId = identity.nodeId;
  }
  if (nodeId) aliases.push(agentEntityValue.magnusNode(nodeId));
  if (agentRef) aliases.push(agentEntityValue.agentRef(agentRef));
  return aliases;
}

export function mergeAliasList(existingJson: string | undefined, additions: string[]): string {
  let existing: unknown = [];
  try {
    existing = JSON.parse(existingJson ?? "[]");
  } catch {
    existing = [];
  }
  const merged = [
    ...new Set([
      ...(Array.isArray(existing)
        ? existing.filter((item): item is string => typeof item === "string")
        : []),
      ...additions,
    ]),
  ];
  return JSON.stringify(merged.slice(0, MAX_AGENT_ALIASES));
}

const aliasCanonical = (value: string) => `agent:${value}`;

/**
 * Store an agent entity. The canonical value is `actor:<actorId>`. An event that
 * names only `agent-ref:<nodeId>~<profile>` joins the agent that reference is
 * already bound to, or else is kept as a provisional agent under that reference.
 */
export async function upsertAgentEntity(
  eventId: string,
  observedAt: Date,
  ref: SecurityFusionEntityRef,
  identity: AgentIdentity | null,
): Promise<string> {
  const db = getDb();
  const parsed = parseAgentEntityValue(ref.value);
  if (!parsed || parsed.kind === "magnus-node")
    throw new HttpError(400, "INVALID_AGENT_ENTITY", "Agent entity value is invalid");
  const aliases = agentAliasesFor(parsed, identity);
  const agentRef =
    parsed.kind === "agent-ref"
      ? parsed.agentRef
      : aliases.find((alias) => alias.startsWith("agent-ref:"))?.slice("agent-ref:".length);
  let canonical = parsed.value;
  if (parsed.kind === "agent-ref") {
    const bound = await db.securityFusionEntityAlias.findUnique({
      where: {
        source_canonical: {
          source: AGENT_REF_ALIAS_SOURCE,
          canonical: aliasCanonical(parsed.value),
        },
      },
    });
    const owner = bound
      ? await db.securityFusionEntity.findUnique({ where: { id: bound.entityId } })
      : null;
    if (owner?.type === "agent") canonical = owner.canonical;
  }
  const existing = await db.securityFusionEntity.findUnique({
    where: { type_canonical: { type: "agent", canonical } },
  });
  const aliasesJson = mergeAliasList(existing?.aliasesJson, [canonical, ...aliases]);
  const row = await db.securityFusionEntity.upsert({
    where: { type_canonical: { type: "agent", canonical } },
    create: {
      type: "agent",
      canonical,
      label: ref.label ?? canonical,
      aliasesJson,
      firstSeenAt: observedAt,
      lastSeenAt: observedAt,
    },
    update: {
      ...(ref.label ? { label: ref.label } : {}),
      aliasesJson,
      lastSeenAt: observedAt,
    },
  });
  await db.securityFusionEventEntity.upsert({
    where: { eventId_entityId: { eventId, entityId: row.id } },
    create: { eventId, entityId: row.id },
    update: {},
  });
  await db.securityFusionEntityAlias.upsert({
    where: {
      source_canonical: { source: "normalized", canonical: aliasCanonical(canonical) },
    },
    create: {
      entityId: row.id,
      source: "normalized",
      value: ref.value,
      canonical: aliasCanonical(canonical),
      firstSeenAt: observedAt,
      lastSeenAt: observedAt,
    },
    update: { entityId: row.id, value: ref.value, lastSeenAt: observedAt },
  });
  if (agentRef) {
    const refValue = agentEntityValue.agentRef(agentRef);
    // A canonical actor claims its reference; a provisional agent never takes one back.
    await db.securityFusionEntityAlias.upsert({
      where: {
        source_canonical: {
          source: AGENT_REF_ALIAS_SOURCE,
          canonical: aliasCanonical(refValue),
        },
      },
      create: {
        entityId: row.id,
        source: AGENT_REF_ALIAS_SOURCE,
        value: refValue,
        canonical: aliasCanonical(refValue),
        firstSeenAt: observedAt,
        lastSeenAt: observedAt,
      },
      update: {
        ...(canonical.startsWith("actor:") ? { entityId: row.id } : {}),
        lastSeenAt: observedAt,
      },
    });
  }
  return row.id;
}

/**
 * Agent entity IDs for a case filter value. An actor includes the provisional
 * agents of references now bound to it; a reference resolves through its alias;
 * a node resolves to every agent recorded on it.
 */
export async function resolveAgentEntityIds(value: string): Promise<string[]> {
  const db = getDb();
  const parsed = parseAgentEntityValue(value);
  if (!parsed) return [];
  const ids = new Set<string>();
  if (parsed.kind === "actor") {
    const actor = await db.securityFusionEntity.findUnique({
      where: { type_canonical: { type: "agent", canonical: parsed.value } },
    });
    if (!actor) return [];
    ids.add(actor.id);
    const refs = await db.securityFusionEntityAlias.findMany({
      where: { entityId: actor.id, source: AGENT_REF_ALIAS_SOURCE },
      take: MAX_FILTER_ENTITIES,
    });
    if (refs.length) {
      const provisional = await db.securityFusionEntity.findMany({
        where: { type: "agent", canonical: { in: refs.map((alias) => alias.value) } },
        take: MAX_FILTER_ENTITIES,
      });
      for (const row of provisional) ids.add(row.id);
    }
  } else if (parsed.kind === "agent-ref") {
    const bound = await db.securityFusionEntityAlias.findUnique({
      where: {
        source_canonical: {
          source: AGENT_REF_ALIAS_SOURCE,
          canonical: aliasCanonical(parsed.value),
        },
      },
    });
    if (bound) ids.add(bound.entityId);
    const provisional = await db.securityFusionEntity.findUnique({
      where: { type_canonical: { type: "agent", canonical: parsed.value } },
    });
    if (provisional) ids.add(provisional.id);
  } else {
    const needle = JSON.stringify(parsed.value);
    const rows = await db.securityFusionEntity.findMany({
      where: { type: "agent", aliasesJson: { contains: needle } },
      orderBy: { lastSeenAt: "desc" },
      take: MAX_FILTER_ENTITIES,
    });
    for (const row of rows)
      if ((JSON.parse(mergeAliasList(row.aliasesJson, [])) as string[]).includes(parsed.value))
        ids.add(row.id);
  }
  return [...ids].slice(0, MAX_FILTER_ENTITIES);
}
