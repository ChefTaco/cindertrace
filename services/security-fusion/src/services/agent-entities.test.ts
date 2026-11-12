import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SecurityFusionEvent } from "@cindertrace/contracts";

type Row = Record<string, any>;
const compound = new Set(["type_canonical", "source_canonical", "eventId_entityId", "caseId_entityId"]);
function matches(row: Row, where: Row = {}): boolean {
  return Object.entries(where).every(([key, expected]) => {
    if (compound.has(key)) return matches(row, expected);
    if (expected && typeof expected === "object" && "in" in expected) return expected.in.includes(row[key]);
    if (expected && typeof expected === "object" && "contains" in expected)
      return String(row[key]).includes(expected.contains);
    return row[key] === expected;
  });
}

/** In-memory entity tables; every other model records its calls and returns empty defaults. */
function fakeDb() {
  let sequence = 0;
  const tables: Record<string, Row[]> = {
    securityFusionEntity: [],
    securityFusionEntityAlias: [],
    securityFusionEventEntity: [],
    securityFusionCaseEntity: [],
  };
  const calls: Array<{ model: string; method: string; args: any }> = [];
  const table = (model: string) => {
    const rows = tables[model]!;
    return {
      findUnique: async ({ where }: Row) => rows.find((row) => matches(row, where)) ?? null,
      findFirst: async ({ where }: Row) => rows.find((row) => matches(row, where)) ?? null,
      findMany: async ({ where, take }: Row = {}) =>
        rows.filter((row) => matches(row, where)).slice(0, take ?? Infinity),
      count: async ({ where }: Row = {}) => rows.filter((row) => matches(row, where)).length,
      upsert: async ({ where, create, update }: Row) => {
        const row = rows.find((item) => matches(item, where));
        if (row) return Object.assign(row, update);
        const created = { id: `${model}-${++sequence}`, ...create };
        rows.push(created);
        return created;
      },
    };
  };
  const generic = (model: string) =>
    new Proxy(
      {},
      {
        get: (_target, method: string) => async (args: any) => {
          calls.push({ model, method, args });
          if (method === "findMany") return [];
          if (method === "count") return 0;
          if (method === "findUnique" && model === "securityFusionCase" && args?.select)
            return { evidenceAcceptedCount: 0 };
          if (method === "findUnique" || method === "findFirst") return null;
          return { id: `${model}-${++sequence}`, ...(args?.create ?? args?.data ?? {}) };
        },
      },
    );
  const models: Record<string, unknown> = Object.fromEntries(
    Object.keys(tables).map((model) => [model, table(model)]),
  );
  const db: any = new Proxy(
    {},
    {
      get: (_target, prop: string) =>
        prop === "$transaction"
          ? async (fn: (tx: unknown) => unknown) => fn(db)
          : prop === "$queryRaw"
            ? async () => []
            : (models[prop] ??= generic(prop)),
    },
  );
  return { db, tables, calls };
}

let current = fakeDb();
vi.mock("../db/index.js", () => ({ getDb: () => current.db }));

const {
  agentIdentityFromAttributes,
  derivedMagnusAgentEntity,
  resolveAgentEntityIds,
  upsertAgentEntity,
} = await import("./agent-entities.js");
const { correlationAnchor, ingestSecurityFusionBatch, resolveCaseFilterEntityIds } =
  await import("./security-fusion-service.js");

beforeEach(() => {
  current = fakeDb();
});

const at = new Date("2026-11-12T10:00:00.000Z");
const magnusEvent = (attributes: Record<string, unknown>, entities: SecurityFusionEvent["entities"] = []): SecurityFusionEvent => ({
  schemaVersion: "1.0",
  eventId: `event-${JSON.stringify(attributes)}`,
  source: "magnus",
  sourceEventId: `source-${JSON.stringify(attributes)}`,
  kind: "magnus.service.health",
  observedAt: at.toISOString(),
  severity: "high",
  confidence: 0.88,
  summary: "synthetic service failed on node",
  entities: [
    { type: "host", value: "node-a" },
    { type: "service", value: "example.service", label: "example.service" },
    ...entities,
  ],
  attributes,
  evidence: [],
});

describe("agent identity from event attributes", () => {
  it("reads actor IDs and agent references exactly as sent", () => {
    expect(agentIdentityFromAttributes({ actorId: "lead", nodeId: "node-1", profile: "Lead" })).toEqual({
      actorId: "lead",
      agentRef: "node-1~Lead",
      nodeId: "node-1",
    });
    expect(agentIdentityFromAttributes({ agentRef: "node-1~lead" })).toEqual({
      agentRef: "node-1~lead",
      nodeId: "node-1",
    });
    expect(agentIdentityFromAttributes({ actorId: "lead" })).toEqual({ actorId: "lead" });
  });

  it("carries no agent identity for node-only or malformed attributes", () => {
    // Magnus service health events today: a node, no profile, no actor.
    expect(agentIdentityFromAttributes({ nodeId: "node-1", serviceStatus: "failed" })).toBeNull();
    expect(agentIdentityFromAttributes({ actorId: "Not Valid", profile: "lead" })).toBeNull();
    expect(agentIdentityFromAttributes({ actorId: 42 })).toBeNull();
  });

  it("drops a conflicting agent reference instead of guessing", () => {
    expect(agentIdentityFromAttributes({ agentRef: "node-1~lead", nodeId: "node-2", profile: "lead" })).toBeNull();
    expect(agentIdentityFromAttributes({ actorId: "lead", agentRef: "node-1~lead", nodeId: "node-2" })).toEqual({
      actorId: "lead",
      nodeId: "node-2",
    });
  });

  it("derives an agent entity only for Magnus events that do not already name one", () => {
    expect(derivedMagnusAgentEntity(magnusEvent({ nodeId: "node-1", actorId: "lead" }))).toEqual({
      type: "agent",
      value: "actor:lead",
    });
    expect(derivedMagnusAgentEntity(magnusEvent({ nodeId: "node-1", profile: "lead" }))).toEqual({
      type: "agent",
      value: "agent-ref:node-1~lead",
    });
    expect(derivedMagnusAgentEntity(magnusEvent({ nodeId: "node-1", serviceStatus: "failed" }))).toBeNull();
    expect(derivedMagnusAgentEntity({ ...magnusEvent({ actorId: "lead" }), source: "wazuh" })).toBeNull();
    expect(
      derivedMagnusAgentEntity(magnusEvent({ actorId: "lead" }, [{ type: "agent", value: "actor:other" }])),
    ).toBeNull();
  });
});

describe("agent entity normalization and deduplication", () => {
  it("stores actor:<actorId> canonically with node and reference aliases", async () => {
    const identity = { actorId: "lead", agentRef: "node-1~Lead", nodeId: "node-1" };
    const first = await upsertAgentEntity("event-1", at, { type: "agent", value: " actor:lead " }, identity);
    const second = await upsertAgentEntity("event-2", at, { type: "agent", value: "actor:lead" }, identity);
    expect(second).toBe(first);
    const [entity] = current.tables.securityFusionEntity;
    expect(entity).toMatchObject({ type: "agent", canonical: "actor:lead" });
    expect(JSON.parse(entity!.aliasesJson)).toEqual(["actor:lead", "magnus-node:node-1", "agent-ref:node-1~Lead"]);
    expect(current.tables.securityFusionEntityAlias.map((row) => [row.source, row.canonical, row.entityId])).toEqual([
      ["normalized", "agent:actor:lead", first],
      ["agent-ref", "agent:agent-ref:node-1~Lead", first],
    ]);
    expect(current.tables.securityFusionEventEntity).toHaveLength(2);
  });

  it("joins a bare agent reference to the actor it is bound to", async () => {
    const actor = await upsertAgentEntity("event-1", at, { type: "agent", value: "actor:lead" }, {
      actorId: "lead",
      agentRef: "node-1~lead",
      nodeId: "node-1",
    });
    const byRef = await upsertAgentEntity("event-2", at, { type: "agent", value: "agent-ref:node-1~lead" }, null);
    expect(byRef).toBe(actor);
    expect(current.tables.securityFusionEntity).toHaveLength(1);
  });

  it("keeps an unbound reference provisional and lets the actor claim it later", async () => {
    const provisional = await upsertAgentEntity("event-1", at, { type: "agent", value: "agent-ref:node-1~lead" }, null);
    expect(current.tables.securityFusionEntity[0]).toMatchObject({ canonical: "agent-ref:node-1~lead" });
    const actor = await upsertAgentEntity("event-2", at, { type: "agent", value: "actor:lead" }, {
      actorId: "lead",
      agentRef: "node-1~lead",
      nodeId: "node-1",
    });
    expect(actor).not.toBe(provisional);
    const alias = current.tables.securityFusionEntityAlias.find((row) => row.source === "agent-ref");
    expect(alias?.entityId).toBe(actor);
    // A later provisional-only event does not take the reference back.
    expect(await upsertAgentEntity("event-3", at, { type: "agent", value: "agent-ref:node-1~lead" }, null)).toBe(actor);
    expect(alias?.entityId).toBe(actor);
    // The actor's cases include the provisional history; the node finds both.
    expect(new Set(await resolveAgentEntityIds("actor:lead"))).toEqual(new Set([actor, provisional]));
    expect(new Set(await resolveAgentEntityIds("agent-ref:node-1~lead"))).toEqual(new Set([actor, provisional]));
    expect(new Set(await resolveAgentEntityIds("magnus-node:node-1"))).toEqual(new Set([actor, provisional]));
  });

  it("does not apply attribute aliases to a different agent", async () => {
    await upsertAgentEntity("event-1", at, { type: "agent", value: "actor:other" }, {
      actorId: "lead",
      agentRef: "node-1~lead",
      nodeId: "node-1",
    });
    expect(JSON.parse(current.tables.securityFusionEntity[0]!.aliasesJson)).toEqual(["actor:other"]);
    expect(await resolveAgentEntityIds("magnus-node:node-1")).toEqual([]);
    expect(await resolveAgentEntityIds("agent-ref:node-1~lead")).toEqual([]);
  });

  it("matches node aliases exactly, not by substring", async () => {
    await upsertAgentEntity("event-1", at, { type: "agent", value: "actor:lead" }, { actorId: "lead", nodeId: "node-10" });
    expect(await resolveAgentEntityIds("magnus-node:node-1")).toEqual([]);
    expect(await resolveAgentEntityIds("magnus-node:node-10")).toHaveLength(1);
    expect(await resolveAgentEntityIds("actor:missing")).toEqual([]);
    expect(await resolveAgentEntityIds("not-an-agent")).toEqual([]);
  });

  it("resolves other entity types with the existing normalization", async () => {
    current.tables.securityFusionEntity.push(
      { id: "host-1", type: "host", canonical: "web-1" },
      { id: "account-1", type: "account", canonical: "aegis_ui:example" },
    );
    expect(await resolveCaseFilterEntityIds("host", " WEB-1 ")).toEqual(["host-1"]);
    expect(await resolveCaseFilterEntityIds("account", "cindertrace_ui:example")).toEqual(["account-1"]);
  });

  it("anchors cases on non-agent entities so existing grouping is unchanged", () => {
    expect(
      correlationAnchor([
        { type: "agent", value: "actor:lead" },
        { type: "host", value: "node-a" },
      ]),
    ).toEqual({ type: "host", value: "node-a" });
    expect(correlationAnchor([{ type: "agent", value: "actor:lead" }])).toEqual({
      type: "agent",
      value: "actor:lead",
    });
  });
});

describe("Magnus ingest attaches agent entities", () => {
  const batch = (event: SecurityFusionEvent) => ({
    schemaVersion: "1.0" as const,
    collectorId: "magnus-control-api",
    sentAt: at.toISOString(),
    events: [event],
  });

  it("links the agent entity to the event and its case", async () => {
    const result = await ingestSecurityFusionBatch(batch(magnusEvent({ nodeId: "node-1", profile: "lead", actorId: "lead" })));
    expect(result.stored).toBe(1);
    const agent = current.tables.securityFusionEntity.find((row) => row.type === "agent");
    expect(agent).toMatchObject({ canonical: "actor:lead" });
    expect(current.tables.securityFusionEventEntity.map((row) => row.entityId)).toContain(agent!.id);
    expect(current.tables.securityFusionCaseEntity.map((row) => row.entityId)).toContain(agent!.id);
    // The case is still anchored on the host, as before agent entities existed.
    const opened = current.calls.find((call) => call.model === "securityFusionCase" && call.method === "upsert");
    expect(opened?.args.create.title).toContain("node-a");
  });

  it("attaches nothing for today's node-only Magnus events", async () => {
    await ingestSecurityFusionBatch(batch(magnusEvent({ nodeId: "node-1", serviceStatus: "failed" })));
    expect(current.tables.securityFusionEntity.map((row) => row.type).sort()).toEqual(["host", "service"]);
  });
});
