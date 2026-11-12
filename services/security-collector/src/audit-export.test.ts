import { describe, expect, it } from "vitest";
import {
  securityFusionEventSchema,
  type HiveAuditRecord,
  type SecurityFusionEvent,
} from "@cindertrace/contracts";
import {
  OathweaveTokenCache,
  auditRecordEvent,
  auditSeverity,
  oathweaveTokenUrl,
  pollAuditSource,
  readAuditExportConfig,
  type AuditSourceConfig,
  type ClientCredentials,
} from "./audit-export.js";

const result = (body: unknown, status = 200) => ({
  response: new Response(null, { status }),
  body: new TextEncoder().encode(JSON.stringify(body)),
});

const credentials: ClientCredentials = {
  tokenUrl: "https://iam.example.com/api/v1/oauth/token",
  clientId: "cindertrace-audit",
  clientSecret: "fixture-client-credential",
};

const config: AuditSourceConfig = {
  source: "hivemem",
  url: "https://hivemem.example.com/v1/audit/export",
  audience: "hivemem",
  scope: "hivemem:audit:read",
  credentials,
};

function record(n: number, overrides: Partial<HiveAuditRecord> = {}): HiveAuditRecord {
  return {
    id: `hivemem:audit:${n}`,
    product: "hivemem",
    occurredAt: `2026-11-12T10:00:${String(n % 60).padStart(2, "0")}Z`,
    action: "memory.create",
    outcome: "success",
    actor: { type: "service", id: "svc-writer" },
    details: {},
    ...overrides,
  };
}

describe("audit export configuration", () => {
  const base = {
    SECURITY_COLLECTOR_AUDIT_OATHWEAVE_URL: "https://iam.example.com",
    SECURITY_COLLECTOR_AUDIT_CLIENT_ID: "cindertrace-audit",
    SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET: "fixture-client-credential",
  };
  it("is off without sources", () => {
    expect(readAuditExportConfig({})).toBeNull();
    expect(() =>
      readAuditExportConfig({ SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET: "x" }),
    ).toThrow("SOURCES_JSON");
  });
  it("reads sources, defaults the scope and shares one client", () => {
    const sources = readAuditExportConfig({
      ...base,
      SECURITY_COLLECTOR_AUDIT_SOURCES_JSON: JSON.stringify([
        { source: "hivemem", url: "https://hivemem.example.com/v1/audit/export", audience: "hivemem" },
        {
          source: "embermend",
          url: "https://embermend.example.com/api/v1/audit/export",
          audience: "embermend",
          scope: "embermend:audit:read",
        },
      ]),
    })!;
    expect(sources.map((s) => [s.source, s.scope])).toEqual([
      ["hivemem", "hivemem:audit:read"],
      ["embermend", "embermend:audit:read"],
    ]);
    expect(sources[0]!.credentials).toEqual(credentials);
    expect(sources[1]!.credentials).toBe(sources[0]!.credentials);
  });
  it("reads secret files and per-source clients", () => {
    const files: Record<string, string> = {
      "/run/secrets/shared": "shared-credential\n",
      "/run/secrets/skills": "skills-credential\n",
    };
    const sources = readAuditExportConfig(
      {
        SECURITY_COLLECTOR_AUDIT_OATHWEAVE_URL: "https://iam.example.com/api/v1/",
        SECURITY_COLLECTOR_AUDIT_CLIENT_ID: "cindertrace-audit",
        SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET_FILE: "/run/secrets/shared",
        SECURITY_COLLECTOR_AUDIT_SOURCES_JSON: JSON.stringify([
          { source: "hivemem", url: "https://m.example.com/v1/audit/export", audience: "hivemem" },
          {
            source: "hiveskills",
            url: "https://s.example.com/v1/audit/export",
            audience: "hiveskills",
            clientId: "cindertrace-skills-audit",
            clientSecretFile: "/run/secrets/skills",
          },
        ]),
      },
      (path) => files[path]!,
    )!;
    expect(sources[0]!.credentials.clientSecret).toBe("shared-credential");
    expect(sources[0]!.credentials.tokenUrl).toBe(credentials.tokenUrl);
    expect(sources[1]!.credentials).toMatchObject({
      clientId: "cindertrace-skills-audit",
      clientSecret: "skills-credential",
    });
  });
  it.each([
    [[{ source: "magnus", url: "https://x.example.com", audience: "a" }], "source must be one of"],
    [[{ source: "hivemem", url: "http://x.example.com", audience: "a" }], "HTTPS"],
    [[{ source: "hivemem", url: "https://u:p@x.example.com", audience: "a" }], "HTTPS"],
    [[{ source: "hivemem", url: "https://x.example.com" }], "audience"],
    [
      [
        { source: "hivemem", url: "https://x.example.com", audience: "a" },
        { source: "hivemem", url: "https://y.example.com", audience: "a" },
      ],
      "twice",
    ],
  ])("rejects %j", (sources, message) => {
    expect(() =>
      readAuditExportConfig({ ...base, SECURITY_COLLECTOR_AUDIT_SOURCES_JSON: JSON.stringify(sources) }),
    ).toThrow(message);
  });
  it("requires one client secret", () => {
    const json = JSON.stringify([{ source: "hivemem", url: "https://x.example.com", audience: "a" }]);
    expect(() =>
      readAuditExportConfig({
        ...base,
        SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET: undefined,
        SECURITY_COLLECTOR_AUDIT_SOURCES_JSON: json,
      }),
    ).toThrow("secret is missing");
    expect(() =>
      readAuditExportConfig({
        ...base,
        SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET_FILE: "/x",
        SECURITY_COLLECTOR_AUDIT_SOURCES_JSON: json,
      }),
    ).toThrow("not both");
    expect(oathweaveTokenUrl("https://iam.example.com/")).toBe(credentials.tokenUrl);
  });
});

describe("HiveAuditRecord mapping", () => {
  it.each([
    ["memory.read", "success", "info"],
    ["memory.create", "success", "low"],
    ["release.promote", "success", "low"],
    ["memory.delete", "success", "medium"],
    ["project.member.remove", "success", "high"],
    ["role.grant", "success", "high"],
    ["credential.rotate", "success", "high"],
    ["api_key.create", "success", "high"],
    ["memory.read", "failure", "medium"],
    ["memory.create", "failure", "medium"],
    ["memory.delete", "failure", "high"],
    ["token.revoke", "failure", "critical"],
  ] as const)("%s %s is %s", (action, outcome, severity) => {
    expect(auditSeverity(action, outcome)).toBe(severity);
  });

  it("maps a record to a valid event with agent entities from the subject", () => {
    const event = auditRecordEvent(
      record(7, {
        action: "memory.delete",
        actor: { type: "user", id: "user-123", issuer: "https://iam.example.com", displayName: "Op" },
        target: { type: "memory", id: "m-9" },
        subject: { actorId: "ardent-writer", agentRef: "node-1~writer", nodeId: "node-1" },
        details: { count: 1 },
      }),
    );
    expect(securityFusionEventSchema.parse(event)).toEqual(event);
    expect(event).toMatchObject({
      source: "hivemem",
      sourceEventId: "hivemem:audit:7",
      kind: "hivemem.memory.delete",
      observedAt: "2026-11-12T10:00:07.000Z",
      severity: "medium",
      summary: "HiveMem memory.delete by user Op on memory m-9",
      entities: [
        { type: "user", value: "user-123", label: "Op" },
        { type: "agent", value: "actor:ardent-writer" },
      ],
      attributes: {
        product: "hivemem",
        action: "memory.delete",
        outcome: "success",
        actorId: "ardent-writer",
        agentRef: "node-1~writer",
        nodeId: "node-1",
        target: { type: "memory", id: "m-9" },
        details: { count: 1 },
      },
      evidence: [{ sourceLocator: "hivemem:audit:7" }],
    });
    expect(event.eventId).toMatch(/^[0-9a-f]{64}$/);
    expect(auditRecordEvent(record(7)).eventId).toBe(event.eventId);
  });

  it("uses an agent reference, agent actors and ignores malformed subject IDs", () => {
    const byRef = auditRecordEvent(record(1, { subject: { agentRef: "node-1~writer" } }));
    expect(byRef.entities).toContainEqual({ type: "agent", value: "agent-ref:node-1~writer" });
    const agentActor = auditRecordEvent(
      record(2, { actor: { type: "agent", id: "lead" }, subject: { actorId: "lead" } }),
    );
    expect(agentActor.entities).toEqual([{ type: "agent", value: "actor:lead" }]);
    const malformed = auditRecordEvent(
      record(3, { actor: { type: "system", id: "scheduler" }, subject: { actorId: "Not Valid", nodeId: "bad node" } }),
    );
    expect(malformed.entities).toEqual([]);
    expect(malformed.attributes).not.toHaveProperty("actorId");
    expect(malformed.attributes).not.toHaveProperty("nodeId");
    expect(auditRecordEvent(record(4, { outcome: "failure" })).summary).toMatch(/failed$/);
  });
});

function tokenCache(counter: { tokens: number }, now = () => 0) {
  return new OathweaveTokenCache(async (input, init) => {
    expect(String(input)).toBe(credentials.tokenUrl);
    const body = new URLSearchParams(String(init?.body));
    expect(body.get("grant_type")).toBe("client_credentials");
    counter.tokens++;
    return result({ access_token: `token-${counter.tokens}`, expires_in: 300, token_type: "Bearer" });
  }, now);
}

describe("Oathweave token cache", () => {
  it("caches until shortly before expiry", async () => {
    let clock = 0;
    const counter = { tokens: 0 };
    const cache = tokenCache(counter, () => clock);
    expect(await cache.token(credentials, "hivemem", "hivemem:audit:read")).toBe("token-1");
    clock = 239_000;
    expect(await cache.token(credentials, "hivemem", "hivemem:audit:read")).toBe("token-1");
    clock = 240_000;
    expect(await cache.token(credentials, "hivemem", "hivemem:audit:read")).toBe("token-2");
    expect(await cache.token(credentials, "hiveskills", "hiveskills:audit:read")).toBe("token-3");
    expect(counter.tokens).toBe(3);
  });
  it("shares one in-flight request and rejects a token for another audience", async () => {
    const counter = { tokens: 0 };
    const cache = tokenCache(counter);
    await Promise.all([1, 2, 3].map(() => cache.token(credentials, "hivemem", "s")));
    expect(counter.tokens).toBe(1);
    const jwt = (aud: string) =>
      ["e30", Buffer.from(JSON.stringify({ aud })).toString("base64url"), "sig"].join(".");
    const audienceCheck = new OathweaveTokenCache(async () => result({ access_token: jwt("embermend") }));
    await expect(audienceCheck.token(credentials, "hivemem", "s")).rejects.toThrow("audience");
    const ok = new OathweaveTokenCache(async () => result({ access_token: jwt("hivemem") }));
    await expect(ok.token(credentials, "hivemem", "s")).resolves.toBe(jwt("hivemem"));
    const refused = new OathweaveTokenCache(async () => result({ error: "invalid_client" }, 401));
    await expect(refused.token(credentials, "hivemem", "s")).rejects.toThrow(
      "Oathweave token endpoint returned 401",
    );
  });
});

describe("pollAuditSource", () => {
  function server(pages: Record<string, { data: unknown[]; nextCursor: string | null }>) {
    const calls: Array<{ after: string | null; limit: string | null; auth: string }> = [];
    return {
      calls,
      request: async (input: string | URL, init?: RequestInit) => {
        const url = new URL(input);
        if (url.pathname === "/api/v1/oauth/token")
          return result({ access_token: "fresh", expires_in: 300 });
        const after = url.searchParams.get("after");
        calls.push({
          after,
          limit: url.searchParams.get("limit"),
          auth: (init?.headers as Record<string, string>)["authorization"]!,
        });
        return result(pages[after ?? ""] ?? { data: [], nextCursor: null });
      },
    };
  }

  it("resumes from the stored cursor and advances page by page", async () => {
    const stub = server({
      c1: { data: [record(2), record(3), record(3)], nextCursor: "c3" },
      c3: { data: [record(4)], nextCursor: "c4" },
    });
    const events: SecurityFusionEvent[] = [];
    const cursors: string[] = [];
    await pollAuditSource({
      config,
      tokens: new OathweaveTokenCache(stub.request),
      cursor: "c1",
      setCursor: (cursor) => cursors.push(cursor),
      request: stub.request,
      enqueue: (event) => events.push(event) > 0,
    });
    expect(stub.calls.map((c) => [c.after, c.limit])).toEqual([
      ["c1", "200"],
      ["c3", "200"],
      ["c4", "200"],
    ]);
    expect(events.map((e) => e.sourceEventId)).toEqual([
      "hivemem:audit:2",
      "hivemem:audit:3",
      "hivemem:audit:4",
    ]);
    // A repeated record is queued once; the empty page (null) leaves the checkpoint at c4.
    expect(cursors).toEqual(["c3", "c4"]);
  });

  it("starts without after= and stops at the page budget", async () => {
    const stub = server({
      "": { data: [record(1)], nextCursor: "a" },
      a: { data: [record(2)], nextCursor: "b" },
      b: { data: [record(3)], nextCursor: "c" },
    });
    const cursors: string[] = [];
    await pollAuditSource({
      config,
      tokens: new OathweaveTokenCache(stub.request),
      cursor: undefined,
      setCursor: (cursor) => cursors.push(cursor),
      request: stub.request,
      enqueue: () => true,
      maxPages: 2,
    });
    expect(stub.calls.map((c) => c.after)).toEqual([null, "a"]);
    expect(cursors).toEqual(["a", "b"]);
  });

  it("holds the checkpoint when the queue is full or a record is malformed, without logging contents", async () => {
    const full = server({ "": { data: [record(1)], nextCursor: "a" } });
    const cursors: string[] = [];
    await expect(
      pollAuditSource({
        config,
        tokens: new OathweaveTokenCache(full.request),
        cursor: undefined,
        setCursor: (cursor) => cursors.push(cursor),
        request: full.request,
        enqueue: () => false,
      }),
    ).rejects.toThrow("checkpoint held");
    const secretDetail = "do-not-log-this-detail";
    const bad = server({
      "": {
        data: [record(1), { ...record(2), outcome: secretDetail }, record(3, { product: "embermend" })],
        nextCursor: "a",
      },
    });
    const queued: SecurityFusionEvent[] = [];
    const error = await pollAuditSource({
      config,
      tokens: new OathweaveTokenCache(bad.request),
      cursor: undefined,
      setCursor: (cursor) => cursors.push(cursor),
      request: bad.request,
      enqueue: (event) => queued.push(event) > 0,
    }).catch((caught: Error) => caught);
    expect(String(error)).toContain("record 1 is not HiveAuditRecord v1 (outcome)");
    expect(String(error)).not.toContain(secretDetail);
    expect(queued).toEqual([]);
    expect(cursors).toEqual([]);
    const foreign = server({
      "": { data: [{ ...record(1), id: "embermend:audit:1", product: "embermend" }], nextCursor: null },
    });
    await expect(
      pollAuditSource({
        config,
        tokens: new OathweaveTokenCache(foreign.request),
        cursor: undefined,
        setCursor: () => undefined,
        request: foreign.request,
        enqueue: () => true,
      }),
    ).rejects.toThrow("names another product");
  });

  it("refreshes a refused token once", async () => {
    let tokens = 0;
    const seen: string[] = [];
    const request = async (input: string | URL, init?: RequestInit) => {
      const url = new URL(input);
      if (url.pathname === "/api/v1/oauth/token")
        return result({ access_token: `t${++tokens}`, expires_in: 900 });
      const auth = (init?.headers as Record<string, string>)["authorization"]!;
      seen.push(auth);
      return auth === "Bearer t1" ? result({ error: "expired" }, 401) : result({ data: [record(1)], nextCursor: null });
    };
    const cache = new OathweaveTokenCache(request);
    await pollAuditSource({ config, tokens: cache, cursor: undefined, setCursor: () => undefined, request, enqueue: () => true });
    expect(seen).toEqual(["Bearer t1", "Bearer t2"]);
    // Still refused after one refresh: fail rather than loop.
    const always = async (input: string | URL) =>
      new URL(input).pathname === "/api/v1/oauth/token"
        ? result({ access_token: `t${++tokens}` })
        : result({}, 401);
    await expect(
      pollAuditSource({
        config,
        tokens: new OathweaveTokenCache(always),
        cursor: undefined,
        setCursor: () => undefined,
        request: always,
        enqueue: () => true,
      }),
    ).rejects.toThrow("hivemem audit export returned 401");
  });
});
