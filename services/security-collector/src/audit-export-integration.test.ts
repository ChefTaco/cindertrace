import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
  hiveAuditRecordSchema,
  securityFusionEventBatchSchema,
  type SecurityFusionEventBatch,
} from "@cindertrace/contracts";

/**
 * The collector process against a stub Oathweave token endpoint and stub
 * products that page HiveAuditRecord v1 the way hive-common `feedPage` does:
 * oldest first, strictly after an opaque cursor, `nextCursor` the last record's
 * cursor on every page with records and `null` only when caught up (Amendment 1).
 */

let state: string | undefined;
afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  if (state) rmSync(state, { recursive: true });
  state = undefined;
});

const encodeCursor = (position: object) =>
  Buffer.from(JSON.stringify(position)).toString("base64url");
const SECRET_DETAIL = "never-log-this-detail";
const records = Array.from({ length: 250 }, (_, index) =>
  hiveAuditRecordSchema.parse({
    id: `hivemem:audit:${index + 1}`,
    product: "hivemem",
    occurredAt: new Date(Date.UTC(2026, 10, 12, 10, 0, index)).toISOString(),
    action: index === 0 ? "memory.delete" : "memory.create",
    outcome: "success",
    actor: { type: "service", id: "svc-writer" },
    subject: { actorId: "ardent-writer", nodeId: "node-1" },
    details: { note: SECRET_DETAIL },
  }),
);

interface Stub {
  tokenRequests: string[];
  productRequests: Array<{ source: string; after: string | null }>;
  batches: SecurityFusionEventBatch[];
  report?: { sources: Array<{ source: string; status: string; error?: string }> };
}

function stubNetwork(checkpoints: Record<string, string>): Stub {
  const stub: Stub = { tokenRequests: [], productRequests: [], batches: [] };
  const issued = new Map<string, string>();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = new URL(input);
      if (url.host === "api.example.com") {
        if (url.pathname.endsWith("/checkpoints"))
          return Response.json({
            success: true,
            allowedSources: ["hivemem", "embermend"],
            data: checkpoints,
          });
        if (url.pathname.endsWith("/ingest/events")) {
          stub.batches.push(securityFusionEventBatchSchema.parse(JSON.parse(String(init?.body))));
          return Response.json({ success: true }, { status: 202 });
        }
        if (url.pathname.endsWith("/source-status")) {
          stub.report = JSON.parse(String(init?.body));
          return Response.json({ success: true }, { status: 202 });
        }
      }
      if (url.host === "iam.example.com" && url.pathname === "/api/v1/oauth/token") {
        const body = new URLSearchParams(String(init?.body));
        if (body.get("client_id") !== "cindertrace-audit" || body.get("client_secret") !== "fixture-audit-client")
          return Response.json({ error: "invalid_client" }, { status: 401 });
        const audience = body.get("audience")!;
        stub.tokenRequests.push(audience);
        const token = `token-${audience}-${stub.tokenRequests.length}`;
        issued.set(token, body.get("scope")!);
        return Response.json({ access_token: token, expires_in: 900, token_type: "Bearer" });
      }
      if (url.host === "hivemem.example.com" && url.pathname === "/v1/audit/export") {
        const auth = new Headers(init?.headers).get("authorization")?.replace(/^Bearer /, "");
        if (!auth || !issued.has(auth)) return Response.json({ error: "unauthorized" }, { status: 401 });
        if (!issued.get(auth)!.split(" ").includes("hivemem:audit:read"))
          return Response.json({ error: "forbidden" }, { status: 403 });
        const after = url.searchParams.get("after");
        stub.productRequests.push({ source: "hivemem", after });
        const limit = Number(url.searchParams.get("limit") ?? 100);
        let start = 0;
        if (after) {
          const position = JSON.parse(Buffer.from(after, "base64url").toString()) as { id: number };
          start = position.id;
        }
        const data = records.slice(start, start + limit);
        return Response.json({
          data,
          nextCursor: data.length ? encodeCursor({ id: start + data.length }) : null,
        });
      }
      if (url.host === "embermend.example.com") {
        stub.productRequests.push({ source: "embermend", after: url.searchParams.get("after") });
        return Response.json({ error: "unavailable" }, { status: 503 });
      }
      throw new Error(`Unexpected request ${url.host}${url.pathname}`);
    }),
  );
  return stub;
}

async function startCollector(checkpoints: Record<string, string>): Promise<{ stub: Stub; logs: string[] }> {
  // A restart: the previous process's timers stop and the module loads fresh.
  vi.clearAllTimers();
  vi.restoreAllMocks();
  vi.resetModules();
  vi.useFakeTimers();
  state ??= mkdtempSync(join(tmpdir(), "cindertrace-audit-export-"));
  for (const name of Object.keys(process.env)) vi.stubEnv(name, undefined);
  for (const [name, value] of Object.entries({
    CINDERTRACE_API_URL: "https://api.example.com",
    SECURITY_FUSION_INGEST_SECRET: "fixture-ingest-credential-".repeat(2),
    SECURITY_FUSION_STATE_DIR: state,
    SECURITY_COLLECTOR_AUDIT_OATHWEAVE_URL: "https://iam.example.com",
    SECURITY_COLLECTOR_AUDIT_CLIENT_ID: "cindertrace-audit",
    SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET: "fixture-audit-client",
    SECURITY_COLLECTOR_AUDIT_SOURCES_JSON: JSON.stringify([
      { source: "hivemem", url: "https://hivemem.example.com/v1/audit/export", audience: "hivemem" },
      { source: "embermend", url: "https://embermend.example.com/api/v1/audit/export", audience: "embermend" },
    ]),
  }))
    vi.stubEnv(name, value);
  const logs: string[] = [];
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  });
  const stub = stubNetwork(checkpoints);
  await import("./index.js");
  await vi.waitFor(() => expect(stub.report).toBeDefined());
  return { stub, logs };
}

it("collects from a stub product, isolates a failing source and resumes from the stored checkpoint", async () => {
  const first = await startCollector({});
  const cursor200 = encodeCursor({ id: 200 });
  const cursor250 = encodeCursor({ id: 250 });
  expect(first.stub.productRequests.filter((r) => r.source === "hivemem").map((r) => r.after)).toEqual([
    null,
    cursor200,
    cursor250,
  ]);
  // One cached token per product audience for the whole poll.
  expect(first.stub.tokenRequests.sort()).toEqual(["embermend", "hivemem"]);
  expect(first.stub.report!.sources).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ source: "hivemem", status: "healthy" }),
      expect.objectContaining({ source: "embermend", status: "error", error: "embermend audit export returned 503" }),
    ]),
  );
  for (let tick = 0; tick < 4; tick++) await vi.advanceTimersByTimeAsync(2_000);
  const events = first.stub.batches.flatMap((batch) => batch.events);
  expect(events).toHaveLength(250);
  expect(events[0]).toMatchObject({
    source: "hivemem",
    kind: "hivemem.memory.delete",
    severity: "medium",
    entities: [
      { type: "service", value: "svc-writer" },
      { type: "agent", value: "actor:ardent-writer" },
    ],
  });
  expect(first.stub.batches.at(-1)!.checkpoints).toEqual({ hivemem: cursor250 });
  expect(first.logs.join("\n")).not.toContain(SECRET_DETAIL);
  expect(first.logs.join("\n")).toContain("embermend audit export poll failed: embermend audit export returned 503");

  // Restart: the collector reads the checkpoint the API stored and continues after it.
  const second = await startCollector({ hivemem: cursor250 });
  expect(second.stub.productRequests.filter((r) => r.source === "hivemem").map((r) => r.after)).toEqual([
    cursor250,
  ]);
  expect(second.stub.batches).toEqual([]);
  expect(second.stub.report!.sources).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ source: "hivemem", status: "healthy", checkpoint: cursor250 }),
    ]),
  );
});
