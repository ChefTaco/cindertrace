import { describe, expect, it } from "vitest";
import { collectHiveSecurity, hiveTokenProvider } from "./hive.js";
import type { BoundedFetchResult } from "./runtime-security.js";
const result = (body: unknown, status = 200) => ({
  response: new Response(null, { status }),
  body: new TextEncoder().encode(JSON.stringify(body)),
});
type Stub = (url: string | URL, init?: RequestInit) => Promise<BoundedFetchResult>;
/** The same stub serves the token endpoint (through fetch) and the export requests. */
const withTokens = (iamUrl: string, request: Stub) => ({
  iamUrl,
  request,
  tokens: hiveTokenProvider({
    iamUrl,
    clientId: "security-exporter",
    secret: "fixture-oauth",
    fetch: async (input, init) => {
      const { response, body } = await request(String(input), init);
      return new Response(body, { status: response.status });
    },
  }),
});
const row = (id: string) => ({
  id,
  timestamp: "2026-11-03T12:00:00Z",
  eventType: "auth.failure",
});
describe("public Hive security export contract", () => {
  it("accepts an IAM API base URL without duplicating its version prefix", async () => {
    const calls: string[] = [];
    await collectHiveSecurity({
      ...withTokens("https://iam.example.com/api/v1", async (input) => {
        const path = new URL(input).pathname;
        calls.push(path);
        return path === "/api/v1/oauth/token"
          ? result({ access_token: "fixture-access" })
          : result({ events: [], total: 0 });
      }),
      enqueue: () => true,
    });
    expect(calls).toEqual(["/api/v1/oauth/token", "/api/v1/audit"]);
  });
  it("paginates a fixed audit window and recovers a legacy Router cursor with scoped OAuth", async () => {
    const calls: URL[] = [],
      events: unknown[] = [];
    let routerCalls = 0;
    const checkpoint = await collectHiveSecurity({
      routerUrl: "https://router.example.com/api/security/events",
      checkpoint: "old-cursor",
      now: new Date("2026-11-03T12:01:00Z"),
      enqueue: (event) => {
        events.push(event);
        return true;
      },
      ...withTokens("https://iam.example.com", async (input, init) => {
        const url = new URL(input);
        calls.push(url);
        if (url.pathname === "/api/v1/oauth/token") {
          expect(String(init?.body)).toContain(
            "iam%3Aaudit%3Aread+router%3Asecurity-events%3Aread",
          );
          return result({ access_token: "fixture-access" });
        }
        expect(init?.headers).toMatchObject({
          authorization: "Bearer fixture-access",
        });
        if (url.pathname === "/api/v1/audit")
          return result({
            events:
              url.searchParams.get("page") === "1"
                ? Array.from({ length: 200 }, (_, i) => row("iam-" + i))
                : [row("last")],
            total: 201,
          });
        if (++routerCalls === 1) {
          expect(url.searchParams.get("cursor")).toBe("old-cursor");
          return result({ earliest_available_cursor: "recovery" }, 410);
        }
        expect(url.searchParams.get("cursor")).toBe("recovery");
        return result({ events: [row("router-event")], nextCursor: "next" });
      }),
    });
    expect(events).toHaveLength(202);
    expect(JSON.parse(checkpoint)).toEqual({
      version: 1,
      iamThrough: "2026-11-03T12:01:00.000Z",
      routerCursor: "next",
    });
    const auditCalls = calls.filter((x) => x.pathname === "/api/v1/audit");
    expect(auditCalls).toHaveLength(2);
    expect(auditCalls[0]!.searchParams.get("from")).toBe(
      auditCalls[1]!.searchParams.get("from"),
    );
    expect(auditCalls[0]!.searchParams.get("to")).toBe(
      auditCalls[1]!.searchParams.get("to"),
    );
  });
  it("does not return an advanced checkpoint when ingestion is full", async () => {
    await expect(
      collectHiveSecurity({
        ...withTokens("https://iam.example.com", async (input) =>
          new URL(input).pathname === "/api/v1/oauth/token"
            ? result({ access_token: "fixture-access" })
            : result({ events: [row("example")], total: 1 }),
        ),
        enqueue: () => false,
      }),
    ).rejects.toThrow("checkpoint held");
  });
  it("caches the token between polls and replaces a refused one once", async () => {
    let issued = 0;
    const seen: string[] = [];
    const options = withTokens("https://iam.example.com", async (input, init) => {
      const url = new URL(input);
      if (url.pathname === "/api/v1/oauth/token")
        return result({ access_token: `t${++issued}`, expires_in: 900 });
      const auth = (init?.headers as Record<string, string>)["authorization"]!;
      seen.push(auth);
      return auth === "Bearer t1" && seen.length > 1
        ? result({ error: "revoked" }, 401)
        : result({ events: [], total: 0 });
    });
    await collectHiveSecurity({ ...options, enqueue: () => true });
    await collectHiveSecurity({ ...options, enqueue: () => true });
    expect(seen).toEqual(["Bearer t1", "Bearer t1", "Bearer t2"]);
    expect(issued).toBe(2);
  });
  it("keeps the token endpoint status in the error", async () => {
    await expect(
      collectHiveSecurity({
        ...withTokens("https://iam.example.com", async () =>
          result({ error: "invalid_client" }, 401),
        ),
        enqueue: () => true,
      }),
    ).rejects.toThrow("Hive OAuth HTTP 401");
  });
  it("refuses a token URL that is not HTTPS at startup", () => {
    for (const iamUrl of [
      "http://iam.example.com",
      "http://127.0.0.1:4000",
      "https://user:pass@iam.example.com",
    ])
      expect(() =>
        hiveTokenProvider({ iamUrl, clientId: "security-exporter", secret: "fixture-oauth" }),
      ).toThrow("HIVE_IAM_SECURITY_URL must be an HTTPS URL");
  });
});
