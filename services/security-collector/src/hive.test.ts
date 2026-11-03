import { describe, expect, it } from "vitest";
import { collectHiveSecurity } from "./hive.js";
const result = (body: unknown, status = 200) => ({
  response: new Response(null, { status }),
  body: new TextEncoder().encode(JSON.stringify(body)),
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
      iamUrl: "https://iam.example.com/api/v1",
      clientId: "security-exporter",
      secret: "fixture-oauth",
      enqueue: () => true,
      request: async (input) => {
        const path = new URL(input).pathname;
        calls.push(path);
        return path === "/api/v1/oauth/token"
          ? result({ access_token: "fixture-access" })
          : result({ events: [], total: 0 });
      },
    });
    expect(calls).toEqual(["/api/v1/oauth/token", "/api/v1/audit"]);
  });
  it("paginates a fixed audit window and recovers a legacy Router cursor with scoped OAuth", async () => {
    const calls: URL[] = [],
      events: unknown[] = [];
    let routerCalls = 0;
    const checkpoint = await collectHiveSecurity({
      iamUrl: "https://iam.example.com",
      clientId: "security-exporter",
      secret: "fixture-oauth",
      routerUrl: "https://router.example.com/api/security/events",
      checkpoint: "old-cursor",
      now: new Date("2026-11-03T12:01:00Z"),
      enqueue: (event) => {
        events.push(event);
        return true;
      },
      request: async (input, init) => {
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
      },
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
        iamUrl: "https://iam.example.com",
        clientId: "security-exporter",
        secret: "fixture-oauth",
        enqueue: () => false,
        request: async (input) =>
          new URL(input).pathname === "/api/v1/oauth/token"
            ? result({ access_token: "fixture-access" })
            : result({ events: [row("example")], total: 1 }),
      }),
    ).rejects.toThrow("checkpoint held");
  });
});
