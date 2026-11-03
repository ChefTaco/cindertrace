import { describe, it, expect, vi, afterEach } from "vitest";
import { Hono } from "hono";
import { createHash } from "node:crypto";
import { SignJWT } from "jose";
import { authMiddleware, requirePermission, requireRole } from "./auth.js";
import type { AppVariables } from "../types/index.js";
import { errorHandler } from "./error-handler.js";
const app = new Hono<AppVariables>();
app.onError(errorHandler);
app.use("*", authMiddleware, requirePermission("security-fusion:read"));
app.get("/api/v1/security-fusion/cases", (c) => c.json({ ok: true }));
app.get("/api/v1/security-fusion/sources", (c) => c.json({ ok: true }));
app.post(
  "/api/v1/security-fusion/actions/x/approve",
  requireRole("ADMIN"),
  (c) => c.json({ ok: true }),
);
afterEach(() => vi.unstubAllEnvs());
describe("independent authorization", () => {
  it("confines the Aegis workflow identity to case, evidence, preview and request lifecycle", async () => {
    const token = "w".repeat(40);
    vi.stubEnv("SECURITY_PLUGIN_WORKFLOW_TOKEN_SHA256", createHash("sha256").update(token).digest("hex"));
    for (const [method, path, allowed] of [
      ["PATCH", "/cases/c1", true],
      ["POST", "/cases/c1/evidence/e1/preserve", true],
      ["POST", "/cases/c1/actions/preview", true],
      ["POST", "/actions/a1/request", true],
      ["POST", "/actions/a1/cancel", true],
      ["POST", "/cases/c1/assurance/exposure", true],
      ["POST", "/cases/c1/assurance/investigation", true],
      ["POST", "/cases/c1/assurance/review", true],
      ["POST", "/cases/c1/assurance/closure", true],
      ["POST", "/actions/x/approve", false],
      ["POST", "/actions/a1/reject", false],
      ["POST", "/actions/a1/release", false],
      ["POST", "/source-registry/x/revoke", false],
      ["GET", "/cases", false],
      ["POST", "/cases/c1/investigations", false],
    ] as const) {
      const result = await app.request('/api/v1/security-fusion'+path, {method, headers:{Authorization:`Bearer ${token}`}});
      expect(result.status, method+' '+path).toBe(allowed ? 404 : 403);
    }
  });
  it("allows source health reads without widening plugin mutation or registry access", async () => {
    const token = "r".repeat(40);
    vi.stubEnv("SECURITY_PLUGIN_READ_DIGESTS_JSON", JSON.stringify({
      aegis: createHash("sha256").update(token).digest("hex"),
    }));
    for (const [method, path, status] of [
      ["GET", "/sources", 200],
      ["POST", "/cases/c1/assurance/exposure/preview", 404],
      ["POST", "/cases/c1/assurance/exposure", 403],
      ["POST", "/sources", 403],
      ["GET", "/sources/private", 403],
      ["GET", "/source-registry", 403],
      ["POST", "/cases/c1/investigations", 403],
      ["POST", "/actions/a1/approve", 403],
    ] as const) {
      const response = await app.request(`/api/v1/security-fusion${path}`, {
        method, headers: { Authorization: `Bearer ${token}` },
      });
      expect(response.status, `${method} ${path}`).toBe(status);
    }
  });
  it("does not grant source reads to the draft-only credential", async () => {
    const token = "d".repeat(40);
    vi.stubEnv("SECURITY_PLUGIN_READ_DIGESTS_JSON", "{}");
    vi.stubEnv("SECURITY_PLUGIN_DRAFT_TOKEN_SHA256", createHash("sha256").update(token).digest("hex"));
    const response = await app.request("/api/v1/security-fusion/sources", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(403);
  });
  it("read plugin cannot approve containment", async () => {
    const token = "a".repeat(40);
    vi.stubEnv(
      "SECURITY_PLUGIN_READ_DIGESTS_JSON",
      JSON.stringify({
        test: createHash("sha256").update(token).digest("hex"),
      }),
    );
    expect(
      (
        await app.request("/api/v1/security-fusion/cases", {
          headers: { Authorization: `Bearer ${token}` },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await app.request("/api/v1/security-fusion/actions/x/approve", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        })
      ).status,
    ).toBe(403);
  });
  it("confines the Senti bridge bearer to exact plan and decision endpoints", async () => {
    const token = "b".repeat(40);
    vi.stubEnv("SECURITY_SENTI_BRIDGE_TOKEN_SHA256", createHash("sha256").update(token).digest("hex"));
    for (const [method, path, allowed] of [
      ["GET", "/approval-plans", true], ["GET", "/approval-plans/containment:a1", true],
      ["POST", "/approval-decisions", true], ["POST", "/actions/a1/approve", false],
      ["POST", "/actions/a1/request", false], ["GET", "/cases", false],
    ] as const) {
      const response = await app.request(`/api/v1/security-fusion${path}`, {
        method, headers: { Authorization: `Bearer ${token}` },
      });
      expect(response.status, `${method} ${path}`).toBe(allowed ? 404 : 403);
    }
  });
  it("rejects a console assertion minted for Magnus", async () => {
    const secret = "s".repeat(40);
    vi.stubEnv("SECURITY_CONSOLE_TOKEN_SECRET", secret);
    const token = await new SignJWT({ userId: "u", role: "ADMIN" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("magnus")
      .setAudience("cindertrace-api")
      .setIssuedAt()
      .setExpirationTime("60s")
      .sign(new TextEncoder().encode(secret));
    expect(
      (
        await app.request("/api/v1/security-fusion/cases", {
          headers: { Authorization: `Bearer ${token}` },
        })
      ).status,
    ).toBe(401);
  });
});
