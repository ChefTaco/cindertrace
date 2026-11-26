import { describe, it, expect, vi, afterEach } from "vitest";
import { Hono } from "hono";
import { createHash } from "node:crypto";
import { SignJWT } from "jose";
import { authMiddleware, hasPermission, pluginReadDigests, requirePermission, requireRole, safeEqual, tokenMatches } from "./auth.js";
import type { AppVariables } from "../types/index.js";
import { errorHandler } from "./error-handler.js";
const app = new Hono<AppVariables>();
app.onError(errorHandler);
app.use("*", authMiddleware, requirePermission("security-fusion:read"));
app.get("/api/v1/security-fusion/cases", (c) => c.json({ ok: true }));
app.get("/api/v1/security-fusion/sources", (c) => c.json({ ok: true }));
app.get("/api/v1/security-fusion/evidence", (c) => c.json({ ok: true }));
app.post(
  "/api/v1/security-fusion/actions/x/approve",
  requireRole("ADMIN"),
  (c) => c.json({ ok: true }),
);
afterEach(() => vi.unstubAllEnvs());
describe("independent authorization", () => {
  it("confines the read credential to routes its role can serve", async () => {
    const token = "r".repeat(40);
    vi.stubEnv("SECURITY_PLUGIN_READ_DIGESTS_JSON", JSON.stringify({ agent: createHash("sha256").update(token).digest("hex") }));
    const status = async (path: string) =>
      (await app.request("/api/v1/security-fusion" + path, { headers: { Authorization: `Bearer ${token}` } })).status;
    expect(await status("/cases")).toBe(200);
    expect(await status("/sources")).toBe(200);
    // Evidence needs ADMIN; the allowlist no longer offers what the role always refused.
    expect(await status("/evidence")).toBe(403);
  });
  it("validates the read credential registry", () => {
    const digest = "a".repeat(64);
    expect(pluginReadDigests({})).toEqual({});
    expect(pluginReadDigests({ SECURITY_PLUGIN_READ_DIGESTS_JSON: JSON.stringify({ agent: digest }) })).toEqual({ agent: digest });
    for (const raw of ["{", "[]", "null", JSON.stringify({ agent: "A".repeat(64) }), JSON.stringify({ agent: 1 }), JSON.stringify({ "bad name": digest })])
      expect(() => pluginReadDigests({ SECURITY_PLUGIN_READ_DIGESTS_JSON: raw }), raw).toThrow(/SECURITY_PLUGIN_READ_DIGESTS_JSON/);
  });
  it("gives VIEWER the summary only", () => {
    const viewer = { userId: "v", email: "", role: "VIEWER" as const, iat: 0, exp: 0 };
    expect(hasPermission(viewer, "security-fusion:summary")).toBe(true);
    expect(hasPermission(viewer, "security-fusion:read")).toBe(false);
    expect(hasPermission({ ...viewer, role: "OPERATOR" }, "security-fusion:evidence:read")).toBe(false);
  });
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
  it("no longer accepts tokens signed with the retired console secret", async () => {
    const secret = "c".repeat(40);
    vi.stubEnv("SECURITY_CONSOLE_TOKEN_SECRET", secret);
    const token = await new SignJWT({ userId: "u", role: "ADMIN" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("cindertrace-console")
      .setAudience("cindertrace-api")
      .setIssuedAt()
      .setExpirationTime("60s")
      .sign(new TextEncoder().encode(secret));
    const status = async () =>
      (await app.request("/api/v1/security-fusion/cases", { headers: { Authorization: `Bearer ${token}` } })).status;
    expect(await status()).toBe(401);
    // Even with the test-suite secret set to the same value, the console issuer is refused.
    vi.stubEnv("CINDERTRACE_TEST_BEARER_SECRET", secret);
    expect(await status()).toBe(401);
  });
  it("accepts test-suite bearers only while their secret is set", async () => {
    const secret = "t".repeat(40);
    const token = await new SignJWT({ userId: "u", role: "OPERATOR" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("cindertrace-test")
      .setAudience("cindertrace-api")
      .setIssuedAt()
      .setExpirationTime("60s")
      .sign(new TextEncoder().encode(secret));
    const status = async () =>
      (await app.request("/api/v1/security-fusion/cases", { headers: { Authorization: `Bearer ${token}` } })).status;
    expect(await status()).toBe(401);
    vi.stubEnv("CINDERTRACE_TEST_BEARER_SECRET", secret);
    expect(await status()).toBe(200);
  });
  it("rejects a console assertion minted for Magnus", async () => {
    const secret = "s".repeat(40);
    vi.stubEnv("CINDERTRACE_TEST_BEARER_SECRET", secret);
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

describe("static credential comparison", () => {
  const digest = (value: string) => createHash("sha256").update(value).digest("hex");
  it("matches a token only against its exact lowercase-hex SHA-256 digest", () => {
    const token = "t".repeat(40);
    expect(tokenMatches(token, digest(token))).toBe(true);
    expect(tokenMatches(token, digest(token).toUpperCase())).toBe(false);
    expect(tokenMatches(`${token}x`, digest(token))).toBe(false);
    expect(tokenMatches(token, digest(token).slice(1))).toBe(false);
    expect(tokenMatches("", digest(""))).toBe(false);
    expect(tokenMatches(token, undefined)).toBe(false);
    expect(tokenMatches(token, "")).toBe(false);
    expect(tokenMatches("töken-ü", digest("töken-ü"))).toBe(true);
  });
  it("compares strings exactly, refusing different lengths", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
    expect(safeEqual("", "")).toBe(true);
    // Same character count, different UTF-8 byte length.
    expect(safeEqual("é", "e")).toBe(false);
  });
});
