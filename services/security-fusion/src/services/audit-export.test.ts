import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { Hono } from "hono";
import { cindertraceAuditExportPageSchema } from "@cindertrace/contracts";
import { logAuditEvent } from "./audit-service.js";
import { exportAuditRecords } from "./audit-export.js";
import { auditExportRouter } from "../routes/audit-export.js";
import { errorHandler } from "../middleware/error-handler.js";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "audit-export-"));
  vi.stubEnv("AUDIT_LOG_DIR", dir);
  vi.stubEnv("AUDIT_HMAC_SECRET", "a".repeat(64));
});
afterEach(async () => {
  vi.unstubAllEnvs();
  await rm(dir, { recursive: true, force: true });
});
const log = (action: string, actorId: string, details: Record<string, unknown> = {}) =>
  logAuditEvent({ action, actorId, targetType: "security-action", targetId: "a1", details, ipAddress: "203.0.113.9" });

it("serves the audit as HiveAuditRecord v1 pages that resume after the last record", async () => {
  await log("security_fusion.action.request", "operator-1", { previewSha256: "b".repeat(64), nested: { x: 1 } });
  await log("auth.login_failed", "anonymous");
  await log("security_fusion.action.expire", "system:security-fusion");
  await log("security_fusion.action.external_approve", "service:senti-approval-bridge");
  const first = await exportAuditRecords({ limit: 3 });
  cindertraceAuditExportPageSchema.parse(first);
  expect(first.data.map((record) => [record.action, record.outcome, record.actor.type])).toEqual([
    ["security_fusion.action.request", "success", "user"],
    ["auth.login_failed", "failure", "user"],
    ["security_fusion.action.expire", "success", "system"],
  ]);
  const [request] = first.data;
  expect(request!.id).toMatch(/^cindertrace:audit:/);
  expect(request!.target).toEqual({ type: "security-action", id: "a1" });
  // Scalars only, the chain state, and never the client address.
  expect(request!.details).toEqual({ chain: "verified", previewSha256: "b".repeat(64) });
  expect(JSON.stringify(first)).not.toContain("203.0.113.9");
  const second = await exportAuditRecords({ after: first.nextCursor!, limit: 3 });
  expect(second.data.map((record) => record.actor)).toEqual([{ type: "service", id: "service:senti-approval-bridge" }]);
  const caughtUp = await exportAuditRecords({ after: second.nextCursor!, limit: 3 });
  expect(caughtUp).toEqual({ data: [], nextCursor: null });
  await log("security_fusion.collector.revoke", "admin-1");
  expect((await exportAuditRecords({ after: second.nextCursor!, limit: 3 })).data.map((r) => r.action)).toEqual([
    "security_fusion.collector.revoke",
  ]);
});

it("continues across days and marks a broken chain", async () => {
  await writeFile(path.join(dir, "2026-01-01.jsonl"), JSON.stringify({
    id: "old1", action: "log.retention", actorId: "system:retention", actorType: "system", targetType: "case", targetId: "c",
    details: {}, ipAddress: null, timestamp: "2026-01-01T00:00:00.000Z", prevHash: "x", integrity: "y", chainVersion: 2,
  }) + "\n");
  await log("security_fusion.evidence.preserve", "admin-1");
  const page = await exportAuditRecords({ limit: 10 });
  expect(page.data.map((record) => [record.occurredAt.slice(0, 10) === "2026-01-01", record.details["chain"]])).toEqual([
    [true, "invalid"],
    [false, "verified"],
  ]);
  const after = await exportAuditRecords({ after: (await exportAuditRecords({ limit: 1 })).nextCursor!, limit: 10 });
  expect(after.data).toHaveLength(1);
  await expect(exportAuditRecords({ after: "not-a-cursor", limit: 1 })).rejects.toMatchObject({ code: "INVALID_CURSOR" });
  expect((await readFile(path.join(dir, "2026-01-01.jsonl"), "utf8")).length).toBeGreaterThan(0);
});

it("lets only an ADMIN or the audit export credential read the export, and scopes that credential", async () => {
  await log("security_fusion.action.request", "operator-1");
  const token = "e".repeat(40);
  vi.stubEnv("SECURITY_AUDIT_EXPORT_TOKEN_SHA256", createHash("sha256").update(token).digest("hex"));
  const app = new Hono();
  app.onError(errorHandler);
  app.route("/api/v1/audit", auditExportRouter);
  const { securityFusionRouter } = await import("../routes/security-fusion.js");
  app.route("/api/v1/security-fusion", securityFusionRouter);
  const get = (url: string, bearer = token) => app.request(url, { headers: { authorization: `Bearer ${bearer}` } });
  const ok = await get("/api/v1/audit/export?limit=5");
  expect(ok.status).toBe(200);
  expect((await ok.json()).data).toHaveLength(1);
  expect((await get("/api/v1/audit/export?limit=abc")).status).toBe(400);
  expect((await get("/api/v1/audit/export?after=!!")).status).toBe(400);
  expect((await get("/api/v1/security-fusion/cases")).status).toBe(403);
  expect((await get("/api/v1/audit/export", "wrong".repeat(10))).status).toBe(401);
  const { SignJWT } = await import("jose");
  vi.stubEnv("CINDERTRACE_TEST_BEARER_SECRET", "t".repeat(64));
  const bearer = (role: string) => new SignJWT({ userId: "u", role }).setProtectedHeader({ alg: "HS256" })
    .setIssuer("cindertrace-test").setAudience("cindertrace-api").setIssuedAt().setExpirationTime("60s")
    .sign(new TextEncoder().encode("t".repeat(64)));
  expect((await get("/api/v1/audit/export", await bearer("ADMIN"))).status).toBe(200);
  expect((await get("/api/v1/audit/export", await bearer("OPERATOR"))).status).toBe(403);
});
