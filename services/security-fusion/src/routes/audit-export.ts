import { Hono } from "hono";
import { parseFeedQuery } from "@hivemagnus/hive-common/events";
import type { AppVariables } from "../types/index.js";
import { authMiddleware, getUser } from "../middleware/auth.js";
import { HttpError } from "../middleware/error-handler.js";
import { exportAuditRecords } from "../services/audit-export.js";

export const AUDIT_EXPORT_ACTOR = "service:audit-export";

/**
 * `GET /api/v1/audit/export?after=&limit=`: Cindertrace's own audit as HiveAuditRecord v1.
 * Readable by an ADMIN, or by the endpoint-scoped SECURITY_AUDIT_EXPORT_TOKEN_SHA256 credential.
 */
export const auditExportRouter = new Hono<AppVariables>();
auditExportRouter.use("*", authMiddleware);
auditExportRouter.get("/export", async (c) => {
  const user = getUser(c);
  if (user.role !== "ADMIN" && user.userId !== AUDIT_EXPORT_ACTOR)
    throw new HttpError(403, "FORBIDDEN", "Audit export requires ADMIN or the audit export credential");
  let query;
  try {
    query = parseFeedQuery(c.req.queries(), { defaultLimit: 100, maxLimit: 200 });
  } catch (error) {
    throw new HttpError(400, "INVALID_QUERY", error instanceof Error ? error.message : "Invalid feed query");
  }
  c.header("Cache-Control", "no-store");
  return c.json(await exportAuditRecords(query));
});
