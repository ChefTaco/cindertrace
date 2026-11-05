import {isRehearsal,securityWritesEnabled} from "./config/rehearsal.js";
import { readFile } from "node:fs/promises";
import { rateLimitMiddleware } from "./middleware/rate-limit.js";
import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
import { securityFusionRouter } from "./routes/security-fusion.js";
import { errorHandler } from "./middleware/error-handler.js";
import { bodyLimitMiddleware } from "./middleware/body-limit.js";
import { tokenMatches } from "./middleware/auth.js";
import { getDb } from "./db/index.js";
import { renderMetrics } from "./routes/metrics.js";
import type { AppVariables } from "./types/index.js";
import { browserAuthRouter } from './browser-auth/routes.js';
export const app = new Hono<AppVariables>();
app.onError(errorHandler);
app.use("*", bodyLimitMiddleware(262144));
app.use("*", async (c, next) => {
  await next();
  c.header("Cache-Control", "no-store");
  c.header("X-Content-Type-Options", "nosniff");
});
app.route('/api/v1/auth/local', browserAuthRouter());
app.get("/health", (c) =>
  c.json({ success: true, service: "cindertrace-api" }),
);
app.get("/ready", async (c) => {
  await getDb().$queryRaw`SELECT 1`;
  const { redisReady } = await import("./middleware/rate-limit.js");
  await redisReady();
  return c.json({ success: true });
});
app.get("/metrics", async (c) => {
  if (
    !tokenMatches(
      c.req.header("Authorization")?.replace(/^Bearer /, "") ?? "",
      process.env["METRICS_TOKEN_SHA256"],
    )
  )
    return c.json({ error: "Unauthorized" }, 401);
  const sources = await getDb().securityFusionSourceState.findMany();
  let extra = sources
    .map(
      (s) =>
        `security_fusion_source_last_success_seconds{source="${s.source}"} ${s.lastSuccessAt ? s.lastSuccessAt.getTime() / 1000 : 0}`,
    )
    .join("\n");
  extra += "\n" + sources.filter(s => s.lastEventAt).map(s => `security_fusion_source_last_event_seconds{source="${s.source}"} ${s.lastEventAt!.getTime()/1000}`).join("\n");
  extra += `\nsecurity_fusion_unknown_actions ${await getDb().securityFusionAction.count({ where: { status: "unknown" } })}`;
  try {
    const status = JSON.parse(
      await readFile(
        process.env["SECURITY_BACKUP_STATUS_FILE"] ?? "state/backup-status.json",
        "utf8",
      ),
    );
    extra += `\nsecurity_fusion_backup_last_success_seconds ${Date.parse(status.completedAt) / 1000}`;
  } catch {
    extra += "\nsecurity_fusion_backup_last_success_seconds 0";
  }
  return c.text(renderMetrics() + extra + "\n");
});
app.get("/api/v1/security-fusion/summary", async (c) => {
  if (
    !tokenMatches(
      c.req.header("Authorization")?.replace(/^Bearer /, "") ?? "",
      process.env["SECURITY_SUMMARY_TOKEN_SHA256"],
    )
  )
    return c.json({ error: "Unauthorized" }, 401);
  const [bySeverity, sources] = await Promise.all([
    getDb().securityFusionCase.groupBy({
      by: ["severity"],
      where: {
        archivedAt: null,
        status: { notIn: ["resolved", "false_positive"] },
      },
      _count: { id: true },
    }),
    getDb().securityFusionSourceState.findMany({
      select: {
        source: true,
        status: true,
        lastSuccessAt: true,
        lastEventAt: true,
      },
    }),
  ]);
  return c.json({
    success: true,
    data: {
      generatedAt: new Date().toISOString(),
      bySeverity,
      sources: sources.map((s) => ({
        ...s,
        status:
          s.status === "healthy" &&
          (!s.lastSuccessAt || Date.now() - s.lastSuccessAt.getTime() > 300000)
            ? "stale"
            : s.status,
      })),
    },
  });
});
export const securityFusionWriteGate: MiddlewareHandler = async (c, next) => {
  if (
    (isRehearsal() || process.env["SECURITY_INGEST_ENABLED"] !== "true") &&
    c.req.path.includes("/ingest/")
  )
    return c.json({ error: "Ingestion paused" }, 503);
  if (
    !securityWritesEnabled() &&
    c.req.method !== "GET" &&
    !(c.req.method === "POST" && /^\/api\/v1\/security-fusion\/cases\/[^/]+\/assurance\/exposure\/preview$/.test(c.req.path))
  )
    return c.json({ error: "Security writes paused" }, 503);
  await next();
};
app.use("/api/v1/security-fusion/*", securityFusionWriteGate);
app.use(
  "/api/v1/security-fusion/ingest/source-status",
  bodyLimitMiddleware(32768),
);
app.use(
  "/api/v1/security-fusion/*",
  rateLimitMiddleware({ max: 120, failClosed: true }),
);
app.route("/api/v1/security-fusion", securityFusionRouter);
