import {isRehearsal,securityWritesEnabled} from "./config/rehearsal.js";
import { config } from "dotenv";
import { readFileSync, existsSync } from "node:fs";
import { createServer } from "node:https";
import { resolveListenerSecurity } from "./config/listener-security.js";
config({ quiet: true });
const { validateRuntimeConfig } = await import("./config/runtime.js");
validateRuntimeConfig();
for (const key of [
  "DATABASE_URL",
  "SECURITY_CONSOLE_TOKEN_SECRET",
  "AUDIT_HMAC_SECRET",
])
  if (
    !process.env[key] ||
    (key !== "DATABASE_URL" && process.env[key]!.length < 32)
  )
    throw new Error(`${key} is required`);
const { serve } = await import("@hono/node-server");
const { app } = await import("./server.js");
const { getDb, disconnectDb } = await import("./db/index.js");
const { syncTargets } = await import("./services/targets.js");
const { startSecurityFusionRetention, stopSecurityFusionRetention } =
  await import("./services/security-fusion-service.js");
const { reconcileSecurityFusionEvidence } =
  await import("./services/security-fusion-evidence-integrity.js");
const {
  startSecurityFusionOutboxDispatcher,
  stopSecurityFusionOutboxDispatcher,
} = await import("./services/security-fusion-outbox.js");
await getDb().$queryRaw`SELECT 1`;
if (securityWritesEnabled())
  await getDb().securityFusionReceiptChainHead.upsert({
    where: { id: "security-fusion" },
    create: { id: "security-fusion", chainSequence: 0 },
    update: {},
  });
if (securityWritesEnabled())
  await reconcileSecurityFusionEvidence();
const listener = resolveListenerSecurity({
  nodeEnv: process.env["NODE_ENV"] ?? "production",
  allowInsecureHttp: process.env["ALLOW_INSECURE_HTTP"] === "true",
  bindHost: process.env["SECURITY_BIND_HOST"],
  certPath: process.env["TLS_CERT_PATH"],
  keyPath: process.env["TLS_KEY_PATH"],
  pathExists: existsSync,
});
const server = serve({
  fetch: app.fetch,
  hostname: listener.hostname,
  port: Number(process.env["SECURITY_API_PORT"] ?? 4101),
  ...(listener.useTls
    ? {
        createServer,
        serverOptions: {
          cert: readFileSync(process.env["TLS_CERT_PATH"]!),
          key: readFileSync(process.env["TLS_KEY_PATH"]!),
        },
      }
    : {}),
});
if (
  process.env["SECURITY_RETENTION_ENABLED"] === "true" &&
  securityWritesEnabled()
)
  startSecurityFusionRetention();
if(!isRehearsal()) startSecurityFusionOutboxDispatcher();
const sync = () => {
  if (!securityWritesEnabled()) return;
  void syncTargets().catch(() =>
    console.error("Security inventory synchronization failed"),
  );
};
sync();
const timer = isRehearsal()?undefined:setInterval(sync, 60000);
let stopping = false;
for (const signal of ["SIGTERM", "SIGINT"])
  process.on(signal, () => {
    if (stopping) return;
    stopping = true;
    if(timer)clearInterval(timer);
    stopSecurityFusionRetention();
    stopSecurityFusionOutboxDispatcher();
    server.close(() => {
      void disconnectDb().then(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 150000).unref();
  });
