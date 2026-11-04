// This read-only probe is sent over stdin to the installed runtime; it has no HTTP listener.
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { readFileSync, existsSync } from "node:fs";
import { pathToFileURL } from "node:url";
const require = createRequire(
  resolve(
    process.env.UPGRADE_RUNTIME_ROOT ?? "/app",
    "services/security-fusion/package.json",
  ),
);
const { Client } = require("pg");
const db = new Client({ connectionString: process.env.DATABASE_URL });
await db.connect();
try {
  await db.query("BEGIN READ ONLY");
  const count = async (q) => Number((await db.query(q)).rows[0].n);
  const state = {
    unsafeActions: await count(
      "SELECT count(*) AS n FROM security_fusion_actions WHERE status IN ('previewed','pending_approval','dispatch_pending','executing','verifying','release_pending','releasing','unknown') OR (kind='host_isolation' AND status='succeeded')",
    ),
    unsafeOutbox: await count(
      "SELECT count(*) AS n FROM security_fusion_command_outbox WHERE status IN ('pending','dispatching','unknown')",
    ),
    pendingApprovals: await count(
      "SELECT count(*) AS n FROM security_fusion_action_approvals WHERE status='pending'",
    ),
    unsafeExecutions: await count(
      "SELECT count(*) AS n FROM security_executions WHERE status NOT IN ('completed','failed')",
    ),
  };
  const migrations = (
    await db.query(
      "SELECT migration_name,checksum,finished_at,rolled_back_at FROM _prisma_migrations ORDER BY migration_name",
    )
  ).rows;
  const tables = (
    await db.query(
      "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
    )
  ).rows.map((x) => x.tablename);
  const runtime = resolve(process.env.UPGRADE_RUNTIME_ROOT ?? "/app");
  const { securityTablesForProfile } = await import(
    pathToFileURL(
      resolve(
        runtime,
        "services/security-fusion/scripts/security-table-contract.mjs",
      ),
    )
  );
  const metadata = resolve(runtime, "cindertrace-release.json");
  const profile = existsSync(metadata)
    ? JSON.parse(readFileSync(metadata)).schemaProfile
    : "cindertrace-v1";
  let expected;
  try {
    expected = securityTablesForProfile(profile);
  } catch (error) {
    if (existsSync(metadata) || profile !== "cindertrace-v1") throw error;
    expected = securityTablesForProfile("current");
  }
  const schemaKnown =
    JSON.stringify(tables) ===
    JSON.stringify(
      [
        ...expected,
        "security_targets",
        "security_executions",
        "_prisma_migrations",
      ].sort(),
    );
  const otherClientSessions = await count(
    "SELECT count(*) AS n FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND pid<>pg_backend_pid() AND backend_type='client backend'",
  );
  console.log(
    JSON.stringify({
      state,
      migrations,
      tables,
      profile,
      schemaKnown,
      otherClientSessions,
      databaseBytes: await count(
        "SELECT pg_database_size(current_database()) AS n",
      ),
    }),
  );
  await db.query("COMMIT");
} finally {
  await db.end();
}
