import { createRequire } from "node:module";
import { resolve, join } from "node:path";
import { readdirSync, readFileSync } from "node:fs";
import { randomUUID, createHash } from "node:crypto";
const require = createRequire(resolve("package.json"));
require("dotenv").config({ quiet: true });
const { Client } = require("pg");
const db = new Client({ connectionString: process.env.DATABASE_URL });
await db.connect();
try {
  await db.query(
    "SELECT pg_advisory_lock(hashtext('cindertrace-schema-migrations'))",
  );
  if (!process.env.DATABASE_URL)
    throw new Error("Explicit dedicated database URL required");
  await db.query(
    `CREATE TABLE IF NOT EXISTS _prisma_migrations (id VARCHAR(36) PRIMARY KEY, checksum VARCHAR(64) NOT NULL, finished_at TIMESTAMPTZ, migration_name VARCHAR(255) NOT NULL, logs TEXT, rolled_back_at TIMESTAMPTZ, started_at TIMESTAMPTZ NOT NULL DEFAULT now(), applied_steps_count INTEGER NOT NULL DEFAULT 0)`,
  );
  for (const name of readdirSync("prisma/migrations")
    .filter((x) => /^\d{14}_[a-z0-9_]+$/.test(x))
    .sort()) {
    const sql = readFileSync(
      join("prisma/migrations", name, "migration.sql"),
      "utf8",
    );
    const checksum = createHash("sha256").update(sql).digest("hex");
    const existing = (
      await db.query(
        "SELECT checksum,finished_at FROM _prisma_migrations WHERE migration_name=$1 AND rolled_back_at IS NULL",
        [name],
      )
    ).rows;
    if (existing.length) {
      if (
        existing.length !== 1 ||
        existing[0].checksum !== checksum ||
        !existing[0].finished_at
      )
        throw new Error(`Migration history mismatch: ${name}`);
      continue;
    }
    const baseline =
      name === "20260917010000_initial" &&
      (
        await db.query(
          "SELECT to_regclass('public.security_fusion_events') AS name",
        )
      ).rows[0].name;
    if (baseline && process.env.SECURITY_MIGRATION_BASELINE !== "true")
      throw new Error("Existing initial schema requires explicit baseline");
    await db.query("BEGIN");
    try {
      if (!baseline) await db.query(sql);
      await db.query(
        "INSERT INTO _prisma_migrations (id,checksum,migration_name,finished_at,applied_steps_count) VALUES ($1,$2,$3,now(),1)",
        [randomUUID(), checksum, name],
      );
      await db.query("COMMIT");
    } catch (error) {
      await db.query("ROLLBACK");
      throw error;
    }
    console.log(
      JSON.stringify({
        migration: name,
        baseline: Boolean(baseline),
        checksum,
      }),
    );
  }
} finally {
  await db.end();
}
