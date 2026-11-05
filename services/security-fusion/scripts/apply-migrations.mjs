import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import {
  packagedMigrations,
  verifyMigrationRows,
} from "./migration-history.mjs";
import { randomUUID } from "node:crypto";
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--verify-current"))
  throw Error("Usage: apply-migrations [--verify-current]");
const verifyOnly = args[0] === "--verify-current";
const migrations = packagedMigrations(
  fileURLToPath(new URL("../prisma/migrations", import.meta.url)),
);
const require = createRequire(import.meta.url);
require("dotenv").config({ quiet: true });
const { Client } = require("pg");
if (!process.env.DATABASE_URL)
  throw new Error("Explicit dedicated database URL required");
const db = new Client({ connectionString: process.env.DATABASE_URL });
await db.connect();
try {
  if (verifyOnly) {
    await db.query(
      "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
    );
    try {
      const present = (
        await db.query(
          "SELECT to_regclass('public._prisma_migrations') AS name",
        )
      ).rows[0]?.name;
      if (!present)
        throw Error(
          "Migration history is absent; verification never creates schema",
        );
      const rows = (
        await db.query(
          "SELECT migration_name,checksum,finished_at,rolled_back_at,applied_steps_count FROM _prisma_migrations ORDER BY started_at,id",
        )
      ).rows;
      const count = verifyMigrationRows(migrations, rows);
      await db.query("COMMIT");
      console.log(JSON.stringify({ verified: true, migrations: count }));
    } catch (error) {
      await db.query("ROLLBACK");
      throw error;
    }
  } else {
    await db.query(
      "SELECT pg_advisory_lock(hashtext('cindertrace-schema-migrations'))",
    );
    if (!process.env.DATABASE_URL)
      throw new Error("Explicit dedicated database URL required");
    await db.query(
      `CREATE TABLE IF NOT EXISTS _prisma_migrations (id VARCHAR(36) PRIMARY KEY, checksum VARCHAR(64) NOT NULL, finished_at TIMESTAMPTZ, migration_name VARCHAR(255) NOT NULL, logs TEXT, rolled_back_at TIMESTAMPTZ, started_at TIMESTAMPTZ NOT NULL DEFAULT now(), applied_steps_count INTEGER NOT NULL DEFAULT 0)`,
    );
    for (const { name, sql, checksum } of migrations) {
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
  }
} finally {
  await db.end();
}
