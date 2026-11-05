import { readdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
export function packagedMigrations(directory) {
  return readdirSync(directory)
    .filter((name) => /^\d{14}_[a-z0-9_]+$/.test(name))
    .sort()
    .map((name) => {
      const sql = readFileSync(join(directory, name, "migration.sql"), "utf8");
      return {
        name,
        sql,
        checksum: createHash("sha256").update(sql).digest("hex"),
      };
    });
}
/** Exact completed history only; this function never creates or repairs schema. */
export function verifyMigrationRows(packaged, rows) {
  if (!packaged.length || rows.length !== packaged.length)
    throw Error("Migration history is incomplete or contains unknown records");
  const expected = new Map(packaged.map((item) => [item.name, item.checksum])),
    seen = new Set();
  for (const row of rows) {
    if (
      seen.has(row.migration_name) ||
      expected.get(row.migration_name) !== row.checksum ||
      !row.finished_at ||
      row.rolled_back_at !== null ||
      Number(row.applied_steps_count) !== 1
    )
      throw Error(
        "Migration history does not match the exact finished package",
      );
    seen.add(row.migration_name);
  }
  return seen.size;
}
