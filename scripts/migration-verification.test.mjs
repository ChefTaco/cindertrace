import { it } from "node:test";
import assert from "node:assert/strict";
import { verifyMigrationRows } from "../services/security-fusion/scripts/migration-history.mjs";
const packaged = [
  { name: "20260101000000_initial", checksum: "a".repeat(64) },
  { name: "20260102000000_next", checksum: "b".repeat(64) },
];
const rows = packaged.map((item) => ({
  migration_name: item.name,
  checksum: item.checksum,
  finished_at: new Date(),
  rolled_back_at: null,
  applied_steps_count: 1,
}));
it("requires every exact finished packaged migration, rejecting unknown, duplicate, unfinished and rolled back rows", () => {
  assert.equal(verifyMigrationRows(packaged, rows), 2);
  for (const wrong of [
    [],
    rows.slice(1),
    [...rows, { ...rows[0], migration_name: "20260103000000_unknown" }],
    [rows[0], rows[0]],
    [rows[0], { ...rows[1], checksum: "c".repeat(64) }],
    [rows[0], { ...rows[1], finished_at: null }],
    [rows[0], { ...rows[1], rolled_back_at: new Date() }],
    [rows[0], { ...rows[1], applied_steps_count: 0 }],
  ])
    assert.throws(() => verifyMigrationRows(packaged, wrong));
});
