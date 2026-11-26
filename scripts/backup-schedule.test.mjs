import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { prunable, runOnce, scheduleOptions } from "./backup-schedule.mjs";

test("schedule settings have safe defaults and refuse nonsense", () => {
  const options = scheduleOptions({ CINDERTRACE_STATE_DIR: "/state" });
  assert.deepEqual(options, { directory: "/state/backups", intervalHours: 24, retain: 7 });
  assert.equal(scheduleOptions({ CINDERTRACE_BACKUP_DIR: "/backups", CINDERTRACE_BACKUP_RETAIN: "30" }).retain, 30);
  for (const env of [{ CINDERTRACE_BACKUP_INTERVAL_HOURS: "0" }, { CINDERTRACE_BACKUP_INTERVAL_HOURS: "1.5" },
    { CINDERTRACE_BACKUP_RETAIN: "0" }, { CINDERTRACE_BACKUP_RETAIN: "many" }])
    assert.throws(() => scheduleOptions(env));
});

test("pruning keeps the newest archives and ignores other files", () => {
  const names = ["security-20261101T000000Z.aes", "security-20261103T000000Z.aes", "notes.txt",
    "security-20261102T000000Z.aes", "security-manual.aes"];
  assert.deepEqual(prunable(names, 2), ["security-20261101T000000Z.aes"]);
  assert.deepEqual(prunable(names, 5), []);
});

test("a run verifies the new archive before pruning, and a failure prunes nothing", async () => {
  const directory = mkdtempSync(join(tmpdir(), "backup-schedule-"));
  try {
    const old = ["01", "02", "03"].map((day) => `security-202611${day}T000000Z.aes`);
    for (const name of old) writeFileSync(join(directory, name), "x");
    await assert.rejects(runOnce({ directory, retain: 1 }, async (args) => {
      if (args[0] === "verify") throw new Error("verification failed");
      writeFileSync(args[1], "bad");
      return JSON.stringify({ name: "x" });
    }));
    // Nothing older was removed, and the unverified archive left the rotation.
    const afterFailure = readdirSync(directory);
    assert(old.every((name) => afterFailure.includes(name)));
    assert.equal(afterFailure.filter((name) => name.endsWith(".aes.unverified")).length, 1);
    const calls = [];
    const result = await runOnce({ directory, retain: 2 }, async (args) => {
      calls.push(args[0]);
      if (args[0] === "backup") {
        writeFileSync(args[1], "new");
        return JSON.stringify({ name: args[1].split("/").at(-1), sha256: "a".repeat(64), bytes: 3 }) + "\n";
      }
      return "";
    });
    assert.deepEqual(calls, ["backup", "verify"]);
    assert.equal(result.pruned, 2);
    const kept = readdirSync(directory).filter((name) => name.endsWith(".aes")).sort();
    assert.deepEqual(kept, [old[2], result.name].sort());
  } finally {
    rmSync(directory, { recursive: true });
  }
});
