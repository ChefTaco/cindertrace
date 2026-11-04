import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  readEnvironment,
  renderEnvironment,
  pausedEnvironment,
  assertSafeState,
  assertMigrations,
  atomicPrivate,
  unitName,
  absolutePath,
  patchEnvironment,
  recoveryArchiveName,
  assertUpgradeNode,
  upgradeChildEnvironment,
} from "./upgrade-policy.mjs";
test("environment round trip preserves escaped credentials and JSON without shell evaluation", () => {
  const value = {
    SESSION_SECRET: "fixture-$(`false`)-value",
    CREDENTIALS_JSON: JSON.stringify({
      source: "example",
      allowed: ["hive", "magnus"],
    }),
  };
  assert.deepEqual(readEnvironment(renderEnvironment(value)), value);
  assert.throws(() => readEnvironment("A=1\nA=2"));
  assert.throws(() => renderEnvironment({ A: "bad\nline" }));
  const paused = pausedEnvironment(value);
  assert.equal(paused.SESSION_SECRET, value.SESSION_SECRET);
  assert.equal(paused.SECURITY_DISPATCH_ENABLED, "false");
});
test("every pending or uncertain effect blocks ownership transfer", () => {
  const safe = {
    unsafeActions: 0,
    unsafeOutbox: 0,
    pendingApprovals: 0,
    unsafeExecutions: 0,
  };
  assertSafeState(safe);
  for (const key of Object.keys(safe))
    assert.throws(() => assertSafeState({ ...safe, [key]: 1 }));
});
test("migration retry accepts unchanged completed history and refuses drift or interrupted history", () => {
  const row = {
    migration_name: "20261103000000_example",
    checksum: "a".repeat(64),
    finished_at: "2026-11-03T00:00:00Z",
    rolled_back_at: null,
  };
  assertMigrations([row], {
    [row.migration_name]: row.checksum,
    new: "b".repeat(64),
  });
  for (const history of [
    [{ ...row, finished_at: null }],
    [{ ...row, rolled_back_at: "2026-11-03" }],
    [row, row],
  ])
    assert.throws(() =>
      assertMigrations(history, { [row.migration_name]: row.checksum }),
    );
  assert.throws(() => assertMigrations([row], {}));
  assert.throws(() =>
    assertMigrations([row], { [row.migration_name]: "b".repeat(64) }),
  );
});
test("private records are atomically replaced and service/path input cannot add shell operations", () => {
  const root = mkdtempSync(join(tmpdir(), "cindertrace-upgrade-"));
  try {
    const file = join(root, "record");
    atomicPrivate(file, "first");
    atomicPrivate(file, "second");
    assert.equal(readFileSync(file, "utf8"), "second");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.throws(() => unitName("api.service; reboot"));
    assert.throws(() => absolutePath("/opt/../etc"));
  } finally {
    rmSync(root, { recursive: true });
  }
});

test("Compose updates preserve byte-exact secret and comment lines", () => {
  const text =
    "# retained comment\nVALUE='fixture-${NAME}-$value'\nSECURITY_WRITES_ENABLED=true\n";
  const result = patchEnvironment(text, {
    SECURITY_WRITES_ENABLED: "false",
    CINDERTRACE_IMAGE: "cindertrace:release-fixture",
  });
  assert(result.includes("VALUE='fixture-${NAME}-$value'\n"));
  assert(result.startsWith("# retained comment\n"));
  assert(result.includes("SECURITY_WRITES_ENABLED=false"));
});

test("upgrade archives use the supported off-host receiver name contract", () => {
  assert.equal(
    recoveryArchiveName(new Date("2026-11-04T01:02:03.456Z")),
    "security-20261104T010203Z.aes",
  );
});

test("unsupported runtimes fail before native dependency activation", () => {
  for (const v of ["24.22.1", "24.22.2", "26.13.0"]) assertUpgradeNode(v);
  for (const v of ["22.15.0", "24.22.0", "26.12.0", "25.1.0"])
    assert.throws(() => assertUpgradeNode(v));
});

test("upgrade children cannot inherit loader or executable-path injection", () => {
  const child = upgradeChildEnvironment({
    NODE_OPTIONS: "--require /tmp/fixture.js",
    LD_PRELOAD: "/tmp/fixture.so",
    NODE_TLS_REJECT_UNAUTHORIZED: "0",
    PATH: "/tmp",
    DATABASE_URL: "postgresql://fixture:fixture@localhost/example",
  });
  assert(!("NODE_OPTIONS" in child));
  assert(!("LD_PRELOAD" in child));
  assert(!("NODE_TLS_REJECT_UNAUTHORIZED" in child));
  assert.equal(child.PATH, "/usr/sbin:/usr/bin:/sbin:/bin");
  assert.equal(
    child.DATABASE_URL,
    "postgresql://fixture:fixture@localhost/example",
  );
});
