import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../services/security-fusion/package.json", import.meta.url),
);
const { Client } = require("pg");
const sourceUrl = process.env.DATABASE_URL;
if (process.env.CINDERTRACE_RECOVERY_TEST_CONFIRM !== "disposable-installation")
  throw new Error(
    "Recovery integration requires an explicitly disposable installation",
  );
const name = "cindertrace_test_restore_" + Date.now();
const db = new Client({ connectionString: sourceUrl });
await db.connect();
try {
  if (
    (await db.query("SELECT 1 FROM pg_database WHERE datname=$1", [name]))
      .rowCount
  )
    throw new Error("Retained restore destination already exists");
  await db.query(`CREATE DATABASE "${name}"`);
} finally {
  await db.end();
}
const state = "/state/recovery-integration-" + Date.now();
mkdirSync(state, { recursive: true, mode: 0o700 });
const file = state + "/security.aes";
const root = resolve(import.meta.dirname, ".."),
  api = resolve(root, "services/security-fusion");
execFileSync(process.execPath, ["scripts/backup.mjs", "backup", file], {
  cwd: root,
  stdio: "pipe",
});
execFileSync(process.execPath, ["scripts/backup.mjs", "verify", file], {
  cwd: root,
  stdio: "pipe",
});
const tampered = readFileSync(file);
tampered[tampered.length - 1] ^= 1;
const broken = state + "/tampered.aes";
writeFileSync(broken, tampered, { mode: 0o600 });
if (
  spawnSync(process.execPath, ["scripts/backup.mjs", "verify", broken], {
    cwd: root,
    stdio: "pipe",
  }).status === 0
)
  throw new Error("Tampered backup was accepted");
const env = {
  ...process.env,
  DATABASE_URL: sourceUrl.replace(/\/[^/]+$/, "/" + name),
  CINDERTRACE_STATE_DIR: state,
  SECURITY_FUSION_EVIDENCE_DIR: state + "/evidence",
  SECURITY_FUSION_RECEIPT_CHAIN_EXPORT: state + "/receipts.jsonl",
  AUDIT_LOG_DIR: state + "/audit-logs",
  CINDERTRACE_RESTORE_CONFIRM: "empty-isolated-destination",
};

execFileSync(process.execPath, ["scripts/backup.mjs", "restore", file], {
  cwd: root,
  env,
  stdio: "pipe",
});
const result = execFileSync(
  process.execPath,
  ["scripts/verify-restored-state.mjs"],
  { cwd: api, env, encoding: "utf8" },
);
if (
  spawnSync(process.execPath, ["scripts/backup.mjs", "restore", file], {
    cwd: root,
    env,
    stdio: "pipe",
  }).status === 0
)
  throw new Error("Nonempty restore destination was accepted");
// A pre-lab native schema remains independently restorable with the new tools.
const nativeV1Name = name.replace("restore_", "native_v1_");
const nativeV1RestoredName = name.replace("restore_", "native_v1_restored_");
const nativeV1Admin = new Client({ connectionString: sourceUrl });
await nativeV1Admin.connect();
try {
  await nativeV1Admin.query(`CREATE DATABASE "${nativeV1Name}" TEMPLATE "${name}"`);
  await nativeV1Admin.query(`CREATE DATABASE "${nativeV1RestoredName}"`);
} finally { await nativeV1Admin.end(); }
const nativeV1Url = sourceUrl.replace(/\/[^/]+$/, "/" + nativeV1Name);
const nativeV1Db = new Client({ connectionString: nativeV1Url });
await nativeV1Db.connect();
try { await nativeV1Db.query('DROP TABLE security_fusion_lab_checkpoints, security_fusion_lab_runs, security_fusion_lab_simulations'); }
finally { await nativeV1Db.end(); }
const nativeV1File = state + "/native-v1.aes";
execFileSync(process.execPath, ["scripts/backup.mjs", "backup", nativeV1File], {
  cwd: root, stdio: "pipe", env: { ...env, DATABASE_URL: nativeV1Url, CINDERTRACE_SOURCE_PROFILE: "cindertrace-v1" },
});
const nativeV1State = state + "/native-v1-restored";
mkdirSync(nativeV1State, { mode: 0o700 });
const nativeV1Env = { ...env, DATABASE_URL: sourceUrl.replace(/\/[^/]+$/, "/" + nativeV1RestoredName),
  CINDERTRACE_STATE_DIR: nativeV1State, SECURITY_FUSION_EVIDENCE_DIR: nativeV1State + "/evidence",
  SECURITY_FUSION_RECEIPT_CHAIN_EXPORT: nativeV1State + "/receipts.jsonl", AUDIT_LOG_DIR: nativeV1State + "/audit",
};
execFileSync(process.execPath, ["scripts/backup.mjs", "restore", nativeV1File], { cwd: root, env: nativeV1Env, stdio: "pipe" });
const nativeV1Integrity = JSON.parse(execFileSync(process.execPath, ["scripts/verify-restored-state.mjs"], { cwd: api, env: nativeV1Env, encoding: "utf8" }));
if (nativeV1Integrity.labRunsVerified !== 0) throw new Error("Historical schema unexpectedly acquired lab state");
// Exercise the public Magnus schema profile, including additive column defaults.
// Retain every database and archive so a failed rehearsal can be investigated.
const legacyName = name.replace("restore_", "legacy_");
const importedName = name.replace("restore_", "imported_");
const admin = new Client({ connectionString: sourceUrl });
await admin.connect();
try {
  await admin.query(`CREATE DATABASE "${legacyName}" TEMPLATE "${name}"`);
  await admin.query(`CREATE DATABASE "${importedName}"`);
} finally {
  await admin.end();
}
const legacyUrl = sourceUrl.replace(/\/[^/]+$/, "/" + legacyName);
const legacy = new Client({ connectionString: legacyUrl });
await legacy.connect();
try {
  await legacy.query(`DROP TABLE security_fusion_lab_checkpoints, security_fusion_lab_runs, security_fusion_lab_simulations, security_fusion_approval_decisions,
    security_fusion_assurance_packets, security_fusion_telegram_decisions`);
  await legacy.query(
    `ALTER TABLE security_fusion_actions DROP COLUMN "verificationDeadline"`,
  );
  await legacy.query(`ALTER TABLE security_fusion_action_approvals
    DROP COLUMN "planRevision", DROP COLUMN "planJson", DROP COLUMN "planSha256"`);
  await legacy.query(
    `ALTER TABLE security_fusion_command_outbox DROP COLUMN "approvalExecutionId"`,
  );
} finally {
  await legacy.end();
}
const legacyFile = state + "/embedded-source.aes";
execFileSync(process.execPath, ["scripts/backup.mjs", "backup", legacyFile], {
  cwd: root,
  env: {
    ...env,
    DATABASE_URL: legacyUrl,
    CINDERTRACE_SOURCE_PROFILE: "embedded-magnus-v1",
    SECURITY_BACKUP_UPLOAD_URL: "",
  },
  stdio: "pipe",
});
const importedState = state + "/imported";
mkdirSync(importedState, { mode: 0o700 });
const importedEnv = {
  ...env,
  DATABASE_URL: sourceUrl.replace(/\/[^/]+$/, "/" + importedName),
  CINDERTRACE_STATE_DIR: importedState,
  SECURITY_FUSION_EVIDENCE_DIR: importedState + "/evidence",
  SECURITY_FUSION_RECEIPT_CHAIN_EXPORT: importedState + "/receipts.jsonl",
  AUDIT_LOG_DIR: importedState + "/audit-logs",
  CINDERTRACE_TRANSFER_CONFIRM: "frozen-source-empty-destination",
};
execFileSync(process.execPath, ["scripts/apply-migrations.mjs"], {
  cwd: api,
  env: importedEnv,
  stdio: "pipe",
});
execFileSync(process.execPath, ["scripts/backup.mjs", "import", legacyFile], {
  cwd: root,
  env: importedEnv,
  stdio: "pipe",
});
const importedIntegrity = execFileSync(
  process.execPath,
  ["scripts/verify-restored-state.mjs"],
  { cwd: api, env: importedEnv, encoding: "utf8" },
);
// Orphaned state must block transfer even when no action points to it.
const unsafeName = name.replace("restore_", "unsafe_");
const clone = new Client({ connectionString: sourceUrl });
await clone.connect();
try {
  await clone.query(`CREATE DATABASE "${unsafeName}" TEMPLATE "${name}"`);
} finally {
  await clone.end();
}
const unsafeEnv = {
  ...env,
  DATABASE_URL: sourceUrl.replace(/\/[^/]+$/, "/" + unsafeName),
  SECURITY_BACKUP_UPLOAD_URL: "",
};
const unsafeDb = new Client({ connectionString: unsafeEnv.DATABASE_URL });
await unsafeDb.connect();
try {
  await unsafeDb.query(
    `INSERT INTO security_executions (id,"actionId",operation,"nodeId",status,"resultJson") VALUES ('fixture-orphan','fixture-missing-action','execute','fixture-node','unknown','{}')`,
  );
  for (const condition of ["unknown-execution", "pending-approval"]) {
    if (condition === "pending-approval") {
      await unsafeDb.query(
        `UPDATE security_executions SET status='completed' WHERE id='fixture-orphan'`,
      );
      await unsafeDb.query(
        `INSERT INTO security_fusion_action_approvals (id,"actionId","previewSha256","tokenHash",status,"requestedBy","expiresAt") VALUES ('fixture-orphan-approval','fixture-missing-action','fixture-digest','fixture-token','pending','fixture-admin',now()+interval '10 minutes')`,
      );
    }
    const native = state + "/" + condition + ".aes",
      json = state + "/" + condition + ".json.gz";
    execFileSync(process.execPath, ["scripts/backup.mjs", "backup", native], {
      cwd: root,
      env: unsafeEnv,
      stdio: "pipe",
    });
    const refusedNative = spawnSync(
      process.execPath,
      ["scripts/backup.mjs", "import", native],
      { cwd: root, env: importedEnv, encoding: "utf8" },
    );
    if (
      refusedNative.status === 0 ||
      !refusedNative.stderr.includes(
        "Pending, active, or unknown effects block ownership transfer",
      )
    )
      throw new Error(
        "Unsafe native transfer was not refused before import: " + condition,
      );
    execFileSync(
      process.execPath,
      ["scripts/migrate-state.mjs", "export", json],
      { cwd: api, env: unsafeEnv, stdio: "pipe" },
    );
    const refusedJson = spawnSync(
      process.execPath,
      ["scripts/migrate-state.mjs", "import", json],
      { cwd: api, env: importedEnv, encoding: "utf8" },
    );
    if (
      refusedJson.status === 0 ||
      !refusedJson.stderr.includes("orphaned effects block ownership transfer")
    )
      throw new Error(
        "Unsafe JSON transfer was not refused before import: " + condition,
      );
  }
} finally {
  await unsafeDb.end();
}
console.log(
  JSON.stringify({
    tamperingRejected: true,
    nonemptyDestinationRejected: true,
    encryptedBackupVerified: true,
    historicalNativeRestoreVerified: true,
    independentRestoreVerified: true,
    embeddedImportVerified: true,
    orphanedEffectsBlockTransfer: true,
    importedIntegrity: JSON.parse(importedIntegrity),
    integrity: JSON.parse(result),
  }),
);
