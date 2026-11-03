#!/usr/bin/env node
// Run from either API installation. No credentials or event contents are logged.
import { createRequire } from "node:module";
import { resolve, join, relative, isAbsolute } from "node:path";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  lstatSync,
} from "node:fs";
import { gzipSync, gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { securityTablesForProfile } from "./security-table-contract.mjs";
const require = createRequire(resolve("package.json"));
require("dotenv").config({ quiet: true });
const { Client } = require("pg");
const db = new Client({ connectionString: process.env.DATABASE_URL });
await db.connect();
const [mode, file] = process.argv.slice(2);
if (
  !["export", "import", "replace-frozen", "verify", "verify-archive"].includes(
    mode,
  ) ||
  !file
)
  throw new Error(
    "Usage: migrate-state.mjs export|import|verify|verify-archive FILE",
  );
const hash = (x) => createHash("sha256").update(x).digest("hex");
const canonical = (x) =>
  JSON.stringify(x, (_k, v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v).sort(([a], [b]) => a.localeCompare(b)),
        )
      : v,
  );
const tables = (
  await db.query(
    "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'security_fusion_%' ORDER BY tablename",
  )
).rows.map((x) => x.tablename);
const sourceProfile = process.env.CINDERTRACE_SOURCE_PROFILE ?? "current";
if (
  JSON.stringify(tables) !==
  JSON.stringify(securityTablesForProfile(sourceProfile))
)
  throw new Error("Source schema differs from the explicit reviewed profile");
const supplementary = (
  await db.query(
    "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename IN ('security_targets','security_executions') ORDER BY tablename",
  )
).rows.map((x) => x.tablename);
const key = (t) => (t === "security_fusion_nonces" ? "nonce" : "id");
async function rows(table) {
  return (
    await db.query(
      `SELECT row_to_json(t) AS value FROM "${table}" t ORDER BY "${key(table)}" COLLATE "C"`,
    )
  ).rows.map((r) => r.value);
}
const historyBase = resolve(
  process.env.SECURITY_MIGRATION_HISTORY_DIR ?? "state",
);
const evidenceBase = resolve(
  process.env.SECURITY_FUSION_EVIDENCE_DIR ?? "state/security-fusion/evidence",
);
function safeArtifact(path) {
  const rel = relative(evidenceBase, path);
  if (rel.startsWith("..") || isAbsolute(rel) || !rel)
    throw new Error("Evidence outside configured root");
  if (lstatSync(path).isSymbolicLink()) throw new Error("Symlink evidence");
  return rel;
}
try {
  if (mode === "export") {
    await db.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const data = {
      version: 1,
      profile: sourceProfile,
      createdAt: new Date().toISOString(),
      evidenceBase,
      tables: {},
      artifacts: [],
      receiptLedger: null,
      historicalCommands: [],
      supplementary: {},
      migratedExecutions: [],
    };
    for (const table of tables) {
      const values = await rows(table);
      data.tables[table] = {
        rows: values,
        count: values.length,
        sha256: hash(canonical(values)),
      };
    }
    for (const table of supplementary) {
      const values = await rows(table);
      data.supplementary[table] = {
        rows: values,
        count: values.length,
        sha256: hash(canonical(values)),
      };
    }
    for (const [name, field] of [
      ["migrated-command-history.json", "historicalCommands"],
      ["migrated-execution-history.json", "migratedExecutions"],
    ]) {
      const file = resolve(historyBase, name);
      if (existsSync(file))
        data[field] = JSON.parse(readFileSync(file, "utf8"));
    }
    for (const row of data.tables.security_fusion_evidence.rows) {
      try {
        const name = safeArtifact(row.storagePath),
          bytes = readFileSync(row.storagePath);
        data.artifacts.push({
          name,
          sha256: hash(bytes),
          data: bytes.toString("base64"),
        });
      } catch (error) {
        if (row.integrityStatus === "verified") throw error;
      }
    }
    const ledger = process.env.SECURITY_FUSION_RECEIPT_CHAIN_EXPORT;
    if (ledger) {
      try {
        data.receiptLedger = readFileSync(ledger).toString("base64");
      } catch (e) {
        if (e.code !== "ENOENT") throw e;
      }
    }
    const hasCommands = (
      await db.query("SELECT to_regclass('public.remote_commands') AS name")
    ).rows[0].name;
    if (hasCommands) {
      data.historicalCommands.push(
        ...(
          await db.query(
            'SELECT row_to_json(c) AS command, row_to_json(r) AS result FROM remote_commands c LEFT JOIN command_results r ON r."commandId"=c.id WHERE c.id IN (SELECT "remoteCommandId" FROM security_fusion_command_outbox)',
          )
        ).rows,
      );
    }
    await db.query("COMMIT");
    const bytes = gzipSync(JSON.stringify(data));
    writeFileSync(file, bytes, { mode: 0o600 });
    console.log(
      JSON.stringify({
        mode,
        archiveSha256: hash(bytes),
        tables: Object.fromEntries(
          Object.entries(data.tables).map(([k, v]) => [
            k,
            { count: v.count, sha256: v.sha256 },
          ]),
        ),
        artifacts: data.artifacts.length,
      }),
    );
  } else {
    const bytes = readFileSync(file),
      data = JSON.parse(
        gunzipSync(bytes, { maxOutputLength: 1024 * 1024 * 1024 }),
      );
    const archiveTables = securityTablesForProfile(
      data.profile ?? process.env.CINDERTRACE_ARCHIVE_PROFILE ?? "dedicated-v1",
    );
    if (
      data.version !== 1 ||
      JSON.stringify(Object.keys(data.tables).sort()) !==
        JSON.stringify(archiveTables)
    )
      throw new Error("Incompatible archive");
    if (
      Object.keys(data.supplementary ?? {}).some(
        (name) => !["security_targets", "security_executions"].includes(name),
      )
    )
      throw new Error("Unexpected supplementary table");
    if (mode === "import" || mode === "replace-frozen") {
      if (
        data.tables.security_fusion_command_outbox.rows.some((row) =>
          ["pending", "dispatching", "unknown"].includes(row.status),
        ) ||
        data.tables.security_fusion_action_approvals.rows.some(
          (row) => row.status === "pending",
        ) ||
        (data.supplementary?.security_executions?.rows ?? []).some(
          (row) => !["completed", "failed"].includes(row.status),
        )
      )
        throw new Error(
          "Pending, active, unknown, or orphaned effects block ownership transfer; reconcile and audit cancellation on the source first",
        );
      for (const row of data.tables.security_fusion_actions.rows) {
        if (
          [
            "previewed",
            "pending_approval",
            "dispatch_pending",
            "executing",
            "verifying",
            "release_pending",
            "releasing",
            "unknown",
          ].includes(row.status) ||
          (row.kind === "host_isolation" && row.status === "succeeded")
        )
          throw new Error(
            "Pending, active, unknown, or isolated actions block ownership transfer; reconcile and audit cancellation on the source first",
          );
      }
    }
    for (const [table, entry] of Object.entries({
      ...data.tables,
      ...(data.supplementary ?? {}),
    })) {
      if (
        entry.count !== entry.rows.length ||
        entry.sha256 !== hash(canonical(entry.rows))
      )
        throw new Error(`Archive digest mismatch: ${table}`);
      if (table === "security_fusion_evidence")
        for (const row of entry.rows) {
          const rel = relative(data.evidenceBase, row.storagePath);
          if (rel.startsWith("..") || isAbsolute(rel))
            throw new Error("Unsafe archived path");
          row.storagePath = join(evidenceBase, rel);
        }
    }
    for (const artifact of data.artifacts) {
      const target = resolve(evidenceBase, artifact.name);
      const rel = relative(evidenceBase, target);
      if (rel.startsWith("..") || isAbsolute(rel))
        throw new Error("Unsafe artifact name");
      const content = Buffer.from(artifact.data, "base64");
      if (hash(content) !== artifact.sha256)
        throw new Error("Artifact digest mismatch");
    }
    if (mode === "import" || mode === "replace-frozen") {
      const replacing = mode === "replace-frozen";
      if (replacing && process.env.SECURITY_MIGRATION_FROZEN !== "true")
        throw new Error(
          "Replacement requires explicitly frozen writers and a current recovery archive",
        );
      // Import is intentionally explicit and requires an empty target; no blind overwrite.
      for (const table of [
        ...tables,
        ...supplementary.filter((t) => t !== "security_targets"),
      ])
        if (
          !replacing &&
          Number(
            (await db.query(`SELECT count(*) AS n FROM "${table}"`)).rows[0].n,
          )
        )
          throw new Error(`Destination is not empty: ${table}`);
      mkdirSync(evidenceBase, { recursive: true, mode: 0o700 });
      for (const artifact of data.artifacts) {
        const target = join(evidenceBase, artifact.name);
        mkdirSync(resolve(target, ".."), { recursive: true, mode: 0o700 });
        writeFileSync(target, Buffer.from(artifact.data, "base64"), {
          mode: 0o600,
        });
      }
      await db.query("BEGIN");
      if (replacing)
        for (const table of [...tables, ...supplementary])
          await db.query(`DELETE FROM "${table}"`);
      else if (data.supplementary?.security_targets)
        await db.query("DELETE FROM security_targets");
      for (const [table, entry] of Object.entries(data.tables)) {
        if (!entry.rows.length) continue;
        const names = Object.keys(entry.rows[0]);
        if (names.some((name) => !/^[A-Za-z][A-Za-z0-9_]*$/.test(name)))
          throw new Error("Unsafe archived column");
        const columns = names.map((name) => `"${name}"`).join(",");
        for (let i = 0; i < entry.rows.length; i += 500)
          await db.query(
            `INSERT INTO "${table}" (${columns}) SELECT ${columns} FROM json_populate_recordset(NULL::"${table}",$1::json)`,
            [JSON.stringify(entry.rows.slice(i, i + 500))],
          );
      }
      for (const table of supplementary)
        for (
          let i = 0;
          i < (data.supplementary?.[table]?.rows.length ?? 0);
          i += 500
        )
          await db.query(
            `INSERT INTO "${table}" SELECT * FROM json_populate_recordset(NULL::"${table}",$1::json)`,
            [JSON.stringify(data.supplementary[table].rows.slice(i, i + 500))],
          );
      await db.query("COMMIT");
      if (
        data.receiptLedger &&
        process.env.SECURITY_FUSION_RECEIPT_CHAIN_EXPORT
      )
        writeFileSync(
          process.env.SECURITY_FUSION_RECEIPT_CHAIN_EXPORT,
          Buffer.from(data.receiptLedger, "base64"),
          { mode: 0o600 },
        );
      mkdirSync(historyBase, { recursive: true, mode: 0o700 });
      writeFileSync(
        resolve(historyBase, "migrated-execution-history.json"),
        JSON.stringify([
          ...(data.migratedExecutions ?? []),
          ...(!supplementary.includes("security_executions")
            ? (data.supplementary?.security_executions?.rows ?? [])
            : []),
        ]),
        { mode: 0o600 },
      );
      writeFileSync(
        resolve(historyBase, "migrated-command-history.json"),
        JSON.stringify(data.historicalCommands),
        { mode: 0o600 },
      );
    }
    if (mode !== "verify-archive") {
      for (const table of [
        ...tables,
        ...supplementary.filter((t) => data.supplementary?.[t]),
      ]) {
        const expected = data.tables[table] ??
          data.supplementary?.[table] ?? { rows: [] };
        const names = expected.rows[0] ? Object.keys(expected.rows[0]) : null;
        const actual = (await rows(table)).map((row) =>
          names
            ? Object.fromEntries(names.map((name) => [name, row[name]]))
            : row,
        );
        if (
          hash(canonical(actual)) !==
          hash(
            canonical(
              (
                data.tables[table] ??
                data.supplementary?.[table] ?? { rows: [] }
              ).rows,
            ),
          )
        )
          throw new Error(`Destination mismatch: ${table}`);
      }
      for (const artifact of data.artifacts)
        if (
          hash(readFileSync(join(evidenceBase, artifact.name))) !==
          artifact.sha256
        )
          throw new Error("Destination artifact mismatch");
    }
    console.log(
      JSON.stringify({
        mode,
        archiveSha256: hash(bytes),
        verifiedTables: tables.length,
        verifiedArtifacts: data.artifacts.length,
      }),
    );
  }
} finally {
  await db.end();
}
