// Streaming native PostgreSQL recovery archive. No credentials or row contents are logged.
import { createRequire } from "node:module";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import {
  createReadStream,
  createWriteStream,
  readFileSync,
  writeFileSync,
  existsSync,
  readdirSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  copyFileSync,
  statSync,
  chmodSync,
  openSync,
  readSync,
  closeSync,
} from "node:fs";
import { join, resolve, relative, isAbsolute } from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { securityTablesForProfile } from "../services/security-fusion/scripts/security-table-contract.mjs";
const require = createRequire(
  new URL("../services/security-fusion/package.json", import.meta.url),
);
require("dotenv").config({ quiet: true });
const { Client } = require("pg");
const [mode, suppliedFile] = process.argv.slice(2);
if (
  !["backup", "restore", "verify", "verify-restored", "import"].includes(mode)
)
  throw new Error("Usage: backup.mjs backup|restore|verify FILE");
const key = Buffer.from(
  process.env.SECURITY_BACKUP_ENCRYPTION_KEY ?? "",
  "hex",
);
if (key.length !== 32)
  throw new Error("A dedicated 32-byte hex backup key is required");
const state = resolve(process.env.CINDERTRACE_STATE_DIR ?? "state");
mkdirSync(state, { recursive: true, mode: 0o700 });
const file = suppliedFile
  ? resolve(suppliedFile)
  : mode === "backup"
    ? join(
        state,
        `security-${new Date()
          .toISOString()
          .replace(/\.\d{3}Z$/, "Z")
          .replace(/[-:]/g, "")}.aes`,
      )
    : null;
if (!file) throw new Error("A recovery file is required");
const temporary = mkdtempSync(join(state, "native-recovery-"));
chmodSync(temporary, 0o700);
const compressed = join(temporary, "recovery.tar.gz");
const evidenceBase = resolve(
  process.env.SECURITY_FUSION_EVIDENCE_DIR ?? "state/security-fusion/evidence",
);
const url = new URL(process.env.DATABASE_URL ?? "");
const pgEnv = {
  ...process.env,
  PGHOST: url.hostname,
  PGPORT: url.port || "5432",
  PGUSER: decodeURIComponent(url.username),
  PGPASSWORD: decodeURIComponent(url.password),
  PGDATABASE: url.pathname.slice(1),
  PGOPTIONS: "-c timezone=UTC",
};
const db = new Client({ connectionString: process.env.DATABASE_URL });
let connected = false;
function run(command, args, env = pgEnv) {
  return new Promise((done, reject) => {
    const child = spawn(command, args, {
      env,
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 4096) stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (code) =>
      code === 0
        ? done()
        : (writeFileSync(
            join(state, `recovery-${Date.now()}-${command}.stderr.private`),
            stderr,
            { mode: 0o600 },
          ),
          reject(
            new Error(
              `${command} failed (exit ${code}); inspect the private recovery diagnostic`,
            ),
          )),
    );
  });
}
async function streamHash(stream) {
  const hash = createHash("sha256");
  for await (const chunk of stream) hash.update(chunk);
  return hash.digest("hex");
}
async function tableDigest(table, snapshot, base, columns = null) {
  if (!/^[a-z_]+$/.test(table)) throw new Error("Unexpected table name");
  if (
    columns &&
    (columns.length > 45 ||
      columns.some((name) => !/^[A-Za-z][A-Za-z0-9_]*$/.test(name)))
  )
    throw new Error("Unreviewed recovery columns");
  const projection = columns
    ? `jsonb_build_object(${columns.flatMap((name) => ["'" + name + "'", 't."' + name + '"']).join(",")})`
    : "to_jsonb(t)";
  const row =
    table === "security_fusion_evidence"
      ? `jsonb_set(${projection},'{storagePath}',to_jsonb(CASE WHEN left(t."storagePath",${Buffer.byteLength(base)})=${"'" + base.replaceAll("'", "''") + "'"} THEN substring(t."storagePath" from ${base.length + 1}) ELSE t."storagePath" END))`
      : projection;
  const keyColumn = table === "security_fusion_nonces" ? "nonce" : "id";
  if (snapshot && !/^[A-Fa-f0-9-]+$/.test(snapshot))
    throw new Error("Unexpected snapshot identity");
  const sql = `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;${snapshot ? ` SET TRANSACTION SNAPSHOT '${snapshot}';` : ""} COPY (SELECT ${row} FROM "${table}" t ORDER BY "${keyColumn}" COLLATE "C") TO STDOUT; COMMIT;`;
  const child = spawn(
    "psql",
    ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql],
    { env: pgEnv, stdio: ["ignore", "pipe", "pipe"] },
  );
  let error = "";
  child.stderr.on("data", (chunk) => {
    if (error.length < 4096) error += chunk;
  });
  const completion = new Promise((done, reject) => {
    child.once("error", reject);
    child.once("close", (code) =>
      code === 0
        ? done()
        : reject(
            new Error("Database digest query failed; recovery is not verified"),
          ),
    );
  });
  const hash = await streamHash(child.stdout);
  await completion;
  return hash;
}
function safeRelative(value) {
  if (
    !value ||
    isAbsolute(value) ||
    value.split(/[\\/]/).some((part) => !part || part === "." || part === "..")
  )
    throw new Error("Unsafe recovery path");
  return value;
}
function allFiles(root, prefix = "") {
  if (!existsSync(root)) return [];
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const rel = prefix + entry.name,
      p = join(root, entry.name);
    if (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile()))
      throw new Error("Recovery refuses symlinks and special files");
    return entry.isDirectory()
      ? allFiles(p, rel + "/")
      : [{ path: p, relative: safeRelative(rel) }];
  });
}
try {
  if (mode === "backup") {
    await db.connect();
    connected = true;
    await db.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const snapshot = (await db.query("SELECT pg_export_snapshot() AS id"))
      .rows[0].id;
    const observed = (
      await db.query(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'security_fusion_%' ORDER BY tablename",
      )
    ).rows.map((x) => x.tablename);
    const profile = process.env.CINDERTRACE_SOURCE_PROFILE ?? "current";
    if (
      JSON.stringify(observed) !==
      JSON.stringify(securityTablesForProfile(profile))
    )
      throw new Error(
        "Database differs from the explicit reviewed schema profile",
      );
    const extra = (
      await db.query(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename IN ('security_targets','security_executions','_prisma_migrations') ORDER BY tablename",
      )
    ).rows.map((x) => x.tablename);
    const tables = [...observed, ...extra];
    await run("pg_dump", [
      "--format=custom",
      "--no-owner",
      "--no-acl",
      "--snapshot=" + snapshot,
      "--file=" + join(temporary, "database.dump"),
      ...tables.flatMap((name) => ["--table=public." + name]),
    ]);
    const unsafeActions = Number(
      (
        await db.query(
          "SELECT count(*) AS n FROM security_fusion_actions WHERE status IN ('previewed','pending_approval','dispatch_pending','executing','verifying','release_pending','releasing','unknown') OR (kind='host_isolation' AND status='succeeded')",
        )
      ).rows[0].n,
    );
    const unsafeOutbox = Number(
      (
        await db.query(
          "SELECT count(*) AS n FROM security_fusion_command_outbox WHERE status IN ('pending','dispatching','unknown')",
        )
      ).rows[0].n,
    );
    const manifest = {
      version: 2,
      transferSafe: unsafeActions === 0 && unsafeOutbox === 0,
      databaseSha256: await streamHash(
        createReadStream(join(temporary, "database.dump")),
      ),
      profile,
      createdAt: new Date().toISOString(),
      evidenceBase,
      tables: {},
      assets: [],
    };
    for (const table of tables) {
      const columns = (
        await db.query(
          "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 ORDER BY ordinal_position",
          [table],
        )
      ).rows.map((row) => row.column_name);
      manifest.tables[table] = {
        columns,
        count: String(
          (await db.query(`SELECT count(*) AS n FROM "${table}"`)).rows[0].n,
        ),
        sha256: await tableDigest(table, snapshot, evidenceBase, columns),
      };
    }
    await db.query("COMMIT");
    mkdirSync(join(temporary, "assets"), { mode: 0o700 });
    const add = async (role, path, name) => {
      if (!existsSync(path))
        throw new Error("Configured recovery asset is missing");
      if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink())
        throw new Error("Unsafe recovery asset");
      const archive =
        "assets/" + String(manifest.assets.length).padStart(8, "0");
      copyFileSync(path, join(temporary, archive));
      chmodSync(join(temporary, archive), 0o600);
      manifest.assets.push({
        role,
        relative: safeRelative(name),
        archive,
        sha256: await streamHash(createReadStream(join(temporary, archive))),
      });
    };
    for (const item of allFiles(evidenceBase))
      await add("evidence", item.path, item.relative);
    for (const item of allFiles(
      resolve(process.env.AUDIT_LOG_DIR ?? join(state, "audit-logs")),
    ))
      await add("audit", item.path, item.relative);
    for (const [role, path] of Object.entries({
      ledger: process.env.SECURITY_FUSION_RECEIPT_CHAIN_EXPORT,
      checkpoint: process.env.CINDERTRACE_COLLECTOR_BOUNDARY_FILE,
      environment: process.env.CINDERTRACE_BACKUP_ENV_FILE,
    }))
      if (path) await add(role, path, role + ".private");
    writeFileSync(join(temporary, "manifest.json"), JSON.stringify(manifest), {
      mode: 0o600,
    });
    await run("tar", [
      "-czf",
      compressed,
      "-C",
      temporary,
      "manifest.json",
      "database.dump",
      "assets",
    ]);
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", key, iv),
      output = createWriteStream(file, { flags: "wx", mode: 0o600 });
    output.write(Buffer.concat([Buffer.from("CNDR0002"), iv]));
    await pipeline(createReadStream(compressed), cipher, output, {
      end: false,
    });
    output.end(cipher.getAuthTag());
    await new Promise((done, reject) => {
      output.once("finish", done);
      output.once("error", reject);
    });
    const sha256 = await streamHash(createReadStream(file)),
      bytes = statSync(file).size;
    if (process.env.SECURITY_BACKUP_UPLOAD_URL) {
      const target = new URL(process.env.SECURITY_BACKUP_UPLOAD_URL);
      if (target.protocol !== "https:")
        throw new Error("Off-host backup requires verified HTTPS");
      if (bytes > 512 * 1024 * 1024)
        throw new Error(
          "Backup exceeds the configured receiver limit; encrypted local archive retained",
        );
      const response = await fetch(target, {
        method: "POST",
        redirect: "error",
        headers: {
          Authorization: `Bearer ${process.env.SECURITY_BACKUP_TOKEN ?? ""}`,
          "content-type": "application/octet-stream",
          "x-backup-name": file.split("/").at(-1),
          "x-backup-sha256": sha256,
        },
        body: createReadStream(file),
        duplex: "half",
        signal: AbortSignal.timeout(180000),
      });
      if (!response.ok)
        throw new Error(
          `Off-host backup HTTP ${response.status}; encrypted local archive retained`,
        );
    }
    const record = {
      success: true,
      completedAt: new Date().toISOString(),
      name: file.split("/").at(-1),
      sha256,
      bytes,
      format: 2,
      tableCount: tables.length,
    };
    writeFileSync(
      process.env.SECURITY_BACKUP_STATUS_FILE ??
        join(state, "backup-status.json"),
      JSON.stringify(record),
      { mode: 0o600 },
    );
    console.log(JSON.stringify(record));
  } else {
    const info = statSync(file);
    if (info.size < 36) throw new Error("Truncated backup");
    const headerFd = openSync(file, "r"),
      descriptor = Buffer.alloc(20);
    readSync(headerFd, descriptor, 0, 20, 0);
    closeSync(headerFd);
    if (descriptor.subarray(0, 8).toString() !== "CNDR0002")
      throw new Error("Unknown native recovery format");
    const fd = openSync(file, "r");
    const tag = Buffer.alloc(16);
    readSync(fd, tag, 0, 16, info.size - 16);
    closeSync(fd);
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      descriptor.subarray(8, 20),
    );
    decipher.setAuthTag(tag);
    await pipeline(
      createReadStream(file, { start: 20, end: info.size - 17 }),
      decipher,
      createWriteStream(compressed, { flags: "wx", mode: 0o600 }),
    );
    const names = execFileSync("tar", ["-tzf", compressed], {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    })
      .trim()
      .split("\n");
    if (
      names.some(
        (name) =>
          !["manifest.json", "database.dump", "assets/"].includes(name) &&
          !/^assets\/[0-9]{8}$/.test(name),
      )
    )
      throw new Error("Unsafe native recovery archive");
    const kinds = execFileSync("tar", ["-tvzf", compressed], {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    })
      .trim()
      .split("\n");
    if (kinds.some((line) => !["-", "d"].includes(line[0])))
      throw new Error("Recovery archive contains a link or special file");
    await run("tar", [
      "-xzf",
      compressed,
      "--no-same-owner",
      "--no-same-permissions",
      "-C",
      temporary,
    ]);
    const manifest = JSON.parse(
      readFileSync(join(temporary, "manifest.json"), "utf8"),
    );
    if (manifest.version !== 2) throw new Error("Unknown native manifest");
    if (
      manifest.databaseSha256 !==
      (await streamHash(createReadStream(join(temporary, "database.dump"))))
    )
      throw new Error("Database archive digest mismatch");
    const core = Object.keys(manifest.tables)
      .filter((x) => x.startsWith("security_fusion_"))
      .sort();
    if (
      JSON.stringify(core) !==
      JSON.stringify(securityTablesForProfile(manifest.profile))
    )
      throw new Error("Unreviewed recovery schema");
    if (
      Object.keys(manifest.tables).some(
        (x) =>
          !core.includes(x) &&
          ![
            "security_targets",
            "security_executions",
            "_prisma_migrations",
          ].includes(x),
      )
    )
      throw new Error("Unreviewed recovery table");
    for (const asset of manifest.assets) {
      safeRelative(asset.relative);
      if (
        !/^assets\/[0-9]{8}$/.test(asset.archive) ||
        asset.sha256 !==
          (await streamHash(createReadStream(join(temporary, asset.archive))))
      )
        throw new Error("Recovery asset digest mismatch");
    }
    if (mode === "restore" || mode === "import") {
      const importing = mode === "import";
      if (
        importing
          ? process.env.CINDERTRACE_TRANSFER_CONFIRM !==
            "frozen-source-empty-destination"
          : process.env.CINDERTRACE_RESTORE_CONFIRM !==
            "empty-isolated-destination"
      )
        throw new Error(
          "Explicit isolated destination confirmation is required",
        );
      await db.connect();
      connected = true;
      if (importing) {
        if (manifest.transferSafe !== true)
          throw new Error(
            "Pending, active, or unknown effects block ownership transfer",
          );
        const current = (
          await db.query(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'security_fusion_%' ORDER BY tablename",
          )
        ).rows.map((row) => row.tablename);
        if (
          JSON.stringify(current) !==
          JSON.stringify(securityTablesForProfile("current"))
        )
          throw new Error(
            "Import requires the prepared current Cindertrace schema",
          );
        for (const table of [
          ...current,
          "security_targets",
          "security_executions",
        ])
          if (
            (await db.query(`SELECT count(*) AS n FROM "${table}"`)).rows[0]
              .n !== "0"
          )
            throw new Error("Import destination contains security state");
        const entries = execFileSync(
          "pg_restore",
          ["--list", join(temporary, "database.dump")],
          { encoding: "utf8" },
        )
          .split("\n")
          .filter((line) => {
            const match = /\bTABLE DATA public ([a-z_]+) /.exec(line);
            return (
              match &&
              match[1] !== "_prisma_migrations" &&
              Object.hasOwn(manifest.tables, match[1])
            );
          });
        writeFileSync(join(temporary, "data.list"), entries.join("\n") + "\n", {
          mode: 0o600,
        });
        await run("pg_restore", [
          "--data-only",
          "--no-owner",
          "--no-acl",
          "--exit-on-error",
          "--use-list=" + join(temporary, "data.list"),
          "--dbname=" + url.pathname.slice(1),
          join(temporary, "database.dump"),
        ]);
      } else {
        if (
          (
            await db.query(
              "SELECT count(*) AS n FROM pg_tables WHERE schemaname='public'",
            )
          ).rows[0].n !== "0"
        )
          throw new Error("Restore destination is not empty");
        await run("pg_restore", [
          "--no-owner",
          "--no-acl",
          "--exit-on-error",
          "--dbname=" + url.pathname.slice(1),
          join(temporary, "database.dump"),
        ]);
      }
      for (const asset of manifest.assets) {
        const base =
          asset.role === "evidence"
            ? evidenceBase
            : asset.role === "audit"
              ? resolve(process.env.AUDIT_LOG_DIR ?? join(state, "audit-logs"))
              : state;
        let target =
          asset.role === "ledger"
            ? process.env.SECURITY_FUSION_RECEIPT_CHAIN_EXPORT
            : asset.role === "checkpoint"
              ? process.env.CINDERTRACE_COLLECTOR_BOUNDARY_FILE
              : null;
        target = target ? resolve(target) : join(base, asset.relative);
        const rel = relative(base, target);
        if (asset.role === "evidence" || asset.role === "audit")
          safeRelative(rel);
        mkdirSync(resolve(target, ".."), { recursive: true, mode: 0o700 });
        if (existsSync(target))
          throw new Error("Recovery refuses to overwrite an existing asset");
        copyFileSync(join(temporary, asset.archive), target, 1);
        chmodSync(target, 0o600);
      }
      if (manifest.evidenceBase !== evidenceBase)
        await db.query(
          'UPDATE security_fusion_evidence SET "storagePath"=$1 || substring("storagePath" from $2::integer) WHERE left("storagePath",$3::integer)=$4',
          [
            evidenceBase,
            manifest.evidenceBase.length + 1,
            manifest.evidenceBase.length,
            manifest.evidenceBase,
          ],
        );
    }
    if (mode === "restore" || mode === "verify-restored" || mode === "import") {
      if (!connected) {
        await db.connect();
        connected = true;
      }
      for (const [table, expected] of Object.entries(manifest.tables)) {
        if (mode === "import" && table === "_prisma_migrations") continue;
        const count = String(
          (await db.query(`SELECT count(*) AS n FROM "${table}"`)).rows[0].n,
        );
        if (
          count !== expected.count ||
          (await tableDigest(
            table,
            null,
            evidenceBase,
            expected.columns ?? null,
          )) !== expected.sha256
        )
          throw new Error(
            `Restored database differs from native snapshot: ${table}`,
          );
      }
      for (const asset of manifest.assets) {
        const base =
          asset.role === "evidence"
            ? evidenceBase
            : asset.role === "audit"
              ? resolve(process.env.AUDIT_LOG_DIR ?? join(state, "audit-logs"))
              : state;
        const configured =
          asset.role === "ledger"
            ? process.env.SECURITY_FUSION_RECEIPT_CHAIN_EXPORT
            : asset.role === "checkpoint"
              ? process.env.CINDERTRACE_COLLECTOR_BOUNDARY_FILE
              : null;
        const target = configured
          ? resolve(configured)
          : join(base, safeRelative(asset.relative));
        if (
          !existsSync(target) ||
          lstatSync(target).isSymbolicLink() ||
          (await streamHash(createReadStream(target))) !== asset.sha256
        )
          throw new Error("Restored asset differs from the native snapshot");
      }
    }

    console.log(
      JSON.stringify({
        success: true,
        mode,
        format: 2,
        tableCount: Object.keys(manifest.tables).length,
        assetsVerified: manifest.assets.length,
      }),
    );
  }
} finally {
  if (connected) await db.end();
  rmSync(temporary, { recursive: true, force: true });
}
