#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  openSync,
  closeSync,
  unlinkSync,
  existsSync,
  realpathSync,
  appendFileSync,
} from "node:fs";
import { resolve, join } from "node:path";
import { spawn } from "node:child_process";
import { randomUUID, createHash } from "node:crypto";
import {
  assertSafeState,
  assertMigrations,
  atomicPrivate,
  readEnvironment,
  renderEnvironment,
  pausedEnvironment,
  assertUpgradeNode,
} from "./upgrade-policy.mjs";
import { NativeInstallation } from "./upgrade-native.mjs";
import { ComposeInstallation } from "./upgrade-compose.mjs";
const help = `Usage: node scripts/upgrade.mjs upgrade --to COMMIT [--project-dir DIR] [--install PRIVATE_NATIVE_MANIFEST --archive FILE --sha256 DIGEST]\n       node scripts/upgrade.mjs status|resume|rollback --id ID [--project-dir DIR | --install MANIFEST] [--retain-current-state]\nA pinned 40-character public commit is required. Native archives must be from that exact verified revision.\nNo database restore or uncertain command redispatch occurs during rollback.`;
function options(argv) {
  const out = { mode: "upgrade", projectDir: process.cwd() };
  if (argv[0] && !argv[0].startsWith("--")) out.mode = argv.shift();
  if (argv.includes("--help")) {
    console.log(help);
    process.exit(0);
  }
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (key === "--dry-run") {
      out.dryRun = true;
      continue;
    }
    if (key === "--retain-current-state") {
      out.retain = true;
      continue;
    }
    const keys = {
      "--to": "revision",
      "--id": "id",
      "--project-dir": "projectDir",
      "--install": "install",
      "--archive": "archive",
      "--sha256": "sha256",
    };
    assert(
      keys[key] && argv[i + 1] && !argv[i + 1].startsWith("--"),
      "Unknown or missing option; use --help",
    );
    out[keys[key]] = argv[++i];
  }
  assert(
    ["upgrade", "resume", "rollback", "status"].includes(out.mode),
    "Unsupported operation",
  );
  if (out.mode === "upgrade")
    assert(
      /^[a-f0-9]{40}$/.test(out.revision ?? ""),
      "Select the exact 40-character release commit",
    );
  else
    assert(
      /^[a-f0-9-]{36}$/.test(out.id ?? ""),
      "Select the retained upgrade ID",
    );
  return out;
}
let directory,
  record,
  backend,
  lock,
  lockOwned = false;
try {
  const opts = options(process.argv.slice(2));
  assertUpgradeNode();
  const project = resolve(opts.projectDir);
  let log;
  const run = (
    args,
    { cwd, env, input, allowFailure = false, binary = false, uid, gid } = {},
  ) =>
    new Promise((done, reject) => {
      const child = spawn(args[0], args.slice(1), {
        cwd: cwd ?? project,
        env: env ?? process.env,
        stdio: ["pipe", "pipe", "pipe"],
        uid,
        gid,
      });
      const stdout = [];
      const timeout = setTimeout(() => child.kill("SIGTERM"), 30 * 60_000);
      let bytes = 0;
      child.stdout.on("data", (b) => {
        bytes += b.length;
        if (bytes > 64 * 1024 * 1024) {
          child.kill("SIGTERM");
        } else stdout.push(b);
      });
      child.stderr.on("data", (b) => {
        if (log) appendFileSync(log, b, { mode: 0o600 });
      });
      child.once("error", (e) => {
        clearTimeout(timeout);
        reject(e);
      });
      child.once("close", (code) => {
        clearTimeout(timeout);
        const out = Buffer.concat(stdout);
        if (code === 0 || allowFailure) done(binary ? out : out.toString());
        else
          reject(
            Error(
              "Command failed (" +
                args[0].split("/").at(-1) +
                "); inspect the private upgrade diagnostic",
            ),
          );
      });
      if (input !== undefined) child.stdin.end(input);
      else child.stdin.end();
    });
  backend = opts.install
    ? new NativeInstallation(resolve(opts.install), run)
    : new ComposeInstallation(project, run);
  const root = opts.install ? backend.config.recordRoot : backend.recordRoot;
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const id = opts.mode === "upgrade" ? randomUUID() : opts.id;
  directory = join(root, id);
  if (opts.mode === "upgrade") mkdirSync(directory, { mode: 0o700 });
  else
    assert(
      existsSync(join(directory, "record.json")),
      "Upgrade record does not exist",
    );
  log = join(directory, "diagnostic.private.log");
  lock = join(root, "upgrade.lock");
  if (opts.mode === "status") {
    const saved = JSON.parse(readFileSync(join(directory, "record.json")));
    console.log(
      JSON.stringify({
        id: saved.id,
        phase: saved.phase,
        revision: saved.revision,
        restoreVerified: Boolean(saved.restoreVerified),
        writesMayHaveStarted: Boolean(saved.writeEnableAttemptedAt),
        lastError: saved.lastError ?? null,
      }),
    );
    process.exit(0);
  }
  // A stale lock requires an explicit process/state review. Never guess that its owner is dead.
  const fd = openSync(lock, "wx", 0o600);
  writeFileSync(fd, JSON.stringify({ pid: process.pid, id }));
  closeSync(fd);
  lockOwned = true;
  const save = (phase) => {
    record.phase = phase;
    record.updatedAt = new Date().toISOString();
    atomicPrivate(
      join(directory, "record.json"),
      JSON.stringify(record, null, 2) + "\n",
    );
  };
  if (opts.mode === "upgrade") {
    record = {
      schemaVersion: 1,
      id,
      directory,
      backend: opts.install ? "native" : "compose",
      revision: opts.revision,
      startedAt: new Date().toISOString(),
      phase: "preflight",
    };
    save("preflight");
    const initial = await backend.preflight();
    assertSafeState(initial.state);
    assert(
      initial.schemaKnown !== false,
      "Unrecognized installed security schema",
    );
    record.before = initial;
    save("building");
    const manifest = await backend.prepare(opts, record);
    assert.equal(manifest.schemaVersion, 1);
    assert.equal(manifest.product, "cindertrace");
    assert.equal(manifest.layoutVersion, 1);
    assertMigrations(initial.migrations, manifest.migrations);
    record.release = manifest;
    save("prepared");
    if (opts.dryRun) {
      save("ready");
      console.log(
        JSON.stringify({
          id: record.id,
          revision: record.revision,
          status: "ready",
          servicesChanged: false,
        }),
      );
      unlinkSync(lock);
      lockOwned = false;
      process.exit(0);
    }
  } else {
    record = JSON.parse(readFileSync(join(directory, "record.json")));
    assert.equal(record.backend, opts.install ? "native" : "compose");
    assert.equal(record.directory, directory);
    if (record.backend === "native") {
      assert.deepEqual(
        backend.config,
        record.installation,
        "Installation manifest changed",
      );
      backend.candidate = record.candidateRuntime;
      backend.oldRuntime = record.previousRuntime;
      backend.originalEnv = record.previousEnvironment;
      backend.env = readEnvironment(record.previousEnvironment.api);
    } else {
      backend.project = record.project;
      backend.image = record.image;
      backend.oldImage = record.previousImage;
      backend.originalEnv = record.previousEnvironment;
      backend.env = readEnvironment(record.previousEnvironment);
      backend.beforeFile = record.beforeFile;
      backend.before = JSON.parse(readFileSync(record.beforeFile));
      backend.stateHost = backend.hostPath(
        "api",
        backend.before.services.api.environment.CINDERTRACE_STATE_DIR ??
          "/state",
      );
    }
    if (opts.mode === "rollback") {
      assert(
        record.links || record.beforeFile,
        "No activation state to roll back",
      );
      assert(
        record.release?.rollbackCompatible === true,
        "This release requires a reviewed application/schema reconciliation",
      );
      if (record.writeEnableAttemptedAt)
        assert(
          opts.retain,
          "New writes may exist; review current state and pass --retain-current-state for code-only rollback",
        );
      const current = await (backend.inspect
        ? backend.inspect()
        : backend
            .node(
              backend.candidate ?? backend.oldRuntime,
              ["--input-type=module", "-"],
              backend.env,
              readFileSync(
                new URL("./upgrade-probe.mjs", import.meta.url),
                "utf8",
              ),
            )
            .then(JSON.parse));
      assertSafeState(current.state);
      assertMigrations(current.migrations, record.release.migrations);
      assertMigrations(
        record.before.migrations,
        Object.fromEntries(
          current.migrations.map((m) => [m.migration_name, m.checksum]),
        ),
      );
      save("rollback-started");
      await backend.rollback(record);
      save("rolled-back-current-state");
      console.log(
        "Application rollback passed. Current database, evidence, audit, and collector state were retained.",
      );
      unlinkSync(lock);
      lockOwned = false;
      process.exit(0);
    }
    assert(
      !record.writeEnableAttemptedAt,
      "A writer may have started; reconcile current state before further activation",
    );
    assert(
      record.restoreVerified || ["ready", "prepared"].includes(record.phase),
      "Resume requires a completed independent restore; use code rollback and start a new upgrade after reviewing an interrupted backup",
    );
    assert(
      !["complete", "rolled-back-current-state"].includes(record.phase),
      "Upgrade is already terminal",
    );
  }
  await backend.pause(record);
  save("paused");
  const frozen = backend.inspect
    ? await backend.inspect()
    : JSON.parse(
        await backend.node(
          backend.oldRuntime,
          ["--input-type=module", "-"],
          backend.env,
          readFileSync(new URL("./upgrade-probe.mjs", import.meta.url), "utf8"),
        ),
      );
  assertSafeState(frozen.state);
  assert.equal(
    frozen.otherClientSessions,
    0,
    "Unrecognized database client remains after pausing",
  );
  assertMigrations(frozen.migrations, record.release.migrations);
  if (!record.restoreVerified) {
    save("backup-started");
    await backend.snapshot(record);
    save("backup-verified");
    await backend.restoreRehearsal(record);
    save("restore-verified");
  }
  save("migration-started");
  await backend.migrate(record);
  save("migrated");
  await backend.activate(record);
  await backend.healthy(record);
  save("healthy-paused");
  // This is recorded BEFORE allowing a writer to start. A lost reply cannot permit a stale restore.
  record.writeEnableAttemptedAt = new Date().toISOString();
  save("resuming");
  await backend.resume(record);
  save("complete");
  console.log(
    JSON.stringify({
      id: record.id,
      revision: record.revision,
      status: "complete",
      independentRestoreVerified: true,
      backupRetained: true,
    }),
  );
} catch (error) {
  if (directory && record) {
    record.lastError =
      "Upgrade stopped; inspect the private diagnostic and reconcile the recorded phase";
    record.failedAt = new Date().toISOString();
    try {
      atomicPrivate(
        join(directory, "record.json"),
        JSON.stringify(record, null, 2) + "\n",
      );
      writeFileSync(
        join(directory, "failure.private.txt"),
        String(error.stack ?? error),
        { mode: 0o600 },
      );
    } catch {}
  }
  console.error(
    "Cindertrace upgrade stopped. " +
      (directory
        ? "Private record: " + join(directory, "record.json")
        : error.message),
  );
  process.exitCode = 1;
} finally {
  if (lockOwned) unlinkSync(lock);
}
