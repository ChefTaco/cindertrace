import assert from "node:assert/strict";
import {
  verifyRuntimeFiles,
  copyVerifiedRuntimeArchive,
  runtimeExtractionCommand,
} from "./upgrade-artifacts.mjs";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  realpathSync,
  readlinkSync,
  lstatSync,
  symlinkSync,
  renameSync,
  chownSync,
  readdirSync,
  statfsSync,
} from "node:fs";
import { join, resolve, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  absolutePath,
  unitName,
  privateFile,
  readEnvironment,
  renderEnvironment,
  pausedEnvironment,
  atomicPrivate,
  recoveryArchiveName,
  upgradeChildEnvironment,
} from "./upgrade-policy.mjs";
const probe = readFileSync(
  new URL("./upgrade-probe.mjs", import.meta.url),
  "utf8",
);
function protectedDirectory(path) {
  let current = path;
  while (!existsSync(current)) current = dirname(current);
  for (;;) {
    const stat = lstatSync(current);
    assert(
      stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        stat.uid === 0 &&
        (stat.mode & 0o022) === 0,
      "Native release/configuration directories must remain root-controlled",
    );
    if (dirname(current) === current) break;
    current = dirname(current);
  }
}
export class NativeInstallation {
  constructor(file, run) {
    assert.equal(
      process.getuid?.(),
      0,
      "Native upgrades require root on the installation host",
    );
    assert.equal(
      privateFile(file).uid,
      0,
      "Native manifest must be root-owned",
    );
    protectedDirectory(dirname(file));
    this.config = JSON.parse(readFileSync(file));
    assert.equal(this.config.schemaVersion, 1);
    assert.equal(this.config.backend, "native");
    this.run = run;
    const c = this.config;
    for (const k of ["runtimeRoot", "releaseRoot", "recordRoot"]) {
      absolutePath(c[k]);
      protectedDirectory(k === "runtimeRoot" ? dirname(c[k]) : c[k]);
    }
    this.names = ["api", "console", ...(c.collector ? ["collector"] : [])];
    for (const n of this.names) {
      const s = c[n];
      unitName(s.unit);
      absolutePath(s.root);
      absolutePath(s.env);
      assert(/^[a-z_][a-z0-9_-]*$/.test(s.user));
      privateFile(s.env);
      assert.equal(
        s.user,
        c.api.user,
        "Native managed upgrades currently require one application service account",
      );
    }
    assert(
      /^https:\/\//.test(c.apiHealth) && /^https:\/\//.test(c.consoleHealth),
    );
    absolutePath(c.caFile);
    this.env = readEnvironment(readFileSync(c.api.env, "utf8"));
    assert(
      /^[a-fA-F0-9]{64}$/.test(this.env.SECURITY_BACKUP_ENCRYPTION_KEY ?? ""),
      "A dedicated backup key is required",
    );
    this.oldRuntime = realpathSync(c.runtimeRoot);
    this.originalEnv = Object.fromEntries(
      this.names.map((n) => [n, readFileSync(c[n].env, "utf8")]),
    );
    this.owner = {
      uid: Number(execFileSync("id", ["-u", c.api.user], { encoding: "utf8" })),
      gid: Number(execFileSync("id", ["-g", c.api.user], { encoding: "utf8" })),
    };
  }
  async command(args, options = {}) {
    return this.run(args, options);
  }
  async node(runtime, args, env = this.env, input) {
    return this.command([process.execPath, ...args], {
      cwd: runtime,
      uid: this.owner.uid,
      gid: this.owner.gid,
      env: upgradeChildEnvironment({
        ...process.env,
        ...env,
        UPGRADE_RUNTIME_ROOT: runtime,
      }),
      input,
    });
  }
  async preflight(runtime = this.oldRuntime) {
    assert(
      Number(statfsSync(this.config.releaseRoot).bavail) *
        Number(statfsSync(this.config.releaseRoot).bsize) >
        2 * 1024 ** 3,
      "At least 2 GiB free release space is required",
    );
    for (const n of this.names) {
      const service = this.config[n];
      const raw = await this.command([
        "systemctl",
        "show",
        service.unit,
        "-p",
        "User",
        "-p",
        "WorkingDirectory",
      ]);
      const fields = Object.fromEntries(
        raw
          .trim()
          .split("\n")
          .map((x) => x.split("=")),
      );
      assert.equal(
        fields.User || "root",
        service.user,
        "Service ownership differs from installation manifest",
      );
      assert.equal(
        fields.WorkingDirectory,
        n === "console"
          ? join(service.root, "apps/security-console")
          : service.root,
        "Service working directory differs from installation manifest",
      );
    }
    for (const n of ["api", "console"])
      assert.equal(
        (
          await this.command(["systemctl", "is-active", this.config[n].unit])
        ).trim(),
        "active",
      );
    return JSON.parse(
      await this.node(runtime, ["--input-type=module", "-"], this.env, probe),
    );
  }
  async inspect() {
    return JSON.parse(
      await this.node(
        this.oldRuntime,
        ["--input-type=module", "-"],
        this.env,
        probe,
      ),
    );
  }
  async prepare(options, record) {
    assert(
      options.archive && /^[a-f0-9]{64}$/.test(options.sha256 ?? ""),
      "Native upgrade needs --archive and its verified --sha256",
    );
    const archive = await copyVerifiedRuntimeArchive(
      absolutePath(resolve(options.archive)),
      join(record.directory, "candidate-runtime.tar.gz"),
      options.sha256,
    );
    const finalCandidate = join(this.config.releaseRoot, record.revision);
    const stageCandidate = join(
      this.config.releaseRoot,
      ".upgrade-" + record.id,
    );
    const reuse = existsSync(finalCandidate);
    this.candidate = reuse ? finalCandidate : stageCandidate;
    record.stagingRuntime = stageCandidate;
    if (reuse) {
      assert.equal(
        readFileSync(
          join(finalCandidate, ".cindertrace-archive.sha256"),
          "utf8",
        ).trim(),
        options.sha256,
        "Existing staged runtime has another archive identity",
      );
    } else {
      mkdirSync(this.candidate, { mode: 0o755 });
      await this.command(runtimeExtractionCommand(archive, this.candidate));
    }
    const manifest = JSON.parse(
      readFileSync(join(this.candidate, "cindertrace-release.json")),
    );
    assert.equal(manifest.product, "cindertrace");
    assert.equal(manifest.layoutVersion, 1);
    assert.equal(manifest.revision, record.revision);
    assert.equal(
      manifest.platform?.os,
      process.platform,
      "Native archive operating system differs",
    );
    assert.equal(
      manifest.platform?.arch,
      process.arch,
      "Native archive architecture differs",
    );
    verifyRuntimeFiles(this.candidate, manifest.files);
    const migrationRoot = join(
      this.candidate,
      "services/security-fusion/prisma/migrations",
    );
    const actual = Object.fromEntries(
      readdirSync(migrationRoot)
        .filter((n) => /^\d{14}_/.test(n))
        .map((n) => [
          n,
          createHash("sha256")
            .update(readFileSync(join(migrationRoot, n, "migration.sql")))
            .digest("hex"),
        ]),
    );
    assert.deepEqual(
      manifest.migrations,
      actual,
      "Archive migration digests differ from its release manifest",
    );
    record.candidateRuntime = this.candidate;
    record.previousRuntime = this.oldRuntime;
    record.installation = this.config;
    record.previousEnvironment = this.originalEnv;
    record.links = {};
    for (const n of this.names) {
      const c = this.config[n];
      record.links[n] = {};
      for (const k of n === "api"
        ? ["dist", "prisma", "scripts", "package.json", "node_modules"]
        : n === "console"
          ? ["apps", "node_modules"]
          : ["dist", "package.json", "node_modules"]) {
        const path = join(c.root, k);
        assert(
          lstatSync(path).isSymbolicLink(),
          "Native application paths must be release symlinks",
        );
        record.links[n][k] = readlinkSync(path);
      }
    }
    record.previousCurrent = readlinkSync(this.config.runtimeRoot);
    record.maintenanceTimers = [];
    for (const unit of this.config.maintenanceTimers ?? []) {
      assert(/^[a-zA-Z0-9@_.-]+\.timer$/.test(unit));
      if (
        (
          await this.command(["systemctl", "is-active", unit], {
            allowFailure: true,
          })
        ).trim() === "active"
      )
        record.maintenanceTimers.push(unit);
    }
    record.environmentOwners = Object.fromEntries(
      this.names.map((n) => {
        const s = lstatSync(this.config[n].env);
        return [n, { uid: s.uid, gid: s.gid }];
      }),
    );
    record.collectorEnabled =
      Boolean(this.config.collector) &&
      (
        await this.command(
          ["systemctl", "is-active", this.config.collector.unit],
          { allowFailure: true },
        )
      ).trim() === "active";
    await this.node(
      this.candidate,
      ["--input-type=module", "-"],
      this.env,
      "const {validateRuntimeConfig}=await import('./services/security-fusion/dist/config/runtime.js');validateRuntimeConfig();console.log('validated');",
    );
    await this.node(
      this.candidate,
      ["--input-type=module", "-"],
      this.env,
      "import {createRequire} from 'node:module';const require=createRequire(process.cwd()+'/console/apps/security-console/package.json');const {hash,verify}=require('argon2');const h=await hash('synthetic-upgrade-runtime-probe');if(!(await verify(h,'synthetic-upgrade-runtime-probe')))throw Error('Native runtime probe failed');console.log('native-runtime-validated');",
    );
    if (record.collectorEnabled) {
      const collectorEnv = readEnvironment(this.originalEnv.collector);
      await this.node(
        this.candidate,
        ["--input-type=module", "-"],
        collectorEnv,
        "const {readSecurityCollectorRuntimeConfig}=await import('./services/security-collector/dist/runtime-security.js');readSecurityCollectorRuntimeConfig();console.log('validated');",
      );
    }
    if (!reuse) {
      assert(
        !existsSync(join(this.candidate, ".cindertrace-archive.sha256")),
        "Archive must not supply an installation marker",
      );
      writeFileSync(
        join(this.candidate, ".cindertrace-archive.sha256"),
        options.sha256 + "\n",
        { mode: 0o644 },
      );
      renameSync(this.candidate, finalCandidate);
    }
    this.candidate = finalCandidate;
    record.candidateRuntime = finalCandidate;
    return manifest;
  }
  async pause(record) {
    record.maintenanceTimers ??= [];
    for (const unit of this.config.maintenanceTimers ?? []) {
      assert(/^[a-zA-Z0-9@_.-]+\.timer$/.test(unit));
      if (
        (
          await this.command(["systemctl", "is-active", unit], {
            allowFailure: true,
          })
        ).trim() === "active" &&
        !record.maintenanceTimers.includes(unit)
      )
        record.maintenanceTimers.push(unit);
      await this.command(["systemctl", "stop", unit]);
    }
    for (const unit of this.config.maintenanceServices ?? []) {
      unitName(unit);
      for (let i = 0; ; i++) {
        const active = (
          await this.command(["systemctl", "is-active", unit], {
            allowFailure: true,
          })
        ).trim();
        if (!["active", "activating"].includes(active)) break;
        assert(
          i < 120,
          "Maintenance job still running; retry after it finishes",
        );
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
    await this.command([
      "systemctl",
      "stop",
      ...this.names.map((n) => this.config[n].unit),
    ]);
    for (const n of this.names) {
      const state = await this.command([
        "systemctl",
        "show",
        this.config[n].unit,
        "--value",
        "-p",
        "MainPID",
      ]);
      assert.equal(state.trim(), "0", "Service did not fully stop");
    }
    atomicPrivate(
      this.config.api.env,
      renderEnvironment(pausedEnvironment(this.env)),
      this.owner,
    );
    record.paused = true;
  }
  async snapshot(record) {
    const parent = join(this.env.CINDERTRACE_STATE_DIR, "upgrades");
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    chownSync(parent, this.owner.uid, this.owner.gid);
    const root = join(parent, record.id);
    mkdirSync(root, { mode: 0o700 });
    chownSync(root, this.owner.uid, this.owner.gid);
    const environment = join(root, "environment.private");
    atomicPrivate(environment, this.originalEnv.api, this.owner);
    const installation = join(root, "installation.private");
    const paths = [
      ...new Set(
        ["api", "console"].flatMap((n) => {
          const e = readEnvironment(this.originalEnv[n]);
          return ["TLS_CERT_PATH", "TLS_KEY_PATH"]
            .map((k) => e[k])
            .filter(Boolean);
        }),
      ),
    ];
    const certificates = JSON.parse(
      await this.node(
        this.candidate,
        [
          "--input-type=module",
          "-e",
          "import fs from 'node:fs';const paths=JSON.parse(fs.readFileSync(0,'utf8'));console.log(JSON.stringify(Object.fromEntries(paths.map(p=>[p,fs.readFileSync(p,'utf8')]))));",
        ],
        this.env,
        JSON.stringify(paths),
      ),
    );
    atomicPrivate(
      installation,
      JSON.stringify({
        environment: this.originalEnv,
        installation: this.config,
        certificates,
      }),
      this.owner,
    );
    record.backupEnvironment = {
      ...this.env,
      CINDERTRACE_STATE_DIR: root,
      SECURITY_BACKUP_STATUS_FILE: join(root, "backup-status.json"),
      UI_SECURITY_LOG_PATH: readEnvironment(this.originalEnv.console)
        .UI_SECURITY_LOG_PATH,
      CINDERTRACE_SOURCE_PROFILE: record.before.profile ?? "cindertrace-v1",
      CINDERTRACE_BACKUP_ENV_FILE: environment,
      CINDERTRACE_BACKUP_INSTALLATION_FILE: installation,
    };
    record.backupFile = join(root, recoveryArchiveName());
    const result = await this.node(
      this.candidate,
      ["scripts/backup.mjs", "backup", record.backupFile],
      record.backupEnvironment,
    );
    record.backup = JSON.parse(result.trim().split("\n").at(-1));
    await this.node(
      this.candidate,
      ["scripts/backup.mjs", "verify", record.backupFile],
      record.backupEnvironment,
    );
  }
  async restoreRehearsal(record) {
    const u = new URL(this.env.DATABASE_URL);
    const database = "cindertrace_upgrade_" + record.id.replaceAll("-", "");
    const role = decodeURIComponent(u.username);
    assert(/^[a-zA-Z0-9_-]+$/.test(role));
    await this.command([
      "runuser",
      "-u",
      "postgres",
      "--",
      "createdb",
      "--owner",
      role,
      database,
    ]);
    u.pathname = "/" + database;
    const state = join(
      this.env.CINDERTRACE_STATE_DIR,
      "upgrades",
      record.id,
      "restore",
    );
    mkdirSync(state, { mode: 0o700 });
    chownSync(state, this.owner.uid, this.owner.gid);
    const env = {
      ...this.env,
      DATABASE_URL: u.href,
      CINDERTRACE_STATE_DIR: state,
      SECURITY_FUSION_EVIDENCE_DIR: join(state, "evidence"),
      AUDIT_LOG_DIR: join(state, "audit-logs"),
      SECURITY_FUSION_RECEIPT_CHAIN_EXPORT: join(state, "ledger.jsonl"),
      CINDERTRACE_COLLECTOR_BOUNDARY_FILE: join(state, "checkpoint.json"),
      CINDERTRACE_RESTORE_CONFIRM: "empty-isolated-destination",
    };
    record.restoreVerification = JSON.parse(
      (
        await this.node(
          this.candidate,
          ["scripts/backup.mjs", "restore", record.backupFile],
          env,
        )
      )
        .trim()
        .split("\n")
        .at(-1),
    );
    record.integrityVerification = JSON.parse(
      (
        await this.node(
          join(this.candidate, "services/security-fusion"),
          ["scripts/verify-restored-state.mjs"],
          env,
        )
      )
        .trim()
        .split("\n")
        .at(-1),
    );
    record.restoreVerified = true;
    record.restoreDatabase = database;
  }
  async migrate(record) {
    await this.node(
      join(this.candidate, "services/security-fusion"),
      ["scripts/apply-migrations.mjs"],
      pausedEnvironment(this.env),
    );
  }
  link(target, path) {
    const temporary = path + ".upgrade-next";
    assert(!existsSync(temporary));
    symlinkSync(target, temporary);
    renameSync(temporary, path);
  }
  async activate(record) {
    for (const n of this.names) {
      const c = this.config[n];
      for (const k of Object.keys(record.links[n])) {
        const target =
          k === "node_modules"
            ? join(
                this.candidate,
                n === "console" ? "console" : "",
                "node_modules",
              )
            : n === "console"
              ? join(this.candidate, "console", k)
              : join(
                  this.candidate,
                  "services",
                  n === "api" ? "security-fusion" : "security-collector",
                  k,
                );
        this.link(target, join(c.root, k));
      }
    }
    this.link(this.candidate, this.config.runtimeRoot);
    await this.command([
      "systemctl",
      "start",
      this.config.api.unit,
      this.config.console.unit,
    ]);
  }
  async healthy() {
    const script =
      "import https from 'node:https';import tls from 'node:tls';import fs from 'node:fs';const u=JSON.parse(process.env.UPGRADE_HEALTH_URLS);for(const url of u)await new Promise((ok,no)=>{const r=https.get(url,{rejectUnauthorized:true,ca:[...tls.rootCertificates,fs.readFileSync(process.env.UPGRADE_CA)]},s=>{s.resume();s.statusCode===200?ok():no(Error('Health response failed'));});r.on('error',no);r.setTimeout(10000,()=>r.destroy(Error('Health timeout')));});";
    for (let i = 0; i < 60; i++) {
      try {
        await this.command(
          [process.execPath, "--input-type=module", "-e", script],
          {
            env: {
              ...upgradeChildEnvironment(process.env),
              UPGRADE_HEALTH_URLS: JSON.stringify([
                this.config.apiHealth,
                this.config.consoleHealth,
              ]),
              UPGRADE_CA: this.config.caFile,
            },
          },
        );
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    throw Error("Candidate did not become healthy; services remain paused");
  }
  async resume(record) {
    atomicPrivate(this.config.api.env, this.originalEnv.api, this.owner);
    await this.command(["systemctl", "restart", this.config.api.unit]);
    await this.healthy();
    if (record.collectorEnabled)
      await this.command(["systemctl", "start", this.config.collector.unit]);
    for (const unit of record.maintenanceTimers ?? [])
      await this.command(["systemctl", "start", unit]);
  }
  async rollback(record) {
    await this.pause(record);
    for (const n of this.names)
      for (const [k, target] of Object.entries(record.links[n]))
        this.link(target, join(this.config[n].root, k));
    this.link(record.previousCurrent, this.config.runtimeRoot);
    for (const n of this.names)
      atomicPrivate(
        this.config[n].env,
        record.previousEnvironment[n],
        record.environmentOwners[n],
      );
    await this.command([
      "systemctl",
      "start",
      this.config.api.unit,
      this.config.console.unit,
    ]);
    await this.healthy();
    if (record.collectorEnabled)
      await this.command(["systemctl", "start", this.config.collector.unit]);
    for (const unit of record.maintenanceTimers ?? [])
      await this.command(["systemctl", "start", unit]);
  }
}
