import assert from "node:assert/strict";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  statfsSync,
  lstatSync,
  chownSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import {
  privateFile,
  readEnvironment,
  renderEnvironment,
  pausedEnvironment,
  patchEnvironment,
  recoveryArchiveName,
  atomicPrivate,
} from "./upgrade-policy.mjs";
const probe = readFileSync(
  new URL("./upgrade-probe.mjs", import.meta.url),
  "utf8",
);
const appServices = ["api", "console", "collector", "migrate"];
export class ComposeInstallation {
  constructor(root, run) {
    this.root = resolve(root);
    this.run = run;
    this.envFile = join(this.root, ".env");
    privateFile(this.envFile);
    const envStat = lstatSync(this.envFile);
    this.envOwner = { uid: envStat.uid, gid: envStat.gid };
    this.originalEnv = readFileSync(this.envFile, "utf8");
    this.env = readEnvironment(this.originalEnv);
    assert(
      readFileSync(join(this.root, "compose.yaml"), "utf8").includes(
        "${CINDERTRACE_IMAGE:-",
      ),
      "Use the upgrade-capable compose.yaml before the first managed upgrade",
    );
    this.files = [join(this.root, "compose.yaml")];
    if (existsSync(join(this.root, "compose.override.yaml")))
      this.files.push(join(this.root, "compose.override.yaml"));
    this.recordRoot = join(this.root, ".cindertrace", "upgrades");
  }
  args(file) {
    return [
      "docker",
      "compose",
      "--project-directory",
      this.root,
      "--env-file",
      this.envFile,
      ...(file ? ["-f", file] : this.files.flatMap((f) => ["-f", f])),
      ...(this.project ? ["-p", this.project] : []),
    ];
  }
  async compose(args, { file, ...options } = {}) {
    return this.run([...this.args(file), ...args], options);
  }
  async configuration() {
    return JSON.parse(
      await this.compose(["--profile", "*", "config", "--format", "json"]),
    );
  }
  saveConfig(record, name, cfg) {
    const path = join(record.directory, name + ".compose.json");
    atomicPrivate(path, JSON.stringify(cfg));
    return path;
  }
  async preflight() {
    assert(
      !process.env.DOCKER_HOST || process.env.DOCKER_HOST.startsWith("unix://"),
      "Use a local Docker Engine for installation bind mounts",
    );
    const [context] = JSON.parse(
      await this.run(["docker", "context", "inspect"]),
    );
    assert(
      context.Endpoints?.docker?.Host?.startsWith("unix://"),
      "Use a local Docker Engine",
    );
    this.before = await this.configuration();
    this.project = this.before.name;
    const statePath =
      this.before.services.api.environment.CINDERTRACE_STATE_DIR ?? "/state";
    this.stateHost = this.hostPath("api", statePath);
    assert(
      /^[a-fA-F0-9]{64}$/.test(
        this.before.services.api.environment.SECURITY_BACKUP_ENCRYPTION_KEY ??
          "",
      ),
      "A dedicated backup key is required",
    );
    for (const name of ["api", "console"])
      for (const key of ["TLS_CERT_PATH", "TLS_KEY_PATH"]) {
        const value = this.before.services[name].environment[key];
        if (value) readFileSync(this.hostPath(name, value));
      }
    assert(/^[a-z0-9][a-z0-9_-]*$/.test(this.project));
    const images = [];
    for (const n of ["api", "console"]) {
      const id = (await this.compose(["ps", "-q", n])).trim();
      assert(id, "A running initialized stack is required");
      const [c] = JSON.parse(await this.run(["docker", "inspect", id]));
      assert.equal(
        c.State.Health?.Status,
        "healthy",
        "Existing application must be healthy",
      );
      images.push(c.Image);
    }
    assert.equal(
      images[0],
      images[1],
      "Existing console and API use different images",
    );
    this.oldImage = images[0];
    const s = statfsSync(this.root);
    assert(
      Number(s.bavail) * Number(s.bsize) > 2 * 1024 ** 3,
      "At least 2 GiB free installation space is required",
    );
    return JSON.parse(
      await this.compose(
        ["exec", "-T", "api", "node", "--input-type=module", "-"],
        { input: probe },
      ),
    );
  }
  hostPath(service, path) {
    assert(
      path.startsWith("/") && !path.split("/").includes(".."),
      "Use normalized container state/certificate paths",
    );
    const mounts = this.before.services[service].volumes ?? [];
    const mount = mounts
      .filter(
        (x) =>
          x.type === "bind" &&
          (path === x.target || path.startsWith(x.target + "/")),
      )
      .sort((a, b) => b.target.length - a.target.length)[0];
    assert(
      mount,
      "Managed upgrades require local bind mounts for state and TLS keys",
    );
    return resolve(mount.source, "." + path.slice(mount.target.length));
  }
  async prepare(options, record) {
    const source = join(record.directory, "source");
    mkdirSync(source);
    const modes = await this.run(["git", "ls-tree", "-r", record.revision], {
      cwd: this.root,
    });
    assert(
      !modes
        .split("\n")
        .some((x) => x.startsWith("120000 ") || x.startsWith("160000 ")),
      "Source snapshots must not contain external links or submodules",
    );
    const archive = await this.run(["git", "archive", record.revision], {
      cwd: this.root,
      binary: true,
    });
    await this.run(["tar", "-xf", "-", "-C", source], { input: archive });
    const candidate = JSON.parse(
      await this.run([
        "docker",
        "compose",
        "--project-directory",
        this.root,
        "--env-file",
        this.envFile,
        "-f",
        join(source, "compose.yaml"),
        "--profile",
        "*",
        "config",
        "--format",
        "json",
      ]),
    );
    for (const n of ["postgres", "redis"])
      assert.equal(
        candidate.services[n]?.image,
        this.before.services[n]?.image,
        "Database/cache image changes require a separate tested infrastructure upgrade",
      );
    for (const n of appServices) {
      assert.deepEqual(
        candidate.services[n]?.command,
        this.before.services[n]?.command,
        "Runtime layout changes require installation migration",
      );
      assert.deepEqual(
        candidate.services[n]?.working_dir,
        this.before.services[n]?.working_dir,
        "Runtime layout changes require installation migration",
      );
    }
    this.image = "cindertrace:release-" + record.revision;
    await this.run([
      "docker",
      "build",
      "--label",
      "org.opencontainers.image.revision=" + record.revision,
      "-t",
      this.image,
      source,
    ]);
    const [image] = JSON.parse(
      await this.run(["docker", "image", "inspect", this.image]),
    );
    assert.equal(
      image.Config.Labels["org.opencontainers.image.revision"],
      record.revision,
    );
    record.image = this.image;
    record.imageId = image.Id;
    const selectionEnv = join(record.directory, "candidate-selection.env");
    atomicPrivate(
      selectionEnv,
      patchEnvironment(this.originalEnv, { CINDERTRACE_IMAGE: this.image }),
    );
    const configArgs = this.args();
    configArgs[configArgs.indexOf("--env-file") + 1] = selectionEnv;
    const selected = JSON.parse(
      await this.run([
        ...configArgs,
        "--profile",
        "*",
        "config",
        "--format",
        "json",
      ]),
    );
    for (const n of appServices)
      assert.equal(
        selected.services[n].image,
        this.image,
        "A Compose override pins an application image; use CINDERTRACE_IMAGE in that override",
      );
    record.previousImage = this.oldImage;
    record.previousEnvironment = this.originalEnv;
    record.project = this.project;
    record.collectorEnabled = Boolean(
      (
        await this.compose(["--profile", "collector", "ps", "-q", "collector"])
      ).trim(),
    );
    const rollbackImage = "cindertrace:rollback-" + record.id;
    await this.run(["docker", "image", "tag", this.oldImage, rollbackImage]);
    record.rollbackImage = rollbackImage;
    for (const n of appServices) this.before.services[n].image = rollbackImage;
    this.beforeFile = this.saveConfig(record, "before", this.before);
    record.beforeFile = this.beforeFile;
    record.directory = resolve(record.directory);
    const migrations = {};
    const { readdirSync } = await import("node:fs");
    const path = join(source, "services/security-fusion/prisma/migrations");
    for (const name of readdirSync(path).filter((x) => /^\d{14}_/.test(x)))
      migrations[name] = createHash("sha256")
        .update(readFileSync(join(path, name, "migration.sql")))
        .digest("hex");
    return {
      ...JSON.parse(readFileSync(join(source, "release.json"))),
      revision: record.revision,
      migrations,
    };
  }
  async pause(record) {
    await this.compose(["stop", "console", "collector", "api"]);
    atomicPrivate(
      this.envFile,
      patchEnvironment(
        this.originalEnv,
        Object.fromEntries(Object.entries(pausedEnvironment({}))),
      ),
    );
    record.paused = true;
  }
  async inspect() {
    return JSON.parse(
      await this.compose(
        [
          "run",
          "--rm",
          "--no-deps",
          "-T",
          "api",
          "node",
          "--input-type=module",
          "-",
        ],
        { file: this.beforeFile, input: probe },
      ),
    );
  }
  async snapshot(record) {
    const state = join(this.stateHost, "upgrades", record.id);
    const ownerText = this.before.services.api.user;
    assert(
      /^\d+:\d+$/.test(ownerText),
      "Use an explicit numeric application UID:GID",
    );
    const [uid, gid] = ownerText.split(":").map(Number);
    const owner = { uid, gid };
    const parent = join(this.stateHost, "upgrades");
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    if (process.getuid?.() === 0) chownSync(parent, uid, gid);
    mkdirSync(state, { recursive: true, mode: 0o700 });
    if (process.getuid?.() === 0) chownSync(state, uid, gid);
    const path = "/state/upgrades/" + record.id;
    const environment = join(state, "environment.private");
    atomicPrivate(environment, this.originalEnv, owner);
    const certs = {};
    for (const service of ["api", "console"])
      for (const key of ["TLS_CERT_PATH", "TLS_KEY_PATH"]) {
        const file = this.before.services[service].environment[key];
        if (file)
          certs[file] = readFileSync(this.hostPath(service, file), "utf8");
      }
    atomicPrivate(
      join(state, "installation.private"),
      JSON.stringify({
        environment: this.originalEnv,
        compose: this.before,
        certificates: certs,
      }),
      owner,
    );
    const cfg = structuredClone(this.before);
    cfg.services.api.image = record.image;
    delete cfg.services.api.build;
    Object.assign(cfg.services.api.environment, {
      CINDERTRACE_SOURCE_PROFILE: record.before.profile ?? "cindertrace-v1",
      CINDERTRACE_BACKUP_ENV_FILE: path + "/environment.private",
      CINDERTRACE_BACKUP_INSTALLATION_FILE: path + "/installation.private",
    });
    const file = this.saveConfig(record, "backup", cfg);
    record.backupConfig = file;
    record.backupFile = path + "/" + recoveryArchiveName();
    record.backup = JSON.parse(
      (
        await this.compose(
          [
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "api",
            "node",
            "scripts/backup.mjs",
            "backup",
            record.backupFile,
          ],
          { file },
        )
      )
        .trim()
        .split("\n")
        .at(-1),
    );
    await this.compose(
      [
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "api",
        "node",
        "scripts/backup.mjs",
        "verify",
        record.backupFile,
      ],
      { file },
    );
  }
  async restoreRehearsal(record) {
    const database = "cindertrace_upgrade_" + record.id.replaceAll("-", "");
    const cfg = structuredClone(this.before);
    cfg.services.api.image = record.image;
    delete cfg.services.api.build;
    const env = cfg.services.api.environment;
    const u = new URL(env.DATABASE_URL);
    const role = decodeURIComponent(u.username);
    assert(/^[a-zA-Z0-9_-]+$/.test(role));
    const postgres = cfg.services.postgres.environment.POSTGRES_USER;
    assert(/^[a-zA-Z0-9_-]+$/.test(postgres));
    await this.compose([
      "exec",
      "-T",
      "postgres",
      "createdb",
      "-U",
      postgres,
      "--owner",
      role,
      database,
    ]);
    u.pathname = "/" + database;
    const state = "/state/upgrades/" + record.id + "/restore";
    Object.assign(env, {
      DATABASE_URL: u.href,
      CINDERTRACE_STATE_DIR: state,
      SECURITY_FUSION_EVIDENCE_DIR: state + "/evidence",
      AUDIT_LOG_DIR: state + "/audit-logs",
      SECURITY_FUSION_RECEIPT_CHAIN_EXPORT: state + "/ledger.jsonl",
      CINDERTRACE_COLLECTOR_BOUNDARY_FILE: state + "/checkpoint.json",
      CINDERTRACE_RESTORE_CONFIRM: "empty-isolated-destination",
    });
    const file = this.saveConfig(record, "restore", cfg);
    const restored = await this.compose(
      [
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "api",
        "node",
        "scripts/backup.mjs",
        "restore",
        record.backupFile,
      ],
      { file },
    );
    const integrity = await this.compose(
      [
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "--workdir",
        "/app/services/security-fusion",
        "api",
        "node",
        "scripts/verify-restored-state.mjs",
      ],
      { file },
    );
    record.restoreVerification = JSON.parse(restored.trim().split("\n").at(-1));
    record.integrityVerification = JSON.parse(integrity.trim().split("\n").at(-1));
    record.restoreVerified = true;
    record.restoreDatabase = database;
  }
  async migrate(record) {
    const cfg = structuredClone(this.before);
    for (const n of appServices) {
      cfg.services[n].image = record.image;
      delete cfg.services[n].build;
      Object.assign(
        cfg.services[n].environment,
        pausedEnvironment(cfg.services[n].environment),
      );
    }
    const file = this.saveConfig(record, "candidate-paused", cfg);
    record.pausedFile = file;
    await this.compose(
      [
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "--workdir",
        "/app/services/security-fusion",
        "migrate",
        "node",
        "scripts/apply-migrations.mjs",
      ],
      { file },
    );
  }
  async activate(record) {
    atomicPrivate(
      this.envFile,
      patchEnvironment(this.originalEnv, {
        ...pausedEnvironment({}),
        CINDERTRACE_IMAGE: record.image,
      }),
      this.envOwner,
    );
    await this.compose([
      "up",
      "-d",
      "--no-build",
      "--pull",
      "never",
      "--no-deps",
      "--wait",
      "--wait-timeout",
      "120",
      "api",
      "console",
    ]);
  }
  async healthy(record) {
    for (const n of ["api", "console"]) {
      const id = (await this.compose(["ps", "-q", n])).trim();
      const [c] = JSON.parse(await this.run(["docker", "inspect", id]));
      assert.equal(
        c.State.Health?.Status,
        "healthy",
        "Application health failed",
      );
      if (record)
        assert.equal(
          c.Image,
          record.imageId,
          "Application image differs from selected candidate",
        );
    }
  }
  async resume(record) {
    atomicPrivate(
      this.envFile,
      patchEnvironment(this.originalEnv, { CINDERTRACE_IMAGE: record.image }),
    );
    await this.compose([
      "up",
      "-d",
      "--no-build",
      "--pull",
      "never",
      "--no-deps",
      "--wait",
      "--wait-timeout",
      "120",
      "api",
      "console",
    ]);
    if (record.collectorEnabled)
      await this.compose([
        "--profile",
        "collector",
        "up",
        "-d",
        "--no-build",
        "--pull",
        "never",
        "--no-deps",
        "collector",
      ]);
    await this.healthy(record);
  }
  async rollback(record) {
    await this.pause(record);
    atomicPrivate(
      this.envFile,
      patchEnvironment(record.previousEnvironment, {
        CINDERTRACE_IMAGE: record.rollbackImage,
      }),
      this.envOwner,
    );
    await this.compose(
      [
        "up",
        "-d",
        "--no-build",
        "--pull",
        "never",
        "--no-deps",
        "--wait",
        "--wait-timeout",
        "120",
        "api",
        "console",
      ],
      { file: record.beforeFile },
    );
    if (record.collectorEnabled)
      await this.compose(
        [
          "--profile",
          "collector",
          "up",
          "-d",
          "--no-build",
          "--pull",
          "never",
          "--no-deps",
          "collector",
        ],
        { file: record.beforeFile },
      );
    await this.healthy();
  }
}
