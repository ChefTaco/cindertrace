// Explicit disposable Docker rehearsal. All incident data and credentials are synthetic.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  cpSync,
  existsSync,
  chmodSync,
  appendFileSync,
  readdirSync,
} from "node:fs";
import { resolve, join, dirname } from "node:path";
import { randomUUID } from "node:crypto";
import https from "node:https";
import { forbiddenPath } from "./privacy-policy.mjs";
import { readEnvironment, renderEnvironment } from "./upgrade-policy.mjs";
assert.equal(
  process.env.CINDERTRACE_UPGRADE_TEST_CONFIRM,
  "disposable-installation",
  "Upgrade rehearsal requires disposable-installation confirmation",
);
const source = resolve(import.meta.dirname, "..");
const id = randomUUID();
const root = process.env.CINDERTRACE_UPGRADE_TEST_ROOT ? resolve(process.env.CINDERTRACE_UPGRADE_TEST_ROOT, "upgrade-test-" + id) : join(source, "artifacts", "upgrade-test-" + id);
mkdirSync(root, { recursive: true, mode: 0o700 });
const log = join(root, "rehearsal.private.log");
const fixture = join(root, "installation");
mkdirSync(fixture, { mode: 0o700 });
async function run(
  args,
  { cwd = fixture, env = process.env, allowFailure = false } = {},
) {
  return new Promise((done, reject) => {
    const child = spawn(args[0], args.slice(1), {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const out = [];
    child.stdout.on("data", (b) => out.push(b));
    child.stderr.on("data", (b) => appendFileSync(log, b, { mode: 0o600 }));
    child.on("error", reject);
    child.on("close", (code) =>
      code === 0 || allowFailure
        ? done({ code, output: Buffer.concat(out).toString() })
        : reject(Error("Disposable rehearsal command failed; inspect " + log)),
    );
  });
}
const dc = (...args) => run(["docker", "compose", ...args]);
const command = (...args) =>
  run([process.execPath, join(source, "scripts/upgrade.mjs"), ...args]);
function consoleRequest(path, { method = "GET", cookie, body } = {}) {
  return new Promise((done, reject) => {
    const req = https.request("https://localhost:35444" + path, {
      method,
      ca: readFileSync(join(fixture, "certs/server.crt")),
      headers: {
        origin: "https://localhost:35444",
        "content-type": "application/json",
        ...(cookie ? { cookie } : {}),
      },
    }, (res) => {
      res.resume();
      res.on("end", () => done({ status: res.statusCode, headers: res.headers }));
    });
    req.on("error", reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
}
let started = false;
let success = false;
try {
  const files = (
    await run(
      ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
      { cwd: source },
    )
  ).output
    .split("\0")
    .filter(Boolean);
  for (const file of files) {
    assert(!forbiddenPath(file), "Forbidden source snapshot path");
    mkdirSync(dirname(join(fixture, file)), { recursive: true });
    cpSync(join(source, file), join(fixture, file));
  }
  if (existsSync(join(source, ".private-terms")))
    cpSync(join(source, ".private-terms"), join(fixture, ".private-terms"));
  // This rehearsal tests current-state rollback between identical schemas.
  // The actual release blocks unreviewed rollback across the new lab migration.
  const releaseFile = join(fixture, "release.json");
  const fixtureRelease = JSON.parse(readFileSync(releaseFile, "utf8"));
  fixtureRelease.rollbackCompatible = true;
  fixtureRelease.notes = "Synthetic same-schema rollback rehearsal; not a publication decision.";
  writeFileSync(releaseFile, JSON.stringify(fixtureRelease, null, 2) + "\n");
  await run(["git", "init", "-q"]);
  await run(["git", "config", "user.name", "Synthetic upgrade fixture"]);
  await run(["git", "config", "user.email", "operator@example.com"]);
  await run(["git", "add", "."]);
  await run([process.execPath, "scripts/check-private.mjs", "--staged"]);
  await run(["git", "commit", "-qm", "test: synthetic upgrade candidate"]);
  const revision = (await run(["git", "rev-parse", "HEAD"])).output.trim();
  await run([process.execPath, join(source, "scripts/init.mjs"), fixture]);
  const env = readEnvironment(readFileSync(join(fixture, ".env"), "utf8"));
  env.COMPOSE_PROJECT_NAME = "cindertrace-upgrade-" + id.slice(0, 8);
  env.DASHBOARD_PUBLIC_ORIGIN = "https://localhost:35444";
  env.CINDERTRACE_IMAGE =
    process.env.CINDERTRACE_UPGRADE_BASE_IMAGE ?? "cindertrace:local";
  writeFileSync(join(fixture, ".env"), renderEnvironment(env), { mode: 0o600 });
  writeFileSync(
    join(fixture, "compose.override.yaml"),
    'services:\n  console:\n    ports: !override ["127.0.0.1:35444:3444"]\n',
  );
  console.log("Starting isolated upgrade fixture");
  await dc("up", "-d", "--no-build", "--wait", "--wait-timeout", "120");
  started = true;
  const password = readFileSync(join(fixture, "state/initial-credentials.txt"), "utf8")
    .match(/^Password: (.+)$/m)[1];
  const login = await consoleRequest("/api/auth/login", {
    method: "POST", body: { username: "admin", password },
  });
  assert.equal(login.status, 200);
  const cookie = login.headers["set-cookie"][0].split(";")[0];
  await dc(
    "exec",
    "-T",
    "-e",
    "CINDERTRACE_DEMO_CONFIRM=isolated-synthetic-installation",
    "api",
    "node",
    "scripts/demo.mjs",
    "--preserve",
  );
  console.log("Building exact candidate and checking a dry run");
  const planned = JSON.parse(
    (await command("--to", revision, "--project-dir", fixture, "--dry-run"))
      .output,
  );
  assert.equal(planned.status, "ready");
  await command("resume", "--id", planned.id, "--project-dir", fixture);
  const upgraded = JSON.parse(
    (await command("status", "--id", planned.id, "--project-dir", fixture))
      .output,
  );
  assert.equal(upgraded.phase, "complete");
  assert(upgraded.restoreVerified);
  const proof = JSON.parse(readFileSync(join(fixture, ".cindertrace/upgrades", planned.id, "record.json")));
  assert(proof.restoreVerification);
  assert(proof.integrityVerification.evidenceVerified > 0);
  assert.equal((await consoleRequest("/api/auth/me", { cookie })).status, 200);
  const noStaleRollback = await run(
    [
      process.execPath,
      join(source, "scripts/upgrade.mjs"),
      "rollback",
      "--id",
      planned.id,
      "--project-dir",
      fixture,
    ],
    { allowFailure: true },
  );
  assert.notEqual(noStaleRollback.code, 0);
  await command(
    "rollback",
    "--id",
    planned.id,
    "--project-dir",
    fixture,
    "--retain-current-state",
  );
  // An additive migration followed by an interrupted activation must be safely rerunnable.
  const migration = "20261104000000_upgrade_rehearsal";
  mkdirSync(
    join(fixture, "services/security-fusion/prisma/migrations", migration),
  );
  writeFileSync(
    join(
      fixture,
      "services/security-fusion/prisma/migrations",
      migration,
      "migration.sql",
    ),
    'CREATE INDEX "fixture_upgrade_observed_idx" ON "security_fusion_events" ("observedAt");\n',
  );
  writeFileSync(
    join(fixture, "Dockerfile"),
    "FROM cindertrace:release-" +
      revision +
      "\nCOPY services/security-fusion/prisma/migrations/" +
      migration +
      " /app/services/security-fusion/prisma/migrations/" +
      migration +
      "\n",
  );
  await run([
    "git",
    "add",
    "Dockerfile",
    "services/security-fusion/prisma/migrations",
  ]);
  await run([process.execPath, "scripts/check-private.mjs", "--staged"]);
  await run(["git", "commit", "-qm", "test: synthetic additive migration"]);
  const retryRevision = (await run(["git", "rev-parse", "HEAD"])).output.trim();
  const wrapper = join(root, "bin");
  mkdirSync(wrapper);
  const docker = (await run(["which", "docker"])).output.trim();
  const marker = join(root, "activation-interrupted");
  writeFileSync(
    join(wrapper, "docker"),
    "#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\na=sys.argv[1:]\np=Path(" +
      JSON.stringify(marker) +
      ')\nif "up" in a and "--wait" in a and not p.exists():\n p.touch();sys.exit(42)\nos.execv(' +
      JSON.stringify(docker) +
      ',["docker",*a])\n',
  );
  chmodSync(join(wrapper, "docker"), 0o700);
  console.log("Rehearsing interruption after migration and safe resume");
  const interrupted = await run(
    [
      process.execPath,
      join(source, "scripts/upgrade.mjs"),
      "--to",
      retryRevision,
      "--project-dir",
      fixture,
    ],
    {
      env: { ...process.env, PATH: wrapper + ":" + process.env.PATH },
      allowFailure: true,
    },
  );
  assert.notEqual(interrupted.code, 0);
  assert(existsSync(marker), "Failure must occur after migration");
  const records = join(fixture, ".cindertrace/upgrades");
  const retryId = readdirSync(records).find(
    (x) => x !== planned.id && x !== "upgrade.lock",
  );
  const saved = JSON.parse(readFileSync(join(records, retryId, "record.json")));
  assert.equal(saved.phase, "migrated");
  assert(!saved.writeEnableAttemptedAt);
  await command("resume", "--id", retryId, "--project-dir", fixture);
  const result = JSON.parse(
    (await command("status", "--id", retryId, "--project-dir", fixture)).output,
  );
  assert.equal(result.phase, "complete");
  await command(
    "rollback",
    "--id",
    retryId,
    "--project-dir",
    fixture,
    "--retain-current-state",
  );
  const read = await dc(
    "exec",
    "-T",
    "api",
    "node",
    "--input-type=module",
    "-e",
    "import {getDb,disconnectDb} from './services/security-fusion/dist/db/index.js';const d=getDb();const rows=await d.securityFusionEvidence.findMany();if(!rows.length||rows.some(x=>x.integrityStatus.startsWith('quarantined')))throw Error('Evidence lost');console.log(JSON.stringify({evidence:rows.length,migrations:Number((await d.$queryRaw`SELECT count(*)::int n FROM _prisma_migrations WHERE migration_name='20261104000000_upgrade_rehearsal'`)[0].n)}));await disconnectDb();",
  );
  assert.equal(JSON.parse(read.output.trim().split("\n").at(-1)).migrations, 1);
  assert.equal((await consoleRequest("/api/auth/me", { cookie })).status, 200);
  assert.equal((await consoleRequest("/api/auth/logout", { method: "POST", cookie })).status, 200);
  assert.equal((await consoleRequest("/api/auth/me", { cookie })).status, 401);
  success = true;
  console.log(
    JSON.stringify({
      upgrades: 2,
      independentRestores: 2,
      interruptedActivationResumed: true,
      appliedMigrationRerun: true,
      currentStateRollbacks: 2,
      staleRollbackRefused: true,
      evidencePreserved: true,
      sessionPreservedAndRevoked: true,
    }),
  );
} finally {
  if (started) await dc("down");
  writeFileSync(
    join(root, "result.private.json"),
    JSON.stringify({ success, root, fixture }),
    { mode: 0o600 },
  );
  console.log("Disposable rehearsal artifacts retained at " + root);
}
