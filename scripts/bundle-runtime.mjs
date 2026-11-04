// Build/typecheck/test the clean revision first. This packages its already staged runtime.
import { execFileSync } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  createReadStream,
  existsSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { resolve, join } from "node:path";
import assert from "node:assert/strict";
import { runtimeFileManifest } from "./upgrade-artifacts.mjs";
import { assertUpgradeNode } from "./upgrade-policy.mjs";
const root = resolve(import.meta.dirname, "..");
const git = (...a) =>
  execFileSync("git", a, { cwd: root, encoding: "utf8" }).trim();
assert.equal(
  git("status", "--porcelain=v1", "--untracked-files=all"),
  "",
  "Bundle requires a clean, verified checkout",
);
const revision = git("rev-parse", "HEAD");
assertUpgradeNode();
assert.equal(
  process.platform,
  "linux",
  "Build native runtime archives on Linux",
);
assert(
  !existsSync(join(root, ".env")),
  "Build release archives in a separate clean checkout without installation configuration",
);
const keep = [
  "PATH",
  "HOME",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
];
const buildEnv = Object.fromEntries(
  keep
    .filter((k) => process.env[k] !== undefined)
    .map((k) => [k, process.env[k]]),
);
buildEnv.NEXT_TELEMETRY_DISABLED = "1";
for (const args of [
  ["ci"],
  ["run", "verify"],
  ["audit", "--omit=dev", "--audit-level=moderate"],
  ["run", "stage", "-w", "@cindertrace/console"],
])
  execFileSync("npm", args, { cwd: root, env: buildEnv, stdio: "inherit" });
execFileSync(process.execPath, ["scripts/stage-runtime.mjs"], {
  cwd: root,
  env: buildEnv,
  stdio: "inherit",
});
const runtime = join(root, "artifacts/runtime");
assert(
  existsSync(join(runtime, "services/security-fusion/dist/index.js")),
  "Run npm run build and stage the runtime first",
);
const migrations = Object.fromEntries(
  JSON.parse(
    execFileSync(
      "node",
      [
        "--input-type=module",
        "-e",
        `import fs from 'node:fs';import crypto from 'node:crypto';const dir='services/security-fusion/prisma/migrations';console.log(JSON.stringify(fs.readdirSync(dir).filter(n=>/^\\d{14}_/.test(n)).map(n=>[n,crypto.createHash('sha256').update(fs.readFileSync(dir+'/'+n+'/migration.sql')).digest('hex')])));`,
      ],
      { cwd: root, encoding: "utf8" },
    ),
  ),
);
const manifest = {
  ...JSON.parse(readFileSync(join(root, "release.json"))),
  revision,
  version: JSON.parse(readFileSync(join(root, "package.json"))).version,
  migrations,
  sourceTree: git("rev-parse", "HEAD^{tree}"),
  files: runtimeFileManifest(runtime),
  platform: {
    os: process.platform,
    arch: process.arch,
    node: process.versions.node,
    napi: process.versions.napi,
  },
};
writeFileSync(
  join(runtime, "cindertrace-release.json"),
  JSON.stringify(manifest, null, 2) + "\n",
);
const file = join(root, "artifacts", "cindertrace-" + revision + ".tar.gz");
execFileSync("tar", [
  "--sort=name",
  "--owner=0",
  "--group=0",
  "--numeric-owner",
  "--mtime=@" + git("show", "-s", "--format=%ct", "HEAD"),
  "-czf",
  file,
  "-C",
  runtime,
  ".",
]);
const hash = createHash("sha256");
for await (const b of createReadStream(file)) hash.update(b);
const digest = hash.digest("hex");
writeFileSync(file + ".sha256", digest + "  " + file.split("/").at(-1) + "\n");
console.log(
  JSON.stringify({ revision, version: manifest.version, file, sha256: digest }),
);
