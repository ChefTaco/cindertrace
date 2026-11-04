import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  cpSync,
  existsSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
test("runtime staging preserves nested versions and traced shims while excluding optional development peers", () => {
  const root = mkdtempSync(join(tmpdir(), "runtime-fixture-"));
  const file = (name, value) => {
    mkdirSync(join(root, name, ".."), { recursive: true });
    writeFileSync(join(root, name), value);
  };
  const pkg = (path, value) =>
    file(path + "/package.json", JSON.stringify(value));
  try {
    pkg(".", { name: "fixture-root", version: "0.1.0", type: "module" });
    file("release.json", JSON.stringify({ product: "cindertrace", layoutVersion: 1, schemaProfile: "cindertrace-v1" }));
    for (const name of [
      "apps/security-console",
      "services/security-fusion",
      "services/security-collector",
      "packages/contracts",
      "packages/integrations",
    ]) {
      pkg(name, { name: "fixture-" + name.split("/")[1], version: "0.1.0" });
      file(name + "/dist/index.js", "export const fixture=true;");
    }
    pkg("services/security-fusion", {
      name: "fixture-api",
      version: "0.1.0",
      dependencies: { specific: "2.0.0" },
    });
    pkg("services/security-fusion/node_modules/specific", {
      name: "specific",
      version: "2.0.0",
      peerDependencies: { "development-cli": "*" },
      peerDependenciesMeta: { "development-cli": { optional: true } },
    });
    file(
      "services/security-fusion/node_modules/specific/index.js",
      "export const version=2;",
    );
    file(
      "services/security-fusion/node_modules/specific/debug.js.map",
      "fixture debug metadata",
    );
    pkg("node_modules/specific", { name: "specific", version: "1.0.0" });
    pkg("node_modules/development-cli", {
      name: "development-cli",
      version: "1.0.0",
    });
    file("services/security-fusion/prisma/migrations/fixture.sql", "SELECT 1;");
    file("services/security-fusion/scripts/apply-migrations.mjs", "// fixture");
    file(
      "apps/security-console/dist/node_modules/traced-shim/index.js",
      "// traced alias",
    );
    for (const name of [
      "backup.mjs",
      "core-integration.mjs",
      "recovery-integration.mjs",
      "demo.mjs",
      "upgrade.mjs",
      "upgrade-policy.mjs",
      "upgrade-artifacts.mjs",
      "upgrade-probe.mjs",
      "upgrade-compose.mjs",
      "upgrade-native.mjs",
    ])
      file("scripts/" + name, "// fixture");
    cpSync(
      new URL("./stage-runtime.mjs", import.meta.url),
      join(root, "scripts/stage-runtime.mjs"),
    );
    execFileSync(process.execPath, ["scripts/stage-runtime.mjs"], {
      cwd: root,
      stdio: "pipe",
    });
    const output = join(root, "artifacts/runtime");
    assert.equal(
      JSON.parse(
        readFileSync(
          join(
            output,
            "services/security-fusion/node_modules/specific/package.json",
          ),
        ),
      ).version,
      "2.0.0",
    );
    assert(
      existsSync(join(output, "console/node_modules/traced-shim/index.js")),
    );
    assert(!existsSync(join(output, "node_modules/development-cli")));
    assert(
      !existsSync(
        join(
          output,
          "services/security-fusion/node_modules/specific/debug.js.map",
        ),
      ),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
