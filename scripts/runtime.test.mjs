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
import { join, resolve } from "node:path";
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
    file("LICENSE", "Synthetic Apache license fixture");
    file("NOTICE", "Synthetic attribution fixture");
    file("apps/security-console/src/app/fonts/OFL.txt", "Synthetic font license fixture");
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
      dependencies: { specific: "2.0.0", "@cindertrace/contracts": "0.1.0" },
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
    mkdirSync(join(root, "node_modules/@cindertrace"), { recursive: true });
    symlinkSync("../../packages/contracts", join(root, "node_modules/@cindertrace/contracts"), "dir");
    pkg("apps/security-console", {name: "fixture-console", dependencies: {next: "1.0.0", "native-fixture": "1.0.0"}});
    pkg("node_modules/next", {name: "next", version: "1.0.0"});
    file("node_modules/next/unneeded.wasm", "Synthetic unused development asset");
    pkg("node_modules/native-fixture", {name: "native-fixture", version: "1.0.0"});
    file("node_modules/native-fixture/index.js", "export const fixture=true;");
    for (const name of ["LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.md"])
      file("node_modules/native-fixture/" + name, "Synthetic attribution " + name);
    for (const name of ["README.md", "index.d.ts", "index.d.mts", "index.d.cts"])
      file("node_modules/native-fixture/" + name, "Synthetic development documentation");
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
      "lab.mjs",
      "lab-integration.mjs",
      "upgrade.mjs",
      "upgrade-policy.mjs",
      "upgrade-artifacts.mjs",
      "upgrade-probe.mjs",
      "upgrade-compose.mjs",
      "upgrade-native.mjs",
    ])
      file("scripts/" + name, "// fixture");
    file("apps/security-console/scripts/stage.mjs", "export const DEPENDENCY_PACKAGES=['native-fixture'];");
    cpSync(new URL("./runtime-dependencies.mjs", import.meta.url), join(root, "scripts/runtime-dependencies.mjs"));
    cpSync(
      new URL("./stage-runtime.mjs", import.meta.url),
      join(root, "scripts/stage-runtime.mjs"),
    );
    execFileSync(process.execPath, ["scripts/stage-runtime.mjs"], {
      cwd: root,
      stdio: "pipe",
    });
    const output = join(root, "artifacts/runtime");
    for (const name of ["LICENSE", "NOTICE", "apps/security-console/src/app/fonts/OFL.txt"])
      assert.equal(readFileSync(join(output, name), "utf8"), readFileSync(join(root, name), "utf8"));
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
    assert(!existsSync(join(output, "node_modules/next")));
    for (const name of ["LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.md"])
      assert.equal(readFileSync(join(output, "node_modules/native-fixture", name), "utf8"), readFileSync(join(root, "node_modules/native-fixture", name), "utf8"));
    for (const name of ["README.md", "index.d.ts", "index.d.mts", "index.d.cts"])
      assert(!existsSync(join(output, "node_modules/native-fixture", name)));
    assert.equal(readFileSync(join(output, "node_modules/@cindertrace/contracts/dist/index.js"), "utf8"), "export const fixture=true;");
    execFileSync(process.execPath, [resolve(import.meta.dirname, "check-private.mjs"), "--artifact", output], {stdio: "pipe"});
    // Executable dependency content is always scanned; packaging never masks findings.
    const credential = "ghp_" + "Z".repeat(40);
    writeFileSync(join(output, "node_modules/native-fixture/index.js"), `export const fixture='${credential}';`);
    assert.throws(() => execFileSync(process.execPath, [resolve(import.meta.dirname, "check-private.mjs"), "--artifact", output], {stdio: "pipe"}));
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
