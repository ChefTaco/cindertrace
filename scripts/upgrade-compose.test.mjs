import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ComposeInstallation } from "./upgrade-compose.mjs";
test("configuration inspection includes disabled profiles and resolves local state bindings", async () => {
  const root = mkdtempSync(join(tmpdir(), "compose-upgrade-"));
  try {
    writeFileSync(join(root, ".env"), "SECURITY_WRITES_ENABLED=true\n", {
      mode: 0o600,
    });
    writeFileSync(
      join(root, "compose.yaml"),
      "image: ${CINDERTRACE_IMAGE:-cindertrace:local}\n",
    );
    const cfg = {
      services: {
        api: {
          volumes: [
            {
              type: "bind",
              source: join(root, "private-state"),
              target: "/state",
            },
          ],
        },
        collector: { profiles: ["collector"] },
      },
    };
    const install = new ComposeInstallation(root, async (args) => {
      assert.deepEqual(args.slice(-5), [
        "--profile",
        "*",
        "config",
        "--format",
        "json",
      ]);
      assert(
        args.includes("--profile") &&
          args[args.indexOf("--profile") + 1] === "*",
      );
      return JSON.stringify(cfg);
    });
    assert.deepEqual(await install.configuration(), cfg);
    install.before = cfg;
    assert.equal(
      install.hostPath("api", "/state/upgrades"),
      join(root, "private-state/upgrades"),
    );
    assert.throws(() => install.hostPath("api", "/state/../etc"));
    assert.throws(() => install.hostPath("api", "/unknown"));
    // The gateway becomes a trusted proxy unless the operator chose otherwise.
    assert.deepEqual(install.releaseDefaults(), { CINDERTRACE_TRUSTED_PROXIES: "gateway" });
    install.env.CINDERTRACE_TRUSTED_PROXIES = "none";
    assert.deepEqual(install.releaseDefaults(), {});
  } finally {
    rmSync(root, { recursive: true });
  }
});
test("the upgrade moves ui to the release's HiveXUI digest and keeps a custom image", async () => {
  const { uiImagePlan, withoutKeys } = await import("./upgrade-compose.mjs");
  const old = "ghcr.io/cheftaco/hivexui@sha256:" + "a".repeat(64);
  const next = "ghcr.io/cheftaco/hivexui:0.12.1@sha256:" + "b".repeat(64);
  assert.deepEqual(uiImagePlan(old, next), { decision: "updated", image: next });
  assert.deepEqual(uiImagePlan("ghcr.io/cheftaco/hivexui:0.10.0", next), { decision: "updated", image: next });
  assert.deepEqual(uiImagePlan(next, next), { decision: "unchanged" });
  assert.deepEqual(uiImagePlan("registry.example/mirror/hivexui:0.12.0", next), { decision: "kept-custom" });
  // A release must pin HiveXUI by digest; a tag alone is refused.
  assert.throws(() => uiImagePlan(old, "ghcr.io/cheftaco/hivexui:0.12.1"));
  assert.throws(() => uiImagePlan(old, undefined));
  assert.equal(
    withoutKeys('A="1"\nCINDERTRACE_UI_IMAGE=x\nexport CINDERTRACE_UI_IMAGE_X=y\n# CINDERTRACE_UI_IMAGE=z\n', ["CINDERTRACE_UI_IMAGE"]),
    'A="1"\nexport CINDERTRACE_UI_IMAGE_X=y\n# CINDERTRACE_UI_IMAGE=z\n',
  );
});
test("activation writes and starts ui only when its image changes", async () => {
  const root = mkdtempSync(join(tmpdir(), "compose-upgrade-"));
  try {
    writeFileSync(join(root, ".env"), "CINDERTRACE_IMAGE=cindertrace:local\n", { mode: 0o600 });
    writeFileSync(join(root, "compose.yaml"), "image: ${CINDERTRACE_IMAGE:-cindertrace:local}\n");
    const calls = [];
    const install = new ComposeInstallation(root, async (args) => {
      calls.push(args);
      return "";
    });
    const ui = "ghcr.io/cheftaco/hivexui:0.12.1@sha256:" + "b".repeat(64);
    const record = { image: "cindertrace:release-x", uiImage: ui };
    await install.activate(record);
    const env = readFileSync(join(root, ".env"), "utf8");
    assert.match(env, /^CINDERTRACE_UI_IMAGE=ghcr\.io\/cheftaco\/hivexui:0\.12\.1@sha256:b{64}$/m);
    assert.match(env, /^CINDERTRACE_IMAGE=cindertrace:release-x$/m);
    assert.deepEqual(calls.at(-1).slice(-3), ["ui", "api", "gateway"]);
    await install.activate({ image: "cindertrace:release-y" });
    assert.doesNotMatch(readFileSync(join(root, ".env"), "utf8"), /CINDERTRACE_UI_IMAGE/);
    assert.deepEqual(calls.at(-1).slice(-3), ["120", "api", "gateway"]);
  } finally {
    rmSync(root, { recursive: true });
  }
});
