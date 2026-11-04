import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
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
  } finally {
    rmSync(root, { recursive: true });
  }
});
