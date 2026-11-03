import { test } from "node:test";
import assert from "node:assert/strict";
import {
  secretFindings,
  privateInfrastructureFindings,
  forbiddenPath,
} from "./privacy-policy.mjs";
import { mkdtempSync, mkdirSync, cpSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
test("recognizes real-looking secrets and private endpoints without returning values", () => {
  const credential = "ghp_" + "A".repeat(40),
    endpoint = "private-machine." + "example.ts" + ".net";
  assert.equal(secretFindings(credential).length, 1);
  assert.equal(privateInfrastructureFindings(endpoint).length, 1);
  assert(!JSON.stringify(secretFindings(credential)).includes(credential));
  for (const path of [
    ".env",
    "state/evidence.json",
    "secret.key",
    "audit-logs/2026.jsonl",
  ])
    assert(forbiddenPath(path));
  assert(!forbiddenPath(".env.example"));
});
test("checks staged bytes even if the working file has been sanitized", () => {
  const root = mkdtempSync(join(tmpdir(), "privacy-fixture-"));
  try {
    mkdirSync(join(root, "scripts"));
    cpSync(
      new URL("./check-private.mjs", import.meta.url),
      join(root, "scripts/check-private.mjs"),
    );
    cpSync(
      new URL("./privacy-policy.mjs", import.meta.url),
      join(root, "scripts/privacy-policy.mjs"),
    );
    const credential = "ghp_" + "B".repeat(40);
    execFileSync("git", ["init", "-q"], { cwd: root });
    writeFileSync(
      join(root, "candidate.js"),
      `const value = '${credential}';\n`,
    );
    execFileSync("git", ["add", "candidate.js"], { cwd: root });
    writeFileSync(join(root, "candidate.js"), "// sanitized\n");
    const result = spawnSync(
      process.execPath,
      ["scripts/check-private.mjs", "--staged"],
      { cwd: root, encoding: "utf8" },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /GitHub token/);
    assert(!result.stderr.includes(credential));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
