import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  writeFileSync,
  symlinkSync,
  unlinkSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  runtimeFileManifest,
  copyVerifiedRuntimeArchive,
  verifyRuntimeFiles,
} from "./upgrade-artifacts.mjs";
test("release verification detects modified, missing and extra files and escaping links", () => {
  const root = mkdtempSync(join(tmpdir(), "runtime-digest-"));
  try {
    writeFileSync(join(root, "app.js"), "public fixture");
    symlinkSync("app.js", join(root, "entry.js"));
    const manifest = runtimeFileManifest(root);
    verifyRuntimeFiles(root, manifest);
    writeFileSync(join(root, "app.js"), "changed");
    assert.throws(() => verifyRuntimeFiles(root, manifest));
    writeFileSync(join(root, "app.js"), "public fixture");
    writeFileSync(join(root, "extra"), "unexpected");
    assert.throws(() => verifyRuntimeFiles(root, manifest));
    unlinkSync(join(root, "extra"));
    unlinkSync(join(root, "entry.js"));
    assert.throws(() => verifyRuntimeFiles(root, manifest));
    symlinkSync("../outside", join(root, "entry.js"));
    assert.throws(() => runtimeFileManifest(root));
  } finally {
    rmSync(root, { recursive: true });
  }
});

test("extraction uses a private snapshot of the exact verified upload bytes", async () => {
  const root = mkdtempSync(join(tmpdir(), "archive-snapshot-"));
  try {
    const { createHash } = await import("node:crypto");
    const input = join(root, "source.tar");
    const target = join(root, "verified.tar");
    writeFileSync(input, "synthetic archive bytes");
    const digest = createHash("sha256")
      .update("synthetic archive bytes")
      .digest("hex");
    await copyVerifiedRuntimeArchive(input, target, digest);
    writeFileSync(input, "replacement upload");
    const { readFileSync, statSync } = await import("node:fs");
    assert.equal(readFileSync(target, "utf8"), "synthetic archive bytes");
    assert.equal(statSync(target).mode & 0o777, 0o600);
    await assert.rejects(
      copyVerifiedRuntimeArchive(input, join(root, "bad.tar"), digest),
    );
    symlinkSync("source.tar", join(root, "upload-link"));
    await assert.rejects(
      copyVerifiedRuntimeArchive(
        join(root, "upload-link"),
        join(root, "link.tar"),
        digest,
      ),
    );
  } finally {
    rmSync(root, { recursive: true });
  }
});
