import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  writeFileSync,
  symlinkSync,
  unlinkSync,
  rmSync,
  mkdirSync,
  statSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  runtimeFileManifest,
  copyVerifiedRuntimeArchive,
  verifyRuntimeFiles,
  runtimeExtractionCommand,
} from "./upgrade-artifacts.mjs";

test("native extraction shares public code under umask 077 while retaining private recovery state", async () => {
  const root = mkdtempSync(join(tmpdir(), "runtime-permissions-"));
  const originalMask = process.umask(0o077);
  try {
    const source = join(root, "source"), candidate = join(root, "candidate");
    mkdirSync(join(source, "config"), { recursive: true });
    writeFileSync(join(source, "config/runtime.js"), "export const fixture=true;", { mode: 0o644 });
    writeFileSync(join(source, "entry"), "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    const archive = join(root, "upload.tar.gz");
    execFileSync("tar", ["-czf", archive, "-C", source, "."]);
    const { createHash } = await import("node:crypto");
    const { readFileSync } = await import("node:fs");
    const snapshot = join(root, "verified.tar.gz");
    await copyVerifiedRuntimeArchive(archive, snapshot, createHash("sha256").update(readFileSync(archive)).digest("hex"));
    mkdirSync(candidate, { mode: 0o755 });
    assert.equal(statSync(candidate).mode & 0o777, 0o700);
    const [command, ...args] = runtimeExtractionCommand(snapshot, candidate);
    execFileSync(command, args);
    for (const directory of [candidate, join(candidate, "config")])
      assert.equal(statSync(directory).mode & 0o777, 0o755);
    assert.equal(statSync(join(candidate, "config/runtime.js")).mode & 0o777, 0o644);
    assert.equal(statSync(join(candidate, "entry")).mode & 0o777, 0o755);
    assert.equal(statSync(snapshot).mode & 0o777, 0o600);
    assert.equal(statSync(root).mode & 0o777, 0o700);
    assert.equal(process.umask(), 0o077);
    const manifest = runtimeFileManifest(candidate);
    verifyRuntimeFiles(candidate, manifest);

    // The data filter must still reject an archive link escaping the public payload.
    symlinkSync("../../outside", join(source, "escape"));
    execFileSync("tar", ["-czf", archive, "-C", source, "."]);
    assert.throws(() => execFileSync(command, runtimeExtractionCommand(archive, candidate).slice(1), { stdio: "pipe" }));
  } finally {
    process.umask(originalMask);
    rmSync(root, { recursive: true, force: true });
  }
});
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
