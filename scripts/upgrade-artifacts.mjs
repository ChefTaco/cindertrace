import assert from "node:assert/strict";
import { readdirSync, lstatSync, readFileSync, readlinkSync } from "node:fs";
import { resolve, relative, join, dirname, isAbsolute } from "node:path";
import { createHash } from "node:crypto";
const metadata = new Set([
  "cindertrace-release.json",
  ".cindertrace-archive.sha256",
]);

/** Release code must be readable by the application account even under a private umask.
 * Keep the verified archive and upgrade record private; only the public payload is shared.
 */
export function runtimeExtractionCommand(archive, directory) {
  const script = [
    "import os,sys,tarfile",
    "os.umask(0o022)",
    "os.chmod(sys.argv[2],0o755)",
    "def public_code(member,destination):",
    "    member=tarfile.data_filter(member,destination)",
    "    if member is not None:",
    "        if member.isdir(): member.mode=0o755",
    "        elif member.isfile(): member.mode=0o755 if member.mode & 0o111 else 0o644",
    "    return member",
    "tarfile.open(sys.argv[1]).extractall(sys.argv[2],filter=public_code)",
  ].join("\n");
  return [
    "python3",
    "-c",
    script,
    archive,
    directory,
  ];
}
export function runtimeFileManifest(root) {
  root = resolve(root);
  const result = [];
  function walk(path) {
    for (const name of readdirSync(path).sort()) {
      const file = join(path, name);
      const rel = relative(root, file);
      if (metadata.has(rel)) continue;
      const stat = lstatSync(file);
      if (stat.isDirectory()) walk(file);
      else {
        assert(
          stat.isFile() || stat.isSymbolicLink(),
          "Runtime archive contains a special file",
        );
        const type = stat.isSymbolicLink() ? "symlink" : "file";
        let bytes;
        if (type === "symlink") {
          const target = readlinkSync(file);
          const inside = relative(root, resolve(dirname(file), target));
          assert(
            !isAbsolute(target) && inside !== ".." && !inside.startsWith("../"),
            "Runtime symlink escapes release",
          );
          bytes = Buffer.from(target);
        } else bytes = readFileSync(file);
        result.push({
          path: rel,
          type,
          sha256: createHash("sha256").update(bytes).digest("hex"),
        });
      }
    }
  }
  walk(root);
  return result.sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
}
export function verifyRuntimeFiles(root, manifest) {
  assert(
    Array.isArray(manifest) && manifest.length > 0,
    "Release must include runtime file digests",
  );
  assert.deepEqual(
    runtimeFileManifest(root),
    manifest,
    "Runtime files differ from the verified archive manifest",
  );
}

/** Keep a private verified snapshot so upload-file replacement cannot race extraction. */
export async function copyVerifiedRuntimeArchive(source, target, expected) {
  assert(/^[a-f0-9]{64}$/.test(expected), "A SHA-256 digest is required");
  const { createReadStream, createWriteStream, constants } = await import(
    "node:fs"
  );
  const { pipeline } = await import("node:stream/promises");
  const { Transform } = await import("node:stream");
  assert(
    lstatSync(source).isFile() && !lstatSync(source).isSymbolicLink(),
    "Runtime archive must be a regular file",
  );
  const h = createHash("sha256");
  await pipeline(
    createReadStream(source, {
      flags: constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    }),
    new Transform({
      transform(chunk, encoding, done) {
        h.update(chunk);
        done(null, chunk);
      },
    }),
    createWriteStream(target, { flags: "wx", mode: 0o600 }),
  );
  assert.equal(h.digest("hex"), expected, "Runtime archive digest differs");
  return target;
}
