import assert from "node:assert/strict";
import {
  lstatSync,
  openSync,
  writeSync,
  fsyncSync,
  closeSync,
  renameSync,
  chmodSync,
  chownSync,
} from "node:fs";
import { dirname, join, isAbsolute, normalize } from "node:path";
import { randomUUID } from "node:crypto";
export const WRITE_FLAGS = [
  "SECURITY_WRITES_ENABLED",
  "SECURITY_INGEST_ENABLED",
  "SECURITY_DISPATCH_ENABLED",
  "SECURITY_RETENTION_ENABLED",
  "SECURITY_NOTIFICATIONS_ENABLED",
];
export function readEnvironment(text) {
  const result = {};
  for (const line of text.split("\n")) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const m = /^(?:export )?([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    assert(m, "Unsupported environment syntax");
    assert(!(m[1] in result), "Duplicate environment key");
    const v = m[2];
    result[m[1]] = v.startsWith('"')
      ? JSON.parse(v)
      : v.startsWith("'") && v.endsWith("'")
        ? v.slice(1, -1)
        : v;
  }
  return result;
}
export function renderEnvironment(env) {
  return (
    Object.entries(env)
      .map(([k, v]) => {
        assert(/^[A-Z][A-Z0-9_]*$/.test(k));
        assert(!/[\r\n\0]/.test(String(v)), "Multiline environment value");
        return k + "=" + JSON.stringify(String(v));
      })
      .join("\n") + "\n"
  );
}
export function pausedEnvironment(env) {
  return {
    ...env,
    ...Object.fromEntries(WRITE_FLAGS.map((k) => [k, "false"])),
  };
}
export function assertSafeState(state) {
  assert.equal(
    state.unsafeActions,
    0,
    "Finish or reconcile active/uncertain actions before upgrading",
  );
  assert.equal(
    state.unsafeOutbox,
    0,
    "Reconcile pending or uncertain dispatch before upgrading",
  );
  assert.equal(
    state.pendingApprovals,
    0,
    "Cancel pending approvals in the console before upgrading",
  );
  assert.equal(
    state.unsafeExecutions,
    0,
    "Reconcile supplemental executions before upgrading",
  );
}
export function assertMigrations(history, candidate) {
  assert(history.length > 0, "An initialized installation is required");
  const names = new Set();
  for (const m of history) {
    assert(!names.has(m.migration_name), "Duplicate migration history");
    names.add(m.migration_name);
    assert(
      m.finished_at && !m.rolled_back_at,
      "Unfinished migration requires recovery",
    );
    assert.equal(
      candidate[m.migration_name],
      m.checksum,
      "Candidate changes or omits an applied migration",
    );
  }
}
export function absolutePath(p) {
  assert(
    typeof p === "string" &&
      isAbsolute(p) &&
      normalize(p) === p &&
      !/[\r\n\0]/.test(p),
    "Expected a normalized absolute path",
  );
  return p;
}
export function unitName(p) {
  assert(/^[a-zA-Z0-9@_.-]+\.service$/.test(p), "Invalid service unit");
  return p;
}
export function privateFile(path) {
  const s = lstatSync(path);
  assert(
    s.isFile() && !s.isSymbolicLink() && (s.mode & 0o077) === 0,
    "Configuration must be a private regular file",
  );
  return s;
}
export function atomicPrivate(path, content, owner) {
  const tmp = join(dirname(path), ".upgrade-" + randomUUID());
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (owner) chownSync(tmp, owner.uid, owner.gid);
  renameSync(tmp, path);
  chmodSync(path, 0o600);
  const dir = openSync(dirname(path), "r");
  try {
    fsyncSync(dir);
  } finally {
    closeSync(dir);
  }
}

/** Change only managed keys; retain Compose's original literal/interpolation semantics. */
export function patchEnvironment(text, updates) {
  const pending = { ...updates };
  const lines = text
    .replace(/\n$/, "")
    .split("\n")
    .map((line) => {
      const m = /^(?:export )?([A-Z][A-Z0-9_]*)=/.exec(line);
      if (!m || !(m[1] in pending)) return line;
      const value = pending[m[1]];
      delete pending[m[1]];
      assert(
        /^[A-Za-z0-9:._/-]+$/.test(String(value)),
        "Managed environment values must be literal",
      );
      return m[1] + "=" + String(value);
    });
  for (const [key, value] of Object.entries(pending)) {
    assert(
      /^[A-Z][A-Z0-9_]*$/.test(key) &&
        /^[A-Za-z0-9:._/-]+$/.test(String(value)),
    );
    lines.push(key + "=" + String(value));
  }
  return lines.join("\n") + "\n";
}

export function recoveryArchiveName(now = new Date()) {
  return (
    "security-" +
    now
      .toISOString()
      .replace(/\.\d{3}Z$/, "Z")
      .replace(/[-:]/g, "") +
    ".aes"
  );
}

export function assertUpgradeNode(version = process.versions.node) {
  const [major, minor, patch] = version.split(".").map(Number);
  assert(
    (major === 24 && (minor > 22 || (minor === 22 && patch >= 3))) ||
      (major === 26 && (minor > 13 || (minor === 13 && patch >= 1))),
    "Upgrade tooling requires Node >=24.22.3 on the 24.x line or >=26.13.1 on the 26.x line",
  );
}

/** Environment for a child AFTER dropping its UID; runtime injection is never inherited. */
export function upgradeChildEnvironment(env) {
  const result = { ...env };
  for (const key of [
    "NODE_OPTIONS",
    "NODE_PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "HOME",
  ])
    delete result[key];
  for (const key of Object.keys(result))
    if (
      /^(?:LD_|DYLD_|PYTHON)/.test(key) ||
      (key.startsWith("NODE_") &&
        !["NODE_ENV", "NODE_EXTRA_CA_CERTS"].includes(key))
    )
      delete result[key];
  result.PATH = "/usr/sbin:/usr/bin:/sbin:/bin";
  return result;
}
