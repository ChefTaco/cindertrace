// Scheduled encrypted backups for a Compose installation (the opt-in `backup` service).
// Every CINDERTRACE_BACKUP_INTERVAL_HOURS it writes a recovery archive with backup.mjs,
// verifies it, and only then prunes the oldest archives beyond CINDERTRACE_BACKUP_RETAIN.
// A failed run keeps every existing archive and is retried after an hour.
import { spawn } from "node:child_process";
import { readdirSync, rmSync, mkdirSync, renameSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { recoveryArchiveName } from "./upgrade-policy.mjs";

const ARCHIVE = /^security-\d{8}T\d{6}Z\.aes$/;

function whole(name, value, fallback, min, max) {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(value) || Number(value) < min || Number(value) > max)
    throw new Error(`${name} must be a whole number from ${min} to ${max}`);
  return Number(value);
}

export function scheduleOptions(env = process.env) {
  return {
    directory: resolve(env.CINDERTRACE_BACKUP_DIR || join(env.CINDERTRACE_STATE_DIR ?? "state", "backups")),
    intervalHours: whole("CINDERTRACE_BACKUP_INTERVAL_HOURS", env.CINDERTRACE_BACKUP_INTERVAL_HOURS, 24, 1, 168),
    retain: whole("CINDERTRACE_BACKUP_RETAIN", env.CINDERTRACE_BACKUP_RETAIN, 7, 1, 365),
  };
}

/** Archives to delete: every scheduled archive name beyond the newest `retain`. */
export function prunable(names, retain) {
  return names.filter((name) => ARCHIVE.test(name)).sort().reverse().slice(retain);
}

function node(args) {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, [new URL("./backup.mjs", import.meta.url).pathname, ...args], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.once("error", reject);
    child.once("close", (code) => (code === 0 ? done(output) : reject(new Error(`backup.mjs ${args[0]} exited ${code}`))));
  });
}

export async function runOnce(options = scheduleOptions(), run = node) {
  mkdirSync(options.directory, { recursive: true, mode: 0o700 });
  const file = join(options.directory, recoveryArchiveName());
  const created = JSON.parse((await run(["backup", file])).trim().split("\n").at(-1));
  try {
    await run(["verify", file]);
  } catch (error) {
    // Out of the rotation (it no longer matches the archive name), kept for inspection.
    if (existsSync(file)) renameSync(file, file + ".unverified");
    throw error;
  }
  const removed = prunable(readdirSync(options.directory), options.retain);
  for (const name of removed) rmSync(join(options.directory, name));
  return { name: created.name, sha256: created.sha256, bytes: created.bytes, pruned: removed.length };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const options = scheduleOptions();
  const once = process.argv.includes("--once");
  let timer;
  let stopping = false;
  for (const signal of ["SIGTERM", "SIGINT"])
    process.on(signal, () => {
      stopping = true;
      clearTimeout(timer);
    });
  const cycle = async () => {
    let next = options.intervalHours * 3_600_000;
    try {
      console.log(JSON.stringify({ backup: "completed", ...(await runOnce(options)) }));
    } catch (error) {
      // Names only: backup.mjs never prints credentials or row contents.
      console.error(JSON.stringify({ backup: "failed", reason: error.message }));
      process.exitCode = once ? 1 : 0;
      next = Math.min(next, 3_600_000);
    }
    if (!once && !stopping) timer = setTimeout(cycle, next);
  };
  await cycle();
}
