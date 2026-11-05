import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, readdirSync, lstatSync } from "node:fs";
import { resolve, relative } from "node:path";
import {
  forbiddenPath,
  privateInfrastructureFindings,
  secretFindings,
} from "./privacy-policy.mjs";
const root = resolve(import.meta.dirname, "..");
const args = process.argv.slice(2);
const staged = args.includes("--staged");
const artifact = args.indexOf("--artifact");
const git = (...argv) =>
  execFileSync("git", argv, { cwd: root, maxBuffer: 128 * 1024 * 1024 });
const skip = new Set([
  ".git",
  ".cindertrace",
  ".playwright-cli",
  "generated",
  "node_modules",
  ".next",
  "dist",
  "state",
  "certs",
  "artifacts",
  "output",
  "backups",
  "test-results",
  "playwright-report",
]);
function walk(base, ignore) {
  return readdirSync(base, { withFileTypes: true }).flatMap((entry) => {
    if (
      ignore &&
      (skip.has(entry.name) ||
        entry.name === ".private-terms" ||
        /^\.env(?:$|\.(?!example$))/.test(entry.name) ||
        /\.tsbuildinfo$/.test(entry.name))
    )
      return [];
    const path = resolve(base, entry.name);
    if (entry.isSymbolicLink()) {
      if (ignore) return [];
      throw new Error(
        "Publication payload contains a symlink; inspect it separately",
      );
    }
    return entry.isDirectory() ? walk(path, ignore) : [path];
  });
}
let files;
if (artifact >= 0)
  files = walk(resolve(args[artifact + 1]), false).map((path) => ({
    path,
    label: relative(resolve(args[artifact + 1]), path),
    bytes: readFileSync(path),
  }));
else if (staged)
  files = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    .toString()
    .split("\0")
    .filter(Boolean)
    .map((path) => ({ path, label: path, bytes: git("show", `:${path}`) }));
else
  files = walk(root, true).map((path) => ({
    path,
    label: relative(root, path),
    bytes: readFileSync(path),
  }));
const terms = existsSync(resolve(root, ".private-terms"))
  ? readFileSync(resolve(root, ".private-terms"), "utf8")
      .split("\n")
      .filter((x) => x.trim() && !x.startsWith("#"))
      .map((x) => new RegExp(x, "i"))
  : [];
let failures = 0;
for (const file of files) {
  const report = (line, rule) => {
    console.error(`${file.label}:${line}: ${rule} [redacted]`);
    failures++;
  };
  if (forbiddenPath(file.label)) report(1, "forbidden path");
  const content = file.bytes.toString("utf8");
  for (const finding of [
    ...privateInfrastructureFindings(content),
    ...secretFindings(content),
  ])
    report(finding.line, finding.rule);
  content.split("\n").forEach((line, i) => {
    if (terms.some((term) => term.test(line))) report(i + 1, "private term");
  });
  if (terms.some((term) => term.test(file.label)))
    report(1, "private filename");
}
if (!staged && artifact < 0 && existsSync(resolve(root, ".git"))) {
  try {
    execFileSync(process.execPath, [import.meta.filename, "--staged"], {
      cwd: root,
      stdio: "inherit",
    });
  } catch {
    failures++;
  }
}
console.log(
  JSON.stringify({ files: files.length, findings: failures, staged }),
);
if (failures) process.exitCode = 1;
