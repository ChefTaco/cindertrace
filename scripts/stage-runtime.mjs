import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  realpathSync,
  cpSync,
  readdirSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { resolve, join, dirname, relative, isAbsolute } from "node:path";
const root = resolve(import.meta.dirname, "..");
const destination = join(root, "artifacts/runtime");
const workspaces = [
  "apps/security-console",
  "services/security-fusion",
  "services/security-collector",
  "packages/contracts",
  "packages/integrations",
];
rmSync(destination, { recursive: true, force: true });
mkdirSync(destination, { recursive: true });
const readPackage = (path) =>
  JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
const copied = new Set(),
  workspacePaths = new Set(workspaces.map((path) => resolve(root, path)));
function resolvePackage(from, name) {
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name))
    throw new Error("Invalid dependency name");
  for (let directory = from; ; directory = dirname(directory)) {
    const candidate = join(directory, "node_modules", name);
    if (existsSync(join(candidate, "package.json")))
      return { link: candidate, path: realpathSync(candidate) };
    if (directory === root || dirname(directory) === directory) break;
  }
  throw new Error(`Missing runtime dependency: ${name}`);
}
function insideRoot(path) {
  const part = relative(root, path);
  if (!part || part.startsWith("..") || isAbsolute(part))
    throw new Error("Runtime dependency escapes the source snapshot");
  return part;
}
function copy(source, target, dependency = false) {
  mkdirSync(dirname(target), { recursive: true });
  cpSync(source, target, {
    recursive: true,
    verbatimSymlinks: true,
    filter: (path) =>
      !path.endsWith(".map") &&
      !path.endsWith(".tsbuildinfo") &&
      (!dependency ||
        path === source ||
        !relative(source, path).split("/").includes("node_modules")),
  });
}
function visit(path) {
  if (copied.has(path)) return;
  copied.add(path);
  const part = insideRoot(path),
    pkg = readPackage(path);
  if (!workspacePaths.has(path)) copy(path, join(destination, part), true);
  const requiredPeers = Object.fromEntries(
    Object.entries(pkg.peerDependencies ?? {}).filter(
      ([name]) => !pkg.peerDependenciesMeta?.[name]?.optional,
    ),
  );
  const names = new Set([
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.optionalDependencies ?? {}),
    ...Object.keys(requiredPeers),
  ]);
  for (const name of names) {
    let dependency;
    try {
      dependency = resolvePackage(path, name);
    } catch (error) {
      if (Object.hasOwn(pkg.optionalDependencies ?? {}, name)) continue;
      throw error;
    }
    const originalLink = insideRoot(dependency.link),
      actual = insideRoot(dependency.path);
    if (originalLink !== actual) {
      const link = join(destination, originalLink),
        target = join(destination, actual);
      if (!existsSync(link)) {
        mkdirSync(dirname(link), { recursive: true });
        try {
          symlinkSync(relative(dirname(link), target), link, "dir");
        } catch (error) {
          if (error.code !== "EEXIST") throw error;
        }
      }
    }
    visit(dependency.path);
  }
}
copy(join(root, "package.json"), join(destination, "package.json"));
for (const workspace of workspaces) {
  const path = join(root, workspace);
  copy(
    join(path, "package.json"),
    join(destination, workspace, "package.json"),
  );
  if (workspace !== "apps/security-console")
    copy(join(path, "dist"), join(destination, workspace, "dist"));
  visit(path);
}
copy(join(root, "apps/security-console/dist"), join(destination, "console"));
copy(
  join(root, "services/security-fusion/prisma"),
  join(destination, "services/security-fusion/prisma"),
);
copy(
  join(root, "services/security-fusion/scripts"),
  join(destination, "services/security-fusion/scripts"),
);
for (const name of [
  "backup.mjs",
  "core-integration.mjs",
  "recovery-integration.mjs",
  "demo.mjs",
  "upgrade.mjs",
  "upgrade-policy.mjs",
  "upgrade-artifacts.mjs",
  "upgrade-probe.mjs",
  "upgrade-compose.mjs",
  "upgrade-native.mjs",
])
  copy(join(root, "scripts", name), join(destination, "scripts", name));
// Retain dependency licences and notices. Source maps and build metadata are not runtime inputs.
function trim(path) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const item = join(path, entry.name);
    if (entry.isDirectory()) trim(item);
    else if (
      entry.isFile() &&
      (entry.name.endsWith(".map") || entry.name.endsWith(".test.mjs"))
    )
      rmSync(item);
  }
}
trim(destination);
writeFileSync(
  join(destination, "runtime-manifest.json"),
  JSON.stringify(
    {
      version: readPackage(root).version,
      packages: [...copied]
        .map((path) => ({
          name: readPackage(path).name,
          version: readPackage(path).version,
          path: insideRoot(path),
        }))
        .sort((a, b) => a.path.localeCompare(b.path)),
    },
    null,
    2,
  ) + "\n",
);
console.log(JSON.stringify({ runtimePackages: copied.size }));

// Public release metadata contains no installation configuration.
writeFileSync(
  join(destination, "cindertrace-release.json"),
  JSON.stringify(
    {
      ...JSON.parse(readFileSync(join(root, "release.json"), "utf8")),
      version: readPackage(root).version,
    },
    null,
    2,
  ) + "\n",
);
