// A no-undefined-name gate for host maintenance scripts, using the existing compiler.
import ts from "typescript";
import { readdirSync } from "node:fs";
import { resolve, relative } from "node:path";
const root = resolve(import.meta.dirname, "..");
const files =
  process.argv.length > 2
    ? process.argv.slice(2).map((p) => resolve(p))
    : readdirSync(import.meta.dirname)
        .filter((n) => n.endsWith(".mjs"))
        .map((n) => resolve(import.meta.dirname, n));
const program = ts.createProgram(files, {
  allowJs: true,
  checkJs: true,
  noEmit: true,
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  skipLibCheck: true,
  types: ["node"],
});
const diagnostics = ts
  .getPreEmitDiagnostics(program)
  .filter(
    (d) =>
      [2304, 2552, 18004].includes(d.code) &&
      d.file &&
      files.includes(resolve(d.file.fileName)),
  );
for (const d of diagnostics) {
  const pos = d.file.getLineAndCharacterOfPosition(d.start ?? 0);
  console.error(
    relative(root, d.file.fileName) +
      ":" +
      (pos.line + 1) +
      ": " +
      ts.flattenDiagnosticMessageText(d.messageText, " "),
  );
}
if (diagnostics.length) process.exitCode = 1;
else console.log("Maintenance-script identifier checks passed.");
