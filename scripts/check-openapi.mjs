import { readFileSync, writeFileSync } from "node:fs";
import { buildOpenApiSpec } from "../services/security-fusion/dist/openapi.js";
const text = JSON.stringify(buildOpenApiSpec(), null, 2) + "\n";
const file = new URL("../docs/openapi.json", import.meta.url);
if (process.argv.includes("--write")) writeFileSync(file, text);
else if (readFileSync(file, "utf8") !== text)
  throw new Error(
    "OpenAPI differs from the current route contract; regenerate and review",
  );
console.log("OpenAPI route and schema contract verified.");
