// Version claims in the docs must match the product version, so a release cannot leave
// them stale. Historical references (changelog, "removed in 0.8.0") are not claims.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const root = new URL("../", import.meta.url);
const version = JSON.parse(readFileSync(new URL("package.json", root), "utf8")).version;
test("the README's example image tag is the current release", () => {
  const readme = readFileSync(new URL("README.md", root), "utf8");
  const example = /tagged with the exact version \(for example `([0-9.]+)`\)/.exec(readme);
  assert(example, "README names an example image tag");
  assert.equal(example[1], version, "Update the README's example image tag to " + version);
});
test("the OpenAPI document does not claim a product version", () => {
  const spec = JSON.parse(readFileSync(new URL("docs/openapi.json", root), "utf8"));
  assert.equal(spec.info.version, "1");
});
