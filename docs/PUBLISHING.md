# Publication gate

Before the first commit or GitHub creation, review the allowlisted source tree,
licenses, fixtures, assets, migrations, and generated publication payloads. Create
fresh history; do not import operational or private repository history.

Run `npm run verify`, `node scripts/check-private.mjs --staged`, and
`node scripts/check-private.mjs --artifact DIRECTORY` on each final payload.
Include built JavaScript, source maps, container filesystem/layers, and archives.
Private terms can be placed in the ignored `.private-terms` file, one regular
expression per line. Findings report locations and rule names with values redacted.
A sanitized working copy must not conceal private staged content.

Record the exact candidate tree and artifact SHA-256 digests and the review result.
Keep private source provenance and operational evidence outside Git. Re-run the
gate after changes. Publish only the verified candidate. Never bypass hooks.

Documentation-only commits can advance `main` after an application release.
Verify the deployed manifest revision and archive digest against the published
application release; documentation changes alone do not require a runtime
replacement. Changes to executable code, configuration, dependencies, or schema
require new verified application artifacts and the normal upgrade gates.
