# Browser contracts

`packages/contracts` owns the public Zod request schemas and browser response
schemas. Its `browser` export maps the exact console routes and their response
envelopes; OpenAPI response schemas are generated from the same definitions.
These contracts contain no datastore, signing, filesystem or deployment code.

After committing a reviewed change, run `npm run contracts:browser -- --output
NEW_DIRECTORY` to export the exact immutable public contract blobs and their
SHA-256 provenance. Existing directories are refused. Consumers vendor this
artifact, verify every digest, and import no sibling implementation files.

The core integration test validates real API responses against these contracts,
including cases, evidence, investigations and exact-plan approval responses.
Account authorization, evidence permission and one-use dispatch remain API-owned.
