# Browser contracts

`packages/contracts` owns the public Zod request schemas and browser response
schemas. Its `browser` export maps the exact browser routes HiveXUI uses and their response
envelopes; OpenAPI response schemas are generated from the same definitions.
These contracts contain no datastore, signing, filesystem or deployment code.

`/cases`, `/events`, `/entities` and `/evidence` (and the non-browser `/deletion-receipts`)
are served newest first, a page at a time. Each response carries `nextCursor`; pass it
back as `?cursor=` for the next page, and stop when it is `null`. `?limit=` sets the page
size (1 to 250; default 100, or 250 for evidence and deletion receipts). The cursor is
opaque and resumes strictly after the last row served, so rows that arrive meanwhile never
shift a page; a tampered cursor is a 400 `INVALID_CURSOR`. Filters must stay the same
from page to page.

Events (`observedAt`), evidence (`preservedAt`) and deletion receipts (chain sequence) are
ordered by values that never change, so paging through them reads every row once. Cases and
entities are ordered by last activity (`lastSeenAt`), which moves forward when new events
correlate: a case or entity that gains activity while a client is paging jumps to the first
page and is not repeated on the later ones. Start again from the first page to see such rows
in their new place; nothing is lost, and the next refresh shows them first.

After committing a reviewed change, run `npm run contracts:browser -- --output
NEW_DIRECTORY` to export the exact immutable public contract blobs and their
SHA-256 provenance. The artifact holds `index.ts`, `lab.ts`, `browser-auth.ts`,
`browser.ts` and `hive-audit.ts`, in that order; an import of any other module
except `zod` is refused. Existing directories are refused. Consumers vendor this
artifact, verify every digest, and import no sibling implementation files.

The core integration test validates real API responses against these contracts,
including cases, evidence, investigations and exact-plan approval responses.
Account authorization, evidence permission and one-use dispatch remain API-owned.
