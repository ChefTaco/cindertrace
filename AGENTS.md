# Cindertrace contributor instructions

Cindertrace is the Hive:Magnus suite's security event collection, investigation and
response product. HiveXUI is its UI in the suite; the API also runs on its own.
It is a public Apache-2.0 security product. Keep personal infrastructure,
credentials, runtime state, incident contents, and private provenance outside Git.
Use synthetic fixtures and screenshots. Never bypass privacy hooks. Before every
commit run `npm run verify` and scan the exact staged index. Before publication,
scan built artifacts and record the candidate tree and artifact digests.

## Layout

- `services/security-fusion`: the API (port `SECURITY_API_PORT`, default 4101), migrations,
  response dispatch. Product name Cindertrace; the `security-fusion` wire names stay.
- `services/security-collector`: source adapters and the suite audit-export collector.
- `packages/contracts` (shared wire types, browser contracts, OpenAPI),
  `packages/integrations`.
- No UI of its own: HiveXUI is the only UI. Standalone and lab Compose installations run
  the pinned HiveXUI image in local mode (`ui`) behind `scripts/ui-gateway.mjs`
  (`gateway`, port 3444, lab 3445), which forwards `/api/cindertrace/*` to `/api/v1/*`.
- `scripts` (init, upgrade, lab, UI gateway, integration suites, privacy), `docs`.

## Checks

`npm ci`, `npm run hooks:install`, then `npm run verify` (build, typecheck, tool
identifiers, tests, OpenAPI, privacy). Session tests need a local `redis-server`. The
`test:*` integration suites need disposable installations and explicit confirmation
variables; see CONTRIBUTING.md.

## Rules

Browsers reach the API through the same-origin gateway, which forwards only the
`cindertrace_session` cookie. Secrets remain server-side.
Hive, Magnus, and external sources are optional. The standalone core must work
without them; disabled integrations must not be reported healthy.

Security state belongs to the API. Shared wire types belong in packages/contracts.
Use strict TypeScript and Zod. Preserve historical IDs, signed payloads, migration
checksums, and receipt/audit chains. Never edit an applied migration.

Response execution belongs to Magnus through managed admission. Require an exact,
unexpired, one-use approval and a durable claim before dispatch. Never replay an
unknown execution. Agent read/draft credentials cannot approve response actions.

Test security changes with regression and integration tests. Review actual browser
renders for UI changes. Keep private operational evidence outside this repository.
Production cutover requires a verified restore rehearsal and one writer/dispatcher.

## Release path

A `v*` tag runs `.github/workflows/release-image.yml`, which publishes
`ghcr.io/cheftaco/cindertrace` (amd64 and arm64, exact version tags) and records the
source commit, tree and image digest in a GitHub release; see docs/PUBLISHING.md.
Hive's signed suite manifest pins the digest.
