# Cindertrace contributor instructions

Cindertrace is a public Apache-2.0 security product. Keep personal infrastructure,
credentials, runtime state, incident contents, and private provenance outside Git.
Use synthetic fixtures and screenshots. Never bypass privacy hooks. Before every
commit run `npm run verify` and scan the exact staged index. Before publication,
scan built artifacts and record the candidate tree and artifact digests.

The console uses same-origin authenticated proxies. Secrets remain server-side.
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
