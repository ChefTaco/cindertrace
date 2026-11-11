# Changelog

## Unreleased

### Security

- Require patched Node.js 24.22.3 or 26.13.1 for supported runtime lines and update container and CI pins.
- Upgrade Hono to 4.13.18 to include the tiny-chunk request-body memory exhaustion fix (GHSA-39q9-qp46-w8xg).

### Fixed

- Keep native release code readable by the application account when the upgrade runs under a restrictive umask. Verified upload snapshots and recovery records retain their private permissions; archive extraction still rejects escaping links.

## [0.2.2] - 2026-11-10

### Security

- Run containers on the pinned, patched Node 26 runtime with maintained system libraries.
- Use the maintained PostgreSQL 18 client pair for backup and restore. Restore archives with the matching or newer `pg_restore`; older clients may reject the archive header.

## 0.2.1 - 2026-11-05

### Security

- Remove npm, npx, corepack and yarn from the runtime image, and purge apt and libapt-pkg6.0 (dpkg and its package database stay). The API, console, collector, migration CLI (`node scripts/apply-migrations.mjs`, also with `--verify-current`) and password-hash CLI run on node alone. This removes the image's fixable HIGH findings: npm's bundled brace-expansion 5.0.9 (CVE-2026-102276, CVE-2026-102278) and undici 6.28.0 (CVE-2026-19534, CVE-2026-87018, CVE-2026-109383, CVE-2026-109869), and apt 2.6.1 (CVE-2026-109518).
- Compose's `migrate` service keeps its `npm run db:migrate` command, which managed upgrades require to stay unchanged. `/usr/local/bin/npm` in the image is a small script that runs only that migration with node and rejects every other npm command.
- The PostgreSQL 18.6 client tools copied into the image (pg_dump, pg_restore, psql and libpq) have no HIGH or CRITICAL findings. gosu is not copied.
- Trivy 0.70.0 reports no fixable HIGH or CRITICAL findings in the image. These Debian 12 findings have no fix available yet and remain: zlib1g CVE-2023-45853 (CRITICAL) and CVE-2026-76844, libldap-2.5-0 CVE-2023-2953, ncurses CVE-2025-69720, libsystemd0/libudev1 CVE-2026-16742, gzip CVE-2026-41992, util-linux CVE-2026-53613, CVE-2026-53615 and CVE-2026-78410, libacl1 CVE-2026-54369, and perl CVE-2026-9538.

## 0.2.0 - 2026-11-05

- Publish `ghcr.io/cheftaco/cindertrace` from version tags as a multi-architecture image built on
  native amd64 and arm64 runners, gated on CI, with provenance attestation and refusal to overwrite
  an existing version. Make the Dockerfile's PostgreSQL client library copy work on arm64.

- Add `RELAX_AUTH_LIMITS` for testing. Sign-in throttles rise to 10000 attempts per window with no retry delay, at runtime only. The API prints a warning at startup and `GET /health` reports `authLimitsRelaxed`. Behaviour without the setting is unchanged.

- Support an optional same-origin post-OAuth console landing path, rejecting unsafe
  redirect configuration before authorization code exchange.

- Add Oathweave OIDC/PKCE sign-in to the retained console with nonce and exact
  identity validation, API-owned encrypted resource sessions, live revocation,
  explicit product links and native recovery authentication. Keep shared identity
  outside legacy host administration and support verified private backchannels.

- Export immutable browser-safe request/response contracts, document consumed
  responses in OpenAPI, and verify real API wire records without changing
  authorization, approval or storage behavior.

- Add an isolated PostgreSQL/API and signed HTTPS dispatcher drill for exact-plan
  expiry, concurrent one-use approval, lost replies, invalid receipts and expired
  dispatch claims, without executing host operations.
- Move optional native browser sign-in, durable sessions, revocation, throttling and
  compatible authentication events into the API, preserving legacy Redis/signing
  state and explicit console delegation.
- Add a protected idempotent Argon2id initializer and read-only exact migration
  verification. Fence restored rehearsals from dispatch, collection, state writes
  and retention.
- Retain resource verifier transport/header exports in the packaged JWT runtime.
