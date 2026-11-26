# Changelog

## [Unreleased]

### Changed

- Fresh Compose installations run HiveXUI 0.12.1, up from 0.12.0. `compose.yaml` names the version next to the digest.
- `npm run upgrade` now moves the `ui` service to the HiveXUI image the release pins. It pulls the image before the downtime, writes it to `.env` as `CINDERTRACE_UI_IMAGE`, restarts `ui` with the API and gateway and waits for it to be healthy; a rollback restores the previous `ui` image. An installation that runs another `ui` image (a mirror or its own build) keeps it. See [the HiveXUI ui image](docs/UPGRADING.md#the-hivexui-ui-image).

### Upgrade notes

- The managed upgrade now restarts `ui` when the release pins a different HiveXUI image, and writes `CINDERTRACE_UI_IMAGE` to `.env`. A `compose.override.yaml` that sets the `ui` image itself stops the upgrade; set `CINDERTRACE_UI_IMAGE` there instead.

## [0.9.0] - 2026-11-26

### Security

- Sign-in throttling and the API rate limits are keyed on the browser's address again instead of the gateway's. Every browser request reaches the API from the gateway (or Hive's ingress), so the per-source sign-in limit and the 120-per-minute API limit were one bucket shared by everyone: repeated failed sign-ins from anywhere could block all sign-ins. The gateway now appends the address it received each API request from to `X-Forwarded-For` and sets `X-Forwarded-Proto`; the API reads `X-Forwarded-For` only when the connection comes from a proxy listed in the new `CINDERTRACE_TRUSTED_PROXIES` (addresses, CIDR ranges, host names, `loopback`, `none`; default `loopback`), from the right, so a forwarding header written by the caller is never used. Compose sets it to `gateway`, and the managed upgrade adds `CINDERTRACE_TRUSTED_PROXIES=gateway` to `.env` when it is not set. In a Hive suite, set it to the ingress address. An invalid entry stops the API at startup. See [client addresses](docs/BROWSER_AUTH.md#client-addresses-behind-the-gateway-or-ingress).
- Successful sign-ins no longer count toward a source's sign-in limit; failed attempts still do.

### Fixed

- Approvals are refused with 503 `DISPATCH_DISABLED` while `SECURITY_DISPATCH_ENABLED` is not `true`, and action details report `responseAvailable: false`. Before, an approval succeeded and the action stayed in `dispatch_pending` for good, which also blocked `npm run upgrade`.
- Previews and approval requests not decided within ten minutes are cancelled by a sweep that runs every minute while security writes are enabled. The case gets a `containment.expired` activity, the approval row becomes `expired`, and the audit log records `security_fusion.action.expire`. They used to stay open and block `npm run upgrade`.
- Cancelling an action updates the action and its approval in one transaction and writes a `containment.cancelled` case activity and a `security_fusion.action.cancel` audit entry.
- The managed upgrade records the candidate's version from `package.json`. `release.json` no longer carries its own (stale) `version`.

### Changed

- Fresh Compose installations run HiveXUI 0.12.0 (the digest Hive 3.14.3 pins), up from 0.10.0. The managed upgrade still keeps the installation's `ui` image; set `CINDERTRACE_UI_IMAGE` to move an existing installation.

### Upgrade notes

- New setting `CINDERTRACE_TRUSTED_PROXIES` (default `loopback`). Compose sets it to `gateway` and the managed upgrade adds `CINDERTRACE_TRUSTED_PROXIES=gateway` to `.env` when it is not set. If another reverse proxy sits in front of the gateway, add it to `CINDERTRACE_TRUSTED_PROXIES`; in a Hive suite, set it to the ingress address. An invalid entry stops the API at startup.
- Approvals now fail with 503 `DISPATCH_DISABLED` while `SECURITY_DISPATCH_ENABLED` is not `true`, and undecided previews and approval requests expire after ten minutes.

No database migration is required.

## [0.8.2] - 2026-11-24

### Security

- The runtime image ships Zstandard 1.6.0 (`libzstd1` 1.5.7-r14 to 1.6.0-r0) for CVE-2026-124851, which affects zstd 1.5.1 to 1.5.7. The PostgreSQL clients pull in `libzstd1`; the runtime stage now requires `libzstd1>=1.6.0` and the image build fails if the installed `libzstd1` is older than 1.6.0.
- Override `effect` to 3.22.1 for CVE-2026-121707 (GHSA-7589-6fvf-x4pw). The Prisma CLI pulls it in through `@prisma/config`; it is used by `npm ci` checkouts and the image build stage, not shipped in the runtime image.

No database migration is required.

## [0.8.1] - 2026-11-18

### Added

- The collector reads IPFIX and NetFlow v9 flows from Loki. UniFi Network 11 no longer logs firewall hits as syslog lines with `SRC=`/`DST=`/`PROTO=`, so the `netflow` and `unifi_dns` sources went silent; a gateway's IPFIX export decoded by goflow2 (`-format json`) and shipped to Loki now feeds them. Each flow becomes a `netflow` observation of the same kind as before (`unifi.firewall.flow.summary`, `derivedFrom: loki-ipfix`, `ruleSet` `ipfix-outbound`, `ipfix-inbound`, `ipfix-internal` or `ipfix-transit`), plus `unifi_dns` network activity when either port is 53. MAC addresses are not kept.
- Sampled flow volumes. `sampledBytes` and `sampledPackets` are what the exporter recorded; `estimatedBytes`, `estimatedPackets` and `estimatedFlowCount` multiply them by the sampling rate, taken from the record's `sampling_rate`, else from the stream's `sampling_rate` label, else 1 (`samplingRateSource` says which). Five-minute summaries sum them and state the estimate and the rate in their summary.
- UniFi Network CEF lines (Activity Logging to a SIEM server) on the Loki path. Threat management, intrusion prevention and honeypot events become `unifi_ids` alerts (`unifi.ids.alert`), firewall events `unifi_ids` firewall alerts (`unifi.firewall.alert`), DNS filtering `unifi_dns` activity; each is ingested on its own, not aggregated, at UniFi's reported UTC time. Audit, monitoring, client, device and system events are skipped, so that an administrator signing in to UniFi Network does not correlate with Wazuh as an endpoint intrusion. CEF was only read by the UDP listener before.
- Quiet source signal. A source whose polls succeed but that has had no event for `SECURITY_FUSION_QUIET_AFTER_HOURS` hours (default 6, `0` turns it off) reports `degraded` with `no events for more than N hours`. `SECURITY_FUSION_QUIET_SOURCES` lists the watched sources (default `netflow`). After a restart the collector's start time is the baseline.

### Fixed

- Five-minute flow and firewall summaries no longer lose the rows of later polls. A summary's ID covered only its window and dimensions, so the second and later polls (every minute) of the same window produced the same ID, which the queue and ingest dropped as a duplicate; about four fifths of the rows of a busy window were not counted. The ID now also covers the rows a summary counts: later polls become further summaries, a replay of the same rows stays a duplicate. Summaries keep the `derivedFrom` of their rows.

### Changed

- `LOKI_QUERY` should select every stream of the gateway (syslog and flows), for example by a shared `exporter` label; see `docs/INTEGRATIONS.md`.

No database migration is required.

## [0.8.0] - 2026-11-17

### Removed

- The standalone console (`apps/security-console`, the Next.js app) and everything that only served it: its workspace, image build stage and runtime files, the bundled JetBrains Mono font, its CI staging steps and the console-only `CINDERTRACE_API_BROWSER_AUTH` setting. HiveXUI is Cindertrace's only UI. The console's own Oathweave sign-in (`docs/OATHWEAVE_CONSOLE.md`) is gone; in a Hive suite, HiveXUI signs in through Oathweave.
- Native systemd installations: the upgrade backend (`scripts/upgrade-native.mjs`, `--install`, `--archive`, `--sha256`), its runtime archive tooling (`npm run release:bundle`, `scripts/upgrade-artifacts.mjs`) and `examples/native-installation.json`. The upgrade command now upgrades Compose installations only.

### Changed

- Standalone and lab Compose installations serve HiveXUI in local mode at the same address (`https://localhost:3444`, lab `3445`). Two services replace `console`: `ui`, the HiveXUI 0.10.0 image pinned by digest (static files, internal only, read-only, its own unprivileged account), and `gateway`, `scripts/ui-gateway.mjs` from the Cindertrace image (read-only, no capabilities, no product secrets). The gateway terminates TLS, forwards `/api/cindertrace/*` to the API's `/api/v1/*` over verified HTTPS with only the `cindertrace_session` cookie, answers 404 for every other `/api/*` path, and serves everything else from HiveXUI. `npm run init` writes HiveXUI's `ui/runtime.json`, enables the API's local sign-in (`CINDERTRACE_BROWSER_AUTH_ENABLED=true`) for standalone installations too, and names the published port `CINDERTRACE_UI_PORT`.
- The release layout is now 2. The upgrade command refuses an installation that still has the `console` service; move a 0.7.x installation by the steps in `docs/UPGRADING.md`. Local sessions created by the 0.7.x console stay valid.
- The lab browser test (`npm run test:lab:browser`, CI `lab` job) drives HiveXUI through the gateway: wrong-password refusal, API sign-in and cookie, every Cindertrace page, all three lab stages, sign-out, and no request outside `/api/cindertrace/`. The upgrade rehearsal signs in through the gateway.

No database migration is required.

## [0.7.2] - 2026-11-17

### Security

- Update `next` to 16.4.6 for GHSA-mfr8-8qww-v76h. The standalone console is built with Next.js and is part of the runtime image.

No database migration is required.

## [0.7.1] - 2026-11-15

### Changed

- Update `@hivemagnus/hive-common` to 0.5.0. The API now uses its shared helpers where they give the same results as Cindertrace's own copies: the SHA-256 checks of static service, metrics and summary credentials and the local administrator login comparison (`/secrets`), the `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` headers on every response (`securityHeaders()`), and the `(occurredAt, id)` order of the HiveEvent feed. A comparison of strings of different length now takes about as long as one of equal length. Responses, status codes and feed cursors are unchanged.

No database migration is required.

## [0.7.0] - 2026-11-13

### Fixed

- The collector no longer retries a refused batch forever. The ingest API refuses a whole batch when one event breaks the event schema, is larger than 32,768 bytes or is nested deeper than 8 levels, and the collector put the refused batch back at the front of its queue, so one such event (for example a CEF datagram with an empty name, or an export row with a `kind` longer than 160 characters) stopped all later events and checkpoints. The collector now checks each event against the same limits before queueing it, drops one that can never be accepted, and logs the source and the failing field names, never the content.
- Deleting an archived case after its grace period now also deletes the case's assurance packets, which were left behind. The case deletion receipt counts them in `childCounts.assurancePackets`.
- A signed ingest request that fails because nonce storage is unavailable is answered 500 `INTERNAL_ERROR`. It was answered 409 `INGEST_REPLAY`, which is now kept for a nonce that has been used.
- An ingest nonce is kept until its signed timestamp can no longer pass the five minute skew check. A request stamped ahead of the API clock could outlive its nonce record by up to five minutes.
- `PATCH /api/v1/security-fusion/cases/:id` validates its body. A body that is not JSON, an `assignedTo` that is not a string or null, and an unknown `status` are answered 400 `VALIDATION_ERROR`; an unknown case is answered 404 `NOT_FOUND`. These were 500s, apart from the unknown status. Only `status` and `assignedTo` are recorded in case activity; the whole request body was recorded before.
- A request body that is not JSON is answered 400 `VALIDATION_ERROR` instead of 500 on the assurance, investigation, action preview and approval decision routes.
- `GET /api/v1/security-fusion/events?limit=` uses the default of 100 when `limit` is not a number, instead of answering 500.
- Stored event attributes and audit details redact sensitive keys whatever their letter case (`AccessToken`, `APIKEY`, `PrivateKey` and similar were kept), and keep nested arrays as arrays instead of turning them into objects.

No database migration is required.

## [0.6.1] - 2026-11-13

### Fixed

- Ingest no longer fails a whole batch with a 500 when one event carries a zero or out-of-range `observedAt`. The 15-minute correlation window subtracted from a zero time such as `0001-01-01T00:00:00Z` underflowed the database date range (SQLSTATE 22008). `POST /api/v1/security-fusion/ingest/events` now rejects each event whose `observedAt` is before `2000-01-01T00:00:00Z` or more than 60 minutes after receipt, stores the rest of the batch, and still answers 202. The response `data` gains `rejected`: one `{index, eventId, status: 400, code: "INGEST_TIMESTAMP_OUT_OF_RANGE", message}` per rejected event. The API logs each rejection's index, code, source and kind, and counts them in the `security_fusion_ingest_events_rejected` metric.
- The collector stamps Tailscale, Hive and ChatterMost events at receive time when the upstream timestamp is a zero time, the Unix epoch or unparsable. `tailscale status --json` reports `LastSeen` as the zero time for peers that are online, which produced these events. Event IDs are unchanged, so replays still deduplicate.

### Security

- Update `@hono/node-server` to 2.1.8 for GHSA-qv5m-9pm6-hqp3 and GHSA-jpvv-r467-5p4w.

No database migration is required.

## [0.6.0] - 2026-11-12

### Added

- Add the Security Fusion sources `hivemem`, `hiveskills`, `ardentstudio` and `embermend`, and a collector that pulls HiveAuditRecord v1 from each product's `GET <api>/v1/audit/export?after=&limit=` with an Oathweave client-credentials token. Configure it with `SECURITY_COLLECTOR_AUDIT_SOURCES_JSON` (`[{source, url, audience, scope}]`), `SECURITY_COLLECTOR_AUDIT_OATHWEAVE_URL`, `SECURITY_COLLECTOR_AUDIT_CLIENT_ID` and `SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET` or `_FILE`; each source may name its own client. Tokens are cached until shortly before expiry and refreshed once on 401. Sources poll independently and resume from their stored cursor checkpoint. Records map to `<product>.<action>` events whose severity follows the action (credential and permission changes high, deletes medium, reads info, failures one step higher), with `agent` entities from the record subject. See `docs/INTEGRATIONS.md`.
- Add `hiveAuditRecordSchema` to the contracts.

### Changed

- `npm run init` admits the four new sources for the generated collector. Existing collector credentials must add them to `allowedSources` before the audit collector is configured.

No database migration is required: sources are stored as text.

## [0.5.0] - 2026-11-12

### Added

- Add `GET /api/v1/hive/events`, a HiveEvent v1 feed for the HiveXUI inbox. It derives events from records Cindertrace already stores: case activity (`case.opened`, `case.reopened`, `case.severity.raised`, `case.closed`, containment approvals and rejections, containment results and isolation releases) and containment approval requests (`containment.approval.requested`). Case severity maps to `info` (info, low), `warning` (medium, high) or `critical`; failed and unknown containment outcomes are `critical`. Links point to HiveXUI's `/security-fusion/cases/<id>`, and a case's single agent entity sets `subject.actorId`, `agentRef` and `nodeId`. Pages are oldest first by `(occurredAt, id)` with an opaque cursor, cover the last 14 days, and are validated with `@hivemagnus/hive-common` before they are served. Authentication and roles match case reads: ADMIN and OPERATOR, 403 for VIEWER and for endpoint-scoped service credentials.
- Publish the feed's route and `hiveEventSchema` in the browser contracts and OpenAPI.

### Changed

- Require `@hivemagnus/hive-common` ^0.4.0 in the API.

No database migration is required.

## [0.4.0] - 2026-11-12

### Added

- Add the `agent` entity type. Its canonical value is `actor:<actorId>` (HiveMem agent ID), with `agent-ref:<nodeId>~<profile>` and `magnus-node:<nodeId>` recorded as aliases. Agent entities join cases without changing how existing cases are grouped.
- Add `entityType` and `entity` query parameters to `GET /api/v1/security-fusion/cases` to list the cases linked to one entity. The unfiltered response, limits and roles are unchanged; an invalid filter returns 400 `INVALID_ENTITY_FILTER`.
- Attach an `agent` entity to `magnus` events whose attributes carry `actorId`, or `nodeId` with `profile`. Current Magnus service health events carry only `nodeId`, so they gain no agent entity; `docs/INTEGRATIONS.md` describes what Magnus would need to send.

No database migration is required: entity types are stored as text and the filter uses the existing case entity index.

## [0.3.0] - 2026-11-12

### Changed

- Verify Oathweave resource tokens with the shared `@hivemagnus/hive-common` verifier and run its conformance vectors in the API tests. Cindertrace keeps its rules: user tokens only, exact `cindertrace` audience, required `clientId` and `roles` claims, no clock skew tolerance, an online session check on every use, and refusal responses unchanged (401). Identity links that name a `service:` or `system` account are now refused.
- Add `GET /health/live` and `GET /health/ready`. `/health` and `/ready` are unchanged.
- Read or generate a request ID (`x-request-id`, also `x-hive-request-id` and `x-correlation-id`) and W3C trace context for every API request, echo `x-request-id` on responses, and include it in API error log lines. Error response bodies are unchanged.

## [0.2.3] - 2026-11-11

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
