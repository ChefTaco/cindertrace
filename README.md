# Cindertrace

Cindertrace is a self-hosted security investigation and response console. It
correlates network, endpoint, identity, and application observations into cases,
preserves sanitized evidence, records revisioned investigations and assurance,
and keeps an auditable approval trail for response actions.

It runs independently with local administrator login, PostgreSQL, and Redis.
[Hive](https://github.com/ChefTaco/hive) can provide identity and security audit
metadata. [Magnus](https://github.com/ChefTaco/magnus) can supply fleet context
and execute explicitly approved host responses. Both integrations are optional.

## Install

Requirements: Node.js 24.22.1 or supported Node.js 26, npm, OpenSSL, and Docker
with Compose. From a clean checkout:

```sh
npm ci
npm run init
docker compose up --build -d
```

Open `https://localhost:3444`. The initial administrator credentials are written
only to `state/initial-credentials.txt`. Trust the generated local certificate
for local development; use your own CA-issued certificate for remote access.
The console binds to loopback by default. Database and Redis ports are private
to the Compose network. Source adapters are disabled until configured.

To start the optional collector after configuring sources:

```sh
docker compose --profile collector up -d collector
```

Never commit `.env`, certificates, state, incident data, or captures of live cases.
See [installation](docs/INSTALLATION.md), [integrations](docs/INTEGRATIONS.md),
[recovery and migration](docs/MIGRATION.md), [privacy](PRIVACY.md), and
[publication](docs/PUBLISHING.md). Reviewed runtime archives, checksums, and the
publication review are available from [GitHub Releases](https://github.com/ChefTaco/cindertrace/releases).

For subsequent Compose releases, select a reviewed commit and run:

```sh
npm run upgrade -- --to COMMIT --project-dir /opt/cindertrace
```

The [upgrade runbook](docs/UPGRADING.md) covers native systemd installations,
dry runs, verified recovery backups, interrupted upgrades, and current-state rollback.

## Synthetic demo

For a synthetic demo, use a separate checkout and newly generated configuration
with no production credentials or sources. Start it with
`docker compose -p cindertrace-demo up --build -d`, then run:

```sh
docker compose -p cindertrace-demo exec -T -e CINDERTRACE_DEMO_CONFIRM=isolated-synthetic-installation api node scripts/demo.mjs --preserve
```

This creates a synthetic case and hashed evidence for browser review. It requires
an explicit disposable-installation confirmation and must run separately from
any installation using real security data.

## Develop

Install `redis-server` for the session revocation tests, then run:

```sh
npm ci
npm run db:generate
npm run verify
```

The npm workspace contains `apps/security-console`, `services/security-fusion`,
`services/security-collector`, `packages/contracts`, and `packages/integrations`.
The `/security-fusion` pages and `/api/v1/security-fusion` API paths remain stable
for existing clients. Cindertrace is the product name; legacy wire identifiers
are retained for data and signature compatibility.

## Security model

ADMIN can access evidence and approve response plans. OPERATOR can investigate
and request response review. VIEWER cannot enumerate sensitive security data.
Service credentials are endpoint-scoped. Browser sessions are revocable and
separate from Magnus. Ingestion is signed and source-bound. Response requires
explicit confirmation of an exact plan, expires after ten minutes, and dispatches
at most once. Unknown outcomes require review and are never automatically replayed.

No response controls are enabled without the Magnus bridge. Installing Cindertrace
does not install a fleet agent, alter host firewalls, or provision external sources.

## License

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and bundled font notices.
