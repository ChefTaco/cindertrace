# Cindertrace

Cindertrace is the self-hosted security event collection, investigation and
response product of the [Hive:Magnus](https://github.com/ChefTaco/hive) suite. Its
API correlates network, endpoint, identity, and application observations into
cases, preserves sanitized evidence, records revisioned investigations and
assurance, and keeps an auditable approval trail for response actions. Its
collector also pulls the suite products' audit exports.

[HiveXUI](https://github.com/ChefTaco/HiveXUI) is Cindertrace's only UI. In the suite it
signs in through Oathweave. The API also runs on its own, with its own local
administrator sign-in, PostgreSQL, and Redis; a standalone installation then serves
HiveXUI in local mode, which shows only Cindertrace's pages.
[Hive](https://github.com/ChefTaco/hive) can provide identity and security audit
metadata. [Magnus](https://github.com/ChefTaco/magnus) can supply fleet context
and execute explicitly approved host responses. Both integrations are optional.

**No standalone console.** Cindertrace 0.8.0 removed its own web console
(`apps/security-console`). Standalone installations and the investigation lab serve
HiveXUI instead; see [upgrading](docs/UPGRADING.md#from-07x-to-080) for 0.7.x installations.

## Install

Requirements: Node.js 24.22.3+ on the 24.x line or 26.13.1+ on the 26.x line, npm, OpenSSL, and Docker
with Compose. From a clean checkout of a release tag, for example
`git clone --branch v0.11.0 https://github.com/ChefTaco/cindertrace.git`:

```sh
npm ci
npm run init
docker compose up --build -d
```

This stack runs the API (port 4101 inside the Compose network), PostgreSQL, Redis,
HiveXUI (the pinned `ghcr.io/cheftaco/hivexui` image, static files only) and a small
gateway from the Cindertrace image. Open `https://localhost:3444` and sign in with the
initial administrator credentials, which are written only to
`state/initial-credentials.txt`. The API owns the sign-in and its `cindertrace_session`
cookie; the gateway serves HiveXUI and forwards `/api/cindertrace/*` to the API's
`/api/v1/*`. Trust the generated local certificate for local development; use your own
CA-issued certificate for remote access. Only the gateway is published, bound to loopback
by default. Database and Redis ports are private to the Compose network. Source adapters
are disabled until configured.

To start the optional collector after configuring sources:

```sh
docker compose --profile collector up -d collector
```

Never commit `.env`, certificates, state, incident data, or captures of live cases.
See [installation](docs/INSTALLATION.md), [integrations](docs/INTEGRATIONS.md),
[recovery and migration](docs/MIGRATION.md), [privacy](PRIVACY.md), and
[publication](docs/PUBLISHING.md).

Releases from 0.2.0 on are published as the container image
`ghcr.io/cheftaco/cindertrace`, tagged with the exact version (for example `0.11.0`) for
`linux/amd64` and `linux/arm64` with a build provenance attestation. Each
[GitHub release](https://github.com/ChefTaco/cindertrace/releases) records the source
commit, source tree and image digest; it has no downloadable assets. The Compose stack
above builds the image locally from your checkout. In a Hive installation, the suite's
`full` profile installs the published image through `hive.sh`, the
[Hive suite controller](https://github.com/ChefTaco/hive#install-the-suite), with its own
ingress and HiveXUI. Native (systemd) installations are no longer supported; only the
0.1.0 release has a native runtime archive.

For subsequent Compose releases, select a reviewed commit and run:

```sh
npm run upgrade -- --to COMMIT --project-dir /opt/cindertrace
```

The [upgrade runbook](docs/UPGRADING.md) covers dry runs, verified recovery backups,
interrupted upgrades, current-state rollback, and the move from 0.7.x.

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

The npm workspace contains `services/security-fusion`, `services/security-collector`,
`packages/contracts`, and `packages/integrations`; `scripts/ui-gateway.mjs` is the
standalone gateway. UI work belongs in HiveXUI. The `/security-fusion` pages and
`/api/v1/security-fusion` API paths remain stable for existing clients. `npm run verify` is the CI gate (build, typecheck, tool identifiers,
tests, OpenAPI and privacy checks); [CONTRIBUTING.md](CONTRIBUTING.md) lists the
integration suites. Cindertrace is the product name; legacy wire identifiers
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

## Evolving investigation lab

In a **fresh separate checkout**, initialize a disposable installation:

```sh
npm ci
npm run init -- --lab
npm run lab -- up
```

Open `https://localhost:3445/security-fusion/lab` (HiveXUI in local mode) and sign in
using that checkout's `state/initial-credentials.txt`. Choose **Start investigation**.
Save an assessment before each evidence release. Completion compares structured
claims and containment choices against evidence available at each revision.
Confidence and freeform reasoning remain investigator judgments, not model grades.

The lab generates a dedicated Compose project, database, volumes, TLS certificate,
state, and independent agent credentials. It refuses existing configuration and
forbids external ingestion, integrations, notifications, and dispatch. Containment
is a human-approved simulation and never changes a host or account.

`npm run lab -- stop` preserves history; `npm run lab -- up` resumes it. To remove
only the lab containers and database volumes, run `npm run lab -- destroy NAME`,
where NAME is the exact `COMPOSE_PROJECT_NAME` in that lab's configuration. Local
state and credentials remain in its separate checkout until you remove it.
See [lab workflow and agent API](docs/INVESTIGATION-LAB.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
