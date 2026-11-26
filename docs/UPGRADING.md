# Upgrading Cindertrace

Cindertrace has a dedicated upgrade command for Compose installations. Run it on the
installation host. It keeps configuration,
PostgreSQL, Redis, evidence, audit, and collector state outside the replacement
application. Upgrade records and diagnostics are private; never publish them.

## Choose a version

Use a reviewed release and resolve its tag to an immutable commit in your trusted
Cindertrace checkout:

```sh
git fetch origin --tags
# Replace the example tag with the release you have reviewed.
git rev-parse 'v0.1.0^{commit}'
```

Pass the resulting 40-character commit as `--to`. Moving a 0.7.x installation to 0.8.0
is a one-time manual step instead; see [From 0.7.x to 0.8.0](#from-07x-to-080). The command does not select
`latest`, reset your checkout, replace secrets, or regenerate installation keys.
Obtain the current upgrade tooling in a separate trusted checkout if the installed
source predates the upgrade command. Supported Node versions are 24.22.3 or later
on the 24.x line, or 26.13.1 or later on the 26.x line. Build and review release
payloads before publishing them, following the [publication gate](PUBLISHING.md).

## Compose

The installation's `compose.yaml` must use `CINDERTRACE_IMAGE` (as the current
example does). Existing `.env`, `certs`, `state`, volumes, port bindings and an
optional `compose.override.yaml` remain in the installation directory. Use a local
Docker Engine and Compose v2. Preserve custom Compose files separately; the command
accepts the standard base file and optional override file only. State and TLS files
must use local bind mounts so they can be included in the recovery archive.

```sh
npm run upgrade -- --to COMMIT --project-dir /opt/cindertrace
```

The command builds that exact Git source into a separately tagged image. It refuses
PostgreSQL/Redis image changes or application command/layout changes. Major database
or deployment-layout changes require their own rehearsed migration. Normal
`docker compose up -d` subsequently uses the selected `CINDERTRACE_IMAGE` in `.env`.
Use the upgrade command for code updates; rebuilding a mutable tag with `--build`
bypasses the retained image selection.

### The HiveXUI ui image

Each release pins a HiveXUI image by digest in `compose.yaml`. The upgrade compares it with
the image the installation's `ui` service runs. When they differ, it pulls the release's
image before the downtime starts, records it as `CINDERTRACE_UI_IMAGE` in `.env` and
restarts `ui` with the API and gateway; the upgrade only completes once `ui` is healthy
on that image. A rollback restores the previous `.env` and starts `ui` on its previous
image. An installation whose `ui` runs an image other than `ghcr.io/cheftaco/hivexui`
(a mirror or its own build) keeps it; the record says `kept-custom`, and you update that
image yourself. The dry run and the final summary report the decision as `ui`
(`updated`, `unchanged` or `kept-custom`).

To build and inspect the plan before downtime:

```sh
npm run upgrade -- --to COMMIT --project-dir /opt/cindertrace --dry-run
npm run upgrade -- resume --id UPGRADE_ID --project-dir /opt/cindertrace
```

## From 0.7.x to 0.8.0

0.8.0 removes the standalone console. A Compose installation serves HiveXUI through the
gateway instead ([installation](INSTALLATION.md#the-ui-hivexui-in-local-mode)), at the same
address and port, signed in by the API. The service layout changes (release layout 2),
so the upgrade command refuses this step: the 0.7.x command stops because the release
layout changed, and the 0.8.0 command stops while the installation still has a `console`
service. 0.8.0 adds no database migration. Hive suite installations are unaffected; they
never ran this console.

1. Make and verify a recovery backup as in [recovery and migration](MIGRATION.md), and
   keep a copy of `.env`.
2. In the installation directory (a checkout of the release tag), stop the old services
   and check out the release:

   ```sh
   docker compose stop console collector api
   git fetch origin --tags && git checkout v0.8.0
   ```

3. Create HiveXUI's runtime file, readable by HiveXUI's own account:

   ```sh
   mkdir -m 755 ui
   printf '%s\n' '{"schema":1,"mode":"local","products":{"cindertrace":"/api/cindertrace"}}' > ui/runtime.json
   chmod 644 ui/runtime.json
   ```

4. Edit `.env`: set `CINDERTRACE_BROWSER_AUTH_ENABLED=true`; rename
   `CINDERTRACE_CONSOLE_PORT` to `CINDERTRACE_UI_PORT` if you set it; remove
   `CINDERTRACE_API_BROWSER_AUTH` and any console-only Hive OAuth settings
   (`HIVE_OAUTH_*`, `DASHBOARD_LOGIN_RETURN_PATH`); remove a `CINDERTRACE_IMAGE` line left
   by an earlier managed upgrade, so the next step builds 0.8.0 instead of retagging the
   old image. Keep `DASHBOARD_PUBLIC_ORIGIN`, `SESSION_SECRET`, `REDIS_URL` and the
   `DASHBOARD_ADMIN_*` values: the API now uses them, and existing local sessions stay
   signed in. Move a port binding from `console` to `gateway` in `compose.override.yaml`.
5. Start 0.8.0 and remove the old console container:

   ```sh
   docker compose up --build -d --wait --remove-orphans
   ```

6. Open the same address, sign in with the existing administrator credentials, and check
   the overview, cases and evidence. Start the collector again if you run it
   (`docker compose --profile collector up -d collector`).

To go back, stop the stack, check out the previous tag, restore the saved `.env`, remove
`ui/`, and run the same `docker compose up` command; the database is unchanged. Later
releases use the upgrade command again.

Native systemd installations are no longer supported, and 0.8.0 removes their upgrade
backend. Move such an installation to Compose through a verified backup and restore
([recovery and migration](MIGRATION.md)) or retire it.

## What the command verifies

1. Check existing health, free space, the explicit installed schema, and unchanged
   applied migration checksums. Refuse pending approvals/dispatch, active response,
   active isolation, or uncertain execution. Cancel pending approvals in HiveXUI
   and reconcile uncertain effects before retrying.
2. Stage the selected release and retain the previous runtime/image. A dry run stops
   here. No application services have been changed.
3. Pause the gateway, collector and API. Verify that no extra database clients remain. External signed exporters can resume from their
   existing durable checkpoints after the API returns.
4. Create an encrypted frozen backup including security tables, evidence, audit,
   receipt ledger, configured collector boundary, environment and installation
   configuration/signing material. Verify the archive, independently restore it
   into a new isolated database and state directory, and verify tables, asset
   digests, evidence and integrity chains. Retain that recovery evidence.
5. Apply checksum-checked additive migrations. Re-running a completed migration is
   safe; an incomplete or conflicting migration stops the upgrade.
6. Start the replacement with writes/ingestion/retention/notifications/dispatch
   paused. Verify API readiness and gateway health using certificate verification.
   Record the point at which writes may start, then restore configured capabilities
   and the single collector. Disabled integrations remain disabled.

## Interrupted upgrades and rollback

```sh
npm run upgrade -- status --id UPGRADE_ID --project-dir /opt/cindertrace
npm run upgrade -- resume --id UPGRADE_ID --project-dir /opt/cindertrace
npm run upgrade -- rollback --id UPGRADE_ID --project-dir /opt/cindertrace
```

Records live under `.cindertrace/upgrades`. They contain secrets and are mode 0600 in private
directories. Diagnostics print locations rather than credential values.

Resume is permitted after preparation or a verified independent restore, before
writes may have started. It rechecks the frozen state and safely reruns migration
checks. An interrupted backup/restore requires reviewing its retained evidence,
rolling application code back, and starting a new upgrade. A stale lock requires
checking the recorded PID and installation state before an operator removes it.
Never remove a lock merely because a command appears slow.

Rollback replaces application code and configuration while retaining the current
database, evidence, audit, receipts, checkpoints and applied migrations. It requires
the release's reviewed `rollbackCompatible` declaration. Once the writer may have
started, inspect and reconcile current state first, then explicitly select
`rollback ... --retain-current-state`. No command automatically restores a stale
database or redispatches an uncertain response. A release declared incompatible
requires its documented forward fix or separately reviewed reconciliation.

A failure after writes may have started is a reconciliation stop. Inspect the
record and running services before taking further action. Before that point the
new application stays paused when activation or migration fails; use the retained
rollback path to restore service. Keep archives and prior images/runtimes until
fresh configured sources, backups, and response receipts have passed observation.

Maintainers must preserve versioned backup schema profiles, publish exact archive
and candidate-tree digests, and review rollback compatibility with every migration.
Do not change a previously applied migration or an older schema profile to make a
new release pass.

The investigation lab release adds schema profile `cindertrace-v2` and declares
`rollbackCompatible=false`. Its lab tables cannot be removed by rolling back
application code. Prepare a verified restore and review the target schema before
production cutover; use a forward fix or separately reviewed reconciliation.
