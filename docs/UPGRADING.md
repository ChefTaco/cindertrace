# Upgrading Cindertrace

Cindertrace has a dedicated upgrade command for Compose installations and native
systemd installations. Run it on the installation host. It keeps configuration,
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

Pass the resulting 40-character commit as `--to`. The command does not select
`latest`, reset your checkout, replace secrets, or regenerate installation keys.
Obtain the current upgrade tooling in a separate trusted checkout if the installed
source predates the upgrade command. Supported Node versions are 24.22.1 or later
on the 24.x line, or 26.13.0 or later on the 26.x line. Build and review release
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

To build and inspect the plan before downtime:

```sh
npm run upgrade -- --to COMMIT --project-dir /opt/cindertrace --dry-run
npm run upgrade -- resume --id UPGRADE_ID --project-dir /opt/cindertrace
```

## Native systemd installations

Use the root-owned mode-0600 installation manifest shown in
[examples/native-installation.json](../examples/native-installation.json), with
paths, service users, verified HTTPS health URLs, and maintenance units matching
the actual installation. Application files must be release symlinks; configuration
and state must remain outside those links. The runtime archive includes the
host-side `scripts/upgrade*.mjs` tools; use the reviewed release's tools together
in a trusted directory. The command uses the existing PostgreSQL
role, local `postgres` maintenance account, and installed native PostgreSQL tools.
The API and console must use one application service account. The collector is
optional; when present, it must use that same account. Other service layouts need
a separately reviewed installation migration before using this command.

Reviewed native archives, SHA-256 sidecars, and publication reviews are attached
to [GitHub Releases](https://github.com/ChefTaco/cindertrace/releases). Select the
archive for your installation's architecture and verify its digest against the
release review. If building your own archive, build on Linux with the
installation's architecture and a supported Node version, in a clean checkout
without installation `.env` files:

```sh
npm run release:bundle
```

This installs the exact lockfile, runs verification, builds and stages the runtime,
and creates `artifacts/cindertrace-COMMIT.tar.gz` and its SHA-256 sidecar. Transfer
both through your verified transport. Check the digest against your trusted release
record, then run on the installation host:

```sh
sudo node scripts/upgrade.mjs upgrade --to COMMIT \
  --install /etc/cindertrace/installation.json \
  --archive /var/lib/cindertrace-downloads/cindertrace-COMMIT.tar.gz \
  --sha256 VERIFIED_ARCHIVE_DIGEST
```

A native upgrade requires neither Hive nor Magnus credentials. It preserves the
existing service names, endpoints, state paths and service users. The manifest
must enumerate backup and TLS maintenance timers/services so they cannot race the
ownership transfer. Keep the encryption key and a recovery copy of the installation
manifest in your separate protected recovery store.

## What the command verifies

1. Check existing health, free space, the explicit installed schema, and unchanged
   applied migration checksums. Refuse pending approvals/dispatch, active response,
   active isolation, or uncertain execution. Cancel pending approvals through the
   console and reconcile uncertain effects before retrying.
2. Stage the selected release and retain the previous runtime/image. A dry run stops
   here. No application services have been changed.
3. Pause console, collector and API, plus native maintenance units. Verify that no
   extra database clients remain. External signed exporters can resume from their
   existing durable checkpoints after the API returns.
4. Create an encrypted frozen backup including security tables, evidence, audit,
   receipt ledger, configured collector boundary, environment and installation
   configuration/signing material. Verify the archive, independently restore it
   into a new isolated database and state directory, and verify tables, asset
   digests, evidence and integrity chains. Retain that recovery evidence.
5. Apply checksum-checked additive migrations. Re-running a completed migration is
   safe; an incomplete or conflicting migration stops the upgrade.
6. Start the replacement with writes/ingestion/retention/notifications/dispatch
   paused. Verify API readiness and console health using certificate verification.
   Record the point at which writes may start, then restore configured capabilities
   and the single collector. Disabled integrations remain disabled.

## Interrupted upgrades and rollback

```sh
npm run upgrade -- status --id UPGRADE_ID --project-dir /opt/cindertrace
npm run upgrade -- resume --id UPGRADE_ID --project-dir /opt/cindertrace
npm run upgrade -- rollback --id UPGRADE_ID --project-dir /opt/cindertrace
```

For native installations replace `--project-dir` with `--install MANIFEST` and run
as root. Records live under `.cindertrace/upgrades` for Compose, or the native
manifest's `recordRoot`. They contain secrets and are mode 0600 in private
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
