# Migration and recovery

Use a verified, pinned application build. Keep live credentials and detailed
provenance outside Git. Production paths and endpoints may remain unchanged at
the first cutover; configuration controls paths and URLs.

## Export and import

Run the state tool from the API package directory with its database and evidence
environment configured:

```sh
node scripts/migrate-state.mjs export /private/recovery/security.json.gz
node scripts/migrate-state.mjs verify-archive /private/recovery/security.json.gz
```

The default profile is `current`. For an existing dedicated Security Fusion
source use `CINDERTRACE_SOURCE_PROFILE=dedicated-v1`; for embedded public Magnus
use `CINDERTRACE_SOURCE_PROFILE=embedded-magnus-v1`. Profiles name exact reviewed
table sets. Unknown schemas fail rather than silently dropping data.

Before transfer, pause source ingestion, retention, notifications, and dispatch.
Reconcile active or unknown actions and active isolation. Cancel pending actions
with an audit record; imports refuse unresolved or pending executable work.
Back up source state before any mutation. Export security tables, supplementary
target/execution state, evidence, receipt ledger, and collector checkpoints.
Preserve audit logs and the signing keys separately or in an encrypted backup.

Migrate an isolated empty Cindertrace database with committed migrations, configure
its evidence directory and preserved signing material, then run:

```sh
node scripts/migrate-state.mjs import /private/recovery/security.json.gz
node scripts/migrate-state.mjs verify /private/recovery/security.json.gz
CINDERTRACE_RESTORE_CONFIRM=empty-isolated-destination node scripts/verify-restored-state.mjs
```

No historical event IDs, source names, evidence bytes, or integrity chains are
rewritten. New schema fields use their additive defaults. Source schema and
migration checksums remain unchanged. Keep the source frozen until the destination
is independently verified. Start exactly one writer and dispatcher.

## Encrypted backups

From the repository/container root with the API environment loaded:

```sh
node scripts/backup.mjs backup /private/recovery/security.aes
node scripts/backup.mjs verify /private/recovery/security.aes
CINDERTRACE_RESTORE_CONFIRM=empty-isolated-destination node scripts/backup.mjs restore /private/recovery/security.aes
```

`SECURITY_BACKUP_ENCRYPTION_KEY` must be a dedicated 32-byte hex key stored
independently. Backups use AES-256-GCM and refuse overwrite. The backup includes
the security state archive and configured audit files and receipt ledger.
`CINDERTRACE_COLLECTOR_BOUNDARY_FILE` includes the collector boundary;
`CINDERTRACE_BACKUP_ENV_FILE` includes recovery configuration. A restored
environment is written to a private file for explicit review, never automatically
installed over current credentials. Copy encrypted backups to independently
administered storage and test restoration regularly.

## Rollback and stabilization

Before destination writes, restore the prior verified application with its
compatible state. After writes, freeze both sides and reconcile the current state;
never overwrite new evidence with an old backup. Retain unknown effects for review.

After cutover, observe 24 hours of fresh configured sources, healthy API/console,
healthy backups, one writer/dispatcher, and no duplicate execution. Preserve failed
samples. Historical acceptance does not conceal a later operational incident.

Current backups use streaming PostgreSQL custom dumps in authenticated encrypted
archives. Native restore requires a completely empty, unmigrated destination;
it restores the source migration history with its original checksums. Verify the
restored data before applying any new additive migrations. A restore rehearsal
never starts ingestion, retention, notifications, or dispatch. The JSON state
transfer utility remains available for compatibility imports into a prepared
Cindertrace schema. Large installations can import a native archive into a
prepared empty current schema without replacing its migration history:

```sh
CINDERTRACE_TRANSFER_CONFIRM=frozen-source-empty-destination node scripts/backup.mjs import /private/recovery/security.aes
```

The archive must attest no pending, active, or unknown effects. Import verifies
every original field and applies new column defaults. Keep the encrypted source
migration history as recovery evidence. Prefer native backups for large datasets.
`verify-restored` checks an already restored database and assets without importing
or overwriting anything; use it to reconcile an interrupted recovery attempt.
