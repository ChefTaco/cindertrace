# Privacy and data handling

Cindertrace stores security observations, entities, cases, investigations, evidence,
approvals, source checkpoints, and audit records in the operator's installation.
These records can contain IP addresses, hostnames, account identifiers, source
locators, and other sensitive operational metadata. Treat them as private data.

## Collection and access

The default installation enables local administrator login and signed ingestion.
Collectors, listeners, Hive login/export, Magnus inventory/response, and other
external sources require explicit configuration. Browser requests use the console's
same-origin proxy; integration credentials remain on the server.

Console authentication audit records use keyed account/source labels and retain
the source IP address. Labels are pseudonyms, not anonymization. The console does
not log submitted passwords, session cookies, authorization headers, or OAuth
codes. Other observations can still contain identities supplied by their source.
Adapters limit collected fields, and audit details are sanitized; review source
configuration and evidence before sharing it. ChatterMost/Mattermost audit export
does not collect message bodies.

Evidence requires a role with evidence-read permission. Read/draft automation
credentials cannot approve response actions. Hive and Magnus receive requests only
when their integrations are configured; approved host execution remains in Magnus.
Optional notification credentials and destinations can cause case summaries to be
sent externally. Review those destinations before enabling notifications.

## Storage, retention, and recovery

PostgreSQL, Redis, evidence, audit files, and collector state live outside the
application image. Normal state files are not encrypted by the application;
operators must secure accounts, networks, disks, and storage permissions. Use
verified TLS and keep dedicated signing and encryption keys private.

The current retention policy keeps observations for 90 days, preserved evidence
for 365 days, archived cases for 365 days with a 30-day grace period, and deletion
receipts for 2,555 days. Case state, integrity checks, and the enabled retention
worker affect when removal occurs; these periods do not promise deletion of every
related record. Inspect the Policies page and `/api/v1/security-fusion/policies`.
Backups and exported copies have separate operator-managed retention.

Recovery archives use authenticated AES-256-GCM encryption. When configured, they
also contain service environments, TLS/signing material, UI audit data, and
installation configuration. Anyone with an archive and its key can recover those
secrets. Store the key separately, protect off-host storage, and independently test
restoration. See [recovery](docs/MIGRATION.md) and [upgrades](docs/UPGRADING.md).

## Contributions and disclosure

Never publish live incidents, credentials, environments, logs, databases, backups,
private infrastructure details, or screenshots of real cases. Use synthetic data
for reports and examples. Follow the [publication gate](docs/PUBLISHING.md) and
report vulnerabilities through the [private security channel](SECURITY.md).
