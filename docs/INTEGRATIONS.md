# Optional integrations

## Sources

Set `CINDERTRACE_API_URL` to the HTTPS API origin and configure collector-specific
`SECURITY_FUSION_INGEST_SECRET` and `SECURITY_FUSION_COLLECTOR_ID`. The API registry
`SECURITY_FUSION_COLLECTOR_CREDENTIALS_JSON` binds each collector to explicit
`allowedSources`. The collector posts directly to the Cindertrace ingestion API;
it does not require a Magnus relay. Existing `CONTROL_API_URL` installations may
use that name as a compatibility alias for the Cindertrace API URL.

UDP input requires `SECURITY_FUSION_UDP_ENABLED=true`; configure an appropriate
bind address and network policy. Tailscale local polling requires
`TAILSCALE_LOCAL_ENABLED=true`; API polling requires its token and tailnet.
Network collection through Loki requires `LOKI_URL`, an explicit `LOKI_QUERY`
selecting the configured source stream, and its dedicated read credential. UI
audit collection uses `UI_SECURITY_SOURCES_JSON` and the authenticated Loki
transport; it does not enable network sources.

### UniFi gateway streams in Loki

One `LOKI_QUERY` feeds `netflow`, `unifi_dns` and `unifi_ids`, so it should select
every stream the gateway produces, for example `{exporter="gateway"}` when the log
shipper gives the gateway's syslog and its flow file the same `exporter` label.
Each entry is read as one of:

- **IPFIX / NetFlow v9 flows** written by [goflow2](https://github.com/netsampler/goflow2)
  as JSON lines (`-format json`; stream label `job="ipfix"`, or any line starting
  with `{`). Each flow becomes a `netflow` observation (`derivedFrom: loki-ipfix`,
  `ruleSet` `ipfix-outbound`, `ipfix-inbound`, `ipfix-internal` or `ipfix-transit`),
  plus `unifi_dns` network activity when either port is 53. MAC addresses are not kept.
- **CEF lines** from UniFi Network's Activity Logging (SIEM server) export. Each line
  becomes one event that is not aggregated (`derivedFrom: loki-cef`).
- **Firewall syslog lines** with `SRC=`, `DST=` and `PROTO=` (UniFi Network before 11).

Flows and firewall lines are aggregated into five-minute summaries per source,
direction or rule set, protocol and destination service.

**Sampling.** Gateways sample flows (UniFi: 1 in N). `sampledBytes` and
`sampledPackets` are what the exporter recorded; `estimatedBytes`,
`estimatedPackets` and `estimatedFlowCount` multiply them by the sampling rate.
The rate comes from the record's `sampling_rate` when the exporter announced it
(`samplingRateSource: exporter`), else from a `sampling_rate` stream label
(`stream-label`), else 1 (`assumed-unsampled`). UniFi gateways do not announce the
rate in a form goflow2 decodes, so set the label to the gateway's setting.

**Quiet sources.** A source whose polls succeed but that has had no event for
`SECURITY_FUSION_QUIET_AFTER_HOURS` hours (default 6, `0` turns it off) reports
`degraded` with the error `no events for more than N hours`. The watched
sources are `SECURITY_FUSION_QUIET_SOURCES` (comma separated, default `netflow`);
leave out sources that are legitimately quiet, such as IDS alerts. After a
restart the collector's start time is the baseline. Source status reports stay within
the collector's admitted sources, including disabled sources it owns.
ChatterMost/Mattermost audit export uses `CHATTERMOST_SECURITY_EXPORT_URL` and
`CHATTERMOST_SECURITY_EXPORT_TOKEN`. No message bodies are ingested.

The wire source aliases `aegis_ui`, `security_console`, and `cindertrace_ui`, and
`chattermost`/`mattermost`, remain readable. Original event IDs, source names,
checksums, and signed payloads are never rewritten for branding.

## Suite product audit

The collector pulls HiveAuditRecord v1 from HiveMem, HiveSkills, ArdentStudio and
Embermend through each product's `GET <api>/v1/audit/export?after=<cursor>&limit=200`
and ingests it under the sources `hivemem`, `hiveskills`, `ardentstudio` and
`embermend`. Add those sources to the collector's `allowedSources` in
`SECURITY_FUSION_COLLECTOR_CREDENTIALS_JSON`; a configured source outside the
collector's admission stops polling at startup.

Configure the products with `SECURITY_COLLECTOR_AUDIT_SOURCES_JSON`, a JSON list:

```json
[
  {"source": "hivemem", "url": "https://hivemem.internal.example/v1/audit/export", "audience": "hivemem"},
  {"source": "embermend", "url": "https://embermend.internal.example/api/v1/audit/export", "audience": "embermend", "scope": "embermend:audit:read"}
]
```

`url` is the product's internal HTTPS export URL. `scope` defaults to
`<source>:audit:read`, the permission each product checks. Tokens come from
Oathweave client credentials at `<SECURITY_COLLECTOR_AUDIT_OATHWEAVE_URL>/api/v1/oauth/token`
with `SECURITY_COLLECTOR_AUDIT_CLIENT_ID` and either
`SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET` or `SECURITY_COLLECTOR_AUDIT_CLIENT_SECRET_FILE`.
An Oathweave machine client issues tokens for one audience, so a source may name
its own `clientId` and `clientSecretFile`; register each client with the
product's audience and its `<product>:audit:read` permission. When the token is a
JWT, the collector refuses one whose `aud` does not include the configured
`audience`. Tokens are cached until shortly before they expire (a fifth of the
lifetime, at most a minute early) and are refreshed once when a product answers 401.

Every source polls independently each minute, so a failing product is reported in
its own source status and never holds the others. A poll reads up to 25 pages
strictly after the source's checkpoint. Each page is validated as a whole before
any of it is queued; a malformed record, a record naming another product or a
full queue holds the checkpoint. The checkpoint advances to each page's
`nextCursor` and is stored by the API with the ingested events, so a restarted
collector resumes after it. A page with records carries its last record's
cursor; an empty page with `nextCursor: null` means caught up, and the next poll
asks again after the last stored cursor. Event IDs (`sha256(<source>:<record id>)`)
deduplicate any replay, and a record repeated within a page is queued once. Collector logs name the
source, status and invalid field paths only, never record contents.

Each record becomes one event: `kind` is `<product>.<action>`, `observedAt` is
`occurredAt`, `sourceEventId` and the evidence locator are the record `id`, and
the attributes keep `product`, `action`, `outcome`, `actor`, `target` and the
product's redacted `details`. A `user` actor becomes a `user` entity, a `service`
actor a `service` entity, and an `agent` actor whose ID is a HiveMem agent ID an
`agent` entity. The record's `subject` names the agent the action concerns:
`subject.actorId` attaches `actor:<actorId>`, otherwise `subject.agentRef` attaches
`agent-ref:<nodeId>~<profile>`. Valid `subject` values are also set as the
`actorId`, `agentRef` and `nodeId` attributes, so the agent gains its
`agent-ref:` and `magnus-node:` aliases as described under Agent entities.
Malformed subject IDs are ignored.

Severity comes from the action's dotted and underscored terms, then the outcome:

| Action terms | Severity |
|---|---|
| credential, secret, token, key, api_key, password, passkey, mfa, totp, certificate; permission, role, grant, acl, policy, scope, access, share, member, membership, privilege, admin, owner | `high` |
| delete, remove, purge, destroy, erase, wipe, revoke, forget, unshare | `medium` |
| read, list, get, view, search, query, fetch, download, export, recall, lookup, login, signin | `info` |
| anything else (create, update, promote, publish, ...) | `low` |

A `failure` outcome raises the severity one step, to at least `medium`; a failed
credential or permission change is `critical`.

Embermend findings (`finding.observed`, `finding.recurred`) take their severity from the
finding instead (`details.severity`: `critical`, `high`, `medium` or `low`; `unknown` falls
back to the table). For Embermend records, `subject.nodeId` (the Magnus node a finding was
observed on or an execution ran on) also attaches a `host` entity with that node ID, so the
event correlates with the host's other events. Embermend reports an execution whose effect
is failed or unknown as outcome `failure`, which raises its severity as above.

### Poll status

Each source's status report also carries what its latest poll read. `GET /sources`
returns, per source, `checkpoint` (the last stored cursor), `lastPollAt`,
`lastPollRecords` (records queued) and `lastPollPages` (pages fetched, including the
final empty one), next to `status`, `lastSuccessAt`, `lastErrorAt` and `lastError`. A
poll that fails part way reports how far it got, so `status: "error"` with
`lastPollPages: 1` and `lastPollRecords: 0` means the first page was refused.

### Cindertrace's own audit

Cindertrace serves its own audit in the same format at `GET /api/v1/audit/export?after=&limit=`
(1 to 200, default 100), oldest first: approvals, evidence preservation, collector
revocation, sign-ins and the rest of the hash-chained audit files. Records have product
`cindertrace` and IDs `cindertrace:audit:<entry id>`; `details` keeps the entry's scalar
values plus `chain` (`verified`, `legacy-partial` or `invalid`), and client addresses are
not exported; details are flattened and redacted with hive-common's `auditDetails()`, and each
record is checked with `validateHiveAuditRecord()` (an entry that fails is skipped). `nextCursor`
names the last entry read, also on the final page; it is `null` only when nothing was read. It can be read by an ADMIN, or by a consumer holding the
endpoint-scoped credential whose SHA-256 is `SECURITY_AUDIT_EXPORT_TOKEN_SHA256` (that
credential reads nothing else).

## Hive

Security export uses the public Hive `security-exporter` client credentials with
only `iam:audit:read router:security-events:read`. Configure
`HIVE_IAM_SECURITY_URL`, `HIVE_IAM_SECURITY_CLIENT_ID`,
`HIVE_IAM_SECURITY_CLIENT_SECRET`, and `HIVE_SECURITY_EXPORT_URL` (Router
`/api/security/events`). Static Hive export tokens are retired.

### HiveXUI inbox feed

`GET /api/v1/hive/events?after=<cursor>&limit=<n>` serves HiveEvent v1 from
`@hivemagnus/hive-common` for the HiveXUI inbox. The Hive Registry entry
announces it as `"capabilities": {"events.v1": {"path": "/api/v1/hive/events"}}`.
Events come from stored records only; nothing is written for the feed.

| Type | Source | Severity |
|---|---|---|
| `case.opened`, `case.reopened`, `case.severity.raised` | case activity | case severity: info and low → `info`, medium and high → `warning`, critical → `critical` |
| `case.closed` | case update to resolved or false positive | `info` |
| `containment.approval.requested` | containment approval request | `warning` |
| `containment.approval.approved`, `containment.approval.rejected` | console or external decision | `info` |
| `containment.action.succeeded`, `containment.action.released`, `containment.release.requested` | dispatch results, release request | `info` |
| `containment.action.failed`, `containment.action.unknown` | dispatch or verification results | `critical` |

Every event links to `/security-fusion/cases/<caseId>`. When a case has one
agent entity, `subject` carries its `actorId`, `agentRef` and `nodeId`;
containment events name the target node. Pages are oldest first by
`(occurredAt, id)`, hold events strictly after `after`, default to 50 and allow
up to 200, and cover the last 14 days. Access matches case reads: ADMIN and
OPERATOR sessions, 401 without one, 403 for VIEWER and for endpoint-scoped
service credentials.

## Magnus

Inventory uses `MAGNUS_INVENTORY_URL` and `MAGNUS_INVENTORY_TOKEN`. Set
`MAGNUS_CONSOLE_URL` to show a fleet link. Observation export and summary tokens
remain purpose-scoped; point Magnus's existing external-security configuration
at Cindertrace.

### Agent entities

The `agent` entity type identifies an agent. Its canonical value is
`actor:<actorId>`, where the actor ID is the HiveMem agent ID (`[a-z0-9_-]{2,32}`).
Cindertrace also records two aliases on the entity: `agent-ref:<nodeId>~<profile>`
(the Magnus node ID and Ardent profile ID) and `magnus-node:<nodeId>`. Agent
values are matched exactly; unlike other entity types they are not lowercased.
An event may name an agent directly with `{ "type": "agent", "value":
"actor:<actorId>" }` or `"agent-ref:<nodeId>~<profile>"`. An agent reference with
no known actor is kept as a provisional agent until an event binds that
reference to an actor. Agent entities join cases but do not change how cases are
grouped: a case is anchored on another entity whenever the event names one.

For `magnus` events Cindertrace attaches the agent entity itself when the event
attributes carry `actorId`, or `nodeId` with `profile` (or `agentRef`). Values are
used exactly as sent and never derived. Magnus security export currently sends
only `magnus.service.health` events with a `host` and a `service` entity and the
attribute `nodeId`. Those events describe a node, not an agent, so no agent entity
is attached. To link Magnus findings to an agent, Magnus would add to an event
that concerns one agent the attributes `actorId` (its HiveMem agent ID) and
`profile` (alongside the existing `nodeId`), or an `agent` entity with the value
`actor:<actorId>`.

`GET /api/v1/security-fusion/cases?entityType=<type>&entity=<value>` lists the
cases linked to one entity, newest first, with the same response, limits,
`status` and `archived` filters, and roles as the unfiltered list. Both
parameters are required together. The value is normalized as on ingest. For
`agent` it may be `actor:<actorId>`, which includes cases of provisional agents
whose reference is now bound to that actor, `agent-ref:<nodeId>~<profile>`, or
`magnus-node:<nodeId>` for every agent recorded on that node. An invalid filter
returns 400 `INVALID_ENTITY_FILTER`; an unknown entity returns an empty list.

### Response

Response additionally requires the Magnus Cindertrace bridge, its additive
migration, and a matching managed agent with the registered `/security-response`
operation. Set Cindertrace's `MAGNUS_RESPONSE_URL` to the Magnus
`/api/v1/security-integration/response` URL and `MAGNUS_RESPONSE_SECRET` to a
new dedicated secret matching Magnus's `CINDERTRACE_RESPONSE_SECRET`.
Configure both restart allowlists and protected target IDs. Only then enable
`SECURITY_DISPATCH_ENABLED=true`. The agent must explicitly enable
`MAGNUS_SECURITY_RESPONSE_ENABLED` and configure a root-owned containment helper.
Enrolled-node admission is required; there is no direct-agent fallback.
While `SECURITY_DISPATCH_ENABLED` is not `true`, previews and approval requests still
work, but approvals (native and external) answer 503 `DISPATCH_DISABLED` and action
details report `responseAvailable: false`, so no action waits in `dispatch_pending`
for a dispatcher that is off. Previews and approval requests that are not decided
within ten minutes are cancelled (case activity `containment.expired`, approval row
`expired`, audit `security_fusion.action.expire`). Operator cancellation is recorded
the same way (`containment.cancelled`, `security_fusion.action.cancel`).

Releasing an isolation waits up to ten seconds for the dispatcher, so the reply and the
`isolation.release_requested` case activity name the Magnus command when it was sent in
time; otherwise the action reports `release_pending` and the dispatcher sends it on its
next pass.

#### Approval safeguards

Two optional settings tighten who may approve a response action. Both are off by default;
the API refuses to start with an invalid value.

- `SECURITY_APPROVAL_MAX_AUTH_AGE_SECONDS` (60 to 86400): an approver must have signed in
  within this many seconds. A local session counts from its sign-in; an Oathweave session
  uses the identity provider's sign-in time (`auth_time`), and one without it is refused.
  An older session gets 401 `REAUTHENTICATION_REQUIRED`: sign out and in again, then
  approve. A local session otherwise lasts 24 hours, so 900 (15 minutes) is a sensible value.
- `SECURITY_APPROVAL_DISTINCT_APPROVER=true`: the administrator who previewed or requested
  an action cannot approve it (403 `DISTINCT_APPROVER_REQUIRED`); another administrator
  must. Anyone may still reject. With a single local administrator this blocks local
  approval, so use it with several administrators (Oathweave) or external approval.

#### Audit after a committed change

Requests, approvals and rejections, cancellations, expiries, evidence preservation and
collector revocation are written to the database first and audited after the commit. If
the audit append then fails (for example a full or read-only `AUDIT_LOG_DIR`), the change
stands and the request still succeeds, so a retry is not refused as already used. The
failure is logged on stderr without the entry's details and counted in `/metrics` as
`security_fusion_audit_append_failures`; alert on any increase. The case activity written
with the change still records it.

## Automation credentials

Read and investigation-draft credentials remain endpoint-scoped. They cannot
approve containment. Local approval (`SECURITY_APPROVAL_MODE=local`, or its legacy
spelling `console`) uses an authenticated ADMIN session.
`SECURITY_APPROVAL_MODE=external` requires the configured signed approval adapter;
local approval cannot bypass that installation policy. Historical external
decisions remain preserved and never become new executable approvals.

Server-side agents can use `CindertraceClient` from the integration workspace.
Configure its HTTPS origin, a registered read token, and a separate optional
draft token. It exposes scoped reads and `draftInvestigation`; it has no approval
or host-execution method. Register read token SHA-256 digests in
`SECURITY_PLUGIN_READ_DIGESTS_JSON` and the draft digest in
`SECURITY_PLUGIN_DRAFT_TOKEN_SHA256`. Keep plaintext credentials outside Git.

New signed external approvals use assertion version 4 and an explicit
`source_channel`. Sign the canonical payload with Ed25519 over the prefix
`cindertrace.external-approval.v4` followed by a newline and canonical JSON.
Configure `SECURITY_APPROVAL_PUBLIC_KEY_B64`, `SECURITY_APPROVAL_ACTOR_SHA256`,
and the bridge bearer digest `SECURITY_EXTERNAL_APPROVAL_TOKEN_SHA256`.
Legacy v2/v3 signatures and historical decisions remain compatible. All new
executable approvals still require a current pending plan and ten-minute expiry.

The bounded response drill uses the built API, an empty disposable PostgreSQL
schema, Redis and a locally generated certificate authority. Run `npm run build`
first, then set `CINDERTRACE_TEST_DATABASE_URL` to a dedicated database named
`cindertrace_test_response_*`, `CINDERTRACE_TEST_REDIS_URL` to disposable Redis,
and `CINDERTRACE_RESPONSE_TEST_CONFIRM=isolated-synthetic-installation` before
`npm run test:response`. The drill applies packaged migrations and retains its
synthetic database rows for inspection; it never selects operational accounts,
contacts Magnus or executes a host command. Its HTTPS responder verifies the
request signature and returns a request-bound signed receipt. Assertions cover
expired approvals before decision and dispatch, changed previews, concurrent
one-use decisions, exactly one command, lost replies and invalid receipts becoming
unknown, and expired durable claims never being sent again. This proves the API
and dispatcher boundary, while real Magnus admission and host execution retain
their separate acceptance gates.
