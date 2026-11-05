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
transport; it does not enable network sources. Source status reports stay within
the collector's admitted sources, including disabled sources it owns.
ChatterMost/Mattermost audit export uses `CHATTERMOST_SECURITY_EXPORT_URL` and
`CHATTERMOST_SECURITY_EXPORT_TOKEN`. No message bodies are ingested.

The wire source aliases `aegis_ui`, `security_console`, and `cindertrace_ui`, and
`chattermost`/`mattermost`, remain readable. Original event IDs, source names,
checksums, and signed payloads are never rewritten for branding.

## Hive

Hive login uses the configured discovery URL, client ID, issuer, API audience,
and Cindertrace public origin. It is optional; local login remains independent.
Use a separately registered Cindertrace OAuth client and callback
`/api/auth/hive/callback`.

Security export uses the public Hive `security-exporter` client credentials with
only `iam:audit:read router:security-events:read`. Configure
`HIVE_IAM_SECURITY_URL`, `HIVE_IAM_SECURITY_CLIENT_ID`,
`HIVE_IAM_SECURITY_CLIENT_SECRET`, and `HIVE_SECURITY_EXPORT_URL` (Router
`/api/security/events`). Static Hive export tokens are retired.

## Magnus

Inventory uses `MAGNUS_INVENTORY_URL` and `MAGNUS_INVENTORY_TOKEN`. Set
`MAGNUS_CONSOLE_URL` to show a fleet link. Observation export and summary tokens
remain purpose-scoped; point Magnus's existing external-security configuration
at Cindertrace.

Response additionally requires the Magnus Cindertrace bridge, its additive
migration, and a matching managed agent with the registered `/security-response`
operation. Set Cindertrace's `MAGNUS_RESPONSE_URL` to the Magnus
`/api/v1/security-integration/response` URL and `MAGNUS_RESPONSE_SECRET` to a
new dedicated secret matching Magnus's `CINDERTRACE_RESPONSE_SECRET`.
Configure both restart allowlists and protected target IDs. Only then enable
`SECURITY_DISPATCH_ENABLED=true`. The agent must explicitly enable
`MAGNUS_SECURITY_RESPONSE_ENABLED` and configure a root-owned containment helper.
Enrolled-node admission is required; there is no direct-agent fallback.

## Automation credentials

Read and investigation-draft credentials remain endpoint-scoped. They cannot
approve containment. Native approval uses an authenticated ADMIN session.
`SECURITY_APPROVAL_MODE=external` requires the configured signed approval adapter;
console approval cannot bypass that installation policy. Historical external
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
