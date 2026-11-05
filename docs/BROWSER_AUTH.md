# API-owned native browser authentication

Suite deployments use Oathweave resource tokens and explicit issuer/subject links.
Standalone local sign-in is also available directly from the API. Enable it with
`CINDERTRACE_BROWSER_AUTH_ENABLED=true`, a canonical HTTPS `DASHBOARD_PUBLIC_ORIGIN`,
`REDIS_URL`, `SESSION_SECRET`, and dedicated `DASHBOARD_ADMIN_USERNAME` plus
`DASHBOARD_ADMIN_PASSWORD_HASH` (Argon2id). Dedicated plaintext or base64-encoded
credentials remain accepted for explicit compatibility; infrastructure passwords
are never a fallback. `DASHBOARD_ADMIN_ACCOUNT_ID` preserves the reviewed local
account identity. `AUTH_RATE_LIMIT_LABEL_KEY` is optional and defaults to the
session secret; both require at least 32 characters.

| API | Behavior |
| --- | --- |
| `POST /api/v1/auth/local/login` | Exact Origin, bounded JSON credentials, durable source/account/pair throttling, Argon2id verification, audited session creation |
| `GET /api/v1/auth/local/session` | Current identity after signature, issuer, audience, expiry, credential generation and durable revocation checks |
| `POST /api/v1/auth/local/logout?all=true` | Revoke the current or all local sessions before clearing the cookie |

The only native cookie is `cindertrace_session`: Secure, HttpOnly, SameSite=Lax,
Path=/, with a maximum 24-hour lifetime. Responses use no-store. Each receiving
security API independently validates this cookie, its current durable state and
its permissions; non-read cookie requests also require the configured exact
Origin. Bearer and signed native clients retain their existing protocols. Redis
or audit failure denies sign-in; failed durable revocation does not clear the
cookie or pretend sign-out succeeded. Caller-supplied forwarding headers never
replace the API's bound socket address for authentication admission.

## Adoption and recovery

Preserve `SESSION_SECRET`, `SESSION_ISSUER`, `SESSION_AUDIENCE`,
`LOCAL_SESSION_GENERATION`, dedicated credential values (including their encoded
form), and the exact Redis data. The API adopts the existing local key prefix,
credential-generation digest, session-generation record and fifty-session limit.
An existing cookie can be verified and revoked across both implementations without
reseeding identities or replacing signing state. Native local credentials do not
merge with an Oathweave account by username or email. Reviewed product links retain
their separate local account IDs.

Set `CINDERTRACE_API_BROWSER_AUTH=true` on the retained console to delegate native
local login, verification, logout and authenticated product requests to the API
via verified HTTPS. It forwards only the local product cookie and exact Origin,
without supplying a shared administrator bearer credential. Existing Hive OAuth
sessions and their encrypted credential store retain their compatibility path.
The legacy console and its default native recovery path remain until replacement
and restored-data parity gates pass; this flag does not authorize a cutover.

Keep existing console security-event files and collector cursors. The API emits
the same schemaVersion 1 `cindertrace_ui` authentication event format and keyed
account/source/pair labels to `UI_SECURITY_LOG_PATH`; a fresh deployment defaults
to `$CINDERTRACE_STATE_DIR/ui-security/events.jsonl` (or `/data/ui-security/events.jsonl`).
Explicit adoption points the API at the preserved private log, with appropriate
producer/collector filesystem access. Existing records are appended, never rewritten.
The API also appends its own integrity-protected audit chain. Neither log contains
submitted passwords, session cookies or authorization headers. Compatibility events
use keyed account labels; API audit records retain the reviewed local account ID,
which may be the configured administrator username. These IDs and source addresses
remain private operational data. Preserve independent installations' logs, keys and cursors separately.

## Fresh initialization

Inside the reviewed non-root API image, run:

```sh
node services/security-fusion/dist/browser-auth/hash-password.js \
  --config /config/initial-browser-account.json --output /data/browser-admin.json
```

The protected input is JSON `{username,password}`; the password must contain
12–4096 characters. Files must be regular, unlinked, owned by the executing UID
and inaccessible to other users; the output directory requires mode 0700. The
protected output contains schema 1, `username`, `passwordHash`, and `sourceSha256`.
Repeated identical input reuses the verified original hash. Changed input or unsafe
existing files fail without replacing credentials. Concurrent first runs use atomic
no-overwrite publication. The command prints neither password nor hash. The Hive
controller reads the result into a protected product environment file; it does not
require a host Node runtime.

The owning migration command supports `--verify-current`. Verification uses a
read-only repeatable-read transaction, requires every exact finished packaged
checksum and rejects unknown, duplicate, unfinished or rolled-back history. It
never creates migration tables, applies SQL, repairs state or adopts a baseline.

## Isolated rehearsals

`HIVE_REHEARSAL=true` forces dispatch, retention, ingestion, security writes,
notifications and host collection flags off, regardless of restored settings.
Startup skips receipt-head creation, evidence reconciliation and inventory sync;
API writes are paused, and direct dispatcher, retention and inventory entrypoints
remain fenced. Authentication in a restored private copy may create its isolated
sessions and authentication audit records. A validated rehearsal flag may accompany
an already isolated synthetic lab; it grants no external integration capability.

Run unit/build/contract/privacy gates with `npm run verify`. Native Redis adoption,
bounded sessions and revocation can be checked using `npm run test:browser-auth`
with `CINDERTRACE_AUTH_TEST_CONFIRM=isolated-synthetic-installation` and an explicit
`CINDERTRACE_TEST_REDIS_URL` for a disposable fixture. The driver creates unique
synthetic session/rate namespaces and cleans only those records. Actual container,
browser and restored-data acceptance remain required before production migration.
