# API-owned native browser authentication

Suite deployments use Oathweave resource tokens and explicit issuer/subject links.
Standalone installations and the investigation lab sign in directly with the API:
HiveXUI in local mode posts to `/api/cindertrace/auth/local/*` on the gateway, which
forwards to the API's `/api/v1/auth/local/*` ([installation](INSTALLATION.md#the-ui-hivexui-in-local-mode)).
The same sign-in is HiveXUI's recovery path in a suite when Oathweave is unavailable.
`npm run init` enables it. It needs `CINDERTRACE_BROWSER_AUTH_ENABLED=true`, a canonical
HTTPS `CINDERTRACE_PUBLIC_ORIGIN` equal to the page origin,
`REDIS_URL`, `SESSION_SECRET`, and dedicated `CINDERTRACE_ADMIN_USERNAME` plus
`CINDERTRACE_ADMIN_PASSWORD_HASH` (Argon2id). Their legacy `DASHBOARD_*` names
(`DASHBOARD_PUBLIC_ORIGIN`, `DASHBOARD_ADMIN_*`) keep working; see
[setting names](INSTALLATION.md#setting-names). Dedicated plaintext or base64-encoded
credentials remain accepted for explicit compatibility; infrastructure passwords
are never a fallback. `CINDERTRACE_ADMIN_ACCOUNT_ID` preserves the reviewed local
account identity. `AUTH_RATE_LIMIT_LABEL_KEY` is optional and defaults to the
session secret; both require at least 32 characters.

`RELAX_AUTH_LIMITS=true` is for testing only. The API sign-in throttles
stay enabled with a ceiling of 10000 attempts per window and no retry delay, and the
Oathweave session exchange limit rises to the same ceiling. Credential checks and
audit events are unchanged, and nothing is written to stored state, so removing the
setting restores normal limits on the next start. The API prints a warning at startup
and its public `GET /health` response reports the mode in `authLimitsRelaxed`.

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
cookie or pretend sign-out succeeded.

## More local accounts, roles and TOTP

Without Oathweave, a standalone installation can give out more than the administrator
account. `CINDERTRACE_LOCAL_ACCOUNTS_JSON` lists further local accounts:

```json
[
  {"username": "analyst", "passwordHash": "$argon2id$...", "role": "OPERATOR", "totpSecret": "BASE32SECRET..."},
  {"username": "auditor", "passwordHash": "$argon2id$...", "role": "VIEWER", "userId": "local-auditor"}
]
```

`role` is `ADMIN`, `OPERATOR` or `VIEWER`, with the same permissions as an Oathweave link.
`passwordHash` must be Argon2id; make one with the hash tool under
[fresh initialization](#fresh-initialization). `userId` is the actor ID in cases, approvals
and the audit (default `local:<username>`). Usernames and user IDs must be unique,
including the administrator's. Because Compose interpolates `$` in `.env`, put the JSON
base64-encoded in `CINDERTRACE_LOCAL_ACCOUNTS_JSON_B64` instead; a malformed value stops
the API at startup. Up to 100 accounts.

An account with `totpSecret` (base32, at least 128 bits; 160 bits is usual) also needs a
six-digit authenticator code (RFC 6238: SHA-1, 30-second steps, one step of drift either
way). `CINDERTRACE_ADMIN_TOTP_SECRET` does the same for the administrator. Sign-in sends
it as `totp`; without it the API answers 401 `{"error":"Authentication code required",
"totpRequired":true}` once the password is right, and the client asks for the code. Each
code works once per account. Missing and wrong codes are audited as `auth.login_failed`
(reason `totp_required` or `totp_invalid`) and count against the sign-in limits. HiveXUI
must offer the code field for these accounts to sign in through it.

Sessions carry the account's role and user ID, read again from the configuration on every
request. Changing an account's password, role, user ID or TOTP secret, or removing it,
ends its sessions; so does adding TOTP to the administrator. The administrator's sessions
are otherwise bound as before, so existing sessions survive an upgrade.

## Client addresses behind the gateway or ingress

Sign-in throttling, the API rate limits and authentication audit records are keyed on
the client address. Browsers reach the API through a proxy, so the API takes it from
`X-Forwarded-For` only when the socket peer is listed in `CINDERTRACE_TRUSTED_PROXIES`,
reading from the right and stopping at the first address that is not a trusted proxy.
A forwarding header a caller writes itself is therefore never used. The list holds IP
addresses, CIDR ranges, host names (resolved through DNS and looked up again when the
proxy's address changes) and the keyword `loopback`; `none` trusts no proxy. Unset, it
is `loopback`. An invalid entry stops the API at startup.

- Compose installations set it to `gateway`. The gateway appends the address it
  received each request from and sets `X-Forwarded-Proto`. If another reverse proxy
  sits in front of the gateway, add that proxy's address as the gateway sees it (for a
  proxy on the Docker host, usually the Compose network's gateway address), for
  example `CINDERTRACE_TRUSTED_PROXIES="gateway 172.18.0.1"` in `.env`.
- In a Hive suite, list the address of Hive's ingress, which sends exactly one
  client address.

Successful sign-ins do not count toward a source's limit; failed attempts do.

## Adoption and recovery

Session tokens name issuer `cindertrace` and audience `cindertrace-browser` unless
`SESSION_ISSUER`/`SESSION_AUDIENCE` say otherwise. Earlier releases used
`cindertrace-console` for both; the API still accepts sessions issued that way, so an
upgrade signs nobody out.

Preserve `SESSION_SECRET`, `SESSION_ISSUER`, `SESSION_AUDIENCE`,
`LOCAL_SESSION_GENERATION`, dedicated credential values (including their encoded
form), and the exact Redis data. The API adopts the existing local key prefix,
credential-generation digest, session-generation record and fifty-session limit.
A cookie issued by the 0.7.x standalone console stays valid after the move to 0.8.0 and
can be revoked, without reseeding identities or replacing signing state: the API uses the
same session record format, which `npm run test:browser-auth` checks. Native local credentials do not
merge with an Oathweave account by username or email. Reviewed product links retain
their separate local account IDs.

Sessions the retired console created through its own Hive OAuth sign-in are not
accepted by the API; those users sign in again through HiveXUI.
`CINDERTRACE_API_BROWSER_AUTH`, the console's switch for delegating to the API, has no
effect in 0.8.0 and can be removed.

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
synthetic session/rate namespaces and cleans only those records. CI runs it in the
`browser-auth` job against a disposable Redis service. The lab job signs in through
HiveXUI and the gateway in a real browser (`npm run test:lab:browser`), and the
standalone job's upgrade rehearsal keeps a session across an upgrade and revokes it.
