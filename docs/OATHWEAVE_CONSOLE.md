# Oathweave sign-in for the standalone console

The retained standalone console can use the same Oathweave identity as HiveXUI.
This shares identity through OIDC; it does not copy or synchronize passwords.
Native local authentication remains available for recovery.

Register a public Oathweave browser client with Authorization Code and PKCE S256,
exact redirect URI `https://security.example.com/api/auth/hive/callback`, and the
`cindertrace` resource audience. Its permission ceiling must explicitly contain the
required `cindertrace:view`, `cindertrace:investigate` or `cindertrace:admin` permissions.
Keep consent, MFA, recovery and step-up requirements in Oathweave. No client secret
or shared administrator credential is needed.

Enable API-owned browser authentication on the API and console, and configure the
existing identity verifier and explicit issuer/subject-to-product-account links:

```dotenv
# API
CINDERTRACE_BROWSER_AUTH_ENABLED=true
OATHWEAVE_ISSUER=https://identity.example.com
OATHWEAVE_JWKS_URL=https://identity.example.com/api/oathweave/oauth/jwks
OATHWEAVE_USERINFO_URL=https://identity.example.com/api/oathweave/oauth/userinfo
CINDERTRACE_OATHWEAVE_IDENTITIES_JSON=[{"issuer":"https://identity.example.com","subject":"reviewed-subject","localUserId":"existing-product-account","role":"ADMIN"}]

# Console; legacy HIVE_OAUTH names and callback path remain supported.
CINDERTRACE_API_BROWSER_AUTH=true
CINDERTRACE_API_URL=https://security-api.example.com
DASHBOARD_PUBLIC_ORIGIN=https://security.example.com
HIVE_OAUTH_ISSUER=https://identity.example.com
HIVE_OAUTH_DISCOVERY_URL=https://identity.example.com/api/oathweave/oauth/.well-known/openid-configuration?client_id=hivexui-security-console
HIVE_OAUTH_CLIENT_ID=hivexui-security-console
HIVE_OAUTH_API_AUDIENCE=cindertrace
```

Both services require their existing protected browser-session configuration and
verified certificate trust. `HIVE_OAUTH_CLIENT_SECRET` must be absent: this flow
requires a public client. For an explicitly configured private ingress, the
optional console `HIVE_OAUTH_BACKCHANNEL_ORIGIN=https://identity-internal.example.com`
may transport discovery, token and JWKS requests. Only requests whose canonical
origin equals the configured public issuer origin can use that override. TLS
verifies the private hostname, while signed issuer/client/audience claims and the
browser authorization endpoint retain their configured public identities. The
API can independently configure its verified private JWKS and userinfo URLs.
Neither mechanism rewrites browser Origin or disables TLS verification.

The console retains encrypted, expiring, one-use OAuth transaction state in Redis
and validates state, PKCE, nonce, ID-token issuer/client audience and resource-token
subject binding. It then exchanges the resource token at
`POST /api/v1/auth/oathweave/session`. Cindertrace independently validates signature,
issuer, exact resource audience, lifetime, live Oathweave session and the explicit
product link before issuing its own Secure/HttpOnly/SameSite=Lax cookie. Encrypted
resource credentials remain in the API's Redis store, never browser storage.
Every cookie use repeats resource authorization and online revocation. Cookies
expire with the resource token; sign in again through the existing SSO session.

An identity role alone never grants a product role. Cindertrace intersects the
reviewed product link with current resource permissions and preserves product IDs.
Do not infer links from email or usernames. Shared-identity sessions cannot use
legacy console host administration; owning backend APIs authorize their actions.
Logout durably revokes the product session, including during identity outages;
Oathweave sign-out/revocation independently invalidates captured product cookies.

For isolated restored-data rehearsals, retain original snapshots and signing files
but use separate runtime-only session signing secrets and identity issuer/audience
so newly created rehearsal credentials cannot authenticate to existing services.
Keep dispatch, collection, external integrations and business mutations fenced.
