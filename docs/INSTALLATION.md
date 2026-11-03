# Installation and configuration

`npm run init` creates unique secrets, an Argon2id administrator hash, and a
90-day local TLS certificate without printing credentials. It refuses to
overwrite an existing environment. Configuration and state are local-only.

Compose runs the console, API, PostgreSQL, and Redis. The collector is an opt-in
profile. The API exposes `/health`, `/ready` (database and Redis), and authenticated
`/metrics`. Only the console is published to the host, bound to loopback.

For a remote installation, replace the TLS certificate/key, configure
`DASHBOARD_PUBLIC_ORIGIN`, and explicitly publish the console on your chosen
interface. Set `NODE_EXTRA_CA_CERTS` to the issuing CA for private PKI. Certificate
verification must stay enabled. Renew certificates separately from code releases.

The generated `CINDERTRACE_UID` and `CINDERTRACE_GID` match the installing user,
so the container can write its private `state` bind mount. Set them explicitly
when installing for a dedicated service account and match directory ownership.
Back up state and PostgreSQL together.

Optional integration configuration is documented in INTEGRATIONS.md. Keep all
secrets out of browser variables, command arguments, logs, and Git.
