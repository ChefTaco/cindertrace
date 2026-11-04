# Direct Oathweave authorization

Cindertrace optionally accepts resource tokens directly from HiveXUI, without
placing the console's signing secret in the browser. Set `OATHWEAVE_ISSUER`,
`OATHWEAVE_JWKS_URL` and `OATHWEAVE_USERINFO_URL` to verified HTTPS endpoints.
Configure private CA trust through `NODE_EXTRA_CA_CERTS` when necessary.

Tokens must carry audience `cindertrace`; session revocation is checked online.
`CINDERTRACE_OATHWEAVE_IDENTITIES_JSON` is a private array of
`{issuer, subject, localUserId, role}` entries, where role is `ADMIN`, `OPERATOR`
or `VIEWER`. Match existing local actor IDs explicitly; never infer a link by
email or username. Duplicate or missing links fail closed.

An ADMIN link also requires `cindertrace:admin` to act as ADMIN. An ADMIN or
OPERATOR link with `cindertrace:investigate` acts as OPERATOR.
`cindertrace:view` permits only VIEWER behavior. Identity-system roles alone grant
no security privileges. Existing service credentials, signed ingestion, evidence
identifiers, approvals and response dispatch rules retain their current contracts.

This integration is rejected by isolated investigation-lab configuration. Existing
standalone console authentication remains available while frontend parity and
recovery acceptance are completed.
