# Changelog

## Unreleased

- Add an isolated PostgreSQL/API and signed HTTPS dispatcher drill for exact-plan
  expiry, concurrent one-use approval, lost replies, invalid receipts and expired
  dispatch claims, without executing host operations.
- Move optional native browser sign-in, durable sessions, revocation, throttling and
  compatible authentication events into the API, preserving legacy Redis/signing
  state and explicit console delegation.
- Add a protected idempotent Argon2id initializer and read-only exact migration
  verification. Fence restored rehearsals from dispatch, collection, state writes
  and retention.
- Retain resource verifier transport/header exports in the packaged JWT runtime.
