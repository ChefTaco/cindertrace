# Changelog

## Unreleased

- Move optional native browser sign-in, durable sessions, revocation, throttling and
  compatible authentication events into the API, preserving legacy Redis/signing
  state and explicit console delegation.
- Add a protected idempotent Argon2id initializer and read-only exact migration
  verification. Fence restored rehearsals from dispatch, collection, state writes
  and retention.
- Retain resource verifier transport/header exports in the packaged JWT runtime.
