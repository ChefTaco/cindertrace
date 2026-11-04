# Evolving investigation lab

This optional lab runs one synthetic login investigation in three evidence
releases. Use a fresh separate checkout and `npm run init -- --lab`; never copy
an operational environment into it. Initialization refuses existing configuration.
The normal demo and normal installation remain available without lab mode.

The console runs at `https://localhost:3445`. Use the generated local administrator
credentials to start a run. Operators can investigate, save revisions and advance.
Only administrators can start/restart runs or decide simulated containment.

## Investigator workflow

Record hypotheses, compromise confidence, a confidence explanation, next checks,
and freeform reasoning. Classify structured claims as asserted, tentative or
retracted and cite released observations. Choose whether to defer containment or
request a simulated response for a specific entity. Every save is a new immutable
revision bound to its evidence snapshot. A stale save must be rebased explicitly
by reloading the current run; it never silently overwrites another revision.

A current-stage revision is required to reveal more evidence or complete the
final stage. Progress survives restarts. Starting fresh retains the old run and
its history. There is one active run per installation and a maximum of 100
revisions per run. Run history lists the latest 100 runs.

Completion reveals the versioned rubric's reasons, unsupported assertion counts,
assertion denominators, supported coverage, tentative/retracted counts, confidence
changes, and unnecessary containment recommendations. There is no aggregate score.
The rubric judges only structured fields; it does not interpret or grade prose,
prove calibrated confidence, or provide a blind agent benchmark. This public
scenario can be read in the source. Comparisons use only evidence released when
each revision was saved, rather than hindsight from the completed scenario.

## Agent API

Use `CindertraceClient` from `@cindertrace/integrations` on the server. Configure
its HTTPS API origin, read token, independent draft token and independent
`labControlToken`. In the disposable Compose installation the internal origin is
`https://api:4101`; external clients must use an explicitly configured TLS endpoint
or an authorized same-origin session proxy. The API is not publicly bound by default.
Generated plaintext tokens are only in `state/lab-agent-credentials.json`; their
server registrations are SHA-256 digests in the lab environment. Do not expose
those tokens to browser code or commit them.

- `lab()` lists enabled status and recent runs. A human administrator starts a run.
- `labRun(id)` returns only released observations, targets, available claims,
  evidence snapshot digest and revision history. Rubric results are withheld until
  completion.
- `draftInvestigation(caseId, draft)` submits the existing draft fields plus
  `lab`: `runId`, `stage`, `previousRevision`, `evidenceSha256`,
  `compromiseConfidence` (0–100), `confidenceRationale`, `assertions`, and
  `containment`. Assertions contain `claimId`, `disposition`, and `evidenceIds`;
  containment contains `kind`, `targetId`, `evidenceIds`, and `rationale`.
  Use observation `id` values as citations. Every citation must belong to this
  run and already be released.
- `advanceLab(id, {stage, evidenceSha256})` and `completeLab(id, ...)` use only the
  separate lab-control credential. Retries do not release an additional stage.
- `compareLab(id)` returns the completed comparison using the read credential.

The `/api/v1/security-fusion/lab` HTTP operations are described in
[OpenAPI](openapi.json). Browser operations use the authenticated same-origin
proxy. Agent read/draft/control credentials cannot approve simulated or real
containment. The control token cannot start runs or access normal response routes.

## Approval simulation and isolation

A containment recommendation creates an exact simulated plan with its target,
effect, rationale, citations, run, revision, evidence digest and ten-minute expiry.
An administrator must inspect and explicitly approve or reject that plan. Approval
is consumed atomically once. New evidence or a superseding revision invalidates
pending plans; expiry, changed digests and replay fail closed. An approval records
only a simulated result, with no production action, outbox entry or network dispatch.

Lab startup rejects external integration settings and enabled ingestion,
notifications, UDP/local collection or dispatch. Synthetic observations do not
update source health. Lab runs, checkpoints and decisions are included in current
backups/restores and case retention. Historical export profiles retain their
original table sets. The additive migration introduces schema profile
`cindertrace-v2`; rollback requires a reviewed compatible schema and verified
restore, rather than an automatic down migration.

Use `npm run lab -- status|stop|up` in the lab checkout. Destruction requires the
exact generated project name and removes only that project's containers/volumes;
it does not delete the checkout's local state. Private captures and operational
proof belong outside Git. Public fixtures and screenshots must remain synthetic.

## Regression checks

Run `npm run verify` before committing. The dedicated CI lab job initializes a
fresh installation, exercises real database/agent boundaries and restore recovery,
and runs browser acceptance. To run browser acceptance locally against a disposable
lab with no active investigation:

```sh
npm exec -w @cindertrace/console -- playwright install chromium
CINDERTRACE_LAB_BROWSER_TEST_CONFIRM=disposable-installation npm run test:lab:browser
```

Set `CINDERTRACE_LAB_BROWSER_INSTALLATION` to the separate installation directory
when running from a development checkout. Optional `CINDERTRACE_LAB_BROWSER_OUTPUT`
requires an absolute directory outside the repository for synthetic captures.
