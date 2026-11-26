# Contributing

Use synthetic data and follow AGENTS.md. Run `npm ci`, `npm run hooks:install`,
and `npm run verify`. Security behavior changes require regression tests.
Never commit local configuration, databases, evidence, private provenance, or
live screenshots. Scan the staged index before committing and built payloads
before publication. Describe changes with Conventional Commits.

`npm run verify` is what CI runs. The integration suites run against disposable
installations and refuse to start without their explicit confirmation variable
(for example `CINDERTRACE_RECOVERY_TEST_CONFIRM`); read each script's header first:
`npm run test:core`, `test:recovery`, `test:upgrade`, `test:browser-auth`,
`test:response`, `test:lab`, `test:lab:browser` and `test:gateway`. `test:gateway` runs
in a freshly initialized installation directory with the stack up: it signs in and calls
the API through the gateway, then checks that repeated failed sign-ins throttle only the
client that made them (it uses up that host's sign-in allowance for 15 minutes). CI runs
the Compose and lab jobs on both supported Node lines (24 and 26); the image builds and
runs on Node 26.

Read the [privacy guidance](PRIVACY.md) before preparing fixtures or reports.
Keep deployment-specific acceptance records outside this public repository;
documentation should describe supported behavior and reproducible commands.

## Secret scanning

Install the pinned, checksum-verified Gitleaks CLI before contributing:

```bash
bash scripts/install-gitleaks.sh
git config core.hooksPath .githooks
bash scripts/test-gitleaks.sh
bash scripts/gitleaks.sh --staged
bash scripts/gitleaks.sh --history
```

Gitleaks 8.30.1 is free and runs directly; no paid Action or organization license
is required. The installer supports Linux and macOS on x64 and ARM64 and uses the
user cache, without sudo. Other platforms can put that exact version on PATH.
Missing or incompatible binaries fail the hooks rather than skipping checks.

The commit hook scans an export of the exact Git index, including force-added
ignored files. The push hook scans every outgoing ref's commit range, including
secrets deleted in a later commit. New refs or unavailable remote bases receive
a complete reachable-history scan. Existing privacy checks still run.

The `Gitleaks` workflow scans full reachable history on pushes, pull requests
and merge queues, and runs synthetic regression checks. Maintain `Gitleaks` as a
required status check on the default branch. CI runs after upload and can block
merging; local hooks and GitHub's native push protection help prevent upload.
Local hooks can be bypassed or absent on other clones, so install them in each
clone. No scanner guarantees detection of arbitrary secrets.

All output redacts matched secrets. Inline `gitleaks:allow` comments are ignored.
Review findings privately: rotate a real exposed credential and remove it through
the appropriate incident process. Never add real credentials to an allowlist.
Any false-positive exception in `.gitleaks.toml` must match both one exact value
and a specific file, with a reason; do not exempt whole test or documentation
directories or disable built-in detection rules.
