# Contributing

Use synthetic data and follow AGENTS.md. Run `npm ci`, `npm run hooks:install`,
and `npm run verify`. Security behavior changes require regression tests.
Never commit local configuration, databases, evidence, private provenance, or
live screenshots. Scan the staged index before committing and built payloads
before publication. Describe changes with Conventional Commits.

Read the [privacy guidance](PRIVACY.md) before preparing fixtures or reports.
Keep deployment-specific acceptance records outside this public repository;
documentation should describe supported behavior and reproducible commands.
