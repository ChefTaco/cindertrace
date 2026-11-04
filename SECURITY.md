# Security reporting

Do not post credentials, incident evidence, private hostnames, or exploit details
in a public issue. Use [private vulnerability reporting](https://github.com/ChefTaco/cindertrace/security/advisories/new)
or contact a maintainer through their public GitHub profile to arrange a private
report. Include the affected version, a synthetic reproducer,
expected behavior, and impact.

Keep Cindertrace and its data stores on trusted networks. Use verified TLS,
dedicated secrets, least-privilege integration credentials, and encrypted backups.
No external integration or host response capability is enabled by default.

Generated local administrator credentials use an Argon2id password verifier.
The session store separately uses an HMAC keyed by the dedicated session secret
to invalidate sessions when administrator credentials or the configured session
generation change. That value is a session-rotation binding, not a password
verifier; login checks do not compare submitted passwords against it.

A passing CodeQL workflow does not establish that the repository has no open
security alerts. Release reviews must also inspect open code-scanning, Dependabot,
and secret-scanning alerts with an account authorized to read them. An unavailable
alert API is an unverified check. Resolve actionable findings; document evidence
and the data flow before dismissing a false positive.
