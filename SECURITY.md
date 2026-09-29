# Security

Report vulnerabilities in **this** project (the gate, not findings it reports) by opening a private GitHub security advisory on the repository, or by emailing the maintainer listed on the GitHub profile.

Do not file a public issue for a secret in the Action or an RCE in `pst-gate decide`.

This Action runs `pip install` from `github.action_path` (the tagged commit you pinned). Pin `@v1` or a SHA. Third-party actions used here are pinned to full commit SHAs; Dependabot opens PRs when they move.

Exceptions in a calling repo are code. Protect `security/exceptions.yml` with `CODEOWNERS` and branch rules so a random PR cannot grant itself an infinite waiver.
