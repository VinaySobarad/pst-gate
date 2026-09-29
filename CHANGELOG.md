# Changelog

## 0.2.0

- Composite Action (`uses: org/pst-gate@v1`) for bring-your-own SARIF.
- Reusable workflow calls that Action after scanners.
- CISA KEV overlay: reachable/shipped KEV is not hidden by baseline.
- SCA fingerprints collapse across tools (package + CVE).
- SBOM component names count as shipped.
- Direct deps from `package.json` / `go.mod` / `[project] dependencies`.
- Validate policy/exceptions/baseline (exit 2).
- Sticky PR comment, merged SARIF, SBOM provenance statement.
- GitHub Actions pinned to commit SHAs; Dependabot for Actions and pip.

## 0.1.0

- Initial `pst-gate decide` loop: baseline, exceptions, CODEOWNERS, advisory.
