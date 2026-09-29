# Adopt pst-gate

Pin a **tag or SHA**, not `@main`.

## A. You already scan (recommended)

```yaml
name: security
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      # ... your Semgrep / Trivy steps write reports/*.sarif
      - uses: VinaySobarad/pst-gate@v1
        with:
          sarif-dir: reports
          fail-on: high
```

Add `security/policy.yml`, `security/baseline.json` (`{"version": 1, "fingerprints": []}`), `security/exceptions.yml` (`exceptions: []`), and `CODEOWNERS`.

## B. You want scanners included

```yaml
jobs:
  gate:
    uses: VinaySobarad/pst-gate/.github/workflows/gate.yml@v1
    secrets:
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
    permissions:
      contents: read
      pull-requests: write
      security-events: write
      actions: read
    with:
      fail-on: high
```

Optional secret `SNYK_TOKEN`. Trivy still runs without it.

Copy-paste samples: `examples/byo-sarif/.github/workflows/security.yml` and `examples/consumer/.github/workflows/security.yml`. GitHub does not run workflows from `examples/`.
