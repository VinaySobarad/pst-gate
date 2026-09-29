# How pst-gate is reused

```
┌─────────────────────────────────────────────────────────────┐
│  Your repo                                                  │
│  security/policy.yml  baseline.json  exceptions.yml         │
│  CODEOWNERS                                                 │
└───────────────┬─────────────────────────────┬───────────────┘
                │                             │
                ▼                             ▼
     Composite action                  Reusable workflow
     uses: org/pst-gate@v1             gate.yml@v1
     (BYO SARIF)                       (scan + then the action)
                │                             │
                └──────────┬──────────────────┘
                           ▼
                    pst-gate decide
                    (Python, same CLI locally)
                           │
                           ▼
              pass / fail + sticky PR comment
              merged.sarif  advisory.md  SBOM  provenance
```

The Python package is the source of truth. The Action installs it from `github.action_path`. The workflow only exists to run scanners with `continue-on-error: true` and then call the Action with `fail-job: false` so artifacts still upload; the last step fails the job on `verdict=fail`.

**KEV vs baseline:** a CVE on the CISA Known Exploited list that you import or ship cannot be silenced by putting the fingerprint in `baseline.json`. Use an exception with an owner and an expiry if the business is accepting it.

**SCA fingerprint:** `sha256(sca|package|CVE)[:16]` — tool name is ignored so two scanners do not create two tickets.

**Provenance:** `out/provenance.json` is an in-toto statement over the SBOM digest. It records the GitHub run id. It is **not** a SLSA Build L3 attestation from a hosted builder.
