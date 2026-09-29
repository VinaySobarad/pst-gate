# Clone-and-run triage cases

These folders are **fixtures**, not live scans. `examples/byo-sarif` stays the empty PASS used by CI. Do not put findings there.

Install the package from the repo root, then:

```bash
# New High → FAIL (exit 1)
pst-gate decide \
  --sarif-dir examples/triage/new-high/reports \
  --baseline examples/triage/new-high/security/baseline.json \
  --exceptions examples/triage/new-high/security/exceptions.yml \
  --policy examples/triage/new-high/security/policy.yml \
  --codeowners examples/triage/new-high/CODEOWNERS \
  --scan-root examples/triage/new-high \
  --out-dir out/triage-new-high \
  --today 2026-09-28

# Same High already in baseline → PASS (exit 0)
pst-gate decide \
  --sarif-dir examples/triage/in-baseline/reports \
  --baseline examples/triage/in-baseline/security/baseline.json \
  --exceptions examples/triage/in-baseline/security/exceptions.yml \
  --policy examples/triage/in-baseline/security/policy.yml \
  --codeowners examples/triage/in-baseline/CODEOWNERS \
  --scan-root examples/triage/in-baseline \
  --out-dir out/triage-in-baseline \
  --today 2026-09-28

# KEV CVE in baseline, package is a direct dep → FAIL (exit 1)
pst-gate decide \
  --sarif-dir examples/triage/kev-in-baseline/reports \
  --baseline examples/triage/kev-in-baseline/security/baseline.json \
  --exceptions examples/triage/kev-in-baseline/security/exceptions.yml \
  --policy examples/triage/kev-in-baseline/security/policy.yml \
  --codeowners examples/triage/kev-in-baseline/CODEOWNERS \
  --scan-root examples/triage/kev-in-baseline \
  --kev examples/triage/kev-in-baseline/kev.json \
  --out-dir out/triage-kev \
  --today 2026-09-28
```
