# Bring-your-own SARIF

If scanners already run in your pipeline, do not copy the reusable workflow. Pin the **composite action** and point it at the SARIF directory.

```yaml
- uses: VinaySobarad/pst-gate@v1
  with:
    sarif-dir: reports
    fail-on: high
```

`reports/empty.sarif` is a valid empty document so CI in this repo can prove `pst-gate decide` on this folder exits 0.
