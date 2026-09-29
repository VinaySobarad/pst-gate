# Example app the gate runs against (same repo CI).

Copy `.github/workflows/security.yml` into **your** repository. GitHub will not run workflows from this folder.

What this app is: HMAC verification of a billing webhook, secret from the environment, private S3 sidecar for scanners.

Prove the gate locally (from the pst-gate repo root):

```bash
pip install -e ".[dev]"
pytest -q
```

`tests/test_decide.py` is the loop: new High fails, baseline passes, owned expiry passes, expired exception fails, unreachable SCA does not fail.
