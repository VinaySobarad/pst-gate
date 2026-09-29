# Contributing

1. `python3 -m pip install -e ".[dev]"`
2. `ruff check src tests`
3. `pytest -q`
4. Do not add scanner-only YAML without a test in `tests/` for the decision.

The reusable workflow must keep `fail-job: false` on the Action so SARIF/SBOM still upload; the last step of `gate.yml` enforces the verdict.
