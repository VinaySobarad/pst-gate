# pst-gate

## What this is

When developers change code, they open a **pull request** (a proposed change). Companies often run **security scanners** on that change — programs that look for bugs like SQL injection or known-bad libraries.

Those scanners produce a pile of alerts. **pst-gate does not find the bugs.** It reads the alerts and answers one question:

> **Is this change allowed to merge, or should CI fail?**

That yes/no is the whole product. You add it to GitHub Actions (the CI GitHub runs on every pull request). Rules live in **your** repository (`security/policy.yml`), not inside this tool.

Think: the scanners are a metal detector. This is the person who decides whether you can board.

---

## Why we built it

Scanners already exist (Semgrep, Trivy, Snyk, Gitleaks, and others). The mess is **what happens after** they finish.

- If **every** serious alert fails the build, the job is red forever and someone **turns the check off**.
- If the scan is allowed to fail silently (`|| true` in a script), it runs and **nobody uses it**.
- Old alerts fail **every new pull request**, even when this change did not introduce them.
- “We’ll fix it later” has **no owner and no end date**.
- Library scanners yell about packages the app **does not even use**.
- A vulnerability that is **actively exploited in the wild** gets filed under “we already knew.”

pst-gate is the middle:

- **New** serious alerts → fail the pull request  
- **Old** alerts you already recorded → do not fail (they still show up)  
- Temporary “allow this” rules need a **person**, a **reason**, and an **expiry date**  
- Actively exploited issues you actually use → **still fail**, even if they were on the old list  

---

## Words used in this README

You can skip this if you already work in AppSec. Otherwise, read it once.

| Word | Plain meaning |
|------|----------------|
| **CI / GitHub Actions** | Automatic checks GitHub runs on a pull request. A “red” job blocks merge if you require it. |
| **Scanner** | A tool that *finds* issues (Semgrep for code, Trivy/Snyk for libraries, Gitleaks for secrets). |
| **SARIF** | A JSON report format scanners write. pst-gate reads `*.sarif` files. |
| **Finding / alert** | One issue in that report (e.g. “SQL injection in `app/db.py`”). |
| **High / Critical** | How serious the scanner says it is. This project can fail the job on High and above. |
| **SAST** | “Bug in *your* source code.” |
| **SCA** | “Bug in a *library you depend on*” (a CVE). |
| **CVE** | Public ID for a known vulnerability, like `CVE-2023-11111`. |
| **CISA KEV** | A US list of CVEs known to be exploited in the wild. |
| **Baseline** | A list of fingerprints for alerts you already accepted as “known, not failing this PR.” |
| **Fingerprint** | A short id so the same bug is recognized next time. |
| **Exception / waiver** | A time-boxed “allow this anyway,” with an owner. |
| **SBOM** | A list of packages you *ship*. If a CVE is in that list, we treat it as in use. |
| **CODEOWNERS** | A GitHub file that maps files to a team (`@payments`). |
| **Exit code** | What a program returns: **0** = pass, **1** = fail, **2** = your config files are invalid. |

---

## What runs (the technical picture)

`pst-gate` is a Python command-line tool (`pst-gate decide`) packaged as a **composite GitHub Action** (a reusable CI step other repos can pin).

1. Scanners run **fail-open**: they write reports even if they crash. They must **not** be the thing that fails the job.
2. They write `*.sarif` into a folder (usually `reports/`).
3. `pst-gate decide` reads that folder plus:
   - `security/policy.yml` — how strict to be  
   - `security/baseline.json` — known fingerprints  
   - `security/exceptions.yml` — temporary waivers  
   - `CODEOWNERS` — whose name goes on the row  
4. It writes `out/report.md` (human), `out/decision.json` (machine), and can post **one** sticky comment on the PR (updated in place, not a new comment every run).
5. Exit **0** pass, **1** fail, **2** broken policy/exception YAML.

The code under `src/pst_gate/` **is** the product. Workflow YAML only starts it.

### How one finding is classified

In order:

| Status | Result |
|--------|--------|
| Waiver expired | **fail** |
| Valid waiver (owner + date still in the future) | pass |
| On CISA KEV **and** you use or ship that package | **fail** (baseline cannot hide it) |
| SCA package not imported, not a direct dependency, not in the SBOM | pass (`unreachable` — noise) |
| Below your bar (e.g. Medium when you fail on High) | pass |
| Fingerprint already in `baseline.json` | pass (still shown) |
| New High or Critical | **fail** |

SAST fingerprints = scanner + rule + file path.  
SCA fingerprints = **package + CVE** (Trivy and Snyk on the same CVE count as **one**).

---

## Run it on your laptop

**Need:** Python **3.11 or newer**. **No API keys. No `.env` file.** (GitHub secrets are only for CI; see below.)

```bash
git clone https://github.com/VinaySobarad/pst-gate.git
cd pst-gate
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
ruff check src tests               # style check
pytest -q                          # 27 tests; this is the proof
pst-gate validate \
  --policy security/policy.yml \
  --exceptions security/exceptions.yml \
  --baseline security/baseline.json
```

`validate` printing `ok` means your policy files are well-formed. It does not mean the repo is free of bugs.

### Three demos (checked-in reports, not live scans)

Full commands: [`examples/triage/README.md`](examples/triage/README.md). Short version:

```bash
# New High → FAIL (exit code 1)
pst-gate decide \
  --sarif-dir examples/triage/new-high/reports \
  --baseline examples/triage/new-high/security/baseline.json \
  --exceptions examples/triage/new-high/security/exceptions.yml \
  --policy examples/triage/new-high/security/policy.yml \
  --codeowners examples/triage/new-high/CODEOWNERS \
  --scan-root examples/triage/new-high \
  --out-dir out/triage-new-high \
  --today 2026-09-28
```

Example output:

```markdown
## pst-gate — FAIL

| Sev  | OWASP              | Owner     | Path           | Rule                   | Why |
|------|--------------------|-----------|----------------|------------------------|-----|
| high | A03:2021 Injection | @platform | `app/db.py:10` | `python.sql-injection` | new |
```

Same High, fingerprint already in baseline → **PASS** (exit 0): use `examples/triage/in-baseline`.  
KEV CVE in baseline but the package is in `requirements.txt` → **FAIL**: use `examples/triage/kev-in-baseline` and pass `--kev …/kev.json`.

| What you try | Expected |
|--------------|----------|
| New High | **fail** |
| Same finding in baseline | **pass** |
| Waiver with owner + future expiry | **pass** |
| Same waiver after the date | **fail** |
| Critical CVE in a library you don’t use | **pass** (`unreachable`) |
| Same CVE in `requirements.txt` or SBOM | **fail** |
| KEV CVE in baseline, but you use it | **fail** |
| Trivy + Snyk, same package+CVE | **one** fingerprint |

Empty report must pass: [`examples/byo-sarif`](examples/byo-sarif) (CI uses this).

---

## Put it on GitHub (your other repo)

Pin a **tag or commit SHA** (`@v1`). Do not use `@main` (it moves).

### 1. Add three files plus CODEOWNERS

```yaml
# security/policy.yml
fail_on: high
ignore_unreachable_sca: true
annotate_ai_touch: true
block_kev: true
sla_days:
  critical: 7
  high: 14
```

```json
{ "version": 1, "fingerprints": [] }
```

```yaml
# security/exceptions.yml
exceptions: []
```

```text
# CODEOWNERS
* @your-team
```

### 2. You already run scanners (recommended)

Copy [`examples/byo-sarif/.github/workflows/security.yml`](examples/byo-sarif/.github/workflows/security.yml) into **your** `.github/workflows/` (GitHub ignores workflows that live only under `examples/`).

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
      # your scanners write reports/*.sarif — do not fail the job here
      - uses: VinaySobarad/pst-gate@v1
        with:
          sarif-dir: reports
          fail-on: high
```

### 3. You have no scanners yet

Copy [`examples/consumer/.github/workflows/security.yml`](examples/consumer/.github/workflows/security.yml). That calls this repo’s reusable workflow: Semgrep, Trivy, Gitleaks, optional Snyk, SBOM, KEV download, then the same decide step.

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

More paste: [`docs/adopt.md`](docs/adopt.md). Diagram: [`docs/architecture.md`](docs/architecture.md).

---

## Environment variables and secrets

**On your laptop: none.** The CLI does not load `.env`. [`.env.example`](.env.example) is comments only.

| Name | Where | Required? | What it is for |
|------|--------|-----------|----------------|
| *(nothing)* | laptop | — | `decide`, `validate`, `pytest` |
| `GITHUB_TOKEN` | GitHub Actions (automatic) | for PR comments | one sticky comment |
| `SNYK_TOKEN` | GitHub **secret** | no | optional `snyk test` in `gate.yml`. Unset → Snyk skipped; Trivy still runs |
| `WEBHOOK_SECRET` / `PORT` | example app only | no | running [`examples/consumer`](examples/consumer) locally |

Set `SNYK_TOKEN` in the **consuming** repo: Settings → Secrets and variables → Actions. Never commit tokens.

---

## Temporary exceptions

```yaml
exceptions:
  - fingerprint: "a1b2c3d4e5f60789"
    owner: "@payments"
    reason: "Vendor fix in 3.2.1; PAY-441"
    expires: "2026-12-01"
```

`pst-gate promote-baseline` copies fingerprints from a decision into `baseline.json`. Only do that after a human reviewed the report.

---

## What is in this repository

| Path | Role |
|------|------|
| `src/pst_gate/` | The gate (Python). |
| `action.yml` | What other repos pin: install the package, run `decide`. |
| `.github/workflows/gate.yml` | Optional full pipeline (scanners + decide). |
| `.github/workflows/ci.yml` | Tests **this** repo. |
| `tests/` | pytest — if this fails, do not trust the README. |
| `examples/triage/` | Three reports you can run without GitHub. |
| `examples/byo-sarif/` | “I already scan; only pin the Action.” |
| `examples/consumer/` | Tiny sample app + full workflow to copy. |

---

## What this will not do

- **Full program analysis** of “is this line reachable?” — it checks imports, direct dependencies, and SBOM names, not a CodeQL-style graph.
- **DAST** (attacking a running website in CI).
- **SLSA Build L3** (a strong build attestation). `out/provenance.json` is a statement about the SBOM in this GitHub job, and the file says it is not L3.

Third-party Actions here are **pinned to full commit SHAs**. Dependabot opens PRs when they move.

The tests in `tests/test_decide.py` and `tests/test_kev.py` are the contract. If they fail, this is only a scanner demo.
