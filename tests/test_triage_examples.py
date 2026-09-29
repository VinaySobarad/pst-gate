import json
from pathlib import Path

from pst_gate.cli import main
from pst_gate.fingerprint import fingerprint

REPO_ROOT = Path(__file__).resolve().parents[1]
TRIAGE_ROOT = REPO_ROOT / "examples" / "triage"
SAST_FINGERPRINT = fingerprint("semgrep", "python.sql-injection", "app/db.py")
SCA_FINGERPRINT = fingerprint(
    "trivy", "CVE-2023-11111", "requirements.txt", "requests", "CVE-2023-11111"
)


def decide_example(folder_name: str, out_dir: Path, *, kev: bool = False) -> int:
    folder = TRIAGE_ROOT / folder_name
    arguments = [
        "decide",
        "--sarif-dir",
        str(folder / "reports"),
        "--baseline",
        str(folder / "security" / "baseline.json"),
        "--exceptions",
        str(folder / "security" / "exceptions.yml"),
        "--policy",
        str(folder / "security" / "policy.yml"),
        "--codeowners",
        str(folder / "CODEOWNERS"),
        "--scan-root",
        str(folder),
        "--out-dir",
        str(out_dir),
        "--today",
        "2026-09-28",
    ]
    if kev:
        arguments.extend(["--kev", str(folder / "kev.json")])
    return main(arguments)


def load_decision(out_dir: Path) -> dict:
    return json.loads((out_dir / "decision.json").read_text(encoding="utf-8"))


def baseline_fingerprints(folder_name: str) -> list[str]:
    payload = json.loads(
        (TRIAGE_ROOT / folder_name / "security" / "baseline.json").read_text(encoding="utf-8")
    )
    return payload["fingerprints"]


def test_example_new_high_fails(tmp_path: Path):
    out_dir = tmp_path / "out"
    exit_code = decide_example("new-high", out_dir)
    decision = load_decision(out_dir)
    finding = decision["findings"][0]
    assert exit_code == 1
    assert decision["verdict"] == "fail"
    assert len(decision["findings"]) == 1
    assert finding["status"] == "block"
    assert finding["fingerprint"] == SAST_FINGERPRINT
    assert finding["owner"] == "@platform"
    assert baseline_fingerprints("new-high") == []


def test_example_in_baseline_passes(tmp_path: Path):
    out_dir = tmp_path / "out"
    exit_code = decide_example("in-baseline", out_dir)
    decision = load_decision(out_dir)
    finding = decision["findings"][0]
    assert exit_code == 0
    assert decision["verdict"] == "pass"
    assert len(decision["findings"]) == 1
    assert finding["status"] == "baseline"
    assert finding["fingerprint"] == SAST_FINGERPRINT
    assert SAST_FINGERPRINT in baseline_fingerprints("in-baseline")


def test_example_kev_in_baseline_fails(tmp_path: Path):
    out_dir = tmp_path / "out"
    exit_code = decide_example("kev-in-baseline", out_dir, kev=True)
    decision = load_decision(out_dir)
    finding = decision["findings"][0]
    assert exit_code == 1
    assert decision["verdict"] == "fail"
    assert len(decision["findings"]) == 1
    assert finding["kev"] is True
    assert finding["status"] == "block"
    assert finding["cve"] == "CVE-2023-11111"
    assert finding["fingerprint"] == SCA_FINGERPRINT
    assert SCA_FINGERPRINT in baseline_fingerprints("kev-in-baseline")
