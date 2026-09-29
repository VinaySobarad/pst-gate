from datetime import date
from pathlib import Path

from pst_gate.cli import main
from pst_gate.decide import decide
from pst_gate.fingerprint import fingerprint
from pst_gate.policy import load_policy
from tests.conftest import write_sarif


def load_test_policy(tmp_path: Path):
    policy_file = tmp_path / "policy.yml"
    policy_file.write_text("fail_on: high\nignore_unreachable_sca: true\n", encoding="utf-8")
    return load_policy(policy_file)


def run_gate(tmp_path: Path, **kwargs):
    defaults = dict(
        sarif_dir=tmp_path / "sarif",
        baseline_path=tmp_path / "baseline.json",
        exceptions_path=tmp_path / "exceptions.yml",
        policy=load_test_policy(tmp_path),
        codeowners_path=tmp_path / "CODEOWNERS",
        scan_root=tmp_path,
        sbom_path=None,
        today=date(2026, 9, 28),
    )
    defaults.update(kwargs)
    (tmp_path / "sarif").mkdir(exist_ok=True)
    if not defaults["codeowners_path"].exists():
        defaults["codeowners_path"].write_text("* @platform\n", encoding="utf-8")
    if not defaults["exceptions_path"].exists():
        defaults["exceptions_path"].write_text("exceptions: []\n", encoding="utf-8")
    return decide(**defaults)


def test_new_high_fails(tmp_path: Path):
    write_sarif(
        tmp_path / "sarif" / "s.sarif",
        tool="semgrep",
        rule_id="python.sql-injection",
        uri="app/db.py",
        message="SQL injection",
        security_severity="8.1",
    )
    decision = run_gate(tmp_path)
    assert decision.verdict == "fail"
    assert decision.blocking[0].status == "block"
    assert decision.blocking[0].owner == "@platform"


def test_baseline_does_not_fail(tmp_path: Path):
    write_sarif(
        tmp_path / "sarif" / "s.sarif",
        tool="semgrep",
        rule_id="python.sql-injection",
        uri="app/db.py",
        message="SQL injection",
        security_severity="8.1",
    )
    finding_id = fingerprint("semgrep", "python.sql-injection", "app/db.py")
    (tmp_path / "baseline.json").write_text(
        '{"fingerprints": ["' + finding_id + '"]}', encoding="utf-8"
    )
    decision = run_gate(tmp_path)
    assert decision.verdict == "pass"
    assert decision.findings[0].status == "baseline"


def test_owned_exception_passes_until_expiry(tmp_path: Path):
    write_sarif(
        tmp_path / "sarif" / "s.sarif",
        tool="semgrep",
        rule_id="python.sql-injection",
        uri="app/db.py",
        message="SQL injection",
        security_severity="8.1",
    )
    finding_id = fingerprint("semgrep", "python.sql-injection", "app/db.py")
    (tmp_path / "exceptions.yml").write_text(
        f"""
exceptions:
  - fingerprint: {finding_id}
    owner: "@payments"
    reason: "hotfix window; PAY-12"
    expires: "2026-10-01"
""",
        encoding="utf-8",
    )
    still_valid = run_gate(tmp_path, today=date(2026, 9, 28))
    assert still_valid.verdict == "pass"
    assert still_valid.findings[0].status == "accepted"
    expired = run_gate(tmp_path, today=date(2026, 10, 2))
    assert expired.verdict == "fail"
    assert expired.findings[0].status == "expired_exception"


def test_unreachable_sca_does_not_fail(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import flask\n", encoding="utf-8")
    write_sarif(
        tmp_path / "sarif" / "t.sarif",
        tool="trivy",
        rule_id="CVE-2021-99999",
        uri="requirements.txt",
        message="left-pad (1.0.0)",
        package="left-pad",
        security_severity="9.9",
    )
    decision = run_gate(tmp_path)
    assert decision.verdict == "pass"
    assert decision.findings[0].status == "unreachable"


def test_direct_sca_does_fail(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    write_sarif(
        tmp_path / "sarif" / "t.sarif",
        tool="trivy",
        rule_id="CVE-2023-11111",
        uri="requirements.txt",
        message="requests (2.0.0)",
        package="requests",
        security_severity="9.1",
    )
    decision = run_gate(tmp_path)
    assert decision.verdict == "fail"
    assert decision.findings[0].kind == "sca"


def test_cli_writes_advisory_and_exit_code(tmp_path: Path):
    sarif = tmp_path / "sarif"
    sarif.mkdir()
    write_sarif(
        sarif / "s.sarif",
        tool="semgrep",
        rule_id="python.sql-injection",
        uri="app/db.py",
        message="SQL injection",
        security_severity="8.1",
    )
    (tmp_path / "security").mkdir()
    (tmp_path / "security" / "baseline.json").write_text(
        '{"fingerprints": []}', encoding="utf-8"
    )
    (tmp_path / "security" / "exceptions.yml").write_text(
        "exceptions: []\n", encoding="utf-8"
    )
    (tmp_path / "security" / "policy.yml").write_text("fail_on: high\n", encoding="utf-8")
    exit_code = main(
        [
            "decide",
            "--sarif-dir",
            str(sarif),
            "--baseline",
            str(tmp_path / "security" / "baseline.json"),
            "--exceptions",
            str(tmp_path / "security" / "exceptions.yml"),
            "--policy",
            str(tmp_path / "security" / "policy.yml"),
            "--scan-root",
            str(tmp_path),
            "--out-dir",
            str(tmp_path / "out"),
            "--today",
            "2026-09-28",
        ]
    )
    assert exit_code == 1
    assert "FAIL" in (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "advisory" in (tmp_path / "out" / "advisory.md").read_text(encoding="utf-8").lower()
