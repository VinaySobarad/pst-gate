from datetime import date
from pathlib import Path

from pst_gate.decide import decide
from pst_gate.fingerprint import fingerprint
from pst_gate.policy import load_policy
from tests.conftest import write_sarif


def test_kev_blocks_even_when_in_baseline(tmp_path: Path):
    write_sarif(
        tmp_path / "sarif" / "t.sarif",
        tool="trivy",
        rule_id="CVE-2023-11111",
        uri="requirements.txt",
        message="requests (2.0.0)",
        package="requests",
        security_severity="9.1",
    )
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    finding_id = fingerprint(
        "trivy", "CVE-2023-11111", "requirements.txt", "requests", "CVE-2023-11111"
    )
    (tmp_path / "baseline.json").write_text(
        '{"fingerprints": ["' + finding_id + '"]}', encoding="utf-8"
    )
    (tmp_path / "kev.json").write_text(
        '{"cves": ["CVE-2023-11111"]}', encoding="utf-8"
    )
    (tmp_path / "exceptions.yml").write_text("exceptions: []\n", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @platform\n", encoding="utf-8")
    policy = load_policy(None)
    decision = decide(
        sarif_dir=tmp_path / "sarif",
        baseline_path=tmp_path / "baseline.json",
        exceptions_path=tmp_path / "exceptions.yml",
        policy=policy,
        codeowners_path=tmp_path / "CODEOWNERS",
        scan_root=tmp_path,
        sbom_path=None,
        today=date(2026, 9, 28),
        kev_path=tmp_path / "kev.json",
    )
    assert decision.findings[0].kev is True
    assert decision.verdict == "fail"
    assert decision.blocking[0].status == "block"


def test_kev_unreachable_does_not_fail(tmp_path: Path):
    write_sarif(
        tmp_path / "sarif" / "t.sarif",
        tool="trivy",
        rule_id="CVE-2021-44228",
        uri="requirements.txt",
        message="left-pad (1.0.0)",
        package="left-pad",
        security_severity="10.0",
    )
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "kev.json").write_text('{"cves": ["CVE-2021-44228"]}', encoding="utf-8")
    (tmp_path / "exceptions.yml").write_text("exceptions: []\n", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @platform\n", encoding="utf-8")
    decision = decide(
        sarif_dir=tmp_path / "sarif",
        baseline_path=tmp_path / "baseline.json",
        exceptions_path=tmp_path / "exceptions.yml",
        policy=load_policy(None),
        codeowners_path=tmp_path / "CODEOWNERS",
        scan_root=tmp_path,
        sbom_path=None,
        today=date(2026, 9, 28),
        kev_path=tmp_path / "kev.json",
    )
    assert decision.verdict == "pass"
    assert decision.findings[0].kev is True
    assert decision.findings[0].status == "unreachable"
