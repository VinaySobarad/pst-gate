from datetime import date
from pathlib import Path

from pst_gate.decide import decide
from pst_gate.policy import load_policy
from tests.conftest import write_sarif


def test_sbom_component_counts_as_shipped(tmp_path: Path):
    write_sarif(
        tmp_path / "sarif" / "t.sarif",
        tool="trivy",
        rule_id="CVE-2024-0001",
        uri="poetry.lock",
        message="orjson (3.0.0)",
        package="orjson",
        security_severity="9.0",
    )
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "sbom.json").write_text(
        '{"bomFormat":"CycloneDX","components":[{"name":"orjson","purl":"pkg:pypi/orjson@3.0.0"}]}',
        encoding="utf-8",
    )
    (tmp_path / "exceptions.yml").write_text("exceptions: []\n", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @platform\n", encoding="utf-8")
    decision = decide(
        sarif_dir=tmp_path / "sarif",
        baseline_path=tmp_path / "baseline.json",
        exceptions_path=tmp_path / "exceptions.yml",
        policy=load_policy(None),
        codeowners_path=tmp_path / "CODEOWNERS",
        scan_root=tmp_path,
        sbom_path=tmp_path / "sbom.json",
        today=date(2026, 9, 28),
    )
    assert decision.findings[0].shipped is True
    assert decision.findings[0].reachable is True
    assert decision.verdict == "fail"
