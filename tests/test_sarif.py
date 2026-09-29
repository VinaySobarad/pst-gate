from pathlib import Path

from pst_gate.owasp import map_owasp
from pst_gate.sarif import load_sarif_dir
from tests.conftest import write_sarif


def test_parse_semgrep_and_trivy(tmp_path: Path):
    write_sarif(
        tmp_path / "semgrep.sarif",
        tool="semgrep",
        rule_id="python.sql-injection",
        uri="app/db.py",
        message="Possible SQL injection",
        security_severity="8.5",
    )
    write_sarif(
        tmp_path / "trivy.sarif",
        tool="trivy",
        rule_id="CVE-2023-12345",
        uri="requirements.txt",
        message="requests (2.0.0)",
        package="requests",
        security_severity="9.8",
    )
    findings = load_sarif_dir(tmp_path)
    assert len(findings) == 2
    sast = next(finding for finding in findings if finding.kind == "sast")
    sca = next(finding for finding in findings if finding.kind == "sca")
    assert sast.severity == "high"
    assert sca.severity == "critical"
    assert sca.cve == "CVE-2023-12345"
    assert sast.owasp.startswith("A03")


def test_owasp_llm_rule():
    assert "LLM01" in map_owasp("ai.prompt-injection", "unsanitized prompt", "sast")
