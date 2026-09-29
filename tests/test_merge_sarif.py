from pathlib import Path

from pst_gate.merge_sarif import merge_sarif_files
from tests.conftest import write_sarif


def test_merge_two_runs(tmp_path: Path):
    write_sarif(
        tmp_path / "a.sarif",
        tool="semgrep",
        rule_id="r1",
        uri="a.py",
        message="a",
    )
    write_sarif(
        tmp_path / "b.sarif",
        tool="trivy",
        rule_id="CVE-1",
        uri="req.txt",
        message="b",
        package="x",
    )
    merged = merge_sarif_files([tmp_path / "a.sarif", tmp_path / "b.sarif"])
    assert len(merged["runs"]) == 1
    assert len(merged["runs"][0]["results"]) == 2
