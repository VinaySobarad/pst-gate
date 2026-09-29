from pathlib import Path

import pytest

from pst_gate.validate import PolicyError, validate_files


def test_bad_exception_fails_validate(tmp_path: Path):
    (tmp_path / "ex.yml").write_text(
        "exceptions:\n  - fingerprint: nope\n    owner: x\n    reason: x\n    expires: no\n",
        encoding="utf-8",
    )
    (tmp_path / "base.json").write_text('{"fingerprints": []}\n', encoding="utf-8")
    with pytest.raises(PolicyError):
        validate_files(None, tmp_path / "ex.yml", tmp_path / "base.json")


def test_ok_files(tmp_path: Path):
    (tmp_path / "ex.yml").write_text("exceptions: []\n", encoding="utf-8")
    (tmp_path / "base.json").write_text('{"fingerprints": []}\n', encoding="utf-8")
    (tmp_path / "policy.yml").write_text("fail_on: high\n", encoding="utf-8")
    validate_files(tmp_path / "policy.yml", tmp_path / "ex.yml", tmp_path / "base.json")
