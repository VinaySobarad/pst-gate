from pathlib import Path

from pst_gate.owners import load_codeowners, owner_for


def test_last_match_wins(tmp_path: Path):
    (tmp_path / "CODEOWNERS").write_text(
        "* @default\n/app/ @payments\n*.tf @platform\n",
        encoding="utf-8",
    )
    rules = load_codeowners(tmp_path / "CODEOWNERS")
    assert owner_for("README.md", rules) == "@default"
    assert owner_for("app/main.py", rules) == "@payments"
    assert owner_for("infra/s3.tf", rules) == "@platform"
