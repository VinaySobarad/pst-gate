from pathlib import Path

from pst_gate.reachability import is_reachable


def test_direct_requirement_is_reachable(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert is_reachable("requests", tmp_path) is True
    assert is_reachable("left-pad", tmp_path) is False


def test_imported_transitive_counts(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("myapp==1.0\n", encoding="utf-8")
    (tmp_path / "svc.py").write_text("import urllib3\n", encoding="utf-8")
    assert is_reachable("urllib3", tmp_path) is True


def test_package_json_direct_dep(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "4.17.21"}}', encoding="utf-8"
    )
    assert is_reachable("lodash", tmp_path) is True
    assert is_reachable("left-pad", tmp_path) is False
