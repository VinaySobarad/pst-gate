from datetime import date
from pathlib import Path

from pst_gate.exceptions import exception_state, load_exceptions
from pst_gate.models import ExceptionRow


def test_valid_exception_until_expiry(tmp_path: Path):
    (tmp_path / "ex.yml").write_text(
        """
exceptions:
  - fingerprint: abcdef1234567890
    owner: "@payments"
    reason: "vendor patch in 3.2.1; JIRA PAY-9"
    expires: "2026-12-01"
""",
        encoding="utf-8",
    )
    rows = load_exceptions(tmp_path / "ex.yml")
    row = rows["abcdef1234567890"]
    assert exception_state(row, date(2026, 9, 28)) == "accepted"
    assert exception_state(row, date(2026, 12, 2)) == "expired_exception"


def test_missing_owner_is_invalid():
    row = ExceptionRow(fingerprint="x", owner="", reason="later", expires="2026-12-01")
    assert exception_state(row, date(2026, 9, 28)) is None
