from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml

from pst_gate.models import ExceptionRow


def load_exceptions(path: Path) -> dict[str, ExceptionRow]:
    if not path.exists():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows = payload.get("exceptions") or []
    by_fingerprint: dict[str, ExceptionRow] = {}
    for raw in rows:
        fingerprint_id = str(raw.get("fingerprint") or "").strip()
        owner = str(raw.get("owner") or "").strip()
        reason = str(raw.get("reason") or "").strip()
        expires = str(raw.get("expires") or "").strip()
        if not fingerprint_id:
            continue
        sla_raw = raw.get("sla_days")
        try:
            sla_days = int(sla_raw) if sla_raw is not None else None
        except (TypeError, ValueError):
            sla_days = None
        by_fingerprint[fingerprint_id] = ExceptionRow(
            fingerprint=fingerprint_id,
            owner=owner,
            reason=reason,
            expires=expires,
            sla_days=sla_days,
        )
    return by_fingerprint


def exception_state(row: ExceptionRow | None, today: date) -> str | None:
    """Return 'accepted', 'expired_exception', or None (no row / invalid)."""
    if row is None:
        return None
    if not row.owner or not row.reason or not row.expires:
        return None
    try:
        expires_on = date.fromisoformat(row.expires)
    except ValueError:
        return None
    if today <= expires_on:
        return "accepted"
    return "expired_exception"
