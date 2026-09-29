from __future__ import annotations

from pathlib import Path

import yaml

from pst_gate.models import Policy


def load_policy(path: Path | None) -> Policy:
    if path is None or not path.exists():
        return Policy()
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sla_days = payload.get("sla_days") or {}
    policy = Policy(
        fail_on=str(payload.get("fail_on") or "high").lower(),
        ignore_unreachable_sca=bool(payload.get("ignore_unreachable_sca", True)),
        annotate_ai_touch=bool(payload.get("annotate_ai_touch", True)),
        block_kev=bool(payload.get("block_kev", True)),
    )
    for severity_name, days in sla_days.items():
        try:
            policy.sla_days[str(severity_name).lower()] = int(days)
        except (TypeError, ValueError):
            continue
    if policy.fail_on not in {"critical", "high", "medium", "low", "info"}:
        policy.fail_on = "high"
    return policy
