from __future__ import annotations

import json
from pathlib import Path


def load_kev(path: Path | None) -> set[str]:
    """Load CISA KEV JSON (or a {\"cves\": [...]} stub). Returns CVE-IDs uppercased."""
    if path is None or not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    cve_ids: set[str] = set()
    if isinstance(payload, dict):
        for row in payload.get("vulnerabilities") or []:
            if isinstance(row, dict) and row.get("cveID"):
                cve_ids.add(str(row["cveID"]).upper())
        for cve_id in payload.get("cves") or []:
            cve_ids.add(str(cve_id).upper())
    elif isinstance(payload, list):
        for cve_id in payload:
            cve_ids.add(str(cve_id).upper())
    return {cve_id for cve_id in cve_ids if cve_id.startswith("CVE-")}
