from __future__ import annotations

import json
from pathlib import Path


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {str(item) for item in data}
    fingerprints = data.get("fingerprints") or []
    return {str(item) for item in fingerprints}


def dump_baseline(fingerprints: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "version": 1,
        "fingerprints": sorted(set(fingerprints)),
    }
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
