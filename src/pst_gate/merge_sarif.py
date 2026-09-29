from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def merge_sarif_files(paths: list[Path]) -> dict[str, Any]:
    """Combine SARIF runs into one document for the GitHub Security tab."""
    runs: list[Any] = []
    for path in paths:
        if not path.exists():
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(document, dict):
            runs.extend(document.get("runs") or [])
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": runs,
    }


def merge_sarif_dir(sarif_dir: Path, dest: Path) -> Path:
    files = sorted(sarif_dir.glob("*.sarif")) if sarif_dir.is_dir() else [sarif_dir]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(merge_sarif_files(files), indent=2) + "\n", encoding="utf-8")
    return dest
