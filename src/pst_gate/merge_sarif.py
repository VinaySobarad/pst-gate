from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def merge_sarif_files(paths: list[Path]) -> dict[str, Any]:
    """One SARIF run for GitHub code scanning (one category cannot contain multiple runs)."""
    results: list[Any] = []
    rules: list[Any] = []
    seen_rule_ids: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        for run in document.get("runs") or []:
            driver = (run.get("tool") or {}).get("driver") or {}
            for rule in driver.get("rules") or []:
                rule_id = str(rule.get("id") or "")
                if not rule_id or rule_id in seen_rule_ids:
                    continue
                seen_rule_ids.add(rule_id)
                rules.append(rule)
            results.extend(run.get("results") or [])
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "pst-gate", "rules": rules}},
                "results": results,
            }
        ],
    }


def merge_sarif_dir(sarif_dir: Path, dest: Path) -> Path:
    files = sorted(sarif_dir.glob("*.sarif")) if sarif_dir.is_dir() else [sarif_dir]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(merge_sarif_files(files), indent=2) + "\n", encoding="utf-8")
    return dest
