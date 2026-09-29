from __future__ import annotations

import json
from pathlib import Path


def write_sarif(
    path: Path,
    *,
    tool: str,
    rule_id: str,
    uri: str,
    level: str = "error",
    message: str = "finding",
    line: int = 10,
    security_severity: str | None = None,
    package: str | None = None,
    extra_rule: str | None = None,
) -> None:
    result = {
        "ruleId": extra_rule or rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
        "properties": {},
    }
    if security_severity:
        result["properties"]["security-severity"] = security_severity
    if package:
        result["properties"]["package"] = package
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "rules": [{"id": extra_rule or rule_id}]}},
                "results": [result],
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
