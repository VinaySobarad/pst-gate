from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_PURL_NAME = re.compile(r"pkg:[^/]+/(?:%40[^/]+/)?([^@/?]+)", re.I)


def summarize_sbom(path: Path | None) -> dict[str, Any]:
    empty: dict[str, Any] = {
        "present": False,
        "format": None,
        "components": 0,
        "name": None,
        "packages": [],
    }
    if path is None or not path.exists():
        return empty
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    if not isinstance(payload, dict):
        return empty
    components = payload.get("components") or []
    packages = sorted(_component_names(components)) if isinstance(components, list) else []
    bom_format = payload.get("bomFormat") or (
        "CycloneDX" if payload.get("specVersion") else None
    )
    metadata = payload.get("metadata") or {}
    name = (metadata.get("component") or {}).get("name") or path.name
    return {
        "present": True,
        "format": bom_format or "CycloneDX",
        "components": len(components) if isinstance(components, list) else 0,
        "name": name,
        "path": str(path),
        "packages": packages,
    }


def _component_names(components: list) -> set[str]:
    names: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            continue
        if component.get("name"):
            names.add(str(component["name"]).lower().replace("_", "-"))
        purl = str(component.get("purl") or "")
        purl_match = _PURL_NAME.search(purl)
        if purl_match:
            names.add(purl_match.group(1).lower().replace("_", "-"))
    return names


def package_in_sbom(package: str | None, sbom: dict[str, Any]) -> bool | None:
    if not package or not sbom.get("present"):
        return None
    package_name = package.lower().replace("_", "-")
    return package_name in set(sbom.get("packages") or [])
