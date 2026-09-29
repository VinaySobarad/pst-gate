from __future__ import annotations

import hashlib
import re
from urllib.parse import unquote


def normalize_path(uri: str) -> str:
    """Turn SARIF URIs into repo-relative POSIX paths."""
    normalized = unquote((uri or "").replace("\\", "/"))
    normalized = re.sub(r"^file://(localhost)?", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"^[A-Za-z]:/", "", normalized)
    for marker in (
        "/github/workspace/",
        "/home/runner/work/",
        "/actions/runner/_work/",
    ):
        if marker in normalized:
            rest = normalized.split(marker, 1)[1]
            parts = rest.split("/")
            if len(parts) >= 3:
                return "/".join(parts[2:])
            return rest
    return normalized.lstrip("./").lstrip("/")


def fingerprint(
    tool: str,
    rule_id: str,
    path: str,
    package: str | None = None,
    cve: str | None = None,
) -> str:
    """Stable id. SCA collapses across tools (Trivy + Snyk on the same CVE)."""
    package_name = (package or "").lower().strip()
    cve_id = (cve or "").upper().strip()
    if package_name and cve_id.startswith("CVE-"):
        key = f"sca|{package_name}|{cve_id}"
    else:
        key = "|".join(
            [
                (tool or "unknown").lower().strip(),
                (rule_id or "unknown").lower().strip(),
                normalize_path(path).lower(),
                package_name,
                cve_id.lower(),
            ]
        )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
