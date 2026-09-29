from __future__ import annotations

import fnmatch
from pathlib import Path


def load_codeowners(path: Path) -> list[tuple[str, str]]:
    """(pattern, owners) in file order. GitHub: last match wins."""
    if not path.exists():
        return []
    rules: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        rules.append((parts[0], " ".join(parts[1:])))
    return rules


def owner_for(rel_path: str, rules: list[tuple[str, str]]) -> str:
    path = rel_path.replace("\\", "/").lstrip("./").lstrip("/")
    matched = "unassigned"
    for pattern, owners in rules:
        if _pattern_matches(path, pattern):
            matched = owners
    return matched


def _pattern_matches(path: str, pattern: str) -> bool:
    stripped = pattern.strip()
    anchored = stripped.startswith("/")
    if anchored:
        stripped = stripped[1:]
    if stripped.endswith("/"):
        prefix = stripped
        if anchored:
            return path == stripped.rstrip("/") or path.startswith(prefix)
        return path.startswith(prefix) or f"/{prefix}" in f"/{path}/"
    if "/" not in stripped:
        return fnmatch.fnmatch(path, stripped) or fnmatch.fnmatch(Path(path).name, stripped)
    if anchored:
        return fnmatch.fnmatch(path, stripped)
    return fnmatch.fnmatch(path, stripped) or fnmatch.fnmatch(path, "*/" + stripped)
