from __future__ import annotations

import ast
import json
import re
from pathlib import Path

_IMPORT_NAMES = {
    "pyyaml": "yaml",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "python-dateutil": "dateutil",
    "scikit-learn": "sklearn",
    "protobuf": "google.protobuf",
    "opencv-python": "cv2",
    "attrs": "attr",
    "psycopg2-binary": "psycopg2",
    "charset-normalizer": "charset_normalizer",
    "pyjwt": "jwt",
}


def _requirement_name(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("-"):
        return None
    stripped = stripped.split(";")[0].strip()
    stripped = re.split(r"[=<>!~\[]", stripped, maxsplit=1)[0].strip()
    stripped = stripped.split("[")[0].strip()
    return stripped.lower().replace("_", "-") if stripped else None


def _pyproject_direct(text: str) -> set[str]:
    names: set[str] = set()
    match = re.search(r"(?ms)^\[project\].*?^dependencies\s*=\s*\[(.*?)\]", text)
    if not match:
        return names
    for quoted, single in re.findall(r'"([^"]+)"|\'([^\']+)\'', match.group(1)):
        name = _requirement_name(quoted or single)
        if name:
            names.add(name)
    return names


def _package_json_direct(path: Path) -> set[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    names: set[str] = set()
    for key in ("dependencies", "optionalDependencies"):
        block = payload.get(key) or {}
        if isinstance(block, dict):
            names.update(str(package_name).lower() for package_name in block)
    return names


def _go_mod_direct(path: Path) -> set[str]:
    names: set[str] = set()
    in_block = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require ") and not stripped.endswith("("):
            parts = stripped.split()
            if len(parts) >= 2:
                names.add(parts[1].lower())
        elif in_block and stripped and not stripped.startswith("//"):
            names.add(stripped.split()[0].lower())
    return names


def direct_packages(root: Path) -> set[str]:
    names: set[str] = set()
    for requirements in root.glob("**/requirements.txt"):
        if any(part in requirements.parts for part in (".venv", "venv", "node_modules")):
            continue
        for line in requirements.read_text(encoding="utf-8", errors="replace").splitlines():
            name = _requirement_name(line)
            if name:
                names.add(name)
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        names |= _pyproject_direct(pyproject.read_text(encoding="utf-8", errors="replace"))
    package_json = root / "package.json"
    if package_json.exists():
        names |= _package_json_direct(package_json)
    go_mod = root / "go.mod"
    if go_mod.exists():
        names |= _go_mod_direct(go_mod)
    return names


def imported_modules(root: Path) -> set[str]:
    modules: set[str] = set()
    for python_file in root.rglob("*.py"):
        if any(part in python_file.parts for part in (".venv", "venv", "node_modules")):
            continue
        try:
            tree = ast.parse(python_file.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
    return {name.lower() for name in modules}


def is_reachable(package: str | None, root: Path) -> bool:
    """Direct requirement or imported module counts as in-use. Transitive-only is noise."""
    if not package:
        return True
    package_name = package.lower().replace("_", "-")
    import_root = _IMPORT_NAMES.get(
        package_name, package_name.replace("-", "_").split(".")[0]
    )
    directs = direct_packages(root)
    normalized_directs = {item.replace("-", "_") for item in directs}
    if package_name in directs or package_name.replace("-", "_") in normalized_directs:
        return True
    if any(
        package_name == item
        or package_name.endswith("/" + item)
        or item.endswith("/" + package_name)
        for item in directs
    ):
        return True
    imports = imported_modules(root)
    return import_root.lower() in imports or package_name.replace("-", "_") in imports
