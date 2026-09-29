from __future__ import annotations

import json
import re
from pathlib import Path

from pst_gate.fingerprint import fingerprint, normalize_path
from pst_gate.models import Finding
from pst_gate.owasp import map_owasp

# SARIF "level" plus CVSS-style numbers in properties.security-severity (GHAS/Trivy).
_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _severity_from_value(raw: str | float | int | None) -> str | None:
    if raw is None or raw == "":
        return None
    try:
        score = float(raw)
    except (TypeError, ValueError):
        name = str(raw).strip().lower()
        if name in {"critical", "high", "medium", "low", "info"}:
            return name
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _tool_name(run: dict) -> str:
    driver = (run.get("tool") or {}).get("driver") or {}
    name = driver.get("name") or "unknown"
    return str(name).split(" ")[0].lower()


def _kind(tool: str, rule_id: str, package: str | None, cve: str | None) -> str:
    rule_lower = (rule_id or "").lower()
    if tool in {"gitleaks", "trufflehog"} or "secret" in rule_lower:
        return "secret"
    if package or cve:
        return "sca"
    if tool in {"trivy", "snyk"} and (
        rule_lower.startswith("cve-") or rule_lower.startswith("ghsa-")
    ):
        return "sca"
    if tool in {"checkov", "tfsec"} or rule_lower.startswith("ckv_"):
        return "iac"
    if tool == "trivy" and ("avd-" in rule_lower or "misconfig" in rule_lower):
        return "iac"
    return "sast"


def _extract_package_and_cve(result: dict, rule_id: str) -> tuple[str | None, str | None]:
    properties = result.get("properties") or {}
    package = properties.get("package") or properties.get("pkg") or None
    cve = properties.get("cve") or None
    cve_match = re.search(r"(CVE-\d{4}-\d+)", rule_id or "", re.I)
    if cve_match:
        cve = cve or cve_match.group(1).upper()
    message = (result.get("message") or {}).get("text") or ""
    if not package:
        package_match = re.search(r"^([A-Za-z0-9_.\-]+)(?:@| )", message)
        if package_match and (cve or "CVE-" in message or "GHSA-" in message):
            package = package_match.group(1)
    return (str(package).lower() if package else None, cve)


def _severity(result: dict, run: dict) -> str:
    properties = result.get("properties") or {}
    for key in ("security-severity", "security_severity", "severity"):
        mapped = _severity_from_value(properties.get(key))
        if mapped:
            return mapped
    level = (result.get("level") or "").lower()
    if level in _LEVEL_TO_SEVERITY:
        return "high" if level == "error" else _LEVEL_TO_SEVERITY[level]
    rule_id = result.get("ruleId")
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    for rule in rules:
        if rule.get("id") != rule_id:
            continue
        default_level = (rule.get("defaultConfiguration") or {}).get("level")
        if default_level:
            return _LEVEL_TO_SEVERITY.get(str(default_level).lower(), "medium")
        rule_properties = rule.get("properties") or {}
        mapped = _severity_from_value(rule_properties.get("security-severity"))
        if mapped:
            return mapped
    return "medium"


def _location(result: dict) -> tuple[str, int]:
    locations = result.get("locations") or [{}]
    physical = locations[0].get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri") or ""
    start_line = (physical.get("region") or {}).get("startLine") or 0
    try:
        start_line = int(start_line)
    except (TypeError, ValueError):
        start_line = 0
    return normalize_path(uri), start_line


def parse_sarif(document: dict, source_name: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for run in document.get("runs") or []:
        tool = _tool_name(run)
        if source_name and tool == "unknown":
            tool = Path(source_name).stem.split(".")[0].lower()
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "unknown")
            path, start_line = _location(result)
            package, cve = _extract_package_and_cve(result, rule_id)
            message = (result.get("message") or {}).get("text") or rule_id
            kind = _kind(tool, rule_id, package, cve)
            findings.append(
                Finding(
                    fingerprint=fingerprint(tool, rule_id, path, package, cve),
                    tool=tool,
                    rule_id=rule_id,
                    severity=_severity(result, run),
                    path=path or source_name,
                    line=start_line,
                    message=message.strip().split("\n")[0][:300],
                    kind=kind,
                    owasp=map_owasp(rule_id, message, kind),
                    package=package,
                    cve=cve,
                )
            )
    return findings


def load_sarif_dir(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    files = sorted(path.glob("*.sarif")) if path.is_dir() else [path]
    findings: list[Finding] = []
    seen: set[str] = set()
    for sarif_file in files:
        try:
            document = json.loads(sarif_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        for finding in parse_sarif(document, sarif_file.name):
            if finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            findings.append(finding)
    return findings
