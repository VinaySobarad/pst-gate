from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import yaml

_FINGERPRINT = re.compile(r"^[a-f0-9]{16}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FAIL_ON = {"critical", "high", "medium", "low", "info"}


class PolicyError(ValueError):
    pass


def validate_policy_data(data: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["policy must be a mapping"]
    fail_on = str(data.get("fail_on") or "high").lower()
    if fail_on not in _FAIL_ON:
        errors.append(f"fail_on must be one of {sorted(_FAIL_ON)}")
    sla_days = data.get("sla_days") or {}
    if sla_days and not isinstance(sla_days, dict):
        errors.append("sla_days must be a mapping")
    return errors


def validate_exceptions_data(data: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["exceptions file must be a mapping"]
    rows = data.get("exceptions")
    if rows is None:
        return ["missing 'exceptions' list"]
    if not isinstance(rows, list):
        return ["exceptions must be a list"]
    for index, raw in enumerate(rows):
        prefix = f"exceptions[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{prefix} must be a mapping")
            continue
        fingerprint_id = str(raw.get("fingerprint") or "").strip()
        owner = str(raw.get("owner") or "").strip()
        reason = str(raw.get("reason") or "").strip()
        expires = str(raw.get("expires") or "").strip()
        if not _FINGERPRINT.match(fingerprint_id):
            errors.append(f"{prefix}.fingerprint must be 16 lowercase hex chars")
        if not owner or not (owner.startswith("@") or "@" in owner):
            errors.append(f"{prefix}.owner is required (GitHub team or @user)")
        if len(reason) < 8:
            errors.append(f"{prefix}.reason must explain the exception (>= 8 chars)")
        if not _DATE.match(expires):
            errors.append(f"{prefix}.expires must be YYYY-MM-DD")
        else:
            try:
                date.fromisoformat(expires)
            except ValueError:
                errors.append(f"{prefix}.expires is not a valid date")
    return errors


def validate_baseline_data(data: object) -> list[str]:
    if isinstance(data, list):
        fingerprints = data
    elif isinstance(data, dict):
        fingerprints = data.get("fingerprints") or []
    else:
        return ["baseline must be an object or list"]
    errors: list[str] = []
    if not isinstance(fingerprints, list):
        return ["fingerprints must be a list"]
    for index, fingerprint_id in enumerate(fingerprints):
        if not _FINGERPRINT.match(str(fingerprint_id)):
            errors.append(f"fingerprints[{index}] must be 16 lowercase hex chars")
    return errors


def validate_files(
    policy_path: Path | None,
    exceptions_path: Path | None,
    baseline_path: Path | None,
) -> None:
    errors: list[str] = []
    if policy_path and policy_path.exists():
        errors += [
            f"policy: {message}" for message in validate_policy_data(_load_yaml(policy_path))
        ]
    if exceptions_path and exceptions_path.exists():
        errors += [
            f"exceptions: {message}"
            for message in validate_exceptions_data(_load_yaml(exceptions_path))
        ]
    if baseline_path and baseline_path.exists():
        try:
            payload = json.loads(baseline_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"baseline: invalid JSON ({exc})")
        else:
            errors += [
                f"baseline: {message}" for message in validate_baseline_data(payload)
            ]
    if errors:
        raise PolicyError("\n".join(errors))


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        return {}
    return payload
