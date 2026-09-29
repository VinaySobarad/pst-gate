from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path
from typing import Literal

from pst_gate.ai_touch import ai_touched_paths, finding_ai_touched
from pst_gate.baseline import load_baseline
from pst_gate.exceptions import exception_state, load_exceptions
from pst_gate.kev import load_kev
from pst_gate.models import Decision, ExceptionRow, Finding, Policy
from pst_gate.owners import load_codeowners, owner_for
from pst_gate.reachability import is_reachable
from pst_gate.sarif import load_sarif_dir
from pst_gate.sbom import package_in_sbom, summarize_sbom
from pst_gate.validate import validate_files

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def decide(
    *,
    sarif_dir: Path,
    baseline_path: Path,
    exceptions_path: Path,
    policy: Policy,
    codeowners_path: Path | None,
    scan_root: Path,
    sbom_path: Path | None,
    diff_text: str = "",
    today: date | None = None,
    kev_path: Path | None = None,
    policy_path: Path | None = None,
    skip_validate: bool = False,
) -> Decision:
    today = today or date.today()
    if not skip_validate:
        validate_files(
            policy_path if policy_path and policy_path.exists() else None,
            exceptions_path if exceptions_path.exists() else None,
            baseline_path if baseline_path.exists() else None,
        )

    findings = load_sarif_dir(sarif_dir)
    baseline = load_baseline(baseline_path)
    exceptions = load_exceptions(exceptions_path)
    owner_rules = load_codeowners(codeowners_path) if codeowners_path else []
    ai_paths = ai_touched_paths(diff_text) if policy.annotate_ai_touch else set()
    kev_cves = load_kev(kev_path)
    sbom = summarize_sbom(sbom_path)

    current_fingerprints = {finding.fingerprint for finding in findings}
    fixed_since_baseline = sorted(baseline - current_fingerprints)

    for finding in findings:
        finding.owner = owner_for(finding.path, owner_rules) if owner_rules else "unassigned"
        if finding.kind == "sca":
            finding.reachable = is_reachable(finding.package, scan_root)
            shipped = package_in_sbom(finding.package, sbom)
            finding.shipped = shipped
            if shipped is True:
                finding.reachable = True
        else:
            finding.reachable = True
        finding.ai_touched = finding_ai_touched(finding.path, ai_paths)
        finding.kev = bool(finding.cve and finding.cve.upper() in kev_cves)
        finding.status = classify_finding(finding, baseline, exceptions, policy, today)
        waiver = exceptions.get(finding.fingerprint)
        if finding.status == "accepted" and waiver and waiver.owner:
            finding.owner = waiver.owner

    blocking = [
        finding
        for finding in findings
        if finding.status in {"block", "expired_exception"}
    ]
    blocking.sort(key=_blocking_sort_key)

    counts = Counter(finding.status for finding in findings)
    verdict: Literal["pass", "fail"] = "fail" if blocking else "pass"
    return Decision(
        verdict=verdict,
        fail_on=policy.fail_on,
        blocking=blocking,
        findings=findings,
        fixed_since_baseline=fixed_since_baseline,
        sbom=sbom,
        summary={
            "total": len(findings),
            "blocking": len(blocking),
            "accepted": counts.get("accepted", 0),
            "baseline": counts.get("baseline", 0),
            "unreachable": counts.get("unreachable", 0),
            "below_threshold": counts.get("below_threshold", 0),
            "expired_exception": counts.get("expired_exception", 0),
            "ai_touched": sum(1 for finding in findings if finding.ai_touched),
            "kev": sum(1 for finding in findings if finding.kev),
            "fixed_since_baseline": len(fixed_since_baseline),
        },
    )


def classify_finding(
    finding: Finding,
    baseline: set[str],
    exceptions: dict[str, ExceptionRow],
    policy: Policy,
    today: date,
) -> str:
    waiver_state = exception_state(exceptions.get(finding.fingerprint), today)
    if waiver_state == "expired_exception":
        return "expired_exception"
    if waiver_state == "accepted":
        return "accepted"
    if finding.kev and policy.block_kev and finding.reachable is not False:
        return "block"
    if finding.kind == "sca" and policy.ignore_unreachable_sca and finding.reachable is False:
        return "unreachable"
    if not policy.blocks(finding.severity):
        return "below_threshold"
    if finding.fingerprint in baseline:
        return "baseline"
    return "block"


def _blocking_sort_key(finding: Finding) -> tuple[int, int, str]:
    return (
        0 if finding.kev else 1,
        _SEVERITY_ORDER.get(finding.severity, 9),
        finding.path,
    )
