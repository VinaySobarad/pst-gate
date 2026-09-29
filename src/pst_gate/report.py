from __future__ import annotations

from pst_gate.comment import MARKER
from pst_gate.models import Decision, Policy


def pr_report(decision: Decision, policy: Policy) -> str:
    summary = decision.summary
    icon = "FAIL" if decision.verdict == "fail" else "PASS"
    lines = [
        MARKER,
        f"## pst-gate — {icon}",
        "",
        f"Fail on **{policy.fail_on}+**. "
        f"{summary['total']} findings · {summary['blocking']} blocking · "
        f"{summary['accepted']} accepted · {summary['baseline']} already in baseline · "
        f"{summary['unreachable']} SCA not in-use · {summary.get('kev', 0)} on CISA KEV · "
        f"{summary['ai_touched']} on AI-touched paths.",
        "",
        "Scanners do not fail the job. This report is the gate: **new** High/Critical, "
        "**reachable / shipped** SCA, **CISA KEV** (not hidden by baseline), "
        "and **expired exceptions**.",
        "",
    ]
    if decision.blocking:
        lines += ["### Blocking (fix, or exception with owner + expiry)", ""]
        lines.append("| Sev | OWASP | Owner | Path | Rule | Why |")
        lines.append("|-----|-------|-------|------|------|-----|")
        for finding in decision.blocking:
            why = "expired exception" if finding.status == "expired_exception" else "new"
            if finding.kev:
                why = "CISA KEV" + ("" if why == "new" else f", {why}")
            if finding.ai_touched:
                why += ", AI-touched"
            location = f"`{finding.path}:{finding.line}`"
            lines.append(
                f"| {finding.severity} | {finding.owasp} | {finding.owner} "
                f"| {location} | `{finding.rule_id}` | {why} |"
            )
        lines.append("")
        sla_days = policy.sla_days.get(policy.fail_on, 14)
        lines.append(
            f"Default SLA for {policy.fail_on}: **{sla_days} days** (`security/policy.yml`)."
        )
        lines.append("")
    accepted = [finding for finding in decision.findings if finding.status == "accepted"]
    if accepted:
        lines += ["### Accepted (owned, not expired)", ""]
        for finding in accepted:
            lines.append(
                f"- `{finding.fingerprint}` {finding.rule_id} @ `{finding.path}` — {finding.owner}"
            )
        lines.append("")
    kev_noise = [
        finding
        for finding in decision.findings
        if finding.kev and finding.status == "unreachable"
    ]
    if kev_noise:
        lines += ["### KEV in packages you do not import (not blocking)", ""]
        for finding in kev_noise:
            lines.append(f"- `{finding.cve}` `{finding.package}`")
        lines.append("")
    if decision.fixed_since_baseline:
        lines += [
            f"### Fixed since baseline ({len(decision.fixed_since_baseline)})",
            "",
            "Fingerprints in baseline that did not show up this run.",
            "",
        ]
    if decision.sbom.get("present"):
        lines += [
            "### Supply chain",
            "",
            f"- SBOM: {decision.sbom.get('format')} · {decision.sbom.get('components')} components"
            f" · `{decision.sbom.get('name')}`",
            "",
        ]
    lines.append("_pst-gate decides ship / don't ship._")
    return "\n".join(lines) + "\n"
