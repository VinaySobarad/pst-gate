from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Kind = Literal["sast", "sca", "iac", "secret", "other"]
Status = Literal[
    "block",
    "accepted",
    "baseline",
    "expired_exception",
    "unreachable",
    "below_threshold",
]

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class Finding:
    fingerprint: str
    tool: str
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    kind: str
    owasp: str
    package: str | None = None
    cve: str | None = None
    owner: str = "unassigned"
    reachable: bool | None = None
    shipped: bool | None = None
    ai_touched: bool = False
    kev: bool = False
    status: str = "block"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExceptionRow:
    fingerprint: str
    owner: str
    reason: str
    expires: str
    sla_days: int | None = None


@dataclass
class Policy:
    fail_on: str = "high"
    ignore_unreachable_sca: bool = True
    annotate_ai_touch: bool = True
    block_kev: bool = True
    sla_days: dict[str, int] = field(
        default_factory=lambda: {
            "critical": 7,
            "high": 14,
            "medium": 30,
            "low": 90,
        }
    )

    def blocks(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(self.fail_on, 3)


@dataclass
class Decision:
    verdict: Literal["pass", "fail"]
    fail_on: str
    blocking: list[Finding]
    findings: list[Finding]
    fixed_since_baseline: list[str]
    sbom: dict[str, Any]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "fail_on": self.fail_on,
            "blocking": [finding.to_dict() for finding in self.blocking],
            "findings": [finding.to_dict() for finding in self.findings],
            "fixed_since_baseline": self.fixed_since_baseline,
            "sbom": self.sbom,
            "summary": self.summary,
        }
