from __future__ import annotations

import re

_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sql.?inject|sqli|tainted.?sql", re.I), "A03:2021 Injection"),
    (re.compile(r"xss|cross.?site.?script", re.I), "A03:2021 Injection"),
    (re.compile(r"command.?inject|os.?command|shell.?inject", re.I), "A03:2021 Injection"),
    (re.compile(r"ssrf", re.I), "A10:2021 SSRF"),
    (
        re.compile(r"path.?traversal|lfi|rfi|\.\./", re.I),
        "A01:2021 Broken Access Control",
    ),
    (
        re.compile(r"idor|broken.?access|authz|missing.?auth", re.I),
        "A01:2021 Broken Access Control",
    ),
    (
        re.compile(r"pickle|deser|yaml\.load|marshal\.loads", re.I),
        "A08:2021 Software and Data Integrity Failures",
    ),
    (
        re.compile(r"secret|hardcoded|gitleaks|private.?key|aws.?access", re.I),
        "A07:2021 Identification and Authentication Failures",
    ),
    (
        re.compile(r"cve-|ghsa-|vulnerable.?and.?outdated|sca", re.I),
        "A06:2021 Vulnerable and Outdated Components",
    ),
    (
        re.compile(r"ckv_|public.?acl|public.?bucket|misconfig|open.?sg", re.I),
        "A05:2021 Security Misconfiguration",
    ),
    (
        re.compile(r"prompt.?injection|llm0?1|unsanitized.?prompt", re.I),
        "LLM01 Prompt Injection",
    ),
    (
        re.compile(r"sensitive.?information.?disclosure|llm0?6|secret.?in.?prompt", re.I),
        "LLM06 Sensitive Information Disclosure",
    ),
]


def map_owasp(rule_id: str, message: str, kind: str) -> str:
    blob = f"{rule_id} {message} {kind}"
    for pattern, label in _RULES:
        if pattern.search(blob):
            return label
    if kind == "sca":
        return "A06:2021 Vulnerable and Outdated Components"
    if kind == "iac":
        return "A05:2021 Security Misconfiguration"
    if kind == "secret":
        return "A07:2021 Identification and Authentication Failures"
    return "Unmapped — review as noise vs real"
