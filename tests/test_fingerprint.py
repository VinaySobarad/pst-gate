from pst_gate.fingerprint import fingerprint


def test_normalize_strips_github_workspace():
    from pst_gate.fingerprint import normalize_path

    uri = "file:///home/runner/work/app/app/src/main.py"
    assert normalize_path(uri) == "src/main.py"


def test_fingerprint_ignores_line_and_is_stable():
    first = fingerprint("semgrep", "python.lang.security.audit.sqli", "app/db.py")
    second = fingerprint("SEMGREP", "python.lang.security.audit.sqli", "./app/db.py")
    assert first == second
    assert len(first) == 16


def test_sca_fingerprint_collapses_tools():
    trivy_id = fingerprint(
        "trivy", "CVE-2023-11111", "requirements.txt", "requests", "CVE-2023-11111"
    )
    snyk_id = fingerprint(
        "snyk", "SNYK-PYTHON-REQUESTS-1", "poetry.lock", "requests", "CVE-2023-11111"
    )
    assert trivy_id == snyk_id
