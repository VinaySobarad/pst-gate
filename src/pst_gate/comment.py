from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

MARKER = "<!-- pst-gate-report -->"


def upsert_pr_comment(
    body: str,
    *,
    token: str,
    repository: str,
    pr_number: int,
    api_url: str = "https://api.github.com",
) -> str:
    """Create or update a single sticky PR comment. Returns 'created' or 'updated'."""
    if MARKER not in body:
        body = MARKER + "\n" + body
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pst-gate",
        "Content-Type": "application/json",
    }
    comments_url = (
        f"{api_url.rstrip('/')}/repos/{repository}/issues/{pr_number}/comments"
    )
    listed = json.loads(_request("GET", comments_url + "?per_page=100", headers=headers))
    existing = None
    if isinstance(listed, list):
        for comment in listed:
            if isinstance(comment, dict) and MARKER in str(comment.get("body") or ""):
                existing = comment
                break
    payload = json.dumps({"body": body}).encode()
    if existing and existing.get("id"):
        _request(
            "PATCH",
            f"{api_url.rstrip('/')}/repos/{repository}/issues/comments/{existing['id']}",
            headers=headers,
            data=payload,
        )
        return "updated"
    _request("POST", comments_url, headers=headers, data=payload)
    return "created"


def comment_from_env(report_path: Path) -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    repository = os.environ.get("GITHUB_REPOSITORY") or ""
    pr_number = os.environ.get("PR_NUMBER") or ""
    api_url = os.environ.get("GITHUB_API_URL") or "https://api.github.com"
    if not token or not repository or not pr_number:
        raise SystemExit("GITHUB_TOKEN, GITHUB_REPOSITORY, and PR_NUMBER are required")
    body = report_path.read_text(encoding="utf-8")
    return upsert_pr_comment(
        body,
        token=token,
        repository=repository,
        pr_number=int(pr_number),
        api_url=api_url,
    )


def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None = None,
) -> bytes:
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"GitHub API {method} {url} failed: {exc.code}") from exc
