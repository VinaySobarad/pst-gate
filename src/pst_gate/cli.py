from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from pst_gate.advisory import advisory_markdown
from pst_gate.baseline import dump_baseline, load_baseline
from pst_gate.comment import comment_from_env
from pst_gate.decide import decide
from pst_gate.merge_sarif import merge_sarif_dir
from pst_gate.policy import load_policy
from pst_gate.provenance import provenance_for_sbom
from pst_gate.report import pr_report
from pst_gate.validate import PolicyError, validate_files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pst-gate")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    decide_parser = subparsers.add_parser(
        "decide", help="Merge SARIF, apply baseline/exceptions, exit 1 if blocking"
    )
    decide_parser.add_argument("--sarif-dir", type=Path, required=True)
    decide_parser.add_argument("--baseline", type=Path, default=Path("security/baseline.json"))
    decide_parser.add_argument(
        "--exceptions", type=Path, default=Path("security/exceptions.yml")
    )
    decide_parser.add_argument("--policy", type=Path, default=Path("security/policy.yml"))
    decide_parser.add_argument("--codeowners", type=Path, default=Path("CODEOWNERS"))
    decide_parser.add_argument("--scan-root", type=Path, default=Path("."))
    decide_parser.add_argument("--sbom", type=Path, default=None)
    decide_parser.add_argument("--kev", type=Path, default=None, help="CISA KEV JSON")
    decide_parser.add_argument(
        "--diff", type=Path, default=None, help="unified diff for AI-touch annotation"
    )
    decide_parser.add_argument("--out-dir", type=Path, default=Path("out"))
    decide_parser.add_argument("--today", default=None, help="YYYY-MM-DD override (tests)")
    decide_parser.add_argument("--fail-on", default=None, help="override policy fail_on")
    decide_parser.add_argument("--github-output", type=Path, default=None)

    promote_parser = subparsers.add_parser(
        "promote-baseline", help="Write current fingerprints into baseline.json"
    )
    promote_parser.add_argument("--decision", type=Path, required=True)
    promote_parser.add_argument(
        "--baseline", type=Path, default=Path("security/baseline.json")
    )

    merge_parser = subparsers.add_parser("merge-sarif", help="Combine *.sarif into one file")
    merge_parser.add_argument("--sarif-dir", type=Path, required=True)
    merge_parser.add_argument("--out", type=Path, required=True)

    comment_parser = subparsers.add_parser("comment", help="Sticky PR comment from report.md")
    comment_parser.add_argument("--report", type=Path, required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="Validate policy / exceptions / baseline files"
    )
    validate_parser.add_argument("--policy", type=Path, default=Path("security/policy.yml"))
    validate_parser.add_argument(
        "--exceptions", type=Path, default=Path("security/exceptions.yml")
    )
    validate_parser.add_argument(
        "--baseline", type=Path, default=Path("security/baseline.json")
    )

    args = parser.parse_args(argv)
    if args.cmd == "decide":
        return run_decide(args)
    if args.cmd == "promote-baseline":
        return run_promote(args)
    if args.cmd == "merge-sarif":
        merge_sarif_dir(args.sarif_dir, args.out)
        print(args.out)
        return 0
    if args.cmd == "comment":
        print(comment_from_env(args.report))
        return 0
    try:
        validate_files(args.policy, args.exceptions, args.baseline)
    except PolicyError as exc:
        print(exc, file=sys.stderr)
        return 2
    print("ok")
    return 0


def run_decide(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
        if args.fail_on:
            policy.fail_on = args.fail_on.lower()
        today = date.fromisoformat(args.today) if args.today else date.today()
        diff_text = ""
        if args.diff and args.diff.exists():
            diff_text = args.diff.read_text(encoding="utf-8", errors="replace")
        decision = decide(
            sarif_dir=args.sarif_dir,
            baseline_path=args.baseline,
            exceptions_path=args.exceptions,
            policy=policy,
            codeowners_path=args.codeowners if args.codeowners.exists() else None,
            scan_root=args.scan_root,
            sbom_path=args.sbom,
            diff_text=diff_text,
            today=today,
            kev_path=args.kev,
            policy_path=args.policy,
        )
    except PolicyError as exc:
        print(exc, file=sys.stderr)
        return 2
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "decision.json").write_text(
        json.dumps(decision.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "report.md").write_text(pr_report(decision, policy), encoding="utf-8")
    (out_dir / "advisory.md").write_text(
        advisory_markdown(decision, policy, today), encoding="utf-8"
    )
    dump_baseline(
        [finding.fingerprint for finding in decision.findings],
        out_dir / "baseline-next.json",
    )
    if args.sarif_dir.exists():
        merge_sarif_dir(args.sarif_dir, out_dir / "merged.sarif")
    if args.sbom and args.sbom.exists():
        provenance_for_sbom(args.sbom, out_dir / "provenance.json")
    if args.github_output:
        args.github_output.parent.mkdir(parents=True, exist_ok=True)
        with args.github_output.open("a", encoding="utf-8") as github_output:
            github_output.write(f"verdict={decision.verdict}\n")
            github_output.write(f"blocking-count={len(decision.blocking)}\n")
            github_output.write(f"report-path={out_dir / 'report.md'}\n")
    sys.stdout.write((out_dir / "report.md").read_text(encoding="utf-8"))
    return 1 if decision.verdict == "fail" else 0


def run_promote(args: argparse.Namespace) -> int:
    payload = json.loads(args.decision.read_text(encoding="utf-8"))
    fingerprints = [row["fingerprint"] for row in payload.get("findings") or []]
    existing = load_baseline(args.baseline)
    combined = sorted(existing | set(fingerprints))
    dump_baseline(combined, args.baseline)
    print(f"wrote {args.baseline} ({len(combined)} fingerprints)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
