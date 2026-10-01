"""The `iam-paths` command. One subcommand, scan, with one job: load an
account (offline file today; --profile is reserved for step 8's live,
read-only boto3 loader), build the report, and either print it or write it
somewhere -- then exit non-zero if --fail-on says the findings are bad
enough to fail a CI build.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from iam_paths.loader import load_account
from iam_paths.report import ReportRow, build_report, render_html, render_json, render_table

_SEVERITY_RANK = {"Critical": 2, "High": 1}
_FAIL_ON_THRESHOLD = {"critical": 2, "high": 1}


def _worst_severity_rank(rows: list[ReportRow]) -> int:
    ranks = [_SEVERITY_RANK.get(row.severity, 0) for row in rows]
    return max(ranks, default=0)


def _should_fail(rows: list[ReportRow], fail_on: str | None) -> bool:
    if fail_on is None:
        return False
    return _worst_severity_rank(rows) >= _FAIL_ON_THRESHOLD[fail_on]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iam-paths")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Find IAM privilege-escalation paths to admin")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--file", type=Path, help="Path to a get-account-authorization-details JSON file"
    )
    source.add_argument("--profile", help="AWS CLI profile for a live, read-only scan (step 8)")
    scan.add_argument("--format", choices=["table", "json", "html"], default="table")
    scan.add_argument("--fail-on", choices=["critical", "high"], default=None)
    scan.add_argument("--out", type=Path, default=None, help="Write output here instead of stdout")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.profile is not None:
        print(
            "Live AWS scanning (--profile) isn't implemented yet -- "
            "see Step 8 (loader.from_boto3) in the build guide.",
            file=sys.stderr,
        )
        return 2

    account = load_account(args.file)
    rows = build_report(account)

    if args.format == "table":
        from rich.console import Console

        Console().print(render_table(rows))
    elif args.format == "json":
        output = render_json(rows)
        if args.out:
            args.out.write_text(output)
        else:
            print(output)
    else:
        output = render_html(rows, account)
        out_path = args.out or Path("out/report.html")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output)
        print(f"Wrote {out_path}")

    return 1 if _should_fail(rows, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
