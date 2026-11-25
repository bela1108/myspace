"""Command line entry point for offline incident recomputation.

Usage::

    python -m detect_secrets.incident CASE.json --report report.json

The case file is one JSON document with the keys ``findings``,
``ownership``, ``exemptions`` and ``events`` (plus an optional
``review_sla_days``).
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List
from typing import Optional

from detect_secrets.incident.report import render_text_report
from detect_secrets.incident.replay import replay_case


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="detect-secrets-incident",
        description=(
            "Offline recomputation of credential-incident ownership, "
            "exemptions and review deadlines from an event history."
        ),
    )
    parser.add_argument(
        "case_file",
        help="JSON case file with findings, ownership, exemptions and events.",
    )
    parser.add_argument(
        "--report",
        help="Write the full JSON report to this path (defaults to stdout).",
    )
    parser.add_argument(
        "--as-of",
        help="ISO timestamp to evaluate current state at (defaults to the "
        "last event timestamp).",
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="Also print a human-readable summary on stderr.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    with open(args.case_file, encoding="utf-8") as handle:
        case_data = json.load(handle)

    report = replay_case(case_data, as_of=args.as_of)
    serialized = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.write("\n")
    else:
        print(serialized)

    if args.text:
        sys.stderr.write(render_text_report(report) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
