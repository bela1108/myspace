# -*- coding: utf-8 -*-

"""Command-line query interface for slot-scoped advisory adjudication."""

from __future__ import unicode_literals

import argparse
import json
import os
from dataclasses import replace

from .query import format_report, load_case, query_case, report_to_dict


DEMO_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "examples",
    "slot_advisory_case.json",
)

MIGRATION_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "examples",
    "slot_migration_case.json",
)


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m cpe.advisory",
        description=(
            "Adjudicate a CPE advisory per application slot and show why a "
            "closure from one slot cannot substitute for another slot."
        ),
    )
    parser.add_argument(
        "case",
        nargs="?",
        help="Path to a case JSON file (default: bundled fictional demo).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the bundled fictional control-cabinet example.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit the structured report as JSON.",
    )
    parser.add_argument(
        "--snapshot",
        action="append",
        default=None,
        metavar="ID",
        help="Restrict the report to one snapshot id (repeatable).",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Restrict the report to the last snapshot in the case.",
    )
    parser.add_argument(
        "--no-policy",
        action="store_true",
        help="Do not append the baseline responsibility policy.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON instead of pretty JSON.",
    )
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)

    source = args.case
    if args.demo or not source:
        source = DEMO_PATH

    case = load_case(source)

    wanted = None
    if args.snapshot:
        wanted = set(args.snapshot)
        missing = wanted - set(item.snapshot_id for item in case.snapshots)
        if missing:
            parser.error(
                "unknown snapshot id(s): " + ", ".join(sorted(missing)))

    # Query the full timeline, then filter the rendered report.  Filtering the
    # case first would hide the earlier evidence that a single-slot supplement
    # relies on.
    report = query_case(case)
    if wanted is not None:
        report = replace(
            report,
            snapshots=tuple(
                item for item in report.snapshots
                if item.snapshot_id in wanted),
        )
    elif args.latest:
        report = replace(
            report,
            snapshots=(report.snapshots[-1],),
        )
    if args.as_json:
        payload = report_to_dict(report)
        if args.no_policy:
            payload["policy_notes"] = []
        print(json.dumps(
            payload,
            indent=None if args.compact else 2,
            ensure_ascii=False,
            sort_keys=False,
        ))
    else:
        print(
            format_report(
                report,
                include_policy=not args.no_policy,
            ),
            end="",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
