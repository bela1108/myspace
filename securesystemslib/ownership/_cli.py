"""Offline command-line entry point for ownership reconciliation.

The CLI reads registrations and statements from JSON files and writes the
reconciliation report to stdout (or a file). It performs no network access:
all signature verification happens through the installed ``securesystemslib``
key implementations.

Example:
    python -m securesystemslib.ownership --registrations regs.json \
        --statements stmts.json --out receipt.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from securesystemslib.ownership._model import Registration, Statement
from securesystemslib.ownership._reconcile import OwnershipReconciler


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser for the offline CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m securesystemslib.ownership",
        description=(
            "Offline ownership reconciliation: verify authorization and "
            "handoff statements against seal registrations and report which "
            "organization is recognized per purpose, interval and jurisdiction."
        ),
    )
    parser.add_argument(
        "--registrations",
        required=True,
        help="JSON file with a list of seal registrations",
    )
    parser.add_argument(
        "--statements",
        required=True,
        help="JSON file with a list of signed statements",
    )
    parser.add_argument(
        "--out",
        help="optional path for the JSON report (defaults to stdout)",
    )
    return parser


def run(
    registrations_path: str,
    statements_path: str,
    out_path: str | None = None,
) -> dict[str, Any]:
    """Load inputs, reconcile and (optionally) persist the report."""
    registrations = [
        Registration.from_dict(item) for item in _load_json(registrations_path)
    ]
    statements = [Statement.from_dict(item) for item in _load_json(statements_path)]

    report = OwnershipReconciler(registrations).reconcile(statements)
    report_dict = report.to_dict()

    rendered = json.dumps(report_dict, indent=2, ensure_ascii=False)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
    else:
        print(rendered)

    return report_dict


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and run the offline reconciliation."""
    args = build_parser().parse_args(argv)
    run(args.registrations, args.statements, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
