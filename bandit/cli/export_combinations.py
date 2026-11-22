#
# SPDX-License-Identifier: Apache-2.0
"""Command-line report for protected export-label combinations."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bandit.core import export_combinations


def _add_protected(parser):
    parser.add_argument(
        "--protect",
        dest="protected",
        action="append",
        default=[],
        metavar="A,B",
        help="comma-separated labels to protect; repeat for more pairs",
    )
    parser.add_argument(
        "--protect-pair",
        dest="protected_pairs",
        action="append",
        nargs=2,
        default=[],
        metavar=("A", "B"),
        help="two labels to protect; repeat for more pairs",
    )


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Review finite Python export sites for caller-protected "
            "label combinations."
        )
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="Python source file or directory to review",
    )
    _add_protected(parser)
    parser.add_argument(
        "--export-function",
        dest="export_functions",
        action="append",
        default=[],
        metavar="NAME",
        help="additional export API function name",
    )
    parser.add_argument(
        "--recipient-argument",
        dest="recipient_arguments",
        action="append",
        default=[],
        metavar="NAME",
        help="additional recipient keyword argument name",
    )
    parser.add_argument(
        "--field-argument",
        dest="field_arguments",
        action="append",
        default=[],
        metavar="NAME",
        help="additional field/label keyword argument name",
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="recurse into directories",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="return success even when a co-executable pair is found",
    )
    return parser


def _protected_combinations(args):
    protected = list(args.protected)
    protected.extend(
        f"{left},{right}" for left, right in args.protected_pairs
    )
    if not protected:
        return ()
    return export_combinations.normalize_protected_combinations(protected)


def _targets(targets, recursive):
    files = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            if not recursive:
                raise ValueError(
                    f"{target!r} is a directory; use --recursive"
                )
            files.extend(sorted(path.rglob("*.py")))
        elif path.is_file():
            files.append(path)
        else:
            raise ValueError(f"target does not exist: {target!r}")
    return files


def _config(args):
    config = {}
    if args.export_functions:
        config["export_functions"] = args.export_functions
    if args.recipient_arguments:
        config["recipient_arguments"] = args.recipient_arguments
    if args.field_arguments:
        config["field_arguments"] = args.field_arguments
    return config


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    protected = _protected_combinations(args)
    if not protected:
        parser.error("at least one --protect or --protect-pair is required")

    try:
        targets = _targets(args.targets, args.recursive)
    except ValueError as error:
        parser.error(str(error))

    findings = []
    reports = []
    for target in targets:
        try:
            report = export_combinations.analyze_file(
                target,
                protected=protected,
                config=_config(args),
            )
        except (OSError, SyntaxError) as error:
            report = export_combinations.ExportCombinationReport(
                filename=str(target),
                findings=(),
                points=(),
                parse_error=str(error),
            )
        reports.append(report)
        findings.extend(report.findings)

    if args.output_format == "json":
        if len(reports) == 1:
            payload = reports[0].as_dict()
        else:
            payload = {
                "reports": [report.as_dict() for report in reports],
                "findings": [
                    finding.as_dict() for finding in findings
                ],
            }
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for index, report in enumerate(reports):
            if index:
                sys.stdout.write("\n")
            sys.stdout.write(report.to_text())
            sys.stdout.write("\n")

    combined = any(finding.co_executable for finding in findings)
    return 0 if args.exit_zero or not combined else 1


if __name__ == "__main__":
    sys.exit(main())
