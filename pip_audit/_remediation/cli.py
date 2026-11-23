"""
Command-line entrypoint for `pip-audit`'s offline lock-plan remediation check.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO

from pip_audit import __version__
from pip_audit._remediation.auditreport import AuditReportError, read_audit_report
from pip_audit._remediation.format import RemediationFormatChoice
from pip_audit._remediation.lockplan import LockPlanError, load_lock_plan
from pip_audit._remediation.report import RemediationChecker, RemediationCheckError

logger = logging.getLogger(__name__)

# Mirror the main CLI by configuring the package logger rather than the root.
package_logger = logging.getLogger("pip_audit")


@contextmanager
def _output_io(name: Path) -> Iterator[IO[str]]:
    """
    A context-managed wrapper for the `--output` flag.

    Mirrors the main `pip-audit` behavior so that output files are not created
    eagerly before input validation has run.
    """

    if str(name) in {"stdout", "-"}:
        yield sys.stdout
    else:
        with name.open("w", encoding="utf-8") as io:
            yield io


def _parser() -> argparse.ArgumentParser:
    """
    Build the argument parser for the remediation-check entrypoint.
    """

    parser = argparse.ArgumentParser(
        prog="pip-audit-remediation",
        description=(
            "offline remediation check: compare two already-resolved PEP 751 lock plans "
            "and their pip-audit JSON reports, group by group, without installing or "
            "resolving anything"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--before-lock",
        type=Path,
        required=True,
        metavar="PYLOCK_TOML",
        help="the earlier resolved lock plan (e.g. pylock.before.toml)",
    )
    parser.add_argument(
        "--after-lock",
        type=Path,
        required=True,
        metavar="PYLOCK_TOML",
        help="the later resolved lock plan, after the attempted remediation",
    )
    parser.add_argument(
        "--before-audit",
        type=Path,
        required=True,
        metavar="AUDIT_JSON",
        help="pip-audit JSON output (--format json) for the before lock plan",
    )
    parser.add_argument(
        "--after-audit",
        type=Path,
        required=True,
        metavar="AUDIT_JSON",
        help="pip-audit JSON output (--format json) for the after lock plan",
    )
    parser.add_argument(
        "-g",
        "--group",
        type=str,
        action="append",
        dest="groups",
        default=[],
        help="limit the report to the given optional group (the base environment is "
        "always included); repeatable",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=RemediationFormatChoice,
        choices=list(RemediationFormatChoice),
        default=RemediationFormatChoice.Columns,
        metavar="FORMAT",
        help="the format to emit (choices: columns, json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        default=Path("stdout"),
        help="output results to the given file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="run with additional debug logging; supply multiple times to increase verbosity",
    )
    return parser


def remediation() -> None:
    """
    The entrypoint for `pip-audit`'s offline remediation check.
    """

    parser = _parser()
    args = parser.parse_args()

    if args.verbose >= 1:
        package_logger.setLevel("DEBUG")
    if args.verbose >= 2:
        logging.getLogger().setLevel("DEBUG")

    for label, path in (
        ("--before-lock", args.before_lock),
        ("--after-lock", args.after_lock),
        ("--before-audit", args.before_audit),
        ("--after-audit", args.after_audit),
    ):
        if not path.is_file():
            parser.error(f"{label} does not exist: {path}")

    try:
        before_plan = load_lock_plan(args.before_lock)
        after_plan = load_lock_plan(args.after_lock)
        before_audit = read_audit_report(args.before_audit)
        after_audit = read_audit_report(args.after_audit)
    except (LockPlanError, AuditReportError) as exc:
        logger.error(str(exc))
        sys.exit(2)

    try:
        result = RemediationChecker(
            before_plan=before_plan,
            before_audit=before_audit,
            after_plan=after_plan,
            after_audit=after_audit,
        ).check(only_groups=args.groups or None)
    except RemediationCheckError as exc:
        logger.error(str(exc))
        sys.exit(2)

    formatter = args.format.to_format()
    with _output_io(args.output) as io:
        print(formatter.format(result), file=io)

    sys.exit(result.exit_code)
