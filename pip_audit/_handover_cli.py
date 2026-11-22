"""
Command-line entrypoints for `pip-audit` handover packages.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pip_audit._handover import (
    HandoverError,
    apply_receipt,
    build_handover,
    dumps,
    load_file,
    new_state,
    verify_handover,
)


def _parser() -> argparse.ArgumentParser:
    """Build the handover CLI parser."""
    parser = argparse.ArgumentParser(
        prog="pip-audit-handover",
        description="build and reconcile disclosure-safe pip-audit handover packages",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build a handover package")
    build.add_argument("--plan", type=Path, required=True, help="remediation plan JSON")
    build.add_argument("--audit", type=Path, required=True, help="offline pip-audit JSON")
    build.add_argument(
        "--environment",
        type=Path,
        help="optional environment version snapshot JSON",
    )
    build.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write the package to this path instead of stdout",
    )

    receive = subparsers.add_parser("receive", help="apply one or more receipts")
    receive.add_argument("--package", type=Path, required=True, help="handover package JSON")
    receive.add_argument(
        "--receipt",
        type=Path,
        action="append",
        required=True,
        help="receipt JSON; may be supplied more than once",
    )
    receive.add_argument(
        "--state",
        type=Path,
        help="read and update reconciliation state at this path",
    )
    receive.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write the reconciliation report to this path instead of stdout",
    )

    verify = subparsers.add_parser("verify", help="verify package and item digests")
    verify.add_argument("--package", type=Path, required=True, help="handover package JSON")
    verify.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write the verification result to this path instead of stdout",
    )
    return parser


def _emit(value: object, output: Path | None) -> None:
    """Write JSON to a path or stdout without adding diagnostic text."""
    text = dumps(value) if isinstance(value, dict) else dumps({"result": value})
    if output is None:
        sys.stdout.write(text)
    else:
        output.write_text(text)


def _load_package(path: Path) -> dict[str, Any]:
    """Load and verify a handover package."""
    package = load_file(path)
    verify_handover(package)
    return package


def _command_build(args: argparse.Namespace) -> int:
    """Implement the `build` subcommand."""
    package = build_handover(
        args.plan,
        args.audit,
        args.environment,
    )
    _emit(package, args.output)
    return 0


def _command_receive(args: argparse.Namespace) -> int:
    """Implement the `receive` subcommand."""
    package = _load_package(args.package)
    if args.state is not None and args.state.exists():
        state = load_file(args.state)
    else:
        state = new_state(package)

    reports: list[dict[str, object]] = []
    rejected = False
    for receipt_path in args.receipt:
        state, report = apply_receipt(package, state, receipt_path)
        reports.append(report)
        if report.get("status") == "rejected":
            rejected = True

    if args.state is not None:
        args.state.write_text(dumps(state))

    if len(reports) == 1:
        _emit(reports[0], args.output)
    else:
        _emit(
            {
                "handover_id": package["handover_id"],
                "reports": reports,
                "status": state["status"],
                "summary": state["summary"],
            },
            args.output,
        )
    return 1 if rejected else 0


def _command_verify(args: argparse.Namespace) -> int:
    """Implement the `verify` subcommand."""
    package = _load_package(args.package)
    _emit(
        {
            "valid": True,
            "handover_id": package["handover_id"],
            "status": package["status"],
            "summary": package["summary"],
        },
        args.output,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the handover CLI and return its process exit code."""
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            return _command_build(args)
        if args.command == "receive":
            return _command_receive(args)
        if args.command == "verify":
            return _command_verify(args)
        parser.error(f"unknown command: {args.command}")
    except (HandoverError, OSError) as exc:
        print(f"pip-audit-handover: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
