"""Command-line entry point for the offline patch-order review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .auditgen import write_audits
from .model import FixtureError, load_fixture
from .reviewer import build_review, render_markdown

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_REPORTS = PACKAGE_ROOT / "reports"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m patch_order_review",
        description="Review candidate patch orders using offline pip-audit results.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("review", "generate", "verify"),
        default="review",
        help=(
            "review (default) writes audits plus report; "
            "generate writes audits; verify checks invariants"
        ),
    )
    parser.add_argument("--fixture", type=Path, default=None, help="fixture directory")
    parser.add_argument("--audit", type=Path, default=None, help="pip-audit result directory")
    parser.add_argument("--reports", type=Path, default=DEFAULT_REPORTS, help="report directory")
    return parser


def _load(args: argparse.Namespace) -> tuple[Any, Path]:
    fixture = load_fixture(args.fixture)
    audit_root = args.audit or fixture.root / "audit"
    return fixture, audit_root


def _write_reports(fixture: Any, review: dict[str, Any], report_dir: Path) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "review.json").write_text(
        json.dumps(review, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (report_dir / "patch_order_review.md").write_text(
        render_markdown(fixture, review), encoding="utf-8"
    )


def _summary(review: dict[str, Any]) -> str:
    lines = ["route                 gap  endpoint  continuity  verdict"]
    for route in review["routes"]:
        lines.append(
            f"{route['id']:<20} {route['endpoint_gap']:>3}  "
            f"{route['endpoint_only_verdict']:<8}  {route['continuity_verdict']:<10}  "
            f"{route['verdict']}"
        )
    lines.append(
        "recommended: {} (gap {}, safety premium {})".format(
            review["recommendation"]["route"],
            review["recommendation"]["endpoint_gap"],
            review["derivation"]["safety_premium"],
        )
    )
    return "\n".join(lines)


def _review(args: argparse.Namespace, write: bool = True) -> tuple[Any, dict[str, Any]]:
    fixture, audit_root = _load(args)
    if write:
        write_audits(fixture, audit_root)
    review = build_review(fixture, audit_root)
    return fixture, review


def _verify(review: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    accepted = [route for route in review["routes"] if route["verdict"] == "accept"]
    if not accepted:
        failures.append("no accepted route")
    counterexample = review["endpoint_only_comparison"]
    if counterexample["counterexample_route"] is None:
        failures.append("no endpoint-only counterexample")
    elif counterexample["counterexample_endpoint_only"] != "pass":
        failures.append("endpoint-only counterexample does not pass the shallow check")
    elif counterexample["counterexample_continuity"] != "fail":
        failures.append("endpoint-only counterexample does not fail continuity")
    if not review["evidence"]["transient_introduced"]:
        failures.append("no transient introduced-risk evidence")
    if not review["evidence"]["terminal_residual"]:
        failures.append("no terminal residual-risk evidence")
    derivation = review["derivation"]
    if derivation["naive_min_continuity_safe"]:
        failures.append("cheapest endpoint path is unexpectedly continuity-safe")
    if derivation["safe_min_gap"] < derivation["naive_min_gap"]:
        failures.append("safe path is cheaper than the unconstrained path")
    return failures


def main(argv: list[str] | None = None) -> int:
    """Run the review CLI and return a process exit code."""

    args = _parser().parse_args(argv)
    try:
        fixture, review = _review(args, write=True)
        if args.command == "generate":
            print(f"wrote {len(review['routes'])} routes of pip-audit results")
            return 0
        _write_reports(fixture, review, args.reports)
        print(_summary(review))
        if args.command == "verify":
            failures = _verify(review)
            if failures:
                for failure in failures:
                    print(f"verify: FAIL: {failure}", file=sys.stderr)
                return 1
            print("verify: OK")
        return 0
    except FixtureError as exc:
        print(f"patch_order_review: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
