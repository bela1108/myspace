"""
Command-line interface for bitemporal advisory reconciliation.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pip_audit._reconcile import (
    Audience,
    ReconciliationError,
    compare_views,
    comparison_as_dict,
    load_bundle,
    reconcile,
    render_json,
    render_markdown,
    views_document,
)


def _parser() -> argparse.ArgumentParser:
    """Build the argument parser for ``pip-audit reconcile``."""

    parser = argparse.ArgumentParser(
        prog="pip-audit reconcile",
        description=(
            "reconcile offline pip-audit results, lockfiles, and versioned advisory "
            "snapshots at a fixed as-of date and one or two visibility instants"
        ),
    )
    parser.add_argument("bundle", nargs="?", type=Path, help="evidence bundle JSON file")
    parser.add_argument(
        "--bundle", dest="bundle_option", type=Path, help="evidence bundle JSON file"
    )
    parser.add_argument(
        "--as-of",
        "--valid-at",
        "--date",
        dest="as_of",
        required=True,
        help="valid-time date or timestamp used by both views",
    )
    parser.add_argument(
        "--visible-at",
        "--known-at",
        "--observed-at",
        dest="visible_at",
        action="append",
        required=True,
        metavar="TIMESTAMP",
        help="transaction-time instant; repeat twice to compare an earlier and a later view",
    )
    parser.add_argument(
        "--audience",
        choices=[audience.value for audience in Audience] + ["public"],
        default=Audience.EXTERNAL.value,
        help="external views redact reasons that the license does not permit sharing",
    )
    parser.add_argument(
        "--advisory-snapshot",
        action="append",
        type=Path,
        default=[],
        dest="advisory_snapshots",
        help="additional advisory snapshot file or directory; may be repeated",
    )
    parser.add_argument(
        "--closure",
        action="append",
        type=Path,
        default=[],
        dest="closures",
        help="additional immutable closure ledger file or directory; may be repeated",
    )
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="optional label for each visibility view, in chronological order",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "md"],
        default="markdown",
        help="output format for the combined report",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write the combined report to this file instead of stdout",
    )
    parser.add_argument(
        "--write-views",
        type=Path,
        metavar="DIRECTORY",
        help="write view-1.json, view-2.json, comparison.json, and review.md",
    )
    parser.add_argument(
        "--fail-on-reopen",
        action="store_true",
        help="exit with status 2 when the later view requires any closure to be reopened",
    )
    return parser


def _write(path: Path, text: str) -> None:
    """Write text to a path, creating parent directories as needed."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the reconciliation CLI and return a process exit status."""

    parser = _parser()
    args = parser.parse_args(argv)
    bundle_path = args.bundle_option or args.bundle
    if bundle_path is None:
        parser.error("an evidence bundle is required")
    if len(args.visible_at) > 2:
        parser.error("provide at most two --visible-at instants")
    if len(set(args.visible_at)) != len(args.visible_at):
        parser.error("the two --visible-at instants must be different")
    if args.label and len(args.label) not in (1, len(args.visible_at)):
        parser.error("provide one label per visible-at instant")

    try:
        bundle = load_bundle(
            bundle_path,
            extra_snapshots=args.advisory_snapshots,
            extra_closures=args.closures,
        )
        instants = sorted(args.visible_at)
        labels = args.label or (["earlier", "later"] if len(instants) == 2 else ["view-1"])
        views = [
            reconcile(
                bundle,
                as_of=args.as_of,
                visible_at=instant,
                audience=(Audience.INTERNAL if args.audience == "internal" else Audience.EXTERNAL),
                label=labels[index],
            )
            for index, instant in enumerate(instants)
        ]
        comparison = compare_views(views[0], views[-1]) if len(views) == 2 else None
        document = views_document(views, comparison)
        text = (
            render_json(document) if args.format == "json" else render_markdown(views, comparison)
        )
        output_path = args.output
        if output_path is not None:
            _write(output_path, text)
        else:
            print(text)
        views_dir = args.write_views
        if views_dir is not None:
            views_dir.mkdir(parents=True, exist_ok=True)
            for index, view in enumerate(views, start=1):
                _write(views_dir / f"view-{index}.json", render_json(views_document([view])))
                _write(views_dir / f"view-{index}.md", render_markdown([view]))
            if len(views) == 2:
                _write(views_dir / "historical.json", render_json(views_document([views[0]])))
                _write(views_dir / "current.json", render_json(views_document([views[1]])))
                _write(views_dir / "historical.md", render_markdown([views[0]]))
                _write(views_dir / "current.md", render_markdown([views[1]]))
            if comparison is not None:
                _write(
                    views_dir / "comparison.json",
                    render_json(comparison_as_dict(comparison)),
                )
                _write(views_dir / "review.md", render_markdown(views, comparison))
        if args.fail_on_reopen and comparison is not None and comparison.reopen:
            return 2
        return 0
    except ReconciliationError as exc:
        print(f"pip-audit reconcile: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
