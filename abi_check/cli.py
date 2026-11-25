"""Command line entry point for the offline ABI reconciliation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .checker import reconcile, render_report
from .fixtures.fixture import write_fixtures

GENERATED_DIR = Path(__file__).parent / "fixtures" / "generated"


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Offline pefile-based ABI check of old vs new DLL exports."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser(
        "generate-fixtures", help="Build the synthetic old/new fixture DLLs."
    )
    generate.add_argument(
        "--output-dir",
        default=str(GENERATED_DIR),
        help="Directory for generated fixture DLLs.",
    )

    check = subparsers.add_parser(
        "check", help="Reconcile two DLL versions against a caller manifest."
    )
    check.add_argument("old_dll")
    check.add_argument("new_dll")
    check.add_argument("manifest")
    check.add_argument(
        "--extra-module",
        action="append",
        default=[],
        help="Additional offline DLL used to confirm forwarder targets.",
    )
    check.add_argument(
        "--json",
        dest="json_path",
        default=None,
        help="Optional path to also write the machine-readable JSON report.",
    )
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate-fixtures":
        paths = write_fixtures(args.output_dir)
        for label, path in sorted(paths.items()):
            print(f"{label}: {path}")
        return 0

    report = reconcile(
        args.old_dll,
        args.new_dll,
        args.manifest,
        extra_module_paths=args.extra_module,
    )
    print(render_report(report))
    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
