"""Command-line entry point for the offline license-conflict review."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from license_audit.engine import LicenseAuditError, run_review
from license_audit.report import render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser."""
    parser = argparse.ArgumentParser(
        prog="license-audit",
        description="Offline license-conflict review driven by plyara rule parsing.",
    )
    parser.add_argument("books_dir", help="Directory containing the release book YARA files.")
    parser.add_argument("manifest", help="Local sample manifest (JSON).")
    parser.add_argument("approvals", help="Approval scope catalog (JSON).")
    parser.add_argument("frozen", help="Frozen rule-version manifest (JSON).")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument("--output", help="Write the report to this path instead of stdout.")
    return parser


def _discover_books(books_dir: Path) -> list[tuple[str, str]]:
    if not books_dir.is_dir():
        raise LicenseAuditError(f"books directory not found: {books_dir}")
    books = sorted(books_dir.glob("*.yar"))
    if not books:
        raise LicenseAuditError(f"no .yar release books found in {books_dir}")
    return [(book.name, str(book)) for book in books]


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    args = build_parser().parse_args(argv)
    try:
        books = _discover_books(Path(args.books_dir))
        report = run_review(books, args.manifest, args.approvals, args.frozen)
    except LicenseAuditError as exc:
        print(f"license-audit: {exc}", file=sys.stderr)
        return 2

    output = render_json(report) if args.json else render_text(report)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 1 if report.summary()["violation"] else 0


if __name__ == "__main__":
    sys.exit(main())
