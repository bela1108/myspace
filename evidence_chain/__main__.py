"""Command-line interface for the read-only evidence-chain audit.

Usage:

    python -m evidence_chain audit \
        --manifest release_manifest.json \
        --records supplements.json \
        --archive-root /path/to/offline/archive \
        [--output evidence_catalog.json]

The audit never writes to the archive; the only output is the evidence
catalog JSON (stdout, or the file given with --output).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from evidence_chain.audit import audit, load_manifest, load_records


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence_chain",
        description=(
            "Read-only audit of supplemental metadata for offline managed "
            "artifacts against the external archive chain."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser(
        "audit", help="audit supplemental records and emit the catalog"
    )
    run.add_argument(
        "--manifest",
        required=True,
        help="original release manifest JSON (the release order)",
    )
    run.add_argument(
        "--records",
        required=True,
        help="supplemental read-only metadata records JSON",
    )
    run.add_argument(
        "--archive-root",
        default=".",
        help="base directory for relative artifact locations",
    )
    run.add_argument(
        "--output",
        default=None,
        help="write the evidence catalog JSON here (default: stdout)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "audit":
        try:
            manifest = load_manifest(args.manifest)
            records = load_records(args.records)
        except (ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        report = audit(manifest, records, archive_root=args.archive_root)
        payload = report.to_json()
        if args.output:
            Path(args.output).write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
        return 0
    return 2  # pragma: no cover - argparse enforces the subcommand


if __name__ == "__main__":
    sys.exit(main())
