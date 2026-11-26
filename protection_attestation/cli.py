"""Command line interface for plaintext-free protection attestation batches."""

from __future__ import annotations

import argparse
from pathlib import Path

from .intake import run_batch
from .reporting import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protection-attestation",
        description="Accept Office protection parameter testimonies without touching plaintext.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run-batch", help="run one batch manifest")
    run_parser.add_argument("--config", required=True, type=Path)
    run_parser.add_argument("--out", required=True, type=Path)

    build_parser = subparsers.add_parser(
        "build-handoff-outputs",
        help="regenerate the two divergent sample tool outputs from the three packages",
    )
    build_parser.add_argument(
        "--handoff-dir",
        type=Path,
        default=Path("protection_attestation/handoff"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run-batch":
        result = run_batch(args.config)
        write_reports(result, args.out)
        summary = result["summary"]
        print(
            "batch={batch} packages={package_count} claims={claim_count} "
            "notation={transcription_note_count} differences={protection_difference_count} "
            "reapproval={reapproval_required_count} cases_verified={review_cases_verified}".format(
                batch=result["batch_id"], **summary
            )
        )
        intake_valid = (
            summary["review_cases_verified"]
            and summary["source_conflict_count"] == 0
            and summary["rejected_claim_count"] == 0
        )
        return 0 if intake_valid else 2

    if args.command == "build-handoff-outputs":
        from .demo import build_handoff_outputs

        paths = build_handoff_outputs(args.handoff_dir)
        for path in paths:
            print(path)
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2
