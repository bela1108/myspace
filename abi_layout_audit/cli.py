"""Command line entry point for static ABI layout audits."""

from __future__ import annotations

import argparse
import json
import sys

from .audit import load_audit_config
from .errors import AuditError
from .parser import read_c_file
from .report import render_text, review_abis


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abi-layout-audit",
        description=(
            "Audit exportable byte ranges of a fixed-size C state block "
            "without executing the declarations. ABI sizes, alignments, "
            "public fields and export ranges are all caller supplied."))
    parser.add_argument(
        "declarations",
        help="path to preprocessed C declarations (cpp -P / gcc -E output)")
    parser.add_argument(
        "--config", action="append", required=True,
        help="JSON config with abi and audit sections; repeat for a second "
             "ABI review of the same declarations")
    parser.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="report format (default: text)")
    parser.add_argument(
        "--output",
        help="write the report here instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        unit = read_c_file(args.declarations)
        loaded = [load_audit_config(path) for path in args.config]
        abis = [abi for abi, _ in loaded]
        audits = [audit for _, audit in loaded]
        reference = audits[0]
        for extra in audits[1:]:
            if extra.type_name != reference.type_name:
                raise AuditError(
                    "all configs must audit the same target type; got "
                    f"{reference.type_name!r} vs {extra.type_name!r}")
            if extra.public_paths != reference.public_paths:
                raise AuditError(
                    "all configs must use the same public_fields list so "
                    "the two ABI reviews are comparable")
        reports = review_abis(unit, abis, reference)
        if args.format == "json":
            payload = json.dumps(
                [report.to_dict() for report in reports], indent=2,
                ensure_ascii=False)
        else:
            payload = "\n\n".join(render_text(report) for report in reports)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
        else:
            print(payload)
        return 0 if all(r.worst_verdict == "ok" for r in reports) else 2
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
