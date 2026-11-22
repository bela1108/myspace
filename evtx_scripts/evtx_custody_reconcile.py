#!/usr/bin/env python3
"""Offline reconciliation of an EVTX hand-over against custody records.

The command never writes to the evidence.  It reads the EVTX files named by
the case document and emits either the internal report or the redacted
external manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from Evtx.Custody import CustodyInputError, load_case, reconcile_custody


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evtx_custody_reconcile",
        description=(
            "Reconcile EVTX record ranges, custodian permissions, signed receipts, "
            "an external hand-over manifest, and an internal responsibility table."
        ),
    )
    parser.add_argument("case", nargs="?", help="Case JSON document")
    parser.add_argument("--config", "--case-file", "--case", dest="config", help="Case JSON document")
    parser.add_argument(
        "--external",
        "--external-manifest",
        "--manifest",
        dest="external_manifest",
        help="External hand-over manifest JSON",
    )
    parser.add_argument(
        "--responsibility",
        "--internal-responsibility",
        "--responsibility-table",
        "--internal",
        dest="responsibility",
        help="Internal responsibility table JSON",
    )
    parser.add_argument(
        "--receipts",
        "--acceptance-receipts",
        "--acceptance",
        dest="receipts",
        help="Receipts JSON",
    )
    parser.add_argument("--deadline", "--archive-deadline", dest="deadline", help="Archive/destruction deadline")
    parser.add_argument("--as-of", dest="as_of", help="Time used for permission windows")
    parser.add_argument("--format", choices=["text", "json", "external"], help="Output format")
    parser.add_argument("--json", action="store_true", help="Print the internal report as JSON")
    parser.add_argument(
        "--external-json",
        "--external-only",
        dest="external_json",
        action="store_true",
        help="Print the redacted external manifest as JSON",
    )
    parser.add_argument("--external-out", help="Write the redacted external manifest to this JSON file")
    parser.add_argument("--internal-out", help="Write the internal report to this JSON file")
    parser.add_argument(
        "--record-time-cutoff",
        action="store_true",
        help="Treat records newer than the governing receipt as not yet accepted",
    )
    parser.add_argument(
        "--allow-missing-manifest",
        action="store_true",
        help="Do not require every accepted range to appear in the external manifest",
    )
    parser.add_argument(
        "--require-responsibility",
        action="store_true",
        help="Reject receipts that cannot be matched to the internal responsibility table",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when any range is not accepted or the manifest scope does not match",
    )
    parser.add_argument("--quiet", action="store_true", help="Do not print the text report")
    parser.add_argument("--version", action="version", version="evtx_custody_reconcile 1.0")
    return parser


def _case_document(args: argparse.Namespace):
    path = args.case or args.config
    if path:
        return load_case(path)
    return {}


def _write_json(path: str, payload) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def main(argv=None) -> int:
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    mode = None
    if arguments and arguments[0] in {"reconcile", "audit", "check", "verify", "external"}:
        mode = arguments.pop(0)
    args = parser.parse_args(arguments)
    if mode == "external":
        args.external_json = True
    if mode == "verify":
        args.strict = True
    if args.format == "json":
        args.json = True
    elif args.format == "external":
        args.external_json = True
    try:
        case = _case_document(args)
        report = reconcile_custody(
            case,
            external_manifest=args.external_manifest,
            responsibility=args.responsibility,
            receipts=args.receipts,
            deadline=args.deadline,
            as_of=args.as_of,
            use_record_timestamps=args.record_time_cutoff,
            require_manifest=not args.allow_missing_manifest,
            require_responsibility=args.require_responsibility,
        )
    except (OSError, KeyError, TypeError, ValueError, CustodyInputError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
        return 2

    if args.internal_out:
        _write_json(args.internal_out, report.to_dict())
    if args.external_out:
        _write_json(args.external_out, report.external_dict())

    if args.external_json:
        if not args.quiet:
            print(report.external_json())
    elif args.json:
        if not args.quiet:
            print(report.to_json())
    elif not args.quiet:
        print(report.render_text())

    if args.strict:
        summary = report.get("summary", {})
        scope = report.get("handover_scope", {}).get("scope_check", {})
        if summary.get("not_accepted_records", 0) or not scope.get("scope_matches", False):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
