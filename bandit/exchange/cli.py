#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
"""Command line entry point for the exception exchange layer."""

import argparse
import json
import sys

from bandit.exchange import mapping as mapping_io
from bandit.exchange import report as report_io
from bandit.exchange import views as view_builder
from bandit.exchange.errors import ExchangeError


def _read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _load_inputs(report_path, mapping_path):
    report = report_io.load_report_text(_read_text(report_path))
    mappings = mapping_io.load_mapping_text(_read_text(mapping_path))
    return report, mappings


def _dump(payload):
    return json.dumps(payload, indent=2, sort_keys=True)


def _write_output(path, text):
    if path and path != "-":
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write(chr(10))
    else:
        sys.stdout.write(text)
        sys.stdout.write(chr(10))


def cmd_views(args):
    """Export local and exchange views from the same report."""
    report, mappings = _load_inputs(args.report, args.mappings)
    exported = view_builder.export_views(
        report, mappings, now=_optional_time(args.at)
    )
    _write_output(args.output, _dump(exported))
    return 0


def cmd_local(args):
    """Export only the local Bandit-centric view."""
    report, mappings = _load_inputs(args.report, args.mappings)
    exported = view_builder.export_local_view(
        report, mappings, now=_optional_time(args.at)
    )
    _write_output(args.output, _dump(exported))
    return 0


def cmd_exchange(args):
    """Export only the external-rule exchange view."""
    report, mappings = _load_inputs(args.report, args.mappings)
    exported = view_builder.export_exchange_view(
        report, mappings, now=_optional_time(args.at)
    )
    _write_output(args.output, _dump(exported))
    return 0


def cmd_validate(args):
    """Validate a mapping document without touching a scan report."""
    mappings = mapping_io.load_mapping_text(_read_text(args.mappings))
    summary = {
        "document": mappings["document"],
        "version": mappings["version"],
        "mapping_count": len(mappings["mappings"]),
        "mappings": [item.as_dict() for item in mappings["mappings"]],
    }
    _write_output(args.output, _dump(summary))
    return 0


def cmd_drop(args):
    """Rebuild views after the auditor removes one or more mappings."""

    report, mappings = _load_inputs(args.report, args.mappings)
    removed = [item.strip() for item in args.ids.split(",") if item.strip()]
    exchange = view_builder.build_exchange(
        report, mappings, now=_optional_time(args.at)
    )
    reduced = exchange.without_mappings(removed)
    exported = {
        "removed_mapping_ids": removed,
        "views": reduced.build_views(),
    }
    _write_output(args.output, _dump(exported))
    return 0


def _optional_time(value):
    if not value:
        return None
    from bandit.exchange.model import _parse_timestamp

    return _parse_timestamp(value, "--at")


def build_parser():
    """Construct the argument parser for the exchange CLI."""
    parser = argparse.ArgumentParser(
        prog="bandit-exchange",
        description="Translate Bandit findings into external scanner rules",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(target, with_output=True):
        target.add_argument("report", help="path to a Bandit JSON report")
        target.add_argument(
            "mappings",
            help="path to the exception mapping document",
        )
        target.add_argument("--at", dest="at", default=None,
            help="reference UTC time (ISO-8601) for validity checks")
        if with_output:
            target.add_argument("-o", "--output", default="-",
                help="output file (defaults to stdout)")

    views_parser = subparsers.add_parser(
        "views", help="export both local and exchange views")
    add_common(views_parser)
    views_parser.set_defaults(func=cmd_views)

    local_parser = subparsers.add_parser(
        "local", help="export the local Bandit view")
    add_common(local_parser)
    local_parser.set_defaults(func=cmd_local)

    exchange_parser = subparsers.add_parser(
        "exchange", help="export the external-rule exchange view")
    add_common(exchange_parser)
    exchange_parser.set_defaults(func=cmd_exchange)

    validate_parser = subparsers.add_parser(
        "validate", help="validate a mapping document")
    validate_parser.add_argument(
        "mappings", help="mapping document to validate"
    )
    validate_parser.add_argument("-o", "--output", default="-",
        help="output file (defaults to stdout)")
    validate_parser.set_defaults(func=cmd_validate)

    drop_parser = subparsers.add_parser(
        "drop", help="remove mappings and rebuild the views")
    add_common(drop_parser)
    drop_parser.add_argument(
        "ids", help="comma-separated mapping ids to delete"
    )
    drop_parser.set_defaults(func=cmd_drop)
    return parser


def main(argv=None):
    """Console entry point used by the bandit-exchange script."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ExchangeError as exc:
        sys.stderr.write(f"bandit-exchange: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
