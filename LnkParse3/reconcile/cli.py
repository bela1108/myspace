#!/usr/bin/env python3

"""Command line entry point for the offline LNK reconciliation."""

__description__ = (
    "Offline reconciliation of LNK targets against historical drive maps "
    "and collected evidence volumes"
)

import argparse
import json
import sys

from LnkParse3.reconcile.lnk_adapter import descriptors_from_inputs
from LnkParse3.reconcile.models import make_target
from LnkParse3.reconcile.models import ReconcileInputError
from LnkParse3.reconcile.reconcile import build_reconciliation


def _load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _load_targets(targets_arg, lnk_args):
    if targets_arg:
        payload = _load_json(targets_arg)
        raw_targets = payload.get("targets", payload) if isinstance(payload, dict) else payload
        return [_target_from_dict(entry) for entry in raw_targets]
    return descriptors_from_inputs(lnk_args)


def _target_from_dict(entry):
    return make_target(
        source=entry["source"],
        written_path=entry.get("written_path"),
        drive_letter=entry.get("drive_letter"),
        volume_serial=entry.get("volume_serial"),
        volume_label=entry.get("volume_label"),
        location=entry.get("location", "Local"),
        lnk_ref=entry.get("lnk_ref"),
        note=entry.get("note"),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument(
        "lnk",
        nargs="*",
        help="LNK file or directory holding recovered LNK files (ignored with --targets)",
    )
    parser.add_argument(
        "--drives",
        required=True,
        help="JSON file with the historical per-collection drive letter tables",
    )
    parser.add_argument(
        "--evidence",
        required=True,
        help="JSON file with the volume identifiers actually readable on exhibits",
    )
    parser.add_argument(
        "--targets",
        help="optional JSON of pre-extracted target descriptors for review without LNK bytes",
    )
    parser.add_argument("--output", help="write the JSON report to this file instead of stdout")
    args = parser.parse_args(argv)

    if not args.targets and not args.lnk:
        parser.error("at least one LNK path or --targets is required")

    try:
        targets = _load_targets(args.targets, args.lnk)
        report = build_reconciliation(
            targets,
            _load_json(args.drives),
            _load_json(args.evidence),
        )
    except ReconcileInputError as exc:
        parser.error(str(exc))

    rendered = json.dumps(report, indent=4, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
