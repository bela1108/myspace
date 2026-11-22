#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Run the advisory withdrawal re-audit against the bundled small inventory."""

from __future__ import print_function

import argparse
import json
import os
import sys


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cpe.audit import (  # noqa: E402
    Advisory,
    InventoryScope,
    InventorySnapshot,
    ReplacementEvidence,
    audit_withdrawal,
)


DEFAULT_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def _load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_example(data_dir=DEFAULT_DATA_DIR):
    """Load the advisory, scope, snapshots and replacement evidence."""

    advisory = Advisory.from_dict(_load(os.path.join(data_dir, "advisory.json")))
    scope = InventoryScope.from_dict(_load(os.path.join(data_dir, "scope.json")))
    before = InventorySnapshot.from_dict(
        _load(os.path.join(data_dir, "inventory_before.json")))
    after = InventorySnapshot.from_dict(
        _load(os.path.join(data_dir, "inventory_after.json")))
    replacements = [
        ReplacementEvidence.from_dict(item)
        for item in _load(os.path.join(data_dir, "replacements.json"))
    ]
    return advisory, scope, before, after, replacements


def build_parser():
    parser = argparse.ArgumentParser(
        description="Re-audit a withdrawn advisory against CPE inventory.")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                        help="directory containing the JSON input files")
    parser.add_argument("--output", default=None,
                        help="write the report to this path instead of stdout")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    advisory, scope, before, after, replacements = load_example(args.data_dir)
    report = audit_withdrawal(advisory, scope, before, after, replacements)
    text = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write("\n")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
