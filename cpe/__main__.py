# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import argparse
import json
import sys

from .adjudication_api import run_adjudication


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Adjudicate CPE announcements during change windows."
    )
    parser.add_argument("input", nargs="?", default="-")
    parser.add_argument("--as-of", dest="as_of")
    parser.add_argument("--output", "-o", default="-")
    parser.add_argument("--remediation-only", action="store_true")
    args = parser.parse_args(argv)

    if args.input == "-":
        payload = json.load(sys.stdin)
    else:
        with open(args.input, "r", encoding="utf-8") as handle:
            payload = json.load(handle)

    result = run_adjudication(payload, as_of=args.as_of)
    output = (
        result.remediation_list()
        if args.remediation_only
        else result.to_dict()
    )
    rendered = json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output == "-":
        sys.stdout.write(rendered + "\n")
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
