#!/usr/bin/env python
"""Print a read-only forensic pairing report for two pcap-ng captures."""

import argparse
import sys

from pcapng.exceptions import PairingInputError
from pcapng.pairing import pair_pcapng


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", help="pcap-ng capture from the left end")
    parser.add_argument("right", help="pcap-ng capture from the right end")
    parser.add_argument("--left-direction", required=True)
    parser.add_argument("--right-direction", required=True)
    parser.add_argument(
        "--max-time-delta",
        required=True,
        type=float,
        help="maximum absolute timestamp difference, in seconds",
    )
    parser.add_argument(
        "--min-common-prefix",
        default=1,
        type=int,
        help="minimum identical captured bytes required as evidence",
    )
    parser.add_argument(
        "--include-payload",
        action="store_true",
        help="include full captured payloads as hexadecimal in the JSON report",
    )
    parser.add_argument(
        "--include-prefix-hex",
        action="store_true",
        help="include each matched common prefix as hexadecimal",
    )
    parser.add_argument(
        "--require-complete-side",
        action="store_true",
        help="require at least one side to have captured the whole packet",
    )
    parser.add_argument(
        "--allow-identical-partial-pairing",
        action="store_true",
        help="pair two captures truncated at exactly the same offset",
    )
    args = parser.parse_args(argv)

    try:
        report = pair_pcapng(
            args.left,
            args.right,
            left_direction=args.left_direction,
            right_direction=args.right_direction,
            max_time_delta=args.max_time_delta,
            min_common_prefix=args.min_common_prefix,
            require_complete_side=args.require_complete_side,
            allow_identical_partial_pairing=(
                args.allow_identical_partial_pairing
            ),
        )
    except PairingInputError as exc:
        parser.error(str(exc))

    print(
        report.to_json(
            indent=2,
            include_payload=args.include_payload,
            include_prefix_hex=args.include_prefix_hex,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
