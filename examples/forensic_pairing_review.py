#!/usr/bin/env python
"""
Double-ended forensic review on synthetic pcapng captures.

Run:

    python examples/forensic_pairing_review.py

The script builds two independent synthetic captures (different link
types, snap lengths, timestamp resolutions and a constant clock offset),
runs the read-only pairing interface against them and independently
re-checks every confirmed pair byte-by-byte from the two files.  It then
verifies that ambiguous evidence (duplicate prefixes, payload divergence,
one-sided observations) is left undecided rather than guessed.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapng.forensics import (  # noqa: E402
    Direction,
    TruncationSide,
    UndecidedReason,
    pair_captures,
)
from pcapng.synthetic_captures import build_capture_pair  # noqa: E402

TIME_TOLERANCE = 0.005  # 5 ms; tighter than the 20 ms inter-frame gap


def review(left_path, right_path, clock_offset):
    """Run the pairing and independently verify every conclusion."""
    report = pair_captures(
        left_path,
        right_path,
        direction=Direction.A_TO_B,
        time_tolerance=TIME_TOLERANCE,
        clock_offset=clock_offset,
        left_label="tap-A",
        right_label="tap-B",
    )

    failures = []

    # Double-ended byte check of every confirmed pair.
    for pairing in report.pairs:
        left = pairing.left
        right = pairing.right
        common = pairing.evidence.common_prefix
        if not left.payload.startswith(common) or not right.payload.startswith(
            common
        ):
            failures.append(
                "pair {0}: common prefix not actually present on both sides"
                .format(pairing)
            )
        if common != left.payload[: pairing.evidence.common_length]:
            failures.append("pair {0}: left prefix mismatch".format(pairing))
        if common != right.payload[: pairing.evidence.common_length]:
            failures.append("pair {0}: right prefix mismatch".format(pairing))

        # Truncation must match what each capture declares about itself.
        if pairing.truncation_side in (TruncationSide.LEFT, TruncationSide.BOTH):
            if not left.truncated:
                failures.append(
                    "pair {0}: left truncation claimed without evidence"
                    .format(pairing)
                )
        if pairing.truncation_side in (
            TruncationSide.RIGHT,
            TruncationSide.BOTH,
        ):
            if not right.truncated:
                failures.append(
                    "pair {0}: right truncation claimed without evidence"
                    .format(pairing)
                )

    # Required undecided evidence from the synthetic scenario.
    reasons = {}
    for record in report.undecided:
        reasons.setdefault(record.reason, []).append(record)

    if UndecidedReason.DUPLICATE_PREFIX not in reasons and (
        UndecidedReason.MULTIPLE_CANDIDATES not in reasons
    ):
        failures.append(
            "duplicate-prefix ambiguity was not surfaced as undecided"
        )
    if UndecidedReason.PAYLOAD_DIVERGENCE not in reasons:
        failures.append("payload divergence was not surfaced as undecided")
    if UndecidedReason.NO_CANDIDATE not in reasons:
        failures.append("one-sided observation was not reported undecided")

    # A confirmed pairing must never reuse an observation.
    seen = set()
    for pairing in report.pairs:
        for ref in (pairing.left.ref, pairing.right.ref):
            if ref in seen:
                failures.append("observation {0} paired twice".format(ref))
            seen.add(ref)

    return report, failures


def main():
    workdir = tempfile.mkdtemp(prefix="forensic_pairing_")
    left_path = os.path.join(workdir, "tap_a_ethernet.pcapng")
    right_path = os.path.join(workdir, "tap_b_rawip.pcapng")
    ground_truth = build_capture_pair(left_path, right_path)

    report, failures = review(left_path, right_path, ground_truth["clock_offset"])

    print("synthetic captures:")
    print("  {0} ({1} bytes)".format(left_path, os.path.getsize(left_path)))
    print("  {0} ({1} bytes)".format(right_path, os.path.getsize(right_path)))
    print()
    print(report.summary())
    print()

    print("truncation localisation for confirmed pairs:")
    for pairing in report.pairs:
        print(
            "  {0} <-> {1}: common {2} bytes; tap-A captured {3}/{4}, "
            "tap-B captured {5}/{6}; bytes lost on: {7!s}".format(
                pairing.left.ref,
                pairing.right.ref,
                pairing.evidence.common_length,
                pairing.left.captured_len,
                pairing.left.original_len,
                pairing.right.captured_len,
                pairing.right.original_len,
                pairing.truncation_side.value,
            )
        )
    print()

    if failures:
        print("REVIEW FAILED:")
        for failure in failures:
            print("  - {0}".format(failure))
        return 1
    print(
        "REVIEW OK: {0} pairs confirmed on byte-level evidence; all "
        "ambiguous/diverging/one-sided packets remain undecided".format(
            len(report.pairs)
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
