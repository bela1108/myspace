#!/usr/bin/env python

"""
Offline review-coverage check for log batches shared by multiple cases.

A single log batch (record positions) may be carved into collection
segments, and each case is only authorized to view specific segments.
Review receipts are issued per case and per segment; receipts from one
case never count towards another case's coverage.

For every case this tool intersects four inputs:

  - record positions: the record numbers actually present in the batch,
  - collection segments: named, possibly overlapping record ranges,
  - case authorizations: the segments a case is allowed to view,
  - review receipts: per-case, per-segment reviewed record ranges,

and reports, per case:

  - covered: authorized record ranges backed by that case's receipts,
  - missing: authorized record ranges with no receipt, including the
    first gap so overlapping segment layouts can be audited from the
    earliest unreviewed record,
  - over_privileged: receipts reaching beyond the case's authorization,
    either targeting a segment the case may not view or extending past
    the bounds of the target segment.

Inputs come from a JSON manifest, and record positions may optionally
be taken straight from an .evtx file:

  {
    "records": [[1, 100]],
    "segments": [{"id": "seg-a", "first": 1, "last": 60}],
    "authorizations": {"case-1": ["seg-a"]},
    "receipts": [{"case": "case-1", "segment": "seg-a", "first": 1, "last": 60}]
  }

Exit status is 0 when every case is fully covered with no
over-privileged receipts, and 1 otherwise.
"""

import json
import argparse
from dataclasses import dataclass

# an inclusive record-number interval: (first, last)
Interval = tuple


def union_intervals(intervals):
    """
    merge overlapping or adjacent inclusive intervals.

    @type intervals: list of (int, int)
    @rtype: list of (int, int)
    """
    merged = []
    for first, last in sorted(intervals):
        if first > last:
            continue
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return merged


def intersect_intervals(left, right):
    """
    intersect two lists of inclusive intervals.

    @type left: list of (int, int)
    @type right: list of (int, int)
    @rtype: list of (int, int)
    """
    result = []
    for first_a, last_a in left:
        for first_b, last_b in right:
            first = max(first_a, first_b)
            last = min(last_a, last_b)
            if first <= last:
                result.append((first, last))
    return union_intervals(result)


def subtract_intervals(scope, cover):
    """
    compute the portions of scope not covered by cover.

    @type scope: list of (int, int)
    @type cover: list of (int, int)
    @rtype: list of (int, int)
    """
    remaining = []
    for first, last in scope:
        cursor = first
        for cover_first, cover_last in union_intervals(cover):
            if cover_last < cursor:
                continue
            if cover_first > last:
                break
            if cover_first > cursor:
                remaining.append((cursor, cover_first - 1))
            cursor = max(cursor, cover_last + 1)
            if cursor > last:
                break
        if cursor <= last:
            remaining.append((cursor, last))
    return remaining


@dataclass
class Segment:
    """a named collection segment spanning an inclusive record range."""

    segment_id: str
    first: int
    last: int


@dataclass
class Receipt:
    """a review receipt issued to one case for one segment."""

    case_id: str
    segment_id: str
    first: int
    last: int


def check_case_coverage(case_id, segments, authorizations, receipts, records):
    """
    compute the coverage report for a single case.

    receipts are matched strictly by (case_id, segment_id), so a case
    can never borrow coverage from another case's receipts.

    @type case_id: str
    @type segments: dict of str to Segment
    @type authorizations: dict of str to list of str
    @type receipts: list of Receipt
    @type records: list of (int, int)
    @rtype: dict
    """
    authorized_ids = authorizations.get(case_id, [])
    own_receipts = [r for r in receipts if r.case_id == case_id]

    covered = []
    missing = []
    over_privileged = []

    for segment_id in authorized_ids:
        segment = segments.get(segment_id)
        if segment is None:
            over_privileged.append(
                {
                    "segment": segment_id,
                    "first": None,
                    "last": None,
                    "reason": "authorized-segment-unknown",
                }
            )
            continue

        bounds = [(segment.first, segment.last)]
        scope = intersect_intervals(bounds, records)

        segment_receipts = [r for r in own_receipts if r.segment_id == segment_id]
        reviewed = union_intervals([(r.first, r.last) for r in segment_receipts])

        # receipt portions outside the segment bounds are over-reach.
        for receipt_first, receipt_last in subtract_intervals(reviewed, bounds):
            over_privileged.append(
                {
                    "segment": segment_id,
                    "first": receipt_first,
                    "last": receipt_last,
                    "reason": "receipt-outside-segment-bounds",
                }
            )

        valid = intersect_intervals(reviewed, bounds)
        for first, last in intersect_intervals(scope, valid):
            covered.append({"segment": segment_id, "first": first, "last": last})
        for first, last in subtract_intervals(scope, valid):
            missing.append({"segment": segment_id, "first": first, "last": last})

    # receipts naming a segment the case is not authorized to view.
    for receipt in own_receipts:
        if receipt.segment_id not in authorized_ids:
            over_privileged.append(
                {
                    "segment": receipt.segment_id,
                    "first": receipt.first,
                    "last": receipt.last,
                    "reason": "segment-not-authorized",
                }
            )

    covered.sort(key=lambda span: (span["first"], span["segment"]))
    missing.sort(key=lambda span: (span["first"], span["segment"]))

    first_gap = None
    if missing:
        earliest = min(missing, key=lambda span: span["first"])
        first_gap = {"segment": earliest["segment"], "record": earliest["first"]}

    return {
        "covered": covered,
        "missing": missing,
        "first_gap": first_gap,
        "over_privileged": over_privileged,
    }


def check_coverage(segments, authorizations, receipts, records):
    """
    compute coverage reports for every case named by the authorizations
    or the receipts.

    @type segments: dict of str to Segment
    @type authorizations: dict of str to list of str
    @type receipts: list of Receipt
    @type records: list of (int, int)
    @rtype: dict of str to dict
    """
    case_ids = sorted(set(authorizations) | {r.case_id for r in receipts})
    return {
        case_id: check_case_coverage(case_id, segments, authorizations, receipts, records) for case_id in case_ids
    }


def load_manifest(path):
    """
    load segments, authorizations, receipts, and record ranges from a
    JSON manifest.

    @type path: str
    @rtype: (dict, dict, list, list of (int, int))
    """
    with open(path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    segments = {}
    for entry in manifest.get("segments", []):
        segment = Segment(segment_id=entry["id"], first=entry["first"], last=entry["last"])
        segments[segment.segment_id] = segment

    authorizations = {case_id: list(ids) for case_id, ids in manifest.get("authorizations", {}).items()}

    receipts = [
        Receipt(case_id=entry["case"], segment_id=entry["segment"], first=entry["first"], last=entry["last"])
        for entry in manifest.get("receipts", [])
    ]

    records = union_intervals([tuple(span) for span in manifest.get("records", [])])
    return segments, authorizations, receipts, records


def evtx_record_intervals(path):
    """
    read the record numbers present in an .evtx file as inclusive
    intervals.

    @type path: str
    @rtype: list of (int, int)
    """
    import Evtx.Evtx as evtx

    numbers = []
    with evtx.Evtx(path) as log:
        for record in log.records():
            numbers.append((record.record_num(), record.record_num()))
    return union_intervals(numbers)


def main():
    parser = argparse.ArgumentParser(
        description="Offline review-coverage check for log batches shared by multiple cases."
    )
    parser.add_argument("manifest", type=str, help="Path to the JSON coverage manifest")
    parser.add_argument(
        "--evtx",
        type=str,
        default=None,
        help="Path to an EVTX file; record positions are taken from it instead of the manifest",
    )
    args = parser.parse_args()

    segments, authorizations, receipts, records = load_manifest(args.manifest)
    if args.evtx is not None:
        records = evtx_record_intervals(args.evtx)

    report = check_coverage(segments, authorizations, receipts, records)
    print(json.dumps({"records": records, "cases": report}, indent=2))

    ok = all(not case["missing"] and not case["over_privileged"] for case in report.values())
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
