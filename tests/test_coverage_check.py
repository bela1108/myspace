import evtx_scripts.evtx_coverage_check as coverage


def make_sample():
    """
    an overlapping-segment sample shared by two cases:

      - records 1..100 are present in the batch,
      - seg-a spans 1..60, seg-b spans 40..100 (overlap at 40..60),
      - case-1 may view both segments, case-2 may view only seg-b.
    """
    segments = {
        "seg-a": coverage.Segment("seg-a", 1, 60),
        "seg-b": coverage.Segment("seg-b", 40, 100),
    }
    authorizations = {
        "case-1": ["seg-a", "seg-b"],
        "case-2": ["seg-b"],
    }
    records = [(1, 100)]
    return segments, authorizations, records


def test_covered_and_first_gap_with_overlapping_segments():
    segments, authorizations, records = make_sample()
    receipts = [
        coverage.Receipt("case-1", "seg-a", 1, 60),
        coverage.Receipt("case-1", "seg-b", 40, 80),
    ]

    report = coverage.check_coverage(segments, authorizations, receipts, records)
    case1 = report["case-1"]

    assert case1["covered"] == [
        {"segment": "seg-a", "first": 1, "last": 60},
        {"segment": "seg-b", "first": 40, "last": 80},
    ]
    assert case1["missing"] == [{"segment": "seg-b", "first": 81, "last": 100}]
    # the first gap is located at the earliest unreviewed record.
    assert case1["first_gap"] == {"segment": "seg-b", "record": 81}
    assert case1["over_privileged"] == []


def test_receipts_are_not_borrowed_across_cases():
    segments, authorizations, records = make_sample()
    receipts = [
        # case-1 fully reviews seg-b, which case-2 is also authorized for.
        coverage.Receipt("case-1", "seg-b", 40, 100),
    ]

    report = coverage.check_coverage(segments, authorizations, receipts, records)

    assert report["case-1"]["missing"] == [{"segment": "seg-a", "first": 1, "last": 60}]
    # case-2 cannot borrow case-1's receipts: its whole scope is missing.
    assert report["case-2"]["covered"] == []
    assert report["case-2"]["missing"] == [{"segment": "seg-b", "first": 40, "last": 100}]
    assert report["case-2"]["first_gap"] == {"segment": "seg-b", "record": 40}


def test_over_privileged_receipt_on_unauthorized_segment():
    segments, authorizations, records = make_sample()
    receipts = [
        # case-2 is not authorized for seg-a at all.
        coverage.Receipt("case-2", "seg-a", 1, 60),
        coverage.Receipt("case-2", "seg-b", 40, 100),
    ]

    report = coverage.check_coverage(segments, authorizations, receipts, records)
    case2 = report["case-2"]

    assert case2["missing"] == []
    assert case2["over_privileged"] == [
        {"segment": "seg-a", "first": 1, "last": 60, "reason": "segment-not-authorized"}
    ]


def test_over_privileged_receipt_beyond_segment_bounds():
    segments, authorizations, records = make_sample()
    receipts = [
        # the receipt runs past the end of seg-a into records the
        # segment does not contain.
        coverage.Receipt("case-1", "seg-a", 1, 70),
        coverage.Receipt("case-1", "seg-b", 40, 100),
    ]

    report = coverage.check_coverage(segments, authorizations, receipts, records)
    case1 = report["case-1"]

    assert case1["missing"] == []
    assert case1["over_privileged"] == [
        {"segment": "seg-a", "first": 61, "last": 70, "reason": "receipt-outside-segment-bounds"}
    ]


def test_scope_is_limited_to_records_present():
    segments, authorizations, _ = make_sample()
    receipts = [coverage.Receipt("case-1", "seg-b", 40, 100)]
    # only records 1..90 were actually collected.
    records = [(1, 90)]

    report = coverage.check_coverage(segments, authorizations, receipts, records)
    case1 = report["case-1"]

    # records 91..100 are out of scope, so only seg-a is missing.
    assert case1["missing"] == [{"segment": "seg-a", "first": 1, "last": 60}]
    assert case1["first_gap"] == {"segment": "seg-a", "record": 1}


def test_interval_helpers():
    assert coverage.union_intervals([(5, 8), (1, 3), (3, 4), (20, 22)]) == [(1, 8), (20, 22)]
    assert coverage.intersect_intervals([(1, 10)], [(3, 5), (8, 20)]) == [(3, 5), (8, 10)]
    assert coverage.subtract_intervals([(1, 10)], [(3, 5), (8, 20)]) == [(1, 2), (6, 7)]
