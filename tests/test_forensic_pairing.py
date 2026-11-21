"""Tests for the read-only forensic pairing interface."""

import os
import tempfile

import pytest

from pcapng.forensics import (
    Direction,
    Observation,
    PairingReport,
    PrefixEvidence,
    TruncationSide,
    UndecidedReason,
    directions_compatible,
    extract_payload,
    load_observations,
    pair_captures,
)
from pcapng.synthetic_captures import (
    build_capture_pair,
    ethernet_frame,
    raw_ip_frame,
)
from pcapng.constants.link_types import LINKTYPE_ETHERNET, LINKTYPE_RAW


@pytest.fixture(scope="module")
def captures():
    tmp = tempfile.mkdtemp(prefix="forensic-test-")
    left = os.path.join(tmp, "left.pcapng")
    right = os.path.join(tmp, "right.pcapng")
    truth = build_capture_pair(left, right)
    return left, right, truth


@pytest.fixture(scope="module")
def report(captures):
    left, right, truth = captures
    return pair_captures(
        left,
        right,
        direction=Direction.A_TO_B,
        time_tolerance=0.005,
        clock_offset=truth["clock_offset"],
        left_label="tap-A",
        right_label="tap-B",
    )


def _reasons(report):
    return {record.reason for record in report.undecided}


def test_confirmed_pair_count(report):
    assert len(report.pairs) == 4


def test_pairs_are_one_to_one(report):
    left_refs = [pair.left.ref for pair in report.pairs]
    right_refs = [pair.right.ref for pair in report.pairs]
    assert len(left_refs) == len(set(left_refs))
    assert len(right_refs) == len(set(right_refs))


def test_common_prefix_actually_present(report):
    for pair in report.pairs:
        length = pair.evidence.common_length
        assert pair.left.payload[:length] == pair.evidence.common_prefix
        assert pair.right.payload[:length] == pair.evidence.common_prefix
        assert length > 0


def test_clean_pair_has_no_truncation(report):
    clean = report.pairs[0]
    assert clean.truncation_side is TruncationSide.NONE
    assert clean.left.truncated is False
    assert clean.right.truncated is False


def test_truncation_localisation(report):
    sides = [pair.truncation_side for pair in report.pairs]
    assert sides == [
        TruncationSide.NONE,
        TruncationSide.LEFT,
        TruncationSide.RIGHT,
        TruncationSide.BOTH,
    ]
    both = report.pairs[3]
    assert both.truncation_bytes[TruncationSide.LEFT] > 0
    assert both.truncation_bytes[TruncationSide.RIGHT] > 0
    assert both.left.truncated and both.right.truncated


def test_truncation_bytes_match_capture_metadata(report):
    for pair in report.pairs:
        if pair.truncation_side in (TruncationSide.LEFT, TruncationSide.BOTH):
            declared = (
                pair.left.original_len
                - pair.left.captured_len
            )
            assert declared > 0
        if pair.truncation_side in (TruncationSide.RIGHT, TruncationSide.BOTH):
            assert pair.right.original_len - pair.right.captured_len > 0


def test_duplicate_prefix_stays_undecided(report):
    dup = [
        record
        for record in report.undecided
        if record.reason is UndecidedReason.DUPLICATE_PREFIX
    ]
    assert dup, "duplicate-prefix ambiguity must be reported"
    for record in dup:
        assert len(record.candidates) >= 1
        for _, evidence in record.candidates:
            assert evidence.diverges is False


def test_payload_divergence_stays_undecided(report):
    diverging = [
        record
        for record in report.undecided
        if record.reason is UndecidedReason.PAYLOAD_DIVERGENCE
    ]
    assert diverging
    for record in diverging:
        assert any(evidence.diverges for _, evidence in record.candidates)


def test_one_sided_observation_is_no_candidate(report):
    no_candidate = [
        record
        for record in report.undecided
        if record.reason is UndecidedReason.NO_CANDIDATE
    ]
    assert len(no_candidate) == 1
    assert no_candidate[0].observation.ref == "tap-A#6"


def test_no_observation_is_both_paired_and_undecided(report):
    overlap = report.paired_refs & {
        record.observation.ref for record in report.undecided
    }
    assert overlap == set()


def test_time_tolerance_is_limited(report, captures):
    left, right, truth = captures
    tight = pair_captures(
        left,
        right,
        direction=Direction.A_TO_B,
        time_tolerance=0.0001,
        clock_offset=truth["clock_offset"],
        left_label="tap-A",
        right_label="tap-B",
    )
    assert tight.pairs == []
    assert all(
        record.reason is UndecidedReason.NO_CANDIDATE
        for record in tight.undecided
    )


def test_wrong_clock_offset_prevents_pairing(captures):
    left, right, _ = captures
    shifted = pair_captures(
        left,
        right,
        direction=Direction.A_TO_B,
        time_tolerance=0.005,
        clock_offset=1.0,
        left_label="tap-A",
        right_label="tap-B",
    )
    assert shifted.pairs == []


def test_directions_compatible_matrix():
    assert directions_compatible(Direction.A_TO_B, Direction.A_TO_B)
    assert directions_compatible(Direction.A_TO_B, Direction.EITHER)
    assert directions_compatible(Direction.EITHER, Direction.B_TO_A)
    assert not directions_compatible(Direction.A_TO_B, Direction.B_TO_A)


def test_extract_payload_strips_known_headers():
    frame = ethernet_frame(b"hello")
    payload = extract_payload(frame, LINKTYPE_ETHERNET)
    assert payload == raw_ip_frame(b"hello")
    raw = raw_ip_frame(b"hello")
    assert extract_payload(raw, LINKTYPE_RAW) == raw


def test_extract_payload_rejects_unknown_link_type():
    with pytest.raises(ValueError):
        extract_payload(b"\x00" * 10, link_type=999)


def test_prefix_evidence_detects_divergence():
    evidence = PrefixEvidence(b"ABX", b"ABY")
    assert evidence.common_length == 2
    assert evidence.diverges is True
    assert evidence.left_remaining == b"X"
    assert evidence.right_remaining == b"Y"


def test_prefix_evidence_strict_prefix_is_not_divergence():
    evidence = PrefixEvidence(b"ABCDEF", b"ABC")
    assert evidence.common_length == 3
    assert evidence.diverges is False
    assert evidence.right_remaining == b""


def test_load_observations_is_read_only(captures):
    left, right, _ = captures
    before = os.stat(left).st_mtime_ns
    observations = load_observations(left, "tap-A", Direction.A_TO_B)
    after = os.stat(left).st_mtime_ns
    assert before == after
    assert all(isinstance(obs, Observation) for obs in observations)
    assert observations[0].direction is Direction.A_TO_B


def test_report_summary_contains_sections(report):
    text = report.summary()
    assert "Forensic pairing report" in text
    assert "[PAIRED]" in text
    assert "[UNDECIDED]" in text
    assert isinstance(report, PairingReport)


def test_negative_tolerance_rejected(captures):
    left, right, _ = captures
    with pytest.raises(ValueError):
        pair_captures(
            left,
            right,
            direction=Direction.A_TO_B,
            time_tolerance=-1.0,
        )


def test_epb_flags_direction_is_honoured():
    import io

    import pcapng.blocks as blocks
    from pcapng import FileWriter
    from pcapng.structs import EPBFlags
    from pcapng.utils import pack_timestamp_resolution

    def make_capture(path, inout):
        shb = blocks.SectionHeader(endianness="<")
        idb = shb.new_member(
            blocks.InterfaceDescription,
            link_type=LINKTYPE_RAW,
            snaplen=4096,
            options={
                "if_tsresol": pack_timestamp_resolution(10, 6),
            },
        )
        with open(path, "wb") as stream:
            writer = FileWriter(stream, shb)
            flags = EPBFlags()
            flags.inout = inout
            epb = shb.new_member(
                blocks.EnhancedPacket,
                timestamp_high=0,
                timestamp_low=1000,
                packet_data=raw_ip_frame(b"direction-check"),
                options={"epb_flags": flags},
            )
            epb.packet_len = len(epb.packet_data)
            writer.write_block(epb)

    tmp = tempfile.mkdtemp(prefix="forensic-dir-")
    inbound = os.path.join(tmp, "in.pcapng")
    outbound = os.path.join(tmp, "out.pcapng")
    make_capture(inbound, "inbound")
    make_capture(outbound, "outbound")

    in_obs = load_observations(inbound, "in", Direction.EITHER)
    out_obs = load_observations(outbound, "out", Direction.EITHER)
    assert in_obs[0].direction is Direction.B_TO_A
    assert out_obs[0].direction is Direction.A_TO_B
    assert not directions_compatible(
        in_obs[0].direction, out_obs[0].direction
    )


def _obs(ref, timestamp, payload, direction=Direction.A_TO_B,
         link_type=LINKTYPE_RAW, original_len=None, truncated=None):
    from pcapng.forensics import Observation

    original = len(payload) if original_len is None else original_len
    is_truncated = (
        original > len(payload) if truncated is None else truncated
    )
    return Observation(
        source_label=ref.split("#")[0],
        index=int(ref.split("#")[1]),
        timestamp=timestamp,
        direction=direction,
        link_type=link_type,
        interface_id=0,
        frame=payload,
        payload=payload,
        captured_len=len(payload),
        original_len=original,
        truncated=is_truncated,
    )


def test_unexplained_length_difference_rejected():
    from pcapng.forensics import _pair_observations

    # Right side is shorter but its own metadata claims it is complete:
    # no truncation evidence, so pairing must be refused.
    left = _obs("L#0", 1.0, b"ABCDEF")
    right = _obs("R#0", 1.0, b"ABC", original_len=3, truncated=False)
    report = _pair_observations([left], [right], 0.01, 0.0, "L", "R")
    assert report.pairs == []
    assert report.undecided[0].reason is (
        UndecidedReason.TRUNCATION_UNEXPLAINED
    )


def test_declared_truncation_with_too_short_original_rejected():
    from pcapng.forensics import _pair_observations

    # Right declares truncation, yet its claimed original length cannot
    # even cover the bytes the left side holds: contradictory evidence.
    left = _obs("L#0", 1.0, b"ABCDEF")
    right = _obs("R#0", 1.0, b"ABC", original_len=4, truncated=True)
    report = _pair_observations([left], [right], 0.01, 0.0, "L", "R")
    assert report.pairs == []
    assert report.undecided[0].reason is (
        UndecidedReason.TRUNCATION_UNEXPLAINED
    )


def test_direction_mismatch_is_reported():
    from pcapng.forensics import _pair_observations

    left = _obs("L#0", 1.0, b"SAME-PAYLOAD", direction=Direction.A_TO_B)
    right = _obs("R#0", 1.0, b"SAME-PAYLOAD", direction=Direction.B_TO_A)
    report = _pair_observations([left], [right], 0.01, 0.0, "L", "R")
    assert report.pairs == []
    assert report.undecided[0].reason is UndecidedReason.DIRECTION_MISMATCH


def test_many_to_one_identical_frames_undecided():
    from pcapng.forensics import _pair_observations

    left_a = _obs("L#0", 1.0, b"IDENTICAL")
    left_b = _obs("L#1", 1.0, b"IDENTICAL")
    right = _obs("R#0", 1.0, b"IDENTICAL")
    report = _pair_observations(
        [left_a, left_b], [right], 0.01, 0.0, "L", "R"
    )
    assert report.pairs == []
    assert all(
        record.reason is UndecidedReason.DUPLICATE_PREFIX
        for record in report.undecided
    )
