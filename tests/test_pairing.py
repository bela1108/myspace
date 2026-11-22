import io
import json

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.exceptions import PairingInputError
from pcapng.pairing import (
    ForensicPairer,
    PacketObservation,
    TimeWindow,
    iter_packet_observations,
    pair_observations,
    pair_pcapng,
)


HEADER = b"\x00\x11\x22\x33\x44\x55\x66\x77\x08\x00"


def _observation(side, timestamp, payload, packet_len=None, direction=None):
    return PacketObservation(
        side=side,
        timestamp=timestamp,
        packet_data=payload,
        packet_len=packet_len,
        direction=direction,
    )


def _make_capture(packets, interface_name, snaplen):
    """Build a one-section synthetic pcapng capture in memory."""

    stream = io.BytesIO()
    section = blocks.SectionHeader(endianness="<")
    section.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=snaplen,
        options={"if_name": interface_name},
    )
    writer = FileWriter(stream, section)

    for timestamp, payload, packet_len in packets:
        packet = section.new_member(blocks.EnhancedPacket)
        packet.timestamp_high = timestamp >> 32
        packet.timestamp_low = timestamp & 0xFFFFFFFF
        packet.packet_data = payload
        packet.packet_len = packet_len
        writer.write_block(packet)

    return stream.getvalue()


def test_two_ended_synthetic_capture_locates_truncation():
    full_payload = HEADER + bytes(range(54))
    assert len(full_payload) == 64

    left = _make_capture(
        [(1000000000, full_payload[:32], len(full_payload))],
        interface_name="left-lan",
        snaplen=32,
    )
    right = _make_capture(
        [(1000000400, full_payload, len(full_payload))],
        interface_name="right-wan",
        snaplen=0,
    )

    report = pair_pcapng(
        io.BytesIO(left),
        io.BytesIO(right),
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.summary() == (
        "paired=1, unresolved=0, ignored=0, truncated_pairs=1"
    )
    assert report.matches is report.pairs
    assert len(report.pairs) == 1
    pair = report.pairs[0]

    assert pair.left.interface_name == "left-lan"
    assert pair.right.interface_name == "right-wan"
    assert pair.left.interface_id == pair.right.interface_id == 0
    assert pair.left.packet_len == pair.right.packet_len == 64
    assert pair.left.captured_len == 32
    assert pair.right.captured_len == 64
    assert pair.common_prefix_length == 32
    assert pair.common_prefix == full_payload[:32]
    assert pair.truncated_sides == ("left",)
    assert pair.truncated_side == "left"
    assert pair.first_truncation_offset == 32
    assert pair.left_truncated_at == 32
    assert pair.right_truncated_at is None
    assert pair.time_delta == pytest.approx(0.0004)

    truncation = pair.truncation_for("left")
    assert truncation.offset == 32
    assert truncation.first_missing_byte == 32
    assert truncation.missing_bytes == 32

    encoded = json.loads(report.to_json(include_prefix_hex=True))
    assert encoded["summary"]["truncated_pairs"] == 1
    assert encoded["pairs"][0]["truncations"] == [
        {
            "side": "left",
            "offset": 32,
            "first_missing_byte": 32,
            "captured_length": 32,
            "packet_length": 64,
            "missing_bytes": 32,
            "direction": "outbound",
            "interface_id": 0,
            "ordinal": 0,
            "source": None,
        }
    ]


def test_repeated_prefix_is_not_automatically_paired():
    prefix = HEADER + b"same-prefix"
    packet_len = len(prefix) + 4

    left_a = _observation("left", 10.0, prefix + b"AAAA", packet_len, "outbound")
    left_b = _observation("left", 10.0, prefix + b"BBBB", packet_len, "outbound")
    right = _observation("right", 10.0, prefix, packet_len, "inbound")

    report = pair_observations(
        [left_a, left_b],
        [right],
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.pairs == ()
    assert report.paired_count == 0
    assert report.unresolved_count == 3

    by_label = {
        item.observation.label: item for item in report.unresolved
    }
    assert by_label["left#0"].reason == "not_mutually_unique"
    assert by_label["left#1"].reason == "not_mutually_unique"
    assert by_label["right#0"].reason == "multiple_candidates"
    assert len(by_label["right#0"].candidates) == 2


def test_different_payload_with_same_header_stays_unresolved():
    left = _observation("left", 20.0, HEADER + b"A" * 20, 30, "outbound")
    right = _observation("right", 20.0001, HEADER + b"B" * 20, 30, "inbound")

    report = pair_observations(
        [left],
        [right],
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.pairs == ()
    assert report.ambiguous == ()
    assert report.unresolved_count == 2
    assert all(
        item.reason == "payload_conflict" for item in report.unresolved
    )
    assert all(
        item.near_misses[0].common_prefix_length == len(HEADER)
        for item in report.unresolved
    )


def test_finite_time_window_disambiguates_repeated_payloads():
    payload = HEADER + b"duplicate"
    packet_len = len(payload)
    left = [
        _observation("left", 30.0, payload, packet_len, "outbound"),
        _observation("left", 30.1, payload, packet_len, "outbound"),
    ]
    right = [
        _observation("right", 30.001, payload, packet_len, "inbound"),
        _observation("right", 30.101, payload, packet_len, "inbound"),
    ]

    narrow = pair_observations(
        left,
        right,
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.002,
    )
    assert narrow.paired_count == 2
    assert narrow.unresolved_count == 0
    assert [pair.time_delta for pair in narrow.pairs] == pytest.approx(
        [0.001, 0.001]
    )

    wide = pair_observations(
        left,
        right,
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.2,
    )
    assert wide.pairs == ()
    assert wide.unresolved_count == 4
    assert all(
        item.reason in ("multiple_candidates", "not_mutually_unique")
        for item in wide.unresolved
    )


@pytest.mark.parametrize(
    "value", [float("inf"), float("-inf"), float("nan"), -0.001]
)
def test_time_window_must_be_finite_and_non_negative(value):
    with pytest.raises(PairingInputError):
        TimeWindow(value)

    with pytest.raises(PairingInputError):
        pair_observations(
            [_observation("left", 1.0, b"x", direction="outbound")],
            [_observation("right", 1.0, b"x", direction="inbound")],
            left_direction="outbound",
            right_direction="inbound",
            max_time_delta=value,
        )


def test_time_window_is_required():
    with pytest.raises(PairingInputError, match="finite time window"):
        pair_observations(
            [_observation("left", 1.0, b"x", direction="outbound")],
            [_observation("right", 1.0, b"x", direction="inbound")],
            left_direction="outbound",
            right_direction="inbound",
        )


def test_direction_filter_accounts_for_ignored_observations():
    left = [
        _observation("left", 40.0, b"abcdef", 6, "outbound"),
        _observation("left", 40.0, b"abcdef", 6, "inbound"),
    ]
    right = [_observation("right", 40.0, b"abcdef", 6, "inbound")]

    report = pair_observations(
        left,
        right,
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.paired_count == 1
    assert report.ignored_count == 1
    assert report.ignored[0].observation.direction == "inbound"


def test_different_truncation_offsets_pair_and_report_both_sides():
    full_payload = HEADER + bytes(range(90))
    left = _observation("left", 50.0, full_payload[:20], len(full_payload), "outbound")
    right = _observation(
        "right", 50.0, full_payload[:40], len(full_payload), "inbound"
    )

    report = pair_observations(
        [left],
        [right],
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.paired_count == 1
    pair = report.pairs[0]
    assert pair.common_prefix_length == 20
    assert pair.truncated_sides == ("left", "right")
    assert pair.truncated_side is None
    assert pair.first_truncation_offset == 20
    assert [(item.side, item.offset) for item in pair.truncations] == [
        ("left", 20),
        ("right", 40),
    ]

    strict = pair_observations(
        [left],
        [right],
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
        require_complete_side=True,
    )
    assert strict.pairs == ()
    assert all(
        item.reason == "unverified_truncated_suffix"
        for item in strict.unresolved
    )


def test_header_only_match_is_not_certified():
    left = _observation("left", 55.0, HEADER, 200, "outbound")
    right = _observation("right", 55.0, HEADER, 200, "inbound")

    report = pair_observations(
        [left],
        [right],
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.pairs == ()
    assert all(
        item.reason == "unverified_truncated_suffix"
        for item in report.unresolved
    )

    explicit = pair_observations(
        [left],
        [right],
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
        allow_identical_partial_pairing=True,
    )
    assert explicit.paired_count == 1


def test_simple_packet_without_timestamp_stays_unresolved():
    payload = HEADER + b"timeless"
    stream = io.BytesIO()
    section = blocks.SectionHeader(endianness="<")
    section.new_member(
        blocks.InterfaceDescription, link_type=1, snaplen=len(payload)
    )
    writer = FileWriter(stream, section)
    packet = section.new_member(blocks.SimplePacket)
    packet.packet_data = payload
    packet.packet_len = len(payload)
    writer.write_block(packet)
    capture = stream.getvalue()

    observations = list(iter_packet_observations(io.BytesIO(capture)))
    assert observations[0].timestamp is None

    report = pair_observations(
        observations,
        [_observation("right", 60.0, payload, len(payload), "inbound")],
        left_direction=None,
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.pairs == ()
    reasons = {item.reason for item in report.unresolved}
    assert reasons == {"missing_timestamp"}


def test_zero_length_payload_is_not_evidence():
    left = _observation("left", 70.0, b"", 0, "outbound")
    right = _observation("right", 70.0, b"", 0, "inbound")

    report = pair_observations(
        [left],
        [right],
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.pairs == ()
    assert report.unresolved_count == 2
    assert all(
        item.reason == "insufficient_common_prefix"
        for item in report.unresolved
    )


def test_direction_convenience_label_applies_to_both_sides():
    left = _observation("left", 80.0, b"same-direction", direction="flow")
    right = _observation("right", 80.0, b"same-direction", direction="flow")

    report = pair_observations(
        [left], [right], direction="flow", max_time_delta=0.001
    )

    assert report.paired_count == 1
    assert report.left_direction == report.right_direction == "flow"


def test_direction_alias_cannot_be_combined_with_explicit_side_labels():
    with pytest.raises(PairingInputError, match="not both"):
        pair_observations(
            [],
            [],
            direction="flow",
            left_direction="outbound",
            max_time_delta=0.001,
        )


def test_forensic_pairer_wrapper_uses_configured_window():
    pairer = ForensicPairer(max_time_delta=0.001)
    left = _observation("left", 90.0, b"wrapper", direction="outbound")
    right = _observation("right", 90.0005, b"wrapper", direction="inbound")

    report = pairer.pair(
        [left],
        [right],
        left_direction="outbound",
        right_direction="inbound",
    )

    assert report.paired_count == 1


def test_same_observation_object_twice_is_not_collapsed():
    left = _observation("left", 95.0, b"same-object", direction="outbound")
    right = _observation("right", 95.0, b"same-object", direction="inbound")

    report = pair_observations(
        [left, left],
        [right],
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.pairs == ()
    assert report.unresolved_count == 3


def test_pair_observations_accepts_raw_blocks_and_direction_labels():
    payload = HEADER + b"raw-block"
    left = _make_capture([(99000000, payload, len(payload))], "left", 0)
    right = _make_capture([(99000100, payload, len(payload))], "right", 0)

    def packet_blocks(capture):
        return [
            block
            for block in FileScanner(io.BytesIO(capture))
            if isinstance(block, blocks.EnhancedPacket)
        ]

    report = pair_observations(
        packet_blocks(left),
        packet_blocks(right),
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.001,
    )

    assert report.paired_count == 1
    assert report.pairs[0].left.direction == "outbound"
    assert report.pairs[0].right.direction == "inbound"


def test_direction_pair_and_time_window_tuple_are_accepted():
    left = _observation("left", 100.0, b"tuple-config", direction="out")
    right = _observation("right", 100.0005, b"tuple-config", direction="in")

    report = pair_observations(
        [left],
        [right],
        direction=("out", "in"),
        time_window=(0.0, 0.001),
    )

    assert report.paired_count == 1
    assert report.time_window.min_delta == 0.0
    assert report.time_window.max_delta == 0.001
