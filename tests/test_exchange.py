import io
import struct

from pcapng import FileScanner
from pcapng.blocks import (
    EnhancedPacket,
    InterfaceDescription,
    SectionHeader,
    SimplePacket,
    UnknownBlock,
)
from pcapng.constants.block_types import (
    BLK_ENHANCED_PACKET,
    BLK_INTERFACE,
    BLK_INTERFACE_STATS,
    BLK_NAME_RESOLUTION,
    BLK_PACKET_SIMPLE,
    BLK_SECTION_HEADER,
)
from pcapng.exchange import (
    ACTION_DROP,
    ACTION_REJECT,
    ACTION_SKIP,
    DECISION_ACCEPT,
    DECISION_ACCEPT_WITH_LOSS,
    DECISION_REJECT,
    DiscardPolicy,
    ReceiverCapabilities,
    preflight_exchange,
    validate_output,
)


CUSTOM_EXTENSION = 0x40000BAD


def _block(block_type, body, endianness):
    padding = (-len(body)) % 4
    total_length = 12 + len(body) + padding
    return (
        struct.pack(endianness + "II", block_type, total_length)
        + body
        + (b"\x00" * padding)
        + struct.pack(endianness + "I", total_length)
    )


def _section_header(endianness):
    body = (
        struct.pack(endianness + "I", 0x1A2B3C4D)
        + struct.pack(endianness + "HH", 1, 0)
        + struct.pack(endianness + "q", -1)
    )
    return _block(BLK_SECTION_HEADER, body, endianness)


def _interface_description(endianness):
    body = struct.pack(endianness + "HHI", 1, 0, 65535)
    return _block(BLK_INTERFACE, body, endianness)


def _enhanced_packet(endianness, packet, timestamp=1):
    body = struct.pack(
        endianness + "IIIII",
        0,
        0,
        timestamp,
        len(packet),
        len(packet),
    )
    return _block(BLK_ENHANCED_PACKET, body + packet, endianness)


def _simple_packet(endianness, packet):
    body = struct.pack(endianness + "I", len(packet)) + packet
    return _block(BLK_PACKET_SIMPLE, body, endianness)


def _custom_block(endianness, payload):
    return _block(CUSTOM_EXTENSION, payload, endianness)


def _name_resolution(endianness):
    return _block(BLK_NAME_RESOLUTION, struct.pack(endianness + "HH", 0, 0), endianness)


def _interface_statistics(endianness, interface_id):
    body = struct.pack(endianness + "III", interface_id, 0, 0)
    return _block(BLK_INTERFACE_STATS, body, endianness)


def _mixed_endian_sample():
    little_section = (
        _section_header("<")
        + _interface_description("<")
        + _enhanced_packet("<", b"little-section-packet")
    )
    big_section = (
        _section_header(">")
        + _interface_description(">")
        + _simple_packet(">", b"big-section-packet")
        + _custom_block(">", b"opaque-extension")
    )
    return little_section + big_section


def _archive_receiver():
    return ReceiverCapabilities(
        ("SHB", "IDB", "EPB", "SPB", "NRB", "ISB"),
        allow_unknown_blocks=True,
        name="archive-reader",
    )


def _enhanced_only_receiver():
    return ReceiverCapabilities(
        ("SHB", "IDB", "EPB"),
        allow_unknown_blocks=True,
        name="enhanced-only",
    )


def test_mixed_endian_receivers_reach_different_decisions():
    sample = _mixed_endian_sample()

    # The legacy scanner can walk the input, but that does not prove that
    # either receiver can interpret the packet evidence inside it.
    scanned = list(FileScanner(io.BytesIO(sample)))
    assert isinstance(scanned[0], SectionHeader)
    assert scanned[0].endianness == "<"
    assert isinstance(scanned[1], InterfaceDescription)
    assert isinstance(scanned[2], EnhancedPacket)
    assert scanned[3].endianness == ">"
    assert isinstance(scanned[5], SimplePacket)
    assert isinstance(scanned[6], UnknownBlock)

    archive_report = preflight_exchange(sample, _archive_receiver())
    enhanced_report = preflight_exchange(sample, _enhanced_only_receiver())

    assert archive_report.exchangeable is True
    assert archive_report.decision == DECISION_ACCEPT
    assert archive_report.readable_again is True
    assert archive_report.lossless is True
    assert archive_report.required_unknown == []

    assert enhanced_report.exchangeable is False
    assert enhanced_report.decision == DECISION_REJECT
    assert enhanced_report.output is None
    assert enhanced_report.readable_again is False
    assert [block.block_type for block in enhanced_report.required_unknown] == [
        BLK_PACKET_SIMPLE
    ]


def test_accepted_output_is_re_readable_and_keeps_mixed_endianness():
    sample = _mixed_endian_sample()
    report = preflight_exchange(sample, _archive_receiver())

    assert report.to_bytes() == report.output
    assert validate_output(report.output, _archive_receiver()).ok is True

    blocks = list(FileScanner(io.BytesIO(report.output)))
    section_headers = [block for block in blocks if isinstance(block, SectionHeader)]
    assert [block.endianness for block in section_headers] == ["<", ">"]
    assert [
        block.packet_data
        for block in blocks
        if isinstance(block, (EnhancedPacket, SimplePacket))
    ] == [b"little-section-packet", b"big-section-packet"]


def test_skippable_extension_is_kept_and_reported_separately():
    sample = _mixed_endian_sample()
    report = preflight_exchange(sample, _archive_receiver())

    assert [block.block_type for block in report.skippable_extensions] == [
        CUSTOM_EXTENSION
    ]
    extension = report.skippable_extensions[0]
    assert extension.action == ACTION_SKIP
    assert extension.section == 1
    assert extension.supported is False
    assert b"opaque-extension" in report.output


def test_strict_receiver_must_interpret_unknown_extension():
    sample = _mixed_endian_sample()
    receiver = ReceiverCapabilities(
        ("SHB", "IDB", "EPB", "SPB", "NRB", "ISB"),
        allow_unknown_blocks=False,
        name="strict-reader",
    )
    report = preflight_exchange(sample, receiver)

    assert report.exchangeable is False
    assert [block.block_type for block in report.required_unknown] == [CUSTOM_EXTENSION]
    assert report.required_unknown[0].action == ACTION_REJECT


def test_policy_drop_accepts_with_separate_interface_evidence_loss():
    sample = _mixed_endian_sample()
    report = preflight_exchange(
        sample,
        _enhanced_only_receiver(),
        DiscardPolicy(discardable_block_types=("SPB",)),
    )

    assert report.exchangeable is True
    assert report.decision == DECISION_ACCEPT_WITH_LOSS
    assert report.lossless is False
    assert report.readable_again is True
    assert [block.block_type for block in report.dropped_blocks] == [BLK_PACKET_SIMPLE]
    assert report.dropped_blocks[0].action == ACTION_DROP
    assert report.affected_interfaces == [0]
    assert report.affected_interface_scopes == [{"section": 1, "interface_id": 0}]
    assert report.evidence_loss[0]["kind"] == "packet"
    assert report.missing_evidence_interfaces == [0]


def test_policy_mapping_and_receiver_manifest_mapping_are_supported():
    sample = _mixed_endian_sample()
    receiver = {
        "name": "manifest-reader",
        "supported_block_types": ["SHB", "IDB", "EPB"],
        "allow_unknown_blocks": True,
    }
    report = preflight_exchange(
        sample,
        receiver,
        {"SPB": "drop", "0x40000BAD": "keep"},
    )

    assert report.receiver.name == "manifest-reader"
    assert report.exchangeable is True
    assert report.decision == DECISION_ACCEPT_WITH_LOSS
    assert report.affected_interfaces == [0]


def test_skipped_metadata_lists_every_affected_interface():
    sample = (
        _section_header("<")
        + _interface_description("<")
        + _interface_description("<")
        + _enhanced_packet("<", b"packet-on-zero")
        + _interface_statistics("<", 1)
        + _name_resolution("<")
    )
    receiver = ReceiverCapabilities(
        ("SHB", "IDB", "EPB"),
        allow_unknown_blocks=True,
        name="packet-only",
    )

    report = preflight_exchange(sample, receiver)

    assert report.exchangeable is True
    assert report.decision == DECISION_ACCEPT_WITH_LOSS
    assert [block.block_type for block in report.skippable_extensions] == [
        BLK_INTERFACE_STATS,
        BLK_NAME_RESOLUTION,
    ]
    assert report.affected_interfaces == [0, 1]
    assert report.affected_interface_scopes == [
        {"section": 0, "interface_id": 1},
        {"section": 0, "interface_id": 0},
    ]
    assert {entry["kind"] for entry in report.evidence_loss} == {
        "statistics",
        "name-resolution",
    }


def test_standard_unknown_block_requires_interpretation():
    sample = (
        _section_header("<")
        + _interface_description("<")
        + _block(0x00000007, b"standard-but-unimplemented", "<")
    )
    receiver = ReceiverCapabilities(
        ("SHB", "IDB", "EPB"),
        allow_unknown_blocks=True,
        name="skip-friendly",
    )

    report = preflight_exchange(sample, receiver)

    assert report.exchangeable is False
    assert [block.block_type for block in report.skippable_extensions] == []
    assert [block.block_type for block in report.required_unknown] == [0x00000007]
