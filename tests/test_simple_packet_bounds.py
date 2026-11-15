import io
import struct

import pytest

from pcapng import FileScanner, FileWriter
from pcapng.blocks import (
    EnhancedPacket,
    InterfaceDescription,
    SectionHeader,
    SimplePacket,
)
from pcapng.exceptions import CorruptedFile, PcapngLoadError


def _section_header():
    return (
        b"\x0a\x0d\x0d\x0a"  # Magic number
        b"\x1c\x00\x00\x00"  # Block size (28 bytes)
        b"\x4d\x3c\x2b\x1a"  # Byte order magic (little endian)
        b"\x01\x00\x00\x00"  # Version 1.0
        b"\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
        b"\x1c\x00\x00\x00"  # Block size (28 bytes)
    )


def _interface_description(snaplen):
    body = struct.pack("<HHI", 1, 0, snaplen)  # link type, reserved, snaplen
    length = 12 + len(body)
    return struct.pack("<II", 0x00000001, length) + body + struct.pack("<I", length)


def _simple_packet(packet_len, data, padding=None):
    if padding is None:
        padding = b"\x00" * ((4 - (len(data) % 4)) % 4)
    body = struct.pack("<I", packet_len) + data + padding
    length = 12 + len(body)
    return struct.pack("<II", 0x00000003, length) + body + struct.pack("<I", length)


def _scan(data):
    return list(FileScanner(io.BytesIO(data)))


def test_valid_simple_packet_parsed_as_simple_packet():
    data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    blocks = _scan(
        _section_header() + _interface_description(65535)
        + _simple_packet(len(data), data)
    )

    assert len(blocks) == 3
    assert isinstance(blocks[0], SectionHeader)
    assert isinstance(blocks[1], InterfaceDescription)

    packet = blocks[2]
    assert type(packet) is SimplePacket
    assert not isinstance(packet, EnhancedPacket)
    assert packet.interface_id == 0
    assert packet.interface is blocks[1]
    assert packet.packet_len == len(data)
    assert packet.captured_len == len(data)
    assert packet.packet_data == data


def test_captured_len_bounded_by_interface_snaplen():
    # packet_len is larger than the interface snaplen: only snaplen
    # bytes were captured, and only those must be exposed as payload.
    blocks = _scan(
        _section_header() + _interface_description(4)
        + _simple_packet(8, b"\xaa\xbb\xcc\xdd")
    )

    packet = blocks[2]
    assert type(packet) is SimplePacket
    assert packet.packet_len == 8
    assert packet.captured_len == 4
    assert packet.packet_data == b"\xaa\xbb\xcc\xdd"


def test_trailing_junk_not_treated_as_payload():
    # Old exporters may stuff extra bytes at the end of the block, past
    # the captured data and its padding. They must be ignored, not
    # mistaken for payload.
    captured = b"\xaa\xbb\xcc\xdd"
    junk = b"\xff" * 28
    body = struct.pack("<I", 1000) + captured + junk
    length = 12 + len(body)
    spb = struct.pack("<II", 0x00000003, length) + body + struct.pack("<I", length)

    blocks = _scan(_section_header() + _interface_description(4) + spb)

    packet = blocks[2]
    assert type(packet) is SimplePacket
    assert packet.packet_len == 1000
    assert packet.captured_len == 4
    assert packet.packet_data == captured


def test_unlimited_snaplen_uses_packet_len():
    data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    blocks = _scan(
        _section_header() + _interface_description(0)
        + _simple_packet(len(data), data)
    )

    packet = blocks[2]
    assert packet.captured_len == len(data)
    assert packet.packet_data == data


def test_simple_packet_without_interface_is_rejected():
    # No Interface Description Block before the SPB: the scanner must
    # refuse the block with a recoverable error instead of fabricating
    # an interface 0.
    stream = _section_header() + _simple_packet(4, b"\xaa\xbb\xcc\xdd")
    with pytest.raises(CorruptedFile, match="Interface Description"):
        _scan(stream)

    # CorruptedFile is a PcapngLoadError: callers can catch it and
    # recover (eg. skip the offending file).
    with pytest.raises(PcapngLoadError):
        _scan(stream)


def test_simple_packet_constructor_without_interface_is_rejected():
    shb = SectionHeader()
    with pytest.raises(CorruptedFile, match="Interface Description"):
        shb.new_member(SimplePacket, raw=struct.pack("<I", 4) + b"\xaa\xbb\xcc\xdd")


def test_simple_packet_too_short_is_rejected():
    # Block payload smaller than the packet_len field: the packet data
    # length would be negative.
    spb = struct.pack("<II", 0x00000003, 12) + struct.pack("<I", 12)
    with pytest.raises(CorruptedFile, match="too short"):
        _scan(_section_header() + _interface_description(65535) + spb)


def test_simple_packet_insufficient_data_is_rejected():
    # The block holds fewer bytes than the derived captured length.
    with pytest.raises(CorruptedFile, match="packet data"):
        _scan(
            _section_header() + _interface_description(0)
            + _simple_packet(100, b"\x01\x02\x03\x04")
        )

    # Same, with the captured length bounded by the snaplen.
    with pytest.raises(CorruptedFile, match="packet data"):
        _scan(
            _section_header() + _interface_description(16)
            + _simple_packet(100, b"\x01\x02\x03\x04")
        )


def test_simple_packet_nonzero_padding_is_rejected():
    with pytest.raises(CorruptedFile, match="padding"):
        _scan(
            _section_header() + _interface_description(0)
            + _simple_packet(5, b"\x01\x02\x03\x04\x05", padding=b"\x01\x02\x03")
        )


def test_valid_simple_packet_roundtrip_bytes_identical():
    raw = (
        _section_header() + _interface_description(65535)
        + _simple_packet(5, b"\x01\x02\x03\x04\x05")
    )

    blocks = _scan(raw)
    assert type(blocks[2]) is SimplePacket

    out = io.BytesIO()
    writer = FileWriter(out, blocks[0])  # writes SHB and its interfaces
    writer.write_block(blocks[2])

    assert out.getvalue() == raw
