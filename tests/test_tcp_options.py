import struct

import pytest

from dpkt import tcp


def _opt(kind, data=b''):
    if kind in (tcp.TCP_OPT_EOL, tcp.TCP_OPT_NOP):
        return bytes([kind])
    return bytes([kind, len(data) + 2]) + data


def _tcp_segment(opts, payload=b'', seq=1):
    assert len(opts) % 4 == 0
    off = 5 + len(opts) // 4
    header = struct.pack(
        '!HHIIHHHH',
        12345,
        80,
        seq,
        0,
        (off << 12) | tcp.TH_SYN,
        65535,
        0x1234,
        0,
    )
    return header + opts + payload


def test_eol_stops_parsing_and_accepts_zero_padding():
    opts = tcp.parse_opts(b'\x00' + b'\x00' * 200)

    assert opts == [(tcp.TCP_OPT_EOL, b'')]
    assert not opts.truncated
    assert not opts.headers_truncated


def test_eol_with_nonzero_padding_keeps_prefix_and_marks_truncated():
    suffix = b'\x00' + b'\x05\x0a' + b'A' * 8 + b'\xff' * 200

    opts = tcp.parse_opts(suffix)

    assert opts == [
        (tcp.TCP_OPT_EOL, b''),
    ]
    assert opts.truncated
    assert opts.headers_truncated


def test_nop_may_appear_alone_or_repeated():
    buf = b'\x01' * 40

    opts = tcp.parse_opts(buf)

    assert opts == [(tcp.TCP_OPT_NOP, b'')] * 40
    assert not opts.truncated


def test_unknown_kind_is_skipped_by_declared_length():
    opts = tcp.parse_opts(b'\x63\x06\xaa\xbb\xcc\xdd\x01')

    assert opts == [
        (99, b'\xaa\xbb\xcc\xdd'),
        (tcp.TCP_OPT_NOP, b''),
    ]
    assert not opts.truncated


@pytest.mark.parametrize(
    'buf, expected',
    [
        (b'\x02', []),
        (b'\x02\x04', []),
        (b'\x02\x04\x05', []),
        (b'\x01\x02\x04', [(tcp.TCP_OPT_NOP, b'')]),
    ],
)
def test_truncated_option_retains_only_parsed_prefix(buf, expected):
    opts = tcp.parse_opts(buf)

    assert opts == expected
    assert opts.truncated


def test_invalid_zero_length_option_stops_without_spinning():
    opts = tcp.parse_opts(b'\x02\x00\x01\x01')

    assert opts == []
    assert opts.truncated


def test_duplicate_sack_and_timestamp_keep_first_valid_value():
    sack_first = b'\x00\x00\x00\x10\x00\x00\x00\x20'
    sack_second = b'\x00\x00\x00\x30\x00\x00\x00\x40'
    ts_first = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    ts_second = b'\x11\x12\x13\x14\x15\x16\x17\x18'
    buf = (
        _opt(tcp.TCP_OPT_NOP)
        + _opt(tcp.TCP_OPT_SACK, sack_first)
        + _opt(tcp.TCP_OPT_TIMESTAMP, ts_first)
        + _opt(tcp.TCP_OPT_SACK, sack_second)
        + _opt(tcp.TCP_OPT_TIMESTAMP, ts_second)
    )

    opts = tcp.parse_opts(buf)

    assert opts == [
        (tcp.TCP_OPT_NOP, b''),
        (tcp.TCP_OPT_SACK, sack_first),
        (tcp.TCP_OPT_TIMESTAMP, ts_first),
    ]
    assert opts.first_by_kind[tcp.TCP_OPT_SACK] == sack_first
    assert opts.first_by_kind[tcp.TCP_OPT_TIMESTAMP] == ts_first


def test_legal_sack_blocks_keep_original_order():
    blocks = b''.join(
        struct.pack('!II', start, end)
        for start, end in ((10, 20), (30, 40), (50, 60))
    )

    opts = tcp.parse_opts(_opt(tcp.TCP_OPT_SACK, blocks))

    assert opts == [(tcp.TCP_OPT_SACK, blocks)]
    assert opts.first_by_kind[tcp.TCP_OPT_SACK] == blocks


def test_out_of_bounds_length_cannot_overwrite_first_sack():
    sack_first = b'\x00\x00\x00\x10\x00\x00\x00\x20'
    buf = _opt(tcp.TCP_OPT_SACK, sack_first) + b'\x05\xfe\x00\x00'

    opts = tcp.parse_opts(buf)

    assert opts == [(tcp.TCP_OPT_SACK, sack_first)]
    assert opts.first_by_kind[tcp.TCP_OPT_SACK] == sack_first
    assert opts.truncated


def test_tcp_unpack_uses_data_offset_and_marks_bad_option_padding():
    options = (
        _opt(tcp.TCP_OPT_MSS, b'\x05\xb4')
        + _opt(tcp.TCP_OPT_EOL)
        + b'\x00' * 3
        + b'\xff' * 4
    )
    segment = _tcp_segment(options, b'PAYLOAD')

    tcp_packet = tcp.TCP(segment)

    assert tcp_packet.data == b'PAYLOAD'
    assert tcp_packet.opts == options
    assert tcp_packet.parsed_opts[:2] == [
        (tcp.TCP_OPT_MSS, b'\x05\xb4'),
        (tcp.TCP_OPT_EOL, b''),
    ]
    assert tcp_packet.headers_truncated
    assert tcp_packet.opts_truncated


def test_tcp_payload_after_eol_is_not_parsed_as_options():
    options = (
        _opt(tcp.TCP_OPT_MSS, b'\x05\xb4')
        + _opt(tcp.TCP_OPT_EOL)
        + b'\x00' * 3
    )
    payload = b'\x05\x0a' + b'A' * 8 + b'B' * 200
    segment = _tcp_segment(options, payload)

    tcp_packet = tcp.TCP(segment)

    assert tcp_packet.data == payload
    assert len(tcp_packet.opts) == 8
    assert tcp_packet.parsed_opts == [
        (tcp.TCP_OPT_MSS, b'\x05\xb4'),
        (tcp.TCP_OPT_EOL, b''),
    ]
    assert not tcp_packet.headers_truncated


def test_legal_handshake_roundtrip_and_checksum_are_unchanged():
    options = (
        _opt(tcp.TCP_OPT_MSS, b'\x05\xb4')
        + _opt(tcp.TCP_OPT_SACKOK)
        + _opt(tcp.TCP_OPT_NOP)
        + _opt(tcp.TCP_OPT_WSCALE, b'\x07')
        + _opt(tcp.TCP_OPT_NOP)
        + _opt(tcp.TCP_OPT_NOP)
    )
    segment = _tcp_segment(options, b'', seq=0x01020304)

    tcp_packet = tcp.TCP(segment)

    assert not tcp_packet.headers_truncated
    assert tcp_packet.parsed_opts == [
        (tcp.TCP_OPT_MSS, b'\x05\xb4'),
        (tcp.TCP_OPT_SACKOK, b''),
        (tcp.TCP_OPT_NOP, b''),
        (tcp.TCP_OPT_WSCALE, b'\x07'),
        (tcp.TCP_OPT_NOP, b''),
        (tcp.TCP_OPT_NOP, b''),
    ]
    assert tcp_packet.sum == 0x1234
    assert bytes(tcp_packet) == segment


def test_two_handshakes_keep_separate_option_boundaries():
    bad_opts = (
        _opt(tcp.TCP_OPT_NOP) * 8
        + _opt(tcp.TCP_OPT_SACK, b'\x00\x00\x00\x10\x00\x00\x00\x20')
        + _opt(tcp.TCP_OPT_SACK, b'\x00\x00\x00\x10\x00\x00\x00\x20')
    )
    good_opts = (
        _opt(tcp.TCP_OPT_MSS, b'\x05\xb4')
        + _opt(tcp.TCP_OPT_EOL)
        + b'\x00' * 3
    )

    first = tcp.TCP(_tcp_segment(bad_opts, b'FIRST', seq=1))
    second = tcp.TCP(_tcp_segment(good_opts, b'SECOND', seq=2))

    assert first.data == b'FIRST'
    assert second.data == b'SECOND'
    assert first.seq != second.seq
    assert first.parsed_opts.first_by_kind[tcp.TCP_OPT_SACK] == (
        b'\x00\x00\x00\x10\x00\x00\x00\x20'
    )
    assert tcp.TCP_OPT_SACK not in second.parsed_opts.first_by_kind
