from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest

from dissect.cstruct.dump import dumpstruct
from dissect.cstruct.types.base import StringReadError
from tests.util import NonSeekableStream, verify_compiled

if TYPE_CHECKING:
    from dissect.cstruct.cstruct import cstruct


# A 32-byte field without a NUL, immediately followed by the next entry (its magic + a credential fragment).
FIELD = b"admin" + b"A" * 27
NEIGHBOUR = b"MAGIC" + b"secret-pw"
BUFFER = FIELD + NEIGHBOUR


def test_fixed_char_array_reads_only_declared_range(cs: cstruct) -> None:
    """A fixed char array never reads past its declared size, even without a NUL."""
    value = cs.char[32](io.BytesIO(BUFFER))
    assert bytes(value) == FIELD
    assert len(value) == 32
    assert b"MAGIC" not in bytes(value)
    assert b"secret-pw" not in bytes(value)


def test_fixed_char_array_stops_stream_at_field_end(cs: cstruct) -> None:
    fh = io.BytesIO(BUFFER)
    value = cs.char[32](fh)
    assert fh.tell() == 32
    assert fh.read() == NEIGHBOUR
    assert bytes(value) == FIELD


def test_fixed_char_array_raw_bytes_viewable_per_field(cs: cstruct, compiled: bool) -> None:
    """The raw bytes of an unterminated field can still be inspected, in isolation."""
    cdef = """
    struct entry {
        char name[32];
        char next[8];
    };
    """
    cs.load(cdef, compiled=compiled)
    assert verify_compiled(cs.entry, compiled)

    obj = cs.entry(FIELD + NEIGHBOUR[:8])
    assert bytes(obj.name) == FIELD
    assert bytes(obj.next) == NEIGHBOUR[:8]
    assert b"MAGIC" not in bytes(obj.name)
    # Round trips keep the exact field bytes, no neighbouring memory is pulled in.
    assert obj.dumps() == FIELD + NEIGHBOUR[:8]


def test_bounded_char_unterminated_reports_raw_bytes(cs: cstruct) -> None:
    """A bounded dynamic string without a NUL raises with the raw field bytes and no neighbour leak."""
    with pytest.raises(StringReadError) as exc:
        cs.char.read_string(io.BytesIO(BUFFER), 32)
    error = exc.value
    assert error.reason == "unterminated"
    assert error.raw == FIELD
    assert len(error.raw) == 32
    assert b"MAGIC" not in error.raw
    assert b"secret-pw" not in error.raw


def test_bounded_char_does_not_consume_past_the_bound(cs: cstruct) -> None:
    fh = io.BytesIO(BUFFER)
    with pytest.raises(StringReadError):
        cs.char.read_string(fh, 32)
    assert fh.tell() == 32
    assert fh.read() == NEIGHBOUR


def test_bounded_char_terminated_stops_at_nul(cs: cstruct) -> None:
    value = cs.char.read_string(io.BytesIO(b"hello\x00LEAK"), 9)
    assert bytes(value) == b"hello"
    assert b"LEAK" not in bytes(value)


def test_bounded_char_from_parent_buffer(cs: cstruct) -> None:
    # Passing a bytes-like parent buffer must never reach beyond max_length.
    with pytest.raises(StringReadError) as exc:
        cs.char.read_string(bytearray(BUFFER), 32)
    assert exc.value.raw == FIELD


@pytest.mark.parametrize("stream_type", [io.BytesIO, NonSeekableStream])
def test_bounded_char_non_seekable(cs: cstruct, stream_type: type) -> None:
    with pytest.raises(StringReadError) as exc:
        cs.char.read_string(stream_type(BUFFER), 32)
    assert exc.value.raw == FIELD

    value = cs.char.read_string(stream_type(b"hello\x00rest"), 10)
    assert bytes(value) == b"hello"


def test_bounded_char_max_length_validation(cs: cstruct) -> None:
    with pytest.raises(ValueError, match="max_length must be non-negative"):
        cs.char.read_string(io.BytesIO(b"abc"), -1)


def test_unbounded_char_preserves_historical_eof(cs: cstruct) -> None:
    # The default (unbounded) null-terminated read still raises EOFError at the end of the stream.
    with pytest.raises(EOFError, match="Read 0 bytes, but expected 1"):
        cs.char[None](io.BytesIO(b"abc"))
    with pytest.raises(EOFError, match="Read 0 bytes, but expected 1"):
        cs.char[None](NonSeekableStream(b"abc"))


def test_fixed_wchar_array_reads_only_declared_range(cs: cstruct) -> None:
    data = "abc".encode("utf-16-le")
    neighbour = b"MMMM"
    value = cs.wchar[3](io.BytesIO(data + neighbour))
    assert str(value) == "abc"
    assert value.dumps() == data


def test_bounded_wchar_truncated_odd_byte(cs: cstruct) -> None:
    """A wchar sample cut on an odd byte is a decoding error carrying the raw bytes."""
    raw = b"A\x00B"
    with pytest.raises(UnicodeDecodeError, match="truncated data"):
        cs.wchar.read_string(io.BytesIO(raw), 3)


@pytest.mark.parametrize("stream_type", [io.BytesIO, NonSeekableStream])
def test_bounded_wchar_truncated_all_streams(cs: cstruct, stream_type: type) -> None:
    with pytest.raises(UnicodeDecodeError):
        cs.wchar.read_string(stream_type(b"A\x00B"), 3)


def test_bounded_wchar_unterminated_even_bytes(cs: cstruct) -> None:
    raw = "abc".encode("utf-16-le")
    with pytest.raises(StringReadError) as exc:
        cs.wchar.read_string(io.BytesIO(raw + b"XX"), 6)
    assert exc.value.reason == "unterminated"
    assert exc.value.raw == raw


def test_bounded_wchar_split_surrogate_pair(cs: cstruct) -> None:
    """A high surrogate ending exactly on the boundary cannot assume its low surrogate is in bounds."""
    pair = "\U0001f600".encode("utf-16-le")
    high = pair[:2]
    with pytest.raises(StringReadError) as exc:
        cs.wchar.read_string(io.BytesIO(high + b"ZZ"), 2)
    assert exc.value.reason == "truncated-surrogate-pair"
    assert exc.value.raw == high


def test_bounded_wchar_terminated_string(cs: cstruct) -> None:
    payload = "hi".encode("utf-16-le")
    value = cs.wchar.read_string(io.BytesIO(payload + b"\x00\x00LEAK"), 10)
    assert str(value) == "hi"
    # Round trip through the matching array type, which encodes every code unit read.
    assert cs.wchar[2].dumps(str(value)) == payload


def test_bounded_wchar_lone_surrogate_is_allowed(cs: cstruct) -> None:
    """A complete lone surrogate inside the bounds is preserved (no surrogate error for in-bounds data)."""
    raw = b"a\x00\x00\xd8"
    value = cs.wchar.read_string(io.BytesIO(raw + b"\x00\x00"), 8)
    assert str(value) == "a\ud800"
    assert cs.wchar[2].dumps(str(value)) == raw


def test_unbounded_wchar_preserves_historical_eof(cs: cstruct) -> None:
    with pytest.raises(EOFError, match="Read 0 bytes, but expected 2"):
        cs.wchar[None](io.BytesIO("abc".encode("utf-16-le")))
    with pytest.raises(EOFError, match="Read 1 bytes, but expected 2"):
        cs.wchar[None](NonSeekableStream("abc".encode("utf-16-le") + b"A"))


def test_normal_ascii_and_utf16_str_behavior_unchanged(cs: cstruct, compiled: bool) -> None:
    cdef = """
    struct record {
        char  label[8];
        wchar title[4];
    };
    """
    cs.load(cdef, compiled=compiled)
    assert verify_compiled(cs.record, compiled)

    label = b"router\x00\x00"
    title = "box\x00".encode("utf-16-le")
    obj = cs.record(label + title)

    # bytes-based char and str-based wchar keep their historical value and str() behaviour
    assert bytes(obj.label) == label
    assert str(obj.label) == str(label)
    assert str(obj.title) == "box\x00"
    assert obj.title == "box\x00"
    assert obj.dumps() == label + title


def test_unterminated_field_does_not_leak_next_entry_in_utf8(cs: cstruct) -> None:
    """Reproduces the forensic scenario: decoding the bounded field alone must not contain the next entry."""
    value = cs.char[32](io.BytesIO(BUFFER))
    decoded = bytes(value).decode("utf-8", errors="replace")
    assert "MAGIC" not in decoded
    assert "secret-pw" not in decoded
    # The neighbour only appears when the whole buffer is decoded, which the type itself never does.
    whole = BUFFER.decode("utf-8", errors="replace")
    assert "secret-pw" in whole


def test_dumpstruct_does_not_include_adjacent_memory(cs: cstruct, compiled: bool) -> None:
    cdef = """
    struct table {
        char name[8];
        char magic[5];
    };
    """
    cs.load(cdef, compiled=compiled)
    assert verify_compiled(cs.table, compiled)

    name = b"abcde" + b"A" * 3  # 8 bytes, no NUL inside the name field
    magic = b"MAGIC"
    obj = cs.table(name + magic)

    tree = dumpstruct(obj, output="dict")
    nodes = {node["name"]: node for node in tree["fields"]}
    assert nodes["name[8]"]["offset"] == 0
    assert nodes["name[8]"]["size"] == 8
    assert nodes["magic[5]"]["offset"] == 8
    assert nodes["magic[5]"]["size"] == 5

    rendered = dumpstruct(obj, output="string", color=False)
    # The hexdump and field tree cover exactly the structure bytes, nothing adjacent.
    assert tree["bytes"] == (name + magic).hex()
    assert "secret-pw" not in rendered
    assert repr(bytes(obj.name)) in rendered or str(bytes(obj.name)) in rendered
