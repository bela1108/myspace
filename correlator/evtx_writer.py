"""Minimal, self-contained .evtx writer used to build synthetic exhibits.

python-evtx only implements the reading side of the Windows Event Log format.
For offline relationship checking we need deterministic evidence files that
the unmodified ``Evtx`` parser can open, so this module emits a small but
spec-compliant subset of the binary XML (BXML) container format:

* one chunk per file,
* a populated common string table (no inline name strings),
* one resident template definition per record,
* fully literal BXML (no substitution slots),
* correct file/header/data CRC32 checksums.

The build is deliberately two-pass: names are collected while walking the
element tree, the common string table is laid out at a known chunk-relative
offset, and only then are element/attribute tokens emitted with concrete
offsets.  This avoids forward references that would otherwise point at -1.
"""

from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass, field

CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
CHUNK_HEADER_SIZE = 0x200
RECORD_MAGIC = 0x00002A2A

# BXML system tokens.
T_END_OF_STREAM = 0x00
T_OPEN_START_ELEMENT = 0x01
T_CLOSE_START_ELEMENT = 0x02
T_CLOSE_EMPTY_ELEMENT = 0x03
T_CLOSE_ELEMENT = 0x04
T_VALUE = 0x05
T_ATTRIBUTE = 0x06
T_TEMPLATE_INSTANCE = 0x0C
T_START_OF_STREAM = 0x0F

# BXML variant value types.
VT_WSTRING = 0x01
VT_UNSIGNED_DWORD = 0x08


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def filetime(dt) -> int:
    """Convert a naive UTC ``datetime`` to a Windows FILETIME (100ns ticks)."""
    import datetime as _datetime

    epoch = _datetime.datetime(1601, 1, 1)
    delta = dt - epoch
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


@dataclass
class XmlElement:
    """Tiny literal XML element model (attributes + text/element children)."""

    name: str
    attributes: dict[str, str] = field(default_factory=dict)
    children: list["XmlElement"] = field(default_factory=list)
    text: str | None = None

    def walk_names(self, sink) -> None:
        sink(self.name)
        for attr_name in self.attributes:
            sink(attr_name)
        for child in self.children:
            child.walk_names(sink)


class NameTable:
    """Chunk common string table: 64 hash buckets plus linked name nodes."""

    BUCKETS = 64

    def __init__(self) -> None:
        self.order: list[str] = []
        self.offsets: dict[str, int] = {}

    def register(self, name: str) -> None:
        if name not in self.offsets:
            self.offsets[name] = -1
            self.order.append(name)

    def offset_of(self, name: str) -> int:
        offset = self.offsets[name]
        if offset < 0:
            raise RuntimeError("name table has not been laid out")
        return offset

    @staticmethod
    def hash_name(name: str) -> int:
        value = 0
        for char in name:
            value = (value * 65599) + ord(char)
        return value & 0xFFFF

    def _encode_node(self, name: str, next_offset: int) -> bytes:
        raw = name.encode("utf-16-le")
        out = struct.pack("<IHH", next_offset, self.hash_name(name), len(name))
        return out + raw + b"\x00\x00"

    def layout(self, start_offset: int) -> bytes:
        encoded_lengths = [len(self._encode_node(name, 0)) for name in self.order]
        cursor = start_offset
        for name, length in zip(self.order, encoded_lengths):
            self.offsets[name] = cursor
            cursor += length
        buckets = [[] for _ in range(self.BUCKETS)]
        for name in self.order:
            buckets[self.hash_name(name) % self.BUCKETS].append(name)
        self._buckets = buckets
        next_in_bucket = {}
        for bucket in buckets:
            for position, name in enumerate(bucket):
                if position + 1 < len(bucket):
                    next_in_bucket[name] = self.offsets[bucket[position + 1]]
                else:
                    next_in_bucket[name] = 0
        nodes = bytearray()
        for name in self.order:
            nodes += self._encode_node(name, next_in_bucket[name])
        return bytes(nodes)

    def bucket_table(self) -> bytes:
        table = bytearray(0x100)
        for index, bucket in enumerate(self._buckets):
            if bucket:
                struct.pack_into("<I", table, index * 4, self.offsets[bucket[0]])
        return bytes(table)
class BxmlBuilder:
    """Encodes fully literal BXML that references the chunk string table."""

    def __init__(self, names: NameTable) -> None:
        self.names = names

    def collect(self, element: XmlElement) -> None:
        element.walk_names(self.names.register)

    @staticmethod
    def wstring_value(text: str) -> bytes:
        raw = text.encode("utf-16-le")
        return bytes([T_VALUE, VT_WSTRING]) + struct.pack("<H", len(text)) + raw

    def element(self, element: XmlElement, measure: bool = False) -> bytes:
        out = bytearray()
        name_offset = 0 if measure else self.names.offset_of(element.name)
        header = struct.pack("<BHII", T_OPEN_START_ELEMENT, 0, 0, name_offset)
        out += header
        for attr_name, attr_value in element.attributes.items():
            attr_offset = 0 if measure else self.names.offset_of(attr_name)
            out += struct.pack("<BI", T_ATTRIBUTE, attr_offset)
            out += self.wstring_value(attr_value)
        if not element.children and element.text is None:
            out.append(T_CLOSE_EMPTY_ELEMENT)
            return bytes(out)
        out.append(T_CLOSE_START_ELEMENT)
        if element.text is not None:
            out += self.wstring_value(element.text)
        for child in element.children:
            out += self.element(child, measure=measure)
        out.append(T_CLOSE_ELEMENT)
        return bytes(out)

    def record_payload(self, root: XmlElement, measure: bool = False) -> bytes:
        self.collect(root)
        stream = bytes([T_START_OF_STREAM, 0x01, 0x01, 0x00])
        stream_start = bytes([T_START_OF_STREAM, 0x01, 0x01, 0x00])
        body = stream_start + self.element(root, measure=measure) + bytes([T_END_OF_STREAM])
        if measure:
            return stream + bytes(10 + 0x18 + len(body) + 4)
        template_id = 0x0BADC0DE
        guid = struct.pack("<I", template_id) + bytes(range(12))
        instance = struct.pack("<BBII", T_TEMPLATE_INSTANCE, 0, template_id, 0)
        tnode = struct.pack("<I", 0) + guid + struct.pack("<I", len(body)) + body
        return stream + instance + tnode + struct.pack("<I", 0)
def _pad_to_8(data: bytes) -> bytes:
    remainder = len(data) % 8
    if remainder:
        data += b"\x00" * (8 - remainder)
    return data


def build_record(record_num: int, timestamp: int, payload: bytes) -> bytes:
    size = 0x18 + len(payload) + 4
    header = struct.pack("<IIQQ", RECORD_MAGIC, size, record_num, timestamp)
    trailing = struct.pack("<I", size - 4)
    return _pad_to_8(header + payload + trailing)


class EvtxChunkWriter:
    """Collects events and renders one 64KiB EVTX chunk."""

    def __init__(self) -> None:
        self.names = NameTable()
        self.builder = BxmlBuilder(self.names)
        self._roots: list[tuple[int, int, XmlElement]] = []

    def add_event(self, record_num: int, timestamp: int, root: XmlElement) -> None:
        self.builder.collect(root)
        self._roots.append((record_num, timestamp, root))

    def _collect_names(self) -> None:
        for _r, _t, root in self._roots:
            self.builder.collect(root)

    def _measure_records(self) -> int:
        total = 0
        for _r, _t, root in self._roots:
            payload = self.builder.record_payload(root, measure=True)
            total += len(_pad_to_8(build_record(0, 0, payload)))
        return total

    def render(self) -> bytes:
        self._collect_names()
        measured = self._measure_records()
        strings_blob = self.names.layout(CHUNK_HEADER_SIZE)
        records_start = CHUNK_HEADER_SIZE + len(strings_blob)
        records = bytearray()
        template_offsets = []
        for record_num, timestamp, root in self._roots:
            payload = bytearray(self.builder.record_payload(root))
            record_abs = records_start + len(records)
            instance_rel = record_abs + 0x18 + 4
            template_rel = instance_rel + 10
            struct.pack_into("<I", payload, 4 + 6, template_rel)
            template_offsets.append(template_rel)
            records += build_record(record_num, timestamp, bytes(payload))
        data = bytes(records)
        if len(data) != measured:
            raise RuntimeError("record size measurement mismatch")
        next_record_offset = records_start + len(data)
        if next_record_offset > CHUNK_SIZE:
            raise ValueError("chunk capacity exceeded")
        header = bytearray(0x200)
        header[0x80:0x180] = self.names.bucket_table()
        first = self._roots[0][0] if self._roots else 0
        last = self._roots[-1][0] if self._roots else 0
        header[0:8] = b"ElfChnk" + bytes(1)
        struct.pack_into("<QQQQ", header, 0x08, first, last, first, last)
        struct.pack_into("<I", header, 0x28, 0x80)
        struct.pack_into("<I", header, 0x2C, 0)
        struct.pack_into("<I", header, 0x30, next_record_offset)
        checksum_region = bytes(strings_blob) + data
        struct.pack_into("<I", header, 0x34, crc32(checksum_region))
        for slot, toff in enumerate(template_offsets[:32]):
            struct.pack_into("<I", header, 0x180 + slot * 4, toff)
        chunk = bytearray(header) + bytearray(strings_blob) + bytearray(data)
        if len(chunk) < CHUNK_SIZE:
            chunk += bytes(CHUNK_SIZE - len(chunk))
        struct.pack_into("<I", chunk, 0x7C, crc32(bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])))
        return bytes(chunk)

def write_evtx(path: str, chunk: EvtxChunkWriter) -> None:
    chunk_bytes = chunk.render()
    last_record = chunk._roots[-1][0] if chunk._roots else 0
    file_header = bytearray(FILE_HEADER_SIZE)
    file_header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", file_header, 0x08, 0, 0, last_record + 1)
    struct.pack_into("<IHHHH", file_header, 0x20, 0x80, 1, 3, 0x1000, 1)
    struct.pack_into("<I", file_header, 0x7C, crc32(bytes(file_header[0:0x78])))
    with open(path, "wb") as handle:
        handle.write(bytes(file_header))
        handle.write(chunk_bytes)
