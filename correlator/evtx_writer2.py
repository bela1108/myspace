"""Minimal python-evtx-compatible .evtx writer (inline name nodes)."""
from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass, field

CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
CHUNK_HEADER_SIZE = 0x200
RECORD_MAGIC = 0x00002A2A

T_END = 0x00
T_OPEN = 0x01
T_CLOSE_START = 0x02
T_CLOSE_EMPTY = 0x03
T_CLOSE = 0x04
T_VALUE = 0x05
T_ATTRIBUTE = 0x06
T_TEMPLATE_INSTANCE = 0x0C
T_STREAM_START = 0x0F

F_OPEN_INLINE = 0x40
VT_WSTRING = 0x01


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def filetime(dt) -> int:
    import datetime as _datetime
    epoch = _datetime.datetime(1601, 1, 1)
    delta = dt - epoch
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def hash_name(name: str) -> int:
    value = 0
    for char in name:
        value = (value * 65599) + ord(char)
    return value & 0xFFFF


def name_node(name: str, next_offset: int) -> bytes:
    raw = name.encode("utf-16-le")
    return struct.pack("<IHH", next_offset, hash_name(name), len(name)) + raw + b"\x00\x00"


def name_node_len(name: str) -> int:
    return 8 + len(name) * 2 + 2


@dataclass
class XmlElement:
    name: str
    attributes: dict = field(default_factory=dict)
    children: list = field(default_factory=list)
    text: str | None = None

    def walk(self, sink):
        sink(self.name)
        for attr in self.attributes:
            sink(attr)
        for child in self.children:
            child.walk(sink)

class RecordEncoder:
    """Encodes one record; name nodes are inline and registered in chunk."""

    def __init__(self, root: XmlElement):
        self.root = root
        self.name_locations = []

    @staticmethod
    def _wstring(text):
        raw = text.encode("utf-16-le")
        return bytes([T_VALUE, VT_WSTRING]) + struct.pack("<H", len(text)) + raw

    def _element(self, el, buf, record_base):
        tag_start = len(buf)
        name_rel = record_base + tag_start + 11
        buf += struct.pack("<BHII", T_OPEN, 0, 0, name_rel)
        self.name_locations.append((el.name, record_base + tag_start + 11))
        buf += name_node(el.name, 0)
        for attr_name, attr_value in el.attributes.items():
            attr_tag = len(buf)
            attr_rel = record_base + attr_tag + 5
            buf += struct.pack("<BI", T_ATTRIBUTE, attr_rel)
            self.name_locations.append((attr_name, record_base + attr_tag + 5))
            buf += name_node(attr_name, 0)
            buf += self._wstring(attr_value)
        if not el.children and el.text is None:
            buf.append(T_CLOSE_EMPTY)
            return
        buf.append(T_CLOSE_START)
        if el.text is not None:
            buf += self._wstring(el.text)
        for child in el.children:
            self._element(child, buf, record_base)
        buf.append(T_CLOSE)


    def encode(self, template_id, record_abs):
        body_buf = bytearray()
        body_buf += bytes([T_STREAM_START, 1, 1, 0])
        inner_start = len(body_buf)
        record_base = record_abs + 0x18 + 4 + 10 + 0x18
        self._element(self.root, body_buf, record_base)
        body_buf.append(T_END)
        body = bytes(body_buf)
        guid = struct.pack("<I", template_id) + bytes(range(12))
        instance = struct.pack("<BBII", T_TEMPLATE_INSTANCE, 0, template_id, 0)
        tnode = struct.pack("<I", 0) + guid + struct.pack("<I", len(body)) + body
        stream = bytes([T_STREAM_START, 1, 1, 0])
        return stream + instance + tnode + struct.pack("<I", 0)


def _pad8(data):
    rem = len(data) % 8
    return data + (bytes(8 - rem) if rem else b"")


def build_record(record_num, timestamp, payload):
    size = 0x18 + len(payload) + 4
    head = struct.pack("<IIQQ", RECORD_MAGIC, size, record_num, timestamp)
    return _pad8(head + payload + struct.pack("<I", size - 4))


class EvtxChunkWriter:
    def __init__(self):
        self._events = []
        self._name_offsets = {}
        self._name_order = []

    def add_event(self, record_num, timestamp, root, template_id=0x0BADC0DE):
        self._events.append((record_num, timestamp, root, template_id))

    def _register_name(self, name, offset):
        if name not in self._name_offsets:
            self._name_offsets[name] = offset
            self._name_order.append(name)

    def render(self):
        records = bytearray()
        template_offsets = []
        cursor = CHUNK_HEADER_SIZE
        for record_num, timestamp, root, template_id in self._events:
            enc = RecordEncoder(root)
            record_abs = cursor
            payload = bytearray(enc.encode(template_id, record_abs))
            instance_rel = record_abs + 0x18 + 4
            template_rel = instance_rel + 10
            struct.pack_into("<I", payload, 10, template_rel)
            for name, off in enc.name_locations:
                self._register_name(name, off)
            records += build_record(record_num, timestamp, bytes(payload))
            template_offsets.append(template_rel)
            cursor = CHUNK_HEADER_SIZE + len(records)
        next_record_offset = cursor
        header = bytearray(0x200)
        header[0:8] = b"ElfChnk\x00"
        first = self._events[0][0]
        last = self._events[-1][0]
        struct.pack_into("<QQQQ", header, 0x08, first, last, first, last)
        struct.pack_into("<I", header, 0x28, 0x80)
        struct.pack_into("<I", header, 0x2C, 0)
        struct.pack_into("<I", header, 0x30, next_record_offset)
        struct.pack_into("<I", header, 0x34, crc32(bytes(records)))
        buckets = [[] for _ in range(64)]
        for name in self._name_order:
            buckets[hash_name(name) % 64].append(name)
        for i, bucket in enumerate(buckets):
            if bucket:
                struct.pack_into("<I", header, 0x80 + i * 4, self._name_offsets[bucket[0]])
        for slot, toff in enumerate(template_offsets[:32]):
            struct.pack_into("<I", header, 0x180 + slot * 4, toff)
        chunk = bytearray(header) + records
        if len(chunk) < CHUNK_SIZE:
            chunk += bytes(CHUNK_SIZE - len(chunk))
        struct.pack_into("<I", chunk, 0x7C, crc32(bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])))
        return bytes(chunk)


def write_evtx(path, chunk):
    chunk_bytes = chunk.render()
    last = chunk._events[-1][0] if chunk._events else 0
    fh = bytearray(FILE_HEADER_SIZE)
    fh[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", fh, 0x08, 0, 0, last + 1)
    struct.pack_into("<IHHHH", fh, 0x20, 0x80, 1, 3, 0x1000, 1)
    struct.pack_into("<I", fh, 0x7C, crc32(bytes(fh[0:0x78])))
    with open(path, "wb") as handle:
        handle.write(bytes(fh))
        handle.write(chunk_bytes)


def build_event_root(event):
    system = XmlElement("System", {}, [
        XmlElement("Provider", {"Name": str(event.get("provider", ""))}, []),
        XmlElement("EventID", {}, [], str(event["event_id"])),
        XmlElement("Computer", {}, [], str(event.get("computer", ""))),
    ])
    kids = [XmlElement(str(k), {}, [], str(v)) for k, v in event.get("data", {}).items()]
    return XmlElement("Event", {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}, [system, XmlElement("EventData", {}, kids)])

