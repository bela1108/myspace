"""Build a tiny, self-contained .NET assembly for attribution tests.

The fixture intentionally contains three custom attribute rows:

* an assembly-level marker whose constructor resolves through AssemblyRef,
* a method-level marker with the same display name but a different AssemblyRef,
* a method-level marker whose TypeRef only reaches a ModuleRef.

The last case is deliberately under-specified: one TypeRef row cannot prove
which assembly owns the constructor.
"""

import struct
from pathlib import Path


def _compressed_uint(value):
    if value < 0x80:
        return bytes((value,))
    if value < 0x4000:
        return struct.pack("<H", value | 0x8000)
    return struct.pack("<I", value | 0xC0000000)


class _Heap:
    def __init__(self):
        self.data = bytearray(b"\x00")
        self.offsets = {"": 0}

    def add(self, raw):
        offset = len(self.data)
        self.data.extend(raw)
        self.data.extend(b"\x00")
        return offset

    def add_blob(self, raw):
        offset = len(self.data)
        self.data.extend(_compressed_uint(len(raw)))
        self.data.extend(raw)
        return offset


def _ser_string(value):
    raw = value.encode("utf-8")
    return _compressed_uint(len(raw)) + raw


def _align4(data):
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def build_security_fixture():
    strings = _Heap()
    blobs = _Heap()

    s_module = strings.add(b"AttributionFixture.dll")
    s_host = strings.add(b"MarkerHost")
    s_namespace = strings.add(b"Fixture")
    s_guarded = strings.add(b"Guarded")
    s_maybe = strings.add(b"MaybeGuarded")
    s_ctor = strings.add(b".ctor")
    s_marker = strings.add(b"SecurityMarkerAttribute")
    s_security_ns = strings.add(b"Acme.Security")
    s_shared = strings.add(b"Shared.Security")
    s_vendor = strings.add(b"Vendor.Security")
    s_module_ref = strings.add(b"peer.netmodule")
    s_assembly = strings.add(b"AttributionFixture")

    token_shared = bytes.fromhex("1122334455667788")
    token_vendor = bytes.fromhex("aabbccddeeff0011")
    b_token_shared = blobs.add_blob(token_shared)
    b_token_vendor = blobs.add_blob(token_vendor)

    ctor_sig = bytes.fromhex("20 02 01 0e 02")
    b_ctor_sig = blobs.add_blob(ctor_sig)
    method_sig = bytes.fromhex("00 00 01")
    b_method_sig = blobs.add_blob(method_sig)

    ca_assembly = (
        b"\x01\x00"
        + _ser_string("assembly")
        + b"\x01"
        + b"\x01\x00"
        + b"\x54"
        + b"\x08"
        + _ser_string("Level")
        + struct.pack("<i", 7)
    )
    ca_member = (
        b"\x01\x00"
        + _ser_string("member")
        + b"\x00"
        + b"\x01\x00"
        + b"\x54"
        + b"\x0e"
        + _ser_string("Scope")
        + _ser_string("method")
    )
    # The constructor declares (string, bool), but the bool byte is absent.
    ca_partial = b"\x01\x00" + _ser_string("maybe")

    b_ca_assembly = blobs.add_blob(ca_assembly)
    b_ca_member = blobs.add_blob(ca_member)
    b_ca_partial = blobs.add_blob(ca_partial)

    tables = bytearray()
    tables.extend(struct.pack("<HHHHH", 0, s_module, 1, 0, 0))  # Module
    tables.extend(struct.pack("<HHH", (1 << 2) | 2, s_marker, s_security_ns))
    tables.extend(struct.pack("<HHH", (2 << 2) | 2, s_marker, s_security_ns))
    tables.extend(struct.pack("<HHH", (1 << 2) | 1, s_marker, s_security_ns))
    tables.extend(struct.pack("<IHHHHH", 0, 0, 0, 0, 1, 1))
    tables.extend(struct.pack("<IHHHHH", 0, s_host, s_namespace, 0, 1, 1))
    tables.extend(struct.pack("<IHHHHH", 0, 0x0016, 0x0006, s_guarded, b_method_sig, 1))
    tables.extend(struct.pack("<IHHHHH", 0, 0x0016, 0x0006, s_maybe, b_method_sig, 1))
    tables.extend(struct.pack("<HHH", (1 << 3) | 1, s_ctor, b_ctor_sig))
    tables.extend(struct.pack("<HHH", (2 << 3) | 1, s_ctor, b_ctor_sig))
    tables.extend(struct.pack("<HHH", (3 << 3) | 1, s_ctor, b_ctor_sig))
    tables.extend(struct.pack("<HHH", (1 << 5) | 14, (1 << 3) | 3, b_ca_assembly))
    tables.extend(struct.pack("<HHH", (1 << 5) | 0, (2 << 3) | 3, b_ca_member))
    tables.extend(struct.pack("<HHH", (2 << 5) | 0, (3 << 3) | 3, b_ca_partial))
    tables.extend(struct.pack("<H", s_module_ref))
    tables.extend(struct.pack("<IHHHHIHHH", 0x8004, 1, 0, 0, 0, 0, 0, s_assembly, 0))
    tables.extend(struct.pack("<HHHHIHHHH", 1, 0, 0, 0, 0, b_token_shared, s_shared, 0, 0))
    tables.extend(struct.pack("<HHHHIHHHH", 1, 0, 0, 0, 0, b_token_vendor, s_vendor, 0, 0))

    valid = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 6) | (1 << 10) | (1 << 12)
    valid |= (1 << 26) | (1 << 32) | (1 << 35)
    sorted_tables = (1 << 12) | (1 << 32) | (1 << 35)
    row_counts = (1, 3, 2, 0, 0, 0, 2, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    row_counts += (0,) * 5
    row_counts += (1, 0, 0, 2)

    tilde = bytearray()
    tilde.extend(struct.pack("<IBBBBQQ", 0, 2, 0, 0, 0, valid, sorted_tables))
    for index in range(36):
        if valid & (1 << index):
            tilde.extend(struct.pack("<I", row_counts[index]))
    tilde.extend(tables)

    streams = [
        (b"#~", bytes(tilde)),
        (b"#Strings", bytes(strings.data)),
        (b"#Blob", bytes(blobs.data)),
        (b"#US", b"\x00"),
        (b"#GUID", b"\x00" * 16),
    ]

    version = b"v4.0.30319\x00\x00"
    metadata = bytearray()
    metadata.extend(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)))
    metadata.extend(version)
    metadata.extend(struct.pack("<HH", 0, len(streams)))
    data_offset = len(metadata) + sum(8 + len(name) + (4 - len(name) % 4) for name, _ in streams)

    current = data_offset
    payloads = bytearray()
    for name, payload in streams:
        metadata.extend(struct.pack("<II", current, len(payload)))
        name_field_len = len(name) + (4 - len(name) % 4)
        metadata.extend(name + b"\x00" * (name_field_len - len(name)))
        payloads.extend(payload)
        current += len(payload)
    metadata.extend(payloads)

    clr_header = struct.pack(
        "<IHHIIIIIIIIIIIIIIII",
        0x48,
        2,
        5,
        0x2048,
        len(metadata),
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    section_data = bytearray(0x400)
    section_data[0:len(clr_header)] = clr_header
    section_data[0x48:0x48 + len(metadata)] = metadata

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 14 * 8, 0x2000, 0x48)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        6,
        0,
        0,
        0,
        0,
        0,
        0x2000,
        0x2000,
        0x400000,
        0x2000,
        0x200,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        0x4000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    ) + bytes(directories)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x400,
        0x2000,
        0x400,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    pe = bytearray()
    pe.extend(dos)
    pe.extend(b"PE\x00\x00")
    pe.extend(coff)
    pe.extend(optional)
    pe.extend(section)
    pe.extend(b"\x00" * (0x200 - len(pe)))
    pe.extend(section_data)
    return bytes(pe)


def write_security_fixture(path):
    path = Path(path)
    path.write_bytes(build_security_fixture())
    return path
