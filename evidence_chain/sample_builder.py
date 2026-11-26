"""Build minimal .NET PE samples for fixtures and demonstrations.

The compliance audit consumes normal samples with dnfile; this builder
synthesizes small but well-formed managed PE images carrying a chosen
module name and Mvid, so tests and demos can run fully offline without
committing binaries.  Each image contains a CLR header, a metadata root
with a #~ tables stream (Module table only), and #Strings/#US/#GUID/#Blob
heaps, mirroring what a compiler would emit for a nearly empty module.
"""

from __future__ import annotations

import struct
import uuid
from pathlib import Path
from typing import Union

_FILE_ALIGNMENT = 0x200
_SECTION_ALIGNMENT = 0x2000
_CLR_RVA = 0x2000
_CLR_HEADER_SIZE = 72


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _metadata_streams(module_name: str, mvid: uuid.UUID) -> bytes:
    strings = b"\x00" + module_name.encode("utf-8") + b"\x00"
    user_strings = b"\x00"
    guids = mvid.bytes_le
    blobs = b"\x00"
    # #~ stream: header, one valid table (Module), one row
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, 0x1, 0x0)
    tables += struct.pack("<I", 1)  # Module row count
    # Generation, Name -> #Strings[1], Mvid -> #GUID[1], EncId, EncBaseId
    tables += struct.pack("<HHHHH", 0, 1, 1, 0, 0)

    streams = [
        (b"#~", tables),
        (b"#Strings", strings),
        (b"#US", user_strings),
        (b"#GUID", guids),
        (b"#Blob", blobs),
    ]
    version = b"v4.0.30319\x00"
    version += b"\x00" * (_align(len(version), 4) - len(version))
    header = struct.pack("<IHHI", 0x424A5342, 1, 1, 0)
    header += struct.pack("<I", len(version)) + version
    header += struct.pack("<HH", 0, len(streams))

    offset = len(header) + sum(
        8 + _align(len(name) + 1, 4) for name, _ in streams
    )
    entries = b""
    bodies = b""
    cursor = offset
    for name, data in streams:
        entries += struct.pack("<II", cursor, len(data)) + name + b"\x00"
        entries += b"\x00" * (_align(len(name) + 1, 4) - (len(name) + 1))
        bodies += data
        bodies += b"\x00" * (_align(len(bodies), 4) - len(bodies))
        cursor += _align(len(data), 4)
    return header + entries + bodies


def build_sample(module_name: str, mvid: Union[str, uuid.UUID]) -> bytes:
    """Return the bytes of a minimal managed PE with the given identity."""
    if not isinstance(mvid, uuid.UUID):
        mvid = uuid.UUID(str(mvid))
    metadata = _metadata_streams(module_name, mvid)

    clr = struct.pack(
        "<IHHII", _CLR_HEADER_SIZE, 2, 5, _CLR_RVA + _CLR_HEADER_SIZE,
        len(metadata),
    )
    clr += struct.pack("<II", 1, 0x06000001)  # ILONLY, entry token
    clr += b"\x00" * (_CLR_HEADER_SIZE - len(clr))

    section = clr + metadata
    section += b"\x00" * (_align(len(section), _FILE_ALIGNMENT) - len(section))

    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x210E)
    opt = struct.pack("<HBBIIIIII", 0x10B, 8, 0, len(section), 0, 0, 0,
                      _SECTION_ALIGNMENT, 0)
    opt += struct.pack("<III", 0x400000, _SECTION_ALIGNMENT, _FILE_ALIGNMENT)
    opt += struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0)
    opt += struct.pack("<IIII", 0, _SECTION_ALIGNMENT * 2, _FILE_ALIGNMENT, 0)
    opt += struct.pack("<HH", 3, 0x8560)
    opt += struct.pack("<IIIIII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    directories = b"\x00" * (14 * 8)
    directories += struct.pack("<II", _CLR_RVA, _CLR_HEADER_SIZE)
    directories += b"\x00" * 8
    opt += directories
    section_header = b".text\x00\x00\x00"
    section_header += struct.pack(
        "<IIIIIIHHI",
        len(clr) + len(metadata),
        _SECTION_ALIGNMENT,
        len(section),
        _FILE_ALIGNMENT,
        0, 0, 0, 0,
        0x60000020,
    )
    headers = dos + b"\x00" * (0x80 - len(dos))
    headers += b"PE\x00\x00" + coff + opt + section_header
    headers += b"\x00" * (_FILE_ALIGNMENT - len(headers))
    return headers + section


def write_sample(
    path: Union[str, Path], module_name: str, mvid: Union[str, uuid.UUID]
) -> Path:
    """Write a minimal managed PE sample to path and return the path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(build_sample(module_name, mvid))
    return target
