#!/usr/bin/env python3
"""Generate a deterministic AssemblyRef/sealing-manifest forensic sample.

No compiler or CLR host is required.  The tiny PE files contain only the
metadata tables and heaps needed by dnfile for identity comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from assemblyref_audit import public_key_token  # noqa: E402


SECTION_RVA = 0x2000
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
CLI_HEADER_SIZE = 72
MISSING_CULTURE_INDEX = 0xFFFE


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


class StringsHeap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")
        self.offsets = {"": 0}

    def add(self, value: str) -> int:
        if value in self.offsets:
            return self.offsets[value]
        offset = len(self.data)
        self.data.extend(value.encode("utf-8") + b"\x00")
        self.offsets[value] = offset
        return offset


class BlobHeap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")
        self.offsets = {b"": 0}

    def add(self, value: bytes) -> int:
        if value in self.offsets:
            return self.offsets[value]
        offset = len(self.data)
        length = len(value)
        if length < 0x80:
            self.data.append(length)
        elif length < 0x4000:
            self.data.extend(struct.pack("<H", 0x8000 | length))
        else:
            self.data.extend(struct.pack(">I", 0xC0000000 | length))
        self.data.extend(value)
        self.offsets[value] = offset
        return offset


@dataclass(frozen=True)
class IdentitySpec:
    name: str
    version: Tuple[int, int, int, int] = (1, 0, 0, 0)
    culture: Optional[str] = ""
    public_key: bytes = b""
    flags: int = 0


@dataclass(frozen=True)
class RefSpec(IdentitySpec):
    full_public_key: bool = False
    hash_value: bytes = b""


def metadata_bytes(module_name: str, assembly: IdentitySpec, references: Sequence[RefSpec]) -> bytes:
    strings = StringsHeap()
    blobs = BlobHeap()
    rows = {
        0: bytearray(),
        32: bytearray(),
        35: bytearray(),
    }

    module_name_index = strings.add(module_name)
    rows[0].extend(struct.pack("<HHHHH", 0, module_name_index, 0, 0, 0))

    assembly_key_index = blobs.add(assembly.public_key)
    assembly_culture_index = MISSING_CULTURE_INDEX if assembly.culture is None else strings.add(assembly.culture)
    rows[32].extend(
        struct.pack(
            "<IHHHHIHHH",
            0x8004,
            assembly.version[0],
            assembly.version[1],
            assembly.version[2],
            assembly.version[3],
            assembly.flags,
            assembly_key_index,
            strings.add(assembly.name),
            assembly_culture_index,
        )
    )

    for ref in references:
        ref_flags = ref.flags | (0x0001 if ref.full_public_key else 0)
        key_index = blobs.add(ref.public_key)
        name_index = strings.add(ref.name)
        culture_index = MISSING_CULTURE_INDEX if ref.culture is None else strings.add(ref.culture)
        hash_index = blobs.add(ref.hash_value)
        rows[35].extend(
            struct.pack(
                "<HHHHIHHHH",
                ref.version[0],
                ref.version[1],
                ref.version[2],
                ref.version[3],
                ref_flags,
                key_index,
                name_index,
                culture_index,
                hash_index,
            )
        )

    row_sizes = {0: 10, 32: 22, 35: 20}
    valid_mask = 0
    counts = bytearray()
    row_data = bytearray()
    for table_number in sorted(rows):
        data = bytes(rows[table_number])
        if not data:
            continue
        if len(data) % row_sizes[table_number]:
            raise AssertionError(f"table {table_number} has partial row")
        valid_mask |= 1 << table_number
        counts.extend(struct.pack("<I", len(data) // row_sizes[table_number]))
        row_data.extend(data)

    tables_header = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0)
    tables_stream = tables_header + bytes(counts) + bytes(row_data)
    return metadata_root(tables_stream, bytes(strings.data), bytes(blobs.data))


def metadata_root(tables_stream: bytes, strings_stream: bytes, blob_stream: bytes) -> bytes:
    streams = [
        (b"#~", tables_stream),
        (b"#Strings", strings_stream),
        (b"#US", b"\x00"),
        (b"#GUID", b"\x00" * 16),
        (b"#Blob", blob_stream),
    ]
    version = b"v4.0.30319\x00"
    version += b"\x00" * (align(len(version), 4) - len(version))
    header_size = 16 + len(version) + 4
    stream_headers_size = 0
    for name, _ in streams:
        encoded_name = name + b"\x00"
        stream_headers_size += 8 + align(len(encoded_name), 4)
    data_offset = align(header_size + stream_headers_size, 4)

    entries = []
    payload = bytearray()
    for name, data in streams:
        offset = data_offset + len(payload)
        entries.append((name, offset, len(data)))
        payload.extend(data)
        padding = align(len(payload), 4) - len(payload)
        payload.extend(b"\x00" * padding)

    root = bytearray()
    root.extend(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)))
    root.extend(version)
    root.extend(struct.pack("<HH", 0, len(streams)))
    for name, offset, size in entries:
        encoded_name = name + b"\x00"
        root.extend(struct.pack("<II", offset, size))
        root.extend(encoded_name)
        root.extend(b"\x00" * (align(len(encoded_name), 4) - len(encoded_name)))
    if len(root) != data_offset:
        raise AssertionError("metadata header offset mismatch")
    root.extend(payload)
    return bytes(root)


def cli_content(metadata: bytes) -> bytes:
    header = struct.pack(
        "<IHHIIII" + "II" * 6,
        CLI_HEADER_SIZE,
        2,
        5,
        SECTION_RVA + CLI_HEADER_SIZE,
        len(metadata),
        0x00000001,
        0,
        0, 0,
        0, 0,
        0, 0,
        0, 0,
        0, 0,
        0, 0,
    )
    if len(header) != CLI_HEADER_SIZE:
        raise AssertionError("CLI header size mismatch")
    return header + metadata


def wrap_pe(section_content: bytes, dll: bool = True) -> bytes:
    raw_size = align(len(section_content), FILE_ALIGN)
    virtual_size = len(section_content)
    size_of_image = align(SECTION_RVA + virtual_size, SECTION_ALIGN)
    headers_size = FILE_ALIGN

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    characteristics = 0x2102 if dll else 0x0102
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0x00E0, characteristics)
    optional = bytearray(0x00E0)
    struct.pack_into("<H", optional, 0, 0x010B)
    struct.pack_into("<BB", optional, 2, 8, 0)
    struct.pack_into("<I", optional, 4, raw_size)
    struct.pack_into("<I", optional, 8, raw_size)
    struct.pack_into("<I", optional, 16, SECTION_RVA)
    struct.pack_into("<I", optional, 20, SECTION_RVA)
    struct.pack_into("<I", optional, 24, 0x400000)
    struct.pack_into("<I", optional, 28, SECTION_ALIGN)
    struct.pack_into("<I", optional, 32, FILE_ALIGN)
    struct.pack_into("<HHHHHH", optional, 36, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<I", optional, 52, size_of_image)
    struct.pack_into("<I", optional, 56, headers_size)
    struct.pack_into("<H", optional, 64, 3)
    struct.pack_into("<H", optional, 66, 0)
    struct.pack_into("<IIII", optional, 68, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", optional, 88, 16)
    struct.pack_into("<II", optional, 96 + 14 * 8, SECTION_RVA, CLI_HEADER_SIZE)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        virtual_size,
        SECTION_RVA,
        raw_size,
        FILE_ALIGN,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
    headers += b"\x00" * (headers_size - len(headers))
    padding = b"\x00" * (raw_size - len(section_content))
    return headers + section_content + padding


def build_pe(assembly: IdentitySpec, references: Sequence[RefSpec] = (), dll: bool = True) -> bytes:
    metadata = metadata_bytes(assembly.name + ".dll", assembly, references)
    return wrap_pe(cli_content(metadata), dll=dll)


def _key(seed: str) -> bytes:
    # Deterministic, clearly synthetic strong-name blob material.
    material = hashlib.sha256(seed.encode("utf-8")).digest()
    return b"\x00\x24\x00\x00" + material * 5


def build_case(output_root: Path) -> dict:
    references_dir = output_root / "references"
    delivery_dir = output_root / "delivery"
    references_dir.mkdir(parents=True, exist_ok=True)
    delivery_dir.mkdir(parents=True, exist_ok=True)

    widgets_key = _key("contoso.widgets.publisher")
    regional_key = _key("regional.resources.publisher")
    imaging_key_a = _key("imaging.codec.publisher-a")
    imaging_key_b = _key("imaging.codec.publisher-b")
    widgets_token = public_key_token(widgets_key)
    regional_token = public_key_token(regional_key)

    artifacts_specs = [
        (
            "Contoso.Widgets_3.1.0.0.dll",
            IdentitySpec("Contoso.Widgets", (3, 1, 0, 0), "", widgets_key),
            "SEAL-WIDGETS-310",
        ),
        (
            "Contoso.Widgets_4.0.0.0.dll",
            IdentitySpec("Contoso.Widgets", (4, 0, 0, 0), "", widgets_key),
            "SEAL-WIDGETS-400",
        ),
        (
            "Regional.Resources_1.0.0.0_en-US.dll",
            IdentitySpec("Regional.Resources", (1, 0, 0, 0), "en-US", regional_key),
            "SEAL-REGIONAL-EN",
        ),
        (
            "Regional.Resources_1.0.0.0_fr-FR.dll",
            IdentitySpec("Regional.Resources", (1, 0, 0, 0), "fr-FR", regional_key),
            "SEAL-REGIONAL-FR",
        ),
        (
            "Imaging.Codec_5.0.0.0_keyA.dll",
            IdentitySpec("Imaging.Codec", (5, 0, 0, 0), "", imaging_key_a),
            "SEAL-IMAGING-KEYA",
        ),
        (
            "Imaging.Codec_5.0.0.0_keyB.dll",
            IdentitySpec("Imaging.Codec", (5, 0, 0, 0), "", imaging_key_b),
            "SEAL-IMAGING-KEYB",
        ),
    ]

    manifest_artifacts = []
    for file_name, identity, seal_id in artifacts_specs:
        path = delivery_dir / file_name
        path.write_bytes(build_pe(identity))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        culture_record = None if seal_id == "SEAL-REGIONAL-FR" else identity.culture
        manifest_artifacts.append(
            {
                "seal_id": seal_id,
                "delivery_path": f"delivery/{file_name}",
                "sealed_artifact": f"sealed-archive/{seal_id}/{file_name}",
                "sha256": digest,
                "size": path.stat().st_size,
                "identity": {
                    "name": identity.name,
                    "version": ".".join(map(str, identity.version)),
                    "culture": culture_record,
                    "public_key_token": public_key_token(identity.public_key).hex(),
                },
            }
        )

    dispatch_assembly = IdentitySpec("ForensicSample.Dispatch", (1, 0, 0, 0), "")
    dispatch_refs = [
        RefSpec(
            "Contoso.Widgets",
            (3, 1, 0, 0),
            "",
            widgets_token,
        ),
        RefSpec(
            "Regional.Resources",
            (1, 0, 0, 0),
            None,
            regional_token,
        ),
        RefSpec(
            "Imaging.Codec",
            (5, 0, 0, 0),
            "",
            b"",
        ),
    ]
    dispatch_path = references_dir / "Dispatch.exe"
    dispatch_path.write_bytes(build_pe(dispatch_assembly, dispatch_refs, dll=False))

    simple_names = output_root / "legacy-simple-name-list.txt"
    simple_names.write_text("Contoso.Widgets\nRegional.Resources\nImaging.Codec\n", encoding="utf-8")

    manifest = {
        "schema": "independent-sealing-manifest/v1",
        "case_id": "FORENSIC-DNFILE-056",
        "note": "确定性合成案卷，用于验证只读 AssemblyRef 与独立封存清单配对。",
        "artifacts": manifest_artifacts,
    }
    manifest_path = output_root / "sealing-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"root": output_root, "manifest": manifest_path, "dispatch": dispatch_path}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "forensic_case")
    args = parser.parse_args()
    result = build_case(args.output)
    print(result["root"])
    print(result["manifest"])
    print(result["dispatch"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
