#!/usr/bin/env python3
"""Read-only provenance audit for resources copied between PE files.

This module is a small command-line and fixture-building wrapper around the
audit API implemented by pefile. Reports retain offsets, section names,
RVA/size ranges and SHA-256 provenance, but never include resource bytes.
"""

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pefile
from pefile import (
    RESOURCE_RANGE_CANDIDATE,
    RESOURCE_RANGE_OUT_OF_RANGE,
    RESOURCE_RANGE_VERIFIED,
    ResourceRangeAuditor,
    audit_resource_ranges,
)

ALPHA_PAYLOAD = b"PE-AUDIT-ALPHA-RANGE-PROOF-0001\n"
DUPLICATE_PAYLOAD = b"PE-AUDIT-DUPLICATE-BYTES-7788\n"
CROSS_ALIGN_PAYLOAD = b"PE-AUDIT-CROSS-ALIGN-PAYLOAD-0002\n"
PADDED_PAYLOAD = b"PE-AUDIT-PADDED-BOUNDARY-0004\n"


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) // alignment * alignment


def build_tiny_resource_pe(
    path: Path,
    resources: List[Tuple[int, Any, int, bytes, Any]],
    *,
    file_alignment: int = 0x200,
    section_alignment: int = 0x1000,
    decoy: Optional[bytes] = None,
    text_virtual_size: int = 64,
) -> Dict[str, Any]:
    """Build a tiny benign PE containing one .text and one .rsrc section."""
    path = Path(path)
    machine = 0x14C
    section_count = 2
    e_lfanew = 0x40
    optional_header_size = 0xE0
    section_table_end = e_lfanew + 4 + 20 + optional_header_size + 40 * section_count
    size_of_headers = align_up(section_table_end, file_alignment)

    text_raw_offset = size_of_headers
    text_raw_size = align_up(max(text_virtual_size, 64), file_alignment)
    resource_raw_offset = text_raw_offset + text_raw_size

    count = len(resources)
    type_directory_offset = 24
    name_directory_start = type_directory_offset + 16 + 8 * count
    name_directory_offsets = [
        name_directory_start + 24 * index for index in range(count)
    ]
    data_entry_start = name_directory_start + 24 * count
    data_entry_offsets = [data_entry_start + 16 * index for index in range(count)]
    payload_start = align_up(data_entry_start + 16 * count, 8)

    payload_offsets: List[int] = []
    cursor = payload_start
    for _resource_type, _resource_id, _language, payload, _key in resources:
        payload_offsets.append(cursor)
        cursor += align_up(len(payload), 8)
    resource_used_size = cursor
    resource_raw_size = align_up(resource_used_size, file_alignment)

    resource_blob = bytearray(resource_raw_size)

    def pack_directory(offset: int, id_count: int) -> None:
        struct.pack_into("<IIHHHH", resource_blob, offset, 0, 0, 0, 0, 0, id_count)

    pack_directory(0, 1)
    struct.pack_into(
        "<II",
        resource_blob,
        16,
        int(pefile.RESOURCE_TYPE["RT_RCDATA"]),
        0x80000000 | type_directory_offset,
    )
    pack_directory(type_directory_offset, count)

    for index, (resource, name_offset, data_entry_offset) in enumerate(
        zip(resources, name_directory_offsets, data_entry_offsets)
    ):
        _resource_type, resource_id, language, payload, _key = resource
        payload_offset = payload_offsets[index]
        struct.pack_into(
            "<II",
            resource_blob,
            type_directory_offset + 16 + 8 * index,
            resource_id,
            0x80000000 | name_offset,
        )
        pack_directory(name_offset, 1)
        struct.pack_into(
            "<II", resource_blob, name_offset + 16, language, data_entry_offset
        )
        struct.pack_into(
            "<IIII", resource_blob, data_entry_offset, 0, len(payload), 0, 0
        )
        resource_blob[payload_offset : payload_offset + len(payload)] = payload

    text_va = 0x1000
    if section_alignment >= 0x1000:
        resource_va = align_up(text_va + 0x1000, section_alignment)
    else:
        resource_va = align_up(text_va + text_raw_size, section_alignment)
    size_of_image = align_up(resource_va + resource_used_size, section_alignment)

    for data_entry_offset, payload_offset in zip(data_entry_offsets, payload_offsets):
        struct.pack_into(
            "<I",
            resource_blob,
            data_entry_offset,
            resource_va + payload_offset,
        )

    text_bytes = bytearray(text_raw_size)
    text_bytes[:18] = b"benign-text-sample"
    if decoy is not None:
        if len(decoy) > text_raw_size - text_virtual_size:
            raise ValueError("decoy does not fit in section padding")
        decoy_offset = text_raw_size - len(decoy)
        text_bytes[decoy_offset : decoy_offset + len(decoy)] = decoy

    total_size = resource_raw_offset + resource_raw_size
    image = bytearray(total_size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, e_lfanew)
    image[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        image,
        e_lfanew + 4,
        machine,
        section_count,
        0,
        0,
        0,
        optional_header_size,
        0x0102,
    )
    optional_header = struct.pack(
        "<HBB9I6H4I2H6I",
        0x10B,
        0,
        0,
        text_raw_size,
        resource_raw_size,
        0,
        0,
        text_va,
        text_va,
        0x400000,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        size_of_headers,
        0,
        2,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional_offset = e_lfanew + 24
    image[optional_offset : optional_offset + len(optional_header)] = optional_header
    resource_directory_index = 2
    struct.pack_into(
        "<II",
        image,
        optional_offset + 96 + 8 * resource_directory_index,
        resource_va,
        resource_used_size,
    )

    section_table_offset = e_lfanew + 4 + 20 + optional_header_size
    section_headers = [
        (
            b".text",
            text_virtual_size,
            text_va,
            text_raw_size,
            text_raw_offset,
            0x60000020,
        ),
        (
            b".rsrc",
            resource_used_size,
            resource_va,
            resource_raw_size,
            resource_raw_offset,
            0x40000040,
        ),
    ]
    for index, (name, virtual_size, va, raw_size, raw_offset, chars) in enumerate(
        section_headers
    ):
        offset = section_table_offset + 40 * index
        struct.pack_into(
            "<8sIIIIIIHHI",
            image,
            offset,
            name,
            virtual_size,
            va,
            raw_size,
            raw_offset,
            0,
            0,
            0,
            0,
            chars,
        )

    image[text_raw_offset : text_raw_offset + text_raw_size] = text_bytes
    image[resource_raw_offset : resource_raw_offset + resource_raw_size] = resource_blob
    path.write_bytes(bytes(image))

    layout: Dict[Any, int] = {}
    descriptions: List[Dict[str, Any]] = []
    for index, resource in enumerate(resources):
        key = resource[4]
        section_offset = payload_offsets[index]
        layout[key] = section_offset
        descriptions.append(
            {
                "key": key,
                "type_id": resource[0],
                "resource_id": resource[1],
                "language_id": resource[2],
                "size": len(resource[3]),
                "section_offset": section_offset,
                "raw_offset": resource_raw_offset + section_offset,
            }
        )

    return {
        "path": str(path),
        "file_alignment": file_alignment,
        "section_alignment": section_alignment,
        "size_bytes": total_size,
        "resource_raw_offset": resource_raw_offset,
        "resource_raw_size": resource_raw_size,
        "layout": layout,
        "resources": descriptions,
    }


def build_benign_resource_pair(
    directory: Union[Path, str],
) -> Dict[str, Any]:
    """Create the two requested tiny benign samples and suggested log records."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    resource_type = int(pefile.RESOURCE_TYPE["RT_RCDATA"])
    source_resources = [
        (resource_type, 101, 1033, ALPHA_PAYLOAD, "alpha"),
        (resource_type, 102, 1033, DUPLICATE_PAYLOAD, "duplicate"),
        (resource_type, 103, 1033, CROSS_ALIGN_PAYLOAD, "cross_align"),
        (resource_type, 104, 1033, PADDED_PAYLOAD, "padded"),
    ]
    target_resources = [
        (resource_type, 201, 2052, ALPHA_PAYLOAD, "alpha"),
        (resource_type, 202, 1033, DUPLICATE_PAYLOAD, "duplicate_a"),
        (resource_type, 203, 1033, DUPLICATE_PAYLOAD, "duplicate_b"),
        (resource_type, 204, 1033, CROSS_ALIGN_PAYLOAD, "cross_align"),
        (resource_type, 205, 1033, PADDED_PAYLOAD, "padded"),
    ]

    source_layout = build_tiny_resource_pe(
        directory / "sealed-source.bin",
        source_resources,
        file_alignment=0x200,
        section_alignment=0x1000,
    )
    target_layout = build_tiny_resource_pe(
        directory / "new-tool.bin",
        target_resources,
        file_alignment=0x80,
        section_alignment=0x80,
        decoy=CROSS_ALIGN_PAYLOAD,
    )

    records = [
        {
            "id": "ALPHA-TRANSFER",
            "section": ".rsrc",
            "section_offset": source_layout["layout"]["alpha"],
            "size": len(ALPHA_PAYLOAD),
            "export_allowed": True,
            "export_ticket": "EXPORT-ALPHA-001",
        },
        {
            "id": "DUPLICATE-TRANSFER",
            "section": ".rsrc",
            "section_offset": source_layout["layout"]["duplicate"],
            "size": len(DUPLICATE_PAYLOAD),
            "export_permission": "granted",
            "export_ticket": "EXPORT-DUP-002",
        },
        {
            "id": "CROSS-ALIGN-TRANSFER",
            "section": ".rsrc",
            "section_offset": source_layout["layout"]["cross_align"],
            "size": len(CROSS_ALIGN_PAYLOAD),
            "export_allowed": True,
            "export_ticket": "EXPORT-CROSS-003",
        },
        {
            "id": "PADDED-TRANSFER",
            "section": ".rsrc",
            "section_offset": source_layout["layout"]["padded"],
            "size": len(PADDED_PAYLOAD) + 16,
            "export_allowed": True,
            "export_ticket": "EXPORT-PAD-005",
            "processing_note": "record rounded the range into alignment padding",
        },
        {
            "id": "GHOST-OFFSET",
            "section": ".rsrc",
            "section_offset": source_layout["resource_raw_size"] - 0x10,
            "size": 0x40,
            "export_allowed": True,
            "export_ticket": "EXPORT-GHOST-004",
        },
    ]

    manifest = {
        "schema": pefile.RESOURCE_RANGE_AUDIT_SCHEMA,
        "source": source_layout["path"],
        "target": target_layout["path"],
        "records": records,
    }
    manifest_path = directory / "resource-transfer-records.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {
        "directory": str(directory),
        "manifest_path": str(manifest_path),
        "manifest": manifest,
        "source": source_layout,
        "target": target_layout,
        "records": records,
    }


def _load_records_argument(value: Optional[str]) -> Any:
    if not value:
        return None
    path = Path(value)
    text = path.read_text(encoding="utf-8") if path.exists() else value
    return json.loads(text)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", help="sealed source PE path")
    parser.add_argument("--target", help="new tool PE path")
    parser.add_argument("--records", help="JSON records file or JSON array")
    parser.add_argument("--manifest", help="JSON manifest with paths and records")
    parser.add_argument("--output", help="write JSON report to this path")
    parser.add_argument(
        "--make-samples",
        metavar="DIR",
        help="generate two tiny benign PE samples and records, then audit them",
    )
    args = parser.parse_args(argv)

    if args.make_samples:
        bundle = build_benign_resource_pair(args.make_samples)
        source = bundle["source"]["path"]
        target = bundle["target"]["path"]
        records = bundle["records"]
    elif args.manifest:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        source = manifest.get("source")
        target = manifest.get("target")
        records = manifest.get("records") or manifest.get("items")
    else:
        source = args.source
        target = args.target
        records = _load_records_argument(args.records)

    if not source or not target or records is None:
        parser.error(
            "provide --source/--target/--records, --manifest, or --make-samples"
        )

    report = audit_resource_ranges(source, target, records)
    rendered = report.to_json()
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    return 0


__all__ = [
    "ALPHA_PAYLOAD",
    "CROSS_ALIGN_PAYLOAD",
    "DUPLICATE_PAYLOAD",
    "PADDED_PAYLOAD",
    "RESOURCE_RANGE_CANDIDATE",
    "RESOURCE_RANGE_OUT_OF_RANGE",
    "RESOURCE_RANGE_VERIFIED",
    "ResourceRangeAuditor",
    "align_up",
    "audit_resource_ranges",
    "build_benign_resource_pair",
    "build_tiny_resource_pe",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
