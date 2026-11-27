#!/usr/bin/env python3
"""Render evidence boundaries for a tiny in-memory PE and two samples."""

import json
import struct

import pefile


def _minimal_pe():
    """Build a 0x400-byte PE32 with one 0x200-byte .text section."""

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    file_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine = I386
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xE0,  # SizeOfOptionalHeader
        0x0102,  # Characteristics
    )

    section_alignment = 0x1000
    file_alignment = 0x200
    virtual_size = 0x200
    size_of_raw_data = 0x200
    pointer_to_raw_data = 0x200
    virtual_address = 0x1000
    size_of_image = 0x2000

    optional_header = (
        struct.pack("<HBB", 0x010B, 14, 0)
        + struct.pack("<I", size_of_raw_data)
        + struct.pack("<II", 0, 0)
        + struct.pack("<I", virtual_address)
        + struct.pack("<II", virtual_address, 0)
        + struct.pack("<I", 0x400000)
        + struct.pack("<II", section_alignment, file_alignment)
        + struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", size_of_image)
        + struct.pack("<I", 0x200)
        + struct.pack("<I", 0)
        + struct.pack("<HH", 2, 0x8100)
        + struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
        + struct.pack("<II", 0, 16)
        + b"\x00" * 128
    )
    assert len(optional_header) == 0xE0

    section_header = (
        b".text\x00\x00\x00"
        + struct.pack("<I", virtual_size)
        + struct.pack("<I", virtual_address)
        + struct.pack("<I", size_of_raw_data)
        + struct.pack("<I", pointer_to_raw_data)
        + struct.pack("<IIHHI", 0, 0, 0, 0, 0x60000020)
    )
    headers = (
        bytes(dos_header)
        + b"PE\x00\x00"
        + file_header
        + optional_header
        + section_header
    ).ljust(pointer_to_raw_data, b"\x00")

    section_data = bytes((index * 7 + 3) & 0xFF for index in range(0x200))
    return headers + section_data


def _make_view(pe, raw, regions):
    samples = []
    for name, start, end, address in regions:
        samples.append(
            pefile.ReadOnlySample(
                name,
                raw[start:end],
                disk_offset=start,
                address=address,
            )
        )
    return pe.get_evidence_view(pe.sections[0], samples=samples)


def _print_boundaries(title, view):
    print("=" * 78)
    print(title)
    print("=" * 78)
    print(view.render())
    print("\nExact boundary JSON:")
    print(
        json.dumps(
            {
                "structure": view.structure.to_dict(),
                "status": view.status,
                "sample_coverage": {
                    "status": view.sample_coverage.status,
                    "coverage": view.sample_coverage.coverage_status,
                    "integrity": view.sample_coverage.integrity,
                    "ranges": [item.to_dict() for item in view.sample_coverage.ranges],
                    "gaps": [item.to_dict() for item in view.sample_coverage.gaps],
                },
                "evidence_segments": [segment.to_dict() for segment in view.segments],
            },
            indent=2,
        )
    )


def main():
    raw = _minimal_pe()
    pe = pefile.PE(data=raw, fast_load=True)
    section_start = pe.sections[0].get_file_offset()
    section_end = section_start + pe.sections[0].sizeof()

    # The two samples are adjacent and together cover the complete section
    # header [0x138, 0x160).  Their source-local addresses remain distinct.
    full_view = _make_view(
        pe,
        raw,
        [
            ("sample-a", 0x120, 0x150, 0x7FF800000120),
            ("sample-b", 0x150, 0x168, 0x7FF900000150),
        ],
    )
    _print_boundaries(
        "CASE 1: FULL COVERAGE (adjacent samples, no missing interval)",
        full_view,
    )

    # The sample ranges are non-adjacent.  The exact gap is [0x150, 0x158);
    # the model keeps that gap and refuses to assemble a complete structure.
    gap_view = _make_view(
        pe,
        raw,
        [
            ("sample-a", 0x120, 0x150, 0x7FF800000120),
            ("sample-b", 0x158, 0x168, 0x7FF900000158),
        ],
    )
    _print_boundaries(
        "CASE 2: MIDDLE GAP (samples must not be stitched together)",
        gap_view,
    )
    print("\n" + "=" * 78)
    print(f"section header disk boundary: [0x{section_start:08x}, 0x{section_end:08x})")
    print("full sample coverage :", full_view.sample_coverage.status)
    print("gap sample coverage  :", gap_view.sample_coverage.status)
    print(
        "gap exact boundary   :",
        ", ".join(
            f"[0x{item.start:08x}, 0x{item.end:08x})"
            for item in gap_view.sample_coverage.gaps
        ),
    )
    try:
        gap_view.cite_samples()
    except pefile.EvidenceUnavailable as error:
        print("sample-set citation  : refused ->", error)
    pe.close()


if __name__ == "__main__":
    main()
