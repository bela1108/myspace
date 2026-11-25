"""Offline minimal PE32 DLL builder with a fully controlled export directory.

The generated images are intentionally tiny (no code section, no relocations,
no imports) but valid enough for ``pefile`` to parse the export directory.
They support every export flavour needed for the offline ABI audit:

* regular named exports, including several names sharing one ordinal
  ("重名别名");
* ordinal-only exports (``name=None``);
* explicit forwarders whose RVA points into the export directory;
* gaps in the export address table (reserved/unused ordinals).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_DLL = 0x2000
IMAGE_SIZEOF_SHORT_NAME = 8

SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x400
IMAGE_BASE = 0x10000000
SECTION_RVA = SECTION_ALIGNMENT


@dataclass(frozen=True)
class ExportSpec:
    """One export slot in the synthetic DLL.

    ``ordinal`` is the public ordinal (including the export base).
    ``name=None`` produces an ordinal-only export. ``forwarder`` is the raw
    forwarder string, e.g. ``OTHER.Func`` or ``OTHER.#7``; when present the
    EAT entry points into the export directory instead of at code.
    Multiple specs may share an ordinal to model duplicate-name aliases.
    """

    ordinal: int
    name: str | None
    forwarder: str | None = None


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _build_export_blob(
    exports: list[ExportSpec],
    base_ordinal: int,
    dll_name: str,
) -> tuple[bytes, int, int]:
    """Return (blob, export_directory_size, number_of_functions).

    Layout inside ``.rdata`` (all RVAs are relative to ``SECTION_RVA``):
    export directory (40 bytes), EAT, name pointer table, ordinal table,
    strings (DLL name, symbol names, forwarders), one RET stub per real export.
    """

    named = [spec for spec in exports if spec.name is not None]
    ordinals = sorted({spec.ordinal for spec in exports})
    first_ordinal = min(ordinals)
    last_ordinal = max(ordinals)
    number_of_functions = last_ordinal - base_ordinal + 1

    directory = bytearray(40)
    eat = bytearray(number_of_functions * 4)
    name_table = bytearray(len(named) * 4)
    ordinal_table = bytearray(len(named) * 2)
    strings = bytearray()

    def add_string(text: str) -> int:
        offset = 40 + len(eat) + len(name_table) + len(ordinal_table) + len(strings)
        strings.extend(text.encode("ascii") + b"\x00")
        return offset

    dll_name_offset = add_string(dll_name)

    # Forwarder strings live in the export region so that the EAT RVA falls
    # inside the export data directory (that is how the loader/pefile tell a
    # forwarder apart from a real function).
    forwarder_offsets: dict[str, int] = {}
    for spec in exports:
        if spec.forwarder is not None and spec.forwarder not in forwarder_offsets:
            forwarder_offsets[spec.forwarder] = add_string(spec.forwarder)

    region_end = 40 + len(eat) + len(name_table) + len(ordinal_table) + len(strings)
    export_directory_size = region_end

    # One byte of "code" (RET) per distinct real export, placed beyond the
    # export directory so its RVA is not mistaken for a forwarder.
    stub_offsets: dict[int, int] = {}
    real_ordinals = sorted(
        {spec.ordinal for spec in exports if spec.forwarder is None}
    )
    for position, ordinal in enumerate(real_ordinals):
        stub_offsets[ordinal] = region_end + position

    def region_rva(offset: int) -> int:
        # RVAs are relative to the image base; the section starts at
        # SECTION_RVA, so no IMAGE_BASE is added here.
        return SECTION_RVA + offset

    # Fill the export address table; zero entries stay as reserved gaps.
    for spec in exports:
        eat_index = spec.ordinal - base_ordinal
        if spec.forwarder is not None:
            value = region_rva(forwarder_offsets[spec.forwarder])
        else:
            value = region_rva(stub_offsets[spec.ordinal])
        struct.pack_into("<I", eat, eat_index * 4, value)

    # Name pointer table (sorted for realism) + matching ordinal table.
    ordered_named = sorted(named, key=lambda spec: spec.name)
    for position, spec in enumerate(ordered_named):
        name_offset = add_string(spec.name)
        struct.pack_into("<I", name_table, position * 4, region_rva(name_offset))
        struct.pack_into(
            "<H", ordinal_table, position * 2, spec.ordinal - base_ordinal
        )

    eat_rva = SECTION_RVA + 40
    name_rva = eat_rva + len(eat)
    ordinal_rva = name_rva + len(name_table)

    # IMAGE_EXPORT_DIRECTORY: Characteristics(I), TimeDateStamp(I),
    # Major/Minor(H, H), Name(I), Base(I), NumberOfFunctions(I),
    # NumberOfNames(I), AddressOfFunctions(I), AddressOfNames(I),
    # AddressOfNameOrdinals(I).
    struct.pack_into(
        "<IIHHIIIIIII",
        directory,
        0,
        0,  # Characteristics
        0,  # TimeDateStamp
        0,  # MajorVersion
        0,  # MinorVersion
        region_rva(dll_name_offset),  # Name RVA
        base_ordinal,  # Base ordinal
        number_of_functions,  # NumberOfFunctions
        len(named),  # NumberOfNames
        region_rva(eat_rva - SECTION_RVA),  # AddressOfFunctions
        region_rva(name_rva - SECTION_RVA),  # AddressOfNames
        region_rva(ordinal_rva - SECTION_RVA),  # AddressOfNameOrdinals
    )

    blob = (
        bytes(directory)
        + bytes(eat)
        + bytes(name_table)
        + bytes(ordinal_table)
        + bytes(strings)
        + b"\xc3" * len(real_ordinals)
    )
    return blob, export_directory_size, number_of_functions


def build_dll(
    exports: list[ExportSpec],
    *,
    dll_name: str = "widget.dll",
    base_ordinal: int = 1,
) -> bytes:
    """Build a minimal PE32 DLL image exposing ``exports``."""

    if not exports:
        raise ValueError("at least one export is required")
    ordinals = sorted({spec.ordinal for spec in exports})
    if min(ordinals) < base_ordinal:
        raise ValueError("export ordinals must be >= base ordinal")

    blob, export_size, number_of_functions = _build_export_blob(
        exports, base_ordinal, dll_name
    )
    raw_size = _align(len(blob), FILE_ALIGNMENT)
    raw_blob = blob + b"\x00" * (raw_size - len(blob))

    headers_size = FILE_ALIGNMENT
    section_va = SECTION_RVA
    export_rva = section_va

    # IMAGE_OPTIONAL_HEADER32 standard fields (28 bytes).
    optional_header = struct.pack(
        "<HBBIIIII",
        0x10B,  # Magic, PE32
        1,  # MajorLinkerVersion
        0,  # MinorLinkerVersion
        raw_size,  # SizeOfCode
        raw_size,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        section_va,  # AddressOfEntryPoint
        section_va,  # BaseOfCode
    )
    optional_header += struct.pack("<I", section_va)  # BaseOfData (PE32)

    # IMAGE_OPTIONAL_HEADER32 Windows-specific fields. Together with the
    # 28 standard bytes and 16 data directories (128 bytes) this is 224 bytes.
    optional_header += struct.pack(
        "<IIIHHHHHHIII",
        IMAGE_BASE,
        SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
        0, 0,  # OS version
        0, 0,  # Image version
        0, 0,  # Subsystem version
        0,  # Win32VersionValue
        _align(section_va + raw_size, SECTION_ALIGNMENT),  # SizeOfImage
        headers_size,  # SizeOfHeaders
    )
    optional_header += struct.pack(
        "<IHHIIIII",
        0,  # CheckSum
        3,  # Subsystem: CONSOLE
        0,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,  # LoaderFlags
    )
    number_of_rva_and_sizes = 16
    optional_header += struct.pack("<I", number_of_rva_and_sizes)
    data_directories = [0] * (number_of_rva_and_sizes * 2)
    data_directories[0] = export_rva
    data_directories[1] = export_size
    for index in range(0, len(data_directories), 2):
        optional_header += struct.pack(
            "<II", data_directories[index], data_directories[index + 1]
        )

    # IMAGE_FILE_HEADER is exactly 20 bytes: machine (H), section count (H),
    # timestamp (I), symbol table ptr (I), symbol count (I), optional header
    # size (H), characteristics (H).
    file_header = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_I386,
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        len(optional_header),  # SizeOfOptionalHeader
        IMAGE_FILE_DLL,  # Characteristics
    )

    section_header = b".rdata".ljust(IMAGE_SIZEOF_SHORT_NAME, b"\x00")
    section_header += struct.pack(
        "<IIIIIIHHI",
        raw_size,  # VirtualSize
        section_va,  # VirtualAddress
        raw_size,  # SizeOfRawData
        headers_size,  # PointerToRawData
        0,  # PointerToRelocations
        0,  # PointerToLinenumbers
        0,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        0x40000040,  # Characteristics: INITIALIZED_DATA | READ
    )

    dos_header = bytearray(FILE_ALIGNMENT)
    struct.pack_into("<H", dos_header, 0, IMAGE_DOS_SIGNATURE)
    struct.pack_into("<I", dos_header, 0x3C, 0x80)  # e_lfanew
    pe_offset = 0x80
    dos_header[pe_offset : pe_offset + 4] = struct.pack("<I", IMAGE_NT_SIGNATURE)
    cursor = pe_offset + 4
    dos_header[cursor : cursor + len(file_header)] = file_header
    cursor += len(file_header)
    dos_header[cursor : cursor + len(optional_header)] = optional_header
    cursor += len(optional_header)
    dos_header[cursor : cursor + len(section_header)] = section_header

    return bytes(dos_header) + raw_blob
