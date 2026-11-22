"""Build minimal but fully valid PE images with hand-crafted resource trees.

The helper in this module assembles a PE32 image containing a single
``.rsrc`` section from raw structures, giving the tests full control over
which resource types, names and language leaves exist. No third party
tooling is required and nothing is written outside the test directory.
"""

import struct


# (primary language id, sublanguage id) pairs used by the test corpus.
NEUTRAL = (0x00, 0x00)
ENGLISH_US = (0x09, 0x01)
ENGLISH_UK = (0x09, 0x02)
FRENCH_FRANCE = (0x0C, 0x01)


def lcid(primary_language, sublanguage=None):
    """Pack a primary language id and sublanguage id the Win32 way.

    Accepts either two integer arguments or a single
    ``(primary_language, sublanguage)`` pair.
    """

    if sublanguage is None:
        primary_language, sublanguage = primary_language
    return (sublanguage << 10) | primary_language


def _resource_directory(number_of_id_entries=0, number_of_named_entries=0):
    return struct.pack(
        "<IIHHHH",
        0,  # Characteristics
        0,  # TimeDateStamp
        0,  # MajorVersion
        0,  # MinorVersion
        number_of_named_entries,
        number_of_id_entries,
    )


def _directory_entry(name, offset_to_data, data_is_directory):
    return struct.pack(
        "<II",
        name,
        (0x80000000 if data_is_directory else 0) | offset_to_data,
    )


def _data_entry(rva, size, code_page=0):
    return struct.pack("<IIII", rva, size, code_page, 0)


def _normalize_leaves(resources):
    """Flatten the resource spec into ordered, uniquely keyed leaves.

    A language may map to bytes or to a list of bytes; the latter creates
    several data entries under the same language id, which is how equally
    preferred duplicate resources are represented on disk.
    """

    leaves = []
    for type_id, named_resources in resources.items():
        for resource_name, language_map in named_resources.items():
            for language, content in language_map.items():
                primary_language, sublanguage = language
                values = content if isinstance(content, list) else [content]
                for occurrence, value in enumerate(values):
                    leaves.append(
                        (
                            type_id,
                            resource_name,
                            primary_language,
                            sublanguage,
                            occurrence,
                            value,
                        )
                    )
    return leaves


def build_resource_section(resources, section_rva=0x1000):
    """Build a ``.rsrc`` section body for a resource specification.

    resources is a mapping of resource type id to a mapping of resource name
    (integer ids only, the tests do not need named resources) to a mapping of
    (primary language, sublanguage) pairs to raw bytes, or a list of raw byte
    strings for duplicate same-language leaves.
    """

    leaves = _normalize_leaves(resources)

    type_directory_offset = 0
    type_count = len(resources)
    type_table_offset = type_directory_offset + 16
    type_table_size = type_count * 8

    name_directory_offsets = {}
    cursor = type_table_offset + type_table_size
    for type_id, named_resources in resources.items():
        name_directory_offsets[type_id] = cursor
        cursor += 16 + len(named_resources) * 8

    language_directory_offsets = {}
    for type_id, named_resources in resources.items():
        for resource_name, language_map in named_resources.items():
            key = (type_id, resource_name)
            language_directory_offsets[key] = cursor
            entry_count = sum(
                len(value) if isinstance(value, list) else 1
                for value in language_map.values()
            )
            cursor += 16 + entry_count * 8

    data_entry_offsets = {}
    for index, leaf in enumerate(leaves):
        data_entry_offsets[index] = cursor
        cursor += 16

    data_base_offset = cursor
    blob_base_offset = cursor  # cursor already includes every data entry
    blob_base_rva = section_rva + blob_base_offset

    output = bytearray()
    output += _resource_directory(number_of_id_entries=type_count)
    for type_id in resources:
        output += _directory_entry(
            type_id, name_directory_offsets[type_id], data_is_directory=True
        )

    for type_id, named_resources in resources.items():
        output += _resource_directory(number_of_id_entries=len(named_resources))
        for resource_name in named_resources:
            output += _directory_entry(
                resource_name,
                language_directory_offsets[(type_id, resource_name)],
                data_is_directory=True,
            )

    for type_id, named_resources in resources.items():
        for resource_name, language_map in named_resources.items():
            entry_count = sum(
                len(value) if isinstance(value, list) else 1
                for value in language_map.values()
            )
            output += _resource_directory(number_of_id_entries=entry_count)
            for index, leaf in enumerate(leaves):
                leaf_type, leaf_name, primary, sub, _occurrence, _value = leaf
                if (leaf_type, leaf_name) != (type_id, resource_name):
                    continue
                output += _directory_entry(
                    lcid(primary, sub),
                    data_entry_offsets[index],
                    data_is_directory=False,
                )

    blob_cursor = blob_base_rva
    for index, leaf in enumerate(leaves):
        value = leaf[5]
        output += _data_entry(blob_cursor, len(value))
        blob_cursor += len(value)

    assert len(output) == blob_base_offset
    output += b"".join(leaf[5] for leaf in leaves)
    return bytes(output)


def build_pe(resources):
    """Return the bytes of a PE32 image whose only section is ``.rsrc``."""

    section_rva = 0x1000
    section_body = build_resource_section(resources, section_rva=section_rva)

    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    raw_size = (
        (len(section_body) + file_alignment - 1) // file_alignment
    ) * file_alignment
    section_body = section_body + b"\x00" * (raw_size - len(section_body))

    dos_header = bytearray(0x40)
    dos_header[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)
    dos_stub = b"\x00" * (e_lfanew - len(dos_header))

    number_of_sections = 1
    size_of_optional_header = 0xE0
    pe_header = bytearray()
    pe_header += b"PE\x00\x00"
    pe_header += struct.pack(
        "<HHIIIHH",
        0x14C,  # Machine: i386
        number_of_sections,
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_of_optional_header,
        0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    size_of_image = section_rva + section_alignment
    optional_header = bytearray(size_of_optional_header)
    struct.pack_into(
        "<HBBIIIII",
        optional_header,
        0,
        0x10B,  # Magic: PE32
        0,  # MajorLinkerVersion
        0,  # MinorLinkerVersion
        raw_size,  # SizeOfCode
        0,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        section_rva,  # AddressOfEntryPoint (inside .rsrc, harmless for parsing)
        0,  # BaseOfCode
    )
    struct.pack_into(
        "<I",
        optional_header,
        24,
        0,  # BaseOfData (PE32 only)
    )
    struct.pack_into(
        "<II",
        optional_header,
        28,
        0x400000,  # ImageBase
        section_alignment,  # SectionAlignment
    )
    struct.pack_into(
        "<II",
        optional_header,
        36,
        file_alignment,  # FileAlignment
        0,  # OS versions
    )
    struct.pack_into(
        "<HHHHHHIIIIHHIIII",
        optional_header,
        40,
        0,  # MajorOperatingSystemVersion
        0,  # MinorOperatingSystemVersion
        0,  # MajorImageVersion
        0,  # MinorImageVersion
        0,  # MajorSubsystemVersion
        0,  # MinorSubsystemVersion
        0,  # Win32VersionValue
        size_of_image,  # SizeOfImage
        headers_size,  # SizeOfHeaders
        0,  # CheckSum
        3,  # Subsystem: WINDOWS_CUI
        0,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
    )
    struct.pack_into(
        "<II",
        optional_header,
        88,
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    # Data directory entry 2 is IMAGE_DIRECTORY_ENTRY_RESOURCE.
    struct.pack_into(
        "<II",
        optional_header,
        96 + 2 * 8,
        section_rva,
        raw_size,
    )

    section_name = b".rsrc\x00\x00\x00"
    section_header = section_name + struct.pack(
        "<IIIIIIHHI",
        len(section_body),  # VirtualSize
        section_rva,  # VirtualAddress
        raw_size,  # SizeOfRawData
        headers_size,  # PointerToRawData
        0,  # PointerToRelocations
        0,  # PointerToLinenumbers
        0,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        0x40000040,  # Characteristics: INITIALIZED_DATA | READ
    )

    headers = (
        bytes(dos_header)
        + dos_stub
        + bytes(pe_header)
        + bytes(optional_header)
        + section_header
    )
    headers = headers + b"\x00" * (headers_size - len(headers))
    return headers + section_body


def build_pe_file(path, resources):
    """Write a synthetic PE image to path and return the path."""

    with open(path, "wb") as output:
        output.write(build_pe(resources))
    return path
