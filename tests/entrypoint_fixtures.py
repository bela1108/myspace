"""
Hand-assembled, deliberately tiny .NET PE fixtures for entry-point tests.

The metadata tables are not produced by a compiler.  Each row is packed
explicitly in ECMA-335 order so the fixtures stay small enough to audit and
so tests can exercise unusual CLI-header combinations.
"""
import struct
from pathlib import Path


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_32BIT_MACHINE = 0x0100

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000

SECTION_RVA = 0x2000
SECTION_RAW_OFFSET = 0x200
SECTION_RAW_SIZE = 0x600

CLR_HEADER_RVA = SECTION_RVA
METADATA_RVA = SECTION_RVA + 0x48
METHOD_BODY_RVA = SECTION_RVA + 0x200

CLR_ILONLY = 0x00000001
CLR_IL_LIBRARY = 0x00000004
CLR_NATIVE_ENTRYPOINT = 0x00000010

METHOD_ENTRY = 0x06000001
FILE_ENTRY = 0x26000001
ASSEMBLYREF_ENTRY = 0x23000001
NATIVE_ENTRY = METHOD_BODY_RVA
TOKEN_SHAPED_NATIVE_ENTRY = METHOD_ENTRY


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _pack_stream_header(name: bytes, offset: int, size: int) -> bytes:
    padded_name = name + b"\x00"
    padded_name += b"\x00" * ((4 - (len(padded_name) % 4)) % 4)
    return struct.pack("<II", offset, size) + padded_name


def _build_strings_heap() -> bytes:
    # Index zero is the mandatory empty string.
    return (
        b"\x00"
        b"Main\x00"
        b"<Module>\x00"
        b"fixture.exe\x00"
        b"other.dll\x00"
        b"FixtureAssembly\x00"
        b"System.Runtime\x00"
    )


def _build_blob_heap() -> bytes:
    # Index zero is the mandatory empty blob.  Index one is a minimal static
    # method signature: default calling convention, zero arguments, void return.
    return b"\x00\x03\x00\x00\x01"


def _build_guid_heap() -> bytes:
    return b"\x00" * 16


def _build_metadata_tables(
    method_rva: int,
    method_impl_flags: int,
    method_flags: int,
) -> bytes:
    strings = _build_strings_heap()
    idx_main = strings.index(b"Main\x00")
    idx_module_type = strings.index(b"<Module>\x00")
    idx_module_name = strings.index(b"fixture.exe\x00")
    idx_file = strings.index(b"other.dll\x00")
    idx_assembly = strings.index(b"FixtureAssembly\x00")
    idx_assembly_ref = strings.index(b"System.Runtime\x00")

    module_row = struct.pack(
        "<HHHHH",
        0,          # Generation
        idx_module_name,
        1,          # Mvid -> GUID 1
        0,          # EncId
        0,          # EncBaseId
    )
    type_def_row = struct.pack(
        "<IHHHHH",
        0,                  # Flags
        idx_module_type,    # TypeName
        0,                  # TypeNamespace
        0,                  # Extends: nil
        1,                  # FieldList
        1,                  # MethodList
    )
    method_def_row = struct.pack(
        "<IHHHHH",
        method_rva,
        method_impl_flags,
        method_flags,
        idx_main,
        1,          # Signature blob 1
        1,          # ParamList
    )
    assembly_row = struct.pack(
        "<IHHHHIHHH",
        0x8004,             # SHA-1
        1,
        0,
        0,
        0,
        0,                  # Flags
        0,                  # PublicKey
        idx_assembly,
        0,                  # Culture
    )
    assembly_ref_row = struct.pack(
        "<HHHHIHHHH",
        4,
        0,
        0,
        0,
        0,                  # Flags
        0,                  # PublicKeyOrToken
        idx_assembly_ref,
        0,                  # Culture
        0,                  # HashValue
    )
    file_row = struct.pack(
        "<IHH",
        0,          # Contains metadata, not a resource file.
        idx_file,
        0,          # HashValue (empty in this fixture)
    )

    # Tables are ordered by their ECMA-335 table number:
    # Module(0), TypeDef(2), MethodDef(6), Assembly(32), AssemblyRef(35), File(38).
    table_numbers = (0, 2, 6, 32, 35, 38)
    rows = {
        0: module_row,
        2: type_def_row,
        6: method_def_row,
        32: assembly_row,
        35: assembly_ref_row,
        38: file_row,
    }
    valid_mask = sum(1 << number for number in table_numbers)

    table_data = bytearray()
    for number in table_numbers:
        table_data += struct.pack("<I", 1)
    for number in table_numbers:
        table_data += rows[number]

    header = struct.pack(
        "<IBBBBQQ",
        0,      # Reserved
        1,      # MajorVersion
        1,      # MinorVersion
        0,      # HeapOffsetSizes: 2-byte string/blob/GUID indexes
        0,      # Reserved
        valid_mask,
        0,      # MaskSorted
    )
    assert strings and idx_main and idx_assembly_ref
    return header + table_data


def build_metadata(
    method_rva: int = METHOD_BODY_RVA,
    method_impl_flags: int = 0,
    method_flags: int = 0x0010,
    corrupt_signature: bool = False,
) -> bytes:
    table_stream = _build_metadata_tables(method_rva, method_impl_flags, method_flags)
    strings_stream = _build_strings_heap()
    guid_stream = _build_guid_heap()
    blob_stream = _build_blob_heap()

    version = b"v4.0.30319\x00\x00"
    fixed_header_size = 4 + 2 + 2 + 4 + 4 + len(version) + 2 + 2
    stream_header_size = (
        len(_pack_stream_header(b"#~", 0, 0))
        + len(_pack_stream_header(b"#Strings", 0, 0))
        + len(_pack_stream_header(b"#GUID", 0, 0))
        + len(_pack_stream_header(b"#Blob", 0, 0))
    )
    offset = _align(fixed_header_size + stream_header_size, 4)

    table_offset = offset
    offset += len(table_stream)
    offset = _align(offset, 4)

    strings_offset = offset
    offset += len(strings_stream)
    offset = _align(offset, 4)

    guid_offset = offset
    offset += len(guid_stream)
    offset = _align(offset, 4)

    blob_offset = offset
    offset += len(blob_stream)
    offset = _align(offset, 4)

    signature = b"BAD!" if corrupt_signature else struct.pack("<I", 0x424A5342)
    metadata = bytearray(signature)
    metadata += struct.pack("<HHII", 1, 1, 0, len(version))
    metadata += version
    metadata += struct.pack("<HH", 0, 4)
    metadata += _pack_stream_header(b"#~", table_offset, len(table_stream))
    metadata += _pack_stream_header(b"#Strings", strings_offset, len(strings_stream))
    metadata += _pack_stream_header(b"#GUID", guid_offset, len(guid_stream))
    metadata += _pack_stream_header(b"#Blob", blob_offset, len(blob_stream))
    assert len(metadata) == table_offset
    metadata += table_stream
    metadata += b"\x00" * (strings_offset - len(metadata))
    metadata += strings_stream
    metadata += b"\x00" * (guid_offset - len(metadata))
    metadata += guid_stream
    metadata += b"\x00" * (blob_offset - len(metadata))
    metadata += blob_stream
    return bytes(metadata)


def build_pe(
    entry_value: int,
    flags: int = 0,
    method_rva: int = METHOD_BODY_RVA,
    method_impl_flags: int = 0,
    method_flags: int = 0x0010,
    corrupt_metadata: bool = False,
    virtual_size: int = 0x1000,
    clr_directory: bool = True,
) -> bytes:
    metadata = build_metadata(
        method_rva=method_rva,
        method_impl_flags=method_impl_flags,
        method_flags=method_flags,
        corrupt_signature=corrupt_metadata,
    )
    if len(metadata) > METHOD_BODY_RVA - METADATA_RVA:
        raise ValueError("fixture metadata would overlap the method body")

    clr_header = struct.pack(
        "<IHHIIIIIIIIIIIIIIII",
        0x48,           # cb
        2,              # MajorRuntimeVersion
        5,              # MinorRuntimeVersion
        METADATA_RVA,
        len(metadata),
        flags,
        entry_value,
        0, 0,           # Resources
        0, 0,           # StrongNameSignature
        0, 0,           # CodeManagerTable
        0, 0,           # VTableFixups
        0, 0,           # ExportAddressTableJumps
        0, 0,           # ManagedNativeHeader
    )
    assert len(clr_header) == 0x48

    section = bytearray(SECTION_RAW_SIZE)
    section[0:len(clr_header)] = clr_header
    metadata_offset = METADATA_RVA - SECTION_RVA
    section[metadata_offset:metadata_offset + len(metadata)] = metadata
    body_offset = METHOD_BODY_RVA - SECTION_RVA
    # A tiny IL method body: header byte 0x02 (tiny, code size 2), ret, nop.
    section[body_offset:body_offset + 4] = b"\x02\x2a\x00\x00"

    size_of_image = _align(SECTION_RVA + max(virtual_size, 0x1000), 0x1000)

    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_I386,
        1,
        0,
        0,
        0,
        0xE0,
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE,
    )

    optional = bytearray(0xE0)
    struct.pack_into("<HBBIIIII", optional, 0x00, 0x10B, 8, 0, SECTION_RAW_SIZE, 0, 0, 0, SECTION_RVA)
    struct.pack_into("<I", optional, 0x1C, 0x400000)   # ImageBase
    struct.pack_into("<II", optional, 0x20, 0x1000, 0x200)  # Section/FileAlignment
    struct.pack_into("<HHHHHH", optional, 0x28, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<I", optional, 0x38, size_of_image)
    struct.pack_into("<I", optional, 0x3C, 0x200)      # SizeOfHeaders
    struct.pack_into("<H", optional, 0x44, 3)          # Console subsystem
    struct.pack_into("<IIIIII", optional, 0x48, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    com_directory_offset = 0x60 + (14 * 8)
    struct.pack_into(
        "<II",
        optional,
        com_directory_offset,
        CLR_HEADER_RVA if clr_directory else 0,
        0x48 if clr_directory else 0,
    )

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        virtual_size,
        SECTION_RVA,
        SECTION_RAW_SIZE,
        SECTION_RAW_OFFSET,
        0,
        0,
        0,
        0,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    )

    pe = bytearray()
    pe += dos_header
    pe += b"PE\x00\x00"
    pe += coff
    pe += optional
    pe += section_header
    pe += b"\x00" * (SECTION_RAW_OFFSET - len(pe))
    pe += section
    return bytes(pe)


def write_fixture(tmp_path: Path, name: str, **kwargs) -> Path:
    path = Path(tmp_path) / name
    path.write_bytes(build_pe(**kwargs))
    return path


def make_managed_method(tmp_path: Path, **kwargs) -> Path:
    kwargs.setdefault("entry_value", METHOD_ENTRY)
    kwargs.setdefault("flags", CLR_ILONLY)
    return write_fixture(tmp_path, "managed-method.exe", **kwargs)


def make_external_file(tmp_path: Path, **kwargs) -> Path:
    kwargs.setdefault("entry_value", FILE_ENTRY)
    return write_fixture(tmp_path, "external-file.exe", **kwargs)


def make_native(tmp_path: Path, **kwargs) -> Path:
    kwargs.setdefault("entry_value", NATIVE_ENTRY)
    kwargs.setdefault("flags", CLR_NATIVE_ENTRYPOINT)
    return write_fixture(tmp_path, "native-entry.exe", **kwargs)


def make_none(tmp_path: Path, **kwargs) -> Path:
    kwargs.setdefault("entry_value", 0)
    kwargs.setdefault("flags", CLR_IL_LIBRARY)
    return write_fixture(tmp_path, "no-entry.dll", **kwargs)


def make_contradictory(tmp_path: Path, **kwargs) -> Path:
    kwargs.setdefault("entry_value", NATIVE_ENTRY)
    kwargs.setdefault("flags", CLR_ILONLY | CLR_NATIVE_ENTRYPOINT)
    return write_fixture(tmp_path, "contradictory.exe", **kwargs)


def make_token_shaped_native(tmp_path: Path, **kwargs) -> Path:
    kwargs.setdefault("entry_value", TOKEN_SHAPED_NATIVE_ENTRY)
    kwargs.setdefault("flags", CLR_NATIVE_ENTRYPOINT)
    kwargs.setdefault("virtual_size", 0x06000000)
    return write_fixture(tmp_path, "token-shaped-native.exe", **kwargs)


def make_corrupt_metadata(tmp_path: Path, **kwargs) -> Path:
    kwargs.setdefault("entry_value", METHOD_ENTRY)
    kwargs.setdefault("flags", CLR_ILONLY)
    kwargs.setdefault("corrupt_metadata", True)
    return write_fixture(tmp_path, "corrupt-metadata.exe", **kwargs)
