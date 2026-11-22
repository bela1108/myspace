# -*- coding: utf-8 -*-
"""Synthetic, metadata-only managed assemblies for ABI tests.

The builder emits a minimal but well-formed PE32 image whose only content is
CLI metadata (Module/TypeRef/TypeDef/Field/MethodDef/Param/Assembly/AssemblyRef
tables plus the four standard heaps).  No IL code is needed: method bodies are
optional for metadata-only responsibility checks and are therefore omitted
(RVA 0, abstract/runtime-implementation flags are not required either).

Everything is constructed in memory; the builder never invokes an external
compiler and never modifies an input file.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# ECMA-335 II.22
TABLE_MODULE = 0x00
TABLE_TYPEREF = 0x01
TABLE_TYPEDEF = 0x02
TABLE_FIELD = 0x04
TABLE_METHODDEF = 0x06
TABLE_PARAM = 0x08
TABLE_MEMBERREF = 0x0A
TABLE_TYPESPEC = 0x1B
TABLE_ASSEMBLY = 0x20
TABLE_ASSEMBLYREF = 0x23

# ECMA-335 II.23.1.16 element types
ELEMENT_TYPE_VOID = 0x01
ELEMENT_TYPE_BOOLEAN = 0x02
ELEMENT_TYPE_I4 = 0x08
ELEMENT_TYPE_STRING = 0x0E
ELEMENT_TYPE_OBJECT = 0x1C
ELEMENT_TYPE_VALUETYPE = 0x11
ELEMENT_TYPE_CLASS = 0x12
ELEMENT_TYPE_SZARRAY = 0x1D
ELEMENT_TYPE_GENERICINST = 0x15
ELEMENT_TYPE_MVAR = 0x1E
ELEMENT_TYPE_VAR = 0x13

# Calling conventions (ECMA-335 II.23.2.3)
DEFAULT_CALL = 0x00
HASTHIS = 0x20
GENERIC = 0x10

# Type attributes (ECMA-335 II.23.1.15)
tdPublic = 0x0001
tdNotPublic = 0x0000
tdNestedPublic = 0x0002
tdNestedPrivate = 0x0003
tdNestedFamily = 0x0004
tdNestedAssembly = 0x0007
tdClass = 0x0000
tdInterface = 0x20
tdAbstract = 0x0080
tdSealed = 0x0100
tdBeforeFieldInit = 0x00100000

# Method attributes (II.23.1.10)
mdMemberAccessMask = 0x0007
mdPrivateScope = 0x0000
mdPrivate = 0x0001
mdFamANDAssem = 0x0002
mdAssem = 0x0003
mdFamily = 0x0004
mdFamORAssem = 0x0005
mdPublic = 0x0006
mdStatic = 0x0010
mdVirtual = 0x0040
mdAbstract = 0x0400

# Field attributes (II.23.1.5)
fdFieldAccessMask = 0x0007
fdPrivate = 0x0001
fdPublic = 0x0006
fdStatic = 0x0010

# Param attributes (II.23.1.12)
pdIn = 0x0001
pdOut = 0x0002
pdOptional = 0x0010


def compress_uint(value: int) -> bytes:
    """Encode an unsigned integer as a CLI compressed (blob) integer."""
    if value < 0:
        raise ValueError("cannot compress negative value")
    if value < 0x80:
        return bytes((value,))
    if value < 0x4000:
        value |= 0x8000
        return struct.pack(">H", value)
    if value < 0x20000000:
        value |= 0xC0000000
        return struct.pack(">I", value)
    raise ValueError("integer out of compressed range")


def _coded_index(tag_bits: int, table_id: int, row_index: int) -> Tuple[int, int]:
    return table_id, (row_index << tag_bits) | table_id


class Heap:
    """A simple index-addressed heap.

    ``mode`` selects the on-disk entry framing:

    * ``"strings"`` - UTF-8 bytes followed by a NUL terminator (#Strings);
    * ``"blob"``    - compressed length prefix followed by the bytes (#Blob);
    * ``"guid"``    - fixed 16-byte entries with no framing (#GUID).
    """

    def __init__(self, mode: str):
        self._mode = mode
        self._chunks: List[bytes] = [b"\x00"]
        self._index: Dict[bytes, int] = {}
        self._size = 1

    def add(self, data: bytes) -> int:
        if not data:
            return 0
        if data in self._index:
            return self._index[data]
        offset = self._size
        self._index[data] = offset
        if self._mode == "strings":
            framed = data + b"\x00"
        elif self._mode == "blob":
            framed = compress_uint(len(data)) + data
        else:
            framed = data
        self._chunks.append(framed)
        self._size += len(framed)
        return offset

    def build(self) -> bytes:
        return b"".join(self._chunks)


@dataclass
class ParamSpec:
    name: str
    type_blob: bytes
    flags: int = 0
    sequence: int = 0


@dataclass
class MethodSpec:
    name: str
    flags: int
    return_blob: bytes
    params: List[ParamSpec] = field(default_factory=list)
    generic_param_count: int = 0


@dataclass
class FieldSpec:
    name: str
    flags: int
    signature: bytes


@dataclass
class TypeSpecModel:
    name: str
    namespace: str
    flags: int
    extends: Optional[Tuple[int, int]] = None  # coded index (table, row), 1-based rows
    methods: List[MethodSpec] = field(default_factory=list)
    fields: List[FieldSpec] = field(default_factory=list)


@dataclass
class TypeRefModel:
    name: str
    namespace: str
    resolution_scope: Optional[Tuple[int, int]] = None  # coded (table, 1-based row)


@dataclass
class AssemblyRefModel:
    name: str
    version: Tuple[int, int, int, int] = (0, 0, 0, 0)
    culture: str = ""


def method_signature(
    param_types: Sequence[bytes],
    return_type: bytes = bytes((ELEMENT_TYPE_VOID,)),
    instance: bool = True,
    generic_param_count: Optional[int] = None,
) -> bytes:
    conv = HASTHIS if instance else DEFAULT_CALL
    if generic_param_count:
        conv |= GENERIC
    out = bytes((conv,))
    if generic_param_count:
        out += compress_uint(generic_param_count)
    out += compress_uint(len(param_types))
    out += return_type
    for param in param_types:
        out += param
    return out


def field_signature(field_type: bytes) -> bytes:
    return bytes((0x06,)) + field_type  # FIELD (0x06), no HASTHIS


def type_ref_blob(table_tag: int, row: int, valuetype: bool = False) -> bytes:
    """TypeDefOrRef-coded type in a signature (CLASS/VALUETYPE + coded token)."""
    lead = ELEMENT_TYPE_VALUETYPE if valuetype else ELEMENT_TYPE_CLASS
    coded = (row << 2) | table_tag
    return bytes((lead,)) + compress_uint(coded)


def szarray(element: bytes) -> bytes:
    return bytes((ELEMENT_TYPE_SZARRAY,)) + element


def generic_instantiation(generic_type: bytes, args: Sequence[bytes]) -> bytes:
    out = bytes((ELEMENT_TYPE_GENERICINST, ELEMENT_TYPE_CLASS)) + generic_type[1:]
    out += compress_uint(len(args))
    for arg in args:
        out += arg
    return out


@dataclass
class AssemblyModel:
    name: str
    types: List[TypeSpecModel] = field(default_factory=list)
    type_refs: List[TypeRefModel] = field(default_factory=list)
    assembly_refs: List[AssemblyRefModel] = field(default_factory=list)
    mvid: bytes = b"\x01" * 16
    version: Tuple[int, int, int, int] = (1, 0, 0, 0)


class _TableBuilder:
    """Collects rows and serializes the #~ stream per ECMA-335 II.24.2.6."""

    def __init__(self):
        self.rows: Dict[int, List[bytes]] = {}
        self.row_counts: Dict[int, int] = {}

    def add(self, table_id: int, row: bytes) -> int:
        self.rows.setdefault(table_id, []).append(row)
        self.row_counts[table_id] = len(self.rows[table_id])
        return self.row_counts[table_id]

    def count(self, table_id: int) -> int:
        return self.row_counts.get(table_id, 0)

    def index_size(self, table_id: int) -> int:
        return 4 if self.count(table_id) >= (1 << 16) else 2

    def coded_size(self, tag_bits: int, table_ids: Sequence[int]) -> int:
        max_rows = max((self.count(t) for t in table_ids), default=0)
        return 4 if max_rows >= (1 << (16 - tag_bits)) else 2

    def simple_index(self, table_id: int, row: int) -> bytes:
        return self._pack(self.index_size(table_id), row)

    @staticmethod
    def _pack(size: int, value: int) -> bytes:
        return struct.pack("<H" if size == 2 else "<I", value)

    def build(self, str_off_size: int, blob_off_size: int, guid_off_size: int) -> bytes:
        present = sorted(self.rows)
        mask_valid = 0
        for table_id in present:
            mask_valid |= 1 << table_id
        head = struct.pack(
            "<IBBBBQQ",
            0,          # Reserved
            2,          # MajorVersion
            0,          # MinorVersion
            (1 if str_off_size == 4 else 0)
            | (2 if guid_off_size == 4 else 0)
            | (4 if blob_off_size == 4 else 0),
            1,          # Reserved (always 1 per ECMA)
            mask_valid,
            0,          # MaskSorted
        )
        counts = b"".join(struct.pack("<I", self.row_counts[t]) for t in present)
        body = b"".join(b"".join(self.rows[t]) for t in present)
        return head + counts + body


def _str_index(size: int, value: int) -> bytes:
    return struct.pack("<H" if size == 2 else "<I", value)


def build_assembly_bytes(model: AssemblyModel) -> bytes:
    strings = Heap("strings")
    blobs = Heap("blob")
    guids = Heap("guid")

    mvid_idx = guids.add(model.mvid)
    enc_name_idx = strings.add(model.name.encode("utf-8"))

    tables = _TableBuilder()

    # Table 0x00 Module (single row, references are patched once known).
    module_row_placeholder = bytearray(10)
    module_row = tables.add(TABLE_MODULE, bytes(module_row_placeholder))

    # Table 0x23 AssemblyRef (must exist before TypeRef resolution scopes).
    for ref in model.assembly_refs:
        row = struct.pack(
            "<HHHHI",
            ref.version[0],
            ref.version[1],
            ref.version[2],
            ref.version[3],
            0,  # Flags
        )
        row += _str_index(2, blobs.add(b""))          # PublicKey
        row += _str_index(2, strings.add(ref.name.encode("utf-8")))
        row += _str_index(2, strings.add(ref.culture.encode("utf-8")))
        row += _str_index(2, blobs.add(b""))          # HashValue
        tables.add(TABLE_ASSEMBLYREF, row)

    # Table 0x01 TypeRef
    for tr in model.type_refs:
        if tr.resolution_scope is None:
            scope_value = 0
        else:
            scope_table, scope_row = tr.resolution_scope
            size = tables.coded_size(2, (TABLE_MODULE, 0x1A, TABLE_ASSEMBLYREF, TABLE_TYPEREF))
            scope_value = (scope_row << 2) | scope_table
        row = _pack_coded(size, scope_value)
        row += _str_index(2, strings.add(tr.name.encode("utf-8")))
        row += _str_index(2, strings.add(tr.namespace.encode("utf-8")))
        tables.add(TABLE_TYPEREF, row)

    # Tables 0x04 Field, 0x06 MethodDef, 0x08 Param, 0x02 TypeDef
    field_ranges: List[Tuple[int, int]] = []
    method_ranges: List[Tuple[int, int]] = []
    for type_model in model.types:
        first_field = tables.count(TABLE_FIELD) + 1
        for fspec in type_model.fields:
            row = struct.pack("<H", fspec.flags)
            row += _str_index(2, strings.add(fspec.name.encode("utf-8")))
            row += _str_index(2, blobs.add(fspec.signature))
            tables.add(TABLE_FIELD, row)
        field_end = tables.count(TABLE_FIELD) + 1
        field_ranges.append((first_field, field_end))

        first_method = tables.count(TABLE_METHODDEF) + 1
        for mspec in type_model.methods:
            param_rows: List[bytes] = []
            for index, pspec in enumerate(mspec.params, start=1):
                prow = struct.pack("<HH", pspec.flags, index)
                prow += _str_index(2, strings.add(pspec.name.encode("utf-8")))
                param_rows.append(prow)
            first_param = tables.count(TABLE_PARAM) + 1
            for prow in param_rows:
                tables.add(TABLE_PARAM, prow)

            row = struct.pack("<IHH", 0, 0, mspec.flags)  # RVA, ImplFlags, Flags
            row += _str_index(2, strings.add(mspec.name.encode("utf-8")))
            row += _str_index(2, blobs.add(
                method_signature(
                    [p.type_blob for p in mspec.params],
                    return_type=mspec.return_blob,
                    instance=not bool(mspec.flags & mdStatic),
                    generic_param_count=mspec.generic_param_count or None,
                )
            ))
            row += tables.simple_index(TABLE_PARAM, first_param)
            tables.add(TABLE_METHODDEF, row)
        method_end = tables.count(TABLE_METHODDEF) + 1
        method_ranges.append((first_method, method_end))

    for type_model, (f_start, f_end), (m_start, m_end) in zip(
        model.types, field_ranges, method_ranges
    ):
        row = struct.pack("<I", type_model.flags)
        row += _str_index(2, strings.add(type_model.name.encode("utf-8")))
        row += _str_index(2, strings.add(type_model.namespace.encode("utf-8")))
        if type_model.extends is None:
            ext_table, ext_row = TABLE_TYPEREF, 0
        else:
            ext_table, ext_row = type_model.extends
        tdr_size = tables.coded_size(2, (TABLE_TYPEDEF, TABLE_TYPEREF, TABLE_TYPESPEC))
        row += _pack_coded(tdr_size, (ext_row << 2) | ext_table)
        row += tables.simple_index(TABLE_FIELD, f_start)
        row += tables.simple_index(TABLE_METHODDEF, m_start)
        tables.add(TABLE_TYPEDEF, row)

    # Patch Module row: Generation(2) + Name + Mvid(Guid) + EncId + EncBaseId
    module_raw = (
        struct.pack("<H", 0)
        + _str_index(2, enc_name_idx)
        + _pack_guid_index(2, mvid_idx)
        + _pack_guid_index(2, 0)
        + _pack_guid_index(2, 0)
    )
    tables.rows[TABLE_MODULE][0] = module_raw

    # Table 0x20 Assembly (single row)
    assembly_row = struct.pack(
        "<IHHHHI",
        0x00008004,                 # HashAlgId (SHA1)
        model.version[0],
        model.version[1],
        model.version[2],
        model.version[3],
        0,                          # Flags
    )
    assembly_row += _str_index(2, blobs.add(b""))
    assembly_row += _str_index(2, enc_name_idx)
    assembly_row += _str_index(2, strings.add(b""))
    tables.add(TABLE_ASSEMBLY, assembly_row)

    strings_blob = strings.build()
    blob_blob = blobs.build()
    guid_blob = guids.build()
    # Heap sizes stay small; 2-byte indices suffice.
    tables_blob = tables.build(2, 2, 2)
    return _emit_pe(tables_blob, strings_blob, blob_blob, guid_blob)


def _pack_coded(size: int, value: int) -> bytes:
    return struct.pack("<H" if size == 2 else "<I", value)


def _pack_guid_index(size: int, value: int) -> bytes:
    return struct.pack("<H" if size == 2 else "<I", value)


SECTION_ALIGN = 0x2000
FILE_ALIGN = 0x200


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _emit_pe(tables_blob: bytes, strings_blob: bytes, blob_heap: bytes, guid_blob: bytes) -> bytes:
    # ---- CLI metadata root + streams ---------------------------------------
    version = b"v4.0.30319"
    version_padded = version + b"\x00" * (_align(len(version), 4) - len(version))
    # Stream header entries are packed consecutively; each name field is
    # padded to a 4-byte boundary.
    packed_headers = []
    for nm in (b"#~", b"#Strings", b"#Blob", b"#GUID"):
        name_field = nm + b"\x00" * (_align(len(nm) + 1, 4) - len(nm))
        packed_headers.append((nm, name_field))

    root_fixed = 16 + len(version_padded) + 4  # fixed fields + version + flags/streams count
    header_total = sum(8 + len(nf) for _, nf in packed_headers)
    data_start = root_fixed + header_total

    offset_tables = _align(data_start, 4)
    offset_strings = _align(offset_tables + len(tables_blob), 4)
    offset_blob = _align(offset_strings + len(strings_blob), 4)
    offset_guid = _align(offset_blob + len(blob_heap), 4)
    metadata_size = _align(offset_guid + len(guid_blob), 4)

    stream_headers = b""
    for (nm, name_field), off in zip(
        packed_headers, (offset_tables, offset_strings, offset_blob, offset_guid)
    ):
        stream_headers += struct.pack("<II", off, {
            b"#~": len(tables_blob),
            b"#Strings": len(strings_blob),
            b"#Blob": len(blob_heap),
            b"#GUID": len(guid_blob),
        }[nm]) + name_field

    root = (
        struct.pack("<IHHI", 0x424A5342, 1, 1, 0)
        + struct.pack("<I", len(version_padded))
        + version_padded
        + struct.pack("<HH", 0, 4)
        + stream_headers
    )
    metadata = bytearray(metadata_size)
    metadata[0:len(root)] = root
    metadata[offset_tables:offset_tables + len(tables_blob)] = tables_blob
    metadata[offset_strings:offset_strings + len(strings_blob)] = strings_blob
    metadata[offset_blob:offset_blob + len(blob_heap)] = blob_heap
    metadata[offset_guid:offset_guid + len(guid_blob)] = guid_blob

    # ---- CLR header (72 bytes) ---------------------------------------------
    clr_header = bytearray(72)
    struct.pack_into(
        "<IHHII",
        clr_header,
        0,
        72,          # cb
        2, 5,        # runtime version
        0x2000,      # MetaDataRVA (patched with real RVA below)
        len(metadata),
    )

    # ---- PE32 shell ---------------------------------------------------------
    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 40
    dos_header = bytearray(0x40)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)  # e_lfanew
    dos_header += dos_stub
    dos_header = dos_header[:0x80]

    # COFF header (20 bytes) + optional header PE32 (96 bytes data dirs base
    # without directories; 16 data directories add 128 bytes -> 224 total).
    size_of_headers = 0x200
    headers_rva_end = size_of_headers
    section_raw_size = _align(len(clr_header) + len(metadata), FILE_ALIGN)
    size_of_image = SECTION_ALIGN + _align(
        headers_rva_end - SECTION_ALIGN + section_raw_size, SECTION_ALIGN
    )

    opt_size = 96 + 128  # PE32 optional header (224)
    coff = struct.pack(
        "<HHIIIHH",
        0x14C, 1, 0, 0, 0, opt_size, 0x0102,
    )
    optional = bytearray()
    # Standard fields (28 bytes for PE32).
    optional += struct.pack("<HBB", 0x10B, 14, 0)          # Magic, linker versions
    optional += struct.pack("<IIIII", 0, 0, 0, 0, 0)       # code/data sizes, entry, BaseOfCode
    optional += struct.pack("<I", 0)                       # BaseOfData
    # Windows-specific fields (68 bytes).
    optional += struct.pack("<I", 0x400000)                # ImageBase
    optional += struct.pack("<II", SECTION_ALIGN, FILE_ALIGN)
    optional += struct.pack("<HHHHHH", 4, 0, 0, 0, 0, 0)   # OS/image/subsystem versions
    optional += struct.pack("<I", 0)                       # Win32VersionValue
    optional += struct.pack("<II", size_of_image, size_of_headers)
    optional += struct.pack("<I", 0)                       # CheckSum
    optional += struct.pack("<HH", 3, 0x8100)              # Subsystem (console), DllCharacteristics
    optional += struct.pack("<II", 0x100000, 0x1000)       # stack reserve/commit
    optional += struct.pack("<II", 0x100000, 0x1000)       # heap reserve/commit
    optional += struct.pack("<I", 0)                       # loader flags
    optional += struct.pack("<I", 16)                      # NumberOfRvaAndSizes
    data_dirs = bytearray(16 * 8)
    clr_rva = SECTION_ALIGN
    metadata_rva = clr_rva + len(clr_header)
    struct.pack_into("<II", data_dirs, 14 * 8, clr_rva, len(clr_header) + len(metadata))
    optional += bytes(data_dirs)
    assert len(optional) == opt_size, len(optional)

    struct.pack_into("<I", clr_header, 8, metadata_rva)

    section_name = b".text" + b"\x00" * 3
    section_raw_data = bytes(clr_header) + bytes(metadata)
    section_raw_data = section_raw_data + b"\x00" * (section_raw_size - len(section_raw_data))
    section_header = section_name + struct.pack(
        "<IIIIIIHHI",
        len(clr_header) + len(metadata),  # VirtualSize
        SECTION_ALIGN,                    # VirtualAddress
        section_raw_size,                 # SizeOfRawData
        size_of_headers,                  # PointerToRawData
        0, 0,                             # PointerToRelocations / PointerToLinenumbers
        0, 0,                             # NumberOfRelocations / NumberOfLinenumbers
        0x60000020,                       # CNT_CODE | MEM_EXECUTE | MEM_READ
    )

    headers = (
        dos_header
        + b"PE\x00\x00"
        + coff
        + bytes(optional)
        + section_header
    )
    headers = headers + b"\x00" * (size_of_headers - len(headers))
    return headers + section_raw_data
