# -*- coding: utf-8 -*-
"""Build minimal, self-contained managed PE32 images for dnfile tests.

No .NET toolchain is available in this environment, so this module emits just
enough of the PE/CLI container for dnfile (and pefile) to parse the metadata
streams and tables.  Two layout strategies are supported:

* canonical keeps the heap insertion order;
* shuffled re-orders #Strings/#Blob entries and changes their indices while
  leaving the table rows and signatures untouched.

Only the metadata used by the signature-view tests is modelled.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from dnfile.utils import compress_int


def _compressed(value: int) -> bytes:
    encoded = compress_int(value)
    if encoded is None:
        raise ValueError(f"cannot compress {value}")
    return encoded


class StringsHeap:
    """#Strings heap with controllable entry order (index 0 is always empty)."""

    def __init__(self) -> None:
        self._entries: Dict[str, int] = {}
        self._pending: List[str] = []

    def add(self, value: str) -> None:
        if value and value not in self._entries and value not in self._pending:
            self._pending.append(value)

    def index_of(self, value: str) -> int:
        if value == "":
            return 0
        return self._entries[value]

    def build(self, shuffled: bool) -> bytes:
        ordered = list(dict.fromkeys(self._pending))
        if shuffled:
            ordered = list(reversed(ordered))
        data = bytearray(b"\x00")
        self._entries = {}
        for value in ordered:
            self._entries[value] = len(data)
            data += value.encode("utf-8") + b"\x00"
        return bytes(data)


class BlobHeap:
    """#Blob heap; identical blobs are de-duplicated, order is controllable."""

    def __init__(self) -> None:
        self._entries: Dict[bytes, int] = {b"": 0}
        self._pending: List[bytes] = []

    def add(self, value: bytes) -> None:
        if value and value not in self._entries and value not in self._pending:
            self._pending.append(value)

    def index_of(self, value: bytes) -> int:
        return self._entries[value]

    def build(self, shuffled: bool) -> bytes:
        ordered = list(dict.fromkeys(self._pending))
        if shuffled:
            ordered = list(reversed(ordered))
        data = bytearray(b"\x00")
        self._entries = {b"": 0}
        for value in ordered:
            self._entries[value] = len(data)
            data += _compressed(len(value)) + value
        return bytes(data)

# ---------------------------------------------------------------------------
# Metadata model
# ---------------------------------------------------------------------------


@dataclass
class TypeRefSpec:
    name: str
    namespace: str
    assembly: str  # AssemblyRef name; "" means current module scope


@dataclass
class FieldSpec:
    name: str
    signature: bytes


@dataclass
class ParamSpec:
    name: str
    flags: int = 0


@dataclass
class MethodSpec:
    name: str
    signature: bytes
    params: List[ParamSpec] = field(default_factory=list)
    rva: int = 0


@dataclass
class GenericParamSpec:
    number: int
    name: str
    flags: int
    owner: Tuple[str, int]  # ("TypeDef", rid) or ("MethodDef", rid)
    constraints: List[Tuple[str, int]] = field(default_factory=list)


@dataclass
class TypeDefSpec:
    name: str
    namespace: str
    flags: int
    extends: Optional[Tuple[str, int]]  # coded TypeDefOrRef (table, rid)
    fields: List[FieldSpec] = field(default_factory=list)
    methods: List[MethodSpec] = field(default_factory=list)


@dataclass
class AssemblyRefSpec:
    name: str
    version: Tuple[int, int, int, int] = (0, 0, 0, 0)


@dataclass
class AssemblySpec:
    name: str
    version: Tuple[int, int, int, int] = (1, 0, 0, 0)


@dataclass
class MetadataModel:
    assembly: AssemblySpec
    assembly_refs: List[AssemblyRefSpec]
    type_refs: List[TypeRefSpec]
    type_defs: List[TypeDefSpec]
    generic_params: List[GenericParamSpec] = field(default_factory=list)
    type_specs: List[bytes] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Signature blob construction (ECMA-335 II.23.2)
# ---------------------------------------------------------------------------

ELEMENT_VOID = 0x01
ELEMENT_BOOLEAN = 0x02
ELEMENT_I4 = 0x08
ELEMENT_STRING = 0x0E
ELEMENT_OBJECT = 0x1C
ELEMENT_VALUETYPE = 0x11
ELEMENT_CLASS = 0x12
ELEMENT_VAR = 0x13
ELEMENT_SZARRAY = 0x1D
ELEMENT_MVAR = 0x1E
ELEMENT_GENERICINST = 0x15
ELEMENT_ARRAY = 0x14


def coded_typedef_or_ref(table: str, rid: int) -> bytes:
    tag = {"TypeDef": 0, "TypeRef": 1, "TypeSpec": 2}[table]
    return _compressed((rid << 2) | tag)


def class_ref(table: str, rid: int, value_type: bool = False) -> bytes:
    marker = ELEMENT_VALUETYPE if value_type else ELEMENT_CLASS
    return bytes([marker]) + coded_typedef_or_ref(table, rid)


def szarray(element: bytes) -> bytes:
    return bytes([ELEMENT_SZARRAY]) + element


def array_shape(element: bytes, rank: int, sizes: Sequence[int], lo_bounds: Sequence[int]) -> bytes:
    blob = bytes([ELEMENT_ARRAY]) + element + _compressed(rank) + _compressed(len(sizes))
    blob += b"".join(_compressed(size) for size in sizes)
    blob += _compressed(len(lo_bounds))
    blob += b"".join(_compressed(bound) for bound in lo_bounds)
    return blob


def generic_inst(table: str, rid: int, args: Sequence[bytes], value_type: bool = False) -> bytes:
    blob = bytes([ELEMENT_GENERICINST, ELEMENT_VALUETYPE if value_type else ELEMENT_CLASS])
    blob += coded_typedef_or_ref(table, rid)
    blob += _compressed(len(args))
    blob += b"".join(args)
    return blob


def var(index: int) -> bytes:
    return bytes([ELEMENT_VAR]) + _compressed(index)


def mvar(index: int) -> bytes:
    return bytes([ELEMENT_MVAR]) + _compressed(index)

# ---------------------------------------------------------------------------
# #~ tables stream construction
# ---------------------------------------------------------------------------

TABLE_MODULE = 0
TYPE_REF = 1
TYPE_DEF = 2
FIELD = 4
METHOD_DEF = 6
PARAM = 8
ASSEMBLY = 32
ASSEMBLY_REF = 35
GENERIC_PARAM = 42
GENERIC_PARAM_CONSTRAINT = 44
TYPE_SPEC = 27


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _coded_resolution_scope(kind: str, rid: int) -> bytes:
    tag = {"Module": 0, "ModuleRef": 1, "AssemblyRef": 2, "TypeRef": 3}[kind]
    return _u16((rid << 2) | tag)


def _coded_typedef_or_ref(table: str, rid: int) -> bytes:
    tag = {"TypeDef": 0, "TypeRef": 1, "TypeSpec": 2}[table]
    return _u16((rid << 2) | tag)


def _coded_type_or_method_def(table: str, rid: int) -> bytes:
    tag = {"TypeDef": 0, "MethodDef": 1}[table]
    return _u16((rid << 1) | tag)


class MetadataBuilder:
    def __init__(self, model: MetadataModel, shuffled_heaps: bool):
        self.model = model
        self.shuffled = shuffled_heaps
        self.strings = StringsHeap()
        self.blobs = BlobHeap()
        self.table_rows: Dict[int, List[bytes]] = {}

    def build_streams(self) -> Dict[bytes, bytes]:
        self._collect_heap_entries()
        strings_data = self.strings.build(self.shuffled)
        blob_data = self.blobs.build(self.shuffled)
        guid_data = b"\x00" * 16
        tables_data = self._build_tables_stream()
        return {
            b"#~": tables_data,
            b"#Strings": strings_data,
            b"#Blob": blob_data,
            b"#GUID": guid_data,
        }

    def _collect_heap_entries(self) -> None:
        self.strings.add(self.model.assembly.name + ".exe")
        self.strings.add("<Module>")
        for ref in self.model.assembly_refs:
            self.strings.add(ref.name)
        for ref in self.model.type_refs:
            self.strings.add(ref.name)
            self.strings.add(ref.namespace)
        self.strings.add(self.model.assembly.name)
        for type_def in self.model.type_defs:
            self.strings.add(type_def.name)
            self.strings.add(type_def.namespace)
            for field_def in type_def.fields:
                self.strings.add(field_def.name)
                self.blobs.add(field_def.signature)
            for method in type_def.methods:
                self.strings.add(method.name)
                self.blobs.add(method.signature)
                for param in method.params:
                    self.strings.add(param.name)
        for gp in self.model.generic_params:
            self.strings.add(gp.name)
        for type_spec in self.model.type_specs:
            self.blobs.add(type_spec)

    def _build_tables_stream(self) -> bytes:
        rows: Dict[int, List[bytes]] = {}
        rows[TABLE_MODULE] = [self._module_row()]
        rows[ASSEMBLY] = [self._assembly_row()]
        rows[ASSEMBLY_REF] = [self._assembly_ref_row(ref) for ref in self.model.assembly_refs]
        rows[TYPE_REF] = [self._type_ref_row(ref) for ref in self.model.type_refs]
        rows[TYPE_SPEC] = [self._type_spec_row(spec) for spec in self.model.type_specs]
        rows[TYPE_DEF] = []
        rows[FIELD] = []
        rows[METHOD_DEF] = []
        rows[PARAM] = []
        self._emit_type_defs(rows)
        rows[GENERIC_PARAM] = []
        rows[GENERIC_PARAM_CONSTRAINT] = []
        self._emit_generic_params(rows)
        return self._wrap_tables_stream(rows)

    def _module_row(self) -> bytes:
        name = self.strings.index_of(self.model.assembly.name + ".exe")
        return _u16(1) + _u16(name) + _u16(0) + _u16(0) + _u16(0)

    def _assembly_row(self) -> bytes:
        major, minor, build, revision = self.model.assembly.version
        name = self.strings.index_of(self.model.assembly.name)
        return (
            _u32(0)  # HashAlgId
            + struct.pack("<HHHH", major, minor, build, revision)
            + _u32(0) + _u16(0) + _u16(name) + _u16(0)
        )

    def _assembly_ref_row(self, ref: AssemblyRefSpec) -> bytes:
        major, minor, build, revision = ref.version
        name = self.strings.index_of(ref.name)
        return (
            struct.pack("<HHHH", major, minor, build, revision)
            + _u32(0) + _u16(0) + _u16(name) + _u16(0) + _u16(0)
        )

    def _type_ref_row(self, ref: TypeRefSpec) -> bytes:
        name = self.strings.index_of(ref.name)
        namespace = self.strings.index_of(ref.namespace)
        if ref.assembly:
            asm_rid = 1 + next(
                index for index, item in enumerate(self.model.assembly_refs) if item.name == ref.assembly
            )
            scope = _coded_resolution_scope("AssemblyRef", asm_rid)
        else:
            scope = _coded_resolution_scope("Module", 1)
        return scope + _u16(name) + _u16(namespace)

    def _type_spec_row(self, signature: bytes) -> bytes:
        return _u16(self.blobs.index_of(signature))

    def _emit_type_defs(self, rows: Dict[int, List[bytes]]) -> None:
        # <Module> pseudo type is always TypeDef rid 1
        module_name = self.strings.index_of("<Module>")
        rows[TYPE_DEF].append(
            _u32(0) + _u16(module_name) + _u16(0) + _u16(0)
            + _u16(1) + _u16(1)
        )
        field_cursor = 1
        method_cursor = 1
        param_cursor = 1
        for type_def in self.model.type_defs:
            field_start = field_cursor
            for field_def in type_def.fields:
                rows[FIELD].append(self._field_row(field_def))
                field_cursor += 1
            method_start = method_cursor
            for method in type_def.methods:
                param_start = param_cursor
                rows[METHOD_DEF].append(self._method_row(method, param_start))
                method_cursor += 1
                for param in method.params:
                    rows[PARAM].append(self._param_row(param))
                    param_cursor += 1
            extends = (
                _coded_typedef_or_ref(*type_def.extends) if type_def.extends else _u16(0)
            )
            name = self.strings.index_of(type_def.name)
            namespace = self.strings.index_of(type_def.namespace)
            rows[TYPE_DEF].append(
                _u32(type_def.flags) + _u16(name) + _u16(namespace) + extends
                + _u16(field_start) + _u16(method_start)
            )

    def _field_row(self, field_def: FieldSpec) -> bytes:
        name = self.strings.index_of(field_def.name)
        signature = self.blobs.index_of(field_def.signature)
        return _u16(0x0010) + _u16(name) + _u16(signature)

    def _method_row(self, method: MethodSpec, param_start: int) -> bytes:
        name = self.strings.index_of(method.name)
        signature = self.blobs.index_of(method.signature)
        return (
            _u32(method.rva) + _u16(0) + _u16(0x0016)
            + _u16(name) + _u16(signature) + _u16(param_start)
        )

    def _param_row(self, param: ParamSpec) -> bytes:
        name = self.strings.index_of(param.name)
        return _u16(param.flags) + _u16(0) + _u16(name)

    def _emit_generic_params(self, rows: Dict[int, List[bytes]]) -> None:
        for gp_index, gp in enumerate(self.model.generic_params, start=1):
            owner_table, owner_rid = gp.owner
            name = self.strings.index_of(gp.name)
            rows[GENERIC_PARAM].append(
                _u16(gp.number) + _u16(gp.flags)
                + _coded_type_or_method_def(owner_table, owner_rid) + _u16(name)
            )
            for table, rid in gp.constraints:
                rows[GENERIC_PARAM_CONSTRAINT].append(
                    _u16(gp_index) + _coded_typedef_or_ref(table, rid)
                )

    def _wrap_tables_stream(self, rows: Dict[int, List[bytes]]) -> bytes:
        present = sorted(number for number, payload in rows.items() if payload)
        mask_valid = 0
        for number in present:
            mask_valid |= 1 << number
        header = struct.pack("<IBBBB", 0, 1, 0, 0, 1)  # Reserved(4), Major, Minor, HeapSizes, Reserved
        header += struct.pack("<Q", mask_valid)
        header += struct.pack("<Q", 0)  # MaskSorted
        for number in present:
            header += _u32(len(rows[number]))
        body = b"".join(b"".join(rows[number]) for number in present)
        return header + body

# ---------------------------------------------------------------------------
# Minimal PE32 container
# ---------------------------------------------------------------------------

DOS_STUB = (
    b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    + b"\x00" * 64
)

SECTION_NAME = b".text"
IMAGE_BASE = 0x00400000
SECTION_RVA = 0x2000
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x2000


def _metadata_root(streams: Dict[bytes, bytes]) -> bytes:
    version = b"v4.0.30319" + b"\x00"
    version += b"\x00" * ((-len(version)) % 4)
    header = struct.pack("<IHH", 0x424A5342, 1, 1) + struct.pack("<I", 0)
    header += struct.pack("<I", len(version)) + version
    header += struct.pack("<HH", 0, len(streams))  # Flags, NumberOfStreams
    aligned_names = []
    for name in streams:
        name_bytes = name + b"\x00"
        name_bytes += b"\x00" * ((-len(name_bytes)) % 4)
        aligned_names.append(name_bytes)
    entries_size = 8 * len(streams) + sum(len(item) for item in aligned_names)
    offset = len(header) + entries_size
    entries = bytearray()
    payload = bytearray()
    for (name, data), name_bytes in zip(streams.items(), aligned_names):
        entries += struct.pack("<II", offset, len(data)) + name_bytes
        padded_size = (len(data) + 3) // 4 * 4
        payload += data + b"\x00" * (padded_size - len(data))
        offset += padded_size
    return header + bytes(entries) + bytes(payload)

def build_pe(model: MetadataModel, layout: str = "canonical") -> bytes:
    """Emit a managed PE32 image from a metadata model."

    ``layout`` is ``canonical`` or ``shuffled``; the latter only changes
    heap entry order/indices, never the table rows or signature content.
    """
    if layout not in ("canonical", "shuffled"):
        raise ValueError(layout)
    streams = MetadataBuilder(model, layout == "shuffled").build_streams()
    metadata = _metadata_root(streams)
    cli_header = struct.pack("<IHH", 72, 2, 5)
    cli_header += struct.pack("<II", 0, len(metadata))  # MetaData rva/size (rva patched later)
    cli_header += struct.pack("<II", 0, 0)  # Resources
    cli_header += struct.pack("<II", 0, 0)  # StrongNameSignature
    cli_header += struct.pack("<II", 0, 0)  # CodeManagerTable
    cli_header += struct.pack("<II", 0, 0)  # EntryPointToken
    cli_header += struct.pack("<II", 0, 0)  # VTableFixups
    cli_header += struct.pack("<II", 0, 0)  # ExportAddressTableJumps
    cli_header += struct.pack("<II", 0, 0)  # ManagedNativeHeader
    assert len(cli_header) == 72
    section_body = cli_header + metadata
    raw_size = (len(section_body) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN
    virtual_size = (len(section_body) + SECTION_ALIGN - 1) // SECTION_ALIGN * SECTION_ALIGN
    metadata_rva = SECTION_RVA + len(cli_header)
    section_body = bytearray(section_body)
    section_body[8:12] = struct.pack("<I", metadata_rva)
    section_body += b"\x00" * (raw_size - len(section_body))
    return _assemble_pe(bytes(section_body), raw_size, virtual_size, metadata_rva, len(metadata))

def _assemble_pe(section_body: bytes, raw_size: int, virtual_size: int,
                 metadata_rva: int, metadata_size: int) -> bytes:
    dos = bytearray(DOS_STUB)
    if len(dos) < 0x80:
        dos += b"\x00" * (0x80 - len(dos))
    pe_offset = len(dos)
    optional_header_size = 224  # PE32: 96 fixed fields + 16 data directories
    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, optional_header_size, 1)
    # PE32 optional header
    optional = struct.pack("<H", 0x10B)  # PE32 magic
    optional += bytes([14, 0])  # linker versions
    optional += struct.pack("<I", raw_size)  # SizeOfCode
    optional += struct.pack("<II", 0, 0)  # initialized/uninitialized data
    optional += struct.pack("<I", SECTION_RVA)  # AddressOfEntryPoint
    optional += struct.pack("<II", SECTION_RVA, 0)  # BaseOfCode, BaseOfData
    optional += struct.pack("<I", IMAGE_BASE)
    optional += struct.pack("<II", SECTION_ALIGN, FILE_ALIGN)
    optional += struct.pack("<HH", 4, 0)  # OS version
    optional += struct.pack("<HH", 0, 0)  # image version
    optional += struct.pack("<HH", 4, 0)  # subsystem version
    optional += struct.pack("<I", 0)  # Win32VersionValue
    size_of_headers = 0x200
    size_of_image = IMAGE_BASE - IMAGE_BASE + SECTION_RVA + virtual_size
    optional += struct.pack("<I", size_of_image)
    optional += struct.pack("<I", size_of_headers)
    optional += struct.pack("<I", 0)  # checksum
    optional += struct.pack("<HH", 3, 0)  # Subsystem=CONSOLE, DllCharacteristics
    optional += struct.pack("<IIII", 0x100000, 0x1000, 0, 0x1000)
    optional += struct.pack("<I", 0)  # LoaderFlags
    optional += struct.pack("<I", 16)  # NumberOfRvaAndSizes
    # 16 data directories; COM descriptor is index 14
    directories = [struct.pack("<II", 0, 0)] * 16
    cli_rva = SECTION_RVA
    directories[14] = struct.pack("<II", cli_rva, 72)
    optional += b"".join(directories)
    headers_size = pe_offset + 4 + len(file_header) + len(optional)
    section_table = struct.pack(
        "<8sIIIIIIIIHH",
        SECTION_NAME,
        virtual_size, SECTION_RVA,
        raw_size, FILE_ALIGN,
        0, 0, 0,
        0x60000020, 0, 0,
    )
    headers = bytes(dos) + b"PE\x00\x00" + file_header + optional + section_table
    headers += b"\x00" * (size_of_headers - len(headers))
    return headers + section_body
