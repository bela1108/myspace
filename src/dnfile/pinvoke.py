# -*- coding: utf-8 -*-
"""
Static P/Invoke inventory.

This module resolves the metadata that describes managed to native calls:

    ImplMap -> ModuleRef (the native module / DLL)
    ImplMap -> MemberForwarded -> MethodDef or Field (the managed declaration)

Nothing here loads or even looks for the referenced native module.  The
inventory is built exclusively from the .NET metadata already present in the
file, so it also works when inspecting files for a platform whose native
libraries are not installed.

References:

    ECMA-335, Partition II, sections 22.22 (ImplMap), 22.23 (ModuleRef), and
    23.2 (signatures)
"""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

__all__ = [
    "CallingConvention",
    "MetadataValue",
    "PInvokeEntry",
    "PInvokeImport",
    "PInvokeInfo",
    "PInvokeInventory",
    "PInvokeDeclaration",
    "PInvokeList",
    "PInvokeMapping",
    "PInvokeRecord",
    "PInvokeTable",
    "build_pinvoke_inventory",
    "collect_pinvoke_entries",
    "collect_pinvoke_imports",
    "extract_pinvoke_imports",
    "get_pinvoke_entries",
    "get_pinvoke_imports",
    "get_pinvoke_inventory",
    "get_pinvoke_list",
    "iter_pinvoke_entries",
    "iter_pinvoke_imports",
    "list_pinvoke_entries",
    "list_pinvoke_imports",
    "pinvoke_entries",
    "pinvoke_imports",
    "pinvoke_list",
]


PINVOKE_CALL_CONV_MASK = 0x0700
PINVOKE_CHAR_SET_MASK = 0x0006
PINVOKE_BEST_FIT_MASK = 0x0030
PINVOKE_THROW_ON_UNMAPPABLE_CHAR_MASK = 0x3000

_CALL_CONV_NAMES = {
    0x0000: "notspecified",
    0x0100: "winapi",
    0x0200: "cdecl",
    0x0300: "stdcall",
    0x0400: "thiscall",
    0x0500: "fastcall",
    0x0600: "unknown1",
    0x0700: "unknown2",
}

_CHAR_SET_NAMES = {
    0x0000: "notspecified",
    0x0002: "ansi",
    0x0004: "unicode",
    0x0006: "auto",
}

_BEST_FIT_NAMES = {
    0x0000: "useassembly",
    0x0010: "enabled",
    0x0020: "disabled",
}

_THROW_ON_UNMAPPABLE_CHAR_NAMES = {
    0x0000: "useassembly",
    0x1000: "enabled",
    0x2000: "disabled",
}

_SIGNATURE_CALL_CONV_NAMES = {
    0x0: "default",
    0x1: "c",
    0x2: "stdcall",
    0x3: "thiscall",
    0x4: "fastcall",
    0x5: "vararg",
    0x6: "field",
    0x7: "localsig",
    0x8: "propertysig",
    0x9: "unmanaged",
}

_ELEMENT_TYPE_NAMES = {
    0x01: "void",
    0x02: "bool",
    0x03: "char",
    0x04: "int8",
    0x05: "uint8",
    0x06: "int16",
    0x07: "uint16",
    0x08: "int32",
    0x09: "uint32",
    0x0A: "int64",
    0x0B: "uint64",
    0x0C: "float32",
    0x0D: "float64",
    0x0E: "string",
    0x16: "typedref",
    0x18: "intptr",
    0x19: "uintptr",
    0x1C: "object",
}


def _as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    candidate = getattr(value, "value", None)
    if isinstance(candidate, str):
        return candidate
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    try:
        return str(value)
    except Exception:
        return None


def _as_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    candidate = getattr(value, "value", None)
    if isinstance(candidate, bytes):
        return candidate
    value_bytes = getattr(value, "value_bytes", None)
    if callable(value_bytes):
        try:
            result = value_bytes()
        except Exception:
            result = None
        if isinstance(result, bytes):
            return result
    return None


def _table_named(mdtables: Any, name: str) -> Any:
    table = getattr(mdtables, name, None)
    if table is not None:
        return table
    for candidate in getattr(mdtables, "tables_list", ()) or ():
        if getattr(candidate, "name", None) == name:
            return candidate
    return None


def _resolve_mdtables(source: Any) -> Any:
    """Accept a dnPE, ClrData, MetaDataTables, ImplMap table, or path."""
    if source is None:
        return None

    if isinstance(source, (str, bytes, os.PathLike)):
        from . import dnPE

        pe = dnPE(source)
        return _resolve_mdtables(pe)

    mdtables = getattr(source, "mdtables", None)
    if mdtables is not None:
        return mdtables

    net = getattr(source, "net", None)
    if net is not None:
        return _resolve_mdtables(net)

    if getattr(source, "name", None) == "ImplMap":
        return getattr(source, "_mdtables", None) or getattr(source, "mdtables", None)

    if hasattr(source, "tables_list") or hasattr(source, "ImplMap"):
        return source

    return None


def _iter_table_rows(table: Any) -> Iterator[Tuple[int, Any]]:
    """Yield (1-based row number, row or None) for every declared table row."""
    if table is None:
        return

    rows = getattr(table, "rows", None)
    if rows is None:
        try:
            rows = list(table)
        except TypeError:
            rows = []

    declared = getattr(table, "num_rows", None)
    try:
        declared = int(declared)
    except (TypeError, ValueError):
        declared = len(rows)

    if declared < len(rows):
        declared = len(rows)

    for zero_index in range(declared):
        try:
            row = table[zero_index]
        except (IndexError, KeyError, TypeError, AttributeError):
            row = None
        except Exception:
            row = None
        yield zero_index + 1, row


def _safe_row(index: Any) -> Any:
    table = getattr(index, "table", None)
    row_number = _as_int(getattr(index, "row_index", None))
    if table is None or not row_number or row_number < 1:
        return None
    try:
        return table[row_number - 1]
    except (IndexError, KeyError, TypeError, AttributeError):
        return None
    except Exception:
        return None


def _row_offset(row: Any) -> Optional[int]:
    if row is None:
        return None
    struct = getattr(row, "struct", None)
    if struct is not None:
        getter = getattr(struct, "get_file_offset", None)
        if callable(getter):
            try:
                return int(getter())
            except (TypeError, ValueError):
                pass
    return None


def _row_rva(row: Any) -> Optional[int]:
    if row is None:
        return None
    value = getattr(row, "rva", None)
    if isinstance(value, int):
        return value
    return None


def _table_row_rva(table: Any, row_number: int) -> Optional[int]:
    table_rva = getattr(table, "rva", None)
    row_size = getattr(table, "row_size", None)
    if isinstance(table_rva, int) and isinstance(row_size, int) and row_number > 0:
        return table_rva + row_size * (row_number - 1)
    return None


def _table_row_offset(table: Any, row_number: int) -> Optional[int]:
    table_offset = getattr(table, "file_offset", None)
    row_size = getattr(table, "row_size", None)
    if isinstance(table_offset, int) and isinstance(row_size, int) and row_number > 0:
        return table_offset + row_size * (row_number - 1)
    return None


def _make_token(table_number: int, row_number: int) -> int:
    return (int(table_number) << 24) | int(row_number)


def _decode_coded_index(
    coded_index: Any,
    raw_value: Optional[int],
    table_numbers: Dict[str, int],
) -> Tuple[Optional[str], int]:
    table = getattr(coded_index, "table", None)
    table_name = getattr(table, "name", None)
    row_number = _as_int(getattr(coded_index, "row_index", None), 0) or 0
    if table_name is not None:
        return table_name, row_number

    if raw_value is None:
        return None, row_number

    tags = getattr(coded_index, "__class__", None)
    names = getattr(tags, "table_names", None)
    tag_bits = _as_int(getattr(tags, "tag_bits", None), 0) or 0
    if not names:
        return None, row_number
    tag = int(raw_value) & ((1 << tag_bits) - 1)
    if tag >= len(names):
        return None, row_number
    table_name = names[tag]
    if table_name not in table_numbers:
        return None, row_number
    return table_name, int(raw_value) >> tag_bits


class MetadataValue(str):
    """A readable metadata value that also compares with its raw value."""

    def __new__(cls, name: str, value: int):
        obj = str.__new__(cls, name)
        obj.value = value
        return obj

    def __eq__(self, other):
        if isinstance(other, int):
            return self.value == other
        if isinstance(other, str):
            return str(self).casefold() == other.casefold()
        return NotImplemented

    def __hash__(self):
        return hash(str(self).casefold())


class CallingConvention(MetadataValue):
    pass


def _calling_convention(value: Optional[int]) -> CallingConvention:
    raw = value or 0
    return CallingConvention(_CALL_CONV_NAMES.get(raw, "unknown"), raw)


def _charset(value: Optional[int]) -> MetadataValue:
    raw = value or 0
    return MetadataValue(_CHAR_SET_NAMES.get(raw, "unknown"), raw)


def _best_fit(value: Optional[int]) -> MetadataValue:
    raw = value or 0
    return MetadataValue(_BEST_FIT_NAMES.get(raw, "unknown"), raw)


def _throw_on_unmappable_char(value: Optional[int]) -> MetadataValue:
    raw = value or 0
    return MetadataValue(_THROW_ON_UNMAPPABLE_CHAR_NAMES.get(raw, "unknown"), raw)


def _read_compressed_uint(data: bytes, offset: int) -> Optional[Tuple[int, int]]:
    if offset >= len(data):
        return None
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if offset + 1 < len(data) and first & 0x40 == 0:
        return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
    if offset + 3 < len(data) and first & 0x20 == 0:
        return (
            ((first & 0x1F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3],
            offset + 4,
        )
    return None


def _decode_type(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    if depth > 16 or offset >= len(data):
        return "?", len(data)

    element_type = data[offset]
    offset += 1
    name = _ELEMENT_TYPE_NAMES.get(element_type)
    if name is not None:
        return name, offset

    if element_type == 0x0F:  # PTR
        inner, offset = _decode_type(data, offset, depth + 1)
        return inner + "*", offset
    if element_type == 0x10:  # BYREF
        inner, offset = _decode_type(data, offset, depth + 1)
        return inner + "&", offset
    if element_type in (0x11, 0x12):  # VALUETYPE / CLASS
        coded, offset = _read_compressed_uint(data, offset) or (0, offset)
        return ("valuetype" if element_type == 0x11 else "class") + "#0x%x" % coded, offset
    if element_type in (0x13, 0x1E):  # VAR / MVAR
        index, offset = _read_compressed_uint(data, offset) or (0, offset)
        return ("!" if element_type == 0x13 else "!!") + str(index), offset
    if element_type == 0x1D:  # SZARRAY
        inner, offset = _decode_type(data, offset, depth + 1)
        return inner + "[]", offset
    if element_type == 0x14:  # ARRAY
        inner, offset = _decode_type(data, offset, depth + 1)
        rank, offset = _read_compressed_uint(data, offset) or (1, offset)
        for _ in range(rank):
            _, offset = _read_compressed_uint(data, offset) or (0, offset)
        for _ in range(rank):
            _, offset = _read_compressed_uint(data, offset) or (0, offset)
        return inner + "[" + "," * max(0, rank - 1) + "]", offset
    if element_type == 0x15:  # GENERICINST
        base, offset = _decode_type(data, offset, depth + 1)
        count, offset = _read_compressed_uint(data, offset) or (0, offset)
        args = []
        for _ in range(count):
            arg, offset = _decode_type(data, offset, depth + 1)
            args.append(arg)
        return base + "<" + ",".join(args) + ">", offset
    if element_type in (0x1F, 0x20):  # CMOD_REQD / CMOD_OPT
        _, offset = _read_compressed_uint(data, offset) or (0, offset)
        return _decode_type(data, offset, depth + 1)
    if element_type == 0x45:  # PINNED
        return _decode_type(data, offset, depth + 1)

    return "0x%02x" % element_type, offset


def _signature_info(signature: Any) -> Dict[str, Any]:
    data = _as_bytes(signature)
    if not data:
        return {
            "signature": data,
            "signature_calling_convention": None,
            "signature_has_this": False,
            "signature_explicit_this": False,
            "signature_is_generic": False,
            "parameter_count": None,
            "return_type": None,
            "parameter_types": [],
        }

    call_conv = data[0] & 0x0F
    result = {
        "signature": data,
        "signature_calling_convention": _SIGNATURE_CALL_CONV_NAMES.get(call_conv, "unknown"),
        "signature_has_this": bool(data[0] & 0x20),
        "signature_explicit_this": bool(data[0] & 0x40),
        "signature_is_generic": bool(data[0] & 0x10),
        "parameter_count": None,
        "return_type": None,
        "parameter_types": [],
    }

    if call_conv in (0x6, 0x7, 0x8):
        return result

    offset = 1
    if result["signature_is_generic"]:
        generic_count = _read_compressed_uint(data, offset)
        if generic_count is None:
            return result
        _, offset = generic_count

    parameter_count = _read_compressed_uint(data, offset)
    if parameter_count is None:
        return result
    count, offset = parameter_count
    result["parameter_count"] = count

    return_type, offset = _decode_type(data, offset)
    result["return_type"] = return_type
    parameter_types = []
    for _ in range(count):
        if offset >= len(data):
            break
        parameter_type, offset = _decode_type(data, offset)
        parameter_types.append(parameter_type)
    result["parameter_types"] = parameter_types
    return result


def _type_full_name(type_def: Any, parents: Dict[int, int], type_rows: Dict[int, Any]) -> Optional[str]:
    if type_def is None:
        return None

    namespace = _as_text(getattr(type_def, "TypeNamespace", None))
    own_name = _as_text(getattr(type_def, "TypeName", None))
    parts = [own_name] if own_name else []

    seen = set()
    row_number = getattr(type_def, "_dnfile_row_number", None)
    while row_number in parents and row_number not in seen:
        seen.add(row_number)
        row_number = parents[row_number]
        parent = type_rows.get(row_number)
        parent_name = _as_text(getattr(parent, "TypeName", None))
        if parent_name:
            parts.append(parent_name)

    if not parts:
        return None
    parts.reverse()
    nested_name = "+".join(parts)
    return "{}.{}".format(namespace, nested_name) if namespace else nested_name


def _build_member_type_map(mdtables: Any) -> Dict[Tuple[str, int], Any]:
    result: Dict[Tuple[str, int], Any] = {}
    type_defs = _table_named(mdtables, "TypeDef")
    if type_defs is None:
        return result

    nested_parents: Dict[int, int] = {}
    nested_class = _table_named(mdtables, "NestedClass")
    if nested_class is not None:
        for _, row in _iter_table_rows(nested_class):
            if row is None:
                continue
            nested = _as_int(getattr(getattr(row, "NestedClass", None), "row_index", None))
            enclosing = _as_int(getattr(getattr(row, "EnclosingClass", None), "row_index", None))
            if nested and enclosing:
                nested_parents[nested] = enclosing

    type_rows: Dict[int, Any] = {}
    for type_row_number, type_row in _iter_table_rows(type_defs):
        if type_row is not None:
            try:
                type_row._dnfile_row_number = type_row_number
            except Exception:
                pass
            type_rows[type_row_number] = type_row

    for type_row_number, type_row in type_rows.items():
        full_name = _type_full_name(type_row, nested_parents, type_rows)
        for attr, table_name in (("MethodList", "MethodDef"), ("FieldList", "Field")):
            for member_index in getattr(type_row, attr, ()) or ():
                member_row_number = _as_int(getattr(member_index, "row_index", None))
                if member_row_number:
                    result[(table_name, member_row_number)] = {
                        "type": type_row,
                        "row_number": type_row_number,
                        "full_name": full_name,
                    }
    return result


def _declares_pinvoke(member: Any, member_table: Optional[str]) -> Optional[bool]:
    flags = getattr(member, "Flags", None)
    if flags is None:
        return None
    if member_table == "MethodDef":
        return bool(getattr(flags, "mdPinvokeImpl", False))
    if member_table == "Field":
        return bool(getattr(flags, "fdPinvokeImpl", False))
    return None


@dataclass
class PInvokeEntry:
    """One ImplMap row and everything it resolves to."""

    module_name: Optional[str] = None
    import_name: Optional[str] = None

    managed_name: Optional[str] = None
    declaring_type: Optional[str] = None
    declaring_type_name: Optional[str] = None
    declaring_type_namespace: Optional[str] = None
    managed_namespace: Optional[str] = None
    managed_member: Optional[str] = None

    target_kind: Optional[str] = None
    target_table: Optional[str] = None
    target_row_number: Optional[int] = None
    target_index: Optional[int] = None
    target_token: Optional[int] = None
    target_rva: Optional[int] = None
    target_file_offset: Optional[int] = None

    calling_convention: str = "notspecified"
    calling_convention_value: int = 0
    declaration: Dict[str, Any] = field(default_factory=dict)
    charset: str = "notspecified"
    charset_value: int = 0
    best_fit: str = "useassembly"
    best_fit_value: int = 0
    throw_on_unmappable_char: str = "useassembly"
    throw_on_unmappable_char_value: int = 0
    no_mangle: bool = False
    supports_last_error: bool = False
    mapping_flags: int = 0

    signature: Optional[bytes] = None
    signature_calling_convention: Optional[str] = None
    signature_has_this: bool = False
    signature_explicit_this: bool = False
    signature_is_generic: bool = False
    parameter_count: Optional[int] = None
    return_type: Optional[str] = None
    parameter_types: List[str] = field(default_factory=list)
    declared_pinvoke: Optional[bool] = None

    impl_map_row_number: int = 0
    impl_map_index: int = 0
    impl_map_token: Optional[int] = None
    impl_map_rva: Optional[int] = None
    impl_map_file_offset: Optional[int] = None

    module_ref_row_number: Optional[int] = None
    module_ref_index: Optional[int] = None
    module_ref_token: Optional[int] = None
    module_ref_rva: Optional[int] = None
    module_ref_file_offset: Optional[int] = None

    member_forwarded_table: Optional[str] = None
    member_forwarded_row_number: Optional[int] = None
    raw_member_forwarded: Optional[int] = None
    raw_import_scope: Optional[int] = None
    member_forwarded: Any = field(default=None, repr=False, compare=False)
    import_scope: Any = field(default=None, repr=False, compare=False)

    resolved: bool = False
    missing_target: bool = True
    missing_module: bool = True

    managed_module_name: Optional[str] = None
    impl_map_row: Any = field(default=None, repr=False, compare=False)
    module_ref_row: Any = field(default=None, repr=False, compare=False)
    target_row: Any = field(default=None, repr=False, compare=False)

    @property
    def dll_name(self) -> Optional[str]:
        return self.module_name

    @property
    def dll(self) -> Optional[str]:
        return self.module_name

    @property
    def library(self) -> Optional[str]:
        return self.module_name

    @property
    def module(self) -> Optional[str]:
        return self.module_name

    @property
    def native_module(self) -> Optional[str]:
        return self.module_name

    @property
    def import_scope_name(self) -> Optional[str]:
        return self.module_name

    @property
    def name(self) -> Optional[str]:
        return self.import_name

    @property
    def target_name(self) -> Optional[str]:
        return self.managed_name

    @property
    def member_name(self) -> Optional[str]:
        return self.managed_name

    @property
    def managed_method(self) -> Optional[str]:
        return self.managed_name

    @property
    def managed_method_name(self) -> Optional[str]:
        return self.managed_name

    @property
    def method_name(self) -> Optional[str]:
        return self.managed_name

    @property
    def call_conv(self) -> str:
        return self.calling_convention

    @property
    def call_conv_value(self) -> int:
        return self.calling_convention_value

    @property
    def declaration_convention(self) -> str:
        return self.calling_convention

    @property
    def convention(self) -> str:
        return self.calling_convention

    @property
    def row_number(self) -> int:
        return self.impl_map_row_number

    @property
    def original_row_number(self) -> int:
        return self.impl_map_row_number

    @property
    def row_index(self) -> int:
        return self.impl_map_index

    @property
    def index(self) -> int:
        return self.impl_map_index

    @property
    def rid(self) -> int:
        return self.impl_map_row_number

    @property
    def line_number(self) -> int:
        return self.impl_map_row_number

    @property
    def line(self) -> int:
        return self.impl_map_row_number

    @property
    def source_line(self) -> int:
        return self.impl_map_row_number

    @property
    def impl_map_row_id(self) -> int:
        return self.impl_map_row_number

    @property
    def rva(self) -> Optional[int]:
        return self.impl_map_rva

    @property
    def file_offset(self) -> Optional[int]:
        return self.impl_map_file_offset

    @property
    def full_name(self) -> Optional[str]:
        return self.managed_member

    @property
    def qualified_name(self) -> Optional[str]:
        return self.managed_member

    @property
    def is_resolved(self) -> bool:
        return self.resolved

    @property
    def fully_resolved(self) -> bool:
        return self.resolved and not self.missing_module

    @property
    def unresolved(self) -> bool:
        return self.missing_target or self.missing_module

    @property
    def missing(self) -> bool:
        return self.unresolved

    @property
    def missing_reason(self):
        if self.missing_target and self.missing_module:
            return "missing_target_and_module"
        if self.missing_target:
            return "missing_target"
        if self.missing_module:
            return "missing_module"
        return None

    @property
    def target(self):
        return self.target_row

    @property
    def module_ref(self):
        return self.module_ref_row

    @property
    def impl_map(self):
        return self.impl_map_row

    @property
    def ImportName(self):
        return self.import_name

    @property
    def ImportScope(self):
        return self.module_ref_row

    @property
    def MemberForwarded(self):
        return self.member_forwarded

    @property
    def MappingFlags(self):
        return self.mapping_flags

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module_name": self.module_name,
            "module": self.module_name,
            "native_module": self.module_name,
            "managed_module_name": self.managed_module_name,
            "dll_name": self.dll_name,
            "dll": self.dll_name,
            "library": self.library,
            "import_name": self.import_name,
            "name": self.import_name,
            "managed_name": self.managed_name,
            "managed_method": self.managed_name,
            "declaring_type": self.declaring_type,
            "declaring_type_name": self.declaring_type_name,
            "declaring_type_namespace": self.declaring_type_namespace,
            "managed_type": self.declaring_type,
            "managed_namespace": self.managed_namespace,
            "managed_member": self.managed_member,
            "target_kind": self.target_kind,
            "target_table": self.target_table,
            "target_row_number": self.target_row_number,
            "target_index": self.target_index,
            "target_token": self.target_token,
            "target_rva": self.target_rva,
            "target_file_offset": self.target_file_offset,
            "calling_convention": self.calling_convention,
            "declaration_convention": self.calling_convention,
            "call_conv": self.calling_convention,
            "calling_convention_value": self.calling_convention_value,
            "charset": self.charset,
            "charset_value": self.charset_value,
            "best_fit": self.best_fit,
            "best_fit_value": self.best_fit_value,
            "throw_on_unmappable_char": self.throw_on_unmappable_char,
            "throw_on_unmappable_char_value": self.throw_on_unmappable_char_value,
            "no_mangle": self.no_mangle,
            "supports_last_error": self.supports_last_error,
            "mapping_flags": self.mapping_flags,
            "signature": self.signature.hex() if isinstance(self.signature, bytes) else self.signature,
            "signature_calling_convention": self.signature_calling_convention,
            "signature_has_this": self.signature_has_this,
            "signature_explicit_this": self.signature_explicit_this,
            "signature_is_generic": self.signature_is_generic,
            "parameter_count": self.parameter_count,
            "return_type": self.return_type,
            "parameter_types": list(self.parameter_types),
            "impl_map_row_number": self.impl_map_row_number,
            "impl_map_index": self.impl_map_index,
            "row_number": self.impl_map_row_number,
            "row_index": self.impl_map_index,
            "rid": self.impl_map_row_number,
            "impl_map_token": self.impl_map_token,
            "impl_map_rva": self.impl_map_rva,
            "impl_map_file_offset": self.impl_map_file_offset,
            "module_ref_row_number": self.module_ref_row_number,
            "module_ref_index": self.module_ref_index,
            "module_ref_token": self.module_ref_token,
            "module_ref_rva": self.module_ref_rva,
            "module_ref_file_offset": self.module_ref_file_offset,
            "member_forwarded_table": self.member_forwarded_table,
            "member_forwarded_row_number": self.member_forwarded_row_number,
            "raw_member_forwarded": self.raw_member_forwarded,
            "raw_import_scope": self.raw_import_scope,
            "declaration": dict(self.declaration),
            "declared_pinvoke": self.declared_pinvoke,
            "resolved": self.resolved,
            "fully_resolved": self.fully_resolved,
            "missing_target": self.missing_target,
            "missing_module": self.missing_module,
            "missing": self.missing,
            "missing_reason": self.missing_reason,
        }

    as_dict = to_dict

    def __getitem__(self, key):
        if hasattr(self, key) and not key.startswith("_"):
            return getattr(self, key)
        data = self.to_dict()
        if key in data:
            return data[key]
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        return self.to_dict().keys()

    def items(self):
        return self.to_dict().items()

    def values(self):
        return self.to_dict().values()

    def __contains__(self, key):
        return key in self.to_dict() or (hasattr(self, key) and not key.startswith("_"))

    @property
    def managed_type(self):
        return self.declaring_type

    @property
    def type_name(self):
        return self.declaring_type_name


PInvokeImport = PInvokeEntry
PInvokeInfo = PInvokeEntry
PInvokeMapping = PInvokeEntry
PInvokeDeclaration = PInvokeEntry
PInvokeRecord = PInvokeEntry


class PInvokeList(List[PInvokeEntry]):
    """A list that can also be called, for compatibility with method-style use."""

    def __call__(self):
        return self

    def to_dict(self) -> List[Dict[str, Any]]:
        return [entry.to_dict() for entry in self]

    as_dict = to_dict

    def duplicates(self):
        return PInvokeInventory(self).duplicates()

    def by_module(self, module_name):
        return PInvokeInventory(self).by_module(module_name)

    def by_import_name(self, import_name):
        return PInvokeInventory(self).by_import_name(import_name)


class PInvokeInventory(Sequence[PInvokeEntry]):
    """A read-only list of P/Invoke entries with lookup helpers."""

    def __init__(self, entries: Iterable[PInvokeEntry]):
        self.entries: List[PInvokeEntry] = list(entries)

    def __iter__(self) -> Iterator[PInvokeEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def __getitem__(self, index):
        return self.entries[index]

    def __call__(self):
        return self.entries

    def by_module(self, module_name: str) -> List[PInvokeEntry]:
        needle = (module_name or "").lower()
        return [e for e in self.entries if (e.module_name or "").lower() == needle]

    def by_import_name(self, import_name: str) -> List[PInvokeEntry]:
        needle = (import_name or "").lower()
        return [e for e in self.entries if (e.import_name or "").lower() == needle]

    def by_calling_convention(self, calling_convention: str) -> List[PInvokeEntry]:
        needle = (calling_convention or "").lower()
        return [e for e in self.entries if (e.calling_convention or "").lower() == needle]

    def find(
        self,
        module_name: Optional[str] = None,
        import_name: Optional[str] = None,
        calling_convention: Optional[str] = None,
        managed_name: Optional[str] = None,
    ) -> List[PInvokeEntry]:
        result = self.entries
        if module_name is not None:
            needle = module_name.lower()
            result = [e for e in result if (e.module_name or "").lower() == needle]
        if import_name is not None:
            needle = import_name.lower()
            result = [e for e in result if (e.import_name or "").lower() == needle]
        if calling_convention is not None:
            needle = calling_convention.lower()
            result = [e for e in result if (e.calling_convention or "").lower() == needle]
        if managed_name is not None:
            needle = managed_name.lower()
            result = [e for e in result if (e.managed_name or "").lower() == needle]
        return list(result)

    def duplicates(self) -> Dict[Tuple[Optional[str], Optional[str]], List[PInvokeEntry]]:
        """Group entries that declare the same module + import name.

        Entries with the same name but different calling conventions remain in
        the same group; they are never collapsed or overwritten.
        """
        groups: Dict[Tuple[Optional[str], Optional[str]], List[PInvokeEntry]] = {}
        for entry in self.entries:
            key = (entry.module_name, entry.import_name)
            groups.setdefault(key, []).append(entry)
        return {key: value for key, value in groups.items() if len(value) > 1}

    by_dll = by_module
    by_name = by_import_name
    by_convention = by_calling_convention

    def duplicates_by_import_name(self) -> Dict[Optional[str], List[PInvokeEntry]]:
        groups: Dict[Optional[str], List[PInvokeEntry]] = {}
        for entry in self.entries:
            groups.setdefault(entry.import_name, []).append(entry)
        return {key: value for key, value in groups.items() if len(value) > 1}

    def unresolved(self) -> List[PInvokeEntry]:
        return [entry for entry in self.entries if entry.missing_target or entry.missing_module]

    find_duplicates = duplicates

    def to_dict(self) -> List[Dict[str, Any]]:
        return [entry.to_dict() for entry in self.entries]

    as_dict = to_dict


PInvokeTable = PInvokeInventory


def iter_pinvoke_entries(source: Any) -> Iterator[PInvokeEntry]:
    """Yield one entry for every row of the ImplMap table, in table order."""
    mdtables = _resolve_mdtables(source)
    if mdtables is None:
        return

    impl_map = _table_named(mdtables, "ImplMap")
    if impl_map is None:
        return

    module_ref_table = _table_named(mdtables, "ModuleRef")
    method_def_table = _table_named(mdtables, "MethodDef")
    field_table = _table_named(mdtables, "Field")
    module_table = _table_named(mdtables, "Module")

    managed_module_name = None
    for _, module_row in _iter_table_rows(module_table):
        if module_row is not None:
            managed_module_name = _as_text(getattr(module_row, "Name", None))
            break

    member_types = _build_member_type_map(mdtables)
    table_numbers = {
        "MethodDef": 6,
        "Field": 4,
        "ModuleRef": 26,
        "ImplMap": 28,
    }

    for impl_map_row_number, impl_map_row in _iter_table_rows(impl_map):
        entry = PInvokeEntry(
            managed_module_name=managed_module_name,
            impl_map_row_number=impl_map_row_number,
            impl_map_index=impl_map_row_number - 1,
            impl_map_token=_make_token(table_numbers["ImplMap"], impl_map_row_number),
            impl_map_rva=_table_row_rva(impl_map, impl_map_row_number),
            impl_map_file_offset=_table_row_offset(impl_map, impl_map_row_number),
            impl_map_row=impl_map_row,
        )

        if impl_map_row is not None:
            struct = getattr(impl_map_row, "struct", None)
            if struct is not None:
                entry.impl_map_rva = _row_rva(impl_map_row) if _row_rva(impl_map_row) is not None else entry.impl_map_rva
                entry.impl_map_file_offset = (
                    _row_offset(impl_map_row)
                    if _row_offset(impl_map_row) is not None
                    else entry.impl_map_file_offset
                )

            entry.import_name = _as_text(getattr(impl_map_row, "ImportName", None))
            raw_mapping_flags = _as_int(getattr(struct, "MappingFlags", None))
            if raw_mapping_flags is None:
                raw_mapping_flags = _as_int(getattr(impl_map_row, "MappingFlags", None), 0)
            entry.mapping_flags = raw_mapping_flags or 0
            entry.calling_convention_value = entry.mapping_flags & PINVOKE_CALL_CONV_MASK

            entry.calling_convention = _calling_convention(entry.calling_convention_value)
            entry.charset_value = entry.mapping_flags & PINVOKE_CHAR_SET_MASK
            entry.best_fit_value = entry.mapping_flags & PINVOKE_BEST_FIT_MASK
            entry.throw_on_unmappable_char_value = (
                entry.mapping_flags & PINVOKE_THROW_ON_UNMAPPABLE_CHAR_MASK
            )
            entry.charset = _charset(entry.charset_value)
            entry.best_fit = _best_fit(entry.best_fit_value)
            entry.throw_on_unmappable_char = _throw_on_unmappable_char(
                entry.throw_on_unmappable_char_value
            )
            entry.no_mangle = bool(entry.mapping_flags & 0x0001)
            entry.supports_last_error = bool(entry.mapping_flags & 0x0040)
            entry.declaration = {
                "calling_convention": entry.calling_convention,
                "charset": entry.charset,
                "charset_value": entry.charset_value,
                "best_fit": entry.best_fit,
                "best_fit_value": entry.best_fit_value,
                "throw_on_unmappable_char": entry.throw_on_unmappable_char,
                "throw_on_unmappable_char_value": entry.throw_on_unmappable_char_value,
                "no_mangle": entry.no_mangle,
                "supports_last_error": entry.supports_last_error,
                "mapping_flags": entry.mapping_flags,
            }

            raw_member_forwarded = _as_int(getattr(struct, "MemberForwarded_CodedIndex", None))
            if raw_member_forwarded is None:
                raw_member_forwarded = _as_int(getattr(impl_map_row, "MemberForwarded_CodedIndex", None))
            entry.raw_member_forwarded = raw_member_forwarded
            member_forwarded = getattr(impl_map_row, "MemberForwarded", None)
            entry.member_forwarded = member_forwarded
            target_table, target_row_number = _decode_coded_index(
                member_forwarded, raw_member_forwarded, table_numbers
            )
            entry.member_forwarded_table = target_table
            entry.member_forwarded_row_number = target_row_number
            entry.target_table = target_table
            entry.target_row_number = target_row_number
            entry.target_index = target_row_number - 1 if target_row_number else None
            entry.target_kind = target_table
            if target_table and target_row_number:
                entry.target_token = _make_token(table_numbers.get(target_table, 0), target_row_number)

            target_row = None
            if target_table == "MethodDef":
                target_row = _safe_row(member_forwarded)
                if target_row is None:
                    try:
                        target_row = method_def_table[target_row_number - 1]
                    except Exception:
                        target_row = None
            elif target_table == "Field":
                target_row = _safe_row(member_forwarded)
                if target_row is None:
                    try:
                        target_row = field_table[target_row_number - 1]
                    except Exception:
                        target_row = None

            entry.target_row = target_row
            entry.missing_target = target_row is None
            entry.resolved = target_row is not None

            if target_row is not None:
                target_struct = getattr(target_row, "struct", None)
                target_table_obj = method_def_table if target_table == "MethodDef" else field_table
                entry.target_rva = _table_row_rva(target_table_obj, target_row_number)
                entry.target_file_offset = _row_offset(target_row)
                entry.managed_name = _as_text(getattr(target_row, "Name", None))
                entry.declared_pinvoke = _declares_pinvoke(target_row, target_table)

                type_info = member_types.get((target_table, target_row_number))
                if type_info:
                    type_def = type_info["type"]
                    entry.declaring_type = type_info["full_name"]
                    entry.declaring_type_name = _as_text(getattr(type_def, "TypeName", None))
                    entry.declaring_type_namespace = _as_text(getattr(type_def, "TypeNamespace", None))
                    entry.managed_namespace = entry.declaring_type_namespace
                if entry.declaring_type and entry.managed_name:
                    entry.managed_member = "{}::{}".format(entry.declaring_type, entry.managed_name)
                else:
                    entry.managed_member = entry.managed_name

                signature_info = _signature_info(getattr(target_row, "Signature", None))
                entry.signature = signature_info["signature"]
                entry.signature_calling_convention = signature_info["signature_calling_convention"]
                entry.signature_has_this = signature_info["signature_has_this"]
                entry.signature_explicit_this = signature_info["signature_explicit_this"]
                entry.signature_is_generic = signature_info["signature_is_generic"]
                entry.parameter_count = signature_info["parameter_count"]
                entry.return_type = signature_info["return_type"]
                entry.parameter_types = signature_info["parameter_types"]
                entry.declaration.update({
                    "signature_calling_convention": entry.signature_calling_convention,
                    "parameter_count": entry.parameter_count,
                    "return_type": entry.return_type,
                })

            raw_import_scope = _as_int(getattr(struct, "ImportScope_Index", None))
            if raw_import_scope is None:
                raw_import_scope = _as_int(getattr(impl_map_row, "ImportScope_Index", None))
            entry.raw_import_scope = raw_import_scope
            import_scope = getattr(impl_map_row, "ImportScope", None)
            entry.import_scope = import_scope
            module_ref_row_number = _as_int(getattr(import_scope, "row_index", None), raw_import_scope)
            entry.module_ref_row_number = module_ref_row_number
            entry.module_ref_index = module_ref_row_number - 1 if module_ref_row_number else None

            module_ref_row = _safe_row(import_scope)
            if module_ref_row is None and module_ref_row_number:
                try:
                    module_ref_row = module_ref_table[module_ref_row_number - 1]
                except Exception:
                    module_ref_row = None

            entry.module_ref_row = module_ref_row
            entry.missing_module = module_ref_row is None
            if module_ref_row_number:
                entry.module_ref_token = _make_token(table_numbers["ModuleRef"], module_ref_row_number)
            if module_ref_row is not None:
                entry.module_name = _as_text(getattr(module_ref_row, "Name", None))
                entry.module_ref_rva = _table_row_rva(module_ref_table, module_ref_row_number)
                entry.module_ref_file_offset = _table_row_offset(module_ref_table, module_ref_row_number)
                row_rva = _row_rva(module_ref_row)
                row_offset = _row_offset(module_ref_row)
                if row_rva is not None:
                    entry.module_ref_rva = row_rva
                if row_offset is not None:
                    entry.module_ref_file_offset = row_offset

        yield entry


def collect_pinvoke_entries(source: Any) -> List[PInvokeEntry]:
    """Return a static P/Invoke list for a dnPE/CLR metadata object."""
    return PInvokeList(iter_pinvoke_entries(source))


def build_pinvoke_inventory(source: Any) -> PInvokeInventory:
    return PInvokeInventory(iter_pinvoke_entries(source))


get_pinvoke_entries = collect_pinvoke_entries
get_pinvoke_imports = collect_pinvoke_entries
list_pinvoke_imports = collect_pinvoke_entries
pinvoke_imports = collect_pinvoke_entries
extract_pinvoke_imports = collect_pinvoke_entries
iter_pinvoke_imports = iter_pinvoke_entries
pinvoke_entries = collect_pinvoke_entries
pinvoke_list = collect_pinvoke_entries
list_pinvoke_entries = collect_pinvoke_entries
collect_pinvoke_imports = collect_pinvoke_entries
get_pinvoke_inventory = build_pinvoke_inventory
get_pinvoke_list = collect_pinvoke_entries


parse = collect_pinvoke_entries
scan = collect_pinvoke_entries
read_pinvoke_entries = collect_pinvoke_entries


