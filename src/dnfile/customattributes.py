# -*- coding: utf-8 -*-
"""
Resolve custom attribute ownership and decode the parts of their value blobs
that can be proven from metadata.

The resolver deliberately keeps the metadata row identifiers and file offsets
used at each hop.  A display name alone is never treated as a type identity:
TypeRef rows with the same namespace and name but different ResolutionScope
values remain separate.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import codedindex, enums


_PRIMITIVES = {
    0x02: ("System.Boolean", 1),
    0x03: ("System.Char", 2),
    0x04: ("System.SByte", 1),
    0x05: ("System.Byte", 1),
    0x06: ("System.Int16", 2),
    0x07: ("System.UInt16", 2),
    0x08: ("System.Int32", 4),
    0x09: ("System.UInt32", 4),
    0x0A: ("System.Int64", 8),
    0x0B: ("System.UInt64", 8),
    0x0C: ("System.Single", 4),
    0x0D: ("System.Double", 8),
}

_UNSIGNED = {0x05, 0x07, 0x09, 0x0B}
_SIGNED = {0x04, 0x06, 0x08, 0x0A}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _row_offset(row: Any) -> Optional[int]:
    struct_ = getattr(row, "struct", None)
    if struct_ is None:
        return None
    getter = getattr(struct_, "get_file_offset", None)
    if getter is None:
        return None
    try:
        return getter()
    except Exception:
        return None


def _blob_bytes(item: Any) -> Optional[bytes]:
    if item is None:
        return None
    value = getattr(item, "value", None)
    if isinstance(value, bytes):
        return value
    if isinstance(item, bytes):
        return item
    return None


def _heap_offset(item: Any) -> Optional[int]:
    return getattr(item, "rva", None)


def _metadata_token(table_name: str, row_index: int) -> Optional[int]:
    try:
        table_number = int(enums.MetadataTables[table_name])
    except (KeyError, ValueError):
        return None
    if row_index < 1:
        return None
    return (table_number << 24) | row_index


def _public_key_token(public_key: bytes, flags: int) -> Optional[str]:
    if not public_key:
        return None
    if flags & 0x0001:
        return hashlib.sha1(public_key).digest()[-8:][::-1].hex()
    if len(public_key) == 8:
        return public_key.hex()
    return None


@dataclass(frozen=True)
class AssemblyIdentity:
    name: str
    version: str
    culture: Optional[str]
    public_key_token: Optional[str]
    table: str
    row_index: int
    token: Optional[int]
    file_offset: Optional[int]

    @property
    def canonical(self) -> str:
        culture = self.culture or "neutral"
        token = self.public_key_token or "null"
        return "{}, Version={}, Culture={}, PublicKeyToken={}".format(
            self.name, self.version, culture, token
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "culture": self.culture,
            "public_key_token": self.public_key_token,
            "canonical": self.canonical,
            "table": self.table,
            "row_index": self.row_index,
            "token": _hex_token(self.token),
            "file_offset": _hex_offset(self.file_offset),
        }


@dataclass(frozen=True)
class TypeIdentity:
    display_name: str
    assembly: Optional[AssemblyIdentity]
    scope_kind: str
    scope_name: str
    table: Optional[str]
    row_index: Optional[int]
    token: Optional[int]
    file_offset: Optional[int]
    resolution_chain: Tuple[str, ...]
    resolved: bool
    reason: Optional[str] = None

    @property
    def identity_key(self) -> Tuple[str, str]:
        if self.assembly is not None:
            return (self.display_name, self.assembly.canonical)
        return (self.display_name, "{}:{}:{}#{}".format(
            self.scope_kind, self.scope_name, self.table, self.row_index))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "display_name": self.display_name,
            "assembly": self.assembly.to_dict() if self.assembly else None,
            "scope_kind": self.scope_kind,
            "scope_name": self.scope_name,
            "table": self.table,
            "row_index": self.row_index,
            "token": _hex_token(self.token),
            "file_offset": _hex_offset(self.file_offset),
            "resolution_chain": list(self.resolution_chain),
            "resolved": self.resolved,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class TypeSignature:
    element_type: int
    name: str
    identity: Optional[TypeIdentity] = None
    element: Optional["TypeSignature"] = None
    arguments: Tuple["TypeSignature", ...] = ()
    width: Optional[int] = None
    signed: Optional[bool] = None

    @property
    def value_kind(self) -> str:
        if self.element_type in _PRIMITIVES:
            return "primitive"
        if self.element_type == 0x0E:
            return "string"
        if self.element_type == 0x1C:
            return "object"
        if self.element_type == 0x1D:
            return "array"
        if self.element_type == 0x12 and self.name == "System.Type":
            return "type"
        if self.element_type in (0x11, 0x12) and self.identity is not None:
            if self.identity.display_name == "System.Type":
                return "type"
        if self.element_type == 0x11:
            return "enum_or_valuetype"
        return "unsupported"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "element_type": self.element_type,
            "name": self.name,
            "value_kind": self.value_kind,
            "identity": self.identity.to_dict() if self.identity else None,
            "element": self.element.to_dict() if self.element else None,
            "arguments": [a.to_dict() for a in self.arguments],
            "width": self.width,
            "signed": self.signed,
        }


@dataclass(frozen=True)
class AttributeTarget:
    table: Optional[str]
    row_index: Optional[int]
    token: Optional[int]
    kind: str
    name: str
    owner: Optional[TypeIdentity]
    assembly: Optional[AssemblyIdentity]
    file_offset: Optional[int]
    resolved: bool
    reason: Optional[str] = None

    @property
    def is_assembly(self) -> bool:
        return self.table == "Assembly" and self.resolved

    def to_dict(self) -> Dict[str, Any]:
        return {
            "table": self.table,
            "row_index": self.row_index,
            "token": _hex_token(self.token),
            "kind": self.kind,
            "name": self.name,
            "owner": self.owner.to_dict() if self.owner else None,
            "assembly": self.assembly.to_dict() if self.assembly else None,
            "file_offset": _hex_offset(self.file_offset),
            "resolved": self.resolved,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AttributeConstructor:
    table: Optional[str]
    row_index: Optional[int]
    token: Optional[int]
    name: str
    signature_hex: str
    parameters: Tuple[TypeSignature, ...]
    owner: Optional[TypeIdentity]
    file_offset: Optional[int]
    signature_file_offset: Optional[int]
    resolved: bool
    reason: Optional[str] = None

    @property
    def display_name(self) -> str:
        if self.owner is None:
            return self.name
        if self.name.startswith("."):
            return "{}::{}".format(self.owner.display_name, self.name)
        return "{}.{}".format(self.owner.display_name, self.name)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "table": self.table,
            "row_index": self.row_index,
            "token": _hex_token(self.token),
            "name": self.name,
            "display_name": self.display_name,
            "signature_hex": self.signature_hex,
            "parameters": [p.to_dict() for p in self.parameters],
            "owner": self.owner.to_dict() if self.owner else None,
            "file_offset": _hex_offset(self.file_offset),
            "signature_file_offset": _hex_offset(self.signature_file_offset),
            "resolved": self.resolved,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AttributeArgument:
    kind: str
    index: int
    name: Optional[str]
    type_name: str
    value: Any
    decoded: bool
    blob_offset: int
    end_blob_offset: int
    file_offset: Optional[int]
    end_file_offset: Optional[int]
    raw_hex: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "index": self.index,
            "name": self.name,
            "type_name": self.type_name,
            "value": self.value,
            "decoded": self.decoded,
            "blob_offset": self.blob_offset,
            "end_blob_offset": self.end_blob_offset,
            "file_offset": _hex_offset(self.file_offset),
            "end_file_offset": _hex_offset(self.end_file_offset),
            "raw_hex": self.raw_hex,
            "error": self.error,
        }


@dataclass(frozen=True)
class AttributeBlob:
    raw_hex: str
    blob_file_offset: Optional[int]
    payload_file_offset: Optional[int]
    prolog_hex: str
    arguments: Tuple[AttributeArgument, ...]
    named_count: Optional[int]
    complete: bool
    error: Optional[str]
    error_offset: Optional[int]
    error_file_offset: Optional[int]
    remaining_hex: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_hex": self.raw_hex,
            "blob_file_offset": _hex_offset(self.blob_file_offset),
            "payload_file_offset": _hex_offset(self.payload_file_offset),
            "prolog_hex": self.prolog_hex,
            "arguments": [a.to_dict() for a in self.arguments],
            "named_count": self.named_count,
            "complete": self.complete,
            "error": self.error,
            "error_offset": self.error_offset,
            "error_file_offset": _hex_offset(self.error_file_offset),
            "remaining_hex": self.remaining_hex,
        }


@dataclass(frozen=True)
class CustomAttributeAttribution:
    index: int
    row_index: int
    token: int
    row_file_offset: Optional[int]
    parent: AttributeTarget
    constructor: AttributeConstructor
    blob: AttributeBlob
    comparison: str
    notes: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def type_display_name(self) -> str:
        return self.constructor.owner.display_name if self.constructor.owner else self.constructor.name

    @property
    def assembly_key(self) -> Optional[str]:
        if self.constructor.owner is not None and self.constructor.owner.assembly is not None:
            return self.constructor.owner.assembly.canonical
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "row_index": self.row_index,
            "token": _hex_token(self.token),
            "row_file_offset": _hex_offset(self.row_file_offset),
            "type_display_name": self.type_display_name,
            "assembly_key": self.assembly_key,
            "comparison": self.comparison,
            "parent": self.parent.to_dict(),
            "constructor": self.constructor.to_dict(),
            "blob": self.blob.to_dict(),
            "notes": list(self.notes),
        }


def _hex_offset(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return "0x{:x}".format(value)


def _hex_token(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return "0x{:08x}".format(value)


class _Reader:
    def __init__(self, data: bytes, base_offset: int = 0):
        self.data = data
        self.pos = 0
        self.base_offset = base_offset

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def u8(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("unexpected end of blob at offset {}".format(self.pos))
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u16(self) -> int:
        if self.pos + 2 > len(self.data):
            raise ValueError("unexpected end of blob at offset {}".format(self.pos))
        value = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return value

    def u32(self) -> int:
        if self.pos + 4 > len(self.data):
            raise ValueError("unexpected end of blob at offset {}".format(self.pos))
        value = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def i32(self) -> int:
        if self.pos + 4 > len(self.data):
            raise ValueError("unexpected end of blob at offset {}".format(self.pos))
        value = struct.unpack_from("<i", self.data, self.pos)[0]
        self.pos += 4
        return value

    def compressed(self) -> int:
        first = self.u8()
        if first & 0x80 == 0:
            return first
        if first & 0xC0 == 0x80:
            second = self.u8()
            return ((first & 0x3F) << 8) | second
        if first & 0xE0 == 0xC0:
            rest = self.data[self.pos:self.pos + 3]
            if len(rest) != 3:
                raise ValueError("unexpected end of compressed integer at offset {}".format(self.pos))
            self.pos += 3
            return ((first & 0x1F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
        raise ValueError("invalid compressed integer at offset {}".format(self.pos - 1))

    def ser_string(self) -> Optional[str]:
        if self.pos < len(self.data) and self.data[self.pos] == 0xFF:
            self.pos += 1
            return None
        length = self.compressed()
        if self.pos + length > len(self.data):
            raise ValueError("unexpected end of SerString at offset {}".format(self.pos))
        raw = self.data[self.pos:self.pos + length]
        self.pos += length
        return raw.decode("utf-8", errors="replace")


class _SignatureReader:
    def __init__(self, data: bytes, tables: Sequence[Any]):
        self.reader = _Reader(data)
        self.tables = tables

    def method_parameters(self) -> Tuple[Tuple[TypeSignature, ...], bool, Optional[str]]:
        try:
            convention = self.reader.u8()
            if convention & 0x10:
                self.reader.compressed()
            count = self.reader.compressed()
            return_type = self._type()
            if return_type.element_type != 0x01:
                raise ValueError("constructor signature does not return void")
            params = tuple(self._type() for _ in range(count))
            return params, True, None
        except (ValueError, IndexError) as exc:
            return (), False, str(exc)

    def _type(self) -> TypeSignature:
        element = self.reader.u8()
        if element == 0x01:
            return TypeSignature(element, "System.Void")
        if element in _PRIMITIVES:
            name, width = _PRIMITIVES[element]
            return TypeSignature(element, name, width=width)
        if element == 0x0E:
            return TypeSignature(element, "System.String")
        if element == 0x1C:
            return TypeSignature(element, "System.Object")
        if element == 0x11 or element == 0x12:
            coded = self.reader.compressed()
            identity = _resolve_typedef_or_ref(coded, self.tables)
            return TypeSignature(element, identity.display_name, identity=identity)
        if element == 0x1D:
            child = self._type()
            return TypeSignature(element, "{}[]".format(child.name), element=child)
        if element == 0x15:
            kind = self.reader.u8()
            if kind not in (0x11, 0x12):
                raise ValueError("invalid GENERICINST type kind 0x{:02x}".format(kind))
            coded = self.reader.compressed()
            identity = _resolve_typedef_or_ref(coded, self.tables)
            count = self.reader.compressed()
            args = tuple(self._type() for _ in range(count))
            name = "{}<{}>".format(identity.display_name, ",".join(a.name for a in args))
            return TypeSignature(element, name, identity=identity, arguments=args)
        if element in (0x1F, 0x20):
            self.reader.compressed()
            return self._type()
        if element in (0x0F, 0x10):
            child = self._type()
            suffix = "*" if element == 0x0F else "&"
            return TypeSignature(element, child.name + suffix, element=child)
        if element in (0x13, 0x1E):
            index = self.reader.compressed()
            return TypeSignature(element, "{}{}".format("!" if element == 0x13 else "!!", index))
        if element == 0x14:
            child = self._type()
            rank = self.reader.compressed()
            for _ in range(self.reader.compressed()):
                self.reader.compressed()
            return TypeSignature(element, "{}[,]".format(child.name), element=child, width=rank)
        if element in (0x16, 0x18, 0x19, 0x1B):
            return TypeSignature(element, "unsupported:0x{:02x}".format(element))
        if element == 0x45:
            return self._type()
        raise ValueError("unsupported signature element 0x{:02x}".format(element))


def _resolve_typedef_or_ref(value: int, tables: Sequence[Any]) -> TypeIdentity:
    index = codedindex.TypeDefOrRef(value, tables)
    if index.table is None or index.row is None:
        return TypeIdentity(
            display_name="<unresolved>",
            assembly=None,
            scope_kind="unresolved",
            scope_name="TypeDefOrRef",
            table=None,
            row_index=index.row_index,
            token=None,
            file_offset=None,
            resolution_chain=(),
            resolved=False,
            reason="coded index does not resolve to TypeDef, TypeRef, or TypeSpec",
        )
    return _type_from_row(index.table, index.row_index, index.row, tables, ())


def _assembly_from_row(table: Any, row_index: int, row: Any) -> Optional[AssemblyIdentity]:
    name = _text(getattr(row, "Name", None))
    if not name:
        return None
    version = "{}.{}.{}.{}".format(
        getattr(row, "MajorVersion", 0),
        getattr(row, "MinorVersion", 0),
        getattr(row, "BuildNumber", 0),
        getattr(row, "RevisionNumber", 0),
    )
    public_key = _blob_bytes(getattr(row, "PublicKey", None)) or b""
    flags = getattr(getattr(row, "struct", None), "Flags", 0)
    if table.name == "Assembly":
        token = hashlib.sha1(public_key).digest()[-8:][::-1].hex() if public_key else None
    else:
        token = _public_key_token(public_key, int(flags or 0))
    return AssemblyIdentity(
        name=name,
        version=version,
        culture=_text(getattr(row, "Culture", None)) or None,
        public_key_token=token,
        table=table.name,
        row_index=row_index,
        token=_metadata_token(table.name, row_index),
        file_offset=_row_offset(row),
    )


def _local_assembly(tables: Sequence[Any]) -> Optional[AssemblyIdentity]:
    for table in tables:
        if table.name == "Assembly" and len(table) > 0:
            row = table.get_with_row_index(1)
            if row is not None:
                return _assembly_from_row(table, 1, row)
    return None


def _type_from_row(
    table: Any,
    row_index: int,
    row: Any,
    tables: Sequence[Any],
    seen: Tuple[Tuple[str, int], ...],
) -> TypeIdentity:
    marker = (table.name, row_index)
    if marker in seen:
        return TypeIdentity(
            display_name="{}[{}]".format(_text(getattr(row, "TypeName", "")), row_index),
            assembly=None,
            scope_kind="cycle",
            scope_name=table.name,
            table=table.name,
            row_index=row_index,
            token=_metadata_token(table.name, row_index),
            file_offset=_row_offset(row),
            resolution_chain=(),
            resolved=False,
            reason="TypeRef resolution-scope cycle",
        )

    if table.name == "TypeDef":
        namespace = _text(getattr(row, "TypeNamespace", None))
        name = _text(getattr(row, "TypeName", None))
        display = "{}.{}".format(namespace, name) if namespace else name
        assembly = _local_assembly(tables)
        return TypeIdentity(
            display_name=display,
            assembly=assembly,
            scope_kind="defined",
            scope_name=assembly.canonical if assembly else "current module",
            table=table.name,
            row_index=row_index,
            token=_metadata_token(table.name, row_index),
            file_offset=_row_offset(row),
            resolution_chain=("TypeDef[{}] {}".format(row_index, display),),
            resolved=assembly is not None,
            reason=None if assembly is not None else "no Assembly row for a local TypeDef",
        )

    if table.name == "TypeRef":
        namespace = _text(getattr(row, "TypeNamespace", None))
        name = _text(getattr(row, "TypeName", None))
        display = "{}.{}".format(namespace, name) if namespace else name
        scope = getattr(row, "ResolutionScope", None)
        chain = ["TypeRef[{}] {}{}".format(
            row_index,
            display,
            "" if namespace else "",
        )]
        if scope is None or getattr(scope, "table", None) is None or getattr(scope, "row", None) is None:
            return TypeIdentity(
                display_name=display,
                assembly=None,
                scope_kind="unresolved",
                scope_name="ResolutionScope",
                table=table.name,
                row_index=row_index,
                token=_metadata_token(table.name, row_index),
                file_offset=_row_offset(row),
                resolution_chain=tuple(chain),
                resolved=False,
                reason="TypeRef ResolutionScope did not resolve",
            )
        scope_table = scope.table
        scope_row = scope.row
        if scope_table.name == "AssemblyRef":
            assembly = _assembly_from_row(scope_table, scope.row_index, scope_row)
            chain.append("AssemblyRef[{}] {}".format(
                scope.row_index,
                assembly.canonical if assembly else _text(getattr(scope_row, "Name", None)),
            ))
            return TypeIdentity(
                display_name=display,
                assembly=assembly,
                scope_kind="assembly-ref",
                scope_name=assembly.canonical if assembly else "AssemblyRef",
                table=table.name,
                row_index=row_index,
                token=_metadata_token(table.name, row_index),
                file_offset=_row_offset(row),
                resolution_chain=tuple(chain),
                resolved=assembly is not None,
                reason=None if assembly is not None else "AssemblyRef has no usable name",
            )
        if scope_table.name == "Module":
            assembly = _local_assembly(tables)
            chain.append("Module[{}] {}".format(
                scope.row_index, _text(getattr(scope_row, "Name", None))
            ))
            return TypeIdentity(
                display_name=display,
                assembly=assembly,
                scope_kind="module",
                scope_name=assembly.canonical if assembly else "Module",
                table=table.name,
                row_index=row_index,
                token=_metadata_token(table.name, row_index),
                file_offset=_row_offset(row),
                resolution_chain=tuple(chain),
                resolved=assembly is not None,
                reason=None if assembly is not None else "Module scope without Assembly row",
            )
        if scope_table.name == "ModuleRef":
            module_name = _text(getattr(scope_row, "Name", None))
            chain.append("ModuleRef[{}] {}".format(scope.row_index, module_name))
            return TypeIdentity(
                display_name=display,
                assembly=None,
                scope_kind="module-ref",
                scope_name=module_name,
                table=table.name,
                row_index=row_index,
                token=_metadata_token(table.name, row_index),
                file_offset=_row_offset(row),
                resolution_chain=tuple(chain),
                resolved=False,
                reason="ModuleRef identifies a netmodule, not the owning assembly",
            )
        if scope_table.name == "TypeRef":
            parent = _type_from_row(
                scope_table, scope.row_index, scope_row, tables, seen + (marker,)
            )
            chain.extend(parent.resolution_chain)
            return TypeIdentity(
                display_name="{}+{}".format(parent.display_name, name),
                assembly=parent.assembly,
                scope_kind="nested",
                scope_name=parent.scope_name,
                table=table.name,
                row_index=row_index,
                token=_metadata_token(table.name, row_index),
                file_offset=_row_offset(row),
                resolution_chain=tuple(chain),
                resolved=parent.resolved,
                reason=parent.reason,
            )
        return TypeIdentity(
            display_name=display,
            assembly=None,
            scope_kind=scope_table.name.lower(),
            scope_name=scope_table.name,
            table=table.name,
            row_index=row_index,
            token=_metadata_token(table.name, row_index),
            file_offset=_row_offset(row),
            resolution_chain=tuple(chain),
            resolved=False,
            reason="unsupported TypeRef ResolutionScope {}".format(scope_table.name),
        )

    if table.name == "TypeSpec":
        return TypeIdentity(
            display_name="TypeSpec[{}]".format(row_index),
            assembly=None,
            scope_kind="typespec",
            scope_name="TypeSpec",
            table=table.name,
            row_index=row_index,
            token=_metadata_token(table.name, row_index),
            file_offset=_row_offset(row),
            resolution_chain=("TypeSpec[{}]".format(row_index),),
            resolved=False,
            reason="TypeSpec signature was not expanded",
        )

    return TypeIdentity(
        display_name="{}[{}]".format(table.name, row_index),
        assembly=None,
        scope_kind=table.name.lower(),
        scope_name=table.name,
        table=table.name,
        row_index=row_index,
        token=_metadata_token(table.name, row_index),
        file_offset=_row_offset(row),
        resolution_chain=(),
        resolved=False,
        reason="unsupported type table {}".format(table.name),
    )


class CustomAttributeAnalyzer:
    def __init__(self, pe: Any):
        self.pe = pe
        net = getattr(pe, "net", None)
        mdtables = getattr(net, "mdtables", None) if net is not None else None
        self.tables = list(mdtables.tables_list) if mdtables is not None else []
        self.table_by_name = {t.name: t for t in self.tables}
        self._method_owner: Dict[int, Tuple[Any, int, Any]] = {}
        self._field_owner: Dict[int, Tuple[Any, int, Any]] = {}
        self._property_owner: Dict[int, Tuple[Any, int, Any]] = {}
        self._build_owner_maps()

    def _build_owner_maps(self) -> None:
        type_def = self.table_by_name.get("TypeDef")
        if type_def is None:
            return
        for type_index, type_row in enumerate(type_def, start=1):
            if type_row is None:
                continue
            for item in getattr(type_row, "MethodList", []) or []:
                rid = getattr(item, "row_index", None)
                if rid is not None:
                    self._method_owner.setdefault(rid, (type_def, type_index, type_row))
            for item in getattr(type_row, "FieldList", []) or []:
                rid = getattr(item, "row_index", None)
                if rid is not None:
                    self._field_owner.setdefault(rid, (type_def, type_index, type_row))

        property_map = self.table_by_name.get("PropertyMap")
        if property_map is not None:
            for map_index, map_row in enumerate(property_map, start=1):
                if map_row is None:
                    continue
                parent = getattr(map_row, "Parent", None)
                if parent is None or getattr(parent, "table", None) is None:
                    continue
                for item in getattr(map_row, "PropertyList", []) or []:
                    rid = getattr(item, "row_index", None)
                    if rid is not None:
                        self._property_owner.setdefault(
                            rid, (parent.table, parent.row_index, parent.row)
                        )

    def analyze(self) -> List[CustomAttributeAttribution]:
        table = self.table_by_name.get("CustomAttribute")
        if table is None:
            return []

        records: List[CustomAttributeAttribution] = []
        for index, row in enumerate(table, start=1):
            if row is None:
                continue
            parent = self._target_from_coded_index(getattr(row, "Parent", None))
            constructor = self._constructor_from_coded_index(getattr(row, "Type", None))
            blob = self._blob_from_value(getattr(row, "Value", None), constructor.parameters)
            comparison, notes = self._classify(parent, constructor, blob)
            records.append(CustomAttributeAttribution(
                index=index - 1,
                row_index=index,
                token=_metadata_token("CustomAttribute", index) or 0,
                row_file_offset=_row_offset(row),
                parent=parent,
                constructor=constructor,
                blob=blob,
                comparison=comparison,
                notes=tuple(notes),
            ))
        return records

    def _classify(
        self,
        parent: AttributeTarget,
        constructor: AttributeConstructor,
        blob: AttributeBlob,
    ) -> Tuple[str, List[str]]:
        notes: List[str] = []
        if not parent.resolved:
            notes.append(parent.reason or "attribute parent did not resolve")
        if not constructor.resolved or constructor.owner is None:
            notes.append(constructor.reason or "constructor owner did not resolve")
        if constructor.owner is not None and constructor.owner.assembly is None:
            notes.append(constructor.owner.reason or "constructor owner has no assembly identity")
        if not blob.complete:
            notes.append("value blob is partial; verified arguments and raw offsets are retained")
        notes = list(dict.fromkeys(notes))
        if notes and (
            not parent.resolved
            or not constructor.resolved
            or (constructor.owner is not None and constructor.owner.assembly is None)
        ):
            return "insufficient", notes
        if parent.is_assembly:
            return "assembly", notes
        return "member_only", notes

    def _target_from_coded_index(self, parent: Any) -> AttributeTarget:
        if parent is None:
            return AttributeTarget(
                None, None, None, "unresolved", "", None, None, None, False,
                "CustomAttribute.Parent is absent",
            )
        table = getattr(parent, "table", None)
        row_index = getattr(parent, "row_index", None)
        row = getattr(parent, "row", None)
        if table is None or row is None:
            return AttributeTarget(
                table.name if table is not None else None,
                row_index,
                _metadata_token(table.name, row_index) if table is not None and row_index else None,
                "unresolved",
                "",
                None,
                None,
                None,
                False,
                "CustomAttribute.Parent coded index did not resolve",
            )

        name = _text(getattr(row, "Name", None))
        owner: Optional[TypeIdentity] = None
        assembly: Optional[AssemblyIdentity] = None
        kind = table.name
        if table.name == "Assembly":
            assembly = _assembly_from_row(table, row_index, row)
            name = assembly.canonical if assembly else name
            kind = "assembly"
        elif table.name == "AssemblyRef":
            assembly = _assembly_from_row(table, row_index, row)
            name = assembly.canonical if assembly else name
            kind = "assembly-ref"
        elif table.name == "MethodDef":
            owner_info = self._method_owner.get(row_index)
            if owner_info is not None:
                owner = _type_from_row(owner_info[0], owner_info[1], owner_info[2], self.tables, ())
                assembly = owner.assembly
            name = _text(getattr(row, "Name", None))
            kind = "method"
        elif table.name == "Field":
            owner_info = self._field_owner.get(row_index)
            if owner_info is not None:
                owner = _type_from_row(owner_info[0], owner_info[1], owner_info[2], self.tables, ())
                assembly = owner.assembly
            name = _text(getattr(row, "Name", None))
            kind = "field"
        elif table.name == "Property":
            owner_info = self._property_owner.get(row_index)
            if owner_info is not None:
                owner = _type_from_row(owner_info[0], owner_info[1], owner_info[2], self.tables, ())
                assembly = owner.assembly
            name = _text(getattr(row, "Name", None))
            kind = "property"
        elif table.name == "TypeDef":
            owner = _type_from_row(table, row_index, row, self.tables, ())
            assembly = owner.assembly
            name = owner.display_name
            kind = "type"
        elif table.name == "Module":
            name = _text(getattr(row, "Name", None))
            assembly = _local_assembly(self.tables)
            kind = "module"
        elif table.name == "MemberRef":
            owner = self._type_owner_from_member_ref(row)
            assembly = owner.assembly if owner else None
            name = _text(getattr(row, "Name", None))
            kind = "member-ref"
        elif table.name == "Param":
            name = _text(getattr(row, "Name", None))
            kind = "param"
        elif table.name == "ModuleRef":
            name = _text(getattr(row, "Name", None))
            kind = "module-ref"
        else:
            name = _text(getattr(row, "Name", None)) or "{}[{}]".format(table.name, row_index)
            kind = table.name.lower()

        return AttributeTarget(
            table.name,
            row_index,
            _metadata_token(table.name, row_index),
            kind,
            name,
            owner,
            assembly,
            _row_offset(row),
            True,
        )

    def _type_owner_from_member_ref(self, row: Any) -> Optional[TypeIdentity]:
        class_index = getattr(row, "Class", None)
        if class_index is None or getattr(class_index, "table", None) is None or getattr(class_index, "row", None) is None:
            return None
        if class_index.table.name in ("TypeDef", "TypeRef", "TypeSpec"):
            return _type_from_row(
                class_index.table,
                class_index.row_index,
                class_index.row,
                self.tables,
                (),
            )
        return None

    def _constructor_from_coded_index(self, type_index: Any) -> AttributeConstructor:
        if type_index is None:
            return AttributeConstructor(
                None, None, None, "", "", (), None, None, None, False,
                "CustomAttribute.Type is absent",
            )
        table = getattr(type_index, "table", None)
        row_index = getattr(type_index, "row_index", None)
        row = getattr(type_index, "row", None)
        if table is None or row is None:
            return AttributeConstructor(
                table.name if table is not None else None,
                row_index,
                _metadata_token(table.name, row_index) if table is not None and row_index else None,
                "",
                "",
                (),
                None,
                None,
                None,
                False,
                "CustomAttribute.Type coded index did not resolve",
            )

        owner: Optional[TypeIdentity] = None
        if table.name == "MemberRef":
            owner = self._type_owner_from_member_ref(row)
        elif table.name == "MethodDef":
            owner_info = self._method_owner.get(row_index)
            if owner_info is not None:
                owner = _type_from_row(owner_info[0], owner_info[1], owner_info[2], self.tables, ())
        else:
            return AttributeConstructor(
                table.name,
                row_index,
                _metadata_token(table.name, row_index),
                "",
                "",
                (),
                None,
                _row_offset(row),
                None,
                False,
                "CustomAttributeType must resolve to MemberRef or MethodDef",
            )

        signature_item = getattr(row, "Signature", None)
        signature = _blob_bytes(signature_item)
        signature_hex = signature.hex() if signature else ""
        params, signature_ok, signature_error = _SignatureReader(signature or b"", self.tables).method_parameters()
        resolved = owner is not None and owner.resolved and signature_ok
        reason = None
        if owner is None:
            reason = "constructor owner did not resolve"
        elif not owner.resolved:
            reason = owner.reason or "constructor owner has no assembly identity"
        elif not signature_ok:
            reason = "constructor signature could not be decoded: {}".format(signature_error)
        return AttributeConstructor(
            table.name,
            row_index,
            _metadata_token(table.name, row_index),
            _text(getattr(row, "Name", None)),
            signature_hex,
            params,
            owner,
            _row_offset(row),
            self._signature_file_offset(signature_item),
            resolved,
            reason,
        )

    def _signature_file_offset(self, item: Any) -> Optional[int]:
        if item is None:
            return None
        rva = getattr(item, "rva", None)
        if rva is None:
            return None
        try:
            return self.pe.get_offset_from_rva(rva)
        except Exception:
            return None

    def _blob_from_value(self, item: Any, params: Sequence[TypeSignature]) -> AttributeBlob:
        raw = _blob_bytes(item)
        if raw is None:
            return AttributeBlob(
                "", None, None, "", (), None, False,
                "custom attribute value blob did not resolve", None, None, "",
            )
        blob_file_offset = None
        payload_file_offset = None
        rva = _heap_offset(item)
        if rva is not None:
            try:
                blob_file_offset = self.pe.get_offset_from_rva(rva)
                prefix_size = getattr(getattr(item, "item_size", None), "raw_size", 0)
                payload_file_offset = blob_file_offset + prefix_size
            except Exception:
                blob_file_offset = None
                payload_file_offset = None
        return _parse_attribute_blob(
            raw,
            params,
            self.tables,
            blob_file_offset=blob_file_offset,
            payload_file_offset=payload_file_offset,
        )


def _arg_file_offset(payload_file_offset: Optional[int], offset: int) -> Optional[int]:
    if payload_file_offset is None:
        return None
    return payload_file_offset + offset


def _parse_attribute_blob(
    raw: bytes,
    params: Sequence[TypeSignature],
    tables: Sequence[Any],
    blob_file_offset: Optional[int],
    payload_file_offset: Optional[int],
) -> AttributeBlob:
    reader = _Reader(raw)
    arguments: List[AttributeArgument] = []
    prolog = ""
    error: Optional[str] = None
    error_offset: Optional[int] = None
    named_count: Optional[int] = None

    try:
        prolog = raw[reader.pos:reader.pos + 2].hex()
        if reader.u16() != 0x0001:
            raise ValueError("custom attribute prolog is not 0x0001")
        for index, param in enumerate(params, start=1):
            start = reader.pos
            try:
                value = _decode_value(reader, param, tables)
            except (ValueError, IndexError):
                if error_offset is None:
                    error_offset = start
                raise
            arguments.append(_make_argument(
                "fixed", index, None, param, value, start, reader.pos,
                payload_file_offset, raw,
            ))

        named_count = reader.u16()
        if named_count > len(raw):
            raise ValueError("named-argument count exceeds blob size")
        for index in range(named_count):
            start = reader.pos
            marker = reader.u8()
            if marker not in (0x53, 0x54):
                raise ValueError("invalid named-argument marker 0x{:02x}".format(marker))
            kind = "named-field" if marker == 0x53 else "named-property"
            type_sig = _read_field_or_prop_type(reader, tables)
            name = reader.ser_string()
            value_start = reader.pos
            try:
                value = _decode_value(reader, type_sig, tables)
            except (ValueError, IndexError) as exc:
                error = str(exc)
                error_offset = value_start
                arguments.append(AttributeArgument(
                    kind=kind,
                    index=index,
                    name=name,
                    type_name=type_sig.name,
                    value=None,
                    decoded=False,
                    blob_offset=start,
                    end_blob_offset=value_start,
                    file_offset=_arg_file_offset(payload_file_offset, start),
                    end_file_offset=_arg_file_offset(payload_file_offset, value_start),
                    raw_hex=raw[start:value_start].hex(),
                    error=error,
                ))
                break
            arguments.append(_make_argument(
                kind, index, name, type_sig, value, start, reader.pos,
                payload_file_offset, raw,
            ))
    except (ValueError, IndexError) as exc:
        error = str(exc)
        if error_offset is None:
            error_offset = reader.pos
    if error_offset is None and error is not None:
        error_offset = reader.pos

    if error is None and reader.pos != len(raw):
        error = "unconsumed trailing bytes"
        error_offset = reader.pos
    complete = error is None and reader.pos == len(raw)
    if complete:
        remaining = b""
    else:
        remaining_start = error_offset if error_offset is not None else reader.pos
        remaining = raw[remaining_start:] if remaining_start < len(raw) else b""
    return AttributeBlob(
        raw_hex=raw.hex(),
        blob_file_offset=blob_file_offset,
        payload_file_offset=payload_file_offset,
        prolog_hex=prolog,
        arguments=tuple(arguments),
        named_count=named_count,
        complete=complete,
        error=error,
        error_offset=error_offset,
        error_file_offset=_arg_file_offset(payload_file_offset, error_offset) if error_offset is not None else None,
        remaining_hex=remaining.hex(),
    )


def _make_argument(
    kind: str,
    index: int,
    name: Optional[str],
    type_sig: TypeSignature,
    value: Any,
    start: int,
    end: int,
    payload_file_offset: Optional[int],
    raw: bytes,
) -> AttributeArgument:
    return AttributeArgument(
        kind=kind,
        index=index,
        name=name,
        type_name=type_sig.name,
        value=value,
        decoded=True,
        blob_offset=start,
        end_blob_offset=end,
        file_offset=_arg_file_offset(payload_file_offset, start),
        end_file_offset=_arg_file_offset(payload_file_offset, end),
        raw_hex=raw[start:end].hex(),
    )


def _read_field_or_prop_type(reader: _Reader, tables: Sequence[Any]) -> TypeSignature:
    element = reader.u8()
    if element in _PRIMITIVES:
        name, width = _PRIMITIVES[element]
        return TypeSignature(element, name, width=width)
    if element == 0x0E:
        return TypeSignature(element, "System.String")
    if element == 0x1D:
        child = _read_field_or_prop_type(reader, tables)
        return TypeSignature(element, "{}[]".format(child.name), element=child)
    if element == 0x50:
        reader.ser_string()
        return TypeSignature(0x12, "System.Type")
    if element == 0x55:
        enum_name = reader.ser_string() or "enum"
        return TypeSignature(0x11, enum_name)
    if element == 0x51:
        return _read_field_or_prop_type(reader, tables)
    raise ValueError("unsupported FieldOrPropType 0x{:02x}".format(element))


def _enum_width(identity: Optional[TypeIdentity], tables: Sequence[Any]) -> Optional[Tuple[int, bool]]:
    if identity is None or identity.table != "TypeDef" or identity.row_index is None:
        return None
    type_table = None
    for table in tables:
        if table.name == "TypeDef":
            type_table = table
            break
    if type_table is None:
        return None
    row = type_table.get_with_row_index(identity.row_index)
    if row is None:
        return None
    for field_index in getattr(row, "FieldList", []) or []:
        field_row = getattr(field_index, "row", None)
        if field_row is None or _text(getattr(field_row, "Name", None)) != "value__":
            continue
        signature = _blob_bytes(getattr(field_row, "Signature", None)) or b""
        if len(signature) >= 2 and signature[0] == 0x06:
            primitive = _PRIMITIVES.get(signature[1])
            if primitive is not None:
                return primitive[1], signature[1] not in _UNSIGNED
    return None


def _decode_value(reader: _Reader, type_sig: TypeSignature, tables: Sequence[Any]) -> Any:
    kind = type_sig.value_kind
    if kind == "primitive":
        element = type_sig.element_type
        if element == 0x02:
            return bool(reader.u8())
        if element == 0x03:
            if reader.pos + 2 > len(reader.data):
                raise ValueError("unexpected end of char at offset {}".format(reader.pos))
            value = struct.unpack_from("<H", reader.data, reader.pos)[0]
            reader.pos += 2
            return chr(value)
        if element in _UNSIGNED:
            width = type_sig.width or 1
            raw = reader.data[reader.pos:reader.pos + width]
            if len(raw) != width:
                raise ValueError("unexpected end of integer at offset {}".format(reader.pos))
            reader.pos += width
            return int.from_bytes(raw, "little")
        if element in _SIGNED:
            width = type_sig.width or 1
            raw = reader.data[reader.pos:reader.pos + width]
            if len(raw) != width:
                raise ValueError("unexpected end of integer at offset {}".format(reader.pos))
            reader.pos += width
            return int.from_bytes(raw, "little", signed=True)
        if element in (0x0C, 0x0D):
            width = type_sig.width or 4
            raw = reader.data[reader.pos:reader.pos + width]
            if len(raw) != width:
                raise ValueError("unexpected end of float at offset {}".format(reader.pos))
            reader.pos += width
            return struct.unpack("<f" if width == 4 else "<d", raw)[0]
    if kind == "string":
        return reader.ser_string()
    if kind == "type":
        return reader.ser_string()
    if kind == "object":
        tag = reader.u8()
        return _decode_tagged_value(reader, tag, tables)
    if kind == "array":
        count = reader.i32()
        if count < 0:
            raise ValueError("negative array length at offset {}".format(reader.pos - 4))
        values = []
        for _ in range(count):
            values.append(_decode_value(reader, type_sig.element, tables))
        return values
    if kind == "enum_or_valuetype":
        width = type_sig.width
        signed = type_sig.signed
        if width is None:
            inferred = _enum_width(type_sig.identity, tables)
            if inferred is not None:
                width, signed = inferred
        if width is not None:
            raw = reader.data[reader.pos:reader.pos + width]
            if len(raw) != width:
                raise ValueError("unexpected end of enum at offset {}".format(reader.pos))
            reader.pos += width
            return int.from_bytes(raw, "little", signed=True if signed is None else signed)
        raise ValueError(
            "enum underlying width is unknown for {}; value left unparsed".format(type_sig.name)
        )
    raise ValueError("unsupported custom attribute parameter type {}".format(type_sig.name))


def _decode_tagged_value(reader: _Reader, tag: int, tables: Sequence[Any]) -> Any:
    if tag == 0x50:
        return reader.ser_string()
    if tag == 0x51:
        return _decode_tagged_value(reader, reader.u8(), tables)
    if tag == 0x55:
        enum_name = reader.ser_string()
        raise ValueError(
            "tagged enum {} has no resolvable underlying width".format(enum_name)
        )
    type_sig = _read_field_or_prop_type_from_tag(reader, tag, tables)
    return _decode_value(reader, type_sig, tables)


def _read_field_or_prop_type_from_tag(
    reader: _Reader, element: int, tables: Sequence[Any]
) -> TypeSignature:
    if element in _PRIMITIVES:
        name, width = _PRIMITIVES[element]
        return TypeSignature(element, name, width=width)
    if element == 0x0E:
        return TypeSignature(element, "System.String")
    if element == 0x1D:
        child = _read_field_or_prop_type(reader, tables)
        return TypeSignature(element, "{}[]".format(child.name), element=child)
    raise ValueError("unsupported tagged value type 0x{:02x}".format(element))


def analyze_custom_attributes(pe: Any) -> List[CustomAttributeAttribution]:
    return CustomAttributeAnalyzer(pe).analyze()
