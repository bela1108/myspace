# -*- coding: utf-8 -*-
"""
Offline .NET metadata entity correlation.

The correlator compares two compiled assemblies without trusting metadata
tokens to survive a rebuild.  Each assembly is projected into a token-free
semantic model first:

* namespaces and declaring-type paths,
* type, method, field, property and event declarations,
* local variable declarations read from method bodies,
* generic parameter constraints,
* nested-type and member ownership relationships.

References inside signatures are resolved through the metadata of the same
assembly and rendered as structural names (for example
``class System.Collections.Generic.List<valuetype System.Int32>``).  A token
from the first assembly is therefore never used to look up a token in the
second assembly.

The public entry points are:

    load_metadata(path)                    -> MetadataView
    correlate(old, new)                    -> CorrelationResult
    correlate_files(old_path, new_path)    -> CorrelationResult
    export_mapping(result, path, ...)      -> writes CSV/JSON/Markdown

Command line:

    python -m dnfile.correlate OLD.dll NEW.dll -o entity-map.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import struct as _struct
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import dnfile

logger = logging.getLogger(__name__)


TOKEN_TABLES = {
    0x00: "Module",
    0x01: "TypeRef",
    0x02: "TypeDef",
    0x04: "Field",
    0x06: "MethodDef",
    0x08: "Param",
    0x09: "InterfaceImpl",
    0x0A: "MemberRef",
    0x0B: "Constant",
    0x0C: "CustomAttribute",
    0x0F: "ClassLayout",
    0x11: "StandAloneSig",
    0x14: "Event",
    0x15: "PropertyPtr",
    0x17: "Property",
    0x18: "MethodSemantics",
    0x19: "MethodImpl",
    0x1A: "ModuleRef",
    0x1B: "TypeSpec",
    0x20: "Assembly",
    0x23: "AssemblyRef",
    0x29: "NestedClass",
    0x2A: "GenericParam",
    0x2B: "MethodSpec",
    0x2C: "GenericParamConstraint",
}

STATUS_UNCHANGED = "unchanged"
STATUS_RENUMBERED = "renumbered_only"
STATUS_METADATA_CHANGED = "metadata_changed"
STATUS_SIGNATURE_CHANGED = "signature_changed"
STATUS_AMBIGUOUS = "ambiguous_same_name"
STATUS_UNMATCHED_OLD = "unmatched_old"
STATUS_UNMATCHED_NEW = "unmatched_new"

SEMANTIC_STATUSES = (
    STATUS_UNCHANGED,
    STATUS_RENUMBERED,
    STATUS_METADATA_CHANGED,
    STATUS_SIGNATURE_CHANGED,
)


class CorrelationError(Exception):
    """Raised when an assembly cannot be projected into the entity model."""


def make_token(table_number: int, row_index: int) -> int:
    """Return the ECMA-335 metadata token for a 1-based table row index."""

    return ((table_number & 0xFF) << 24) | (row_index & 0x00FFFFFF)


def token_str(token: Optional[int]) -> str:
    if token is None:
        return ""
    return "0x%08X" % token


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:16]


def _strip_namespace(name: Optional[str], namespace: str) -> str:
    if not name:
        return ""
    prefix = (namespace or "") + "."
    if namespace and name.startswith(prefix):
        return name[len(prefix):]
    return name


def _blob_bytes(value: Any) -> bytes:
    """Normalize dnfile blob values (bytes or HeapItemBinary) to bytes."""

    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    value_bytes = getattr(value, "value_bytes", None)
    if callable(value_bytes):
        try:
            return bytes(value_bytes())
        except (TypeError, ValueError):
            pass
    interpreted = getattr(value, "value", None)
    if isinstance(interpreted, (bytes, bytearray)):
        return bytes(interpreted)
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return b""


@dataclass
class LocalVariable:
    index: int
    type: str
    pinned: bool = False

    def projection(self) -> Dict[str, Any]:
        return {"index": self.index, "type": self.type, "pinned": self.pinned}


@dataclass
class GenericParameter:
    number: int
    name: str
    flags: int
    variance: str
    constraints: List[str] = field(default_factory=list)

    def projection(self) -> Dict[str, Any]:
        return {
            "number": self.number,
            "name": self.name,
            "variance": self.variance,
            "flags": _generic_param_flags(self.flags),
            "constraints": sorted(self.constraints),
        }


@dataclass
class Entity:
    kind: str
    token: int
    rid: int
    name: str
    namespace: str
    declaring_type: Optional[str]
    full_name: str
    identity: str
    projection: Dict[str, Any]
    semantic_projection: Dict[str, Any]
    signature: Dict[str, Any]
    locals: Optional[Dict[str, Any]]
    constraints: List[Dict[str, Any]]
    notes: List[str] = field(default_factory=list)

    @property
    def token_name(self) -> str:
        return token_str(self.token)

    @property
    def projection_key(self) -> str:
        return _digest(self.projection)

    @property
    def semantic_key(self) -> str:
        return _digest(self.semantic_projection)

    @property
    def namespace_key(self) -> str:
        return self.namespace or ""

    @property
    def loose_identity(self) -> str:
        """Identity with the namespace removed, used only as a fallback.

        Namespace equality is then scored as evidence instead of making a
        namespace move look like a completely new entity.
        """

        if self.kind == "type":
            return "type:%s" % _strip_namespace(self.full_name, self.namespace)
        declaring = _strip_namespace(self.declaring_type, self.namespace)
        if self.kind == "method":
            return "method:%s::%s" % (declaring, self.name)
        return "%s:%s::%s" % (self.kind, declaring, self.name)

    def summary(self) -> str:
        if self.declaring_type:
            return "%s %s::%s" % (self.kind, self.declaring_type, self.name)
        return "%s %s" % (self.kind, self.full_name)


@dataclass
class MetadataView:
    path: str
    assembly_name: str
    module_name: str
    entities: List[Entity]
    pe: Any
    metadata: Any
    type_full_names: Dict[int, str] = field(default_factory=dict)
    method_by_rid: Dict[int, Entity] = field(default_factory=dict)

    @property
    def types(self) -> List[Entity]:
        return [e for e in self.entities if e.kind == "type"]

    @property
    def methods(self) -> List[Entity]:
        return [e for e in self.entities if e.kind == "method"]


@dataclass
class Candidate:
    target: Entity
    score: float
    comparisons: Dict[str, Any]
    token_equal: bool
    semantic_equal: bool
    projection_equal: bool


@dataclass
class Match:
    source: Entity
    status: str
    target: Optional[Entity]
    score: float
    group_id: str
    candidates: List[Candidate]
    comparisons: Dict[str, Any]
    notes: List[str] = field(default_factory=list)

    @property
    def review_required(self) -> bool:
        return self.status in (STATUS_AMBIGUOUS, STATUS_UNMATCHED_OLD)


@dataclass
class CorrelationResult:
    old: MetadataView
    new: MetadataView
    matches: List[Match]
    unmatched_new: List[Entity]

    @property
    def ambiguous(self) -> List[Match]:
        return [m for m in self.matches if m.status == STATUS_AMBIGUOUS]

    @property
    def renumbered(self) -> List[Match]:
        return [m for m in self.matches if m.status == STATUS_RENUMBERED]

    @property
    def signature_changed(self) -> List[Match]:
        return [m for m in self.matches if m.status == STATUS_SIGNATURE_CHANGED]

    def status_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for m in self.matches:
            counts[m.status] = counts.get(m.status, 0) + 1
        counts[STATUS_UNMATCHED_NEW] = len(self.unmatched_new)
        return dict(sorted(counts.items()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "old": {"path": self.old.path, "assembly": self.old.assembly_name},
            "new": {"path": self.new.path, "assembly": self.new.assembly_name},
            "summary": self.status_counts(),
            "matches": [_match_to_dict(m) for m in self.matches],
            "unmatched_new": [_entity_to_dict(e) for e in self.unmatched_new],
        }


class _BlobReader:
    def __init__(self, data: Any):
        self.data = _blob_bytes(data)
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("unexpected end of signature blob")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def peek(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("unexpected end of signature blob")
        return self.data[self.pos]

    def compressed_uint(self) -> int:
        first = self.byte()
        if first & 0x80 == 0:
            return first
        if first & 0x40 == 0:
            return ((first & 0x3F) << 8) | self.byte()
        if first & 0x20 == 0:
            return (
                ((first & 0x1F) << 24)
                | (self.byte() << 16)
                | (self.byte() << 8)
                | self.byte()
            )
        raise ValueError("invalid compressed integer in signature blob")

    def skip(self, count: int) -> None:
        if self.pos + count > len(self.data):
            raise ValueError("unexpected end of signature blob")
        self.pos += count


PRIMITIVE_TYPES = {
    0x01: "void",
    0x02: "System.Boolean",
    0x03: "System.Char",
    0x04: "System.SByte",
    0x05: "System.Byte",
    0x06: "System.Int16",
    0x07: "System.UInt16",
    0x08: "System.Int32",
    0x09: "System.UInt32",
    0x0A: "System.Int64",
    0x0B: "System.UInt64",
    0x0C: "System.Single",
    0x0D: "System.Double",
    0x0E: "System.String",
    0x16: "System.TypedReference",
    0x18: "System.IntPtr",
    0x19: "System.UIntPtr",
    0x1C: "System.Object",
}

ELEMENT_TYPE_END = 0x00
ELEMENT_TYPE_VOID = 0x01
ELEMENT_TYPE_BOOLEAN = 0x02
ELEMENT_TYPE_CHAR = 0x03
ELEMENT_TYPE_I1 = 0x04
ELEMENT_TYPE_U1 = 0x05
ELEMENT_TYPE_I2 = 0x06
ELEMENT_TYPE_U2 = 0x07
ELEMENT_TYPE_I4 = 0x08
ELEMENT_TYPE_U4 = 0x09
ELEMENT_TYPE_I8 = 0x0A
ELEMENT_TYPE_U8 = 0x0B
ELEMENT_TYPE_R4 = 0x0C
ELEMENT_TYPE_R8 = 0x0D
ELEMENT_TYPE_STRING = 0x0E
ELEMENT_TYPE_PTR = 0x0F
ELEMENT_TYPE_BYREF = 0x10
ELEMENT_TYPE_VALUETYPE = 0x11
ELEMENT_TYPE_CLASS = 0x12
ELEMENT_TYPE_VAR = 0x13
ELEMENT_TYPE_ARRAY = 0x14
ELEMENT_TYPE_GENERICINST = 0x15
ELEMENT_TYPE_TYPEDBYREF = 0x16
ELEMENT_TYPE_I = 0x18
ELEMENT_TYPE_U = 0x19
ELEMENT_TYPE_FNPTR = 0x1B
ELEMENT_TYPE_OBJECT = 0x1C
ELEMENT_TYPE_SZARRAY = 0x1D
ELEMENT_TYPE_MVAR = 0x1E
ELEMENT_TYPE_CMOD_REQD = 0x1F
ELEMENT_TYPE_CMOD_OPT = 0x20
ELEMENT_TYPE_SENTINEL = 0x41
ELEMENT_TYPE_PINNED = 0x45


def _type_flag_projection(flags: int) -> Dict[str, Any]:
    visibility = flags & 0x7
    layout = flags & 0x18
    string_format = flags & 0x30000
    return {
        "visibility": visibility,
        "interface": bool(flags & 0x20),
        "abstract": bool(flags & 0x80),
        "sealed": bool(flags & 0x100),
        "special_name": bool(flags & 0x400),
        "layout": layout,
        "string_format": string_format,
        "before_field_init": bool(flags & 0x100000),
    }


def _method_flag_projection(flags: int) -> Dict[str, Any]:
    return {
        "access": flags & 0x7,
        "static": bool(flags & 0x10),
        "final": bool(flags & 0x20),
        "virtual": bool(flags & 0x40),
        "hide_by_sig": bool(flags & 0x80),
        "new_slot": bool(flags & 0x100),
        "abstract": bool(flags & 0x400),
        "special_name": bool(flags & 0x800),
        "runtime_special_name": bool(flags & 0x1000),
        "pinvoke_impl": bool(flags & 0x2000),
    }


def _method_impl_projection(flags: int) -> Dict[str, Any]:
    return {
        "code_type": flags & 0x3,
        "managed": not bool(flags & 0x4),
        "forward_ref": bool(flags & 0x10),
        "synchronized": bool(flags & 0x20),
        "no_inlining": bool(flags & 0x8),
        "preserve_sig": bool(flags & 0x80),
        "internal_call": bool(flags & 0x1000),
    }


def _field_flag_projection(flags: int) -> Dict[str, Any]:
    return {
        "access": flags & 0x7,
        "static": bool(flags & 0x10),
        "init_only": bool(flags & 0x20),
        "literal": bool(flags & 0x40),
        "not_serialized": bool(flags & 0x80),
        "special_name": bool(flags & 0x200),
        "runtime_special_name": bool(flags & 0x400),
        "has_field_marshal": bool(flags & 0x1000),
        "pinvoke_impl": bool(flags & 0x2000),
    }


def _param_flag_projection(flags: int) -> Dict[str, Any]:
    return {
        "in": bool(flags & 0x1),
        "out": bool(flags & 0x2),
        "optional": bool(flags & 0x10),
        "has_default": bool(flags & 0x1000),
        "has_field_marshal": bool(flags & 0x2000),
    }


def _property_flag_projection(flags: int) -> Dict[str, Any]:
    return {
        "special_name": bool(flags & 0x200),
        "runtime_special_name": bool(flags & 0x400),
        "has_default": bool(flags & 0x1000),
    }


def _event_flag_projection(flags: int) -> Dict[str, Any]:
    return {
        "special_name": bool(flags & 0x200),
        "runtime_special_name": bool(flags & 0x400),
    }


def _generic_param_flags(flags: int) -> Dict[str, Any]:
    return {
        "variance": flags & 0x3,
        "reference_type_constraint": bool(flags & 0x4),
        "not_nullable_value_type_constraint": bool(flags & 0x8),
        "default_constructor_constraint": bool(flags & 0x10),
    }


def _variance_name(flags: int) -> str:
    variance = flags & 0x3
    if variance == 1:
        return "covariant"
    if variance == 2:
        return "contravariant"
    return "invariant"


class _SignatureProjector:
    """Render signature blobs as stable, token-free structural strings."""

    def __init__(self, view_builder: "_ViewBuilder"):
        self.builder = view_builder
        self._type_spec_stack: List[int] = []

    def field_signature(self, blob: Any) -> Dict[str, Any]:
        reader = _BlobReader(blob)
        if reader.remaining() and reader.byte() != 0x06:
            raise ValueError("not a field signature")
        return {"type": self.type_signature(reader)}

    def method_signature(self, blob: Any, name: str = "") -> Dict[str, Any]:
        reader = _BlobReader(blob)
        if not reader.remaining():
            return {
                "generic_arity": 0,
                "has_this": False,
                "explicit_this": False,
                "calling_convention": "empty",
                "return": "void",
                "parameters": [],
            }

        first = reader.byte()
        calling_convention = first & 0x0F
        has_this = bool(first & 0x20)
        explicit_this = bool(first & 0x40)
        generic_arity = 0
        if first & 0x10:
            generic_arity = reader.compressed_uint()
        param_count = reader.compressed_uint()
        ret = self.type_signature(reader)
        params: List[Optional[str]] = []
        for _ in range(param_count):
            if reader.remaining() and reader.peek() == ELEMENT_TYPE_SENTINEL:
                # The sentinel marks the start of the vararg tail; the type
                # immediately following it is still part of the signature.
                reader.byte()
            params.append(self.type_signature(reader))
        return {
            "calling_convention": calling_convention,
            "has_this": has_this,
            "explicit_this": explicit_this,
            "generic_arity": generic_arity,
            "return": ret,
            "parameters": params,
        }

    def property_signature(self, blob: Any) -> Dict[str, Any]:
        reader = _BlobReader(blob)
        if not reader.remaining():
            return {"has_this": False, "return": "void", "parameters": []}
        first = reader.byte()
        if (first & 0x0F) != 0x08:
            raise ValueError("not a property signature")
        param_count = reader.compressed_uint()
        ret = self.type_signature(reader)
        params = []
        for _ in range(param_count):
            if reader.remaining() and reader.peek() == ELEMENT_TYPE_SENTINEL:
                reader.byte()
            params.append(self.type_signature(reader))
        return {
            "has_this": bool(first & 0x20),
            "return": ret,
            "parameters": params,
        }

    def local_signature(self, blob: Any) -> Dict[str, Any]:
        reader = _BlobReader(blob)
        if not reader.remaining():
            return {"init_only": None, "variables": []}
        if reader.byte() != 0x07:
            raise ValueError("not a local variable signature")
        count = reader.compressed_uint()
        variables: List[Dict[str, Any]] = []
        for index in range(count):
            pinned = False
            while reader.remaining() and reader.peek() == ELEMENT_TYPE_PINNED:
                reader.byte()
                pinned = True
            variables.append(
                LocalVariable(
                    index=index,
                    type=self.type_signature(reader),
                    pinned=pinned,
                ).projection()
            )
        return {"init_only": None, "variables": variables}

    def method_instantiation(self, blob: Any) -> Dict[str, Any]:
        reader = _BlobReader(blob)
        if not reader.remaining():
            return {"arguments": []}
        if reader.byte() != 0x0A:
            raise ValueError("not a generic method instantiation signature")
        count = reader.compressed_uint()
        return {"arguments": [self.type_signature(reader) for _ in range(count)]}

    def type_signature(self, reader: _BlobReader) -> str:
        element = reader.byte()
        if element in PRIMITIVE_TYPES:
            return PRIMITIVE_TYPES[element]
        if element == ELEMENT_TYPE_PTR:
            return "%s*" % self.type_signature(reader)
        if element == ELEMENT_TYPE_BYREF:
            return "%s&" % self.type_signature(reader)
        if element == ELEMENT_TYPE_VALUETYPE:
            return "valuetype %s" % self.builder.typedeforref_name(reader.compressed_uint())
        if element == ELEMENT_TYPE_CLASS:
            return "class %s" % self.builder.typedeforref_name(reader.compressed_uint())
        if element == ELEMENT_TYPE_VAR:
            return "!%d" % reader.compressed_uint()
        if element == ELEMENT_TYPE_MVAR:
            return "!!%d" % reader.compressed_uint()
        if element == ELEMENT_TYPE_ARRAY:
            item = self.type_signature(reader)
            rank = reader.compressed_uint()
            num_sizes = reader.compressed_uint()
            for _ in range(num_sizes):
                reader.compressed_uint()
            num_lo_bounds = reader.compressed_uint()
            for _ in range(num_lo_bounds):
                reader.compressed_uint()
            suffix = "[]" if rank == 1 else ("[" + "," * (rank - 1) + "]")
            return item + suffix
        if element == ELEMENT_TYPE_GENERICINST:
            kind_byte = reader.byte()
            kind = "class" if kind_byte == ELEMENT_TYPE_CLASS else "valuetype"
            base = self.builder.typedeforref_name(reader.compressed_uint())
            count = reader.compressed_uint()
            args = [self.type_signature(reader) for _ in range(count)]
            return "%s %s<%s>" % (kind, base, ", ".join(args))
        if element == ELEMENT_TYPE_SZARRAY:
            return "%s[]" % self.type_signature(reader)
        if element == ELEMENT_TYPE_FNPTR:
            signature = self.method_signature_from_reader(reader)
            params = ", ".join(signature["parameters"])
            return "fnptr %s(%s)" % (signature["return"], params)
        if element in (ELEMENT_TYPE_CMOD_REQD, ELEMENT_TYPE_CMOD_OPT):
            modifier = "modreq" if element == ELEMENT_TYPE_CMOD_REQD else "modopt"
            modifier_type = self.builder.typedeforref_name(reader.compressed_uint())
            return "%s %s(%s)" % (modifier, modifier_type, self.type_signature(reader))
        if element == ELEMENT_TYPE_PINNED:
            return "%s pinned" % self.type_signature(reader)
        if element == ELEMENT_TYPE_SENTINEL:
            return "..."
        return "unknown(0x%02X)" % element

    def method_signature_from_reader(self, reader: _BlobReader) -> Dict[str, Any]:
        first = reader.byte()
        calling_convention = first & 0x0F
        has_this = bool(first & 0x20)
        explicit_this = bool(first & 0x40)
        generic_arity = reader.compressed_uint() if first & 0x10 else 0
        param_count = reader.compressed_uint()
        ret = self.type_signature(reader)
        params = [self.type_signature(reader) for _ in range(param_count)]
        return {
            "calling_convention": calling_convention,
            "has_this": has_this,
            "explicit_this": explicit_this,
            "generic_arity": generic_arity,
            "return": ret,
            "parameters": params,
        }


class _ViewBuilder:
    def __init__(self, path: str, pe: Any):
        self.path = path
        self.pe = pe
        self.mdtables = None
        self.signature = _SignatureProjector(self)
        self.type_full_names: Dict[int, str] = {}
        self._type_full_names_in_progress: set = set()
        self.nested_to_enclosing: Dict[int, int] = {}
        self.enclosing_to_nested: Dict[int, List[int]] = {}
        self.method_by_rid: Dict[int, Entity] = {}
        self.field_by_rid: Dict[int, Entity] = {}
        self.property_by_rid: Dict[int, Entity] = {}
        self.event_by_rid: Dict[int, Entity] = {}
        self.generic_params_by_owner: Dict[Tuple[str, int], List[GenericParameter]] = {}
        self.constants_by_owner: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.method_declaring_type: Dict[int, int] = {}
        self.field_declaring_type: Dict[int, int] = {}

    def build(self) -> MetadataView:
        if self.pe.net is None or self.pe.net.mdtables is None:
            raise CorrelationError("%s does not contain CLR metadata tables" % self.path)
        self.mdtables = self.pe.net.mdtables
        self._index_nested_types()
        self._index_constants()
        self._index_member_owners()

        assembly_name = ""
        module_name = ""
        assembly_table = getattr(self.mdtables, "Assembly", None)
        if assembly_table is not None and len(assembly_table):
            assembly_name = str(assembly_table[0].Name or "")
        module_table = getattr(self.mdtables, "Module", None)
        if module_table is not None and len(module_table):
            module_name = str(module_table[0].Name or "")

        # Methods and fields are built first because type projections contain
        # their structural signatures.  No token from another assembly is used.
        method_entities = self._build_methods()
        field_entities = self._build_fields()
        property_entities = self._build_properties()
        event_entities = self._build_events()
        type_entities = self._build_types(method_entities, field_entities, property_entities, event_entities)
        self._build_generic_parameters()
        self._refresh_entity_projections(
            type_entities, method_entities, field_entities, property_entities, event_entities
        )

        entities: List[Entity] = []
        entities.extend(type_entities)
        entities.extend(method_entities)
        entities.extend(field_entities)
        entities.extend(property_entities)
        entities.extend(event_entities)
        entities.sort(key=lambda e: (e.token, e.kind, e.identity))
        return MetadataView(
            path=self.path,
            assembly_name=assembly_name,
            module_name=module_name,
            entities=entities,
            pe=self.pe,
            metadata=self.pe.net,
            type_full_names=dict(self.type_full_names),
            method_by_rid={rid: entity for rid, entity in self.method_by_rid.items()},
        )

    def _index_nested_types(self) -> None:
        table = getattr(self.mdtables, "NestedClass", None)
        if table is None:
            return
        for row in table:
            if row is None:
                continue
            nested = getattr(row.NestedClass, "row_index", None)
            enclosing = getattr(row.EnclosingClass, "row_index", None)
            if nested is None or enclosing is None:
                continue
            self.nested_to_enclosing[nested] = enclosing
            self.enclosing_to_nested.setdefault(enclosing, []).append(nested)
        for values in self.enclosing_to_nested.values():
            values.sort()

    def _index_member_owners(self) -> None:
        table = getattr(self.mdtables, "TypeDef", None)
        if table is None:
            return
        for type_rid, row in enumerate(table, start=1):
            if row is None:
                continue
            try:
                fields = row.FieldList
                methods = row.MethodList
            except (AttributeError, TypeError, ValueError):
                continue
            for index in fields:
                rid = getattr(index, "row_index", None)
                if rid:
                    self.field_declaring_type[rid] = type_rid
            for index in methods:
                rid = getattr(index, "row_index", None)
                if rid:
                    self.method_declaring_type[rid] = type_rid

    def _index_constants(self) -> None:
        table = getattr(self.mdtables, "Constant", None)
        if table is None:
            return
        for row in table:
            if row is None:
                continue
            parent = getattr(row, "Parent", None)
            if parent is None or getattr(parent, "table", None) is None:
                continue
            value = _blob_bytes(getattr(row, "Value", None))
            self.constants_by_owner[(parent.table.name, parent.row_index)] = {
                "type": int(getattr(row, "Type", 0)),
                "value": value.hex(),
            }

    def _type_row(self, rid: int) -> Any:
        table = getattr(self.mdtables, "TypeDef", None)
        if table is None:
            return None
        return table.get_with_row_index(rid)

    def _method_row(self, rid: int) -> Any:
        table = getattr(self.mdtables, "MethodDef", None)
        if table is None:
            return None
        return table.get_with_row_index(rid)

    def _type_ref_row(self, rid: int) -> Any:
        table = getattr(self.mdtables, "TypeRef", None)
        if table is None:
            return None
        return table.get_with_row_index(rid)

    def _type_spec_row(self, rid: int) -> Any:
        table = getattr(self.mdtables, "TypeSpec", None)
        if table is None:
            return None
        return table.get_with_row_index(rid)

    def type_def_name(self, rid: int) -> str:
        """Return a declaring-path name such as ``Ns.Outer+Inner``."""

        cached = self.type_full_names.get(rid)
        if cached is not None:
            return cached
        if rid in self._type_full_names_in_progress:
            return "<cycle:type:%d>" % rid
        row = self._type_row(rid)
        if row is None:
            return "<missing:type:%d>" % rid
        self._type_full_names_in_progress.add(rid)
        try:
            name = str(row.TypeName or "")
            if rid in self.nested_to_enclosing:
                name = "%s+%s" % (self.type_def_name(self.nested_to_enclosing[rid]), name)
            else:
                namespace = str(row.TypeNamespace or "")
                if namespace:
                    name = "%s.%s" % (namespace, name)
            self.type_full_names[rid] = name
            return name
        finally:
            self._type_full_names_in_progress.discard(rid)

    def type_ref_name(self, rid: int, depth: int = 0) -> str:
        if depth > 32:
            return "<cycle:typeref:%d>" % rid
        row = self._type_ref_row(rid)
        if row is None:
            return "<missing:typeref:%d>" % rid
        name = str(row.TypeName or "")
        scope = getattr(row, "ResolutionScope", None)
        if scope is not None and getattr(scope, "table", None) is not None:
            if scope.table.name == "TypeRef":
                return "%s+%s" % (self.type_ref_name(scope.row_index, depth + 1), name)
            if scope.table.name == "AssemblyRef":
                # Assembly simple names are enough for structural comparison;
                # assembly version/build numbers change routinely on recompiles.
                assembly = scope.row
                assembly_name = str(getattr(assembly, "Name", "") or "")
                namespace = str(row.TypeNamespace or "")
                full = "%s.%s" % (namespace, name) if namespace else name
                return "%s [%s]" % (full, assembly_name) if assembly_name else full
        namespace = str(row.TypeNamespace or "")
        return "%s.%s" % (namespace, name) if namespace else name

    def type_spec_name(self, rid: int) -> str:
        if rid in self.signature._type_spec_stack:
            return "<cycle:typespec:%d>" % rid
        row = self._type_spec_row(rid)
        if row is None:
            return "<missing:typespec:%d>" % rid
        self.signature._type_spec_stack.append(rid)
        try:
            blob = _blob_bytes(getattr(row, "Signature", b""))
            if not blob:
                return "<empty:typespec:%d>" % rid
            return self.signature.type_signature(_BlobReader(blob))
        except (ValueError, IndexError):
            return "<invalid:typespec:%d>" % rid
        finally:
            self.signature._type_spec_stack.pop()

    def typedeforref_name(self, value: int) -> str:
        tag = value & 0x3
        rid = value >> 2
        if tag == 0:
            return self.type_def_name(rid)
        if tag == 1:
            return self.type_ref_name(rid)
        if tag == 2:
            return self.type_spec_name(rid)
        return "<invalid:typedeforref:%d>" % value

    def coded_index_name(self, index: Any) -> Optional[str]:
        if index is None:
            return None
        table = getattr(index, "table", None)
        if table is None:
            return None
        if table.name == "TypeDef":
            return self.type_def_name(index.row_index)
        if table.name == "TypeRef":
            return self.type_ref_name(index.row_index)
        if table.name == "TypeSpec":
            return self.type_spec_name(index.row_index)
        return None

    def _type_namespace(self, rid: int) -> str:
        current = rid
        seen = set()
        while current in self.nested_to_enclosing and current not in seen:
            seen.add(current)
            current = self.nested_to_enclosing[current]
        row = self._type_row(current)
        if row is None:
            return ""
        return str(row.TypeNamespace or "")

    def _type_declaring_name(self, rid: int) -> Optional[str]:
        enclosing = self.nested_to_enclosing.get(rid)
        if enclosing is None:
            return None
        return self.type_def_name(enclosing)

    def _method_identity(self, declaring_name: str, name: str, generic_arity: int) -> str:
        # Generic arity is part of the signature, not the identity.  Keeping it
        # out of the key means an arity change is reported as a signature
        # change instead of looking like a brand new method.
        return "method:%s::%s" % (declaring_name, name)

    def _safe_method_signature(self, blob: bytes, name: str) -> Dict[str, Any]:
        try:
            return self.signature.method_signature(blob, name)
        except (ValueError, IndexError) as e:
            logger.warning("failed to parse method signature for %s: %s", name, e)
            return {
                "calling_convention": "invalid",
                "has_this": False,
                "explicit_this": False,
                "generic_arity": 0,
                "return": "<invalid>",
                "parameters": [],
            }

    def _build_methods(self) -> List[Entity]:
        table = getattr(self.mdtables, "MethodDef", None)
        if table is None:
            return []
        entities: List[Entity] = []
        for rid, row in enumerate(table, start=1):
            if row is None:
                continue
            declaring_rid = self._declaring_type_for_method(rid)
            declaring_name = self.type_def_name(declaring_rid) if declaring_rid else "<global>"
            name = str(row.Name or "")
            signature = self._safe_method_signature(getattr(row, "Signature", b"") or b"", name)
            generic_arity = int(signature.get("generic_arity", 0))
            identity = self._method_identity(declaring_name, name, generic_arity)
            display_name = "%s#%d" % (identity, generic_arity)
            locals_projection = self._local_declarations(row)
            flags = int(getattr(row.struct, "Flags", 0))
            impl_flags = int(getattr(row.struct, "ImplFlags", 0))
            params = self._method_parameters(row)
            token = make_token(0x06, rid)
            projection = {
                "kind": "method",
                "declaring_type": declaring_name,
                "name": name,
                "flags": _method_flag_projection(flags),
                "impl_flags": _method_impl_projection(impl_flags),
                "signature": signature,
                "parameters": params,
                "locals": locals_projection,
                "generic_parameters": [],
            }
            namespace = self._type_namespace(declaring_rid) if declaring_rid else ""
            semantic = {
                "kind": "method",
                "declaring_type": _strip_namespace(declaring_name, namespace),
                "name": name,
                "signature": signature,
                "parameters": [{"sequence": p["sequence"], "type": p["type"]} for p in params],
                "locals": locals_projection,
                "generic_parameters": [],
            }
            entity = Entity(
                kind="method",
                token=token,
                rid=rid,
                name=name,
                namespace=self._type_namespace(declaring_rid) if declaring_rid else "",
                declaring_type=declaring_name if declaring_rid else None,
                full_name=display_name,
                identity=identity,
                projection=projection,
                semantic_projection=semantic,
                signature=signature,
                locals=locals_projection,
                constraints=[],
            )
            self.method_by_rid[rid] = entity
            entities.append(entity)
        return entities

    def _declaring_type_for_method(self, method_rid: int) -> Optional[int]:
        return self.method_declaring_type.get(method_rid)

    def _declaring_type_for_field(self, field_rid: int) -> Optional[int]:
        return self.field_declaring_type.get(field_rid)

    def _method_parameters(self, row: Any) -> List[Dict[str, Any]]:
        params: List[Dict[str, Any]] = []
        try:
            indexes = row.ParamList
        except (AttributeError, TypeError, ValueError):
            return params
        for index in indexes:
            param = getattr(index, "row", None)
            if param is None:
                continue
            flags = int(getattr(param.struct, "Flags", 0))
            sequence = int(getattr(param, "Sequence", 0))
            params.append(
                {
                    "sequence": sequence,
                    "name": str(getattr(param, "Name", "") or ""),
                    "type": self._param_signature_type(row, sequence),
                    "flags": _param_flag_projection(flags),
                    "constant": self.constants_by_owner.get(("Param", index.row_index)),
                }
            )
        params.sort(key=lambda p: p["sequence"])
        return params

    def _param_signature_type(self, method_row: Any, sequence: int) -> str:
        if sequence <= 0:
            return ""
        try:
            signature = self.signature.method_signature(
                getattr(method_row, "Signature", b"") or b"",
                str(getattr(method_row, "Name", "") or ""),
            )
            return signature["parameters"][sequence - 1]
        except (ValueError, IndexError):
            return "<invalid>"

    def _local_declarations(self, method_row: Any) -> Optional[Dict[str, Any]]:
        rva = int(getattr(method_row, "Rva", 0) or 0)
        if not rva:
            return {"init_only": None, "variables": []}
        try:
            header = self.pe.get_data(rva, 12)
        except Exception as e:
            logger.warning("failed to read method body at RVA 0x%x: %s", rva, e)
            return None
        if not header:
            return None
        first = header[0]
        header_kind = first & 0x3
        if header_kind == 0x2:
            return {"init_only": None, "variables": []}
        if header_kind != 0x3 or len(header) < 12:
            return None
        flags = _struct.unpack_from("<H", header, 0)[0]
        header_size = (flags >> 12) * 4
        if header_size < 12:
            header_size = 12
        local_token = _struct.unpack_from("<I", header, 8)[0]
        init_only = bool(flags & 0x10)
        if local_token == 0:
            return {"init_only": init_only, "variables": []}
        table_id = (local_token >> 24) & 0xFF
        rid = local_token & 0x00FFFFFF
        if table_id != 0x11:
            return {"init_only": init_only, "variables": [], "token": token_str(local_token)}
        table = getattr(self.mdtables, "StandAloneSig", None)
        if table is None:
            return None
        local_row = table.get_with_row_index(rid)
        if local_row is None:
            return None
        try:
            result = self.signature.local_signature(getattr(local_row, "Signature", b""))
        except (ValueError, IndexError) as e:
            logger.warning("failed to parse local signature for %s: %s", method_row.Name, e)
            return None
        if not result.get("variables"):
            result["init_only"] = None
        else:
            result["init_only"] = init_only
        return result

    def _build_fields(self) -> List[Entity]:
        table = getattr(self.mdtables, "Field", None)
        if table is None:
            return []
        entities: List[Entity] = []
        for rid, row in enumerate(table, start=1):
            if row is None:
                continue
            declaring_rid = self._declaring_type_for_field(rid)
            declaring_name = self.type_def_name(declaring_rid) if declaring_rid else "<global>"
            name = str(row.Name or "")
            try:
                signature = self.signature.field_signature(getattr(row, "Signature", b"") or b"")
            except (ValueError, IndexError) as e:
                logger.warning("failed to parse field signature for %s: %s", name, e)
                signature = {"type": "<invalid>"}
            flags = int(getattr(row.struct, "Flags", 0))
            identity = "field:%s::%s" % (declaring_name, name)
            token = make_token(0x04, rid)
            constant = self.constants_by_owner.get(("Field", rid))
            projection = {
                "kind": "field",
                "declaring_type": declaring_name,
                "name": name,
                "flags": _field_flag_projection(flags),
                "signature": signature,
                "constant": constant,
            }
            semantic = {
                "kind": "field",
                "declaring_type": _strip_namespace(
                    declaring_name, self._type_namespace(declaring_rid) if declaring_rid else ""
                ),
                "name": name,
                "signature": signature,
                "constant": constant,
            }
            entity = Entity(
                kind="field",
                token=token,
                rid=rid,
                name=name,
                namespace=self._type_namespace(declaring_rid) if declaring_rid else "",
                declaring_type=declaring_name if declaring_rid else None,
                full_name=identity,
                identity=identity,
                projection=projection,
                semantic_projection=semantic,
                signature=signature,
                locals=None,
                constraints=[],
            )
            self.field_by_rid[rid] = entity
            entities.append(entity)
        return entities

    def _build_properties(self) -> List[Entity]:
        table = getattr(self.mdtables, "Property", None)
        if table is None:
            return []
        owner_by_property = self._property_owners()
        accessors = self._method_semantics_by_association()
        entities: List[Entity] = []
        for rid, row in enumerate(table, start=1):
            if row is None:
                continue
            declaring_rid = owner_by_property.get(rid)
            declaring_name = self.type_def_name(declaring_rid) if declaring_rid else "<global>"
            name = str(row.Name or "")
            try:
                signature = self.signature.property_signature(getattr(row, "Type", b"") or b"")
            except (ValueError, IndexError):
                signature = {"has_this": False, "return": "<invalid>", "parameters": []}
            flags = int(getattr(row.struct, "Flags", 0))
            identity = "property:%s::%s" % (declaring_name, name)
            token = make_token(0x17, rid)
            projection = {
                "kind": "property",
                "declaring_type": declaring_name,
                "name": name,
                "flags": _property_flag_projection(flags),
                "signature": signature,
                "accessors": accessors.get(("Property", rid), []),
                "constant": self.constants_by_owner.get(("Property", rid)),
            }
            semantic = {
                "kind": "property",
                "declaring_type": _strip_namespace(
                    declaring_name, self._type_namespace(declaring_rid) if declaring_rid else ""
                ),
                "name": name,
                "signature": signature,
                "accessors": accessors.get(("Property", rid), []),
                "constant": self.constants_by_owner.get(("Property", rid)),
            }
            entity = Entity(
                kind="property",
                token=token,
                rid=rid,
                name=name,
                namespace=self._type_namespace(declaring_rid) if declaring_rid else "",
                declaring_type=declaring_name if declaring_rid else None,
                full_name=identity,
                identity=identity,
                projection=projection,
                semantic_projection=semantic,
                signature=signature,
                locals=None,
                constraints=[],
            )
            self.property_by_rid[rid] = entity
            entities.append(entity)
        return entities

    def _build_events(self) -> List[Entity]:
        table = getattr(self.mdtables, "Event", None)
        if table is None:
            return []
        owner_by_event = self._event_owners()
        accessors = self._method_semantics_by_association()
        entities: List[Entity] = []
        for rid, row in enumerate(table, start=1):
            if row is None:
                continue
            declaring_rid = owner_by_event.get(rid)
            declaring_name = self.type_def_name(declaring_rid) if declaring_rid else "<global>"
            name = str(row.Name or "")
            event_type = self.coded_index_name(getattr(row, "EventType", None))
            flags = int(getattr(row.struct, "EventFlags", 0))
            identity = "event:%s::%s" % (declaring_name, name)
            token = make_token(0x14, rid)
            projection = {
                "kind": "event",
                "declaring_type": declaring_name,
                "name": name,
                "flags": _event_flag_projection(flags),
                "event_type": event_type,
                "accessors": accessors.get(("Event", rid), []),
            }
            semantic = dict(projection)
            semantic["declaring_type"] = _strip_namespace(
                declaring_name, self._type_namespace(declaring_rid) if declaring_rid else ""
            )
            entity = Entity(
                kind="event",
                token=token,
                rid=rid,
                name=name,
                namespace=self._type_namespace(declaring_rid) if declaring_rid else "",
                declaring_type=declaring_name if declaring_rid else None,
                full_name=identity,
                identity=identity,
                projection=projection,
                semantic_projection=semantic,
                signature={"event_type": event_type},
                locals=None,
                constraints=[],
            )
            self.event_by_rid[rid] = entity
            entities.append(entity)
        return entities

    def _property_owners(self) -> Dict[int, int]:
        result: Dict[int, int] = {}
        table = getattr(self.mdtables, "PropertyMap", None)
        if table is None:
            return result
        for row in table:
            if row is None:
                continue
            parent = getattr(row, "Parent", None)
            if parent is None:
                continue
            try:
                properties = row.PropertyList
            except (AttributeError, TypeError, ValueError):
                continue
            for index in properties:
                result[getattr(index, "row_index", 0)] = getattr(parent, "row_index", 0)
        return result

    def _event_owners(self) -> Dict[int, int]:
        result: Dict[int, int] = {}
        table = getattr(self.mdtables, "EventMap", None)
        if table is None:
            return result
        for row in table:
            if row is None:
                continue
            parent = getattr(row, "Parent", None)
            if parent is None:
                continue
            try:
                events = row.EventList
            except (AttributeError, TypeError, ValueError):
                continue
            for index in events:
                result[getattr(index, "row_index", 0)] = getattr(parent, "row_index", 0)
        return result

    def _method_semantics_by_association(self) -> Dict[Tuple[str, int], List[Dict[str, Any]]]:
        result: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        table = getattr(self.mdtables, "MethodSemantics", None)
        if table is None:
            return result
        semantics_names = {
            0x0001: "setter",
            0x0002: "getter",
            0x0004: "other",
            0x0008: "add_on",
            0x0010: "remove_on",
            0x0020: "fire",
        }
        for row in table:
            if row is None:
                continue
            association = getattr(row, "Association", None)
            if association is None or getattr(association, "table", None) is None:
                continue
            method = getattr(row, "Method", None)
            if method is None:
                continue
            raw = int(getattr(row.struct, "Semantics", 0))
            method_entity = self.method_by_rid.get(getattr(method, "row_index", 0))
            result.setdefault((association.table.name, association.row_index), []).append(
                {
                    "semantics": semantics_names.get(raw, "0x%04X" % raw),
                    "method": method_entity.identity if method_entity else "<missing>",
                    "method_signature": method_entity.signature if method_entity else None,
                }
            )
        for values in result.values():
            values.sort(key=lambda item: (item["semantics"], item["method"]))
        return result

    def _build_types(
        self,
        methods: List[Entity],
        fields: List[Entity],
        properties: List[Entity],
        events: List[Entity],
    ) -> List[Entity]:
        table = getattr(self.mdtables, "TypeDef", None)
        if table is None:
            return []
        methods_by_declaring: Dict[str, List[Entity]] = {}
        for method in methods:
            if method.declaring_type:
                methods_by_declaring.setdefault(method.declaring_type, []).append(method)
        fields_by_declaring: Dict[str, List[Entity]] = {}
        for field_entity in fields:
            if field_entity.declaring_type:
                fields_by_declaring.setdefault(field_entity.declaring_type, []).append(field_entity)
        properties_by_declaring: Dict[str, List[Entity]] = {}
        for property_entity in properties:
            if property_entity.declaring_type:
                properties_by_declaring.setdefault(property_entity.declaring_type, []).append(property_entity)
        events_by_declaring: Dict[str, List[Entity]] = {}
        for event_entity in events:
            if event_entity.declaring_type:
                events_by_declaring.setdefault(event_entity.declaring_type, []).append(event_entity)

        layout_by_type = {}
        layout_table = getattr(self.mdtables, "ClassLayout", None)
        if layout_table is not None:
            for row in layout_table:
                if row is None or getattr(row, "Parent", None) is None:
                    continue
                layout_by_type[getattr(row.Parent, "row_index", 0)] = {
                    "packing_size": int(getattr(row, "PackingSize", 0) or 0),
                    "class_size": int(getattr(row, "ClassSize", 0) or 0),
                }

        interfaces_by_type: Dict[int, List[str]] = {}
        interface_table = getattr(self.mdtables, "InterfaceImpl", None)
        if interface_table is not None:
            for row in interface_table:
                if row is None:
                    continue
                class_rid = getattr(getattr(row, "Class", None), "row_index", None)
                interface_name = self.coded_index_name(getattr(row, "Interface", None))
                if class_rid is not None and interface_name:
                    interfaces_by_type.setdefault(class_rid, []).append(interface_name)
        for values in interfaces_by_type.values():
            values.sort()

        entities: List[Entity] = []
        for rid, row in enumerate(table, start=1):
            if row is None:
                continue
            full_name = self.type_def_name(rid)
            name = str(row.TypeName or "")
            namespace = self._type_namespace(rid)
            flags = int(getattr(row.struct, "Flags", 0))
            base_type = self.coded_index_name(getattr(row, "Extends", None))
            nested_types = sorted(self.type_def_name(child) for child in self.enclosing_to_nested.get(rid, []))
            layout = layout_by_type.get(rid)
            interfaces = interfaces_by_type.get(rid, [])

            method_entries = sorted(
                (m.projection for m in methods_by_declaring.get(full_name, [])),
                key=lambda item: (item["name"], _stable_json(item["signature"])),
            )
            method_semantics = sorted(
                (m.semantic_projection for m in methods_by_declaring.get(full_name, [])),
                key=lambda item: (item["name"], _stable_json(item["signature"])),
            )
            field_entries = sorted(
                (f.projection for f in fields_by_declaring.get(full_name, [])),
                key=lambda item: item["name"],
            )
            field_semantics = sorted(
                (f.semantic_projection for f in fields_by_declaring.get(full_name, [])),
                key=lambda item: item["name"],
            )
            property_entries = sorted(
                (p.projection for p in properties_by_declaring.get(full_name, [])),
                key=lambda item: item["name"],
            )
            property_semantics = sorted(
                (p.semantic_projection for p in properties_by_declaring.get(full_name, [])),
                key=lambda item: item["name"],
            )
            event_entries = sorted(
                (e.projection for e in events_by_declaring.get(full_name, [])),
                key=lambda item: item["name"],
            )
            event_semantics = sorted(
                (e.semantic_projection for e in events_by_declaring.get(full_name, [])),
                key=lambda item: item["name"],
            )

            signature = {
                "base_type": base_type,
                "interfaces": interfaces,
                "generic_arity": None,  # filled from generic parameters below
                "layout": layout,
            }
            projection = {
                "kind": "type",
                "namespace": namespace,
                "name": name,
                "full_name": full_name,
                "declaring_type": self._type_declaring_name(rid),
                "flags": _type_flag_projection(flags),
                "signature": signature,
                "generic_parameters": [],
                "fields": field_entries,
                "methods": method_entries,
                "properties": property_entries,
                "events": event_entries,
                "nested_types": nested_types,
                "layout": layout,
            }
            semantic = {
                "kind": "type",
                "full_name": _strip_namespace(full_name, namespace),
                "signature": signature,
                "generic_parameters": [],
                "fields": field_semantics,
                "methods": method_semantics,
                "properties": property_semantics,
                "events": event_semantics,
                "nested_types": [
                    _strip_namespace(name, namespace) for name in nested_types
                ],
            }
            identity = "type:%s" % full_name
            entity = Entity(
                kind="type",
                token=make_token(0x02, rid),
                rid=rid,
                name=name,
                namespace=namespace,
                declaring_type=self._type_declaring_name(rid),
                full_name=full_name,
                identity=identity,
                projection=projection,
                semantic_projection=semantic,
                signature=signature,
                locals=None,
                constraints=[],
            )
            entities.append(entity)
        return entities

    def _build_generic_parameters(self) -> None:
        table = getattr(self.mdtables, "GenericParam", None)
        if table is None:
            return
        constraints_by_param: Dict[int, List[str]] = {}
        constraint_table = getattr(self.mdtables, "GenericParamConstraint", None)
        if constraint_table is not None:
            for row in constraint_table:
                if row is None:
                    continue
                owner = getattr(row, "Owner", None)
                if owner is None:
                    continue
                constraint = self.coded_index_name(getattr(row, "Constraint", None))
                if constraint:
                    constraints_by_param.setdefault(owner.row_index, []).append(constraint)

        for rid, row in enumerate(table, start=1):
            if row is None:
                continue
            owner = getattr(row, "Owner", None)
            if owner is None or getattr(owner, "table", None) is None:
                continue
            flags = int(getattr(row.struct, "Flags", 0))
            parameter = GenericParameter(
                number=int(getattr(row, "Number", 0)),
                name=str(getattr(row, "Name", "") or ""),
                flags=flags,
                variance=_variance_name(flags),
                constraints=sorted(constraints_by_param.get(rid, [])),
            )
            key = (owner.table.name, owner.row_index)
            self.generic_params_by_owner.setdefault(key, []).append(parameter)
        for values in self.generic_params_by_owner.values():
            values.sort(key=lambda p: (p.number, p.name))

    def _generic_params_for_type(self, type_rid: int) -> List[Dict[str, Any]]:
        return [
            parameter.projection()
            for parameter in self.generic_params_by_owner.get(("TypeDef", type_rid), [])
        ]

    def _generic_params_for_method(self, method_rid: int) -> List[Dict[str, Any]]:
        return [
            parameter.projection()
            for parameter in self.generic_params_by_owner.get(("MethodDef", method_rid), [])
        ]

    def _refresh_entity_projections(
        self,
        types: List[Entity],
        methods: List[Entity],
        fields: List[Entity],
        properties: List[Entity],
        events: List[Entity],
    ) -> None:
        for method in methods:
            generic_parameters = self._generic_params_for_method(method.rid)
            method.projection["generic_parameters"] = generic_parameters
            method.semantic_projection["generic_parameters"] = generic_parameters
            method.constraints = generic_parameters

        for type_entity in types:
            generic_parameters = self._generic_params_for_type(type_entity.rid)
            type_entity.projection["generic_parameters"] = generic_parameters
            type_entity.semantic_projection["generic_parameters"] = generic_parameters
            type_entity.constraints = generic_parameters
            generic_arity = len(generic_parameters)
            type_entity.signature["generic_arity"] = generic_arity
            type_entity.projection["signature"]["generic_arity"] = generic_arity
            type_entity.semantic_projection["signature"]["generic_arity"] = generic_arity
            # Keep nested member projections in sync with the fully populated
            # method/field/property/event dictionaries.
            type_entity.projection["methods"] = sorted(
                (
                    m.projection
                    for m in methods
                    if m.declaring_type == type_entity.full_name
                ),
                key=lambda item: (item["name"], _stable_json(item["signature"])),
            )
            type_entity.semantic_projection["methods"] = sorted(
                (
                    m.semantic_projection
                    for m in methods
                    if m.declaring_type == type_entity.full_name
                ),
                key=lambda item: (item["name"], _stable_json(item["signature"])),
            )


def load_metadata(
    path_or_pe: Union[str, os.PathLike, Any],
    *,
    lazy_load: bool = False,
) -> MetadataView:
    """Project a .NET PE file into a token-independent metadata view."""

    if hasattr(path_or_pe, "net") and hasattr(path_or_pe, "get_data"):
        pe = path_or_pe
        path = str(getattr(pe, "filename", "<dnPE>"))
    else:
        path = os.fspath(path_or_pe)
        try:
            pe = dnfile.dnPE(path, fast_load=False, clr_lazy_load=lazy_load)
        except Exception as e:
            raise CorrelationError("failed to parse %s: %s" % (path, e)) from e
    if getattr(pe, "net", None) is None:
        raise CorrelationError("%s is not a managed .NET assembly" % path)
    return _ViewBuilder(path, pe).build()


def extract_metadata(path: Union[str, os.PathLike, Any], **kwargs: Any) -> MetadataView:
    """Alias for :func:`load_metadata`."""

    return load_metadata(path, **kwargs)


def _entity_brief(entity: Entity) -> Dict[str, Any]:
    return {
        "kind": entity.kind,
        "token": token_str(entity.token),
        "name": entity.name,
        "namespace": entity.namespace,
        "declaring_type": entity.declaring_type,
        "full_name": entity.full_name,
    }


def _entity_to_dict(entity: Entity) -> Dict[str, Any]:
    value = _entity_brief(entity)
    value.update(
        {
            "identity": entity.identity,
            "projection_key": entity.projection_key,
            "semantic_key": entity.semantic_key,
            "projection": entity.projection,
        }
    )
    return value


def _candidate_to_dict(candidate: Candidate) -> Dict[str, Any]:
    value = _entity_brief(candidate.target)
    value.update(
        {
            "score": round(candidate.score, 6),
            "token_equal": candidate.token_equal,
            "semantic_equal": candidate.semantic_equal,
            "projection_equal": candidate.projection_equal,
            "comparisons": candidate.comparisons,
        }
    )
    return value


def _match_to_dict(match: Match) -> Dict[str, Any]:
    value = {
        "group_id": match.group_id,
        "source": _entity_brief(match.source),
        "status": match.status,
        "score": round(match.score, 6),
        "review_required": match.review_required,
        "comparisons": match.comparisons,
        "notes": match.notes,
        "target": _entity_brief(match.target) if match.target else None,
        "candidates": [_candidate_to_dict(c) for c in match.candidates],
    }
    return value


def _compare(
    source: Entity,
    target: Entity,
) -> Candidate:
    namespace_equal = source.namespace_key == target.namespace_key
    declaring_equal = source.declaring_type == target.declaring_type
    signature_equal = _stable_json(source.signature) == _stable_json(target.signature)
    semantic_equal = source.semantic_key == target.semantic_key
    projection_equal = source.projection_key == target.projection_key
    token_equal = source.token == target.token

    if source.locals is None or target.locals is None:
        locals_equal: Optional[bool] = None
    else:
        locals_equal = _stable_json(source.locals) == _stable_json(target.locals)

    constraints_equal = _stable_json(source.constraints) == _stable_json(target.constraints)
    comparisons = {
        "namespace_equal": namespace_equal,
        "declaring_type_equal": declaring_equal,
        "signature_equal": signature_equal,
        "locals_equal": locals_equal,
        "generic_constraints_equal": constraints_equal,
        "semantic_equal": semantic_equal,
        "projection_equal": projection_equal,
        "token_equal": token_equal,
    }

    if source.kind == "method":
        components = [
            (0.05, namespace_equal),
            (0.10, declaring_equal),
            (0.30, signature_equal),
            (0.20, locals_equal),
            (0.10, constraints_equal),
            (0.25, projection_equal),
        ]
    elif source.kind == "type":
        components = [
            (0.10, namespace_equal),
            (0.20, signature_equal),
            (0.10, constraints_equal),
            (0.60, projection_equal),
        ]
    elif source.kind in ("property", "event"):
        components = [
            (0.10, namespace_equal),
            (0.30, declaring_equal),
            (0.25, signature_equal),
            (0.35, projection_equal),
        ]
    else:
        components = [
            (0.10, namespace_equal),
            (0.30, declaring_equal),
            (0.25, signature_equal),
            (0.35, projection_equal),
        ]
    available_weight = sum(weight for weight, value in components if value is not None)
    score = 0.0
    for weight, value in components:
        if value is None:
            continue
        if value:
            score += weight
    if available_weight:
        score /= available_weight
    return Candidate(
        target=target,
        score=score,
        comparisons=comparisons,
        token_equal=token_equal,
        semantic_equal=semantic_equal,
        projection_equal=projection_equal,
    )


def _candidate_rank(candidate: Candidate) -> Tuple[float, bool, bool, bool]:
    return (
        candidate.score,
        candidate.projection_equal,
        candidate.semantic_equal,
        # A metadata token is deliberately not part of the ranking.  If two
        # candidates are otherwise equivalent, a preserved token does not make
        # one of them more trustworthy.
        False,
    )


def _classify(match: Match) -> str:
    candidate = match.candidates[0]
    if candidate.projection_equal:
        return STATUS_UNCHANGED if candidate.token_equal else STATUS_RENUMBERED
    if candidate.semantic_equal:
        return STATUS_METADATA_CHANGED
    return STATUS_SIGNATURE_CHANGED


def _evidence_notes(candidate: Candidate) -> List[str]:
    notes: List[str] = []
    comparisons = candidate.comparisons
    for key, label in (
        ("namespace_equal", "namespace"),
        ("declaring_type_equal", "declaring type"),
        ("signature_equal", "signature"),
        ("locals_equal", "local declarations"),
        ("generic_constraints_equal", "generic constraints"),
        ("projection_equal", "structural projection"),
        ("token_equal", "metadata token"),
    ):
        value = comparisons.get(key)
        if value is None:
            notes.append("%s=unknown" % label)
        elif value:
            notes.append("%s=equal" % label)
        else:
            notes.append("%s=changed" % label)
    return notes


def correlate(
    old: Union[str, os.PathLike, MetadataView, Any],
    new: Union[str, os.PathLike, MetadataView, Any],
    *,
    include_module_type: bool = False,
    max_candidates: int = 8,
) -> CorrelationResult:
    """Correlate two assemblies and return token-independent entity matches."""

    old_view = old if isinstance(old, MetadataView) else load_metadata(old)
    new_view = new if isinstance(new, MetadataView) else load_metadata(new)
    max_candidates = max(1, int(max_candidates))

    def visible(entity: Entity) -> bool:
        return include_module_type or (
            entity.full_name != "<Module>" and entity.declaring_type != "<Module>"
        )

    old_entities = [e for e in old_view.entities if visible(e)]
    new_entities = [e for e in new_view.entities if visible(e)]

    targets_by_identity: Dict[str, List[Entity]] = {}
    targets_by_loose_identity: Dict[str, List[Entity]] = {}
    for entity in new_entities:
        targets_by_identity.setdefault(entity.identity, []).append(entity)
        targets_by_loose_identity.setdefault(entity.loose_identity, []).append(entity)

    matches: List[Match] = []
    ambiguous_group_ids: Dict[str, str] = {}
    target_claims: Dict[Tuple[str, int], List[Match]] = {}

    for source in old_entities:
        targets = targets_by_identity.get(source.identity, [])
        if not targets:
            # A namespace move still leaves a comparable entity; namespace is
            # then treated as evidence, not as an identity boundary.
            targets = targets_by_loose_identity.get(source.loose_identity, [])
        if not targets:
            matches.append(
                Match(
                    source=source,
                    status=STATUS_UNMATCHED_OLD,
                    target=None,
                    score=0.0,
                    group_id="",
                    candidates=[],
                    comparisons={},
                    notes=["no candidate with the same kind/name/scope"],
                )
            )
            continue

        candidates = sorted(
            (_compare(source, target) for target in targets),
            key=_candidate_rank,
            reverse=True,
        )
        top_score = candidates[0].score
        tied = [
            candidate for candidate in candidates
            if abs(candidate.score - top_score) <= 1e-9
        ]

        # Multiple indistinguishable same-name declarations are deliberately
        # left as a multi-select.  Choosing one would fabricate evidence.
        if len(tied) > 1:
            group_key = "%s|%s" % (source.kind, source.identity)
            group_id = ambiguous_group_ids.get(group_key)
            if group_id is None:
                group_id = "AMB-%04d" % (len(ambiguous_group_ids) + 1)
                ambiguous_group_ids[group_key] = group_id
            chosen = tied[:max_candidates]
            match = Match(
                source=source,
                status=STATUS_AMBIGUOUS,
                target=None,
                score=top_score,
                group_id=group_id,
                candidates=chosen,
                comparisons=chosen[0].comparisons,
                notes=[
                    "%d candidates share the best evidence; manual review required"
                    % len(tied)
                ] + _evidence_notes(chosen[0]),
            )
            matches.append(match)
            continue

        candidate = candidates[0]
        status = _classify(
            Match(
                source=source,
                status="",
                target=candidate.target,
                score=candidate.score,
                group_id="",
                candidates=[candidate],
                comparisons=candidate.comparisons,
            )
        )
        group_id = "MAP-%04d" % (len(matches) + 1)
        match = Match(
            source=source,
            status=status,
            target=candidate.target,
            score=candidate.score,
            group_id=group_id,
            candidates=[candidate],
            comparisons=candidate.comparisons,
            notes=_evidence_notes(candidate),
        )
        matches.append(match)
        target_claims.setdefault((candidate.target.kind, candidate.target.token), []).append(match)

    # If two indistinguishable source declarations were forced onto one target,
    # do not pretend the assignment is unique.
    for claims in target_claims.values():
        if len(claims) <= 1:
            continue
        for match in claims:
            match.status = STATUS_AMBIGUOUS
            if not match.group_id.startswith("AMB-"):
                match.group_id = "AMB-%04d" % (len(ambiguous_group_ids) + 1)
            match.candidates = sorted(
                match.candidates,
                key=_candidate_rank,
                reverse=True,
            )
            match.notes.append("multiple source entities claim this target")

    unmatched_new: List[Entity] = []
    old_identities = {entity.identity for entity in old_entities}
    old_loose_identities = {entity.loose_identity for entity in old_entities}
    for entity in new_entities:
        if entity.identity not in old_identities and entity.loose_identity not in old_loose_identities:
            unmatched_new.append(entity)

    return CorrelationResult(
        old=old_view,
        new=new_view,
        matches=matches,
        unmatched_new=unmatched_new,
    )


def correlate_files(
    old_path: Union[str, os.PathLike],
    new_path: Union[str, os.PathLike],
    **kwargs: Any,
) -> CorrelationResult:
    """Convenience wrapper around :func:`correlate` for two file paths."""

    return correlate(old_path, new_path, **kwargs)


class EntityCorrelator:
    """Small stateful facade for callers that prefer an object API."""

    def __init__(
        self,
        old: Union[str, os.PathLike, MetadataView, Any],
        new: Union[str, os.PathLike, MetadataView, Any],
        **kwargs: Any,
    ) -> None:
        self.old = old
        self.new = new
        self.options = dict(kwargs)
        self._result: Optional[CorrelationResult] = None

    @property
    def result(self) -> CorrelationResult:
        if self._result is None:
            self._result = correlate(self.old, self.new, **self.options)
        return self._result

    def correlate(self) -> CorrelationResult:
        return self.result

    def export(self, path: Union[str, os.PathLike], *, fmt: Optional[str] = None) -> str:
        return export_mapping(self.result, path, fmt=fmt)


def export_entity_table(
    result: CorrelationResult,
    path: Union[str, os.PathLike],
    *,
    fmt: Optional[str] = None,
) -> str:
    """Alias for :func:`export_mapping`."""

    return export_mapping(result, path, fmt=fmt)


ROW_FIELDS = [
    "group_id",
    "source_kind",
    "source_token",
    "source_namespace",
    "source_name",
    "source_declaring_type",
    "source_full_name",
    "status",
    "confidence",
    "review_required",
    "candidate_count",
    "candidate_index",
    "target_kind",
    "target_token",
    "target_namespace",
    "target_name",
    "target_declaring_type",
    "target_full_name",
    "token_changed",
    "semantic_equal",
    "projection_equal",
    "evidence",
    "notes",
]


def _match_rows(match: Match) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if match.candidates:
        candidates = match.candidates
    else:
        candidates = []
    if not candidates:
        rows.append(
            {
                "group_id": match.group_id,
                "source_kind": match.source.kind,
                "source_token": token_str(match.source.token),
                "source_namespace": match.source.namespace,
                "source_name": match.source.name,
                "source_declaring_type": match.source.declaring_type or "",
                "source_full_name": match.source.full_name,
                "status": match.status,
                "confidence": "%.3f" % match.score,
                "review_required": str(match.review_required).lower(),
                "candidate_count": "0",
                "candidate_index": "0",
                "target_kind": "",
                "target_token": "",
                "target_namespace": "",
                "target_name": "",
                "target_declaring_type": "",
                "target_full_name": "",
                "token_changed": "",
                "semantic_equal": "",
                "projection_equal": "",
                "evidence": "; ".join(match.notes),
                "notes": "; ".join(match.notes),
            }
        )
        return rows

    for index, candidate in enumerate(candidates, start=1):
        evidence = _evidence_notes(candidate)
        rows.append(
            {
                "group_id": match.group_id,
                "source_kind": match.source.kind,
                "source_token": token_str(match.source.token),
                "source_namespace": match.source.namespace,
                "source_name": match.source.name,
                "source_declaring_type": match.source.declaring_type or "",
                "source_full_name": match.source.full_name,
                "status": match.status,
                "confidence": "%.3f" % (candidate.score if match.target is None else match.score),
                "review_required": str(match.review_required).lower(),
                "candidate_count": str(len(candidates)),
                "candidate_index": str(index),
                "target_kind": candidate.target.kind,
                "target_token": token_str(candidate.target.token),
                "target_namespace": candidate.target.namespace,
                "target_name": candidate.target.name,
                "target_declaring_type": candidate.target.declaring_type or "",
                "target_full_name": candidate.target.full_name,
                "token_changed": str(not candidate.token_equal).lower(),
                "semantic_equal": str(candidate.semantic_equal).lower(),
                "projection_equal": str(candidate.projection_equal).lower(),
                "evidence": "; ".join(evidence),
                "notes": "; ".join(match.notes),
            }
        )
    return rows


def result_rows(result: CorrelationResult) -> List[Dict[str, Any]]:
    """Return the exported entity table as a list of flat rows."""

    rows: List[Dict[str, Any]] = []
    for match in result.matches:
        rows.extend(_match_rows(match))
    for entity in result.unmatched_new:
        rows.append(
            {
                "group_id": "",
                "source_kind": "",
                "source_token": "",
                "source_namespace": "",
                "source_name": "",
                "source_declaring_type": "",
                "source_full_name": "",
                "status": STATUS_UNMATCHED_NEW,
                "confidence": "0.000",
                "review_required": "true",
                "candidate_count": "0",
                "candidate_index": "0",
                "target_kind": entity.kind,
                "target_token": token_str(entity.token),
                "target_namespace": entity.namespace,
                "target_name": entity.name,
                "target_declaring_type": entity.declaring_type or "",
                "target_full_name": entity.full_name,
                "token_changed": "",
                "semantic_equal": "",
                "projection_equal": "",
                "evidence": "no source candidate with the same kind/name/scope",
                "notes": "",
            }
        )
    return rows


def export_mapping(
    result: CorrelationResult,
    path: Union[str, os.PathLike],
    *,
    fmt: Optional[str] = None,
) -> str:
    """Write the entity correspondence table and return the output path."""

    output = os.fspath(path)
    if fmt is None:
        extension = os.path.splitext(output)[1].lower()
        fmt = "json" if extension == ".json" else ("markdown" if extension in (".md", ".markdown") else "csv")
    fmt = fmt.lower()
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)

    if fmt == "json":
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(result.to_dict(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    elif fmt in ("md", "markdown"):
        rows = result_rows(result)
        columns = [
            "status",
            "source_token",
            "source_name",
            "target_token",
            "target_name",
            "candidate_count",
            "candidate_index",
            "review_required",
        ]
        with open(output, "w", encoding="utf-8") as handle:
            handle.write("# .NET entity correspondence\n\n")
            handle.write("| %s |\n" % " | ".join(columns))
            handle.write("| %s |\n" % " | ".join("---" for _ in columns))
            for row in rows:
                handle.write("| %s |\n" % " | ".join(str(row.get(c, "")) for c in columns))
    else:
        with open(output, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=ROW_FIELDS)
            writer.writeheader()
            writer.writerows(result_rows(result))
    return output


def _summary_text(result: CorrelationResult) -> str:
    lines = [
        "old: %s" % result.old.path,
        "new: %s" % result.new.path,
        "entity status:",
    ]
    for status, count in result.status_counts().items():
        lines.append("  %-24s %d" % (status, count))
    ambiguous_groups = {}
    for match in result.ambiguous:
        ambiguous_groups.setdefault(match.group_id, []).append(match)
    if ambiguous_groups:
        lines.append("ambiguous groups:")
        for group_id, matches in ambiguous_groups.items():
            first = matches[0]
            lines.append(
                "  %s %s %s (%d source rows, %d candidates)"
                % (
                    group_id,
                    first.source.kind,
                    first.source.full_name,
                    len(matches),
                    len(first.candidates),
                )
            )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline token-independent .NET metadata entity correlator",
    )
    parser.add_argument("old", help="first assembly (.dll/.exe)")
    parser.add_argument("new", help="second assembly (.dll/.exe)")
    parser.add_argument("-o", "--output", default="entity-map.csv", help="output table path")
    parser.add_argument(
        "--format",
        choices=("csv", "json", "markdown"),
        default=None,
        help="output format (defaults from the output extension)",
    )
    parser.add_argument("--include-module-type", action="store_true", help="include the <Module> TypeDef row")
    parser.add_argument("--max-candidates", type=int, default=8, help="maximum candidates per ambiguous group")
    parser.add_argument("-q", "--quiet", action="store_true", help="do not print the summary")
    args = parser.parse_args(argv)

    result = correlate(
        args.old,
        args.new,
        include_module_type=args.include_module_type,
        max_candidates=max(1, args.max_candidates),
    )
    export_mapping(result, args.output, fmt=args.format)
    if not args.quiet:
        print(_summary_text(result))
        print("wrote %s" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
