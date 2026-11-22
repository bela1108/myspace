# -*- coding: utf-8 -*-
"""
.NET signature blob parsing and heap-layout independent signature views.

The :class:`dnfile.mdtable` row objects expose raw signature blobs but never
interpret them.  This module implements the ECMA-335 II.23.2 binary grammar
for those blobs and, on top of the raw parse tree, builds a *comparable
signature view* in which every type reference is reduced to a stable
:class:`TypeIdentity`.

The stable identities deliberately do not embed heap offsets or blob
indices, so two assemblies whose metadata heaps were re-ordered (the common
"heap swap" case) still produce identical fingerprints as long as the public
API is unchanged.  References that cannot be resolved are represented by
:class:`UnresolvedIdentity`, which keeps its table/rid origin instead of
silently collapsing onto a same-named type.

Reference: ECMA-335, Partition II, sections 23.1 and 23.2.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .utils import read_compressed_int


# ---------------------------------------------------------------------------
# ECMA-335 II.23.1.16 element types used inside signatures
# ---------------------------------------------------------------------------


class ElementType(IntEnum):
    END = 0x00
    VOID = 0x01
    BOOLEAN = 0x02
    CHAR = 0x03
    I1 = 0x04
    U1 = 0x05
    I2 = 0x06
    U2 = 0x07
    I4 = 0x08
    U4 = 0x09
    I8 = 0x0A
    U8 = 0x0B
    R4 = 0x0C
    R8 = 0x0D
    STRING = 0x0E
    PTR = 0x0F
    BYREF = 0x10
    VALUETYPE = 0x11
    CLASS = 0x12
    VAR = 0x13
    ARRAY = 0x14
    GENERICINST = 0x15
    TYPEDBYREF = 0x16
    I = 0x18
    U = 0x19
    FNPTR = 0x1B
    OBJECT = 0x1C
    SZARRAY = 0x1D
    MVAR = 0x1E
    CMOD_REQD = 0x1F
    CMOD_OPT = 0x20
    INTERNAL = 0x21
    MODIFIER = 0x40
    SENTINEL = 0x41
    PINNED = 0x45


class CallingConvention(IntEnum):
    DEFAULT = 0x00
    C = 0x01
    STDCALL = 0x02
    THISCALL = 0x03
    FASTCALL = 0x04
    VARARG = 0x05
    GENERIC = 0x10
    HASTHIS = 0x20
    EXPLICITTHIS = 0x40


ELEMENT_TYPE_NAMES: Dict[int, str] = {
    ElementType.VOID: "System.Void",
    ElementType.BOOLEAN: "System.Boolean",
    ElementType.CHAR: "System.Char",
    ElementType.I1: "System.SByte",
    ElementType.U1: "System.Byte",
    ElementType.I2: "System.Int16",
    ElementType.U2: "System.UInt16",
    ElementType.I4: "System.Int32",
    ElementType.U4: "System.UInt32",
    ElementType.I8: "System.Int64",
    ElementType.U8: "System.UInt64",
    ElementType.R4: "System.Single",
    ElementType.R8: "System.Double",
    ElementType.STRING: "System.String",
    ElementType.TYPEDBYREF: "System.TypedReference",
    ElementType.I: "System.IntPtr",
    ElementType.U: "System.UIntPtr",
    ElementType.OBJECT: "System.Object",
}


class SignatureError(ValueError):
    """Raised when a signature blob does not follow the ECMA grammar."""


# ---------------------------------------------------------------------------
# Raw parse tree
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Modifier:
    """A custom modifier (``modreq``/``modopt``) attached to a type."""

    required: bool
    type_token: "TypeToken"


@dataclass(frozen=True)
class TypeToken:
    """A coded TypeDefOrRef token as it appears inside a blob.

    ``table`` is one of ``"TypeDef"``, ``"TypeRef"``, ``"TypeSpec"`` and
    ``rid`` is the 1-based row index.  Resolution to a stable identity
    happens later, in :class:`SignatureView`.
    """

    table: str
    rid: int


@dataclass(frozen=True)
class ArrayShape:
    """The rank / bounds portion of a general ``ELEMENT_TYPE_ARRAY``."""

    rank: int
    sizes: Tuple[int, ...]
    lo_bounds: Tuple[int, ...]


@dataclass(frozen=True)
class TypeSig:
    """A parsed type (a node in the signature type grammar).

    Only the attributes relevant to the grammar are populated; ``token`` is
    set for ``CLASS``/``VALUETYPE`` and generic instantiation arguments,
    ``var_index`` for ``VAR``/``MVAR`` and the remaining fields describe
    composite types.
    """

    kind: int
    token: Optional[TypeToken] = None
    var_index: Optional[int] = None
    is_value_type: bool = False
    modifiers: Tuple[Modifier, ...] = ()
    pinned: bool = False
    element: Optional["TypeSig"] = None
    generic_args: Tuple["TypeSig", ...] = ()
    array_shape: Optional[ArrayShape] = None
    fnptr: Optional["MethodSignature"] = None
    internal_type: Optional[int] = None


@dataclass(frozen=True)
class ParamSig:
    type: TypeSig
    sentinel: bool = False


@dataclass(frozen=True)
class MethodSignature:
    """Raw method/function-pointer signature."""

    raw_calling_convention: int
    has_this: bool
    explicit_this: bool
    convention: int
    is_generic: bool
    generic_param_count: int
    return_type: TypeSig
    params: Tuple[ParamSig, ...]
    vararg: bool = False


@dataclass(frozen=True)
class FieldSignature:
    type: TypeSig


@dataclass(frozen=True)
class LocalSignature:
    locals: Tuple[TypeSig, ...]


class _BlobReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise SignatureError("unexpected end of signature blob")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read_compressed(self) -> int:
        result = read_compressed_int(self.data[self.pos:])
        if result is None:
            raise SignatureError("invalid compressed integer in signature")
        value, size = result
        self.pos += size
        return value

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


def _parse_modifiers(reader: _BlobReader) -> Tuple[List[Modifier], bool]:
    """Consume leading modreq/modopt and PINNED markers before a type."""
    modifiers: List[Modifier] = []
    pinned = False
    while True:
        marker = reader.read_byte()
        if marker == ElementType.CMOD_REQD or marker == ElementType.CMOD_OPT:
            token = _parse_typedef_or_ref(reader)
            modifiers.append(Modifier(marker == ElementType.CMOD_REQD, token))
        elif marker == ElementType.PINNED:
            pinned = True
        else:
            reader.pos -= 1
            return tuple(modifiers), pinned


def _parse_typedef_or_ref(reader: _BlobReader) -> TypeToken:
    coded = reader.read_compressed()
    tag = coded & 0x3
    rid = coded >> 2
    table = ("TypeDef", "TypeRef", "TypeSpec")[tag]
    return TypeToken(table, rid)


def parse_type(reader: _BlobReader) -> TypeSig:
    """Parse one ECMA-335 Type value, including leading modifiers."""
    modifiers, pinned = _parse_modifiers(reader)
    kind = reader.read_byte()

    if kind in ELEMENT_TYPE_NAMES:
        node = TypeSig(kind=kind, modifiers=tuple(modifiers), pinned=pinned)
    elif kind == ElementType.CLASS or kind == ElementType.VALUETYPE:
        node = TypeSig(
            kind=kind,
            token=_parse_typedef_or_ref(reader),
            is_value_type=kind == ElementType.VALUETYPE,
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.VAR or kind == ElementType.MVAR:
        node = TypeSig(
            kind=kind,
            var_index=reader.read_compressed(),
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.PTR:
        node = TypeSig(
            kind=kind,
            element=parse_type(reader),
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.BYREF:
        node = TypeSig(
            kind=kind,
            element=parse_type(reader),
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.SZARRAY:
        node = TypeSig(
            kind=kind,
            element=parse_type(reader),
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.ARRAY:
        element = parse_type(reader)
        rank = reader.read_compressed()
        num_sizes = reader.read_compressed()
        sizes = tuple(reader.read_compressed() for _ in range(num_sizes))
        num_lo = reader.read_compressed()
        lo_bounds = tuple(reader.read_compressed() for _ in range(num_lo))
        node = TypeSig(
            kind=kind,
            element=element,
            array_shape=ArrayShape(rank, sizes, lo_bounds),
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.GENERICINST:
        is_value_type = reader.read_byte() == ElementType.VALUETYPE
        token = _parse_typedef_or_ref(reader)
        arg_count = reader.read_compressed()
        args = tuple(parse_type(reader) for _ in range(arg_count))
        node = TypeSig(
            kind=kind,
            token=token,
            is_value_type=is_value_type,
            generic_args=args,
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.FNPTR:
        node = TypeSig(
            kind=kind,
            fnptr=_parse_method_signature(reader),
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.INTERNAL:
        node = TypeSig(
            kind=kind,
            internal_type=reader.read_compressed(),
            modifiers=tuple(modifiers),
            pinned=pinned,
        )
    elif kind == ElementType.OBJECT:
        node = TypeSig(kind=kind, modifiers=tuple(modifiers), pinned=pinned)
    else:
        raise SignatureError(f"unsupported element type 0x{kind:02x}")
    return node


def _parse_method_signature(reader: _BlobReader) -> MethodSignature:
    raw = reader.read_byte()
    has_this = bool(raw & CallingConvention.HASTHIS)
    explicit_this = bool(raw & CallingConvention.EXPLICITTHIS)
    convention = raw & 0x0F
    is_generic = bool(raw & CallingConvention.GENERIC)
    generic_param_count = reader.read_compressed() if is_generic else 0
    param_count = reader.read_compressed()
    return_type = parse_type(reader)

    params: List[ParamSig] = []
    vararg = False
    for _ in range(param_count):
        sentinel = False
        if not reader.at_end() and reader.data[reader.pos] == ElementType.SENTINEL:
            reader.read_byte()
            sentinel = True
            vararg = True
        params.append(ParamSig(parse_type(reader), sentinel))

    return MethodSignature(
        raw_calling_convention=raw,
        has_this=has_this,
        explicit_this=explicit_this,
        convention=convention,
        is_generic=is_generic,
        generic_param_count=generic_param_count,
        return_type=return_type,
        params=tuple(params),
        vararg=vararg,
    )


def parse_signature(blob: bytes) -> Union[MethodSignature, FieldSignature, LocalSignature]:
    """Parse a full standalone signature blob from the ``#Blob`` heap.

    The leading byte determines whether it is a method (DEFAULT/.../GENERIC),
    field (FIELD 0x06) or local (LOCAL_SIG 0x07) signature.
    """
    if not blob:
        raise SignatureError("empty signature blob")
    reader = _BlobReader(blob)
    lead = blob[0]
    if lead & 0x0F in (
        CallingConvention.DEFAULT,
        CallingConvention.C,
        CallingConvention.STDCALL,
        CallingConvention.THISCALL,
        CallingConvention.FASTCALL,
        CallingConvention.VARARG,
    ) or lead & CallingConvention.GENERIC:
        result = _parse_method_signature(reader)
    elif lead == 0x06:  # FIELD
        reader.read_byte()
        result = FieldSignature(parse_type(reader))
    elif lead == 0x07:  # LOCAL_SIG
        reader.read_byte()
        count = reader.read_compressed()
        result = LocalSignature(tuple(parse_type(reader) for _ in range(count)))
    else:
        raise SignatureError(f"unknown signature kind 0x{lead:02x}")
    if not reader.at_end():
        raise SignatureError(f"{reader.pos} trailing byte(s) in signature blob")
    return result


# ---------------------------------------------------------------------------
# Stable type identities
#
# Every type reachable from a signature is reduced to one of these
# dataclasses.  ``key()`` renders a canonical, heap-independent string that
# still distinguishes different origins: an unresolved TypeRef token never
# compares equal to a same-named TypeDef because their key prefixes differ.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TypeIdentity:
    """Base class for heap-layout independent type identities."""

    def key(self) -> str:
        raise NotImplementedError

    @property
    def resolved(self) -> bool:
        return not isinstance(self, UnresolvedIdentity)


@dataclass(frozen=True)
class PrimitiveIdentity(TypeIdentity):
    """One of the built-in element types (I4, STRING, OBJECT, I, ...)."""

    name: str

    def key(self) -> str:
        return f"prim:{self.name}"


@dataclass(frozen=True)
class TypeDefIdentity(TypeIdentity):
    """A type defined inside the module under analysis."""

    full_name: str

    def key(self) -> str:
        return f"typedef:{self.full_name}"


@dataclass(frozen=True)
class TypeRefIdentity(TypeIdentity):
    """A type imported from another assembly/module."""

    full_name: str
    scope: str

    def key(self) -> str:
        return f"typeref:{self.scope}!{self.full_name}"


@dataclass(frozen=True)
class GenericParamIdentity(TypeIdentity):
    """A VAR/MVAR slot.

    ``owner`` is the stable key of the owning type or method and ``index``
    is the zero-based parameter number, so generic parameters of different
    owners never merge even when they share a name.
    """

    owner: str
    index: int
    name: str

    def key(self) -> str:
        return f"genvar:{self.owner}!{self.index}"


@dataclass(frozen=True)
class UnresolvedIdentity(TypeIdentity):
    """A token we could not resolve.

    The table name and 1-based rid are retained explicitly so the marker
    stays distinct from any same-named real type.  ``reason`` records why
    resolution failed.
    """

    table: str
    rid: int
    reason: str

    def key(self) -> str:
        return f"unresolved:{self.table}/{self.rid}({self.reason})"


@dataclass(frozen=True)
class ModifierIdentity:
    required: bool
    modifier: TypeIdentity

    def key(self) -> str:
        kind = "modreq" if self.required else "modopt"
        return f"{kind}[{self.modifier.key()}]"


@dataclass(frozen=True)
class ByRefIdentity(TypeIdentity):
    element: TypeIdentity
    modifiers: Tuple[ModifierIdentity, ...] = ()
    pinned: bool = False

    def key(self) -> str:
        head = "pinned " if self.pinned else ""
        return f"{head}byref {_modifier_prefix(self.modifiers)}{self.element.key()}"


@dataclass(frozen=True)
class PointerIdentity(TypeIdentity):
    element: TypeIdentity
    modifiers: Tuple[ModifierIdentity, ...] = ()
    pinned: bool = False

    def key(self) -> str:
        head = "pinned " if self.pinned else ""
        return f"{head}ptr {_modifier_prefix(self.modifiers)}{self.element.key()}"


@dataclass(frozen=True)
class SzArrayIdentity(TypeIdentity):
    """A one-dimensional, zero-based vector (``ELEMENT_TYPE_SZARRAY``)."""

    element: TypeIdentity
    modifiers: Tuple[ModifierIdentity, ...] = ()
    pinned: bool = False

    def key(self) -> str:
        head = "pinned " if self.pinned else ""
        return f"{head}szarray[{_modifier_prefix(self.modifiers)}{self.element.key()}]"


@dataclass(frozen=True)
class ArrayIdentity(TypeIdentity):
    """A general array with explicit rank, sizes and lower bounds."""

    element: TypeIdentity
    rank: int
    sizes: Tuple[int, ...]
    lo_bounds: Tuple[int, ...]
    modifiers: Tuple[ModifierIdentity, ...] = ()
    pinned: bool = False

    def key(self) -> str:
        head = "pinned " if self.pinned else ""
        sizes = ",".join(str(s) for s in self.sizes)
        los = ",".join(str(b) for b in self.lo_bounds)
        return (
            f"{head}array[{_modifier_prefix(self.modifiers)}{self.element.key()}]"
            f"(rank={self.rank},sizes=({sizes}),lobounds=({los}))"
        )


@dataclass(frozen=True)
class GenericInstIdentity(TypeIdentity):
    definition: TypeIdentity
    args: Tuple[TypeIdentity, ...]
    is_value_type: bool

    def key(self) -> str:
        kind = "valuetype" if self.is_value_type else "class"
        args = ",".join(a.key() for a in self.args)
        return f"geninst {kind} {self.definition.key()}<{args}>"


@dataclass(frozen=True)
class FnPtrIdentity(TypeIdentity):
    signature: "MethodView"

    def key(self) -> str:
        return f"fnptr({self.signature.fingerprint()})"


@dataclass(frozen=True)
class ModifiedType(TypeIdentity):
    """A leaf type carrying leading modreq/modopt (and/or PINNED) markers."""

    element: TypeIdentity
    modifiers: Tuple[ModifierIdentity, ...]
    pinned: bool = False

    def key(self) -> str:
        head = "pinned " if self.pinned else ""
        return f"{head}{_modifier_prefix(self.modifiers)}{self.element.key()}"


def _modifier_prefix(modifiers: Sequence[ModifierIdentity]) -> str:
    if not modifiers:
        return ""
    return " ".join(m.key() for m in modifiers) + " "


# ---------------------------------------------------------------------------
# Comparable views
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParamView:
    name: Optional[str]
    type: TypeIdentity
    sentinel: bool

    def fingerprint(self) -> str:
        marker = "sentinel " if self.sentinel else ""
        return f"{marker}{self.type.key()}"


@dataclass(frozen=True)
class MethodView:
    """Comparable view of a MethodDef (or function-pointer) signature."""

    name: str
    owner: str
    has_this: bool
    explicit_this: bool
    calling_convention: int
    vararg: bool
    generic_params: Tuple["GenericParamView", ...]
    return_type: TypeIdentity
    params: Tuple[ParamView, ...]
    unresolved: Tuple[UnresolvedIdentity, ...]

    def fingerprint(self) -> str:
        gps = (
            "<" + ",".join(gp.fingerprint() for gp in self.generic_params) + ">"
            if self.generic_params
            else ""
        )
        parts = [
            f"cc={self.calling_convention}",
            f"hasthis={int(self.has_this)}",
            f"explicitthis={int(self.explicit_this)}",
            f"vararg={int(self.vararg)}",
            f"gen={gps}",
            f"ret={self.return_type.key()}",
            "params=(" + ",".join(p.fingerprint() for p in self.params) + ")",
        ]
        return "method " + " ".join(parts)


@dataclass(frozen=True)
class FieldView:
    """Comparable view of a Field signature."""

    name: str
    owner: str
    type: TypeIdentity
    unresolved: Tuple[UnresolvedIdentity, ...]

    def fingerprint(self) -> str:
        return f"field {self.type.key()}"


@dataclass(frozen=True)
class GenericParamView:
    """A generic parameter with its owner, variance and constraints."""

    name: str
    index: int
    owner: str
    flags: int
    constraints: Tuple[TypeIdentity, ...]
    unresolved: Tuple[UnresolvedIdentity, ...]

    @property
    def variance(self) -> str:
        # ECMA-335 II.23.1.9 GenericParamConstraint variance bits
        if self.flags & 0x04:
            return "in"
        if self.flags & 0x08:
            return "out"
        return "invariant"

    def fingerprint(self) -> str:
        constraints = (
            " constraints=(" + ",".join(c.key() for c in self.constraints) + ")"
            if self.constraints
            else ""
        )
        return f"{self.variance} {self.name}{constraints}"


@dataclass(frozen=True)
class TypeView:
    """Comparable view of a TypeDef declaration."""

    name: str
    namespace: str
    full_name: str
    is_value_type: bool
    extends: Optional[TypeIdentity]
    generic_params: Tuple[GenericParamView, ...]
    fields: Tuple[FieldView, ...]
    methods: Tuple[MethodView, ...]
    unresolved: Tuple[UnresolvedIdentity, ...]

    def fingerprint(self) -> str:
        gps = (
            "<" + ",".join(gp.fingerprint() for gp in self.generic_params) + ">"
            if self.generic_params
            else ""
        )
        extends = self.extends.key() if self.extends is not None else ""
        return f"type {self.full_name}{gps} extends={extends}"


# ---------------------------------------------------------------------------
# SignatureView: reduces dnfile metadata rows to the comparable views above
# ---------------------------------------------------------------------------


def _text(value: Any) -> str:
    """Coerce a heap string item (or plain str) to a native str."""
    if value is None:
        return ""
    return str(value)


def _deref(item: Any) -> Any:
    """Unwrap an MDTableIndex/CodedIndex to its underlying row, if needed."""
    return getattr(item, "row", item)


def _blob_bytes(value: Any) -> bytes:
    """Return raw bytes from a row signature (blob heap item or plain bytes)."""
    if value is None:
        return b""
    if hasattr(value, "value_bytes"):
        return value.value_bytes()
    return bytes(value)


def _full_name(namespace: Optional[str], name: Optional[str]) -> str:
    if namespace:
        return f"{namespace}.{name}"
    return name or ""


class SignatureView:
    """Builds heap-layout independent signature views from a parsed PE.

    Construct with a :class:`dnfile.dnPE` (anything exposing
    ``net.mdtables`` works) and call :meth:`build`.  All type tokens found
    in method, field and type signatures are resolved through the metadata
    tables; anything that cannot be resolved becomes an
    :class:`UnresolvedIdentity` rather than matching a same-named type.
    """

    def __init__(self, pe: Any):
        self.pe = pe
        mdtables = getattr(getattr(pe, "net", None), "mdtables", None)
        self.mdtables = mdtables
        self._gp_owner: Dict[Tuple[str, int], Tuple[str, str]] = {}
        self._gp_index: Dict[Tuple[str, int], int] = {}

    def _table(self, name: str):
        if self.mdtables is None:
            return None
        return getattr(self.mdtables, name, None)

    def _row(self, name: str, rid: int):
        table = self._table(name)
        if table is None or rid < 1 or rid > table.num_rows:
            return None
        return table.get_with_row_index(rid)

    # -- generic parameter ownership -------------------------------------

    def _index_generic_params(self) -> None:
        table = self._table("GenericParam")
        if table is None:
            return
        for row_index, row in enumerate(table, start=1):
            owner = row.Owner
            if owner is None or owner.table is None:
                continue
            owner_table = owner.table.name
            owner_rid = owner.row_index
            owner_key = self._owner_key(owner_table, owner_rid)
            self._gp_owner[(owner_table, owner_rid)] = (owner_key, _text(row.Name))
            self._gp_index[(owner_table, owner_rid)] = row.Number

    def _owner_key(self, owner_table: str, owner_rid: int) -> str:
        if owner_table == "TypeDef":
            row = self._row("TypeDef", owner_rid)
            if row is not None:
                return "typedef:" + _full_name(_text(row.TypeNamespace), _text(row.TypeName))
            return f"typedef:rid/{owner_rid}"
        if owner_table == "MethodDef":
            row = self._row("MethodDef", owner_rid)
            if row is not None:
                return "method:" + (_text(row.Name) or f"rid/{owner_rid}")
            return f"method:rid/{owner_rid}"
        return f"{owner_table.lower()}:rid/{owner_rid}"

    # -- token resolution ------------------------------------------------

    def _scope_key(self, scope: Any) -> str:
        if scope is None or getattr(scope, "table", None) is None:
            return "scope:unknown"
        table = scope.table
        name = table.name
        rid = scope.row_index
        if name == "AssemblyRef":
            row = table.get_with_row_index(rid) if 1 <= rid <= table.num_rows else None
            if row is not None and _text(row.Name):
                return f"assembly:{_text(row.Name)}"
            return f"assemblyref:rid/{rid}"
        if name == "ModuleRef":
            row = table.get_with_row_index(rid) if 1 <= rid <= table.num_rows else None
            if row is not None and _text(row.Name):
                return f"module:{_text(row.Name)}"
            return f"moduleref:rid/{rid}"
        if name == "Module":
            return "module:<this>"
        if name == "TypeRef":
            row = table.get_with_row_index(rid) if 1 <= rid <= table.num_rows else None
            if row is not None:
                return "tyrefscope:" + _full_name(_text(row.TypeNamespace), _text(row.TypeName))
            return f"tyrefscope:rid/{rid}"
        return f"{name.lower()}:rid/{rid}"

    def _resolve_token(self, token: TypeToken) -> TypeIdentity:
        if token.rid < 1:
            return UnresolvedIdentity(token.table, token.rid, "rid is zero")
        if token.table == "TypeDef":
            row = self._row("TypeDef", token.rid)
            if row is None:
                return UnresolvedIdentity("TypeDef", token.rid, "row missing")
            return TypeDefIdentity(_full_name(_text(row.TypeNamespace), _text(row.TypeName)))
        if token.table == "TypeRef":
            row = self._row("TypeRef", token.rid)
            if row is None:
                return UnresolvedIdentity("TypeRef", token.rid, "row missing")
            full = _full_name(_text(row.TypeNamespace), _text(row.TypeName))
            if not full:
                return UnresolvedIdentity("TypeRef", token.rid, "empty type name")
            scope = self._scope_key(row.ResolutionScope)
            return TypeRefIdentity(full, scope)
        if token.table == "TypeSpec":
            return self._resolve_typespec(token.rid)
        return UnresolvedIdentity(token.table, token.rid, "unknown token table")

    def _resolve_typespec(self, rid: int) -> TypeIdentity:
        row = self._row("TypeSpec", rid)
        if row is None:
            return UnresolvedIdentity("TypeSpec", rid, "row missing")
        try:
            parsed = parse_signature(_blob_bytes(row.Signature))
        except SignatureError as exc:
            return UnresolvedIdentity("TypeSpec", rid, f"bad blob: {exc}")
        if not isinstance(parsed, FieldSignature):
            return UnresolvedIdentity("TypeSpec", rid, "not a type blob")
        return self._identity_of(parsed.type, owner=None)

    def _collect_unresolved(self, identity: TypeIdentity) -> Tuple[UnresolvedIdentity, ...]:
        found: List[UnresolvedIdentity] = []
        def walk(node: TypeIdentity) -> None:
            if isinstance(node, UnresolvedIdentity):
                found.append(node)
            for attr_value in getattr(node, "__dict__", {}).values():
                if isinstance(attr_value, TypeIdentity):
                    walk(attr_value)
                elif isinstance(attr_value, (tuple, list)):
                    for item in attr_value:
                        if isinstance(item, TypeIdentity):
                            walk(item)
                        elif isinstance(item, ModifierIdentity):
                            walk(item.modifier)
            if isinstance(node, FnPtrIdentity):
                for param in node.signature.params:
                    walk(param.type)
                walk(node.signature.return_type)
        walk(identity)
        return tuple(found)

    def _identity_of(self, sig: TypeSig, owner: Optional[Tuple[str, int]]) -> TypeIdentity:
        modifiers = tuple(
            ModifierIdentity(mod.required, self._resolve_token(mod.type_token))
            for mod in sig.modifiers
        )
        if sig.kind in ELEMENT_TYPE_NAMES:
            identity: TypeIdentity = PrimitiveIdentity(ELEMENT_TYPE_NAMES[sig.kind])
        elif sig.kind in (ElementType.CLASS, ElementType.VALUETYPE):
            assert sig.token is not None
            identity = self._resolve_token(sig.token)
        elif sig.kind in (ElementType.VAR, ElementType.MVAR):
            identity = self._generic_param_identity(sig.kind, sig.var_index or 0, owner)
        elif sig.kind == ElementType.PTR:
            assert sig.element is not None
            identity = PointerIdentity(self._identity_of(sig.element, owner), modifiers, sig.pinned)
            modifiers = ()
        elif sig.kind == ElementType.BYREF:
            assert sig.element is not None
            identity = ByRefIdentity(self._identity_of(sig.element, owner), modifiers, sig.pinned)
            modifiers = ()
        elif sig.kind == ElementType.SZARRAY:
            assert sig.element is not None
            identity = SzArrayIdentity(self._identity_of(sig.element, owner), modifiers, sig.pinned)
            modifiers = ()
        else:
            identity = self._composite_identity(sig, owner, modifiers)
            modifiers = ()
        if modifiers:
            identity = ModifiedType(identity, modifiers, sig.pinned)
        return identity

    def _composite_identity(self, sig: TypeSig, owner, modifiers):
        if sig.kind == ElementType.ARRAY:
            assert sig.element is not None and sig.array_shape is not None
            shape = sig.array_shape
            return ArrayIdentity(
                self._identity_of(sig.element, owner),
                shape.rank, shape.sizes, shape.lo_bounds, modifiers, sig.pinned
            )
        if sig.kind == ElementType.GENERICINST:
            assert sig.token is not None
            args = tuple(self._identity_of(arg, owner) for arg in sig.generic_args)
            return GenericInstIdentity(
                self._resolve_token(sig.token), args, sig.is_value_type
            )
        if sig.kind == ElementType.FNPTR:
            assert sig.fnptr is not None
            fn_view = self._method_signature_view(sig.fnptr, name="<fnptr>", owner_key="fnptr")
            return FnPtrIdentity(fn_view)
        if sig.kind == ElementType.INTERNAL:
            return UnresolvedIdentity("blob", sig.internal_type or 0, "ELEMENT_TYPE_INTERNAL")
        return UnresolvedIdentity("blob", sig.kind, f"unsupported element 0x{sig.kind:02x}")

    def _generic_param_identity(self, kind: int, index: int, owner) -> TypeIdentity:
        if owner is None:
            return UnresolvedIdentity("GenericParam", index, "VAR/MVAR without owner context")
        owner_table, owner_rid = owner
        if kind == ElementType.VAR and owner_table != "TypeDef":
            return UnresolvedIdentity("GenericParam", index, "VAR used outside a type owner")
        if kind == ElementType.MVAR and owner_table != "MethodDef":
            return UnresolvedIdentity("GenericParam", index, "MVAR used outside a method owner")
        owner_key = self._owner_key(owner_table, owner_rid)
        info = self._gp_owner.get((owner_table, owner_rid))
        name = info[1] if info is not None else f"T{index}"
        return GenericParamIdentity(owner_key, index, name)

    def _generic_param_views(self, owner_table: str, owner_rid: int, owner_key: str):
        gp_table = self._table("GenericParam")
        if gp_table is None:
            return ()
        gpc_table = self._table("GenericParamConstraint")
        views: List[GenericParamView] = []
        for row_index, gp in enumerate(gp_table, start=1):
            owner = gp.Owner
            if owner is None or owner.table is None:
                continue
            if owner.table.name != owner_table or owner.row_index != owner_rid:
                continue
            constraints: List[TypeIdentity] = []
            unresolved: List[UnresolvedIdentity] = []
            if gpc_table is not None:
                for gpc in gpc_table:
                    if gpc.Owner is None or gpc.Owner.row_index != row_index:
                        continue
                    if getattr(gpc.Owner, "table", None) is not None and gpc.Owner.table.name != "GenericParam":
                        continue
                    coded = gpc.Constraint
                    if coded is None or coded.table is None:
                        unresolved.append(UnresolvedIdentity("TypeDefOrRef", 0, "empty constraint token"))
                        continue
                    token = TypeToken(coded.table.name, coded.row_index)
                    identity = self._resolve_token(token)
                    constraints.append(identity)
                    unresolved.extend(self._collect_unresolved(identity))
            views.append(GenericParamView(
                name=_text(gp.Name), index=gp.Number, owner=owner_key,
                flags=int(getattr(gp, "struct", gp).Flags), constraints=tuple(constraints), unresolved=tuple(unresolved)
            ))
        views.sort(key=lambda view: view.index)
        return tuple(views)

    def _method_signature_view(self, sig: MethodSignature, name: str, owner_key: str,
                                type_owner=None, method_owner=None, param_rows=()) -> MethodView:
        return_type = self._identity_of(sig.return_type, self._type_owner(sig.return_type, type_owner, method_owner))
        param_views: List[ParamView] = []
        unresolved: List[UnresolvedIdentity] = list(self._collect_unresolved(return_type))
        for index, param in enumerate(sig.params):
            owner = self._type_owner(param.type, type_owner, method_owner)
            identity = self._identity_of(param.type, owner)
            param_name = (_text(param_rows[index].Name) if index < len(param_rows) else None)
            param_views.append(ParamView(param_name, identity, param.sentinel))
            unresolved.extend(self._collect_unresolved(identity))
        return MethodView(
            name=name, owner=owner_key, has_this=sig.has_this,
            explicit_this=sig.explicit_this, calling_convention=sig.convention,
            vararg=sig.vararg, generic_params=(), return_type=return_type,
            params=tuple(param_views), unresolved=tuple(_dedupe(unresolved))
        )

    def _type_owner(self, sig_type: TypeSig, type_owner, method_owner):
        # VAR always belongs to the enclosing type; MVAR to the method.
        # For composite nodes pick whichever owner the first variable leaf needs.
        if sig_type.kind == ElementType.VAR:
            return type_owner
        if sig_type.kind == ElementType.MVAR:
            return method_owner
        if sig_type.element is not None:
            child = self._type_owner(sig_type.element, type_owner, method_owner)
            if child is not None:
                return child
        for arg in sig_type.generic_args:
            child = self._type_owner(arg, type_owner, method_owner)
            if child is not None:
                return child
        return method_owner if method_owner is not None else type_owner

    def _field_view(self, row, owner_key: str, type_owner) -> Optional[FieldView]:
        try:
            parsed = parse_signature(_blob_bytes(row.Signature))
        except SignatureError as exc:
            unresolved = (UnresolvedIdentity("Field", 0, f"bad blob: {exc}"),)
            return FieldView(name=_text(row.Name), owner=owner_key,
                             type=unresolved[0], unresolved=unresolved)
        if not isinstance(parsed, FieldSignature):
            unresolved = (UnresolvedIdentity("Field", 0, "not a field blob"),)
            return FieldView(name=_text(row.Name), owner=owner_key,
                             type=unresolved[0], unresolved=unresolved)
        identity = self._identity_of(parsed.type, type_owner)
        return FieldView(
            name=_text(row.Name), owner=owner_key, type=identity,
            unresolved=self._collect_unresolved(identity)
        )

    def _method_view(self, row, owner_key: str, type_owner, method_rid: int = 0) -> Optional[MethodView]:
        method_owner = ("MethodDef", method_rid)
        param_rows = tuple(_deref(item) for item in (row.ParamList or ()))
        try:
            parsed = parse_signature(_blob_bytes(row.Signature))
        except SignatureError as exc:
            unresolved = (UnresolvedIdentity("MethodDef", method_rid, f"bad blob: {exc}"),)
            return MethodView(
                name=_text(row.Name), owner=owner_key, has_this=False, explicit_this=False,
                calling_convention=0, vararg=False, generic_params=(),
                return_type=unresolved[0], params=(), unresolved=unresolved
            )
        if not isinstance(parsed, MethodSignature):
            unresolved = (UnresolvedIdentity("MethodDef", method_rid, "not a method blob"),)
            return MethodView(
                name=_text(row.Name), owner=owner_key, has_this=False, explicit_this=False,
                calling_convention=0, vararg=False, generic_params=(),
                return_type=unresolved[0], params=(), unresolved=unresolved
            )
        view = self._method_signature_view(
            parsed, _text(row.Name), owner_key, type_owner, method_owner, param_rows
        )
        gps = self._generic_param_views("MethodDef", method_rid, owner_key + "#" + (_text(row.Name)))
        gp_unresolved = [item for gp in gps for item in gp.unresolved]
        return MethodView(
            name=view.name, owner=view.owner, has_this=view.has_this,
            explicit_this=view.explicit_this, calling_convention=view.calling_convention,
            vararg=view.vararg, generic_params=gps, return_type=view.return_type,
            params=view.params, unresolved=tuple(_dedupe(list(view.unresolved) + gp_unresolved))
        )

    def _type_view(self, row, type_rid: int) -> TypeView:
        full = _full_name(_text(row.TypeNamespace), _text(row.TypeName))
        owner_key = "typedef:" + full
        type_owner = ("TypeDef", type_rid)
        extends: Optional[TypeIdentity] = None
        unresolved: List[UnresolvedIdentity] = []
        if row.Extends is not None and getattr(row.Extends, "table", None) is not None:
            token = TypeToken(row.Extends.table.name, row.Extends.row_index)
            extends = self._resolve_token(token)
            unresolved.extend(self._collect_unresolved(extends))
        fields = tuple(
            view for field_index in (row.FieldList or ())
            for field_row in (_deref(field_index),)
            if (view := self._field_view(field_row, owner_key, type_owner)) is not None
        )
        methods = tuple(
            view
            for method_index in (row.MethodList or ())
            for method_row in (_deref(method_index),)
            if (view := self._method_view(
                method_row, owner_key, type_owner, method_index.row_index
            )) is not None
        )
        gps = self._generic_param_views("TypeDef", type_rid, owner_key)
        unresolved.extend(item for gp in gps for item in gp.unresolved)
        for view in fields + methods:
            unresolved.extend(view.unresolved)
        is_value_type = isinstance(extends, TypeRefIdentity) and extends.full_name == "System.ValueType"
        return TypeView(
            name=_text(row.TypeName), namespace=_text(row.TypeNamespace), full_name=full,
            is_value_type=is_value_type, extends=extends, generic_params=gps,
            fields=fields, methods=methods, unresolved=tuple(_dedupe(unresolved))
        )

    def build(self) -> "ModuleView":
        self._gp_owner.clear()
        self._gp_index.clear()
        self._index_generic_params()
        type_views: List[TypeView] = []
        all_unresolved: List[UnresolvedIdentity] = []
        typedef = self._table("TypeDef")
        if typedef is not None:
            for type_rid, row in enumerate(typedef, start=1):
                if row.TypeName == "<Module>":
                    continue
                view = self._type_view(row, type_rid)
                type_views.append(view)
                all_unresolved.extend(view.unresolved)
        return ModuleView(types=tuple(type_views), unresolved=tuple(_dedupe(all_unresolved)))

def _dedupe(items: Sequence[UnresolvedIdentity]) -> Tuple[UnresolvedIdentity, ...]:
    seen = set()
    result = []
    for item in items:
        marker = item.key()
        if marker not in seen:
            seen.add(marker)
            result.append(item)
    return tuple(result)


@dataclass(frozen=True)
class ModuleView:
    """Comparable view of every public type and its members in a module."""

    types: Tuple[TypeView, ...]
    unresolved: Tuple[UnresolvedIdentity, ...]

    def fingerprints(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for type_view in self.types:
            result[type_view.full_name] = type_view.fingerprint()
            for method in type_view.methods:
                result[f"{type_view.full_name}#M#{method.name}"] = method.fingerprint()
            for field_view in type_view.fields:
                result[f"{type_view.full_name}#F#{field_view.name}"] = field_view.fingerprint()
        return result

    def unresolved_keys(self) -> Tuple[str, ...]:
        return tuple(sorted(item.key() for item in self.unresolved))


def build_signature_view(pe: Any) -> ModuleView:
    """Convenience entry point: build the comparable view from a dnPE."""
    return SignatureView(pe).build()


@dataclass(frozen=True)
class SignatureChange:
    kind: str
    member: str
    left: Optional[str]
    right: Optional[str]

    def describe(self) -> str:
        if self.kind == "changed":
            return f"{self.member}: {self.left}  ->  {self.right}"
        if self.kind == "added":
            return f"{self.member}: added {self.right}"
        return f"{self.member}: removed {self.left}"


def compare_views(left: ModuleView, right: ModuleView) -> Tuple[SignatureChange, ...]:
    """Diff two module views by their heap-independent fingerprints."

    Returns one :class:`SignatureChange` per member whose fingerprint
    differs.  Identical APIs under re-ordered heaps produce an empty tuple.
    """
    left_map = left.fingerprints()
    right_map = right.fingerprints()
    changes: List[SignatureChange] = []
    for member in sorted(set(left_map) | set(right_map)):
        left_value = left_map.get(member)
        right_value = right_map.get(member)
        if left_value == right_value:
            continue
        if left_value is None:
            changes.append(SignatureChange("added", member, None, right_value))
        elif right_value is None:
            changes.append(SignatureChange("removed", member, left_value, None))
        else:
            changes.append(SignatureChange("changed", member, left_value, right_value))
    return tuple(changes)
