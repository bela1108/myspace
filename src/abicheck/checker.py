# -*- coding: utf-8 -*-
"""Read-only ABI responsibility checking for managed assemblies.

The checker answers a narrow question for every caller-supplied entry:

* ``SUPPORTED``        - the old public identity can still be proven present
                         with an equivalent contract;
* ``IDENTITY_CHANGED`` - a public identity demonstrably changed (renamed,
                         removed, re-typed, re-scoped, narrowed in visibility,
                         or given a different parameter/return signature);
* ``UNRESOLVED``       - the metadata alone does not carry enough evidence,
                         typically because a referenced component is missing or
                         not among the approved type sources.

Row order never participates in identity comparison: members are keyed by
their metadata names and interpreted signatures, so table-row reshuffles
between versions produce no difference.

Only dnfile read APIs are used; inspected files are never modified.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import dnfile
from dnfile import enums as clr_enums
from dnfile.mdtable import (
    AssemblyRefRow,
    MethodDefRow,
    TypeDefRow,
    TypeRefRow,
    TypeSpecRow,
)
from dnfile.utils import read_compressed_int

# Coded-index table tags (ECMA-335 II.24.2.6).
TAG_TYPEDEF = 0
TAG_TYPEREF = 1
TAG_TYPESPEC = 2

# Signature element types needed for ordinary method/field signatures.
E_VOID = 0x01
E_BOOLEAN = 0x02
E_CHAR = 0x03
E_I1 = 0x04
E_U1 = 0x05
E_I2 = 0x06
E_U2 = 0x07
E_I4 = 0x08
E_U4 = 0x09
E_I8 = 0x0A
E_U8 = 0x0B
E_R4 = 0x0C
E_R8 = 0x0D
E_STRING = 0x0E
E_PTR = 0x0F
E_BYREF = 0x10
E_VALUETYPE = 0x11
E_CLASS = 0x12
E_VAR = 0x13
E_GENERICINST = 0x15
E_FNPTR = 0x1B
E_OBJECT = 0x1C
E_SZARRAY = 0x1D
E_MVAR = 0x1E
E_CMOD_REQD = 0x1F
E_CMOD_OPT = 0x20
E_INTERNAL = 0x21
E_GENERICARRAY = 0x14
E_TYPEDBYREF = 0x16
E_I = 0x18
E_U = 0x19

_PRIMITIVES = {
    E_VOID: "void",
    E_BOOLEAN: "bool",
    E_CHAR: "char",
    E_I1: "int8",
    E_U1: "uint8",
    E_I2: "int16",
    E_U2: "uint16",
    E_I4: "int32",
    E_U4: "uint32",
    E_I8: "int64",
    E_U8: "uint64",
    E_R4: "float32",
    E_R8: "float64",
    E_STRING: "string",
    E_OBJECT: "object",
    E_TYPEDBYREF: "TypedReference",
    E_I: "nint",
    E_U: "nuint",
}


class Verdict(enum.Enum):
    SUPPORTED = "supported"
    IDENTITY_CHANGED = "identity-changed"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class SupportedTypeSource:
    """An externally defined type source the caller accepts as evidence.

    ``assembly_name`` matches an AssemblyRef name; when omitted, any
    AssemblyRef-backed TypeRef is acceptable. ``type_names`` optionally
    restricts recognition to specific fully qualified type names.
    """

    assembly_name: Optional[str] = None
    type_names: Optional[Tuple[str, ...]] = None


@dataclass(frozen=True)
class EntrySpec:
    """A caller-supplied entry point to hold the maintenance team to."""

    type_name: str
    member_name: Optional[str] = None
    parameter_types: Optional[Tuple[str, ...]] = None

    @property
    def is_type_entry(self) -> bool:
        return self.member_name is None


@dataclass
class EntryVerdict:
    entry: EntrySpec
    verdict: Verdict
    reasons: List[str] = field(default_factory=list)
    old_identity: Optional[str] = None
    new_identity: Optional[str] = None


@dataclass
class AbiReport:
    verdicts: List[EntryVerdict]

    def by_verdict(self, verdict: Verdict) -> List[EntryVerdict]:
        return [item for item in self.verdicts if item.verdict is verdict]


class SignatureError(Exception):
    """Raised when a signature blob cannot be interpreted soundly."""


class _BlobReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def compressed(self) -> int:
        result = read_compressed_int(self.data[self.pos:])
        if result is None:
            raise SignatureError("truncated compressed integer")
        value, size = result
        self.pos += size
        return value

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise SignatureError("truncated signature")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def expect_end(self) -> None:
        if self.pos != len(self.data):
            raise SignatureError("trailing signature bytes")


@dataclass(frozen=True)
class TypeReference:
    """A resolved or unresolved type used inside a signature."""

    text: str
    resolved: bool
    source: Optional[str] = None

    def __str__(self) -> str:
        return self.text


@dataclass(frozen=True)
class MethodSignatureView:
    instance: bool
    generic_param_count: int
    return_type: TypeReference
    parameters: Tuple[TypeReference, ...]
    param_flags: Tuple[int, ...]

    def parameter_key(self) -> Tuple[str, ...]:
        return tuple(parameter.text for parameter in self.parameters)


class AssemblyView:
    """Read-only, comparison-oriented projection of one assembly version."""

    def __init__(
        self,
        pe: dnfile.dnPE,
        label: str,
        approved_sources: Sequence[SupportedTypeSource],
    ):
        self.pe = pe
        self.label = label
        self.approved = list(approved_sources)
        self.mdtables = pe.net.mdtables
        self.type_defs: Dict[str, TypeDefRow] = {}
        self._unresolved: Dict[str, str] = {}
        self._index_types()

    def _index_types(self) -> None:
        if self.mdtables.TypeDef is None:
            return
        for row in self.mdtables.TypeDef.rows:
            name = qualified_name(_as_text(row.TypeNamespace), _as_text(row.TypeName))
            if name and name not in self.type_defs:
                self.type_defs[name] = row

    def unresolved_notes(self) -> List[str]:
        return [f"{key}: {note}" for key, note in sorted(self._unresolved.items())]

    # -- external reference recognition ------------------------------------
    def resolve_typeref(self, row: TypeRefRow) -> Tuple[Optional[str], bool, Optional[str]]:
        """Return (qualified name, resolvable, source label)."""
        name = qualified_name(_as_text(row.TypeNamespace), _as_text(row.TypeName))
        scope = row.ResolutionScope
        source_name: Optional[str] = None
        scope_row = None
        if scope is not None and scope.table is not None:
            try:
                scope_row = scope.row
            except IndexError:
                scope_row = None
        if isinstance(scope_row, AssemblyRefRow):
            source_name = _as_text(scope_row.Name)
        elif scope is not None and (scope.table is None or scope_row is None) and scope.row_index != 0:
            self._unresolved.setdefault(
                name,
                f"TypeRef {name} points at a missing resolution scope component",
            )
            return name, False, source_name
        approved = self._source_approved(name, source_name)
        if not approved:
            self._unresolved.setdefault(
                name,
                f"external type {name}"
                + (f" from {source_name}" if source_name else "")
                + " is not among the approved type sources",
            )
        return name, approved, source_name

    def _source_approved(self, qualified: str, source_name: Optional[str]) -> bool:
        if not self.approved:
            return False
        for source in self.approved:
            if source.assembly_name is not None and source.assembly_name != source_name:
                continue
            if source.type_names is not None and qualified not in source.type_names:
                # The assembly is recognized but this specific type is not on
                # the caller's approved list, so it cannot serve as evidence.
                continue
            return True
        return False

    def resolve_typedef_or_ref(self, coded: Any) -> Tuple[TypeReference, bool]:
        if coded is None or coded.table is None:
            return TypeReference("<unresolved>", False), False
        row = coded.row
        if isinstance(row, TypeDefRow):
            name = qualified_name(_as_text(row.TypeNamespace), _as_text(row.TypeName))
            return TypeReference(name, True, "local"), True
        if isinstance(row, TypeRefRow):
            name, ok, source = self.resolve_typeref(row)
            return TypeReference(name, ok, source), ok
        if isinstance(row, TypeSpecRow):
            self._unresolved.setdefault(
                "<typespec>", "TypeSpec-based reference requires additional blob evidence"
            )
            return TypeReference("<typespec>", False), False
        return TypeReference("<unresolved>", False), False

    # -- signature interpretation ------------------------------------------
    def read_type(self, reader: _BlobReader) -> TypeReference:
        element = reader.byte()
        if element in _PRIMITIVES:
            return TypeReference(_PRIMITIVES[element], True, "builtin")
        if element in (E_BYREF, E_PTR):
            inner = self.read_type(reader)
            return TypeReference(inner.text + ("&" if element == E_BYREF else "*"),
                                 inner.resolved, inner.source)
        if element == E_SZARRAY:
            inner = self.read_type(reader)
            return TypeReference(inner.text + "[]", inner.resolved, inner.source)
        if element in (E_VAR, E_MVAR):
            ordinal = reader.compressed()
            return TypeReference(("!" if element == E_VAR else "!!") + str(ordinal),
                                 True, "generic-var")
        if element in (E_CLASS, E_VALUETYPE):
            coded_value = reader.compressed()
            tag = coded_value & 0x3
            row_index = coded_value >> 2
            ref, ok = self._read_coded_target(tag, row_index)
            prefix = "valuetype " if element == E_VALUETYPE else "class "
            return TypeReference(prefix + ref.text, ok and ref.resolved, ref.source)
        if element == E_GENERICINST:
            kind = reader.byte()
            if kind not in (E_CLASS, E_VALUETYPE):
                raise SignatureError("unexpected generic instantiation kind")
            coded_value = reader.compressed()
            generic_ref, ref_ok = self._read_coded_target(coded_value & 0x3, coded_value >> 2)
            arg_count = reader.compressed()
            args = [self.read_type(reader) for _ in range(arg_count)]
            resolved = ref_ok and generic_ref.resolved and all(arg.resolved for arg in args)
            text = generic_ref.text + "<" + ", ".join(arg.text for arg in args) + ">"
            return TypeReference(text, resolved, generic_ref.source)
        if element in (E_CMOD_REQD, E_CMOD_OPT):
            reader.compressed()  # modifier type coded index; skip its token
            return self.read_type(reader)
        if element == E_INTERNAL:
            reader.byte()
            return self.read_type(reader)
        raise SignatureError(f"unsupported signature element type 0x{element:02x}")

    def _read_coded_target(self, tag: int, row_index: int) -> Tuple[TypeReference, bool]:
        if tag == TAG_TYPEDEF:
            table = self.mdtables.TypeDef
            if table is None or row_index < 1 or row_index > len(table.rows):
                return TypeReference("<missing-typedef>", False), False
            row = table.rows[row_index - 1]
            name = qualified_name(_as_text(row.TypeNamespace), _as_text(row.TypeName))
            return TypeReference(name, True, "local"), True
        if tag == TAG_TYPEREF:
            table = self.mdtables.TypeRef
            if table is None or row_index < 1 or row_index > len(table.rows):
                self._unresolved.setdefault(
                    "<missing-typeref>",
                    "signature references a TypeRef row that does not exist in this metadata",
                )
                return TypeReference("<missing-typeref>", False), False
            name, resolvable, source = self.resolve_typeref(table.rows[row_index - 1])
            return TypeReference(name, resolvable, source), resolvable
        self._unresolved.setdefault(
            "<typespec>", "TypeSpec token inside signature is not supported by the entry evidence"
        )
        return TypeReference("<typespec>", False), False

    def read_method_signature(self, row: MethodDefRow) -> MethodSignatureView:
        blob = _as_blob(row.Signature)
        reader = _BlobReader(blob)
        # The calling convention is a single packed byte (ECMA-335 II.23.2.3),
        # not a blob-compressed integer.
        convention = reader.byte()
        instance = bool(convention & 0x40)
        generic_count = 0
        if convention & 0x10:
            generic_count = reader.compressed()
        param_count = reader.compressed()
        return_type = self.read_type(reader)
        parameters: List[TypeReference] = []
        for _ in range(param_count):
            parameters.append(self.read_type(reader))
        reader.expect_end()
        param_flags = tuple(self._param_flags(row, index) for index in range(1, param_count + 1))
        return MethodSignatureView(
            instance=instance,
            generic_param_count=generic_count,
            return_type=return_type,
            parameters=tuple(parameters),
            param_flags=param_flags,
        )

    @staticmethod
    def _param_flags(row: MethodDefRow, sequence: int) -> int:
        for param_index in row.ParamList or []:
            param = param_index.row if hasattr(param_index, "row") else param_index
            if param is None:
                continue
            if getattr(param, "Sequence", 0) == sequence:
                return int(param.struct.Flags)
        return 0


def qualified_name(namespace: str, name: str) -> str:
    return f"{namespace}.{name}" if namespace else name


def _as_text(value: Any) -> str:
    """Normalize dnfile heap items or plain values to a comparable string."""
    if value is None:
        return ""
    return str(value)


def _as_blob(value: Any) -> bytes:
    """Return the payload bytes of a #Blob heap item (without its length prefix)."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    # HeapItemBinary.value_bytes() strips the compressed length prefix.
    payload = getattr(value, "value_bytes", None)
    if callable(payload):
        return payload()
    raw = getattr(value, "value", None)
    if isinstance(raw, bytes):
        return raw
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise SignatureError("unrecognised blob heap item")


def type_visibility(flags: int) -> int:
    visibility = flags & 0x00000007
    if visibility in (0x0, 0x1):  # NotPublic / Public
        return visibility
    # nested types reuse the 0..7 band with different semantics; keep the raw
    # value so same-vs-different comparisons remain accurate.
    return visibility


def method_visibility(flags: int) -> int:
    return flags & int(clr_enums.CorMethodAttr.mdMemberAccessMask)


_TYPE_VISIBILITY_RANK = {
    0x0: 1,  # NotPublic
    0x1: 6,  # Public
    0x2: 5,  # NestedPublic
    0x3: 1,  # NestedPrivate
    0x4: 3,  # NestedFamily
    0x5: 2,  # NestedFamANDAssem
    0x6: 2,  # NestedAssembly
    0x7: 4,  # NestedFamORAssem
}

_METHOD_VISIBILITY_RANK = {
    0x0: 0,  # PrivateScope
    0x1: 1,  # Private
    0x2: 2,  # FamANDAssem
    0x3: 2,  # Assembly
    0x4: 3,  # Family
    0x5: 4,  # FamORAssem
    0x6: 5,  # Public
}


class _TypeAnalysis:
    """Cached per-type interpretation shared across entry checks."""

    def __init__(self, view: AssemblyView, row: TypeDefRow):
        self.view = view
        self.row = row
        self.name = qualified_name(_as_text(row.TypeNamespace), _as_text(row.TypeName))
        self.methods: Dict[str, List[MethodDefRow]] = {}
        for method_index in row.MethodList or []:
            method_row = method_index.row if hasattr(method_index, "row") else method_index
            if method_row is None:
                continue
            self.methods.setdefault(_as_text(method_row.Name), []).append(method_row)
        self.base_name: Optional[str] = None
        self.base_resolved = True
        self._analyse_base()

    def _analyse_base(self) -> None:
        coded = self.row.Extends
        if coded is None or coded.table is None or coded.row_index == 0:
            self.base_name = None
            return
        ref, ok = self.view.resolve_typedef_or_ref(coded)
        self.base_name = ref.text
        self.base_resolved = ok and ref.resolved

    def visibility(self) -> int:
        return type_visibility(int(self.row.struct.Flags))


def _open_view(
    source: Union[str, Path, bytes, dnfile.dnPE],
    label: str,
    approved_sources: Sequence[SupportedTypeSource],
) -> AssemblyView:
    if isinstance(source, dnfile.dnPE):
        pe = source
    elif isinstance(source, (bytes, bytearray)):
        pe = dnfile.dnPE(data=bytes(source))
    else:
        # dnfile opens the file itself; no write handle is requested.
        pe = dnfile.dnPE(str(source))
    if pe.net is None or pe.net.mdtables is None:
        raise SignatureError(f"{label}: not a managed assembly with metadata tables")
    return AssemblyView(pe, label, approved_sources)


def compare_assemblies(
    old_source: Union[str, Path, bytes, dnfile.dnPE],
    new_source: Union[str, Path, bytes, dnfile.dnPE],
    entries: Sequence[EntrySpec],
    approved_sources: Sequence[SupportedTypeSource] = (),
) -> AbiReport:
    """Compare two read-only assembly views for the supplied entry list."""
    old = _open_view(old_source, "old", approved_sources)
    new = _open_view(new_source, "new", approved_sources)

    old_types = {name: _TypeAnalysis(old, row) for name, row in old.type_defs.items()}
    new_types = {name: _TypeAnalysis(new, row) for name, row in new.type_defs.items()}

    verdicts = [_check_entry(entry, old, new, old_types, new_types) for entry in entries]
    return AbiReport(verdicts=verdicts)


def _check_entry(
    entry: EntrySpec,
    old: AssemblyView,
    new: AssemblyView,
    old_types: Dict[str, _TypeAnalysis],
    new_types: Dict[str, _TypeAnalysis],
) -> EntryVerdict:
    if entry.is_type_entry:
        return _check_type_entry(entry, old, new, old_types, new_types)
    return _check_method_entry(entry, old, new, old_types, new_types)


def _check_type_entry(
    entry: EntrySpec,
    old: AssemblyView,
    new: AssemblyView,
    old_types: Dict[str, _TypeAnalysis],
    new_types: Dict[str, _TypeAnalysis],
) -> EntryVerdict:
    old_type = old_types.get(entry.type_name)
    if old_type is None:
        return EntryVerdict(
            entry,
            Verdict.UNRESOLVED,
            [f"entry type {entry.type_name} is absent from the old metadata; no baseline identity to compare"],
        )
    new_type = new_types.get(entry.type_name)
    if new_type is None:
        return EntryVerdict(
            entry,
            Verdict.IDENTITY_CHANGED,
            [f"public type {entry.type_name} no longer exists in the new assembly"],
            old_identity=entry.type_name,
        )

    reasons: List[str] = []
    unresolved: List[str] = []
    if not old_type.base_resolved or not new_type.base_resolved:
        unresolved.append(
            f"base type of {entry.type_name} references a missing or unapproved component"
        )
    elif old_type.base_name != new_type.base_name:
        reasons.append(
            f"base type changed from {old_type.base_name} to {new_type.base_name}"
        )

    old_rank = _TYPE_VISIBILITY_RANK.get(old_type.visibility(), 0)
    new_rank = _TYPE_VISIBILITY_RANK.get(new_type.visibility(), 0)
    # unknown visibility bands conservatively rank as most-restrictive
    if old_type.visibility() != new_type.visibility():
        if new_rank < old_rank:
            reasons.append(
                f"type visibility narrowed (0x{old_type.visibility():x} -> 0x{new_type.visibility():x})"
            )
        else:
            reasons.append(
                f"type visibility widened (0x{old_type.visibility():x} -> 0x{new_type.visibility():x})"
            )

    if unresolved:
        return EntryVerdict(
            entry, Verdict.UNRESOLVED, unresolved + reasons,
            old_identity=entry.type_name, new_identity=entry.type_name,
        )
    if reasons:
        return EntryVerdict(
            entry, Verdict.IDENTITY_CHANGED, reasons,
            old_identity=entry.type_name, new_identity=entry.type_name,
        )
    return EntryVerdict(
        entry,
        Verdict.SUPPORTED,
        ["type identity, base type and visibility match (row position ignored)"],
        old_identity=entry.type_name,
        new_identity=entry.type_name,
    )


def _check_method_entry(
    entry: EntrySpec,
    old: AssemblyView,
    new: AssemblyView,
    old_types: Dict[str, _TypeAnalysis],
    new_types: Dict[str, _TypeAnalysis],
) -> EntryVerdict:
    assert entry.member_name is not None
    old_type = old_types.get(entry.type_name)
    if old_type is None:
        return EntryVerdict(
            entry,
            Verdict.UNRESOLVED,
            [f"declaring type {entry.type_name} is absent from the old metadata; no baseline identity"],
        )
    new_type = new_types.get(entry.type_name)
    if new_type is None:
        return EntryVerdict(
            entry,
            Verdict.IDENTITY_CHANGED,
            [f"declaring type {entry.type_name} no longer exists, so member {entry.member_name} is gone"],
            old_identity=_member_id(entry.type_name, entry.member_name),
        )

    old_candidates = _select_overloads(old, old_type, entry)
    if isinstance(old_candidates, str):
        return EntryVerdict(entry, Verdict.UNRESOLVED, [old_candidates])
    new_candidates = _select_overloads(new, new_type, entry)
    if isinstance(new_candidates, str):
        return EntryVerdict(entry, Verdict.UNRESOLVED, [new_candidates])

    if not old_candidates:
        return EntryVerdict(
            entry,
            Verdict.UNRESOLVED,
            [f"member {entry.member_name} is not declared on {entry.type_name} in the old metadata"
             " and inherited members cannot be enumerated without their defining component"],
        )

    old_views = _interpret_methods(old, old_candidates)
    if isinstance(old_views, str):
        return EntryVerdict(entry, Verdict.UNRESOLVED, [old_views])
    new_views = _interpret_methods(new, new_candidates)
    if isinstance(new_views, str):
        return EntryVerdict(entry, Verdict.UNRESOLVED, [new_views])

    wanted = entry.parameter_types
    if wanted is not None:
        scoped_old = [pair for pair in old_views if pair[1].parameter_key() == tuple(wanted)]
        if not scoped_old:
            return EntryVerdict(
                entry,
                Verdict.IDENTITY_CHANGED,
                [f"no overload of {entry.member_name} matches parameter types {list(wanted)}"
                 " in the old assembly (re-check the entry list)"],
            )
        old_views = scoped_old

    identity = _member_id(entry.type_name, entry.member_name)
    if not new_views:
        return EntryVerdict(
            entry,
            Verdict.IDENTITY_CHANGED,
            [f"member {identity} is missing from the new assembly"],
            old_identity=identity,
        )

    new_by_key: Dict[Tuple[str, ...], List[Tuple[MethodDefRow, MethodSignatureView]]] = {}
    for method, signature in new_views:
        new_by_key.setdefault(signature.parameter_key(), []).append((method, signature))

    for old_method, old_sig in old_views:
        key_candidates = new_by_key.get(old_sig.parameter_key(), [])
        if not key_candidates:
            return EntryVerdict(
                entry,
                Verdict.IDENTITY_CHANGED,
                [_describe_signature_drift(identity, old_views, new_views)],
                old_identity=identity,
                new_identity=identity,
            )
        match = _find_signature_match(old_sig, key_candidates)
        if match is None:
            # Same parameter types but return type, calling convention or
            # parameter direction changed: the public identity moved.
            new_method, new_sig = key_candidates[0]
            drift = (
                f"signature of {identity} changed "
                f"(old return {old_sig.return_type.text}, new return {new_sig.return_type.text})"
                if old_sig.return_type.text != new_sig.return_type.text
                else _describe_signature_drift(identity, old_views, new_views)
            )
            return EntryVerdict(
                entry, Verdict.IDENTITY_CHANGED, [drift],
                old_identity=identity, new_identity=identity,
            )
        new_method, new_sig = match
        if not _all_types_resolved(old_sig) or not _all_types_resolved(new_sig):
            return EntryVerdict(
                entry,
                Verdict.UNRESOLVED,
                [f"signature of {identity} references a missing or unapproved component"],
                old_identity=identity,
                new_identity=identity,
            )
        reasons: List[str] = []
        old_vis = method_visibility(int(old_method.struct.Flags))
        new_vis = method_visibility(int(new_method.struct.Flags))
        if old_vis != new_vis:
            if _METHOD_VISIBILITY_RANK.get(new_vis, 0) < _METHOD_VISIBILITY_RANK.get(old_vis, 0):
                reasons.append(
                    f"visibility narrowed (0x{old_vis:x} -> 0x{new_vis:x}); callers may lose access"
                )
            else:
                reasons.append(
                    f"visibility widened (0x{old_vis:x} -> 0x{new_vis:x}); public contract retained"
                )
        if any("narrowed" in note for note in reasons):
            return EntryVerdict(
                entry, Verdict.IDENTITY_CHANGED, reasons,
                old_identity=identity, new_identity=identity,
            )
        return EntryVerdict(
            entry,
            Verdict.SUPPORTED,
            reasons or ["name, parameter signature, return type and visibility match (row position ignored)"],
            old_identity=identity,
            new_identity=identity,
        )

    return EntryVerdict(
        entry,
        Verdict.IDENTITY_CHANGED,
        [_describe_signature_drift(identity, old_views, new_views)],
        old_identity=identity,
        new_identity=identity,
    )


def _select_overloads(
    view: AssemblyView,
    analysis: _TypeAnalysis,
    entry: EntrySpec,
) -> Union[List[MethodDefRow], str]:
    rows = analysis.methods.get(entry.member_name or "", [])
    if rows:
        return rows
    # Declared members take precedence.  Inheritance from another assembly
    # cannot be proven here because that component's tables are not available.
    if not analysis.base_resolved:
        return (
            f"member {entry.member_name} is not declared on {entry.type_name} and its base type "
            "references a missing or unapproved component"
        )
    return []


def _interpret_methods(
    view: AssemblyView, rows: Sequence[MethodDefRow]
) -> Union[List[Tuple[MethodDefRow, MethodSignatureView]], str]:
    interpreted: List[Tuple[MethodDefRow, MethodSignatureView]] = []
    for row in rows:
        try:
            interpreted.append((row, view.read_method_signature(row)))
        except SignatureError as exc:
            return f"cannot interpret signature of {row.name}: {exc}"
    return interpreted


def _find_signature_match(
    target: MethodSignatureView,
    candidates: Sequence[Tuple[MethodDefRow, MethodSignatureView]],
) -> Optional[Tuple[MethodDefRow, MethodSignatureView]]:
    for method, signature in candidates:
        if (
            signature.instance == target.instance
            and signature.generic_param_count == target.generic_param_count
            and signature.parameter_key() == target.parameter_key()
            and signature.return_type.text == target.return_type.text
            and signature.param_flags == target.param_flags
        ):
            return method, signature
    return None


def _all_types_resolved(signature: MethodSignatureView) -> bool:
    if not signature.return_type.resolved:
        return False
    return all(parameter.resolved for parameter in signature.parameters)


def _describe_signature_drift(
    identity: str,
    old_views: Sequence[Tuple[MethodDefRow, MethodSignatureView]],
    new_views: Sequence[Tuple[MethodDefRow, MethodSignatureView]],
) -> str:
    old_keys = sorted({sig.parameter_key() and ", ".join(sig.parameter_key()) for _, sig in old_views})
    new_keys = sorted({sig.parameter_key() and ", ".join(sig.parameter_key()) for _, sig in new_views})
    return (
        f"parameter/return signature of {identity} changed "
        f"(old parameters: {old_keys}; new parameters: {new_keys})"
    )


def _member_id(type_name: str, member_name: str) -> str:
    return f"{type_name}::{member_name}"
