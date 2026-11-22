# -*- coding: utf-8 -*-
"""
Read-only managed ABI checks for .NET assemblies.

This module intentionally does not execute, load, or rewrite either input
assembly.  It uses :mod:`dnfile` to read the metadata tables and compares
public interfaces by their *metadata identity* (declaring type, member name,
signature, visibility), never by a metadata table row number.  Consequently,
rows moving within the TypeDef/MethodDef/Field tables are not reported as API
changes.

The three externally relevant outcomes are:

``supported``
    The old interface is present with the same identity and no narrowing of
    its externally observable visibility.

``changed``
    The old interface identity changed, was removed, or became less visible.

``unresolved``
    Evidence is insufficient.  Typically this means a reference escaped into
    an assembly/module that was not supplied as an approved type source.  In
    that situation the module deliberately does not make a supported/changed
    claim.

Example
-------

.. code-block:: python

    import dnfile.abi

    report = dnfile.abi.audit_abi(
        "old.dll",
        "new.dll",
        entrypoints=[
            "Example.Widget::Render",
            "Example.Widget::Color",
        ],
        approved_sources=["System.Runtime.dll"],
    )
    print(report.summary)

The public entry point is :func:`audit_abi`.  :func:`compare_assemblies`,
:func:`compare_abi`, :func:`check_abi`, and :func:`diff_abi` are aliases that
are useful for callers that prefer those names.

ECMA-335 references used by the signature decoder:

* II.23.1.16 - Element types used in signatures
* II.23.2.1 - Method signature calling conventions
* II.23.2.6 - TypeDefOrRef encoded indexes
* II.23.2.12 - Class, valuetype, generic instantiations, arrays, and byrefs
"""
from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import os
import re
import struct
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple, Union

import dnfile


__all__ = [
    "AbiStatus",
    "Status",
    "InterfaceStatus",
    "MissingReference",
    "SignatureInfo",
    "TypeRefInfo",
    "EntryPoint",
    "EntrySpec",
    "AuditResult",
    "AbiResult",
    "Finding",
    "AbiReport",
    "AuditReport",
    "AbiAuditor",
    "AbiAudit",
    "audit_abi",
    "audit",
    "abi_audit",
    "compare_assemblies",
    "compare_abi",
    "check_abi",
    "diff_abi",
    "audit_compatibility",
    "check_compatibility",
    "compare_versions",
    "analyze_abi",
    "compare_api",
    "abi_diff",
    "check_public_api",
    "audit_assembly_pair",
    "compare_managed_assemblies",
    "AbiChecker",
    "AbiCompatibilityChecker",
    "main",
]


class AbiStatus(str, enum.Enum):
    """Outcome of checking one old interface."""

    SUPPORTED = "supported"
    CHANGED = "changed"
    UNRESOLVED = "unresolved"

    # Common synonyms.  Enum aliases retain the canonical value, so
    # ``AbiStatus.IDENTITY_CHANGED == "changed"`` and
    # ``AbiStatus.INDETERMINATE == "unresolved"``.
    IDENTITY_CHANGED = "changed"
    REMOVED = "changed"
    BREAKING = "changed"
    INDETERMINATE = "unresolved"
    INSUFFICIENT_EVIDENCE = "unresolved"
    UNKNOWN = "unresolved"

    @property
    def label(self) -> str:
        return self.value

    @property
    def is_supported(self) -> bool:
        return self.value == "supported"

    @property
    def is_changed(self) -> bool:
        return self.value == "changed"

    @property
    def is_unresolved(self) -> bool:
        return self.value == "unresolved"

    def __str__(self) -> str:
        return self.value

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            candidate = other.strip().lower().replace("-", "_").replace(" ", "_")
            synonyms = {
                "supported": {"supported", "ok", "compatible", "unchanged", "still_supported"},
                "changed": {"changed", "identity_changed", "breaking", "removed", "incompatible"},
                "unresolved": {"unresolved", "indeterminate", "unknown", "insufficient_evidence", "needs_evidence"},
            }
            if candidate in synonyms[self.value]:
                return True
        return super().__eq__(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self.value)


# Short aliases used by the report/result objects.
Status = AbiStatus
InterfaceStatus = AbiStatus


_VISIBILITY_RANK = {
    "private_scope": 0,
    "private": 0,
    "private_protected": 1,
    "internal": 2,
    "protected": 3,
    "protected_internal": 4,
    "public": 5,
    "unknown": -1,
}

_TYPE_VISIBILITY = {
    0: "internal",          # tdNotPublic
    1: "public",            # tdPublic
    2: "public",            # tdNestedPublic
    3: "private",           # tdNestedPrivate
    4: "protected",         # tdNestedFamily
    5: "internal",          # tdNestedAssembly
    6: "private_protected", # tdNestedFamANDAssem
    7: "protected_internal",# tdNestedFamORAssem
}

_METHOD_VISIBILITY = {
    0: "private_scope",
    1: "private",
    2: "private_protected",
    3: "internal",
    4: "protected",
    5: "protected_internal",
    6: "public",
    7: "unknown",
}

_FIELD_VISIBILITY = {
    0: "private_scope",
    1: "private",
    2: "private_protected",
    3: "internal",
    4: "protected",
    5: "protected_internal",
    6: "public",
    7: "unknown",
}

_MD_METHOD_STATIC = 0x0010
_MD_FIELD_STATIC = 0x0010

_MISSING = object()


def _visibility_rank(value: Optional[str]) -> int:
    return _VISIBILITY_RANK.get(value or "unknown", -1)


def _is_externally_visible(value: Optional[str], include_protected: bool = True) -> bool:
    rank = _visibility_rank(value)
    minimum = _visibility_rank("protected") if include_protected else _visibility_rank("public")
    return rank >= minimum


def _visibility_narrowed(old: Optional[str], new: Optional[str]) -> bool:
    return _visibility_rank(new) < _visibility_rank(old)


def _normalize_type_name(name: str) -> str:
    """Normalize harmless spelling differences in a full type name.

    Nested types may be written either as ``Outer+Inner`` (reflection
    spelling) or ``Outer.Inner`` (C# spelling).  We index both.
    """

    name = name.strip()
    if name.startswith("[") and "]" in name:
        name = name.split("]", 1)[1]
    return name.replace("/", "+")


def _normalize_member_hint(text: Any) -> Optional[str]:
    if text is None:
        return None
    if isinstance(text, (list, tuple)):
        parts = []
        for item in text:
            if isinstance(item, Mapping):
                item = item.get("type") or item.get("name") or item
            parts.append(str(item))
        text = ",".join(parts)
    elif isinstance(text, Mapping):
        text = text.get("types") or text.get("parameters") or text
        if isinstance(text, (list, tuple)):
            return _normalize_member_hint(text)
        text = str(text)
    if not str(text).strip():
        return None
    return re.sub(r"\s+", "", str(text))


@dataclasses.dataclass
class MissingReference:
    """A reference that could not be resolved from the supplied evidence."""

    kind: str
    name: str
    assembly: Optional[str] = None
    reason: str = "reference target unavailable"
    source: Optional[str] = None

    def __str__(self) -> str:
        where = ""
        if self.assembly:
            where = "[%s]" % self.assembly
        return "%s:%s%s" % (self.kind, where, self.name)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def as_dict(self) -> Dict[str, Any]:
        return self.to_dict()


@dataclasses.dataclass
class TypeRefInfo:
    """A decoded type reference, with resolution evidence attached."""

    display: str
    full_name: Optional[str] = None
    assembly: Optional[str] = None
    resolved: bool = True
    local: bool = False
    source: Optional[str] = None
    missing: List[MissingReference] = dataclasses.field(default_factory=list)
    generic_args: Tuple["TypeRefInfo", ...] = ()
    element_kind: str = "named"
    source_type: Any = dataclasses.field(default=None, repr=False)
    source_model: Any = dataclasses.field(default=None, repr=False)
    dependencies: Tuple["TypeRefInfo", ...] = ()

    def __str__(self) -> str:
        return self.display

    @property
    def unresolved(self) -> List[MissingReference]:
        result = list(self.missing)
        for arg in self.generic_args:
            result.extend(arg.unresolved)
        for dependency in self.dependencies:
            result.extend(dependency.unresolved)
        return _unique_missing(result)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "display": self.display,
            "full_name": self.full_name,
            "assembly": self.assembly,
            "resolved": self.resolved and not self.unresolved,
            "local": self.local,
            "source": self.source,
            "element_kind": self.element_kind,
            "generic_args": [a.to_dict() for a in self.generic_args],
            "missing": [m.to_dict() for m in self.unresolved],
        }


@dataclasses.dataclass
class SignatureInfo:
    """A decoded method, field, property, or event signature."""

    kind: str
    display: str
    identity: str
    return_type: Optional[TypeRefInfo] = None
    parameters: List[TypeRefInfo] = dataclasses.field(default_factory=list)
    calling_convention: Optional[str] = None
    generic_parameter_count: int = 0
    has_this: bool = False
    sentinel_index: Optional[int] = None
    valid: bool = True
    error: Optional[str] = None
    missing: List[MissingReference] = dataclasses.field(default_factory=list)

    @property
    def unresolved(self) -> List[MissingReference]:
        result = list(self.missing)
        if self.return_type is not None:
            result.extend(self.return_type.unresolved)
        for parameter in self.parameters:
            result.extend(parameter.unresolved)
        return _unique_missing(result)

    @property
    def parameter_types(self) -> List[str]:
        return [p.display for p in self.parameters]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "display": self.display,
            "identity": self.identity,
            "return_type": self.return_type.display if self.return_type else None,
            "parameters": [p.display for p in self.parameters],
            "calling_convention": self.calling_convention,
            "generic_parameter_count": self.generic_parameter_count,
            "has_this": self.has_this,
            "valid": self.valid,
            "error": self.error,
            "missing": [m.to_dict() for m in self.unresolved],
        }


@dataclasses.dataclass
class MemberModel:
    kind: str
    name: str
    declaring_type: "TypeModel"
    visibility: str
    identity: str
    signature: SignatureInfo
    row: Any = dataclasses.field(default=None, repr=False)
    flags: int = 0
    accessors: Dict[str, "MemberModel"] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "declaring_type": self.declaring_type.full_name,
            "visibility": self.visibility,
            "identity": self.identity,
            "signature": self.signature.to_dict(),
            "accessors": {name: member.to_dict() for name, member in self.accessors.items()},
        }

    @property
    def signature_display(self) -> str:
        return self.signature.display

    @property
    def unresolved(self) -> List[MissingReference]:
        return self.signature.unresolved


@dataclasses.dataclass
class EffectiveMember:
    """A member as seen through a type, possibly inherited from a base type."""

    member: MemberModel
    declaring_type: "TypeModel"
    inherited_from: List[str] = dataclasses.field(default_factory=list)
    depth: int = 0
    compat_identity: Optional[str] = None

    @property
    def identity(self) -> str:
        return self.member.identity

    @property
    def compatibility_identity(self) -> str:
        """Declaration-independent identity used to follow inherited members."""
        if self.compat_identity is not None:
            return self.compat_identity
        return _member_compat_identity(self.member, self.member.signature)

    @property
    def kind(self) -> str:
        return self.member.kind

    @property
    def name(self) -> str:
        return self.member.name

    @property
    def visibility(self) -> str:
        return self.member.visibility

    @property
    def signature(self) -> SignatureInfo:
        return self.member.signature

    def to_dict(self) -> Dict[str, Any]:
        data = self.member.to_dict()
        data["inherited_from"] = list(self.inherited_from)
        data["depth"] = self.depth
        return data


@dataclasses.dataclass
class TypeModel:
    model: "_AssemblyModel"
    row_index: int
    namespace: str
    name: str
    full_name: str
    visibility: str
    effective_visibility: str
    flags: int
    base_ref: Optional[TypeRefInfo] = None
    interfaces: List[TypeRefInfo] = dataclasses.field(default_factory=list)
    declared_members: List[MemberModel] = dataclasses.field(default_factory=list)
    enclosing_type: Optional["TypeModel"] = None
    row: Any = dataclasses.field(default=None, repr=False)

    @property
    def is_interface(self) -> bool:
        return bool(self.flags & 0x20)

    @property
    def is_public(self) -> bool:
        return _is_externally_visible(self.effective_visibility)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "full_name": self.full_name,
            "namespace": self.namespace,
            "name": self.name,
            "visibility": self.visibility,
            "effective_visibility": self.effective_visibility,
            "is_interface": self.is_interface,
            "base": self.base_ref.to_dict() if self.base_ref else None,
            "interfaces": [i.to_dict() for i in self.interfaces],
            "members": [m.to_dict() for m in self.declared_members],
        }


@dataclasses.dataclass
class EntrySpec:
    """A normalized caller-provided entry-point specification."""

    raw: Any
    type_name: Optional[str] = None
    member_name: Optional[str] = None
    kind: Optional[str] = None
    signature_hint: Optional[str] = None

    @property
    def is_type_entry(self) -> bool:
        return self.member_name is None

    @property
    def display_name(self) -> str:
        if self.type_name and self.member_name:
            return "%s::%s" % (self.type_name, self.member_name)
        return self.type_name or str(self.raw)


EntryPoint = EntrySpec


def _json_entry(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool, type(None), list, tuple, dict)):
        return value
    display = getattr(value, "display_name", None)
    if display is not None:
        return str(display)
    return str(value)


@dataclasses.dataclass
class AuditResult:
    """The result of checking one entry point."""

    entry: Any
    name: str
    kind: str
    status: AbiStatus
    reason: str
    old_identity: Optional[str] = None
    new_identity: Optional[str] = None
    declaring_type: Optional[str] = None
    member_name: Optional[str] = None
    old_visibility: Optional[str] = None
    new_visibility: Optional[str] = None
    signature: Optional[Dict[str, Any]] = None
    old: Optional[Dict[str, Any]] = None
    new: Optional[Dict[str, Any]] = None
    changes: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    inherited_from: Optional[List[str]] = None
    unresolved: List[MissingReference] = dataclasses.field(default_factory=list)
    details: Dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def is_supported(self) -> bool:
        return self.status == AbiStatus.SUPPORTED

    @property
    def is_changed(self) -> bool:
        return self.status == AbiStatus.CHANGED

    @property
    def is_unresolved(self) -> bool:
        return self.status == AbiStatus.UNRESOLVED

    @property
    def compatible(self) -> bool:
        return self.is_supported

    @property
    def breaking(self) -> bool:
        return self.is_changed

    @property
    def indeterminate(self) -> bool:
        return self.is_unresolved

    @property
    def conclusion(self) -> str:
        return self.status.value

    @property
    def supported(self) -> bool:
        return self.is_supported

    @property
    def changed(self) -> bool:
        return self.is_changed

    @property
    def identity_changed(self) -> bool:
        return self.is_changed

    @property
    def removed(self) -> bool:
        return any(
            change.get("kind") in ("member_removed", "type_removed", "overload_removed")
            for change in self.changes
        )

    @property
    def missing(self) -> List[MissingReference]:
        return self.unresolved

    @property
    def evidence(self) -> Dict[str, Any]:
        return self.details

    @property
    def visibility_changed(self) -> bool:
        return any(change.get("kind") == "visibility" for change in self.changes)

    @property
    def signature_changed(self) -> bool:
        return any(
            change.get("kind") in (
                "signature", "parameter_type", "parameter_count", "return_type",
                "calling_convention", "generic_arity",
            )
            for change in self.changes
        )

    @property
    def inheritance(self) -> Optional[Dict[str, Any]]:
        value = self.details.get("inheritance")
        return value if isinstance(value, dict) else None

    @property
    def message(self) -> str:
        return self.reason

    def __str__(self) -> str:
        return "%s: %s (%s)" % (self.name, self.status.value, self.reason)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry": _json_entry(self.entry),
            "name": self.name,
            "kind": self.kind,
            "status": self.status.value,
            "reason": self.reason,
            "old_identity": self.old_identity,
            "new_identity": self.new_identity,
            "declaring_type": self.declaring_type,
            "member_name": self.member_name,
            "old_visibility": self.old_visibility,
            "new_visibility": self.new_visibility,
            "signature": self.signature,
            "old": self.old,
            "new": self.new,
            "changes": list(self.changes),
            "inherited_from": self.inherited_from,
            "unresolved": [m.to_dict() for m in self.unresolved],
            "details": self.details,
        }

    def as_dict(self) -> Dict[str, Any]:
        return self.to_dict()

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


AbiResult = AuditResult
Finding = AuditResult


class AbiReport:
    """An ordered collection of :class:`AuditResult` objects."""

    def __init__(
        self,
        results: Optional[Iterable[AuditResult]] = None,
        *,
        old_assembly: Optional[str] = None,
        new_assembly: Optional[str] = None,
        warnings: Optional[Iterable[str]] = None,
    ):
        self.results: List[AuditResult] = list(results or [])
        self.old_assembly = old_assembly
        self.new_assembly = new_assembly
        self.warnings: List[str] = list(warnings or [])

    @property
    def entries(self) -> List[AuditResult]:
        return self.results

    @property
    def findings(self) -> List[AuditResult]:
        return self.results

    @property
    def supported(self) -> List[AuditResult]:
        return [r for r in self.results if r.status == AbiStatus.SUPPORTED]

    @property
    def changed(self) -> List[AuditResult]:
        return [r for r in self.results if r.status == AbiStatus.CHANGED]

    @property
    def unresolved(self) -> List[AuditResult]:
        return [r for r in self.results if r.status == AbiStatus.UNRESOLVED]

    # Status-specific aliases.
    @property
    def identity_changed(self) -> List[AuditResult]:
        return self.changed

    @property
    def indeterminate(self) -> List[AuditResult]:
        return self.unresolved

    @property
    def supported_names(self) -> List[str]:
        return [r.name for r in self.supported]

    @property
    def changed_names(self) -> List[str]:
        return [r.name for r in self.changed]

    @property
    def unresolved_names(self) -> List[str]:
        return [r.name for r in self.unresolved]

    @property
    def counts(self) -> Dict[str, int]:
        return {
            "supported": len(self.supported),
            "changed": len(self.changed),
            "unresolved": len(self.unresolved),
            "total": len(self.results),
        }

    @property
    def summary(self) -> str:
        counts = self.counts
        return "%d supported, %d changed, %d unresolved (%d checked)" % (
            counts["supported"],
            counts["changed"],
            counts["unresolved"],
            counts["total"],
        )

    @property
    def status(self) -> AbiStatus:
        if self.changed:
            return AbiStatus.CHANGED
        if self.unresolved:
            return AbiStatus.UNRESOLVED
        return AbiStatus.SUPPORTED

    @property
    def ok(self) -> bool:
        return not self.changed and not self.unresolved

    @property
    def all_supported(self) -> bool:
        return bool(self.results) and all(r.status == AbiStatus.SUPPORTED for r in self.results)

    def by_name(self, name: str) -> Optional[AuditResult]:
        normalized = _normalize_type_name(name)
        for result in self.results:
            candidates = [result.name]
            if isinstance(result.entry, str):
                candidates.append(result.entry)
                candidates.append(result.entry.strip())
            for candidate in candidates:
                if candidate == name or _normalize_type_name(candidate) == normalized:
                    return result
        return None

    def find(self, name: str) -> Optional[AuditResult]:
        return self.by_name(name)

    def by_entry(self, name: str) -> Optional[AuditResult]:
        return self.by_name(name)

    def lookup(self, name: str) -> Optional[AuditResult]:
        return self.by_name(name)

    @property
    def status_counts(self) -> Dict[str, int]:
        return self.counts

    def __iter__(self) -> Iterator[AuditResult]:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __bool__(self) -> bool:
        return bool(self.results)

    def __getitem__(self, key: Union[int, slice, str]) -> Any:
        if isinstance(key, (int, slice)):
            return self.results[key]
        if key in ("supported", "changed", "unresolved"):
            return getattr(self, key)
        if key == "counts":
            return self.counts
        if key in ("results", "entries", "findings"):
            return self.results
        if key in ("summary", "status"):
            return getattr(self, key)
        result = self.by_name(key)
        if result is None:
            raise KeyError(key)
        return result

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self) -> Dict[str, Any]:
        return {
            "old_assembly": self.old_assembly,
            "new_assembly": self.new_assembly,
            "summary": self.summary,
            "counts": self.counts,
            "warnings": list(self.warnings),
            "supported_names": self.supported_names,
            "changed_names": self.changed_names,
            "unresolved_names": self.unresolved_names,
            "supported": [r.to_dict() for r in self.supported],
            "changed": [r.to_dict() for r in self.changed],
            "unresolved": [r.to_dict() for r in self.unresolved],
            "results": [r.to_dict() for r in self.results],
        }

    def as_dict(self) -> Dict[str, Any]:
        return self.to_dict()

    def to_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("indent", 2)
        kwargs.setdefault("sort_keys", True)
        return json.dumps(self.to_dict(), **kwargs)

    def format_text(self) -> str:
        lines = []
        if self.old_assembly or self.new_assembly:
            lines.append("old: %s" % (self.old_assembly or "<unknown>"))
            lines.append("new: %s" % (self.new_assembly or "<unknown>"))
        for result in self.results:
            lines.append("[%s] %s: %s" % (result.status.value, result.name, result.reason))
            if result.old_identity and result.old_identity != result.new_identity:
                lines.append("  old: %s" % result.old_identity)
                lines.append("  new: %s" % (result.new_identity or "<none>"))
            for missing in result.unresolved:
                lines.append("  missing: %s" % missing)
        lines.append(self.summary)
        return "\n".join(lines)


AuditReport = AbiReport


class AbiAuditError(ValueError):
    pass


class _SignatureError(ValueError):
    pass


def _unique_missing(items: Iterable[MissingReference]) -> List[MissingReference]:
    result: List[MissingReference] = []
    seen: Set[Tuple[str, str, Optional[str], str]] = set()
    for item in items:
        key = (item.kind, item.name, item.assembly, item.reason)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _unique_missing_from_types(items: Iterable[TypeRefInfo]) -> List[MissingReference]:
    result: List[MissingReference] = []
    for item in items:
        result.extend(item.unresolved)
    return _unique_missing(result)


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "replace")
        except Exception:
            return repr(value)
    return str(value)



def _as_blob_bytes(value: Any) -> Optional[bytes]:
    """Normalize blob-heap wrappers (e.g. HeapItemBinary) to raw bytes."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin1", "replace")
    value_bytes = getattr(value, "value_bytes", None)
    if callable(value_bytes):
        try:
            data = value_bytes()
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
        except Exception:
            pass
    inner = getattr(value, "value", None)
    if isinstance(inner, (bytes, bytearray)):
        return bytes(inner)
    if isinstance(inner, str):
        return inner.encode("latin1", "replace")
    try:
        return bytes(value)
    except Exception:
        return None

def _read_compressed_uint(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise _SignatureError("truncated compressed integer")
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if first & 0xC0 == 0x80:
        if offset + 1 >= len(data):
            raise _SignatureError("truncated two-byte compressed integer")
        value = ((first & 0x3F) << 8) | data[offset + 1]
        return value, offset + 2
    if first & 0xE0 == 0xC0:
        if offset + 3 >= len(data):
            raise _SignatureError("truncated four-byte compressed integer")
        value = (
            ((first & 0x1F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3]
        )
        return value, offset + 4
    raise _SignatureError("invalid compressed integer prefix 0x%02x" % first)


_ELEMENTARY_TYPES = {
    0x01: "System.Void",
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


class _SignatureReader:
    """A small, strict ECMA-335 signature decoder."""

    def __init__(self, data: bytes, model: "_AssemblyModel"):
        self.data = bytes(data or b"")
        self.model = model
        self.offset = 0

    def _byte(self) -> int:
        if self.offset >= len(self.data):
            raise _SignatureError("truncated signature")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def _peek(self) -> Optional[int]:
        if self.offset >= len(self.data):
            return None
        return self.data[self.offset]

    def _compressed(self) -> int:
        value, self.offset = _read_compressed_uint(self.data, self.offset)
        return value

    def _type_def_or_ref(self) -> TypeRefInfo:
        encoded = self._compressed()
        return self.model.resolve_type_def_or_ref(encoded)

    def parse_type(self, *, allow_void: bool = True) -> TypeRefInfo:
        element = self._byte()

        if element == 0x01:  # ELEMENT_TYPE_VOID
            if not allow_void:
                raise _SignatureError("unexpected void element type")
            return TypeRefInfo(
                display="System.Void",
                full_name="System.Void",
                resolved=True,
                local=True,
                element_kind="void",
            )

        if element in _ELEMENTARY_TYPES:
            name = _ELEMENTARY_TYPES[element]
            return TypeRefInfo(
                display=name,
                full_name=name,
                resolved=True,
                local=True,
                element_kind="primitive",
            )

        if element in (0x11, 0x12):  # VALUETYPE / CLASS
            target = self._type_def_or_ref()
            target.element_kind = "valuetype" if element == 0x11 else "class"
            return target

        if element == 0x0F:  # PTR
            inner = self.parse_type()
            return TypeRefInfo(
                display=inner.display + "*",
                full_name=inner.display + "*",
                resolved=inner.resolved and not inner.unresolved,
                local=inner.local,
                missing=list(inner.unresolved),
                element_kind="pointer",
                generic_args=(inner,),
            )

        if element == 0x10:  # BYREF
            inner = self.parse_type()
            return TypeRefInfo(
                display=inner.display + "&",
                full_name=inner.display + "&",
                resolved=inner.resolved and not inner.unresolved,
                local=inner.local,
                missing=list(inner.unresolved),
                element_kind="byref",
                generic_args=(inner,),
            )

        if element == 0x1D:  # SZARRAY
            inner = self.parse_type()
            return TypeRefInfo(
                display=inner.display + "[]",
                full_name=inner.display + "[]",
                resolved=inner.resolved and not inner.unresolved,
                local=inner.local,
                missing=list(inner.unresolved),
                element_kind="szarray",
                generic_args=(inner,),
            )

        if element == 0x14:  # ARRAY
            inner = self.parse_type()
            rank = self._compressed()
            num_sizes = self._compressed()
            sizes = [self._compressed() for _ in range(num_sizes)]
            num_lower_bounds = self._compressed()
            lower_bounds = [self._compressed() for _ in range(num_lower_bounds)]
            suffix = "[" + "," * max(rank - 1, 0) + "]"
            display = inner.display + suffix
            details = []
            if sizes:
                details.append("sizes=" + ",".join(str(v) for v in sizes))
            if lower_bounds:
                details.append("lower=" + ",".join(str(v) for v in lower_bounds))
            if details:
                display += "{" + ";".join(details) + "}"
            return TypeRefInfo(
                display=display,
                full_name=inner.display + suffix,
                resolved=inner.resolved and not inner.unresolved,
                local=inner.local,
                missing=list(inner.unresolved),
                element_kind="array",
                generic_args=(inner,),
            )

        if element == 0x15:  # GENERICINST
            next_element = self._byte()
            if next_element not in (0x11, 0x12):
                raise _SignatureError("invalid generic instance base element 0x%02x" % next_element)
            target = self._type_def_or_ref()
            arg_count = self._compressed()
            args = tuple(self.parse_type() for _ in range(arg_count))
            display = "%s<%s>" % (target.display, ",".join(a.display for a in args))
            return TypeRefInfo(
                display=display,
                full_name=target.full_name,
                assembly=target.assembly,
                resolved=target.resolved and all(a.resolved and not a.unresolved for a in args),
                local=target.local,
                source=target.source,
                missing=list(target.unresolved) + _unique_missing_from_types(args),
                generic_args=args,
                element_kind="genericinst",
                source_type=target.source_type,
                source_model=target.source_model,
                dependencies=(target,),
            )

        if element == 0x13:  # VAR
            index = self._compressed()
            return TypeRefInfo(
                display="!%d" % index,
                full_name="!%d" % index,
                resolved=True,
                local=True,
                element_kind="var",
            )

        if element == 0x1E:  # MVAR
            index = self._compressed()
            return TypeRefInfo(
                display="!!%d" % index,
                full_name="!!%d" % index,
                resolved=True,
                local=True,
                element_kind="mvar",
            )

        if element == 0x1B:  # FNPTR
            nested = self.parse_method()
            return TypeRefInfo(
                display="method " + nested.display,
                full_name="method " + nested.display,
                resolved=nested.valid and not nested.unresolved,
                local=True,
                missing=list(nested.unresolved),
                element_kind="fnptr",
            )

        if element in (0x1F, 0x20):  # CMOD_REQD / CMOD_OPT
            modifier = self._type_def_or_ref()
            inner = self.parse_type()
            label = "modreq" if element == 0x1F else "modopt"
            display = "%s(%s) %s" % (label, modifier.display, inner.display)
            return TypeRefInfo(
                display=display,
                full_name=inner.display,
                resolved=modifier.resolved
                and not modifier.unresolved
                and inner.resolved
                and not inner.unresolved,
                local=modifier.local and inner.local,
                missing=list(modifier.unresolved) + list(inner.unresolved),
                element_kind=label,
                generic_args=(inner,),
                dependencies=(modifier, inner),
            )

        if element == 0x45:  # PINNED
            inner = self.parse_type()
            return TypeRefInfo(
                display="pinned " + inner.display,
                full_name=inner.display,
                resolved=inner.resolved and not inner.unresolved,
                local=inner.local,
                missing=list(inner.unresolved),
                element_kind="pinned",
                generic_args=(inner,),
            )

        if element == 0x21:  # INTERNAL, native type
            native = self._byte()
            return TypeRefInfo(
                display="native(0x%02x)" % native,
                full_name="native(0x%02x)" % native,
                resolved=True,
                local=True,
                element_kind="native",
            )

        raise _SignatureError("unsupported signature element type 0x%02x at offset %d" % (element, self.offset - 1))

    @staticmethod
    def _calling_convention_name(value: int) -> str:
        base = value & 0x0F
        names = {
            0x00: "default",
            0x01: "cdecl",
            0x02: "stdcall",
            0x03: "thiscall",
            0x04: "fastcall",
            0x05: "vararg",
            0x09: "unmanaged",
            0x0A: "generic",
        }
        return names.get(base, "cc(0x%x)" % base)

    def parse_method(self) -> SignatureInfo:
        start = self.offset
        calling_convention = self._byte()
        has_this = bool(calling_convention & 0x20)
        explicit_this = bool(calling_convention & 0x40)
        generic = bool(calling_convention & 0x10)

        generic_count = self._compressed() if generic else 0
        parameter_count = self._compressed()
        return_type = self.parse_type()

        parameters: List[TypeRefInfo] = []
        sentinel_index: Optional[int] = None
        for index in range(parameter_count):
            if self._peek() == 0x41:  # ELEMENT_TYPE_SENTINEL
                self.offset += 1
                sentinel_index = index
            parameters.append(self.parse_type())

        kind_name = self._calling_convention_name(calling_convention)
        if explicit_this:
            kind_name += "/explicit-this"
        instance_prefix = "instance " if has_this else "static "
        generic_prefix = "<%d>" % generic_count if generic_count else ""
        param_text = ", ".join(p.display for p in parameters)
        display = "%s%s%s %s(%s)" % (
            instance_prefix,
            generic_prefix,
            return_type.display,
            kind_name,
            param_text,
        )
        identity = "%s%s%s(%s)" % (
            instance_prefix,
            generic_prefix,
            return_type.display,
            param_text,
        )

        try:
            consumed = self.offset - start
            trailing = self.data[self.offset:]
        except Exception:
            consumed = 0
            trailing = b""

        info = SignatureInfo(
            kind="method",
            display=display,
            identity=identity,
            return_type=return_type,
            parameters=parameters,
            calling_convention=kind_name,
            generic_parameter_count=generic_count,
            has_this=has_this,
            sentinel_index=sentinel_index,
            valid=True,
        )
        if trailing.strip(b"\x00"):
            info.details = {"trailing_signature_bytes": trailing.hex()}  # type: ignore[attr-defined]
        return info

    def parse_field(self) -> SignatureInfo:
        calling_convention = self._byte()
        if calling_convention & 0x0F != 0x06:
            raise _SignatureError("invalid field signature prefix 0x%02x" % calling_convention)
        field_type = self.parse_type()
        display = "field %s" % field_type.display
        return SignatureInfo(
            kind="field",
            display=display,
            identity=field_type.display,
            return_type=field_type,
            calling_convention="field",
        )

    def parse_property(self) -> SignatureInfo:
        calling_convention = self._byte()
        has_this = bool(calling_convention & 0x20)
        parameter_count = self._compressed()
        property_type = self.parse_type()
        parameters = [self.parse_type() for _ in range(parameter_count)]
        param_text = ", ".join(p.display for p in parameters)
        display = "%sproperty %s(%s)" % ("instance " if has_this else "", property_type.display, param_text)
        identity = "%s(%s)" % (property_type.display, param_text)
        return SignatureInfo(
            kind="property",
            display=display,
            identity=identity,
            return_type=property_type,
            parameters=parameters,
            calling_convention="property",
            has_this=has_this,
        )


class _AuditContext:
    """Approved evidence used to resolve references outside the input files."""

    def __init__(
        self,
        *,
        approved_models: Optional[Dict[str, "_AssemblyModel"]] = None,
        approved_assemblies: Optional[Iterable[str]] = None,
        approved_types: Optional[Iterable[str]] = None,
        trust_core_library: bool = False,
    ):
        self.approved_models: Dict[str, _AssemblyModel] = dict(approved_models or {})
        self.approved_assemblies: Set[str] = {a.lower() for a in (approved_assemblies or []) if a}
        self.approved_types: Set[str] = {_normalize_type_name(t) for t in (approved_types or []) if t}
        self.trust_core_library = trust_core_library

    def resolve_external(
        self,
        full_name: str,
        assembly: Optional[str],
        scope: str,
    ) -> Tuple[bool, Optional[TypeModel], Optional[_AssemblyModel], Optional[MissingReference]]:
        normalized = _normalize_type_name(full_name)
        assembly_key = assembly.lower() if assembly else None

        if assembly_key and assembly_key in self.approved_models:
            model = self.approved_models[assembly_key]
            target = model.get_type(normalized)
            if target is not None:
                return True, target, model, None
            return (
                False,
                None,
                None,
                MissingReference(
                    kind="type",
                    name=normalized,
                    assembly=assembly,
                    reason="type is not present in the approved source assembly",
                    source=scope,
                ),
            )

        if normalized in self.approved_types:
            return True, None, None, None

        if assembly_key and assembly_key in self.approved_assemblies:
            # The caller explicitly vouches for this assembly as a type
            # source, but did not give us its metadata.  Its type identity may
            # be used for comparison, but member inheritance through it cannot
            # be inspected.
            return True, None, None, None

        if self.trust_core_library and assembly_key in {
            "mscorlib",
            "system.runtime",
            "system.private.corelib",
            "netstandard",
        }:
            return True, None, None, None

        return (
            False,
            None,
            None,
            MissingReference(
                kind="type",
                name=normalized,
                assembly=assembly,
                reason="referenced component was not supplied as an approved type source",
                source=scope,
            ),
        )


class _AssemblyModel:
    """Read-only view over one ``dnfile.dnPE`` metadata image."""

    def __init__(self, pe: Any, *, source: Optional[str] = None):
        self.pe = pe
        self.source = source
        self.warnings: List[str] = []
        self.assembly_name: Optional[str] = None
        self.assembly_version: Optional[str] = None
        self.tables = None
        self.type_defs_by_rid: Dict[int, TypeModel] = {}
        self.types_by_name: Dict[str, TypeModel] = {}
        self._type_ref_cache: Dict[int, TypeRefInfo] = {}
        self._type_spec_cache: Dict[int, TypeRefInfo] = {}
        self._effective_cache: Dict[Tuple[int, bytes], Tuple[List[EffectiveMember], List[MissingReference]]] = {}

        net = getattr(pe, "net", None)
        tables = getattr(net, "mdtables", None) if net is not None else None
        if tables is None:
            raise AbiAuditError("input does not contain parsed .NET metadata tables")
        self.tables = tables

        self._read_assembly_identity()
        self._build_types()
        self._build_members()

    # ------------------------------------------------------------------
    # Basic table helpers
    # ------------------------------------------------------------------
    def _table(self, name: str) -> Any:
        table = getattr(self.tables, name, None)
        if table is None:
            return None
        return table

    def _row(self, table_name: str, row_index: Optional[int]) -> Any:
        if not row_index or row_index <= 0:
            return None
        table = self._table(table_name)
        if table is None:
            return None
        try:
            return table.get_with_row_index(row_index)
        except (IndexError, TypeError):
            return None

    @staticmethod
    def _raw_flags(row: Any) -> int:
        struct_obj = getattr(row, "struct", None)
        value = getattr(struct_obj, "Flags", None) if struct_obj is not None else None
        if value is None and struct_obj is not None:
            # MethodSemantics uses the field name "Semantics" rather than
            # "Flags"; both are raw bit masks in the row structure.
            value = getattr(struct_obj, "Semantics", None)
        if value is None:
            flags = getattr(row, "Flags", None)
            if isinstance(flags, int):
                return flags
            corhdr = getattr(flags, "corhdr_enum", None)
            if corhdr is not None:
                return 0
            return 0
        return int(value)

    def _read_assembly_identity(self) -> None:
        assembly = self._table("Assembly")
        if assembly is not None and len(assembly) > 0 and assembly[0] is not None:
            row = assembly[0]
            self.assembly_name = _safe_text(getattr(row, "Name", None)) or None
            major = getattr(row, "MajorVersion", None)
            minor = getattr(row, "MinorVersion", None)
            build = getattr(row, "BuildNumber", None)
            revision = getattr(row, "RevisionNumber", None)
            if all(v is not None for v in (major, minor, build, revision)):
                self.assembly_version = "%s.%s.%s.%s" % (major, minor, build, revision)
        if not self.assembly_name:
            module = self._table("Module")
            if module is not None and len(module) > 0 and module[0] is not None:
                self.assembly_name = _safe_text(getattr(module[0], "Name", None)) or None

    # ------------------------------------------------------------------
    # Type identities
    # ------------------------------------------------------------------
    def _nested_parents(self) -> Dict[int, int]:
        result: Dict[int, int] = {}
        table = self._table("NestedClass")
        if table is None:
            return result
        for row in table:
            if row is None:
                continue
            nested = getattr(row, "NestedClass", None)
            enclosing = getattr(row, "EnclosingClass", None)
            if nested is not None and enclosing is not None:
                result[int(nested.row_index)] = int(enclosing.row_index)
        return result

    def _build_types(self) -> None:
        table = self._table("TypeDef")
        if table is None:
            return
        parents = self._nested_parents()

        raw: Dict[int, Any] = {}
        for index, row in enumerate(table, start=1):
            if row is None:
                continue
            name = _safe_text(getattr(row, "TypeName", None))
            if not name or name == "<Module>":
                continue
            raw[index] = row

        def full_name_of(index: int, seen: Optional[Set[int]] = None) -> str:
            seen = set(seen or ())
            if index in seen:
                return "<cycle>"
            seen.add(index)
            row = raw.get(index)
            if row is None:
                return "<missing-type-%d>" % index
            name = _safe_text(getattr(row, "TypeName", None))
            namespace = _safe_text(getattr(row, "TypeNamespace", None))
            parent_index = parents.get(index)
            if parent_index is not None and parent_index in raw:
                return full_name_of(parent_index, seen) + "+" + name
            if namespace:
                return namespace + "." + name
            return name

        for index, row in raw.items():
            namespace = _safe_text(getattr(row, "TypeNamespace", None))
            name = _safe_text(getattr(row, "TypeName", None))
            flags = self._raw_flags(row)
            visibility = _TYPE_VISIBILITY.get(flags & 0x7, "unknown")
            full_name = full_name_of(index)
            type_model = TypeModel(
                model=self,
                row_index=index,
                namespace=namespace,
                name=name,
                full_name=full_name,
                visibility=visibility,
                effective_visibility=visibility,
                flags=flags,
                row=row,
            )
            self.type_defs_by_rid[index] = type_model
            self._register_type_name(type_model)

        # Attach nested parents and compute effective visibility.
        for index, type_model in self.type_defs_by_rid.items():
            parent_index = parents.get(index)
            parent = self.type_defs_by_rid.get(parent_index)
            if parent is not None:
                type_model.enclosing_type = parent

        def effective_visibility(type_model: TypeModel, seen: Optional[Set[int]] = None) -> str:
            seen = set(seen or ())
            if type_model.row_index in seen:
                return "internal"
            seen.add(type_model.row_index)
            declared = type_model.visibility
            parent = type_model.enclosing_type
            if parent is None:
                return declared
            parent_visibility = effective_visibility(parent, seen)
            if _visibility_rank(parent_visibility) < _visibility_rank(declared):
                return parent_visibility
            return declared

        for type_model in self.type_defs_by_rid.values():
            type_model.effective_visibility = effective_visibility(type_model)

    def _register_type_name(self, type_model: TypeModel) -> None:
        names = {
            type_model.full_name,
            type_model.full_name.replace("+", "."),
            type_model.full_name.replace(".", "+"),
        }
        for name in names:
            self.types_by_name.setdefault(_normalize_type_name(name), type_model)

    def get_type(self, full_name: str) -> Optional[TypeModel]:
        normalized = _normalize_type_name(full_name)
        result = self.types_by_name.get(normalized)
        if result is not None:
            return result
        # Accept C# nested spelling and a generic arity marker written as
        # <...> rather than the metadata `N suffix.
        without_csharp_args = re.sub(r"<[^<>]*>$", "", normalized)
        result = self.types_by_name.get(without_csharp_args)
        if result is not None:
            return result
        return self.types_by_name.get(normalized.replace(".", "+"))

    def type_by_rid(self, rid: int) -> Optional[TypeModel]:
        return self.type_defs_by_rid.get(rid)

    def _assembly_ref_name(self, row_index: Optional[int]) -> Optional[str]:
        row = self._row("AssemblyRef", row_index)
        if row is None:
            return None
        return _safe_text(getattr(row, "Name", None)) or None

    def _type_ref_info(self, row_index: int) -> TypeRefInfo:
        if row_index in self._type_ref_cache:
            return self._type_ref_cache[row_index]
        row = self._row("TypeRef", row_index)
        if row is None:
            info = TypeRefInfo(
                display="<missing TypeRef rid=%d>" % row_index,
                resolved=False,
                missing=[
                    MissingReference(
                        kind="type",
                        name="<missing TypeRef rid=%d>" % row_index,
                        reason="TypeRef row is unavailable",
                    )
                ],
                element_kind="missing",
            )
            self._type_ref_cache[row_index] = info
            return info

        name = _safe_text(getattr(row, "TypeName", None))
        namespace = _safe_text(getattr(row, "TypeNamespace", None))
        scope = getattr(row, "ResolutionScope", None)
        assembly: Optional[str] = None
        external_scope = "TypeRef"
        local = False
        enclosing_full: Optional[str] = None

        if scope is None or getattr(scope, "table", None) is None:
            external_scope = "unscoped TypeRef"
            assembly = None
        else:
            scope_table_name = getattr(scope.table, "name", "")
            if scope_table_name == "AssemblyRef":
                assembly = self._assembly_ref_name(scope.row_index)
                external_scope = "AssemblyRef"
            elif scope_table_name == "ModuleRef":
                module_row = self._row("ModuleRef", scope.row_index)
                assembly = _safe_text(getattr(module_row, "Name", None)) or "<module-ref-%d>" % scope.row_index
                external_scope = "ModuleRef"
            elif scope_table_name == "Module":
                local = True
                external_scope = "Module"
            elif scope_table_name == "TypeRef":
                enclosing = self._type_ref_info(int(scope.row_index))
                enclosing_full = enclosing.full_name
                assembly = enclosing.assembly
                external_scope = "nested TypeRef"
            else:
                external_scope = str(scope_table_name or "TypeRef")

        if enclosing_full:
            full_name = enclosing_full + "+" + name
        else:
            full_name = (namespace + "." + name) if namespace else name
        full_name = _normalize_type_name(full_name)

        if (
            local
            or (assembly and self.assembly_name and assembly.lower() == self.assembly_name.lower())
            or (assembly is None and self.get_type(full_name) is not None)
        ):
            target = self.get_type(full_name)
            if target is not None:
                info = TypeRefInfo(
                    display=target.full_name,
                    full_name=target.full_name,
                    assembly=self.assembly_name,
                    resolved=True,
                    local=True,
                    source="local TypeDef",
                    element_kind="class",
                    source_type=target,
                    source_model=self,
                )
            else:
                info = TypeRefInfo(
                    display=full_name,
                    full_name=full_name,
                    assembly=self.assembly_name,
                    resolved=True,
                    local=True,
                    source="local module",
                    element_kind="class",
                )
        else:
            info = TypeRefInfo(
                display=full_name,
                full_name=full_name,
                assembly=assembly,
                resolved=False,
                local=False,
                source=external_scope,
                element_kind="class",
            )
        self._type_ref_cache[row_index] = info
        return info

    def _type_spec_info(self, row_index: int) -> TypeRefInfo:
        if row_index in self._type_spec_cache:
            return self._type_spec_cache[row_index]
        row = self._row("TypeSpec", row_index)
        if row is None:
            info = TypeRefInfo(
                display="<missing TypeSpec rid=%d>" % row_index,
                resolved=False,
                element_kind="missing",
                missing=[
                    MissingReference(
                        kind="typespec",
                        name="<missing TypeSpec rid=%d>" % row_index,
                        reason="TypeSpec row is unavailable",
                    )
                ],
            )
            self._type_spec_cache[row_index] = info
            return info
        signature = _as_blob_bytes(getattr(row, "Signature", None))
        if not signature:
            info = TypeRefInfo(
                display="<unavailable TypeSpec rid=%d>" % row_index,
                resolved=False,
                element_kind="missing",
                missing=[
                    MissingReference(
                        kind="typespec",
                        name="<unavailable TypeSpec rid=%d>" % row_index,
                        reason="TypeSpec signature blob is unavailable",
                    )
                ],
            )
            self._type_spec_cache[row_index] = info
            return info
        try:
            reader = _SignatureReader(signature, self)
            info = reader.parse_type()
        except _SignatureError as exc:
            info = TypeRefInfo(
                display="<invalid TypeSpec rid=%d>" % row_index,
                resolved=False,
                element_kind="invalid",
                missing=[
                    MissingReference(
                        kind="typespec",
                        name="<invalid TypeSpec rid=%d>" % row_index,
                        reason=str(exc),
                    )
                ],
            )
        self._type_spec_cache[row_index] = info
        return info

    def resolve_type_def_or_ref(self, encoded: int) -> TypeRefInfo:
        tag = encoded & 0x03
        rid = encoded >> 2
        if tag == 0:  # TypeDef
            target = self.type_by_rid(rid)
            if target is None:
                return TypeRefInfo(
                    display="<missing TypeDef rid=%d>" % rid,
                    resolved=False,
                    element_kind="missing",
                    missing=[
                        MissingReference(
                            kind="typedef",
                            name="<missing TypeDef rid=%d>" % rid,
                            reason="TypeDef row is unavailable",
                        )
                    ],
                )
            return TypeRefInfo(
                display=target.full_name,
                full_name=target.full_name,
                assembly=self.assembly_name,
                resolved=True,
                local=True,
                source="local TypeDef",
                element_kind="class",
                source_type=target,
                source_model=self,
            )
        if tag == 1:  # TypeRef
            return self._type_ref_info(rid)
        if tag == 2:  # TypeSpec
            return self._type_spec_info(rid)
        return TypeRefInfo(
            display="<unknown TypeDefOrRef 0x%x>" % encoded,
            resolved=False,
            element_kind="missing",
            missing=[
                MissingReference(
                    kind="typedeforref",
                    name="<unknown 0x%x>" % encoded,
                    reason="invalid TypeDefOrRef tag",
                )
            ],
        )

    # ------------------------------------------------------------------
    # Signatures and member construction
    # ------------------------------------------------------------------
    def _signature(self, blob: Any, kind: str) -> SignatureInfo:
        if not blob:
            return SignatureInfo(
                kind=kind,
                display="<missing signature>",
                identity="<missing signature>",
                valid=False,
                error="signature blob is unavailable",
                missing=[
                    MissingReference(
                        kind="signature",
                        name="<missing %s signature>" % kind,
                        reason="signature blob is unavailable",
                    )
                ],
            )
        blob = _as_blob_bytes(blob)
        if blob is None:
            return SignatureInfo(
                kind=kind,
                display="<missing signature>",
                identity="<missing signature>",
                valid=False,
                error="signature blob is unavailable",
                missing=[
                    MissingReference(
                        kind="signature",
                        name="<missing %s signature>" % kind,
                        reason="signature blob is unavailable",
                    )
                ],
            )
        try:
            reader = _SignatureReader(blob, self)
            if kind == "method":
                return reader.parse_method()
            if kind == "field":
                return reader.parse_field()
            if kind == "property":
                init = getattr(reader, "offset", 0)
                # Some producers hand us a property signature without the
                # PROPERTY marker; insert the canonical marker when needed.
                if not blob or (blob[0] & 0x0F) != 0x08:
                    reader = _SignatureReader(bytes([0x08]) + bytes(blob), self)
                return reader.parse_property()
            raise _SignatureError("unknown signature kind %r" % kind)
        except _SignatureError as exc:
            return SignatureInfo(
                kind=kind,
                display="<invalid %s signature: %s>" % (kind, exc),
                identity="<invalid %s signature>" % kind,
                valid=False,
                error=str(exc),
                missing=[
                    MissingReference(
                        kind="signature",
                        name="<invalid %s signature>" % kind,
                        reason=str(exc),
                    )
                ],
            )

    def _method_visibility(self, row: Any) -> str:
        return _METHOD_VISIBILITY.get(self._raw_flags(row) & 0x7, "unknown")

    def _field_visibility(self, row: Any) -> str:
        return _FIELD_VISIBILITY.get(self._raw_flags(row) & 0x7, "unknown")

    def _build_method_model(self, type_model: TypeModel, row: Any) -> MemberModel:
        name = _safe_text(getattr(row, "Name", None))
        flags = self._raw_flags(row)
        visibility = self._method_visibility(row)
        signature = self._signature(getattr(row, "Signature", None), "method")
        static = "static " if flags & _MD_METHOD_STATIC else "instance "
        identity = "M:%s::%s::%s" % (type_model.full_name, name, signature.identity)
        return MemberModel(
            kind="method",
            name=name,
            declaring_type=type_model,
            visibility=visibility,
            identity=identity,
            signature=signature,
            row=row,
            flags=flags,
        )

    def _build_field_model(self, type_model: TypeModel, row: Any) -> MemberModel:
        name = _safe_text(getattr(row, "Name", None))
        flags = self._raw_flags(row)
        visibility = self._field_visibility(row)
        signature = self._signature(getattr(row, "Signature", None), "field")
        static = "static " if flags & _MD_FIELD_STATIC else "instance "
        identity = "F:%s::%s::%s%s" % (type_model.full_name, name, static, signature.identity)
        return MemberModel(
            kind="field",
            name=name,
            declaring_type=type_model,
            visibility=visibility,
            identity=identity,
            signature=signature,
            row=row,
            flags=flags,
        )

    def _build_members(self) -> None:
        # Methods and fields.
        for type_model in self.type_defs_by_rid.values():
            row = type_model.row
            method_list = getattr(row, "MethodList", None) or []
            for method_index in method_list:
                method_row = getattr(method_index, "row", None)
                if method_row is None:
                    continue
                model = self._build_method_model(type_model, method_row)
                type_model.declared_members.append(model)

            field_list = getattr(row, "FieldList", None) or []
            for field_index in field_list:
                field_row = getattr(field_index, "row", None)
                if field_row is None:
                    continue
                model = self._build_field_model(type_model, field_row)
                type_model.declared_members.append(model)

        # Base types and interfaces.
        for type_model in self.type_defs_by_rid.values():
            row = type_model.row
            extends = getattr(row, "Extends", None)
            if extends is not None and (getattr(extends, "row_index", 0) or getattr(extends, "table", None) is not None):
                if getattr(extends, "table", None) is not None and getattr(extends, "row_index", 0) > 0:
                    type_model.base_ref = self._coded_type_info(extends)

        interface_table = self._table("InterfaceImpl")
        if interface_table is not None:
            for row in interface_table:
                if row is None:
                    continue
                class_index = getattr(getattr(row, "Class", None), "row_index", None)
                owner = self.type_by_rid(int(class_index)) if class_index else None
                interface = getattr(row, "Interface", None)
                if owner is None or interface is None or getattr(interface, "table", None) is None:
                    continue
                owner.interfaces.append(self._coded_type_info(interface))

        self._build_properties_and_events()

    def _coded_type_info(self, coded: Any) -> TypeRefInfo:
        table = getattr(coded, "table", None)
        row_index = getattr(coded, "row_index", 0) or 0
        if table is None or row_index <= 0:
            return TypeRefInfo(
                display="<unresolved coded type>",
                resolved=False,
                element_kind="missing",
                missing=[
                    MissingReference(
                        kind="type",
                        name="<unresolved coded type>",
                        reason="coded index target table is unavailable",
                    )
                ],
            )
        table_name = getattr(table, "name", "")
        if table_name == "TypeDef":
            return self.resolve_type_def_or_ref(row_index << 2)
        if table_name == "TypeRef":
            return self._type_ref_info(row_index)
        if table_name == "TypeSpec":
            return self._type_spec_info(row_index)
        row = getattr(coded, "row", None)
        if row is not None and hasattr(row, "Signature"):
            return self._type_spec_info(row_index)
        return TypeRefInfo(
            display="<unresolved coded type in %s>" % table_name,
            resolved=False,
            element_kind="missing",
            missing=[
                MissingReference(
                    kind="type",
                    name="<unresolved coded type in %s>" % table_name,
                    reason="unsupported coded index table",
                )
            ],
        )

    def _method_from_index(self, index: Any) -> Optional[MemberModel]:
        row = getattr(index, "row", None)
        if row is None:
            return None
        for type_model in self.type_defs_by_rid.values():
            for member in type_model.declared_members:
                if member.kind == "method" and member.row is row:
                    return member
        # Fall back to a standalone method model if the row was not listed by
        # TypeDef (malformed input); its declaring type is unknown.
        return None

    def _build_properties_and_events(self) -> None:
        semantics_table = self._table("MethodSemantics")
        semantics_by_property: Dict[int, List[Tuple[str, MemberModel]]] = {}
        semantics_by_event: Dict[int, List[Tuple[str, MemberModel]]] = {}
        if semantics_table is not None:
            for row in semantics_table:
                if row is None:
                    continue
                association = getattr(row, "Association", None)
                if association is None or getattr(association, "table", None) is None:
                    continue
                table_name = getattr(association.table, "name", "")
                association_rid = getattr(association, "row_index", 0)
                method = self._method_from_index(getattr(row, "Method", None))
                if method is None:
                    continue
                semantics_flags = self._raw_flags(row)
                accessor_names = []
                if semantics_flags & 0x0002:
                    accessor_names.append("get")
                if semantics_flags & 0x0001:
                    accessor_names.append("set")
                if semantics_flags & 0x0008:
                    accessor_names.append("add")
                if semantics_flags & 0x0010:
                    accessor_names.append("remove")
                if semantics_flags & 0x0020:
                    accessor_names.append("raise")
                if semantics_flags & 0x0004:
                    accessor_names.append("other")
                target = semantics_by_property if table_name == "Property" else semantics_by_event
                if table_name not in ("Property", "Event"):
                    continue
                for accessor_name in accessor_names:
                    target.setdefault(int(association_rid), []).append((accessor_name, method))

        # PropertyMap -> Property rows.
        property_map = self._table("PropertyMap")
        if property_map is not None:
            for map_row in property_map:
                if map_row is None:
                    continue
                parent_index = getattr(getattr(map_row, "Parent", None), "row_index", None)
                owner = self.type_by_rid(int(parent_index)) if parent_index else None
                if owner is None:
                    continue
                for property_index in getattr(map_row, "PropertyList", None) or []:
                    rid = getattr(property_index, "row_index", None)
                    property_row = getattr(property_index, "row", None)
                    if property_row is None:
                        continue
                    name = _safe_text(getattr(property_row, "Name", None))
                    signature = self._signature(getattr(property_row, "Type", None), "property")
                    accessors = semantics_by_property.get(int(rid or 0), [])
                    visibility = self._accessor_visibility(accessors)
                    static_prefix = "instance" if signature.has_this else "static"
                    identity = "P:%s::%s::%s::%s" % (owner.full_name, name, static_prefix, signature.identity)
                    member = MemberModel(
                        kind="property",
                        name=name,
                        declaring_type=owner,
                        visibility=visibility,
                        identity=identity,
                        signature=signature,
                        row=property_row,
                        accessors={key: value for key, value in accessors},
                    )
                    owner.declared_members.append(member)

        # EventMap -> Event rows.
        event_map = self._table("EventMap")
        if event_map is not None:
            for map_row in event_map:
                if map_row is None:
                    continue
                parent_index = getattr(getattr(map_row, "Parent", None), "row_index", None)
                owner = self.type_by_rid(int(parent_index)) if parent_index else None
                if owner is None:
                    continue
                for event_index in getattr(map_row, "EventList", None) or []:
                    rid = getattr(event_index, "row_index", None)
                    event_row = getattr(event_index, "row", None)
                    if event_row is None:
                        continue
                    name = _safe_text(getattr(event_row, "Name", None))
                    event_type = getattr(event_row, "EventType", None)
                    if event_type is not None and getattr(event_type, "table", None) is not None:
                        type_info = self._coded_type_info(event_type)
                    else:
                        type_info = TypeRefInfo(
                            display="<unresolved event type>",
                            resolved=False,
                            element_kind="missing",
                            missing=[
                                MissingReference(
                                    kind="type",
                                    name="<unresolved event type>",
                                    reason="event type reference is unavailable",
                                )
                            ],
                        )
                    signature = SignatureInfo(
                        kind="event",
                        display=str(type_info),
                        identity=str(type_info),
                        return_type=type_info,
                        calling_convention="event",
                    )
                    accessors = semantics_by_event.get(int(rid or 0), [])
                    visibility = self._accessor_visibility(accessors)
                    identity = "E:%s::%s::%s" % (owner.full_name, name, signature.identity)
                    member = MemberModel(
                        kind="event",
                        name=name,
                        declaring_type=owner,
                        visibility=visibility,
                        identity=identity,
                        signature=signature,
                        row=event_row,
                        accessors={key: value for key, value in accessors},
                    )
                    owner.declared_members.append(member)

    @staticmethod
    def _accessor_visibility(accessors: Iterable[Tuple[str, MemberModel]]) -> str:
        best = "private"
        for _, method in accessors:
            if _visibility_rank(method.visibility) > _visibility_rank(best):
                best = method.visibility
        return best

    # ------------------------------------------------------------------
    # Effective members (including inheritance)
    # ------------------------------------------------------------------
    def effective_members(
        self,
        type_model: TypeModel,
        *,
        include_protected: bool = True,
        include_private: bool = False,
    ) -> Tuple[List[EffectiveMember], List[MissingReference]]:
        key = (id(type_model), bytes([1 if include_protected else 0, 1 if include_private else 0]))
        cached = self._effective_cache.get(key)
        if cached is not None:
            return cached

        result: List[EffectiveMember] = []
        missing: List[MissingReference] = []
        seen_keys: Dict[Tuple[str, str], int] = {}
        visited: Set[Tuple[int, str]] = set()

        def add_members(owner: TypeModel, chain: List[str], depth: int, substitution: Optional[Mapping[str, str]]) -> None:
            for member in owner.declared_members:
                if not include_private and not _is_externally_visible(member.visibility, include_protected):
                    continue
                if member.kind == "method" and member.name in (".ctor", ".cctor"):
                    # Constructors are not inherited.
                    if chain:
                        continue
                signature = member.signature
                if substitution:
                    signature = _substituted_signature(signature, substitution)
                compat_identity = _member_compat_identity(member, signature)
                shadow_key = (member.kind, member.name, signature.identity)
                if shadow_key in seen_keys:
                    continue
                # Name+signature shadowing across kinds is unusual, but keep
                # methods/fields from colliding in name-only lookups.
                seen_keys[shadow_key] = depth
                result.append(
                    EffectiveMember(
                        member=member,
                        declaring_type=owner,
                        inherited_from=list(chain),
                        depth=depth,
                        compat_identity=compat_identity,
                    )
                )

        def walk(current: TypeModel, chain: List[str], depth: int, substitution: Optional[Mapping[str, str]]) -> None:
            marker = (id(current.model), current.full_name)
            if marker in visited:
                missing.append(
                    MissingReference(
                        kind="inheritance",
                        name=current.full_name,
                        reason="inheritance cycle detected",
                    )
                )
                return
            visited.add(marker)

            add_members(current, chain, depth, substitution)

            # Interface types inherit members from their interfaces.
            base_refs: List[TypeRefInfo] = []
            if current.is_interface:
                base_refs.extend(current.interfaces)
            elif current.base_ref is not None:
                base_refs.append(current.base_ref)

            for base_ref in base_refs:
                if base_ref is None:
                    continue
                base_model = base_ref.source_type
                base_assembly_model = base_ref.source_model
                if isinstance(base_model, TypeModel) and isinstance(base_assembly_model, _AssemblyModel):
                    next_substitution = _compose_substitution(base_ref, substitution)
                    walk(base_model, chain + [current.full_name], depth + 1, next_substitution)
                    continue
                if not base_ref.unresolved and base_ref.local:
                    # A local reference without a TypeModel means the row was
                    # malformed; do not claim inheritance is complete.
                    missing.append(
                        MissingReference(
                            kind="inheritance",
                            name=base_ref.display,
                            assembly=base_ref.assembly,
                            reason="base type metadata could not be located",
                        )
                    )
                    continue
                for item in base_ref.unresolved:
                    missing.append(
                        MissingReference(
                            kind="inheritance",
                            name=item.name,
                            assembly=item.assembly,
                            reason="inherited members cannot be enumerated: %s" % item.reason,
                        )
                    )
                if not base_ref.unresolved:
                    # The caller vouched for the assembly name but supplied no
                    # metadata; its members cannot be enumerated.
                    missing.append(
                        MissingReference(
                            kind="inheritance",
                            name=base_ref.display,
                            assembly=base_ref.assembly,
                            reason="approved type source has no metadata for inherited-member enumeration",
                        )
                    )

        walk(type_model, [], 0, None)
        missing = _unique_missing(missing)
        self._effective_cache[key] = (result, missing)
        return result, missing



def _member_compat_identity(member: MemberModel, signature: Optional[SignatureInfo] = None) -> str:
    """Return an identity that does not depend on where a member is declared."""

    signature = signature or member.signature
    if member.kind == "method":
        return "M::%s::%s" % (member.name, signature.identity)
    if member.kind == "field":
        static = "static" if member.flags & _MD_FIELD_STATIC else "instance"
        return "F::%s::%s::%s" % (member.name, static, signature.identity)
    if member.kind == "property":
        static = "instance" if signature.has_this else "static"
        return "P::%s::%s::%s" % (member.name, static, signature.identity)
    if member.kind == "event":
        return "E::%s::%s" % (member.name, signature.identity)
    return "%s::%s::%s" % (member.kind, member.name, signature.identity)

def _substitute_generic_params(text: str, substitution: Mapping[str, str]) -> str:
    def replace(match: re.Match) -> str:
        token = match.group(0)
        return substitution.get(token, token)

    return re.sub(r"!(?:!\d+|\d+)", replace, text)


def _substituted_signature(signature: SignatureInfo, substitution: Mapping[str, str]) -> SignatureInfo:
    if not substitution:
        return signature
    return SignatureInfo(
        kind=signature.kind,
        display=_substitute_generic_params(signature.display, substitution),
        identity=_substitute_generic_params(signature.identity, substitution),
        return_type=signature.return_type,
        parameters=signature.parameters,
        calling_convention=signature.calling_convention,
        generic_parameter_count=signature.generic_parameter_count,
        has_this=signature.has_this,
        sentinel_index=signature.sentinel_index,
        valid=signature.valid,
        error=signature.error,
        missing=signature.missing,
    )


def _compose_substitution(
    base_ref: TypeRefInfo,
    outer: Optional[Mapping[str, str]],
) -> Optional[Mapping[str, str]]:
    if not base_ref.generic_args:
        return outer
    result: Dict[str, str] = {}
    for index, arg in enumerate(base_ref.generic_args):
        text = arg.display
        if outer:
            text = _substitute_generic_params(text, outer)
        result["!%d" % index] = text
    if outer:
        for key, value in outer.items():
            result.setdefault(key, value)
    return result


# ----------------------------------------------------------------------
# Entry parsing and auditing
# ----------------------------------------------------------------------
_MEMBER_KINDS = {"method", "field", "property", "event", "type"}


def _parse_entrypoint(value: Any, old_model: Optional[_AssemblyModel] = None) -> EntrySpec:
    if isinstance(value, EntrySpec):
        return value

    if isinstance(value, Mapping):
        raw = value
        type_name = None
        for key in ("type", "type_name", "declaring_type", "class", "owner"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                type_name = candidate
                break
        kind = value.get("kind")
        if isinstance(kind, str):
            kind = kind.lower()
            if kind not in _MEMBER_KINDS:
                kind = None
        member_name = None
        for key in ("member", "member_name", "method", "field", "property", "event", "name", "entry", "entry_name"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                member_name = candidate
                if key in _MEMBER_KINDS and kind is None:
                    kind = key
                break
        if type_name is None and member_name and "::" in member_name:
            parsed = _parse_entrypoint(member_name, old_model)
            return EntrySpec(
                raw=raw,
                type_name=parsed.type_name,
                member_name=parsed.member_name,
                kind=kind or parsed.kind,
                signature_hint=value.get("signature") or parsed.signature_hint,
            )
        if type_name is None and isinstance(value.get("full_name"), str):
            type_name = value["full_name"]
        if type_name is None and isinstance(value.get("entrypoint"), str):
            parsed = _parse_entrypoint(value["entrypoint"], old_model)
            return EntrySpec(
                raw=raw,
                type_name=parsed.type_name,
                member_name=parsed.member_name,
                kind=kind or parsed.kind,
                signature_hint=value.get("signature") or parsed.signature_hint,
            )
        signature_hint = None
        for key in ("signature", "parameters", "params", "parameter_types"):
            if key in value and value.get(key) is not None:
                signature_hint = value.get(key)
                break
        if type_name is None and member_name and old_model is not None:
            if old_model.get_type(member_name) is not None:
                type_name, member_name = member_name, None
                kind = "type"
        if kind is None and member_name is None:
            kind = "type"
        return EntrySpec(
            raw=raw,
            type_name=type_name,
            member_name=member_name,
            kind=kind,
            signature_hint=signature_hint,
        )

    if isinstance(value, (tuple, list)):
        if not value:
            raise AbiAuditError("empty entry point tuple")
        if len(value) == 1:
            return _parse_entrypoint(value[0], old_model)
        type_name = str(value[0])
        member_name = str(value[1]) if len(value) > 1 else None
        kind = str(value[2]).lower() if len(value) > 2 and value[2] else None
        return EntrySpec(raw=value, type_name=type_name, member_name=member_name, kind=kind)

    if not isinstance(value, str):
        raise AbiAuditError("unsupported entry point specification: %r" % (value,))

    raw = value
    text = value.strip()
    prefix_match = re.match(r"^([TMFPE]):(.*)$", text)
    if prefix_match:
        prefix = prefix_match.group(1)
        text = prefix_match.group(2).strip()
        if prefix == "T":
            return EntrySpec(raw=raw, type_name=text, kind="type")
        prefix_kind = {
            "M": "method",
            "F": "field",
            "P": "property",
            "E": "event",
        }[prefix]
    else:
        prefix_kind = None

    signature_hint = None
    if "(" in text:
        before, _, after = text.partition("(")
        close = after.find(")")
        if close >= 0:
            signature_hint = after[:close]
            text_without_hint = before
        else:
            text_without_hint = text
    else:
        text_without_hint = text

    type_name: Optional[str] = None
    member_name: Optional[str] = None
    kind: Optional[str] = prefix_kind

    if "::" in text_without_hint:
        left, _, right = text_without_hint.partition("::")
        type_name = left.strip()
        member_name = right.strip()
    elif text_without_hint.startswith("["):
        # An assembly-qualified name; keep it as a type entry.
        type_name = text_without_hint
    elif old_model is not None and old_model.get_type(text_without_hint) is not None:
        type_name = text_without_hint
        kind = kind or "type"
    else:
        # Try the C# spelling Type.Member, splitting only at a dot that
        # leaves a known type on the left when we have the old model.
        pieces = text_without_hint.split(".")
        found = None
        if old_model is not None:
            for split_at in range(len(pieces) - 1, 0, -1):
                candidate_type = ".".join(pieces[:split_at])
                if old_model.get_type(candidate_type) is not None:
                    found = (candidate_type, ".".join(pieces[split_at:]))
                    break
        if found is not None:
            type_name, member_name = found
        elif "::" not in text_without_hint and "." in text_without_hint:
            candidate_type, _, candidate_member = text_without_hint.rpartition(".")
            type_name = candidate_type
            member_name = candidate_member
        else:
            type_name = text_without_hint

    if kind is None and member_name is None:
        kind = "type"
    return EntrySpec(
        raw=raw,
        type_name=type_name,
        member_name=member_name,
        kind=kind,
        signature_hint=signature_hint,
    )


def _lookup_entry_type(model: Optional[_AssemblyModel], type_name: Optional[str]) -> Optional[TypeModel]:
    if model is None or not type_name:
        return None
    result = model.get_type(type_name)
    if result is not None:
        return result
    # Allow a leading assembly qualifier in reflection-style names.
    if type_name.startswith("[") and "]" in type_name:
        result = model.get_type(type_name.split("]", 1)[1])
    return result


_SIGNATURE_ALIASES = {
    "string": "System.String",
    "int": "System.Int32",
    "uint": "System.UInt32",
    "long": "System.Int64",
    "ulong": "System.UInt64",
    "short": "System.Int16",
    "ushort": "System.UInt16",
    "byte": "System.Byte",
    "sbyte": "System.SByte",
    "bool": "System.Boolean",
    "char": "System.Char",
    "float": "System.Single",
    "double": "System.Double",
    "object": "System.Object",
    "void": "System.Void",
}


def _expand_signature_aliases(text: str) -> str:
    for alias, full in _SIGNATURE_ALIASES.items():
        text = re.sub(r"(?<![.\w])" + re.escape(alias) + r"(?![\w])", full, text)
    return text


def _candidate_name_matches(spec: EntrySpec, member: EffectiveMember) -> bool:
    if spec.member_name is not None and member.name != spec.member_name:
        return False
    if spec.kind and spec.kind != "type" and member.kind != spec.kind:
        return False
    hint = _normalize_member_hint(spec.signature_hint)
    if hint:
        hint = _expand_signature_aliases(hint)
    if hint:
        normalized_display = _normalize_member_hint(member.signature.display) or ""
        normalized_params = _normalize_member_hint(",".join(member.signature.parameter_types)) or ""
        normalized_identity = _normalize_member_hint(member.member.identity) or ""
        if (
            hint not in normalized_display
            and hint not in normalized_params
            and hint not in normalized_identity
        ):
            return False
    return True


def _member_summary(member: EffectiveMember) -> Dict[str, Any]:
    data = member.to_dict()
    data["signature"] = member.signature.to_dict()
    return data


def _visibility_change(old: Optional[str], new: Optional[str]) -> Optional[Dict[str, Any]]:
    if old == new:
        return None
    return {
        "kind": "visibility",
        "old": old,
        "new": new,
        "narrowed": _visibility_narrowed(old, new),
    }


def _signature_changes(old: SignatureInfo, new: SignatureInfo) -> List[Dict[str, Any]]:
    changes: List[Dict[str, Any]] = []
    if old.calling_convention != new.calling_convention:
        changes.append(
            {
                "kind": "calling_convention",
                "old": old.calling_convention,
                "new": new.calling_convention,
            }
        )
    if old.generic_parameter_count != new.generic_parameter_count:
        changes.append(
            {
                "kind": "generic_arity",
                "old": old.generic_parameter_count,
                "new": new.generic_parameter_count,
            }
        )
    old_return = old.return_type.display if old.return_type else None
    new_return = new.return_type.display if new.return_type else None
    if old_return != new_return:
        changes.append({"kind": "return_type", "old": old_return, "new": new_return})
    if len(old.parameters) != len(new.parameters):
        changes.append(
            {
                "kind": "parameter_count",
                "old": len(old.parameters),
                "new": len(new.parameters),
            }
        )
    for index in range(min(len(old.parameters), len(new.parameters))):
        old_param = old.parameters[index].display
        new_param = new.parameters[index].display
        if old_param != new_param:
            changes.append(
                {
                    "kind": "parameter_type",
                    "parameter": index,
                    "old": old_param,
                    "new": new_param,
                }
            )
    if not changes and old.identity != new.identity:
        changes.append({"kind": "signature", "old": old.identity, "new": new.identity})
    return changes


def _accessor_changes(old: MemberModel, new: MemberModel) -> List[Dict[str, Any]]:
    if not old.accessors and not new.accessors:
        return []
    changes: List[Dict[str, Any]] = []
    for name in sorted(set(old.accessors) | set(new.accessors)):
        old_accessor = old.accessors.get(name)
        new_accessor = new.accessors.get(name)
        if old_accessor is None and new_accessor is not None:
            changes.append({"kind": "accessor_added", "accessor": name, "new": new_accessor.visibility})
        elif old_accessor is not None and new_accessor is None:
            changes.append({"kind": "accessor_removed", "accessor": name, "old": old_accessor.visibility})
        elif old_accessor is not None and new_accessor is not None:
            if old_accessor.visibility != new_accessor.visibility:
                changes.append(
                    {
                        "kind": "accessor_visibility",
                        "accessor": name,
                        "old": old_accessor.visibility,
                        "new": new_accessor.visibility,
                        "narrowed": _visibility_narrowed(old_accessor.visibility, new_accessor.visibility),
                    }
                )
    return changes


class AbiAuditor:
    """Compare two managed assemblies using read-only metadata evidence."""

    def __init__(
        self,
        old: Any,
        new: Any,
        *,
        approved_sources: Any = None,
        approved_assemblies: Optional[Iterable[str]] = None,
        approved_types: Optional[Iterable[str]] = None,
        trust_core_library: bool = False,
        include_protected: bool = True,
        include_private: bool = False,
    ):
        self.include_protected = include_protected
        self.include_private = include_private
        self.old_source = _source_description(old)
        self.new_source = _source_description(new)
        self.warnings: List[str] = []

        self.old = _coerce_model(old)
        self.new = _coerce_model(new)
        if self.old is None or self.new is None:
            raise AbiAuditError("both old and new inputs must contain .NET metadata")

        models, assembly_names, type_names = _load_approved_sources(approved_sources)
        if approved_assemblies:
            assembly_names.update(str(a) for a in approved_assemblies if a)
        if approved_types:
            type_names.update(str(t) for t in approved_types if t)
        if self.old.assembly_name:
            assembly_names.add(self.old.assembly_name)
        if self.new.assembly_name:
            assembly_names.add(self.new.assembly_name)
        if self.old.assembly_name:
            models.setdefault(self.old.assembly_name.lower(), self.old)
        if self.new.assembly_name:
            models.setdefault(self.new.assembly_name.lower(), self.new)

        self.context = _AuditContext(
            approved_models=models,
            approved_assemblies=assembly_names,
            approved_types=type_names,
            trust_core_library=trust_core_library,
        )
        # External TypeRefs were resolved lazily by the models.  Re-resolve the
        # cached entries with the completed context.
        self._attach_context(self.old)
        self._attach_context(self.new)
        seen_models = {id(self.old), id(self.new)}
        for approved in models.values():
            if id(approved) not in seen_models:
                seen_models.add(id(approved))
                self._attach_context(approved)

    def _attach_context(self, model: _AssemblyModel) -> None:
        for info in list(model._type_ref_cache.values()):
            if info.local or not info.full_name:
                continue
            resolved, source_type, source_model, missing = self.context.resolve_external(
                info.full_name,
                info.assembly,
                info.source or "TypeRef",
            )
            if resolved:
                info.resolved = True
                info.missing = []
                info.source_type = source_type
                info.source_model = source_model
                if source_type is not None:
                    info.source = "approved type source"
            else:
                info.resolved = False
                if missing is not None:
                    info.missing = [missing]
        for info in list(model._type_spec_cache.values()):
            # Type specs are built from the cached TypeRefs; recompute their
            # resolution flag from their component references.
            if info.element_kind == "genericinst":
                info.resolved = all(a.resolved and not a.unresolved for a in info.generic_args)
                if info.dependencies:
                    target = info.dependencies[0]
                    info.source_type = target.source_type
                    info.source_model = target.source_model
            elif info.element_kind in ("szarray", "array", "byref", "pointer"):
                info.resolved = all(a.resolved and not a.unresolved for a in info.generic_args)

    # ------------------------------------------------------------------
    def audit(self, entrypoints: Any = None) -> AbiReport:
        specs = self._normalize_entries(entrypoints)
        results = [self._audit_entry(spec) for spec in specs]
        return AbiReport(
            results,
            old_assembly=self.old.assembly_name,
            new_assembly=self.new.assembly_name,
            warnings=self.warnings + self.old.warnings + self.new.warnings,
        )

    def check(self, entrypoints: Any = None) -> AbiReport:
        return self.audit(entrypoints)

    def compare(self, entrypoints: Any = None) -> AbiReport:
        return self.audit(entrypoints)

    def run(self, entrypoints: Any = None) -> AbiReport:
        return self.audit(entrypoints)

    def report(self, entrypoints: Any = None) -> AbiReport:
        return self.audit(entrypoints)

    def _normalize_entries(self, entrypoints: Any) -> List[EntrySpec]:
        if entrypoints is None:
            return self._default_entries()
        if isinstance(entrypoints, (str, os.PathLike)):
            text = os.fspath(entrypoints)
            if text.lower().endswith(".json") and os.path.isfile(text):
                with open(text, "r", encoding="utf-8") as handle:
                    entrypoints = json.load(handle)
        if isinstance(entrypoints, Mapping):
            for key in ("entrypoints", "entries", "entry_points"):
                if key in entrypoints:
                    return self._normalize_entries(entrypoints[key])
            spec_keys = {
                "type", "type_name", "declaring_type", "class", "owner",
                "member", "member_name", "method", "field", "property",
                "event", "name", "entry", "entry_name", "kind",
                "full_name", "entrypoint", "signature", "parameters",
                "params", "parameter_types",
            }
            if not (set(entrypoints) & spec_keys):
                expanded: List[Any] = []
                for type_name, members in entrypoints.items():
                    if members is None or members is True:
                        expanded.append(type_name)
                    elif isinstance(members, str):
                        expanded.append("%s::%s" % (type_name, members))
                    elif isinstance(members, Mapping):
                        spec = dict(members)
                        spec.setdefault("type", type_name)
                        expanded.append(spec)
                    elif isinstance(members, (list, tuple)):
                        for member in members:
                            if isinstance(member, Mapping):
                                spec = dict(member)
                                spec.setdefault("type", type_name)
                                expanded.append(spec)
                            else:
                                expanded.append("%s::%s" % (type_name, member))
                    else:
                        expanded.append(type_name)
                entrypoints = expanded
        if isinstance(entrypoints, (str, bytes, Mapping, EntrySpec)):
            values = [entrypoints]
        else:
            values = list(entrypoints)
        return [_parse_entrypoint(value, self.old) for value in values]

    def _default_entries(self) -> List[EntrySpec]:
        specs: List[EntrySpec] = []
        for type_model in sorted(self.old.type_defs_by_rid.values(), key=lambda t: t.full_name):
            if not self.include_private and not _is_externally_visible(type_model.effective_visibility, self.include_protected):
                continue
            specs.append(
                EntrySpec(
                    raw=type_model.full_name,
                    type_name=type_model.full_name,
                    kind="type",
                )
            )
            for member in sorted(type_model.declared_members, key=lambda m: (m.kind, m.name, m.identity)):
                if not self.include_private and not _is_externally_visible(member.visibility, self.include_protected):
                    continue
                specs.append(
                    EntrySpec(
                        raw="%s::%s" % (type_model.full_name, member.name),
                        type_name=type_model.full_name,
                        member_name=member.name,
                        kind=member.kind,
                        signature_hint=member.signature.identity,
                    )
                )
        return specs

    # ------------------------------------------------------------------
    def _audit_entry(self, spec: EntrySpec) -> AuditResult:
        if spec.is_type_entry:
            return self._audit_type(spec)
        return self._audit_member(spec)

    def _audit_type(self, spec: EntrySpec) -> AuditResult:
        old_type = _lookup_entry_type(self.old, spec.type_name)
        if old_type is None:
            return AuditResult(
                entry=spec.raw,
                name=spec.display_name,
                kind="type",
                status=AbiStatus.UNRESOLVED,
                reason="entry type is not present in the old assembly; no old identity to audit",
                unresolved=[
                    MissingReference(
                        kind="entry",
                        name=spec.type_name or spec.display_name,
                        reason="entry type is not present in the old assembly",
                    )
                ],
            )

        new_type = _lookup_entry_type(self.new, old_type.full_name)
        changes: List[Dict[str, Any]] = []
        unresolved: List[MissingReference] = []
        evidence_incomplete: List[MissingReference] = []
        if old_type.base_ref is not None:
            evidence_incomplete.extend(old_type.base_ref.unresolved)
        if old_type.interfaces:
            evidence_incomplete.extend(_unique_missing_from_types(old_type.interfaces))

        if new_type is None:
            return AuditResult(
                entry=spec.raw,
                name=old_type.full_name,
                kind="type",
                status=AbiStatus.CHANGED,
                reason="type is absent from the new assembly",
                old_identity="T:" + old_type.full_name,
                declaring_type=old_type.full_name,
                old_visibility=old_type.effective_visibility,
                old=old_type.to_dict(),
                changes=[{"kind": "type_removed"}],
                details={"old_type": old_type.full_name},
            )

        new_unresolved: List[MissingReference] = []
        if new_type.base_ref is not None:
            new_unresolved.extend(new_type.base_ref.unresolved)
        if new_type.interfaces:
            new_unresolved.extend(_unique_missing_from_types(new_type.interfaces))
        evidence_incomplete.extend(new_unresolved)

        visibility_change = _visibility_change(old_type.effective_visibility, new_type.effective_visibility)
        if visibility_change:
            changes.append(visibility_change)

        old_base = old_type.base_ref.display if old_type.base_ref else None
        new_base = new_type.base_ref.display if new_type.base_ref else None
        if old_base != new_base:
            change = {"kind": "base_type", "old": old_base, "new": new_base}
            changes.append(change)
            if (
                old_type.base_ref is not None
                and new_type.base_ref is not None
                and (old_type.base_ref.unresolved or new_type.base_ref.unresolved)
            ):
                unresolved.extend(old_type.base_ref.unresolved)
                unresolved.extend(new_type.base_ref.unresolved)

        old_interfaces = sorted(i.display for i in old_type.interfaces)
        new_interfaces = sorted(i.display for i in new_type.interfaces)
        if old_interfaces != new_interfaces:
            changes.append(
                {
                    "kind": "interfaces",
                    "old": old_interfaces,
                    "new": new_interfaces,
                }
            )
            for interface in old_type.interfaces + new_type.interfaces:
                unresolved.extend(interface.unresolved)

        # Summarize members but keep the type-level result independent: an
        # opaque base type must not turn every directly declared member into an
        # unresolved result.
        old_members, old_inheritance_missing = self.old.effective_members(
            old_type,
            include_protected=self.include_protected,
            include_private=self.include_private,
        )
        new_members, new_inheritance_missing = self.new.effective_members(
            new_type,
            include_protected=self.include_protected,
            include_private=self.include_private,
        )
        old_by_identity = {m.compatibility_identity: m for m in old_members}
        new_by_identity = {m.compatibility_identity: m for m in new_members}
        missing_members = sorted(set(old_by_identity) - set(new_by_identity))
        member_summary = {
            "old_count": len(old_members),
            "new_count": len(new_members),
            "missing_identities": missing_members[:50],
            "inheritance_old_incomplete": bool(old_inheritance_missing),
            "inheritance_new_incomplete": bool(new_inheritance_missing),
        }
        unresolved = _unique_missing(list(unresolved) + list(evidence_incomplete))
        if any(change.get("kind") == "type_removed" for change in changes):
            status = AbiStatus.CHANGED
            reason = "type is absent from the new assembly"
        elif any(
            change.get("kind") in ("base_type", "interfaces") for change in changes
        ):
            status = AbiStatus.CHANGED
            reason = "type contract changed: %s" % ", ".join(c["kind"] for c in changes)
        elif visibility_change and visibility_change.get("narrowed"):
            status = AbiStatus.CHANGED
            reason = "type visibility narrowed from %s to %s" % (
                old_type.effective_visibility,
                new_type.effective_visibility,
            )
        elif unresolved:
            status = AbiStatus.UNRESOLVED
            reason = "type references cross an unresolved source: %s" % ", ".join(str(m) for m in unresolved[:4])
        elif visibility_change:
            status = AbiStatus.SUPPORTED
            reason = "type identity unchanged; visibility widened from %s to %s" % (
                old_type.effective_visibility,
                new_type.effective_visibility,
            )
        else:
            status = AbiStatus.SUPPORTED
            reason = "type identity and visibility are unchanged"

        return AuditResult(
            entry=spec.raw,
            name=old_type.full_name,
            kind="type",
            status=status,
            reason=reason,
            old_identity="T:" + old_type.full_name,
            new_identity="T:" + new_type.full_name,
            declaring_type=old_type.full_name,
            old_visibility=old_type.effective_visibility,
            new_visibility=new_type.effective_visibility,
            old=old_type.to_dict(),
            new=new_type.to_dict(),
            changes=changes,
            unresolved=unresolved,
            details={
                "members": member_summary,
                "base_old": old_base,
                "base_new": new_base,
                "interfaces_old": old_interfaces,
                "interfaces_new": new_interfaces,
                "evidence_incomplete": [m.to_dict() for m in _unique_missing(evidence_incomplete)],
            },
        )

    # ------------------------------------------------------------------
    def _audit_member(self, spec: EntrySpec) -> AuditResult:
        old_type = _lookup_entry_type(self.old, spec.type_name)
        if old_type is None:
            return AuditResult(
                entry=spec.raw,
                name=spec.display_name,
                kind=spec.kind or "member",
                status=AbiStatus.UNRESOLVED,
                reason="declaring type is not present in the old assembly",
                declaring_type=spec.type_name,
                member_name=spec.member_name,
                unresolved=[
                    MissingReference(
                        kind="entry",
                        name=spec.type_name or spec.display_name,
                        reason="declaring type is not present in the old assembly",
                    )
                ],
            )

        old_candidates, old_inheritance_missing = self.old.effective_members(
            old_type,
            include_protected=self.include_protected,
            include_private=self.include_private,
        )
        old_matches = [m for m in old_candidates if _candidate_name_matches(spec, m)]
        if not old_matches:
            if old_inheritance_missing:
                return self._unresolved_member_result(
                    spec,
                    old_type,
                    "member is not declared locally and inherited members cannot be resolved",
                    old_inheritance_missing,
                )
            return AuditResult(
                entry=spec.raw,
                name=spec.display_name,
                kind=spec.kind or "member",
                status=AbiStatus.UNRESOLVED,
                reason="entry member is not present in the old assembly; no old identity to audit",
                declaring_type=old_type.full_name,
                member_name=spec.member_name,
                unresolved=[
                    MissingReference(
                        kind="entry",
                        name=spec.display_name,
                        reason="entry member is not present in the old assembly",
                    )
                ],
            )

        new_type = _lookup_entry_type(self.new, old_type.full_name)
        if new_type is None:
            old_member = old_matches[0]
            return AuditResult(
                entry=spec.raw,
                name=spec.display_name,
                kind=old_member.kind,
                status=AbiStatus.CHANGED,
                reason="declaring type is absent from the new assembly",
                old_identity=old_member.identity,
                declaring_type=old_type.full_name,
                member_name=old_member.name,
                old_visibility=old_member.visibility,
                signature=old_member.signature.to_dict(),
                old=_member_summary(old_member),
                changes=[{"kind": "type_removed", "type": old_type.full_name}],
                inherited_from=old_member.inherited_from or None,
            )

        new_candidates, new_inheritance_missing = self.new.effective_members(
            new_type,
            include_protected=self.include_protected,
            include_private=self.include_private,
        )
        new_matches = [m for m in new_candidates if _candidate_name_matches(spec, m)]
        if not new_matches and len(old_matches) == 1:
            # A declaration may still exist with reduced visibility (for
            # example public -> private).  That is a definite visibility
            # change even when the member is no longer in the public surface.
            declared = [
                m
                for m in new_type.declared_members
                if _candidate_name_matches(
                    spec,
                    EffectiveMember(
                        member=m,
                        declaring_type=new_type,
                        compat_identity=_member_compat_identity(m),
                    ),
                )
            ]
            if declared:
                candidate = EffectiveMember(
                    member=declared[0],
                    declaring_type=new_type,
                    compat_identity=_member_compat_identity(declared[0]),
                )
                return self._compare_changed_member(spec, old_matches[0], candidate)
        if not new_matches and new_inheritance_missing:
            return self._unresolved_member_result(
                spec,
                old_type,
                "member is not declared locally in the new assembly and inherited members cannot be resolved",
                old_inheritance_missing + new_inheritance_missing,
                old_matches=old_matches,
            )

        if len(old_matches) > 1:
            return self._audit_overload_group(spec, old_type, old_matches, new_matches)

        old_member = old_matches[0]
        exact_matches = [m for m in new_matches if m.compatibility_identity == old_member.compatibility_identity]
        if exact_matches:
            new_member = exact_matches[0]
            return self._compare_matched_member(
                spec,
                old_member,
                new_member,
                old_inheritance_missing + new_inheritance_missing,
            )

        # The same name exists but with a different identity.
        if new_matches:
            new_member = new_matches[0]
            return self._compare_changed_member(spec, old_member, new_member)

        # No same-name member: if we could not enumerate one side's
        # inheritance, we must not call it removed.
        if old_inheritance_missing or new_inheritance_missing:
            return self._unresolved_member_result(
                spec,
                old_type,
                "member is absent from the visible declarations, but an inherited member may exist in an unresolved base type",
                old_inheritance_missing + new_inheritance_missing,
                old_matches=old_matches,
            )

        return AuditResult(
            entry=spec.raw,
            name=spec.display_name,
            kind=old_member.kind,
            status=AbiStatus.CHANGED,
            reason="member identity is absent from the new assembly",
            old_identity=old_member.identity,
            new_identity=None,
            declaring_type=old_type.full_name,
            member_name=old_member.name,
            old_visibility=old_member.visibility,
            signature=old_member.signature.to_dict(),
            old=_member_summary(old_member),
            changes=[{"kind": "member_removed", "identity": old_member.identity}],
            inherited_from=old_member.inherited_from or None,
        )

    def _audit_overload_group(
        self,
        spec: EntrySpec,
        old_type: TypeModel,
        old_matches: List[EffectiveMember],
        new_matches: List[EffectiveMember],
    ) -> AuditResult:
        new_by_identity = {m.compatibility_identity: m for m in new_matches}
        matched = [m for m in old_matches if m.compatibility_identity in new_by_identity]
        missing = [m for m in old_matches if m.compatibility_identity not in new_by_identity]
        unresolved: List[MissingReference] = []
        for member in old_matches + new_matches:
            unresolved.extend(member.member.unresolved)
        unresolved = _unique_missing(unresolved)
        if unresolved:
            status = AbiStatus.UNRESOLVED
            reason = "overload set crosses unresolved references"
        elif missing:
            status = AbiStatus.CHANGED
            reason = "%d of %d old overload identities are absent" % (len(missing), len(old_matches))
        else:
            status = AbiStatus.SUPPORTED
            reason = "all old overload identities remain present"
        return AuditResult(
            entry=spec.raw,
            name=spec.display_name,
            kind=old_matches[0].kind,
            status=status,
            reason=reason,
            old_identity=" | ".join(m.identity for m in old_matches),
            new_identity=" | ".join(m.identity for m in new_matches) if new_matches else None,
            declaring_type=old_type.full_name,
            member_name=old_matches[0].name,
            old_visibility=",".join(sorted(set(m.visibility for m in old_matches))),
            new_visibility=",".join(sorted(set(m.visibility for m in new_matches))) if new_matches else None,
            old={"overloads": [_member_summary(m) for m in old_matches]},
            new={"overloads": [_member_summary(m) for m in new_matches]},
            changes=(
                [{"kind": "overload_removed", "identity": m.identity} for m in missing]
                if missing
                else []
            ),
            unresolved=unresolved,
            details={
                "overload_set": True,
                "matched": [m.identity for m in matched],
                "missing": [m.identity for m in missing],
            },
        )

    def _compare_matched_member(
        self,
        spec: EntrySpec,
        old_member: EffectiveMember,
        new_member: EffectiveMember,
        inheritance_missing: List[MissingReference],
    ) -> AuditResult:
        unresolved = _unique_missing(
            list(old_member.member.unresolved)
            + list(new_member.member.unresolved)
        )
        changes: List[Dict[str, Any]] = []
        visibility_change = _visibility_change(old_member.visibility, new_member.visibility)
        if visibility_change:
            changes.append(visibility_change)
        signature_changes = _signature_changes(old_member.signature, new_member.signature)
        changes.extend(signature_changes)
        changes.extend(_accessor_changes(old_member.member, new_member.member))

        inheritance_note = None
        if new_member.inherited_from:
            inheritance_note = {
                "old_declaring_type": old_member.member.declaring_type.full_name,
                "new_declaring_type": new_member.member.declaring_type.full_name,
                "new_inherited_from": list(new_member.inherited_from),
                "moved_to_base": (
                    old_member.member.declaring_type.full_name
                    != new_member.member.declaring_type.full_name
                ),
            }

        if unresolved:
            status = AbiStatus.UNRESOLVED
            reason = "identity comparison needs an unresolved component: %s" % ", ".join(
                str(m) for m in unresolved[:4]
            )
        elif signature_changes:
            status = AbiStatus.CHANGED
            reason = "public interface identity changed: %s" % ", ".join(
                sorted(set(c["kind"] for c in signature_changes))
            )
        elif any(
            c.get("kind") == "accessor_removed"
            or (c.get("kind") == "accessor_visibility" and c.get("narrowed"))
            for c in changes
        ):
            status = AbiStatus.CHANGED
            reason = "property/event accessor was removed or narrowed"
        elif visibility_change and visibility_change.get("narrowed"):
            status = AbiStatus.CHANGED
            reason = "visibility narrowed from %s to %s" % (
                old_member.visibility,
                new_member.visibility,
            )
        else:
            status = AbiStatus.SUPPORTED
            if inheritance_note and inheritance_note["moved_to_base"]:
                reason = "same identity is supported through inheritance from %s" % (
                    new_member.member.declaring_type.full_name
                )
            elif visibility_change:
                reason = "identity unchanged; visibility widened from %s to %s" % (
                    old_member.visibility,
                    new_member.visibility,
                )
            else:
                reason = "identity and visibility are unchanged"

        return AuditResult(
            entry=spec.raw,
            name=spec.display_name,
            kind=old_member.kind,
            status=status,
            reason=reason,
            old_identity=old_member.identity,
            new_identity=new_member.identity,
            declaring_type=old_member.member.declaring_type.full_name,
            member_name=old_member.name,
            old_visibility=old_member.visibility,
            new_visibility=new_member.visibility,
            signature=old_member.signature.to_dict(),
            old=_member_summary(old_member),
            new=_member_summary(new_member),
            changes=changes,
            inherited_from=new_member.inherited_from or None,
            unresolved=unresolved,
            details={
                "inheritance": inheritance_note,
                "inheritance_evidence_incomplete": [m.to_dict() for m in _unique_missing(inheritance_missing)],
                "parameters_old": old_member.signature.parameter_types,
                "parameters_new": new_member.signature.parameter_types,
            },
        )

    def _compare_changed_member(
        self,
        spec: EntrySpec,
        old_member: EffectiveMember,
        new_member: EffectiveMember,
    ) -> AuditResult:
        changes = _signature_changes(old_member.signature, new_member.signature)
        visibility_change = _visibility_change(old_member.visibility, new_member.visibility)
        if visibility_change:
            changes.append(visibility_change)
        changes.extend(_accessor_changes(old_member.member, new_member.member))
        unresolved = _unique_missing(list(old_member.member.unresolved) + list(new_member.member.unresolved))

        for change in changes:
            if change.get("kind") == "parameter_type":
                change["parameter"] = int(change.get("parameter", 0)) + 1  # human-facing 1-based index

        if unresolved:
            status = AbiStatus.UNRESOLVED
            reason = "identity differs, but a referenced component is unresolved"
        elif changes:
            status = AbiStatus.CHANGED
            signature_kinds = [c["kind"] for c in changes if c["kind"] not in ("visibility",)]
            if signature_kinds:
                reason = "public interface identity changed: %s" % ", ".join(sorted(set(signature_kinds)))
            else:
                reason = "visibility changed from %s to %s" % (
                    old_member.visibility,
                    new_member.visibility,
                )
        else:
            status = AbiStatus.CHANGED
            reason = "member identity changed"

        return AuditResult(
            entry=spec.raw,
            name=spec.display_name,
            kind=old_member.kind,
            status=status,
            reason=reason,
            old_identity=old_member.identity,
            new_identity=new_member.identity,
            declaring_type=old_member.member.declaring_type.full_name,
            member_name=old_member.name,
            old_visibility=old_member.visibility,
            new_visibility=new_member.visibility,
            signature=old_member.signature.to_dict(),
            old=_member_summary(old_member),
            new=_member_summary(new_member),
            changes=changes,
            inherited_from=new_member.inherited_from or None,
            unresolved=unresolved,
            details={
                "parameters_old": old_member.signature.parameter_types,
                "parameters_new": new_member.signature.parameter_types,
                "signature_old": old_member.signature.identity,
                "signature_new": new_member.signature.identity,
            },
        )

    def _unresolved_member_result(
        self,
        spec: EntrySpec,
        old_type: TypeModel,
        reason: str,
        missing: Iterable[MissingReference],
        *,
        old_matches: Optional[List[EffectiveMember]] = None,
    ) -> AuditResult:
        unique = _unique_missing(missing)
        old_identity = None
        if old_matches:
            old_identity = old_matches[0].identity
        return AuditResult(
            entry=spec.raw,
            name=spec.display_name,
            kind=spec.kind or "member",
            status=AbiStatus.UNRESOLVED,
            reason=reason,
            old_identity=old_identity,
            declaring_type=old_type.full_name,
            member_name=spec.member_name,
            old=_member_summary(old_matches[0]) if old_matches else None,
            unresolved=unique,
            details={"missing_evidence": [m.to_dict() for m in unique]},
        )


AbiAudit = AbiAuditor


# ----------------------------------------------------------------------
# Input coercion and approved sources
# ----------------------------------------------------------------------
def _source_description(value: Any) -> Optional[str]:
    if isinstance(value, (str, os.PathLike)):
        return os.fspath(value)
    if isinstance(value, (bytes, bytearray)):
        return "<memory:%d bytes>" % len(value)
    source = getattr(value, "source", None)
    if source:
        return str(source)
    name = getattr(value, "name", None)
    if isinstance(name, (str, os.PathLike)):
        return os.fspath(name)
    return None


def _coerce_pe(value: Any) -> Any:
    if isinstance(value, dnfile.dnPE):
        return value
    if isinstance(value, _AssemblyModel):
        return value.pe
    if isinstance(value, (bytes, bytearray, memoryview)):
        return dnfile.dnPE(data=bytes(value))
    if isinstance(value, (str, os.PathLike)):
        return dnfile.dnPE(name=os.fspath(value))
    if hasattr(value, "net"):
        return value
    if hasattr(value, "read") and callable(getattr(value, "read")):
        if hasattr(value, "seek"):
            try:
                value.seek(0)
            except Exception:
                pass
        data = value.read()
        if isinstance(data, str):
            data = data.encode("latin1", "replace")
        return dnfile.dnPE(data=bytes(data))
    raise AbiAuditError("unsupported assembly input: %r" % (value,))


def _coerce_model(value: Any) -> _AssemblyModel:
    if isinstance(value, _AssemblyModel):
        return value
    pe = _coerce_pe(value)
    return _AssemblyModel(pe, source=_source_description(value))


def _looks_like_path(value: str) -> bool:
    suffixes = (".dll", ".exe", ".winmd", ".netmodule")
    return os.path.sep in value or (os.path.altsep and os.path.altsep in value) or value.lower().endswith(suffixes)


def _load_approved_sources(
    approved_sources: Any,
) -> Tuple[Dict[str, _AssemblyModel], Set[str], Set[str]]:
    models: Dict[str, _AssemblyModel] = {}
    assembly_names: Set[str] = set()
    type_names: Set[str] = set()

    if approved_sources is None:
        return models, assembly_names, type_names
    if isinstance(approved_sources, (str, os.PathLike)):
        text = os.fspath(approved_sources)
        if text.lower().endswith(".json") and os.path.isfile(text):
            with open(text, "r", encoding="utf-8") as handle:
                approved_sources = json.load(handle)

    if isinstance(approved_sources, Mapping):
        items: Iterable[Any] = list(approved_sources.items())
    elif isinstance(approved_sources, (str, bytes, os.PathLike, dnfile.dnPE, _AssemblyModel)):
        items = [approved_sources]
    else:
        items = list(approved_sources)

    for item in items:
        key: Optional[str] = None
        value = item
        if isinstance(item, tuple) and len(item) == 2:
            key = str(item[0])
            value = item[1]

        if isinstance(value, str) and not _looks_like_path(value):
            # A bare name is an explicitly approved assembly identity.  Its
            # types can be named in signatures, but its members cannot be
            # enumerated.
            assembly_names.add(value)
            # A bare qualified name may also be a caller-approved type
            # identity.  Recording both interpretations is harmless and makes
            # the source list forgiving for CLI users.
            if "." in value:
                type_names.add(_normalize_type_name(value))
            if key:
                assembly_names.add(key)
            continue

        if isinstance(value, (str, bytes, bytearray, memoryview, os.PathLike, dnfile.dnPE, _AssemblyModel)) or (
            hasattr(value, "read") and callable(getattr(value, "read"))
        ):
            try:
                model = _coerce_model(value)
            except Exception:
                if isinstance(value, str):
                    assembly_names.add(value)
                continue
            names = set()
            if model.assembly_name:
                names.add(model.assembly_name.lower())
            if key:
                names.add(key.lower())
            for name in names:
                models[name] = model
            for type_model in model.type_defs_by_rid.values():
                type_names.add(type_model.full_name)
            continue

        # Objects with metadata-like attributes.
        path = getattr(item, "path", None)
        name = getattr(item, "name", None)
        metadata = getattr(item, "metadata", None)
        if path is not None:
            try:
                model = _coerce_model(path)
            except Exception:
                if name:
                    assembly_names.add(str(name))
                continue
            if name:
                models[str(name).lower()] = model
            if model.assembly_name:
                models[model.assembly_name.lower()] = model
            continue
        if metadata is not None:
            try:
                model = _AssemblyModel(metadata, source=_source_description(item))
            except Exception:
                continue
            if name:
                models[str(name).lower()] = model
            if model.assembly_name:
                models[model.assembly_name.lower()] = model
            continue
        if name:
            assembly_names.add(str(name))
        elif key:
            if "." in key:
                type_names.add(_normalize_type_name(key))
            else:
                assembly_names.add(key)

    return models, assembly_names, type_names


# ----------------------------------------------------------------------
# Public functions
# ----------------------------------------------------------------------
def audit_abi(
    old: Any = None,
    new: Any = None,
    entrypoints: Any = None,
    approved_sources: Any = None,
    *,
    entry_points: Any = None,
    entries: Any = None,
    entry_names: Any = None,
    entry_list: Any = None,
    approved_assemblies: Optional[Iterable[str]] = None,
    approved_types: Optional[Iterable[str]] = None,
    type_sources: Any = None,
    trusted_sources: Any = None,
    recognized_sources: Any = None,
    sources: Any = None,
    old_assembly: Any = None,
    new_assembly: Any = None,
    trust_core_library: bool = False,
    include_protected: bool = True,
    include_private: bool = False,
) -> AbiReport:
    """Audit the old public interfaces of ``old`` against ``new``.

    Parameters
    ----------
    old, new:
        Paths, ``bytes``, ``dnfile.dnPE`` objects, or ``_AssemblyModel``
        objects.  They are parsed read-only.
    entrypoints:
        The caller's list of old interfaces.  A string, iterable of strings,
        mappings, tuples, or :class:`EntrySpec` objects are accepted.  Each
        string may be ``Namespace.Type``, ``Namespace.Type::Member``,
        ``Namespace.Type.Member``, or a reflection-style
        ``M:Namespace.Type::Member``.  If omitted, the complete externally
        visible old surface is audited.
    approved_sources:
        Assemblies or type names the caller accepts as resolution evidence.
        Paths and ``dnPE`` objects are parsed (enabling inherited-member
        inspection); bare assembly names and type names vouch for identity
        without providing member metadata.

    The result is an :class:`AbiReport`.  References that leave the two input
    assemblies and the approved sources are reported as ``unresolved`` rather
    than guessed.
    """

    if old is None:
        old = old_assembly
    if new is None:
        new = new_assembly
    if old is None or new is None:
        raise AbiAuditError("both old and new assemblies are required")
    if entrypoints is None:
        for candidate in (entry_points, entries, entry_names, entry_list):
            if candidate is not None:
                entrypoints = candidate
                break
    if approved_sources is None:
        for candidate in (type_sources, trusted_sources, recognized_sources, sources):
            if candidate is not None:
                approved_sources = candidate
                break
    auditor = AbiAuditor(
        old,
        new,
        approved_sources=approved_sources,
        approved_assemblies=approved_assemblies,
        approved_types=approved_types,
        trust_core_library=trust_core_library,
        include_protected=include_protected,
        include_private=include_private,
    )
    return auditor.audit(entrypoints)


def audit(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def abi_audit(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def compare_assemblies(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def compare_abi(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def check_abi(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def diff_abi(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)
def audit_compatibility(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def check_compatibility(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def compare_versions(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def analyze_abi(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)



def audit_assembly_pair(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def compare_managed_assemblies(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)

AbiChecker = AbiAuditor
AbiCompatibilityChecker = AbiAuditor


def compare_api(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def abi_diff(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


def check_public_api(
    old: Any,
    new: Any,
    entrypoints: Any = None,
    approved_sources: Any = None,
    **kwargs: Any,
) -> AbiReport:
    return audit_abi(old, new, entrypoints, approved_sources, **kwargs)


# ----------------------------------------------------------------------
# Command line
# ----------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dnfile-abi",
        description="Read-only managed ABI audit using dnfile metadata.",
    )
    parser.add_argument("old", help="old managed assembly")
    parser.add_argument("new", help="new managed assembly")
    parser.add_argument(
        "-e",
        "--entry",
        "--entrypoint",
        dest="entries",
        action="append",
        default=None,
        help="old entry point (repeatable); omit to audit the public surface",
    )
    parser.add_argument(
        "-s",
        "--source",
        "--approved-source",
        dest="sources",
        action="append",
        default=None,
        help="approved type source assembly or type name (repeatable)",
    )
    parser.add_argument(
        "--include-private",
        action="store_true",
        help="include non-public declarations in the default surface",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="write the complete report as JSON",
    )
    parser.add_argument(
        "--fail-on-changed",
        action="store_true",
        help="exit 1 if any interface changed",
    )
    args = parser.parse_args(argv)

    try:
        report = audit_abi(
            args.old,
            args.new,
            entrypoints=args.entries,
            approved_sources=args.sources,
            include_protected=True,
            include_private=args.include_private,
        )
    except Exception as exc:
        print("dnfile-abi: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(report.to_json())
    else:
        print(report.format_text())
    if report.unresolved:
        return 2
    if args.fail_on_changed and report.changed:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
