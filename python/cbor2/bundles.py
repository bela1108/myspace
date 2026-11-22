"""Offline reference auditing for CBOR bundles.

A *bundle* is a CBOR document with a public index and, optionally, the
contents of the entries listed in that index::

    {
        "bundle": "A",
        "index": {
            0: {"refs": [{"local": 1}, {"bundle": "B", "id": 7}]},
            1: {"content": "the evidence"},
        },
        "entries": {1: "the evidence"},
    }

The index is intentionally separate from the entry contents.  A recipient can
therefore inspect what a bundle refers to even when the actual entry lives in
another, separately approved bundle.  Local entry numbers are always scoped to
the bundle that declares them: ``("A", 0)`` and ``("B", 0)`` are different
entries even though both use the local number ``0``.

The helpers in this module deliberately build on the public decoding entry
points (:func:`cbor2.load` and :func:`cbor2.loads`).  They do not require a
special decoder backend and never perform network I/O.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, TypeAlias, cast

from . import CBORTag, load, loads

__all__ = [
    "ABSENT",
    "AuditReport",
    "Bundle",
    "BundleManifest",
    "CROSS_REF_TAG",
    "ChecklistItem",
    "ChecklistEntry",
    "Conclusion",
    "DENIED",
    "EntryDescriptor",
    "EntryId",
    "EvidencePolicy",
    "EvidencePermissions",
    "FORBIDDEN",
    "HandoverReport",
    "LOCAL_REF_TAG",
    "MISSING",
    "NOT_FOUND",
    "NOT_AUTHORIZED",
    "PRESENT",
    "Package",
    "Reference",
    "ReferenceKind",
    "ReferenceState",
    "ReferenceStatus",
    "RESOLVED",
    "Resolution",
    "UNAUTHORIZED",
    "UNAPPROVED",
    "audit",
    "audit_bundles",
    "audit_claim",
    "audit_handover",
    "audit_packages",
    "build_checklist",
    "check_bundles",
    "check_claim",
    "check_handover",
    "check_packages",
    "closure",
    "cross_ref",
    "dump_bundle",
    "dumps_bundle",
    "handover_check",
    "handover_audit",
    "load_bundle",
    "load_bundles",
    "loads_bundle",
    "loads_bundles",
    "local_ref",
    "make_bundle",
    "parse_bundle",
    "public_index",
    "reference_semantic_decoders",
    "reference_tag_hook",
    "resolve_claim",
    "resolve_reference",
    "resolve_references",
    "trace_references",
    "verify_claim",
    "verify_handover",
]

EntryId: TypeAlias = int | str
BundleKey: TypeAlias = tuple[str, EntryId]


class ReferenceKind(str, Enum):
    """Where an entry reference points."""

    LOCAL = "local"
    CROSS_BUNDLE = "cross_bundle"
    CROSS_PACKAGE = "cross_bundle"
    CROSS = "cross_bundle"


class ReferenceStatus(str, Enum):
    """The outcome of resolving one reference."""

    RESOLVED = "resolved"
    MISSING = "missing"
    FORBIDDEN = "forbidden"

    ABSENT = "missing"
    NOT_FOUND = "missing"
    UNAUTHORIZED = "forbidden"
    NOT_AUTHORIZED = "forbidden"
    UNAPPROVED = "forbidden"
    DENIED = "forbidden"
    RESTRICTED = "forbidden"
    WITHDRAWN = "missing"
    PRESENT = "resolved"


RESOLVED = ReferenceStatus.RESOLVED
MISSING = ReferenceStatus.MISSING
FORBIDDEN = ReferenceStatus.FORBIDDEN
ABSENT = ReferenceStatus.MISSING
PRESENT = ReferenceStatus.RESOLVED
UNAUTHORIZED = ReferenceStatus.FORBIDDEN
NOT_AUTHORIZED = ReferenceStatus.FORBIDDEN
UNAPPROVED = ReferenceStatus.FORBIDDEN
DENIED = ReferenceStatus.FORBIDDEN
NOT_FOUND = ReferenceStatus.MISSING

ReferenceState = ReferenceStatus

LOCAL_REF_TAG = 1000
CROSS_REF_TAG = 1001

_ABSENT = object()


def _as_name(value: Any) -> str | None:
    """Convert a bundle name to a stable string."""

    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    return str(value)


def _as_entry_id(value: Any) -> EntryId:
    """Convert an entry identifier to a hashable, printable local number."""

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    return str(value)


def _first(mapping: Mapping[Any, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return _ABSENT


@dataclass(frozen=True)
class Reference:
    """A local or cross-bundle reference to an indexed entry.

    ``bundle`` is ``None`` for a local reference.  The origin fields are
    filled in when a reference is discovered inside an entry; they are what
    makes the resulting checklist ordered by provenance.
    """

    entry: EntryId
    bundle: str | None = None
    origin_bundle: str | None = field(default=None, compare=False)
    origin_entry: EntryId | None = field(default=None, compare=False)
    ordinal: int = field(default=0, compare=False)
    kind_hint: ReferenceKind | None = field(default=None, compare=False)

    @property
    def kind(self) -> ReferenceKind:
        if self.kind_hint is not None:
            return self.kind_hint
        if self.bundle is None:
            return ReferenceKind.LOCAL
        return ReferenceKind.CROSS_BUNDLE

    @property
    def is_local(self) -> bool:
        return self.kind is ReferenceKind.LOCAL

    @property
    def is_cross_bundle(self) -> bool:
        return not self.is_local

    def target(self, source_bundle: str | None = None) -> BundleKey:
        bundle = self.bundle if self.bundle is not None else source_bundle
        if bundle is None:
            raise ValueError("local reference has no source bundle")
        return (bundle, self.entry)

    def bind(
        self,
        *,
        origin_bundle: str | None,
        origin_entry: EntryId | None,
        ordinal: int,
    ) -> Reference:
        return replace(
            self,
            origin_bundle=origin_bundle,
            origin_entry=origin_entry,
            ordinal=ordinal,
        )

    def to_dict(self) -> dict[str, Any]:
        if self.bundle is None:
            return {"local": self.entry}
        return {"bundle": self.bundle, "id": self.entry}


@dataclass(frozen=True)
class EntryDescriptor:
    """The publicly shareable description of one indexed entry."""

    raw: Any = None
    refs: tuple[Reference, ...] = ()
    home_bundle: str | None = None
    redirect: Reference | None = None
    content: Any = _ABSENT
    content_present: bool = False
    meta: Mapping[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = dict(self.meta)
        if self.refs:
            result["refs"] = [ref.to_dict() for ref in self.refs]
        if self.home_bundle is not None:
            result["home"] = self.home_bundle
        if self.redirect is not None:
            result["redirect"] = self.redirect.to_dict()
        return result


@dataclass(frozen=True)
class Bundle:
    """A CBOR package with a public index and optional private entries."""

    name: str
    index: Mapping[EntryId, EntryDescriptor] = field(default_factory=dict)
    entries: Mapping[EntryId, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _as_name(self.name) or "")
        entries = {_as_entry_id(key): value for key, value in self.entries.items()}
        index: dict[EntryId, EntryDescriptor] = {}
        for key, value in self.index.items():
            entry = _as_entry_id(key)
            if isinstance(value, EntryDescriptor):
                index[entry] = value
            else:
                index[entry] = _make_descriptor(
                    value, standalone_index=not entries
                )
        object.__setattr__(self, "index", index)
        object.__setattr__(self, "entries", entries)

    def entry_ids(self) -> tuple[EntryId, ...]:
        """Return indexed entry numbers in declaration order."""

        return tuple(self.index)

    def descriptor(self, entry: EntryId) -> EntryDescriptor | None:
        return self.index.get(entry)

    def has_content(self, entry: EntryId) -> bool:
        if entry in self.entries:
            return True
        descriptor = self.index.get(entry)
        return bool(descriptor and descriptor.content_present)

    def content_for(self, entry: EntryId) -> Any:
        if entry in self.entries:
            return self.entries[entry]
        descriptor = self.index.get(entry)
        if descriptor and descriptor.content_present:
            return descriptor.content
        raise KeyError(entry)

    def public_index(self) -> dict[EntryId, dict[str, Any]]:
        """Return the public part of the index, never entry contents."""

        return {
            entry: descriptor.to_public_dict()
            for entry, descriptor in self.index.items()
        }

    def to_dict(self, *, include_entries: bool = True) -> dict[str, Any]:
        document: dict[str, Any] = {
            "bundle": self.name,
            "index": {
                entry: descriptor.to_public_dict()
                for entry, descriptor in self.index.items()
            },
        }
        if include_entries:
            entries = dict(self.entries)
            for entry, descriptor in self.index.items():
                if entry not in entries and descriptor.content_present:
                    entries[entry] = descriptor.content
            document["entries"] = entries
        return document


@dataclass(frozen=True)
class Resolution:
    """The result of resolving one reference target."""

    status: ReferenceStatus
    bundle: str | None
    entry: EntryId
    content: Any = None
    reason: str = ""
    resolved_bundle: str | None = None
    resolved_entry: EntryId | None = None

    @property
    def key(self) -> BundleKey | None:
        bundle = self.resolved_bundle if self.resolved_bundle is not None else self.bundle
        if bundle is None:
            return None
        return (bundle, self.resolved_entry if self.resolved_entry is not None else self.entry)

    @property
    def state(self) -> ReferenceStatus:
        return self.status


@dataclass(frozen=True)
class EvidencePermissions:
    """A caller-declared permission boundary for reference closure.

    ``full`` contains bundles whose whole index may be inspected,
    ``partial`` contains per-entry allowlists and ``denied`` contains bundles
    that may not be inspected at all.  Bundles not mentioned anywhere use the
    ``default`` decision (allow by default, matching a normal offline check).
    """

    full: frozenset[str] = frozenset()
    partial: Mapping[str, frozenset[EntryId]] = field(default_factory=dict)
    denied: frozenset[str] = frozenset()
    default: bool = True

    def allows(self, bundle: str, entry: EntryId) -> bool:
        if bundle in self.denied:
            return False
        if bundle in self.full:
            return True
        allowed_entries = self.partial.get(bundle)
        if allowed_entries is not None:
            return entry in allowed_entries
        return self.default

    @classmethod
    def coerce(cls, value: Any, *, default: bool = True) -> EvidencePermissions:
        if isinstance(value, EvidencePermissions):
            return value
        if value is None:
            return cls(default=default)
        if isinstance(value, bool):
            return cls(default=value)
        if isinstance(value, str):
            return cls(full=frozenset({value}), default=False)
        if not isinstance(value, Mapping):
            if isinstance(value, Collection):
                items = list(value)
                if items and all(
                    isinstance(item, (tuple, list)) and len(item) == 2
                    for item in items
                ):
                    partial: dict[str, set[EntryId]] = {}
                    for raw_bundle, raw_entry in items:
                        bundle = _as_name(raw_bundle) or ""
                        partial.setdefault(bundle, set()).add(
                            _as_entry_id(raw_entry)
                        )
                    return cls(
                        partial={
                            bundle: frozenset(entries)
                            for bundle, entries in partial.items()
                        },
                        default=False,
                    )
                names = {str(item) for item in value}
                return cls(full=frozenset(names), default=False)
            raise TypeError("permissions must be a bool, collection or mapping")

        full: set[str] = set()
        partial: dict[str, frozenset[EntryId]] = {}
        denied: set[str] = set()
        default_decision = False
        for raw_bundle, decision in value.items():
            bundle = _as_name(raw_bundle)
            if bundle is None:
                continue
            if bundle == "*":
                if isinstance(decision, bool):
                    default_decision = decision
                else:
                    default_decision = True
                continue
            if decision is None or decision is True or decision in ("*", "all", "full"):
                full.add(bundle)
            elif isinstance(decision, str) and decision.lower() in (
                "none",
                "no",
                "deny",
                "denied",
                "false",
            ):
                denied.add(bundle)
            elif decision is False:
                denied.add(bundle)
            elif isinstance(decision, Mapping):
                entries = _first(
                    decision,
                    ("entries", "ids", "allow", "allowed", "permitted", "entry"),
                )
                if entries is _ABSENT or entries is None:
                    full.add(bundle)
                elif isinstance(entries, (int, str)):
                    if entries == "*":
                        full.add(bundle)
                    else:
                        partial[bundle] = frozenset({_as_entry_id(entries)})
                else:
                    allowed_entries = {
                        _as_entry_id(item) for item in entries
                    }
                    if "*" in allowed_entries:
                        full.add(bundle)
                    else:
                        partial[bundle] = frozenset(allowed_entries)
            elif isinstance(decision, (int, str)):
                partial[bundle] = frozenset({_as_entry_id(decision)})
            elif isinstance(decision, Collection):
                allowed_entries = {_as_entry_id(item) for item in decision}
                if "*" in allowed_entries:
                    full.add(bundle)
                else:
                    partial[bundle] = frozenset(allowed_entries)
            else:
                raise TypeError(
                    f"unsupported permission decision for bundle {bundle!r}: "
                    f"{decision!r}"
                )

        return cls(
            full=frozenset(full),
            partial=partial,
            denied=frozenset(denied),
            default=default_decision,
        )


@dataclass(frozen=True)
class ChecklistItem:
    """One reference occurrence in provenance order."""

    claim_index: int
    source_bundle: str | None
    source_entry: EntryId | None
    ordinal: int
    reference: Reference
    kind: ReferenceKind
    target_bundle: str | None
    target_entry: EntryId
    status: ReferenceStatus
    reason: str = ""
    resolved_bundle: str | None = None
    resolved_entry: EntryId | None = None
    is_claim: bool = False

    @property
    def provenance(self) -> tuple[str | None, EntryId | None, int]:
        return (self.source_bundle, self.source_entry, self.ordinal)

    @property
    def target(self) -> BundleKey | None:
        if self.target_bundle is None:
            return None
        return (self.target_bundle, self.target_entry)

    @property
    def state(self) -> ReferenceStatus:
        return self.status

    def to_dict(self) -> dict[str, Any]:
        location: dict[str, Any] | None = None
        if self.resolved_bundle is not None:
            location = {
                "bundle": self.resolved_bundle,
                "entry": self.resolved_entry,
            }
        result = {
            "claim_index": self.claim_index,
            "provenance": {
                "bundle": self.source_bundle,
                "entry": self.source_entry,
                "ordinal": self.ordinal,
            },
            "kind": self.kind.value,
            "reference": self.reference.to_dict(),
            "target": (
                {"bundle": self.target_bundle, "entry": self.target_entry}
                if self.target_bundle is not None
                else None
            ),
            "resolved": location if self.status is ReferenceStatus.RESOLVED else None,
            "status": self.status.value,
            "reason": self.reason,
            "is_claim": self.is_claim,
        }
        if location is not None and self.status is not ReferenceStatus.RESOLVED:
            result["location"] = location
        return result


@dataclass(frozen=True)
class Conclusion:
    """The reviewable conclusion for one claim."""

    claim: Reference
    complete: bool
    status: ReferenceStatus
    items: tuple[ChecklistItem, ...]
    resolved: tuple[BundleKey, ...] = ()
    missing: tuple[BundleKey, ...] = ()
    forbidden: tuple[BundleKey, ...] = ()

    @property
    def sufficient(self) -> bool:
        return self.complete

    def checklist(self) -> tuple[ChecklistItem, ...]:
        return self.items

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim.to_dict(),
            "complete": self.complete,
            "status": self.status.value,
            "resolved": [_key_dict(key) for key in self.resolved],
            "missing": [_key_dict(key) for key in self.missing],
            "forbidden": [_key_dict(key) for key in self.forbidden],
            "checklist": [item.to_dict() for item in self.items],
        }


@dataclass(frozen=True)
class AuditReport:
    """An offline handover report containing one conclusion per claim."""

    claim: Reference
    conclusions: tuple[Conclusion, ...]
    bundles: tuple[str, ...] = ()
    withdrawn: frozenset[str] = frozenset()

    @property
    def items(self) -> tuple[ChecklistItem, ...]:
        items = [item for conclusion in self.conclusions for item in conclusion.items]
        return tuple(sorted(items, key=_checklist_sort_key))

    @property
    def complete(self) -> bool:
        return bool(self.conclusions) and all(item.complete for item in self.conclusions)

    @property
    def sufficient(self) -> bool:
        return self.complete

    @property
    def ok(self) -> bool:
        return self.complete

    @property
    def passed(self) -> bool:
        return self.complete

    @property
    def reviewable(self) -> bool:
        return self.complete

    @property
    def can_review(self) -> bool:
        return self.complete

    @property
    def claims(self) -> tuple[Reference, ...]:
        return tuple(conclusion.claim for conclusion in self.conclusions)

    @property
    def status(self) -> ReferenceStatus:
        if self.complete:
            return ReferenceStatus.RESOLVED
        if any(item.status is ReferenceStatus.FORBIDDEN for item in self.conclusions):
            return ReferenceStatus.FORBIDDEN
        return ReferenceStatus.MISSING

    @property
    def resolved(self) -> tuple[BundleKey, ...]:
        return _unique_keys(
            key for conclusion in self.conclusions for key in conclusion.resolved
        )

    @property
    def missing(self) -> tuple[BundleKey, ...]:
        return _unique_keys(
            key for conclusion in self.conclusions for key in conclusion.missing
        )

    @property
    def forbidden(self) -> tuple[BundleKey, ...]:
        return _unique_keys(
            key for conclusion in self.conclusions for key in conclusion.forbidden
        )

    @property
    def missing_bundles(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(key[0] for key in self.missing))

    @property
    def forbidden_bundles(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(key[0] for key in self.forbidden))

    @property
    def unresolved(self) -> tuple[BundleKey, ...]:
        return self.missing + self.forbidden

    def checklist(self) -> tuple[ChecklistItem, ...]:
        """Return the checklist ordered by reference provenance."""

        return self.items

    def __iter__(self) -> Iterator[ChecklistItem]:
        return iter(self.items)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim.to_dict(),
            "complete": self.complete,
            "sufficient": self.sufficient,
            "status": self.status.value,
            "bundles": list(self.bundles),
            "withdrawn": sorted(self.withdrawn),
            "missing": [_key_dict(key) for key in self.missing],
            "missing_bundles": list(self.missing_bundles),
            "forbidden": [_key_dict(key) for key in self.forbidden],
            "forbidden_bundles": list(self.forbidden_bundles),
            "resolved": [_key_dict(key) for key in self.resolved],
            "checklist": [item.to_dict() for item in self.items],
            "conclusions": [item.to_dict() for item in self.conclusions],
        }


def _key_dict(key: BundleKey) -> dict[str, Any]:
    return {"bundle": key[0], "entry": key[1]}


BundleManifest = Bundle
Package = Bundle
EvidencePolicy = EvidencePermissions
HandoverReport = AuditReport
ChecklistEntry = ChecklistItem


def _unique_keys(keys: Iterable[BundleKey]) -> tuple[BundleKey, ...]:
    seen: set[BundleKey] = set()
    result: list[BundleKey] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            result.append(key)
    return tuple(result)


def _id_sort_key(value: EntryId | None) -> tuple[int, Any]:
    if isinstance(value, int):
        return (0, value)
    return (1, "" if value is None else str(value))


def _checklist_sort_key(item: ChecklistItem) -> tuple[Any, ...]:
    return (
        item.claim_index,
        item.source_bundle is not None,
        item.source_bundle or "",
        _id_sort_key(item.source_entry),
        item.ordinal,
        item.target_bundle or "",
        _id_sort_key(item.target_entry),
        item.status.value,
    )


_REF_KEYS = ("$ref", "ref", "reference", "$reference")
_LOCAL_ID_KEYS = ("local", "local_id", "localId", "local_ref", "localRef", "$local")
_CROSS_KEYS = (
    "cross",
    "cross_ref",
    "crossRef",
    "cross_bundle",
    "crossBundle",
    "$cross",
)
_BUNDLE_KEYS = (
    "bundle",
    "package",
    "bundle_id",
    "bundleId",
    "package_id",
    "packageId",
    "bundle_name",
    "package_name",
)
_ID_KEYS = (
    "id",
    "entry",
    "entry_id",
    "entryId",
    "entry_number",
    "local",
    "local_id",
    "localId",
    "local_ref",
    "local_number",
    "index",
)
_HOME_KEYS = (
    "home",
    "content_bundle",
    "contentBundle",
    "content_in",
    "contentIn",
    "stored_in",
    "storedIn",
    "stored_at",
    "content_location",
    "present_in",
    "location",
    "storage",
    "source_bundle",
    "sourceBundle",
)
_STRONG_HOME_KEYS = (
    "home",
    "content_bundle",
    "contentBundle",
    "content_in",
    "contentIn",
    "stored_in",
    "storedIn",
    "stored_at",
    "content_location",
    "present_in",
)
_REDIRECT_KEYS = (
    "redirect",
    "pointer",
    "target",
    "points_to",
    "pointsTo",
    "$pointer",
)
_PAYLOAD_KEYS = ("content", "payload", "data")
_REF_LIST_KEYS = (
    "refs",
    "references",
    "links",
    "dependencies",
    "deps",
    "local_refs",
    "cross_refs",
    "refs_local",
    "refs_cross",
)


def _parse_ref_string(value: str) -> Reference | None:
    text = value.strip()
    if not text:
        return None
    if text.startswith("#/"):
        return Reference(entry=_text_entry_id(text[2:]))
    if text.startswith("#"):
        return Reference(entry=_text_entry_id(text[1:]))
    if text.startswith("@"):
        return Reference(entry=_text_entry_id(text[1:]))
    for separator in (":", "#", "/"):
        if separator in text:
            bundle, entry = text.rsplit(separator, 1)
            if bundle:
                return Reference(entry=_text_entry_id(entry), bundle=bundle)
    return None


def _text_entry_id(value: str) -> EntryId:
    """Treat decimal local numbers as integers while preserving other ids."""

    text = value.strip()
    if text.isdecimal():
        return int(text)
    return _as_entry_id(text)


def _reference_from_inner(value: Any) -> Reference | None:
    if isinstance(value, Reference):
        return value
    if isinstance(value, CBORTag):
        return _reference_from_tag(value)
    if isinstance(value, Mapping):
        return _as_reference(value)
    if (
        isinstance(value, (list, tuple))
        and len(value) == 2
        and isinstance(value[0], (str, bytes))
        and isinstance(value[1], (str, bytes, int))
    ):
        bundle = _as_name(value[0])
        if bundle is not None:
            return Reference(entry=_as_entry_id(value[1]), bundle=bundle)
    if isinstance(value, str):
        parsed = _parse_ref_string(value)
        if parsed is not None:
            return parsed
    if isinstance(value, int):
        return Reference(entry=_as_entry_id(value))
    if isinstance(value, str):
        return Reference(entry=_text_entry_id(value))
    return None


def _reference_from_tag(tag: CBORTag) -> Reference | None:
    if tag.tag == LOCAL_REF_TAG:
        if isinstance(tag.value, (list, tuple)) and len(tag.value) == 1:
            return Reference(entry=_as_entry_id(tag.value[0]))
        return Reference(entry=_as_entry_id(tag.value))
    if tag.tag == CROSS_REF_TAG:
        reference = _reference_from_inner(tag.value)
        if reference is None:
            return None
        return replace(reference, kind_hint=ReferenceKind.CROSS_BUNDLE)
    return None


def _as_reference(value: Any) -> Reference | None:
    """Interpret an explicit reference marker, or return ``None``."""

    if isinstance(value, Reference):
        return value
    if isinstance(value, CBORTag):
        return _reference_from_tag(value)
    if isinstance(value, Mapping):
        kind = value.get("kind", value.get("type", value.get("scope")))
        if isinstance(kind, str):
            kind_name = kind.lower().replace("-", "_")
            if kind_name in ("local", "local_ref", "localref"):
                local_entry = _first(value, _LOCAL_ID_KEYS + _ID_KEYS)
                if local_entry is not _ABSENT:
                    return Reference(entry=_as_entry_id(local_entry))
            if kind_name in ("cross", "cross_bundle", "cross_package", "crossbundle"):
                bundle = _first(value, _BUNDLE_KEYS)
                entry = _first(value, _ID_KEYS)
                if bundle is not _ABSENT and entry is not _ABSENT:
                    return Reference(
                        entry=_as_entry_id(entry),
                        bundle=_as_name(bundle),
                        kind_hint=ReferenceKind.CROSS_BUNDLE,
                    )

        for key in _REF_KEYS:
            if key in value:
                reference = _reference_from_inner(value[key])
                if reference is not None:
                    if reference.bundle is None:
                        bundle_name = _first(value, _BUNDLE_KEYS)
                        if bundle_name is not _ABSENT:
                            return replace(
                                reference,
                                bundle=_as_name(bundle_name),
                                kind_hint=ReferenceKind.CROSS_BUNDLE,
                            )
                    return reference

        for key in _CROSS_KEYS:
            if key in value:
                inner = value[key]
                if isinstance(inner, Mapping):
                    reference = _as_reference(inner)
                elif (
                    isinstance(inner, (list, tuple))
                    and len(inner) == 2
                    and isinstance(inner[0], (str, bytes))
                    and isinstance(inner[1], (str, bytes, int))
                ):
                    reference = Reference(
                        entry=_as_entry_id(inner[1]), bundle=_as_name(inner[0])
                    )
                else:
                    reference = _reference_from_inner(inner)
                if reference is not None:
                    return replace(reference, kind_hint=ReferenceKind.CROSS_BUNDLE)

        for key in _LOCAL_ID_KEYS:
            if key in value and not any(name in value for name in _BUNDLE_KEYS):
                return Reference(entry=_as_entry_id(value[key]))

        bundle = _first(value, _BUNDLE_KEYS)
        entry = _first(value, _ID_KEYS)
        if bundle is not _ABSENT and entry is not _ABSENT:
            return Reference(
                entry=_as_entry_id(entry),
                bundle=_as_name(bundle),
                kind_hint=ReferenceKind.CROSS_BUNDLE,
            )
    return None


def _walk_refs(
    value: Any,
    *,
    expect_reference: bool = False,
    seen: set[int] | None = None,
) -> Iterator[Reference]:
    """Yield references found anywhere inside a decoded value."""

    if seen is None:
        seen = set()

    if (
        expect_reference
        and isinstance(value, (int, str))
        and not isinstance(value, bool)
    ):
        reference = _reference_from_inner(value)
        if reference is not None:
            yield reference
        return

    direct = _as_reference(value)
    if direct is not None:
        yield direct
        return

    if isinstance(value, CBORTag):
        yield from _walk_refs(
            value.value, expect_reference=expect_reference, seen=seen
        )
        return

    if isinstance(value, Mapping):
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)
        for key, child in value.items():
            if key in _REF_LIST_KEYS:
                yield from _walk_refs(
                    child, expect_reference=True, seen=seen
                )
            elif key in _HOME_KEYS and isinstance(child, (str, bytes)):
                continue
            else:
                yield from _walk_refs(
                    child, expect_reference=False, seen=seen
                )
        seen.remove(marker)
        return

    if isinstance(value, (list, tuple)):
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)
        if (
            expect_reference
            and len(value) == 2
            and isinstance(value[0], (str, bytes))
            and isinstance(value[1], (str, bytes, int))
        ):
            bundle = _as_name(value[0])
            if bundle is not None:
                yield Reference(entry=_as_entry_id(value[1]), bundle=bundle)
                seen.remove(marker)
                return
        for child in value:
            yield from _walk_refs(
                child, expect_reference=expect_reference, seen=seen
            )
        seen.remove(marker)


def _extract_home(raw: Any) -> str | None:
    if not isinstance(raw, Mapping):
        return None
    for key in _STRONG_HOME_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if isinstance(value, (str, bytes)):
            return _as_name(value)
    return None


def _extract_redirect(raw: Any) -> Reference | None:
    if isinstance(raw, Reference) or isinstance(raw, CBORTag):
        return _as_reference(raw)
    if not isinstance(raw, Mapping):
        return None
    for key in _REDIRECT_KEYS:
        if key in raw:
            reference = _reference_from_inner(raw[key])
            if reference is not None:
                return reference
    for key in _HOME_KEYS:
        if key in raw:
            value = raw[key]
            if isinstance(value, Mapping) or (
                isinstance(value, (list, tuple))
                and len(value) == 2
                and isinstance(value[0], (str, bytes))
            ):
                reference = _reference_from_inner(value)
                if reference is not None:
                    return replace(
                        reference, kind_hint=ReferenceKind.CROSS_BUNDLE
                    )
    if _as_reference(raw) is not None and not any(
        key in raw for key in ("refs", "references", "links")
    ):
        return _as_reference(raw)
    return None


def _make_descriptor(raw: Any, *, standalone_index: bool) -> EntryDescriptor:
    redirect = _extract_redirect(raw)
    refs = tuple(ref for ref in _walk_refs(raw) if ref != redirect)
    home_bundle = _extract_home(raw)
    content: Any = _ABSENT
    content_present = False
    meta: dict[str, Any] = {}
    if isinstance(raw, Mapping):
        descriptor_keys = set(_REF_KEYS + _LOCAL_ID_KEYS + _CROSS_KEYS + _ID_KEYS)
        descriptor_keys.update(_STRONG_HOME_KEYS + _REDIRECT_KEYS + _PAYLOAD_KEYS)
        descriptor_keys.update(_REF_LIST_KEYS)
        meta = {
            str(key): value
            for key, value in raw.items()
            if key not in descriptor_keys
        }
        for key in _PAYLOAD_KEYS:
            if key in raw:
                content = raw[key]
                content_present = True
                break
        if content_present and redirect is None:
            content_ref = _as_reference(content)
            if content_ref is not None and (
                isinstance(content, (Reference, CBORTag))
                or (
                    isinstance(content, Mapping)
                    and any(key in content for key in _REF_KEYS + _CROSS_KEYS)
                )
            ):
                redirect = content_ref
                content = _ABSENT
                content_present = False
        if not content_present and standalone_index:
            if not (set(raw) & descriptor_keys) and raw:
                content = raw
                content_present = True
                meta = {}
    elif standalone_index and redirect is None:
        refs_only = bool(raw) and isinstance(raw, (list, tuple)) and all(
            _as_reference(item) is not None for item in raw
        )
        if not refs_only:
            content = raw
            content_present = True

    return EntryDescriptor(
        raw=raw,
        refs=tuple(ref for ref in refs if ref != redirect),
        home_bundle=home_bundle,
        redirect=redirect,
        content=content,
        content_present=content_present,
        meta=meta,
    )


def _named_entries(value: Any) -> Mapping[EntryId, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return {_as_entry_id(key): child for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return {index: child for index, child in enumerate(value)}
    raise TypeError("bundle entries must be a mapping or a sequence")


def _named_index(value: Any) -> Mapping[EntryId, Any]:
    if isinstance(value, Mapping):
        return {_as_entry_id(key): child for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return {index: child for index, child in enumerate(value)}
    raise TypeError("bundle index must be a mapping or a sequence")


def parse_bundle(document: Any, name: str | None = None) -> Bundle:
    """Turn a decoded CBOR bundle document into a :class:`Bundle`."""

    if isinstance(document, CBORTag):
        document = document.value

    if isinstance(document, Bundle):
        if name is not None and name != document.name:
            return replace(document, name=name)
        return document

    if not isinstance(document, Mapping):
        if isinstance(document, (list, tuple)) and len(document) in (2, 3):
            parts = list(document)
            if len(parts) == 3:
                name = name if name is not None else _as_name(parts[0])
                document = {"bundle": parts[0], "index": parts[1], "entries": parts[2]}
            else:
                document = {"index": parts[0], "entries": parts[1]}
        else:
            raise TypeError("a bundle must decode to a mapping or a [name, index, entries]")

    document_name = _first(
        document,
        (
            "bundle",
            "package",
            "bundle_id",
            "bundle_name",
            "package_name",
            "name",
            "label",
        ),
    )
    if name is None and document_name is not _ABSENT:
        name = _as_name(document_name)
    name = name or "package"

    index_value = _first(
        document,
        ("index", "manifest", "public_index", "catalogue", "catalog", "toc", "public"),
    )
    entries_value = _first(
        document,
        (
            "entries",
            "contents",
            "content",
            "body",
            "items",
            "private_entries",
            "private",
            "payloads",
        ),
    )

    if entries_value is _ABSENT:
        entries_value = None

    if index_value is _ABSENT:
        if entries_value is not None:
            index_value = {key: {} for key in _named_entries(entries_value)}
        else:
            metadata = {
                "bundle",
                "package",
                "bundle_id",
                "bundle_name",
                "package_name",
                "name",
                "label",
            }
            index_value = {
                key: value for key, value in document.items() if key not in metadata
            }

    entries = _named_entries(entries_value)
    standalone_index = not entries
    index = {
        entry: _make_descriptor(raw, standalone_index=standalone_index)
        for entry, raw in _named_index(index_value).items()
    }

    return Bundle(name=name, index=index, entries=entries)


def loads_bundle(data: Any, name: str | None = None, **kwargs: Any) -> Bundle:
    """Decode a CBOR bundle with :func:`cbor2.loads` and parse it."""

    kwargs.setdefault("tag_hook", reference_tag_hook)
    document = loads(data, **kwargs)
    return parse_bundle(document, name=name)


def load_bundle(source: Any, name: str | None = None, **kwargs: Any) -> Bundle:
    """Load a bundle from bytes, a file object, a path or a decoded document."""

    if isinstance(source, Bundle):
        return parse_bundle(source, name=name)

    if isinstance(source, Mapping):
        return parse_bundle(source, name=name)

    if isinstance(source, (list, tuple)):
        return parse_bundle(source, name=name)

    if isinstance(source, (bytes, bytearray, memoryview)):
        return loads_bundle(bytes(source), name=name, **kwargs)

    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(str(path))
        with path.open("rb") as fp:
            kwargs.setdefault("tag_hook", reference_tag_hook)
            bundle = parse_bundle(load(fp, **kwargs), name=name)
        if name is None and bundle.name == "package":
            bundle = replace(bundle, name=path.stem)
        return bundle

    if hasattr(source, "read"):
        kwargs.setdefault("tag_hook", reference_tag_hook)
        return parse_bundle(load(cast(BinaryIO, source), **kwargs), name=name)

    raise TypeError(
        "bundle source must be decoded data, CBOR bytes, a path or a readable file"
    )


def _bundle_collection(
    packages: Any,
    names: Sequence[str] | None = None,
) -> dict[str, Bundle]:
    """Normalize a mapping or sequence of packages into a named collection."""

    if isinstance(packages, Mapping):
        values = list(packages.values())
        if values and all(
            isinstance(value, Bundle)
            or isinstance(value, (bytes, bytearray, memoryview))
            for value in values
        ):
            result: dict[str, Bundle] = {}
            for position, (raw_name, source) in enumerate(packages.items()):
                bundle = load_bundle(source, name=_as_name(raw_name))
                _add_bundle(result, bundle)
            return result

        if isinstance(packages, Bundle):
            return {packages.name: packages}

        if any(
            key in packages
            for key in ("index", "entries", "manifest", "bundle", "name", "package")
        ):
            bundle = load_bundle(packages)
            return {bundle.name: bundle}

        result = {}
        for position, (raw_name, source) in enumerate(packages.items()):
            bundle = load_bundle(source, name=_as_name(raw_name))
            _add_bundle(result, bundle)
        return result

    if isinstance(packages, Bundle):
        return {packages.name: packages}

    if isinstance(packages, (bytes, bytearray, memoryview, str, Path)) or hasattr(
        packages, "read"
    ):
        bundle = load_bundle(packages)
        return {bundle.name: bundle}

    if isinstance(packages, Sequence):
        result = {}
        for position, source in enumerate(packages):
            name = names[position] if names is not None and position < len(names) else None
            bundle = load_bundle(source, name=name)
            if not bundle.name or bundle.name == "package":
                bundle = replace(bundle, name=f"package-{position}")
            _add_bundle(result, bundle)
        return result

    if isinstance(packages, Iterable):
        result = {}
        for position, source in enumerate(packages):
            name = names[position] if names is not None and position < len(names) else None
            bundle = load_bundle(source, name=name)
            if not bundle.name or bundle.name == "package":
                bundle = replace(bundle, name=f"package-{position}")
            _add_bundle(result, bundle)
        return result

    raise TypeError("packages must be a bundle, a sequence of bundles or a mapping")


def _add_bundle(bundles: dict[str, Bundle], bundle: Bundle) -> None:
    if bundle.name in bundles:
        raise ValueError(
            f"duplicate bundle name {bundle.name!r}; package names must be distinct"
        )
    bundles[bundle.name] = bundle


def load_bundles(packages: Any, names: Sequence[str] | None = None) -> dict[str, Bundle]:
    """Load and name a set of bundles."""

    return _bundle_collection(packages, names=names)


def loads_bundles(
    packages: Sequence[Any] | Mapping[str, Any],
    names: Sequence[str] | None = None,
) -> dict[str, Bundle]:
    """Decode several byte strings as bundles."""

    return _bundle_collection(packages, names=names)


def reference_tag_hook(tag: CBORTag, immutable: bool) -> Any:
    """A ``tag_hook`` that recognises local and cross-bundle references."""

    reference = _reference_from_tag(tag)
    return tag if reference is None else reference


def reference_semantic_decoders() -> dict[int, Any]:
    """Return ``semantic_decoders`` entries for the reference tags."""

    def decode_local(value: Any, immutable: bool) -> Reference:
        return Reference(entry=_as_entry_id(value))

    def decode_cross(value: Any, immutable: bool) -> Reference:
        reference = _reference_from_inner(value)
        if reference is None:
            raise ValueError(f"invalid cross-bundle reference: {value!r}")
        return replace(reference, kind_hint=ReferenceKind.CROSS_BUNDLE)

    return {LOCAL_REF_TAG: decode_local, CROSS_REF_TAG: decode_cross}


def local_ref(entry: EntryId) -> Reference:
    """Create a local reference."""

    return Reference(entry=_as_entry_id(entry), kind_hint=ReferenceKind.LOCAL)


def cross_ref(bundle: str, entry: EntryId) -> Reference:
    """Create a cross-bundle reference."""

    return Reference(
        entry=_as_entry_id(entry),
        bundle=_as_name(bundle),
        kind_hint=ReferenceKind.CROSS_BUNDLE,
    )


def _entry_refs(
    bundles: Mapping[str, Bundle],
    bundle_name: str,
    entry: EntryId,
    *,
    include_content: bool = True,
    include_descriptor: bool = True,
) -> tuple[Reference, ...]:
    bundle = bundles[bundle_name]
    descriptor = bundle.descriptor(entry)
    refs: list[Reference] = []
    if include_descriptor and descriptor is not None:
        refs.extend(descriptor.refs)
    if include_content and bundle.has_content(entry):
        content = bundle.content_for(entry)
        refs.extend(_walk_refs(content))
    return tuple(refs)


def _resolve_target(
    bundles: Mapping[str, Bundle],
    bundle_name: str,
    entry: EntryId,
    permissions: EvidencePermissions,
    withdrawn: frozenset[str],
    seen: set[BundleKey] | None = None,
) -> Resolution:
    if seen is None:
        seen = set()
    key = (bundle_name, entry)
    if key in seen:
        return Resolution(
            ReferenceStatus.MISSING,
            bundle_name,
            entry,
            reason="reference cycle",
            resolved_bundle=bundle_name,
            resolved_entry=entry,
        )

    if bundle_name in withdrawn:
        return Resolution(
            ReferenceStatus.MISSING,
            bundle_name,
            entry,
            reason="bundle withdrawn",
            resolved_bundle=bundle_name,
            resolved_entry=entry,
        )

    bundle = bundles.get(bundle_name)
    if bundle is None:
        return Resolution(
            ReferenceStatus.MISSING,
            bundle_name,
            entry,
            reason="bundle not supplied",
            resolved_bundle=bundle_name,
            resolved_entry=entry,
        )

    if not permissions.allows(bundle_name, entry):
        return Resolution(
            ReferenceStatus.FORBIDDEN,
            bundle_name,
            entry,
            reason="entry not permitted",
            resolved_bundle=bundle_name,
            resolved_entry=entry,
        )

    descriptor = bundle.descriptor(entry)
    if entry not in bundle.index and entry not in bundle.entries:
        return Resolution(
            ReferenceStatus.MISSING,
            bundle_name,
            entry,
            reason="entry not in public index",
            resolved_bundle=bundle_name,
            resolved_entry=entry,
        )

    seen.add(key)
    if descriptor is not None and descriptor.redirect is not None:
        redirect = descriptor.redirect
        target_bundle = redirect.bundle if redirect.bundle is not None else bundle_name
        return _resolve_target(
            bundles,
            target_bundle,
            redirect.entry,
            permissions,
            withdrawn,
            seen,
        )

    if descriptor is not None and descriptor.home_bundle is not None:
        return _resolve_target(
            bundles,
            descriptor.home_bundle,
            entry,
            permissions,
            withdrawn,
            seen,
        )

    if bundle.has_content(entry):
        return Resolution(
            ReferenceStatus.RESOLVED,
            bundle_name,
            entry,
            content=bundle.content_for(entry),
            resolved_bundle=bundle_name,
            resolved_entry=entry,
        )

    return Resolution(
        ReferenceStatus.MISSING,
        bundle_name,
        entry,
        reason="entry content is not supplied",
        resolved_bundle=bundle_name,
        resolved_entry=entry,
    )


def resolve_reference(
    bundles: Mapping[str, Bundle] | Sequence[Any],
    reference: Any,
    *,
    source_bundle: str | None = None,
    permissions: Any = None,
    withdrawn: Collection[str] | str | None = None,
) -> Resolution:
    """Resolve one reference against a set of bundles."""

    bundle_map = load_bundles(bundles)
    resolved_ref = _as_reference(reference)
    if resolved_ref is None and isinstance(reference, (list, tuple)) and len(reference) == 2:
        if isinstance(reference[0], (str, bytes)):
            resolved_ref = Reference(
                entry=_as_entry_id(reference[1]),
                bundle=_as_name(reference[0]),
                kind_hint=ReferenceKind.CROSS_BUNDLE,
            )
    if resolved_ref is None and isinstance(reference, str):
        resolved_ref = _parse_ref_string(reference)
    if resolved_ref is None and isinstance(reference, int):
        resolved_ref = Reference(entry=_as_entry_id(reference))
    if resolved_ref is None:
        raise ValueError(f"not a reference: {reference!r}")
    target_bundle = resolved_ref.bundle if resolved_ref.bundle is not None else source_bundle
    if target_bundle is None:
        raise ValueError("a local reference needs a source bundle")
    return _resolve_target(
        bundle_map,
        target_bundle,
        resolved_ref.entry,
        EvidencePermissions.coerce(permissions),
        _withdrawn_names(withdrawn),
    )


def _withdrawn_names(value: Collection[str] | str | None) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    return frozenset(str(item) for item in value)


def _normalize_claim(claim: Any, bundle: str | None = None) -> Reference:
    if isinstance(claim, Reference):
        if claim.bundle is None and bundle is not None:
            return replace(claim, bundle=bundle, kind_hint=ReferenceKind.CROSS_BUNDLE)
        if claim.bundle is None:
            raise ValueError("a claim reference needs a bundle name")
        return claim

    reference = _as_reference(claim)
    if reference is not None:
        if reference.bundle is None and bundle is not None:
            return replace(
                reference, bundle=bundle, kind_hint=ReferenceKind.CROSS_BUNDLE
            )
        return reference

    if isinstance(claim, (list, tuple)) and len(claim) == 2:
        return Reference(
            entry=_as_entry_id(claim[1]),
            bundle=_as_name(claim[0]),
            kind_hint=ReferenceKind.CROSS_BUNDLE,
        )

    if isinstance(claim, (int, str)):
        text = str(claim)
        parsed = _parse_ref_string(text)
        if parsed is not None and parsed.bundle is not None:
            return parsed
        if bundle is None:
            raise ValueError("a claim given as a local number needs a bundle name")
        return Reference(
            entry=_as_entry_id(claim),
            bundle=bundle,
            kind_hint=ReferenceKind.CROSS_BUNDLE,
        )

    raise TypeError(f"unsupported claim: {claim!r}")


def _audit_claim(
    bundles: Mapping[str, Bundle],
    claim: Reference,
    *,
    claim_index: int,
    permissions: EvidencePermissions,
    withdrawn: frozenset[str],
    include_claim: bool,
) -> Conclusion:
    """Audit one claim and expand public index edges inside the boundary."""

    items: list[ChecklistItem] = []
    resolved: list[BundleKey] = []
    missing: list[BundleKey] = []
    forbidden: list[BundleKey] = []
    has_missing = False
    has_forbidden = False
    visited: set[BundleKey] = set()
    visited_index: set[BundleKey] = set()
    queue: deque[tuple[Reference, str | None, EntryId | None, int, bool]] = deque()
    queue.append((claim, None, None, 0, True))

    while queue:
        reference, source_bundle, source_entry, ordinal, is_claim = queue.popleft()
        bound = reference.bind(
            origin_bundle=source_bundle,
            origin_entry=source_entry,
            ordinal=ordinal,
        )
        target_bundle = reference.bundle if reference.bundle is not None else source_bundle
        if target_bundle is None:
            resolution = Resolution(
                ReferenceStatus.MISSING,
                None,
                reference.entry,
                reason="no bundle context",
            )
        else:
            resolution = _resolve_target(
                bundles,
                target_bundle,
                reference.entry,
                permissions,
                withdrawn,
            )

        if resolution.key is not None:
            if resolution.status is ReferenceStatus.RESOLVED:
                resolved.append(resolution.key)
            elif resolution.status is ReferenceStatus.FORBIDDEN:
                forbidden.append(resolution.key)
            else:
                missing.append(resolution.key)
        if resolution.status is ReferenceStatus.FORBIDDEN:
            has_forbidden = True
        elif resolution.status is ReferenceStatus.MISSING:
            has_missing = True

        if include_claim or not is_claim:
            items.append(
                ChecklistItem(
                    claim_index=claim_index,
                    source_bundle=source_bundle,
                    source_entry=source_entry,
                    ordinal=ordinal,
                    reference=bound,
                    kind=reference.kind,
                    target_bundle=target_bundle,
                    target_entry=reference.entry,
                    status=resolution.status,
                    reason=resolution.reason,
                    resolved_bundle=resolution.resolved_bundle,
                    resolved_entry=resolution.resolved_entry,
                    is_claim=is_claim,
                )
            )

        declared_key: BundleKey | None = None
        if (
            target_bundle is not None
            and target_bundle in bundles
            and target_bundle not in withdrawn
            and resolution.status is not ReferenceStatus.FORBIDDEN
        ):
            declared_key = (target_bundle, reference.entry)
            if declared_key not in visited_index:
                visited_index.add(declared_key)
                for child_ordinal, child in enumerate(
                    _entry_refs(
                        bundles,
                        target_bundle,
                        reference.entry,
                        include_content=False,
                    )
                ):
                    queue.append(
                        (child, target_bundle, reference.entry, child_ordinal, False)
                    )

        if resolution.status is not ReferenceStatus.RESOLVED:
            continue
        if resolution.key is None or resolution.key in visited:
            continue
        visited.add(resolution.key)
        bundle_name, entry = resolution.key
        for child_ordinal, child in enumerate(
            _entry_refs(
                bundles,
                bundle_name,
                entry,
                include_content=True,
                include_descriptor=resolution.key != declared_key,
            )
        ):
            queue.append((child, bundle_name, entry, child_ordinal, False))

    if has_forbidden:
        status = ReferenceStatus.FORBIDDEN
    elif has_missing:
        status = ReferenceStatus.MISSING
    else:
        status = ReferenceStatus.RESOLVED

    ordered = tuple(sorted(items, key=_checklist_sort_key))
    return Conclusion(
        claim=claim,
        complete=not has_missing and not has_forbidden,
        status=status,
        items=ordered,
        resolved=_unique_keys(resolved),
        missing=_unique_keys(missing),
        forbidden=_unique_keys(forbidden),
    )


def handover_check(
    packages: Any,
    claim: Any = None,
    *,
    bundle: str | None = None,
    permissions: Any = None,
    approved: Any = None,
    allowed: Any = None,
    evidence: Any = None,
    evidence_scope: Any = None,
    scope: Any = None,
    permit: Any = None,
    withdrawn: Collection[str] | str | None = None,
    excluded: Collection[str] | str | None = None,
    names: Sequence[str] | None = None,
    include_claim: bool = True,
) -> AuditReport:
    """Check whether the supplied packages suffice to review a claim.

    ``packages`` may be a mapping of bundle name to bundle/source, a sequence
    of bundles/sources, or a single bundle.  ``claim`` is a reference, a
    ``(bundle, entry)`` pair, a ``"bundle:entry"`` string, or a local number
    accompanied by the ``bundle`` keyword.

    The permission boundary is declared by the caller through one of
    ``permissions``, ``approved``, ``allowed`` or ``evidence``.  Entries
    outside that boundary are reported as ``FORBIDDEN``; entries that are
    absent, unindexed or belong to a withdrawn package are reported as
    ``MISSING``.
    """

    if isinstance(packages, Mapping) and "bundles" in packages and claim is None:
        request = packages
        packages = request["bundles"]
        claim = request.get("claim")
        bundle = request.get("bundle", bundle)
        permissions = request.get("permissions", permissions)
        withdrawn = request.get("withdrawn", withdrawn)
        names = request.get("names", names)

    permission_value = permissions
    for candidate in (approved, allowed, evidence, evidence_scope, scope, permit):
        if permission_value is None and candidate is not None:
            permission_value = candidate

    bundle_map = load_bundles(packages, names=names)
    claims = _normalize_claims(claim, bundle)
    permission_rules = EvidencePermissions.coerce(permission_value)
    withdrawn_names = _withdrawn_names(withdrawn) | _withdrawn_names(excluded)

    conclusions = tuple(
        _audit_claim(
            bundle_map,
            item,
            claim_index=index,
            permissions=permission_rules,
            withdrawn=withdrawn_names,
            include_claim=include_claim,
        )
        for index, item in enumerate(claims)
    )

    return AuditReport(
        claim=claims[0],
        conclusions=conclusions,
        bundles=tuple(bundle_map),
        withdrawn=withdrawn_names,
    )


def _normalize_claims(claim: Any, bundle: str | None) -> tuple[Reference, ...]:
    if claim is None:
        raise ValueError("a claim is required")
    if isinstance(claim, Sequence) and not isinstance(claim, (str, bytes)):
        if len(claim) == 2 and isinstance(claim[0], (str, bytes)):
            return (_normalize_claim(claim, bundle),)
        if all(
            isinstance(item, (Reference, Mapping, list, tuple, int, str))
            for item in claim
        ) and not isinstance(claim, Reference):
            return tuple(_normalize_claim(item, bundle) for item in claim)
    return (_normalize_claim(claim, bundle),)


def build_checklist(
    packages: Any,
    claim: Any = None,
    **kwargs: Any,
) -> tuple[ChecklistItem, ...]:
    """Return only the provenance-ordered checklist."""

    if isinstance(packages, AuditReport):
        return packages.checklist()
    return handover_check(packages, claim, **kwargs).checklist()


def audit_handover(
    packages: Any,
    claim: Any = None,
    **kwargs: Any,
) -> AuditReport:
    """Alias for :func:`handover_check`."""

    return handover_check(packages, claim, **kwargs)


def make_bundle(
    name: str,
    index: Mapping[EntryId, Any] | Sequence[Any] | None = None,
    entries: Mapping[EntryId, Any] | Sequence[Any] | None = None,
) -> Bundle:
    """Create a bundle from index and entry data without encoding it."""

    return parse_bundle(
        {"bundle": name, "index": index or {}, "entries": entries or {}}
    )


def public_index(bundle: Bundle | Any) -> dict[EntryId, dict[str, Any]]:
    """Return a bundle's public index without any entry contents."""

    return load_bundle(bundle).public_index()


def dumps_bundle(bundle: Bundle | Any, **kwargs: Any) -> bytes:
    """Encode a bundle with :func:`cbor2.dumps`."""

    from . import dumps

    if not isinstance(bundle, Bundle):
        bundle = load_bundle(bundle)
    kwargs.setdefault("default", _encode_reference)
    return dumps(bundle.to_dict(), **kwargs)


def dump_bundle(bundle: Bundle | Any, fp: BinaryIO, **kwargs: Any) -> None:
    """Encode a bundle to a file with :func:`cbor2.dump`."""

    from . import dump

    if not isinstance(bundle, Bundle):
        bundle = load_bundle(bundle)
    kwargs.setdefault("default", _encode_reference)
    dump(bundle.to_dict(), fp, **kwargs)


def _encode_reference(encoder: Any, value: Any) -> Any:
    if isinstance(value, Reference):
        return value.to_dict()
    raise TypeError(f"cannot encode {type(value).__name__} as CBOR")


audit = handover_check
audit_bundles = handover_check
audit_claim = handover_check
check_bundles = handover_check
check_claim = handover_check
check_handover = handover_check
closure = handover_check
resolve_claim = handover_check
resolve_references = handover_check
trace_references = handover_check
verify_claim = handover_check
verify_handover = handover_check
handover_audit = handover_check


def audit_packages(*packages: Any, claim: Any, **kwargs: Any) -> AuditReport:
    """Audit three (or more) packages passed as separate positional arguments."""

    return handover_check(list(packages), claim, **kwargs)


check_packages = audit_packages


def _parse_cli_claim(value: str) -> Reference:
    reference = _parse_ref_string(value)
    if reference is None or reference.bundle is None:
        raise argparse.ArgumentTypeError(
            "claim must be BUNDLE:ENTRY, BUNDLE#ENTRY or BUNDLE/ENTRY"
        )
    return reference


def _parse_cli_permission(value: str) -> tuple[str, frozenset[EntryId] | None]:
    if ":" in value:
        bundle, entries = value.split(":", 1)
        return bundle, frozenset(
            _text_entry_id(item) for item in entries.split(",") if item != ""
        )
    if "/" in value:
        bundle, entries = value.split("/", 1)
        return bundle, frozenset(
            _text_entry_id(item) for item in entries.split(",") if item != ""
        )
    return value, None


def main(argv: Sequence[str] | None = None) -> None:
    """Command-line entry point for an offline bundle handover check."""

    parser = argparse.ArgumentParser(
        prog="python -m cbor2.bundles",
        description="Check a CBOR bundle handover and print a provenance-ordered checklist.",
    )
    parser.add_argument("packages", nargs="+", help="CBOR bundle files")
    parser.add_argument(
        "--claim",
        required=True,
        type=_parse_cli_claim,
        help="claim as BUNDLE:ENTRY (or BUNDLE#ENTRY)",
    )
    parser.add_argument(
        "--permit",
        action="append",
        default=[],
        metavar="BUNDLE[:ENTRY,...]",
        help="approve a bundle, optionally limited to specific entries",
    )
    parser.add_argument(
        "--withdraw",
        action="append",
        default=[],
        metavar="BUNDLE",
        help="treat a bundle as withdrawn",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="emit compact JSON",
    )
    options = parser.parse_args(argv)

    bundles = load_bundles(options.packages)
    permission_map: dict[str, frozenset[EntryId] | None] = {}
    for raw in options.permit:
        bundle, entries = _parse_cli_permission(raw)
        permission_map[bundle] = entries

    report = handover_check(
        bundles,
        options.claim,
        permissions=permission_map if permission_map else None,
        withdrawn=options.withdraw,
    )
    json.dump(
        report.to_dict(),
        sys.stdout,
        ensure_ascii=False,
        indent=None if options.compact else 2,
        sort_keys=False,
    )
    sys.stdout.write("\n")
    raise SystemExit(0 if report.complete else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
