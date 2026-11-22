"""Offline reference checks for CBOR packages split across evidence holders.

This module is deliberately implemented on top of the normal :func:`cbor2.loads`
entry point.  It does not add another CBOR decoder, and it does not follow
references by looking at process-global state.

A package is a decoded CBOR value with a public index.  The canonical shape is::

    {
        "package": "case-a",
        "index": {
            "finding": {
                "content": "the reviewed statement",
                "references": [
                    {"entry": "exhibit-1"},
                    {"package": "case-b", "entry": "exhibit-2"},
                ],
            },
            "exhibit-1": {"content": "locally held material"},
        },
    }

Local identifiers are scoped by package.  ``("case-a", "exhibit-1")`` and
``("case-b", "exhibit-1")`` are therefore different references even when both
packages use ``"exhibit-1"`` in their indexes.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Collection, Hashable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, TypeAlias

from . import loads
from ._cbor2 import CBORDecodeError, CBORTag

__all__ = [
    "CROSS_PACKAGE_REFERENCE_TAG",
    "LOCAL_REFERENCE_TAG",
    "REFERENCE_TAG",
    "ChecklistItem",
    "EvidenceLicense",
    "EvidenceScope",
    "HandoffAudit",
    "HandoffError",
    "HandoffFormatError",
    "HandoffReport",
    "Package",
    "PackageRef",
    "PackageReference",
    "Reference",
    "ReferenceKind",
    "ReferenceStatus",
    "audit",
    "audit_claims",
    "audit_handoff",
    "audit_packages",
    "build_checklist",
    "check_handoff",
    "check_packages",
    "package_id_from_value",
    "resolve_references",
    "review_claim",
    "scan_references",
    "verify_handoff",
    "withdraw_package",
]

# Synthetic semantic tags.  A caller can use these in a package index, but the
# same references are also accepted as ordinary mappings and strings.
LOCAL_REFERENCE_TAG = 40000
CROSS_PACKAGE_REFERENCE_TAG = 40001
REFERENCE_TAG = 40002

_REFERENCE_TAGS = {LOCAL_REFERENCE_TAG, CROSS_PACKAGE_REFERENCE_TAG, REFERENCE_TAG}

_ID_KEYS = {
    "package",
    "package_id",
    "packageid",
    "package_name",
    "packagename",
    "pkg",
    "pkg_id",
    "bundle",
    "bundle_id",
    "bag",
    "holder",
    "case",
    "case_id",
}
_ENTRY_ID_KEYS = {
    "entry",
    "entry_id",
    "entryid",
    "local",
    "local_id",
    "localid",
    "number",
    "no",
    "id",
    "key",
    "doc",
    "doc_id",
    "record",
    "record_id",
    "exhibit",
    "exhibit_id",
}
_INDEX_KEYS = {
    "index",
    "public_index",
    "publicindex",
    "catalog",
    "catalogue",
    "manifest",
    "contents",
    "items",
    "files",
}
_CONTENT_KEYS = {
    "content",
    "contents",
    "body",
    "payload",
    "data",
    "document",
    "material",
    "record",
    "text",
    "statement",
    "value",
}
_PRESENT_KEYS = {"present", "available", "included", "supplied", "has_content", "exists"}
_ABSENT_KEYS = {"missing", "withheld", "sealed", "redacted", "removed", "absent"}
_LOCAL_REF_KEYS = {
    "local_ref",
    "local_refs",
    "local_reference",
    "local_references",
}
_CROSS_REF_KEYS = {
    "cross_ref",
    "cross_refs",
    "cross_reference",
    "cross_references",
    "cross_package",
    "cross_package_ref",
    "external",
    "external_ref",
    "foreign",
    "foreign_ref",
}
_REF_KEYS = {
    "ref",
    "reference",
    "references",
    "refs",
    "requires",
    "required",
    "required_refs",
    "dependencies",
    "deps",
    "depends_on",
    "links",
    "linked_to",
    "cites",
    "citations",
    "see_also",
    "targets",
    "target",
    "pointer",
    "evidence_refs",
    "evidence_references",
    "needs",
    "uses",
    "depends",
    "related_refs",
    "internal_refs",
    "external_refs",
    "crossref",
    "crossrefs",
} | _LOCAL_REF_KEYS | _CROSS_REF_KEYS
_ENTRY_META_KEYS = (
    _ENTRY_ID_KEYS
    | _CONTENT_KEYS
    | _PRESENT_KEYS
    | _ABSENT_KEYS
    | _REF_KEYS
    | {
        "kind",
        "type",
        "role",
        "title",
        "label",
        "description",
        "summary",
        "provenance",
        "source",
        "source_package",
        "package",
        "package_id",
        "pkg",
        "pkg_id",
        "bundle",
        "bundle_id",
        "holder",
        "custodian",
        "held_by",
        "content_package",
        "content_entry",
    }
)


class HandoffError(ValueError):
    """Base class for malformed packages, claims and evidence licenses."""


class HandoffFormatError(HandoffError):
    """Raised when a package, claim or reference has an unusable shape."""


class ReferenceKind(str, Enum):
    """The namespace used by a reference."""

    LOCAL = "local"
    LOCAL_REFERENCE = "local"
    CROSS_PACKAGE = "cross_package"
    CROSS = "cross_package"
    CROSS_PACKAGE_REFERENCE = "cross_package"

    def __str__(self) -> str:
        return str(self.value)


class ReferenceStatus(str, Enum):
    """Result of looking up one reference."""

    RESOLVED = "resolved"
    OK = "resolved"
    PRESENT = "resolved"
    COMPLETE = "resolved"
    MISSING = "missing"
    ABSENT = "missing"
    MISSING_ENTRY = "missing"
    NOT_AUTHORIZED = "not_authorized"
    UNAUTHORIZED = "not_authorized"
    DENIED = "not_authorized"
    NOT_PERMITTED = "not_authorized"
    OUT_OF_SCOPE = "not_authorized"
    PACKAGE_MISSING = "package_missing"
    WITHDRAWN = "package_missing"
    MISSING_PACKAGE = "package_missing"
    PACKAGE_ABSENT = "package_missing"

    def __str__(self) -> str:
        return str(self.value)

    @property
    def is_resolved(self) -> bool:
        return self is ReferenceStatus.RESOLVED

    @property
    def is_missing(self) -> bool:
        return self in {ReferenceStatus.MISSING, ReferenceStatus.PACKAGE_MISSING}


def _normalise_key(value: Any) -> str:
    return str(value).strip().casefold().replace("-", "_").replace(" ", "_")


def _ensure_hashable(value: Any, what: str) -> Hashable:
    try:
        hash(value)
    except TypeError as exc:
        raise HandoffFormatError(f"{what} must be hashable, got {value!r}") from exc

    return value


def _sort_key(value: Any) -> tuple[int, str, str]:
    if isinstance(value, bool):
        return (0, "bool", repr(value))
    if isinstance(value, int):
        return (0, "int", f"{value:030d}")
    if isinstance(value, float):
        return (0, "float", f"{value:030.12g}")
    if isinstance(value, str):
        return (0, "str", value)
    if isinstance(value, bytes):
        return (0, "bytes", value.hex())
    return (1, type(value).__qualname__, repr(value))


@dataclass(frozen=True)
class PackageRef:
    """A package-qualified local entry identifier."""

    package: Hashable
    entry: Hashable

    def __post_init__(self) -> None:
        if self.package is None:
            raise HandoffFormatError("package identifier must not be None")
        if self.entry is None:
            raise HandoffFormatError("entry identifier must not be None")
        _ensure_hashable(self.package, "package identifier")
        _ensure_hashable(self.entry, "entry identifier")

    def __str__(self) -> str:
        return f"{self.package}#{self.entry}"

    def __iter__(self) -> Iterator[Hashable]:
        return iter((self.package, self.entry))

    def __getitem__(self, index: int | str) -> Hashable:
        if index in (0, "package", "package_id"):
            return self.package
        if index in (1, "entry", "entry_id"):
            return self.entry
        raise KeyError(index)

    @classmethod
    def parse(
        cls, value: Any, *, package: Hashable | None = None
    ) -> PackageRef:
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            has_package, parsed_package = _mapping_get_normalised(value, _ID_KEYS)
            has_entry, parsed_entry = _mapping_get_normalised(
                value, _ENTRY_ID_KEYS | {"value"}
            )
            if not has_entry:
                raise HandoffFormatError("package reference has no entry id")
            package_value = parsed_package if has_package else package
            if package_value is None:
                raise HandoffFormatError("unqualified package reference")
            return cls(
                _ensure_hashable(package_value, "reference package"),
                _ensure_hashable(parsed_entry, "reference entry"),
            )
        if isinstance(value, str):
            parsed_package, parsed_entry = _split_ref_string(value)
            if parsed_package is None:
                parsed_package = package
            if parsed_package is None:
                raise HandoffFormatError("unqualified package reference")
            return cls(parsed_package, parsed_entry)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            if len(value) != 2:
                raise HandoffFormatError("package reference sequence must have two items")
            return cls(
                _ensure_hashable(value[0], "reference package"),
                _ensure_hashable(value[1], "reference entry"),
            )
        if package is None:
            raise HandoffFormatError("unqualified package reference")
        return cls(package, _ensure_hashable(value, "reference entry"))

    def as_tuple(self) -> tuple[Hashable, Hashable]:
        return self.package, self.entry

    @property
    def package_id(self) -> Hashable:
        return self.package

    @property
    def entry_id(self) -> Hashable:
        return self.entry

    @property
    def local_id(self) -> Hashable:
        return self.entry

    def as_dict(self) -> dict[str, Hashable]:
        return {"package": self.package, "entry": self.entry}


PackageReference: TypeAlias = PackageRef


@dataclass(frozen=True)
class Reference:
    """An edge from one package entry to another entry."""

    source: PackageRef
    target: PackageRef
    kind: ReferenceKind
    path: str = ""

    @property
    def source_package(self) -> Hashable:
        return self.source.package

    @property
    def source_entry(self) -> Hashable:
        return self.source.entry

    @property
    def target_package(self) -> Hashable:
        return self.target.package

    @property
    def target_entry(self) -> Hashable:
        return self.target.entry

    @property
    def is_local(self) -> bool:
        return self.kind is ReferenceKind.LOCAL

    @property
    def is_cross_package(self) -> bool:
        return self.kind is ReferenceKind.CROSS_PACKAGE

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "path": self.path,
        }


@dataclass(frozen=True)
class ChecklistItem:
    """One source-to-target reference in an archivist's checklist."""

    source: PackageRef
    target: PackageRef
    kind: ReferenceKind
    status: ReferenceStatus
    reason: str
    path: str = ""

    @property
    def reference(self) -> Reference:
        return Reference(self.source, self.target, self.kind, self.path)

    @property
    def source_package(self) -> Hashable:
        return self.source.package

    @property
    def source_entry(self) -> Hashable:
        return self.source.entry

    @property
    def target_package(self) -> Hashable:
        return self.target.package

    @property
    def target_entry(self) -> Hashable:
        return self.target.entry

    @property
    def resolved(self) -> bool:
        return self.status.is_resolved

    @property
    def missing(self) -> bool:
        return self.status.is_missing

    @property
    def authorized(self) -> bool:
        return self.status is not ReferenceStatus.NOT_AUTHORIZED

    @property
    def state(self) -> ReferenceStatus:
        return self.status

    @property
    def resolution(self) -> ReferenceStatus:
        return self.status

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "status": self.status,
            "reason": self.reason,
            "path": self.path,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()


@dataclass(frozen=True)
class HandoffReport:
    """The result of checking one claim and its transitive references."""

    claim: PackageRef
    status: ReferenceStatus
    sufficient: bool
    checklist: list[ChecklistItem] = field(default_factory=list)
    missing: list[PackageRef] = field(default_factory=list)
    not_authorized: list[PackageRef] = field(default_factory=list)
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.sufficient

    @property
    def complete(self) -> bool:
        return self.sufficient

    @property
    def reviewable(self) -> bool:
        return self.sufficient

    @property
    def conclusion(self) -> str:
        return "reviewable" if self.sufficient else "not_reviewable"

    def __bool__(self) -> bool:
        return self.sufficient

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def as_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "status": self.status,
            "sufficient": self.sufficient,
            "conclusion": self.conclusion,
            "reason": self.reason,
            "checklist": [item.as_dict() for item in self.checklist],
            "missing": list(self.missing),
            "not_authorized": list(self.not_authorized),
        }

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()


@dataclass(frozen=True)
class HandoffAudit:
    """A collection of independent per-claim reports."""

    reports: list[HandoffReport] = field(default_factory=list)

    def __iter__(self) -> Iterator[HandoffReport]:
        return iter(self.reports)

    def __len__(self) -> int:
        return len(self.reports)

    def __getitem__(self, index: int) -> HandoffReport:
        return self.reports[index]

    @property
    def sufficient(self) -> bool:
        return all(report.sufficient for report in self.reports)

    @property
    def ok(self) -> bool:
        return self.sufficient

    @property
    def complete(self) -> bool:
        return self.sufficient

    @property
    def checklist(self) -> list[ChecklistItem]:
        items: list[ChecklistItem] = []
        for report in self.reports:
            items.extend(report.checklist)
        return items

    def as_dict(self) -> dict[str, Any]:
        return {
            "reports": [report.as_dict() for report in self.reports],
            "sufficient": self.sufficient,
            "checklist": [item.as_dict() for item in self.checklist],
        }

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()


LicenseValue: TypeAlias = (
    bool
    | None
    | Collection[Hashable]
    | Callable[[Hashable, Hashable], bool]
    | Mapping[str, Any]
)


class EvidenceLicense:
    """The caller's declaration of which evidence may be inspected.

    ``EvidenceLicense()`` permits every package that was handed over.  Passing
    an iterable permits all entries in those packages.  A mapping can grant a
    whole package (``True``), deny it (``False``), or grant selected entries
    (a collection of entry ids).
    An iterable of ``(package, entry)`` pairs (or :class:`PackageRef` objects)
    grants only those individual entries.
    """

    def __init__(
        self,
        packages: Mapping[Hashable, LicenseValue] | Iterable[Hashable] | bool | None = None,
        *,
        allow_all: bool | None = None,
        predicate: Callable[[Hashable, Hashable], bool] | None = None,
    ) -> None:
        self._predicate = predicate
        self._packages: dict[Hashable, LicenseValue] = {}
        self._allow_all = allow_all
        if packages is None:
            if allow_all is None:
                self._allow_all = True
        elif isinstance(packages, bool):
            self._allow_all = packages
        elif isinstance(packages, Mapping):
            self._packages = {
                _ensure_hashable(key, "licensed package"): value
                for key, value in packages.items()
            }
            self._allow_all = False if allow_all is None else allow_all
        elif isinstance(packages, (str, bytes)):
            key = _ensure_hashable(packages, "licensed package")
            self._packages = {key: True}
            self._allow_all = False if allow_all is None else allow_all
        else:
            values = list(packages)
            pairs: dict[Hashable, set[Hashable]] = {}
            if values and all(
                isinstance(value, PackageRef)
                or (
                    isinstance(value, Sequence)
                    and not isinstance(value, (str, bytes, bytearray))
                    and len(value) == 2
                )
                for value in values
            ):
                for value in values:
                    if isinstance(value, PackageRef):
                        package, entry = value.package, value.entry
                    else:
                        package, entry = value
                    pairs.setdefault(_ensure_hashable(package, "licensed package"), set()).add(
                        _ensure_hashable(entry, "licensed entry")
                    )
                self._packages = pairs
            else:
                self._packages = {
                    _ensure_hashable(pkg, "licensed package"): True for pkg in values
                }
            self._allow_all = False if allow_all is None else allow_all

    @classmethod
    def all(cls) -> EvidenceLicense:
        return cls(allow_all=True)

    @classmethod
    def none(cls) -> EvidenceLicense:
        return cls(allow_all=False)

    @property
    def allows_all(self) -> bool:
        return bool(self._allow_all)

    def allows(self, package: Hashable, entry: Hashable) -> bool:
        if self._predicate is not None and not self._predicate(package, entry):
            return False
        if self._allow_all:
            return True
        if package not in self._packages:
            return False

        grant = self._packages[package]
        if grant is True or grant is None:
            return True
        if grant is False:
            return False
        if callable(grant):
            return bool(grant(package, entry))
        if isinstance(grant, Mapping):
            if bool(grant.get("all")) or bool(grant.get("all_entries")):
                return True
            entries = grant.get("entries", grant.get("entry_ids"))
            if entries is None:
                return False
            if isinstance(entries, (str, bytes)):
                return entry == entries
            return entry in entries
        if isinstance(grant, Collection) and not isinstance(grant, (str, bytes)):
            return entry in grant
        if isinstance(grant, (str, bytes)):
            return grant == "*" or grant == "all" or entry == grant
        return False

    def __call__(self, package: Hashable, entry: Hashable) -> bool:
        return self.allows(package, entry)


EvidenceScope: TypeAlias = EvidenceLicense


@dataclass(frozen=True)
class _Entry:
    id: Hashable
    content: Any
    has_content: bool
    references: tuple[Reference, ...]


@dataclass(frozen=True)
class Package:
    """A decoded package with a public index."""

    id: Hashable
    entries: Mapping[Hashable, _Entry]
    raw: Any = field(default=None, compare=False, repr=False)

    def has_entry(self, entry: Hashable) -> bool:
        return entry in self.entries


def _unwrap_tag(value: Any) -> tuple[int | None, Any]:
    if isinstance(value, CBORTag):
        return value.tag, value.value
    return None, value


def _split_ref_string(value: str) -> tuple[str | None, Hashable]:
    text = value.strip()
    if text.startswith("#"):
        return None, text[1:]
    for separator in ("::", "//", ":", "#", "/"):
        if separator in text:
            package, entry = text.split(separator, 1)
            if package and entry:
                return package, entry
    return None, text


def _mapping_get_normalised(value: Mapping[Any, Any], keys: Collection[str]) -> tuple[bool, Any]:
    for key, item in value.items():
        if _normalise_key(key) in keys:
            return True, item
    return False, None


def _looks_like_reference(value: Any) -> bool:
    tag, inner = _unwrap_tag(value)
    if tag in _REFERENCE_TAGS:
        return True
    if isinstance(value, PackageRef):
        return True
    if not isinstance(inner, Mapping):
        return False

    keys = {_normalise_key(key) for key in inner}
    if keys & {"ref", "reference", "$ref", "target", "pointer"}:
        return True
    if "local" in keys and "id" not in keys:
        return True
    package_keys = keys & _ID_KEYS
    entry_keys = keys & (_ENTRY_ID_KEYS | {"value"})
    return bool(package_keys and entry_keys)


def _iter_reference_values(value: Any) -> Iterator[Any]:
    if value is None:
        return
    if isinstance(value, Mapping):
        keys = {_normalise_key(key) for key in value}
        if _looks_like_reference(value) or keys & (_ENTRY_ID_KEYS | {"value"}):
            yield value
            return
        for key, item in value.items():
            if isinstance(item, (list, tuple, set, frozenset)):
                for child in item:
                    yield {"package": key, "entry": child}
            else:
                yield {"package": key, "entry": item}
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield item
        return
    yield value


def _coerce_reference(
    value: Any,
    *,
    source: PackageRef,
    path: str,
    force: ReferenceKind | None = None,
) -> Reference:
    tag, inner = _unwrap_tag(value)
    if tag == LOCAL_REFERENCE_TAG:
        force = ReferenceKind.LOCAL
    elif tag == CROSS_PACKAGE_REFERENCE_TAG:
        force = ReferenceKind.CROSS_PACKAGE

    if isinstance(inner, Reference):
        return inner if force is None else Reference(inner.source, inner.target, force, path)
    if isinstance(inner, PackageRef):
        kind = (
            ReferenceKind.LOCAL
            if inner.package == source.package
            else ReferenceKind.CROSS_PACKAGE
        )
        if force is not None:
            if force is ReferenceKind.LOCAL:
                inner = PackageRef(source.package, inner.entry)
            elif inner.package == source.package:
                raise HandoffFormatError(
                    f"cross-package reference at {path} does not name a package"
                )
            kind = force
        return Reference(source, inner, kind, path)

    if isinstance(inner, Mapping):
        # A wrapper such as {"ref": {"package": "B", "entry": 2}} is common.
        has_ref, nested = _mapping_get_normalised(inner, {"ref", "reference", "$ref"})
        if has_ref and not (has_ref and _mapping_get_normalised(inner, _ID_KEYS)[0]):
            return _coerce_reference(nested, source=source, path=f"{path}.ref", force=force)

        has_target, target = _mapping_get_normalised(inner, {"target", "pointer"})
        if has_target and target is not None:
            return _coerce_reference(target, source=source, path=f"{path}.target", force=force)

        has_package, package = _mapping_get_normalised(inner, _ID_KEYS)
        has_entry, entry = _mapping_get_normalised(inner, _ENTRY_ID_KEYS | {"value"})
        if not has_entry:
            has_local, entry = _mapping_get_normalised(inner, {"local"})
            if has_local:
                has_package = False
                package = None
        if not has_entry:
            raise HandoffFormatError(f"reference at {path} does not contain an entry id")

        if has_package and isinstance(package, str):
            package_tag, package_inner = _unwrap_tag(package)
            if package_tag is None and any(
                separator in package for separator in ("#", "::", ":", "/")
            ):
                embedded_package, embedded_entry = _split_ref_string(package)
                if embedded_package is not None:
                    package = embedded_package
                    entry = embedded_entry
        if not has_package:
            package = source.package

        target = PackageRef(
            _ensure_hashable(package, "reference package"),
            _ensure_hashable(entry, "reference entry"),
        )
        kind = (
            ReferenceKind.LOCAL
            if target.package == source.package
            else ReferenceKind.CROSS_PACKAGE
        )
        if force is ReferenceKind.LOCAL:
            target = PackageRef(source.package, target.entry)
            kind = ReferenceKind.LOCAL
        elif force is ReferenceKind.CROSS_PACKAGE and kind is ReferenceKind.LOCAL:
            raise HandoffFormatError(f"cross-package reference at {path} does not name a package")
        return Reference(source, target, kind, path)

    if isinstance(inner, str):
        package, entry = _split_ref_string(inner)
        if package is None:
            target_package: Hashable = source.package
            kind = ReferenceKind.LOCAL
        else:
            target_package = package
            kind = ReferenceKind.CROSS_PACKAGE
        if force is ReferenceKind.LOCAL:
            target_package = source.package
            kind = ReferenceKind.LOCAL
        elif force is ReferenceKind.CROSS_PACKAGE:
            if kind is ReferenceKind.LOCAL:
                raise HandoffFormatError(
                    f"cross-package reference at {path} does not name a package"
                )
        return Reference(
            source,
            PackageRef(target_package, _ensure_hashable(entry, "reference entry")),
            kind,
            path,
        )

    if isinstance(inner, Sequence) and not isinstance(inner, (str, bytes, bytearray)):
        if len(inner) == 1:
            return _coerce_reference(inner[0], source=source, path=path, force=force)
        if len(inner) == 2:
            package, entry = inner
            target = PackageRef(
                _ensure_hashable(package, "reference package"),
                _ensure_hashable(entry, "reference entry"),
            )
            kind = (
                ReferenceKind.LOCAL
                if target.package == source.package
                else ReferenceKind.CROSS_PACKAGE
            )
            if force is ReferenceKind.LOCAL:
                target = PackageRef(source.package, target.entry)
                kind = ReferenceKind.LOCAL
            elif force is ReferenceKind.CROSS_PACKAGE and kind is ReferenceKind.LOCAL:
                raise HandoffFormatError(
                    f"cross-package reference at {path} does not name a package"
                )
            return Reference(source, target, kind, path)

    if isinstance(inner, Hashable):
        return Reference(source, PackageRef(source.package, inner), ReferenceKind.LOCAL, path)

    raise HandoffFormatError(f"cannot interpret reference at {path}: {value!r}")


def _iter_custom_tag_references(value: Any, path: str) -> Iterator[tuple[Any, str]]:
    if isinstance(value, CBORTag):
        if value.tag in _REFERENCE_TAGS or _looks_like_reference(value):
            yield value, path
            return
        yield from _iter_custom_tag_references(value.value, f"{path}<{value.tag}>")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _iter_custom_tag_references(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _iter_custom_tag_references(item, f"{path}[{index}]")


def _parse_entry(package: Hashable, entry_id: Hashable, value: Any) -> _Entry:
    source = PackageRef(package, entry_id)
    references: list[Reference] = []
    seen_references: set[tuple[PackageRef, PackageRef, ReferenceKind]] = set()
    content = value
    has_content = value is not None

    def add_reference(reference: Reference) -> None:
        key = (reference.source, reference.target, reference.kind)
        if key not in seen_references:
            seen_references.add(key)
            references.append(reference)

    if isinstance(value, Mapping):
        has_content = False
        content = None
        absent_flag, absent_value = _mapping_get_normalised(value, _ABSENT_KEYS)
        if absent_flag and bool(absent_value):
            has_content = False
        present_flag, present_value = _mapping_get_normalised(value, _PRESENT_KEYS)
        if present_flag and present_value is False:
            has_content = False

        has_content_field, content_value = _mapping_get_normalised(value, _CONTENT_KEYS)
        if has_content_field:
            if _looks_like_reference(content_value):
                reference = _coerce_reference(
                    content_value, source=source, path=f"{source}.content"
                )
                add_reference(reference)
            elif content_value is not None and not (absent_flag and bool(absent_value)):
                has_content = bool(present_value) if present_flag else True
                content = content_value
                for tagged, tag_path in _iter_custom_tag_references(
                    content_value, f"{source}.content"
                ):
                    add_reference(
                        _coerce_reference(tagged, source=source, path=tag_path)
                    )
        elif _looks_like_reference(value):
            add_reference(_coerce_reference(value, source=source, path=f"{source}.self"))

        has_content_package, content_package = _mapping_get_normalised(
            value, {"content_package", "held_by", "holder", "custodian"}
        )
        has_content_entry, content_entry = _mapping_get_normalised(
            value, {"content_entry"}
        )
        if has_content_package and has_content_entry:
            add_reference(
                Reference(
                    source,
                    PackageRef(
                        _ensure_hashable(content_package, "reference package"),
                        _ensure_hashable(content_entry, "reference entry"),
                    ),
                    ReferenceKind.LOCAL
                    if content_package == source.package
                    else ReferenceKind.CROSS_PACKAGE,
                    f"{source}.content",
                )
            )

        for key, item in value.items():
            normalised = _normalise_key(key)
            if normalised in _LOCAL_REF_KEYS:
                for child in _iter_reference_values(item):
                    add_reference(
                        _coerce_reference(
                            child,
                            source=source,
                            path=f"{source}.{key}",
                            force=ReferenceKind.LOCAL,
                        )
                    )
            elif normalised in _CROSS_REF_KEYS:
                for child in _iter_reference_values(item):
                    add_reference(
                        _coerce_reference(
                            child,
                            source=source,
                            path=f"{source}.{key}",
                            force=ReferenceKind.CROSS_PACKAGE,
                        )
                    )
            elif normalised in _REF_KEYS:
                for child in _iter_reference_values(item):
                    add_reference(
                        _coerce_reference(child, source=source, path=f"{source}.{key}")
                    )

        if not has_content and not references:
            unknown_keys = {
                key for key in value if _normalise_key(key) not in _ENTRY_META_KEYS
            }
            if unknown_keys:
                has_content = True
                content = value

    else:
        for tagged, tag_path in _iter_custom_tag_references(value, str(source)):
            add_reference(_coerce_reference(tagged, source=source, path=tag_path))

    return _Entry(entry_id, content, has_content, tuple(references))


def _coerce_entry_id(value: Any) -> Hashable:
    if isinstance(value, Mapping):
        has_id, entry_id = _mapping_get_normalised(value, _ENTRY_ID_KEYS | {"value"})
        if has_id:
            return _ensure_hashable(entry_id, "entry identifier")
    return _ensure_hashable(value, "entry identifier")


def _merge_index_entry(entry_value: Any, entry_content: Any) -> Any:
    if not isinstance(entry_value, Mapping) or _looks_like_reference(entry_value):
        return entry_content
    if _mapping_get_normalised(entry_value, _CONTENT_KEYS)[0]:
        return entry_value
    merged = dict(entry_value)
    merged["content"] = entry_content
    return merged


def _parse_package(package_id: Hashable, value: Any) -> Package:
    package_id = _ensure_hashable(package_id, "package identifier")
    _, value = _unwrap_tag(value)

    wrapper: Mapping[Any, Any] | None = value if isinstance(value, Mapping) else None
    index_value: Any = None
    content_lookup: Mapping[Any, Any] = {}

    if wrapper is not None:
        has_index, index_value = _mapping_get_normalised(wrapper, _INDEX_KEYS)
        has_entries, entries_value = _mapping_get_normalised(wrapper, {"entries"})
        if has_entries:
            if isinstance(entries_value, Mapping):
                content_lookup = entries_value
                if not has_index:
                    index_value = entries_value
            elif not has_index:
                index_value = entries_value
        if not has_index and index_value is None:
            # A bare mapping remains a valid public index.
            index_value = wrapper

    if index_value is None:
        index_value = value

    raw_entries: list[tuple[Hashable, Any]] = []
    if isinstance(index_value, Mapping):
        for entry_id, entry_value in index_value.items():
            if wrapper is not None and _normalise_key(entry_id) in (
                _ID_KEYS | _INDEX_KEYS | {"entries", "version", "metadata"}
            ):
                continue
            if entry_id in content_lookup:
                entry_value = _merge_index_entry(entry_value, content_lookup[entry_id])
            raw_entries.append((_coerce_entry_id(entry_id), entry_value))
    elif isinstance(index_value, Sequence) and not isinstance(
        index_value, (str, bytes, bytearray)
    ):
        for position, item in enumerate(index_value):
            if isinstance(item, Mapping):
                has_entry_id = _mapping_get_normalised(
                    item, _ENTRY_ID_KEYS | {"value"}
                )[0]
                entry_id = _coerce_entry_id(item) if has_entry_id else position
                entry_value: Any = item
                if entry_id in content_lookup and not _looks_like_reference(item):
                    entry_value = _merge_index_entry(item, content_lookup[entry_id])
            else:
                entry_id = _coerce_entry_id(item)
                entry_value = content_lookup.get(entry_id, item)
            raw_entries.append((entry_id, entry_value))
    elif isinstance(index_value, Hashable):
        entry_id = _coerce_entry_id(index_value)
        raw_entries.append((entry_id, content_lookup.get(entry_id, index_value)))
    else:
        raise HandoffFormatError(f"package {package_id!r} has an unusable public index")

    entries: dict[Hashable, _Entry] = {}
    for entry_id, entry_value in raw_entries:
        if entry_id not in entries:
            entries[entry_id] = _parse_entry(package_id, entry_id, entry_value)

    return Package(package_id, entries, value)


def _decode_payload(payload: Any, decoder_options: Mapping[str, Any] | None) -> Any:
    options = dict(decoder_options or {})
    if isinstance(payload, Package):
        return payload
    if isinstance(payload, (bytes, bytearray, memoryview)):
        try:
            return loads(payload, **options)
        except CBORDecodeError as exc:
            raise HandoffFormatError(f"could not decode CBOR package: {exc}") from exc
    if isinstance(payload, str) and Path(payload).is_file():
        return _decode_payload(Path(payload), decoder_options)
    if isinstance(payload, os.PathLike):
        try:
            return loads(Path(payload).read_bytes(), **options)
        except OSError as exc:
            raise HandoffFormatError(f"could not read CBOR package {payload!s}: {exc}") from exc
        except CBORDecodeError as exc:
            raise HandoffFormatError(f"could not decode CBOR package {payload!s}: {exc}") from exc
    if hasattr(payload, "read") and callable(payload.read):
        try:
            return loads(payload.read(), **options)
        except CBORDecodeError as exc:
            raise HandoffFormatError(f"could not decode CBOR package: {exc}") from exc
    return payload


def _looks_like_package_wrapper(value: Mapping[Any, Any]) -> bool:
    keys = {_normalise_key(key) for key in value}
    has_index = bool(keys & (_INDEX_KEYS | {"entries"}))
    return has_index and bool(keys & (_ID_KEYS | {"version", "metadata"}))


def _package_id_from_value(value: Any) -> Hashable | None:
    if not isinstance(value, Mapping):
        return None
    has_id, package_id = _mapping_get_normalised(value, _ID_KEYS)
    return _ensure_hashable(package_id, "package identifier") if has_id else None


def _prepare_packages(
    packages: Mapping[Hashable, Any] | Iterable[Any] | Package,
    decoder_options: Mapping[str, Any] | None,
) -> dict[Hashable, Package]:
    if isinstance(packages, Package):
        return {packages.id: packages}

    if isinstance(packages, str) and Path(packages).is_file():
        return _prepare_packages(Path(packages), decoder_options)
    if isinstance(packages, str):
        raise HandoffFormatError(f"package file does not exist: {packages}")

    if isinstance(packages, Mapping):
        if len(packages) == 1:
            has_collection, collection = _mapping_get_normalised(
                packages, {"packages", "bundles", "bags"}
            )
            if has_collection:
                return _prepare_packages(collection, decoder_options)
        if _looks_like_package_wrapper(packages):
            decoded = _decode_payload(packages, decoder_options)
            package_id = _package_id_from_value(decoded)
            if package_id is None:
                raise HandoffFormatError("single package does not declare its package id")
            return _normalise_package_targets({package_id: _parse_package(package_id, decoded)})

        result: dict[Hashable, Package] = {}
        for package_id, payload in packages.items():
            package_id = _ensure_hashable(package_id, "package identifier")
            decoded = _decode_payload(payload, decoder_options)
            result[package_id] = _parse_package(package_id, decoded)
        return _normalise_package_targets(result)

    if isinstance(packages, (bytes, bytearray, memoryview, os.PathLike)) or (
        hasattr(packages, "read") and callable(packages.read)
    ):
        decoded = _decode_payload(packages, decoder_options)
        if isinstance(decoded, Mapping) and _looks_like_package_wrapper(decoded):
            package_id = _package_id_from_value(decoded)
            if package_id is None:
                raise HandoffFormatError("single package does not declare its package id")
            return _normalise_package_targets({package_id: _parse_package(package_id, decoded)})
        return _prepare_packages(decoded, None)

    result: dict[Hashable, Package] = {}
    for index, payload in enumerate(packages):
        decoded = _decode_payload(payload, decoder_options)
        if (
            isinstance(decoded, Sequence)
            and not isinstance(decoded, (str, bytes, bytearray))
            and len(decoded) == 2
            and isinstance(decoded[1], Mapping)
        ):
            package_id = _ensure_hashable(decoded[0], "package identifier")
            package_value = decoded[1]
        else:
            package_id = _package_id_from_value(decoded)
            package_value = decoded
        if package_id is None:
            raise HandoffFormatError(
                f"package at position {index} does not declare its package id"
            )
        if package_id in result:
            raise HandoffFormatError(f"duplicate package id: {package_id!r}")
        result[package_id] = _parse_package(package_id, package_value)
    return _normalise_package_targets(result)


def _alternate_entry_id(entries: Mapping[Hashable, _Entry], entry: Hashable) -> Hashable | None:
    if entry in entries:
        return None
    if isinstance(entry, str):
        try:
            numeric = int(entry)
        except ValueError:
            return None
        if numeric in entries:
            return numeric
    elif isinstance(entry, int) and not isinstance(entry, bool):
        textual = str(entry)
        if textual in entries:
            return textual
    return None


def _alternate_package_id(
    packages: Mapping[Hashable, Package], package: Hashable
) -> Hashable | None:
    if package in packages:
        return None
    if isinstance(package, str):
        try:
            numeric = int(package)
        except ValueError:
            return None
        if numeric in packages:
            return numeric
    elif isinstance(package, int) and not isinstance(package, bool):
        textual = str(package)
        if textual in packages:
            return textual
    return None


def _normalise_package_targets(packages: Mapping[Hashable, Package]) -> dict[Hashable, Package]:
    """Resolve textual numeric ids against a package that indexed them as integers."""

    result: dict[Hashable, Package] = {}
    for package_id, package in packages.items():
        entries: dict[Hashable, _Entry] = {}
        for entry_id, entry in package.entries.items():
            references: list[Reference] = []
            for reference in entry.references:
                target_package_id = reference.target.package
                target_package = packages.get(target_package_id)
                if target_package is None:
                    alternate_package = _alternate_package_id(packages, target_package_id)
                    if alternate_package is not None:
                        target_package_id = alternate_package
                        target_package = packages[alternate_package]
                if target_package is None:
                    references.append(reference)
                    continue
                actual = _alternate_entry_id(target_package.entries, reference.target.entry)
                if actual is None:
                    if target_package_id == reference.target.package:
                        references.append(reference)
                        continue
                    actual = reference.target.entry
                references.append(
                    Reference(
                        reference.source,
                        PackageRef(target_package_id, actual),
                        ReferenceKind.LOCAL
                        if target_package_id == reference.source.package
                        else ReferenceKind.CROSS_PACKAGE,
                        reference.path,
                    )
                )
            entries[entry_id] = _Entry(
                entry.id, entry.content, entry.has_content, tuple(references)
            )
        result[package_id] = Package(package_id, entries, package.raw)
    return result


def _coerce_claim_raw(
    claim: PackageRef | Mapping[Any, Any] | Sequence[Any] | str | Hashable,
    packages: Mapping[Hashable, Package],
) -> PackageRef:
    if isinstance(claim, PackageRef):
        return claim
    if isinstance(claim, Mapping):
        has_claim, nested = _mapping_get_normalised(claim, {"claim", "review", "target"})
        if has_claim and not _mapping_get_normalised(claim, _ID_KEYS)[0]:
            return _coerce_claim(nested, packages)
        has_package, package = _mapping_get_normalised(claim, _ID_KEYS)
        has_entry, entry = _mapping_get_normalised(claim, _ENTRY_ID_KEYS | {"value"})
        if not (has_package and has_entry):
            raise HandoffFormatError("claim must contain a package and an entry id")
        return PackageRef(
            _ensure_hashable(package, "claim package"),
            _ensure_hashable(entry, "claim entry"),
        )
    if isinstance(claim, str):
        package, entry = _split_ref_string(claim)
        if package is None:
            if len(packages) != 1:
                raise HandoffFormatError(
                    "an unqualified claim is ambiguous when more than one package is present"
                )
            package = next(iter(packages))
        return PackageRef(package, entry)
    if isinstance(claim, Sequence) and not isinstance(claim, (bytes, bytearray)):
        if len(claim) != 2:
            raise HandoffFormatError("claim sequence must be (package, entry)")
        return PackageRef(
            _ensure_hashable(claim[0], "claim package"),
            _ensure_hashable(claim[1], "claim entry"),
        )
    if len(packages) != 1:
        raise HandoffFormatError(
            "an unqualified claim is ambiguous when more than one package is present"
        )
    return PackageRef(next(iter(packages)), _ensure_hashable(claim, "claim entry"))


def _coerce_claim(
    claim: PackageRef | Mapping[Any, Any] | Sequence[Any] | str | Hashable,
    packages: Mapping[Hashable, Package],
) -> PackageRef:
    claim_ref = _coerce_claim_raw(claim, packages)
    package = packages.get(claim_ref.package)
    if package is None:
        alternate_package = _alternate_package_id(packages, claim_ref.package)
        if alternate_package is not None:
            claim_ref = PackageRef(alternate_package, claim_ref.entry)
            package = packages[alternate_package]
    if package is not None:
        actual = _alternate_entry_id(package.entries, claim_ref.entry)
        if actual is not None:
            return PackageRef(claim_ref.package, actual)
    return claim_ref


def _check_reference(
    reference: Reference,
    packages: Mapping[Hashable, Package],
    license: EvidenceLicense,
) -> tuple[ReferenceStatus, str]:
    target = reference.target
    if target.package not in packages:
        return ReferenceStatus.PACKAGE_MISSING, f"package {target.package!r} was not handed over"
    if not license.allows(target.package, target.entry):
        return ReferenceStatus.NOT_AUTHORIZED, "target is outside the declared evidence license"

    package = packages[target.package]
    entry = package.entries.get(target.entry)
    if entry is None:
        return ReferenceStatus.MISSING, "entry is absent from the public index"
    if not entry.has_content and not entry.references:
        return (
            ReferenceStatus.MISSING,
            "entry has no reviewable content in the handed-over package",
        )
    return ReferenceStatus.RESOLVED, "entry is available"


def _claim_status(
    claim: PackageRef,
    packages: Mapping[Hashable, Package],
    license: EvidenceLicense,
) -> tuple[ReferenceStatus, str, _Entry | None]:
    if claim.package not in packages:
        return (
            ReferenceStatus.PACKAGE_MISSING,
            f"package {claim.package!r} was not handed over",
            None,
        )
    if not license.allows(claim.package, claim.entry):
        return (
            ReferenceStatus.NOT_AUTHORIZED,
            "claim is outside the declared evidence license",
            None,
        )
    entry = packages[claim.package].entries.get(claim.entry)
    if entry is None:
        return ReferenceStatus.MISSING, "claim entry is absent from the public index", None
    if not entry.has_content and not entry.references:
        return (
            ReferenceStatus.MISSING,
            "claim entry has no reviewable content in the handed-over package",
            None,
        )
    return ReferenceStatus.RESOLVED, "claim entry is available", entry


def _aggregate_status(
    statuses: Iterable[ReferenceStatus], default: ReferenceStatus
) -> ReferenceStatus:
    values = list(statuses)
    if not values:
        return default
    for status in (
        ReferenceStatus.NOT_AUTHORIZED,
        ReferenceStatus.PACKAGE_MISSING,
        ReferenceStatus.MISSING,
    ):
        if status in values:
            return status
    return ReferenceStatus.RESOLVED


def _audit_one(
    packages: Mapping[Hashable, Package],
    claim: PackageRef,
    license: EvidenceLicense,
) -> HandoffReport:
    claim_status, claim_reason, claim_entry = _claim_status(claim, packages, license)
    checklist: list[ChecklistItem] = []
    missing: list[PackageRef] = []
    denied: list[PackageRef] = []
    if claim_entry is None:
        if claim_status.is_missing:
            missing.append(claim)
        elif claim_status is ReferenceStatus.NOT_AUTHORIZED:
            denied.append(claim)
        return HandoffReport(
            claim=claim,
            status=claim_status,
            sufficient=False,
            checklist=[],
            missing=missing,
            not_authorized=denied,
            reason=claim_reason,
        )

    queue: list[PackageRef] = [claim]
    visited: set[PackageRef] = set()
    checklist_keys: set[tuple[PackageRef, PackageRef, ReferenceKind]] = set()
    statuses: list[ReferenceStatus] = []
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        if current.package not in packages:
            continue
        entry = packages[current.package].entries.get(current.entry)
        if entry is None:
            continue
        for reference in entry.references:
            key = (reference.source, reference.target, reference.kind)
            if key in checklist_keys:
                continue
            checklist_keys.add(key)
            status, reason = _check_reference(reference, packages, license)
            statuses.append(status)
            checklist.append(
                ChecklistItem(
                    source=reference.source,
                    target=reference.target,
                    kind=reference.kind,
                    status=status,
                    reason=reason,
                    path=reference.path,
                )
            )
            if status is ReferenceStatus.MISSING:
                if reference.target not in missing:
                    missing.append(reference.target)
            elif status is ReferenceStatus.PACKAGE_MISSING:
                if reference.target not in missing:
                    missing.append(reference.target)
            elif status is ReferenceStatus.NOT_AUTHORIZED:
                if reference.target not in denied:
                    denied.append(reference.target)
            elif reference.target not in visited:
                queue.append(reference.target)

    checklist.sort(
        key=lambda item: (
            _sort_key(item.source_package),
            _sort_key(item.source_entry),
            0 if item.kind is ReferenceKind.LOCAL else 1,
            _sort_key(item.target_package),
            _sort_key(item.target_entry),
        )
    )
    missing.sort(key=lambda item: (_sort_key(item.package), _sort_key(item.entry)))
    denied.sort(key=lambda item: (_sort_key(item.package), _sort_key(item.entry)))
    status = _aggregate_status(statuses, claim_status)
    sufficient = status is ReferenceStatus.RESOLVED and claim_status is ReferenceStatus.RESOLVED
    if sufficient:
        reason = "claim and all referenced entries are available under the evidence license"
    elif status is ReferenceStatus.NOT_AUTHORIZED:
        reason = "at least one required entry is outside the declared evidence license"
    elif status is ReferenceStatus.PACKAGE_MISSING:
        reason = "at least one required package was not handed over"
    elif status is ReferenceStatus.MISSING:
        reason = "at least one required entry is absent from the handed-over index"
    else:
        reason = claim_reason
    return HandoffReport(
        claim=claim,
        status=status,
        sufficient=sufficient,
        checklist=checklist,
        missing=missing,
        not_authorized=denied,
        reason=reason,
    )


def _coerce_license(value: Any) -> EvidenceLicense:
    if isinstance(value, EvidenceLicense):
        return value
    if value is None:
        return EvidenceLicense.all()
    return EvidenceLicense(value)


def _pick_license(
    license: Any,
    evidence_license: Any,
    permitted_packages: Any,
    authorized_packages: Any,
    approved_packages: Any = None,
    permissions: Any = None,
    evidence_scope: Any = None,
) -> EvidenceLicense:
    supplied = [
        value
        for value in (
            license,
            evidence_license,
            permitted_packages,
            authorized_packages,
            approved_packages,
            permissions,
            evidence_scope,
        )
        if value is not None
    ]
    if len(supplied) > 1:
        raise HandoffFormatError("declare the evidence license once")
    return _coerce_license(supplied[0] if supplied else None)


def audit_handoff(
    packages: Mapping[Hashable, Any] | Iterable[Any] | Package,
    claim: PackageRef | Mapping[Any, Any] | Sequence[Any] | str | Hashable,
    *,
    license: Any = None,
    evidence_license: Any = None,
    permitted_packages: Any = None,
    authorized_packages: Any = None,
    approved_packages: Any = None,
    permissions: Any = None,
    evidence_scope: Any = None,
    withdrawn: Iterable[Hashable] = (),
    decoder_options: Mapping[str, Any] | None = None,
) -> HandoffReport:
    """Check whether handed-over packages can review ``claim`` offline.

    ``packages`` may contain decoded package mappings or CBOR bytes.  It is
    normally a mapping of package id to payload; an iterable of self-identifying
    packages is accepted as well.

    References are followed only while the target package and entry are allowed
    by ``license``.  A missing package, a missing index entry and an entry that
    is present but not licensed are reported as distinct statuses.
    """

    prepared = _prepare_packages(packages, decoder_options)
    claim_ref = _coerce_claim(claim, prepared)
    withdrawn_set = {_ensure_hashable(package, "withdrawn package") for package in withdrawn}
    if withdrawn_set:
        prepared = {
            package_id: package
            for package_id, package in prepared.items()
            if package_id not in withdrawn_set
        }
    return _audit_one(
        prepared,
        claim_ref,
        _pick_license(
            license,
            evidence_license,
            permitted_packages,
            authorized_packages,
            approved_packages,
            permissions,
            evidence_scope,
        ),
    )


def audit_claims(
    packages: Mapping[Hashable, Any] | Iterable[Any] | Package,
    claims: Iterable[PackageRef | Mapping[Any, Any] | Sequence[Any] | str | Hashable],
    *,
    license: Any = None,
    evidence_license: Any = None,
    permitted_packages: Any = None,
    authorized_packages: Any = None,
    approved_packages: Any = None,
    permissions: Any = None,
    evidence_scope: Any = None,
    withdrawn: Iterable[Hashable] = (),
    decoder_options: Mapping[str, Any] | None = None,
) -> HandoffAudit:
    """Audit several claims independently and return one report per claim."""

    prepared = _prepare_packages(packages, decoder_options)
    claim_refs = [_coerce_claim(claim, prepared) for claim in claims]
    withdrawn_set = {_ensure_hashable(package, "withdrawn package") for package in withdrawn}
    if withdrawn_set:
        prepared = {
            package_id: package
            for package_id, package in prepared.items()
            if package_id not in withdrawn_set
        }
    evidence = _pick_license(
        license,
        evidence_license,
        permitted_packages,
        authorized_packages,
        approved_packages,
        permissions,
        evidence_scope,
    )
    reports: list[HandoffReport] = []
    for claim_ref in claim_refs:
        reports.append(_audit_one(prepared, claim_ref, evidence))
    return HandoffAudit(reports)


def withdraw_package(
    packages: Mapping[Hashable, Any] | Iterable[Any] | Package,
    *package_ids: Hashable,
) -> Any:
    """Return a copy of ``packages`` without the named packages.

    The original input is never modified.
    """

    withdrawn = {_ensure_hashable(package_id, "withdrawn package") for package_id in package_ids}
    if isinstance(packages, Package):
        if packages.id in withdrawn:
            return {}
        return {packages.id: packages}
    if isinstance(packages, Mapping):
        return {key: value for key, value in packages.items() if key not in withdrawn}
    result = []
    for package in packages:
        package_id = package_id_from_value(package)
        if package_id is None and isinstance(package, (bytes, bytearray, memoryview)):
            try:
                package_id = package_id_from_value(loads(package))
            except CBORDecodeError:
                pass
        if package_id not in withdrawn:
            result.append(package)
    return result


def package_id_from_value(value: Any) -> Hashable | None:
    """Return the declared id of a decoded package value, if any."""

    return _package_id_from_value(value)


def scan_references(
    packages: Mapping[Hashable, Any] | Iterable[Any] | Package,
    *,
    decoder_options: Mapping[str, Any] | None = None,
) -> list[Reference]:
    """Return every index reference, sorted by source provenance."""

    prepared = _prepare_packages(packages, decoder_options)
    references = [
        reference
        for package in prepared.values()
        for entry in package.entries.values()
        for reference in entry.references
    ]
    references.sort(
        key=lambda reference: (
            _sort_key(reference.source.package),
            _sort_key(reference.source.entry),
            0 if reference.kind is ReferenceKind.LOCAL else 1,
            _sort_key(reference.target.package),
            _sort_key(reference.target.entry),
        )
    )
    return references


def resolve_references(
    packages: Mapping[Hashable, Any] | Iterable[Any] | Package,
    claim: PackageRef | Mapping[Any, Any] | Sequence[Any] | str | Hashable,
    *,
    license: Any = None,
    decoder_options: Mapping[str, Any] | None = None,
) -> list[ChecklistItem]:
    """Return the claim's provenance-ordered reference checklist."""

    return audit_handoff(
        packages,
        claim,
        license=license,
        decoder_options=decoder_options,
    ).checklist


def build_checklist(
    packages: Mapping[Hashable, Any] | Iterable[Any] | Package,
    claim: PackageRef | Mapping[Any, Any] | Sequence[Any] | str | Hashable,
    *,
    license: Any = None,
    decoder_options: Mapping[str, Any] | None = None,
) -> list[ChecklistItem]:
    """Alias of :func:`resolve_references` for archival handoff checklists."""

    return resolve_references(
        packages,
        claim,
        license=license,
        decoder_options=decoder_options,
    )


def review_claim(
    packages: Mapping[Hashable, Any] | Iterable[Any] | Package,
    claim: PackageRef | Mapping[Any, Any] | Sequence[Any] | str | Hashable,
    **kwargs: Any,
) -> HandoffReport:
    """Alias of :func:`audit_handoff`."""

    return audit_handoff(packages, claim, **kwargs)


audit = audit_handoff
audit_packages = audit_handoff
verify_handoff = audit_handoff
check_handoff = audit_handoff
check_packages = audit_handoff
