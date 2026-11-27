# -------------------------------------------------------------------------------
# elftools: elf/note_types.py
#
# Owner-scoped ELF note type metadata and provenance.
#
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from .enums import ENUM_ANDROID_NOTE_N_TYPE, ENUM_CORE_NOTE_N_TYPE, ENUM_NOTE_N_TYPE

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


NOTE_TYPE_VOCABULARY_VERSION = "elf-note-types-2026.11"
LEGACY_NOTE_TYPE_VOCABULARY_VERSION = "pyelftools-0.33"


@dataclass(frozen=True)
class NoteTypeEntry:
    """One symbolic interpretation in one owner's note-type namespace."""

    owner: str
    value: int
    name: str
    description: str
    source: str
    vocabulary_version: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "value": self.value,
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "vocabulary_version": self.vocabulary_version,
        }


@dataclass(frozen=True)
class NoteTypeNamespace:
    """A note-type table owned by one ELF note name (n_name).

    Symbolic note type names only have meaning inside their owner namespace.
    ``core_only`` namespaces are valid only for ET_CORE inputs.
    """

    owner: str
    source: str
    vocabulary_version: str
    entries: tuple[NoteTypeEntry, ...]
    core_only: bool = False

    def entries_for(self, value: int) -> tuple[NoteTypeEntry, ...]:
        return tuple(entry for entry in self.entries if entry.value == value)

    def entries_for_name(self, name: str) -> tuple[NoteTypeEntry, ...]:
        return tuple(entry for entry in self.entries if entry.name == name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "source": self.source,
            "vocabulary_version": self.vocabulary_version,
            "core_only": self.core_only,
            "entries": [entry.as_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class NoteTypeVocabulary:
    """A versioned manifest of owner-scoped note type namespaces."""

    version: str
    namespaces: Mapping[str, NoteTypeNamespace]

    def __getitem__(self, owner: str) -> NoteTypeNamespace:
        return self.namespaces[owner]

    def get(self, owner: str) -> NoteTypeNamespace | None:
        return self.namespaces.get(owner)

    def resolve(
        self, owner: str | None, value: int, *, e_type: str | int | None = None
    ) -> NoteTypeInterpretation:
        return resolve_note_type(owner, value, e_type=e_type, vocabulary=self)

    def lookup(
        self, owner: str | None, name: str, *, e_type: str | int | None = None
    ) -> NoteTypeNameLookup:
        return resolve_note_type_name(owner, name, e_type=e_type, vocabulary=self)

    def namespace_for(
        self, owner: str | None, *, e_type: str | int | None = None
    ) -> NoteTypeNamespace | None:
        if owner is None:
            return None
        namespace = self.namespaces.get(owner)
        if namespace is None:
            return None
        if (
            namespace.core_only
            and e_type is not None
            and not _is_core_file_type(e_type)
        ):
            return None
        return namespace

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "namespaces": {
                owner: namespace.as_dict()
                for owner, namespace in self.namespaces.items()
            },
        }


@dataclass(frozen=True)
class NoteTypeInterpretation:
    """Provenance-bearing interpretation of a raw ELF note type code."""

    raw: int
    legacy: str | int
    owner: str | None
    name: str | None
    names: tuple[str, ...]
    source: str | None
    vocabulary_version: str | None
    registry_version: str
    entries: tuple[NoteTypeEntry, ...]
    candidates: tuple[NoteTypeEntry, ...]
    disputed: bool
    resolved: bool

    @property
    def description(self) -> str | None:
        if self.disputed or not self.entries:
            return None
        return self.entries[0].description

    @property
    def candidate_names(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(entry.name for entry in self.candidates))

    def as_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "raw_hex": f"0x{self.raw:08x}",
            "legacy": self.legacy,
            "owner": self.owner,
            "name": self.name,
            "description": self.description,
            "names": list(self.names),
            "candidate_names": list(self.candidate_names),
            "source": self.source,
            "vocabulary_version": self.vocabulary_version,
            "registry_version": self.registry_version,
            "disputed": self.disputed,
            "resolved": self.resolved,
            "entries": [entry.as_dict() for entry in self.entries],
            "candidates": [entry.as_dict() for entry in self.candidates],
        }


@dataclass(frozen=True)
class NoteTypeNameLookup:
    """Reverse lookup for auditing a historical output that only has a name."""

    owner: str | None
    name: str
    entries: tuple[NoteTypeEntry, ...]
    values: tuple[int, ...]
    source: str | None
    vocabulary_version: str | None
    ambiguous: bool

    @property
    def resolved(self) -> bool:
        return bool(self.values) and not self.ambiguous

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "name": self.name,
            "values": list(self.values),
            "values_hex": [f"0x{value:08x}" for value in self.values],
            "source": self.source,
            "vocabulary_version": self.vocabulary_version,
            "ambiguous": self.ambiguous,
            "resolved": self.resolved,
            "entries": [entry.as_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class NoteTypeConflict:
    """A genuine conflict: one owner maps one code to multiple explanations."""

    owner: str
    value: int
    entries: tuple[NoteTypeEntry, ...]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(entry.name for entry in self.entries)

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "value": self.value,
            "value_hex": f"0x{self.value:08x}",
            "names": [entry.name for entry in self.entries],
            "entries": [entry.as_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class NoteTypeSymbolGroup:
    """The same abbreviation used legitimately by more than one owner."""

    name: str
    entries: tuple[NoteTypeEntry, ...]

    @property
    def owners(self) -> tuple[str, ...]:
        return tuple(sorted({entry.owner for entry in self.entries}))

    @property
    def values(self) -> tuple[int, ...]:
        return tuple(sorted({entry.value for entry in self.entries}))

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "owners": list(self.owners),
            "entries": [entry.as_dict() for entry in self.entries],
        }


_GNU_SOURCE = "binutils include/elf/common.h (GNU ELF note types)"
_GNU_VERSION = "binutils-2.47"
_ANDROID_SOURCE = "Android bionic libc/include/elfnote.h (Android ELF note types)"
_ANDROID_VERSION = "android-bionic-main"
_CORE_SOURCE = "Linux UAPI include/uapi/linux/elfcore.h (ELF core note types)"
_CORE_VERSION = "linux-uapi"

_GNU_DESCRIPTIONS = {
    "NT_GNU_ABI_TAG": "ABI version tag",
    "NT_GNU_HWCAP": "DSO-supplied software HWCAP info",
    "NT_GNU_BUILD_ID": "unique build ID bitstring",
    "NT_GNU_GOLD_VERSION": "gold version",
    "NT_GNU_PROPERTY_TYPE_0": "program properties",
}

_ANDROID_DESCRIPTIONS = {
    "NT_VERSION": "version",
}

_CORE_DESCRIPTIONS = {
    "NT_PRSTATUS": "process status",
    "NT_FPREGSET": "floating point registers",
    "NT_PRPSINFO": "process information",
    "NT_TASKSTRUCT": "task structure",
    "NT_AUXV": "auxiliary vector",
    "NT_SIGINFO": "signal information",
    "NT_FILE": "mapped files",
}


def _build_entries(
    owner: str,
    enum: Mapping[str, int],
    descriptions: Mapping[str, str],
    source: str,
    version: str,
) -> tuple[NoteTypeEntry, ...]:
    return tuple(
        NoteTypeEntry(
            owner=owner,
            value=value,
            name=name,
            description=descriptions.get(name, name),
            source=source,
            vocabulary_version=version,
        )
        for name, value in enum.items()
        if name != "_default_" and isinstance(value, int)
    )


_GNU_NAMESPACE = NoteTypeNamespace(
    owner="GNU",
    source=_GNU_SOURCE,
    vocabulary_version=_GNU_VERSION,
    entries=_build_entries(
        "GNU", ENUM_NOTE_N_TYPE, _GNU_DESCRIPTIONS, _GNU_SOURCE, _GNU_VERSION
    ),
)

_ANDROID_NAMESPACE = NoteTypeNamespace(
    owner="Android",
    source=_ANDROID_SOURCE,
    vocabulary_version=_ANDROID_VERSION,
    entries=_build_entries(
        "Android",
        ENUM_ANDROID_NOTE_N_TYPE,
        _ANDROID_DESCRIPTIONS,
        _ANDROID_SOURCE,
        _ANDROID_VERSION,
    ),
)

_CORE_NAMESPACE = NoteTypeNamespace(
    owner="CORE",
    source=_CORE_SOURCE,
    vocabulary_version=_CORE_VERSION,
    entries=_build_entries(
        "CORE", ENUM_CORE_NOTE_N_TYPE, _CORE_DESCRIPTIONS, _CORE_SOURCE, _CORE_VERSION
    ),
    core_only=True,
)


NOTE_TYPE_REGISTRY = NoteTypeVocabulary(
    version=NOTE_TYPE_VOCABULARY_VERSION,
    namespaces=MappingProxyType(
        {
            namespace.owner: namespace
            for namespace in (_GNU_NAMESPACE, _ANDROID_NAMESPACE, _CORE_NAMESPACE)
        }
    ),
)

LEGACY_NOTE_TYPE_REGISTRY = NoteTypeVocabulary(
    version=LEGACY_NOTE_TYPE_VOCABULARY_VERSION,
    namespaces=NOTE_TYPE_REGISTRY.namespaces,
)

NOTE_TYPE_REGISTRIES: Mapping[str, NoteTypeVocabulary] = MappingProxyType(
    {
        NOTE_TYPE_REGISTRY.version: NOTE_TYPE_REGISTRY,
        LEGACY_NOTE_TYPE_REGISTRY.version: LEGACY_NOTE_TYPE_REGISTRY,
        "current": NOTE_TYPE_REGISTRY,
        "legacy": LEGACY_NOTE_TYPE_REGISTRY,
    }
)

# Explicit aliases for callers that describe these tables as a manifest or as
# a vocabulary collection rather than a registry.
NOTE_TYPE_MANIFEST = NOTE_TYPE_REGISTRY
NOTE_TYPE_NAMESPACES = NOTE_TYPE_REGISTRY.namespaces
NOTE_TYPE_VOCABULARIES = NOTE_TYPE_REGISTRIES


def _legacy_names(enum: Mapping[str, int]) -> dict[int, str]:
    # Keep exactly the historical last-name-wins behavior. Existing reports
    # depend on this mapping even if the provenance registry gains aliases.
    return {
        value: name
        for name, value in enum.items()
        if name != "_default_" and isinstance(value, int)
    }


_LEGACY_NOTE_TYPE_NAMES = {
    "GNU": _legacy_names(ENUM_NOTE_N_TYPE),
    "Android": _legacy_names(ENUM_ANDROID_NOTE_N_TYPE),
}
_LEGACY_CORE_NOTE_TYPE_NAMES = _legacy_names(ENUM_CORE_NOTE_N_TYPE)


def _is_core_file_type(e_type: str | int | None) -> bool:
    return e_type in ("ET_CORE", 4)


def legacy_note_type_name(
    owner: str | None, value: int, *, e_type: str | int | None = None
) -> str | int:
    """Return the historical ``n_type`` value used by pyelftools 0.33."""

    if owner == "CORE" and _is_core_file_type(e_type):
        names = _LEGACY_CORE_NOTE_TYPE_NAMES
    else:
        names = _LEGACY_NOTE_TYPE_NAMES.get(owner or "", {})
    return names.get(value, value)


def _coerce_vocabulary(
    vocabulary: NoteTypeVocabulary | str | None,
) -> NoteTypeVocabulary:
    if vocabulary is None:
        return NOTE_TYPE_REGISTRY
    if isinstance(vocabulary, NoteTypeVocabulary):
        return vocabulary
    try:
        return NOTE_TYPE_REGISTRIES[vocabulary]
    except KeyError as exc:
        raise ValueError(
            f"Unknown note type vocabulary {vocabulary!r}; known versions: "
            f"{sorted(NOTE_TYPE_REGISTRIES)}"
        ) from exc


def get_note_type_vocabulary(
    vocabulary: NoteTypeVocabulary | str | None = None,
) -> NoteTypeVocabulary:
    """Return a versioned registry object for a vocabulary name or object."""

    return _coerce_vocabulary(vocabulary)


def _iter_candidate_entries(
    vocabulary: NoteTypeVocabulary, value: int, e_type: str | int | None
) -> tuple[NoteTypeEntry, ...]:
    candidates: list[NoteTypeEntry] = []
    for namespace in vocabulary.namespaces.values():
        if (
            namespace.core_only
            and e_type is not None
            and not _is_core_file_type(e_type)
        ):
            continue
        candidates.extend(namespace.entries_for(value))
    return tuple(candidates)


def resolve_note_type(
    owner: str | None,
    value: int,
    *,
    e_type: str | int | None = None,
    vocabulary: NoteTypeVocabulary | str | None = None,
) -> NoteTypeInterpretation:
    """Resolve a raw note type code in the namespace named by its owner.

    ``value`` is the unmodified on-disk code. The owner (the ELF note name) is
    the namespace selector; a symbolic type name is never enough to select a
    namespace. Cross-owner collisions are therefore resolved, not reported as
    conflicts. A genuine conflict exists only when one owner assigns more than
    one explanation to one code; those entries remain visible in ``entries``
    and ``disputed`` is set.
    """

    registry = _coerce_vocabulary(vocabulary)
    legacy = legacy_note_type_name(owner, value, e_type=e_type)
    namespace = registry.namespace_for(owner, e_type=e_type)
    candidates = _iter_candidate_entries(registry, value, e_type)

    if namespace is None:
        return NoteTypeInterpretation(
            raw=value,
            legacy=legacy,
            owner=owner,
            name=None,
            names=(),
            source=None,
            vocabulary_version=None,
            registry_version=registry.version,
            entries=(),
            candidates=candidates,
            disputed=False,
            resolved=False,
        )

    entries = namespace.entries_for(value)
    names = tuple(dict.fromkeys(entry.name for entry in entries))
    disputed = len(names) > 1 or len({entry.description for entry in entries}) > 1
    name = names[0] if names and not disputed else None
    return NoteTypeInterpretation(
        raw=value,
        legacy=legacy,
        owner=owner,
        name=name,
        names=names,
        source=namespace.source,
        vocabulary_version=namespace.vocabulary_version,
        registry_version=registry.version,
        entries=entries,
        candidates=candidates,
        disputed=disputed,
        resolved=name is not None,
    )


def resolve_note_type_name(
    owner: str | None,
    name: str,
    *,
    e_type: str | int | None = None,
    vocabulary: NoteTypeVocabulary | str | None = None,
) -> NoteTypeNameLookup:
    """Reverse a historical symbolic note type using its owner namespace.

    When an owner is supplied, the lookup is limited to that namespace. Only an
    owner-less lookup searches all namespaces, and such a lookup is marked
    ambiguous if the name is shared. This prevents two legitimate local names
    from being collapsed by display text alone.
    """

    registry = _coerce_vocabulary(vocabulary)
    if owner is not None:
        namespace = registry.namespace_for(owner, e_type=e_type)
        namespaces = () if namespace is None else (namespace,)
    else:
        namespaces = tuple(
            namespace
            for namespace in registry.namespaces.values()
            if not namespace.core_only or e_type is None or _is_core_file_type(e_type)
        )

    entries = tuple(
        entry for namespace in namespaces for entry in namespace.entries_for_name(name)
    )
    values = tuple(dict.fromkeys(entry.value for entry in entries))
    owners = tuple(dict.fromkeys(entry.owner for entry in entries))
    source = namespaces[0].source if len(namespaces) == 1 and entries else None
    version = (
        namespaces[0].vocabulary_version if len(namespaces) == 1 and entries else None
    )
    return NoteTypeNameLookup(
        owner=owner,
        name=name,
        entries=entries,
        values=values,
        source=source,
        vocabulary_version=version,
        ambiguous=len(values) > 1 or len(owners) > 1,
    )


def iter_note_type_conflicts(
    vocabulary: NoteTypeVocabulary | str | None = None,
) -> Iterator[NoteTypeConflict]:
    """Yield genuine same-owner, same-code conflicts only.

    The same numeric code assigned different meanings by GNU, Android or CORE
    is normal namespacing because the owner selects the interpretation. Those
    are exposed through ``iter_shared_note_type_symbols`` only when the
    abbreviation itself is shared; they are not conflicts.
    """

    registry = _coerce_vocabulary(vocabulary)
    for namespace in registry.namespaces.values():
        for value in dict.fromkeys(entry.value for entry in namespace.entries):
            entries = namespace.entries_for(value)
            explanations = {(entry.name, entry.description) for entry in entries}
            if len(explanations) > 1:
                yield NoteTypeConflict(
                    owner=namespace.owner,
                    value=value,
                    entries=entries,
                )


def iter_shared_note_type_symbols(
    vocabulary: NoteTypeVocabulary | str | None = None,
) -> Iterator[NoteTypeSymbolGroup]:
    """Yield abbreviations legitimately reused by distinct local entries."""

    registry = _coerce_vocabulary(vocabulary)
    by_name: dict[str, list[NoteTypeEntry]] = {}
    for namespace in registry.namespaces.values():
        for entry in namespace.entries:
            by_name.setdefault(entry.name, []).append(entry)
    for name, entries in by_name.items():
        local_entries = {(entry.owner, entry.value) for entry in entries}
        if len(local_entries) > 1:
            yield NoteTypeSymbolGroup(name=name, entries=tuple(entries))
