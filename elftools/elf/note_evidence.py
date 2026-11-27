# -------------------------------------------------------------------------------
# elftools: elf/note_evidence.py
#
# Read-only, provenance-preserving note evidence reports.
#
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .elffile import ELFFile
from .note_types import (
    NoteTypeConflict,
    NoteTypeInterpretation,
    NoteTypeSymbolGroup,
    NoteTypeVocabulary,
    get_note_type_vocabulary,
    iter_note_type_conflicts,
    iter_shared_note_type_symbols,
)
from .sections import NoteSection
from .segments import NoteSegment

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence


@dataclass(frozen=True)
class NoteEvidenceView:
    """One section or segment view that exposed the same note bytes."""

    kind: str
    name: str | None
    offset: int
    size: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
        }


@dataclass(frozen=True)
class NoteObservation:
    """A single raw note plus the interpretation used by a report."""

    owner: str | None
    raw_type: int
    descriptor: bytes
    namesz: int
    descsz: int
    offset: int
    size: int
    legacy_type: str | int
    interpretation: NoteTypeInterpretation
    views: tuple[NoteEvidenceView, ...]

    @property
    def resolved(self) -> bool:
        return self.interpretation.resolved

    def as_dict(self) -> dict[str, Any]:
        return {
            "n_name": self.owner,
            "n_type_raw": self.raw_type,
            "n_type_raw_hex": f"0x{self.raw_type:08x}",
            "n_type": self.legacy_type,
            "n_type_legacy": self.legacy_type,
            "n_type_name": self.interpretation.name,
            "n_type_description": self.interpretation.description,
            "n_type_owner": self.owner,
            "n_type_source": self.interpretation.source,
            "n_type_vocabulary_version": self.interpretation.vocabulary_version,
            "n_type_registry_version": self.interpretation.registry_version,
            "n_type_disputed": self.interpretation.disputed,
            "n_type_candidate_names": list(self.interpretation.candidate_names),
            "n_type_interpretation": self.interpretation.as_dict(),
            "n_namesz": self.namesz,
            "n_descsz": self.descsz,
            "n_descdata": self.descriptor.hex(),
            "n_offset": self.offset,
            "n_size": self.size,
            "views": [view.as_dict() for view in self.views],
        }


@dataclass(frozen=True)
class NoteEvidenceReport:
    """Offline evidence report; every interpretation keeps its provenance."""

    vocabulary: NoteTypeVocabulary
    observations: tuple[NoteObservation, ...]
    conflicts: tuple[NoteTypeConflict, ...]
    shared_symbols: tuple[NoteTypeSymbolGroup, ...]
    artifact: str | None = None

    @property
    def unresolved(self) -> tuple[NoteObservation, ...]:
        return tuple(obs for obs in self.observations if not obs.resolved)

    @property
    def disputed(self) -> tuple[NoteObservation, ...]:
        return tuple(obs for obs in self.observations if obs.interpretation.disputed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "vocabulary_version": self.vocabulary.version,
            "manifest": {
                owner: namespace.as_dict()
                for owner, namespace in self.vocabulary.namespaces.items()
            },
            "observations": [obs.as_dict() for obs in self.observations],
            "unresolved_offsets": [obs.offset for obs in self.unresolved],
            "disputed_offsets": [obs.offset for obs in self.disputed],
            "conflicts": [conflict.as_dict() for conflict in self.conflicts],
            "shared_symbols": [group.as_dict() for group in self.shared_symbols],
        }


def _note_view(item: NoteSection | NoteSegment) -> NoteEvidenceView:
    if isinstance(item, NoteSection):
        return NoteEvidenceView(
            kind="section",
            name=item.name,
            offset=item["sh_offset"],
            size=item["sh_size"],
        )
    return NoteEvidenceView(
        kind="segment",
        name="PT_NOTE",
        offset=item["p_offset"],
        size=item["p_filesz"],
    )


def _observation_key(note: Any) -> tuple[Any, ...]:
    return (
        note["n_offset"],
        note["n_size"],
        note["n_name"],
        note["n_type_raw"],
        note["n_descdata"],
    )


def iter_note_evidence(
    elf: ELFFile,
    *,
    vocabulary: NoteTypeVocabulary | str | None = None,
) -> Iterator[NoteObservation]:
    """Yield one observation per physical note, regardless of view count.

    A note visible through both PT_NOTE and SHT_NOTE is one piece of evidence;
    both views are retained instead of counted as independent observations.
    """

    views_by_key: dict[tuple[Any, ...], list[NoteEvidenceView]] = {}
    notes_by_key: dict[tuple[Any, ...], Any] = {}

    for section in elf.iter_sections():
        if not isinstance(section, NoteSection):
            continue
        for note in section.iter_notes(vocabulary=vocabulary):
            key = _observation_key(note)
            notes_by_key[key] = note
            views_by_key.setdefault(key, []).append(_note_view(section))

    for segment in elf.iter_segments():
        if not isinstance(segment, NoteSegment):
            continue
        for note in segment.iter_notes(vocabulary=vocabulary):
            key = _observation_key(note)
            notes_by_key[key] = note
            views_by_key.setdefault(key, []).append(_note_view(segment))

    for key, note in notes_by_key.items():
        yield NoteObservation(
            owner=note["n_name"],
            raw_type=note["n_type_raw"],
            descriptor=bytes(note["n_descdata"]),
            namesz=note["n_namesz"],
            descsz=note["n_descsz"],
            offset=note["n_offset"],
            size=note["n_size"],
            legacy_type=note["n_type"],
            interpretation=note["n_type_interpretation"],
            views=tuple(views_by_key[key]),
        )


def collect_note_evidence(
    source: ELFFile | str | os.PathLike[str],
    *,
    vocabulary: NoteTypeVocabulary | str | None = None,
    artifact: str | None = None,
) -> NoteEvidenceReport:
    """Collect a read-only evidence report from an ELFFile or a local path."""

    registry = get_note_type_vocabulary(vocabulary)
    if isinstance(source, ELFFile):
        elf = source
        observations = tuple(iter_note_evidence(elf, vocabulary=registry))
    else:
        path = os.fspath(source)
        if artifact is None:
            artifact = path
        with ELFFile.load_from_path(path) as elf:
            observations = tuple(iter_note_evidence(elf, vocabulary=registry))

    return NoteEvidenceReport(
        vocabulary=registry,
        observations=observations,
        conflicts=tuple(iter_note_type_conflicts(registry)),
        shared_symbols=tuple(iter_shared_note_type_symbols(registry)),
        artifact=artifact,
    )


def collect_note_evidence_many(
    sources: Sequence[ELFFile | str | os.PathLike[str]],
    *,
    vocabulary: NoteTypeVocabulary | str | None = None,
) -> tuple[NoteEvidenceReport, ...]:
    """Collect independent reports without merging separate artifacts."""

    return tuple(
        collect_note_evidence(source, vocabulary=vocabulary) for source in sources
    )
