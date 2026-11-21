#-------------------------------------------------------------------------------
# elftools: elf/corefile.py
#
# Static matching of file-backed mappings recorded in an ELF core file against
# caller-supplied candidate ELF archives.
#-------------------------------------------------------------------------------
from __future__ import annotations

import io
import os
from contextlib import ExitStack
from dataclasses import dataclass, field
from enum import Enum
from typing import IO, Any, Iterable, Iterator, Mapping, Sequence

from ..common.exceptions import ELFError, ELFParseError
from .elffile import ELFFile
from .sections import NoteSection
from .segments import NoteSegment

NT_FILE = 0x46494C45
_DEFAULT_CHUNK_SIZE = 1024 * 1024
_DELETED_SUFFIX = " (deleted)"
_RESOLUTION = {
    "matched": "unique",
    "unconfirmed": "unconfirmed",
    "contradicted": "contradicted",
    "missing": "missing",
}


class CoreMatchStatus(str, Enum):
    """Result of matching one core-file mapping instance.

    ``MATCHED`` means exactly one supplied candidate is both consistent and
    supported by positive evidence (mapped bytes or a readable build-id).
    ``UNCONFIRMED`` means the evidence does not select one candidate.
    ``CONTRADICTED`` means every supplied candidate is ruled out.
    ``MISSING`` means no candidate archive was supplied for the path.
    """

    MATCHED = "matched"
    UNCONFIRMED = "unconfirmed"
    CONTRADICTED = "contradicted"
    MISSING = "missing"

    # Descriptive aliases for callers that use the terminology from the
    # evidence-matching domain rather than the compact manifest vocabulary.
    UNIQUE = "matched"
    AMBIGUOUS = "unconfirmed"
    CONFLICT = "contradicted"
    IDENTIFIED = "matched"
    DUPLICATE = "unconfirmed"
    EVIDENCE_CONFLICT = "contradicted"


@dataclass(frozen=True)
class CoreMapping:
    """One file-backed VM range from an ``NT_FILE`` note."""

    path: str
    raw_path: bytes
    vm_start: int
    vm_end: int
    page_offset: int
    page_size: int

    @property
    def file_offset(self) -> int:
        return self.page_offset * self.page_size

    @property
    def length(self) -> int:
        return self.vm_end - self.vm_start

    @property
    def file_end(self) -> int:
        return self.file_offset + self.length

    @property
    def instance_key(self) -> int:
        """A candidate-independent key for one load-bias instance."""

        return self.vm_start - self.file_offset

    @property
    def filename(self) -> str:
        """Alias for the path decoded from the NT_FILE record."""

        return self.path

    def __getitem__(self, name: str) -> Any:
        return getattr(self, name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "vm_start": self.vm_start,
            "vm_end": self.vm_end,
            "page_offset": self.page_offset,
            "page_size": self.page_size,
            "file_offset": self.file_offset,
            "length": self.length,
        }


@dataclass(frozen=True)
class ArchiveCandidate:
    """A candidate original explicitly supplied by the caller.

    ``path`` is the nominal path this archive claims in ``NT_FILE``. It is
    metadata supplied with the archive; it is never resolved by opening that
    path on the filesystem. ``source`` may be a binary stream, an ELFFile, or
    an explicitly supplied filesystem path.
    """

    path: str | None
    source: Any
    label: str | None = None
    index: int = -1

    def __post_init__(self) -> None:
        if self.path is not None:
            object.__setattr__(self, "path", _decode_path(self.path))


@dataclass(frozen=True)
class _BuildId:
    value: str
    note_offset: int
    note_size: int
    raw_note: bytes


@dataclass(frozen=True)
class _CoreLoad:
    offset: int
    vaddr: int
    filesz: int
    memsz: int

    @property
    def file_end(self) -> int:
        return self.offset + self.filesz

    @property
    def vaddr_end(self) -> int:
        return self.vaddr + self.filesz


@dataclass
class CandidateAssessment:
    """Assessment of one candidate against one mapping instance."""

    archive: ArchiveCandidate
    consistent: bool
    compared_bytes: int = 0
    matched_bytes: int = 0
    missing_bytes: int = 0
    first_mismatch: int | None = None
    build_id: str | None = None
    core_build_id: str | None = None
    build_id_match: bool = False
    load_bias: int | None = None
    evidence: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)

    @property
    def has_positive_evidence(self) -> bool:
        return self.build_id_match or self.matched_bytes > 0

    @property
    def status(self) -> str:
        if not self.consistent:
            return "conflict"
        if self.has_positive_evidence:
            return "match"
        return "unconfirmed"

    @property
    def candidate(self) -> ArchiveCandidate:
        return self.archive

    @property
    def candidate_index(self) -> int:
        return self.archive.index

    @property
    def label(self) -> str:
        return self.archive.label or self.archive.path or "<unnamed>"

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "archive": self.label,
            "candidate_index": self.archive.index,
            "status": self.status,
            "consistent": self.consistent,
            "evidence": list(self.evidence),
            "contradictions": list(self.contradictions),
            "compared_bytes": self.compared_bytes,
            "matched_bytes": self.matched_bytes,
            "missing_bytes": self.missing_bytes,
        }
        if self.first_mismatch is not None:
            result["first_mismatch"] = self.first_mismatch
        if self.build_id is not None:
            result["build_id"] = self.build_id
        if self.core_build_id is not None:
            result["core_build_id"] = self.core_build_id
        if self.load_bias is not None:
            result["load_bias"] = self.load_bias
        return result


@dataclass
class InstanceMatch:
    """Match result for one mapping instance (one load bias) of a path."""

    path: str
    mappings: tuple[CoreMapping, ...]
    status: CoreMatchStatus
    candidates: list[CandidateAssessment]
    selected: CandidateAssessment | None = None
    reason: str = ""

    @property
    def vm_start(self) -> int:
        return min(mapping.vm_start for mapping in self.mappings)

    @property
    def vm_end(self) -> int:
        return max(mapping.vm_end for mapping in self.mappings)

    @property
    def file_offset(self) -> int:
        return min(mapping.file_offset for mapping in self.mappings)

    @property
    def selected_archive(self) -> ArchiveCandidate | None:
        return self.selected.archive if self.selected is not None else None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "vm_start": self.vm_start,
            "vm_end": self.vm_end,
            "file_offset": self.file_offset,
            "status": self.status.value,
            "resolution": _RESOLUTION[self.status.value],
            "reason": self.reason,
            "selected": self.selected.label if self.selected is not None else None,
            "selected_index": (
                self.selected.archive.index if self.selected is not None else None
            ),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "mappings": [mapping.to_dict() for mapping in self.mappings],
        }
        return result


@dataclass
class ModuleMatch:
    """Match results for all instances of one ``NT_FILE`` path."""

    path: str
    instances: list[InstanceMatch]
    status: CoreMatchStatus
    candidates: list[CandidateAssessment]
    selected: CandidateAssessment | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        selected = self.selected.label if self.selected is not None else None
        selected_index = (
            self.selected.archive.index if self.selected is not None else None
        )
        if selected is None and all(
            instance.selected is not None for instance in self.instances
        ):
            indices = {
                instance.selected.archive.index
                for instance in self.instances
                if instance.selected is not None
            }
            if len(indices) == 1:
                first = next(
                    instance.selected for instance in self.instances
                    if instance.selected is not None
                )
                if first is not None:
                    selected = first.label
                    selected_index = first.archive.index
        return {
            "path": self.path,
            "selected_index": selected_index,
            "status": self.status.value,
            "resolution": _RESOLUTION[self.status.value],
            "reason": self.reason,
            "selected": selected,
            "selected_archives": [
                {
                    "vm_start": instance.vm_start,
                    "selected": (
                        instance.selected.label
                        if instance.selected is not None else None
                    ),
                    "selected_index": (
                        instance.selected.archive.index
                        if instance.selected is not None else None
                    ),
                }
                for instance in self.instances
            ],
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "instances": [instance.to_dict() for instance in self.instances],
        }

    def __getitem__(self, name: str) -> Any:
        return getattr(self, name)

    @property
    def selected_archive(self) -> ArchiveCandidate | None:
        return self.selected.archive if self.selected is not None else None


@dataclass
class CoreFileMatchManifest:
    """JSON-friendly result returned by :func:`match_core_files`."""

    modules: list[ModuleMatch]
    core_elfclass: int | None = None
    core_machine: str | int | None = None

    @property
    def entries(self) -> list[ModuleMatch]:
        return self.modules

    def to_dict(self) -> dict[str, Any]:
        return {
            "core": {
                "elfclass": self.core_elfclass,
                "machine": self.core_machine,
            },
            "modules": [module.to_dict() for module in self.modules],
            "matches": [module.to_dict() for module in self.modules],
        }

    def to_json(self, **kwargs: Any) -> str:
        import json

        kwargs.setdefault("ensure_ascii", False)
        kwargs.setdefault("indent", 2)
        return json.dumps(self.to_dict(), **kwargs)

    def __iter__(self) -> Iterator[ModuleMatch]:
        return iter(self.modules)

    def __len__(self) -> int:
        return len(self.modules)

    def __getitem__(self, name: str | int) -> Any:
        if isinstance(name, int):
            return self.modules[name]
        if name in {"modules", "entries", "matches"}:
            return self.modules
        if name == "core":
            return {"elfclass": self.core_elfclass, "machine": self.core_machine}
        raise KeyError(name)


class CoreFileMatcher:
    """Reusable matcher for one core file.

    Candidate archives are always supplied explicitly to :meth:`match`; the
    matcher never opens a path merely because it appeared in ``NT_FILE``.
    """

    def __init__(self, core: ELFFile | IO[bytes] | str | os.PathLike[str]) -> None:
        self._stack = ExitStack()
        try:
            self.core = _coerce_elffile(core, self._stack)
            self._core_loads = _core_loads(self.core)
        except BaseException:
            self._stack.close()
            raise

    def __enter__(self) -> CoreFileMatcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._stack.close()

    def get_mappings(self) -> list[CoreMapping]:
        return get_core_file_mappings(self.core)

    def match(
        self,
        archives: Iterable[ArchiveCandidate] | Mapping[str, Iterable[Any]] | None = None,
        *,
        candidates: Iterable[ArchiveCandidate] | Mapping[str, Iterable[Any]] | None = None,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
    ) -> CoreFileMatchManifest:
        supplied = archives if archives is not None else candidates
        if supplied is None:
            raise TypeError("match() requires archives or candidates")
        return _match_with_core(
            self.core,
            self._core_loads,
            supplied,
            chunk_size=chunk_size,
        )


def get_core_file_mappings(
    core: ELFFile | IO[bytes] | str | os.PathLike[str],
) -> list[CoreMapping]:
    """Return all file-backed mappings recorded by ``NT_FILE`` notes.

    The return value preserves duplicate paths and multiple VM ranges. A path
    is decoded with ``surrogateescape`` and its original bytes remain available
    as ``raw_path``.
    """

    with ExitStack() as stack:
        elf = _coerce_elffile(core, stack)
        return _get_core_file_mappings(elf)


iter_core_file_mappings = get_core_file_mappings


def match_core_files(
    core: ELFFile | IO[bytes] | str | os.PathLike[str],
    archives: Iterable[ArchiveCandidate] | Mapping[str, Iterable[Any]] | None = None,
    *,
    candidates: Iterable[ArchiveCandidate] | Mapping[str, Iterable[Any]] | None = None,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> CoreFileMatchManifest:
    """Statically match core mappings against explicitly supplied archives.

    ``archives`` may be an iterable of :class:`ArchiveCandidate`, a mapping
    from a nominal ``NT_FILE`` path to candidate sources, or a sequence of
    ``(path, source)`` pairs. A source can be a binary stream, an
    :class:`~elftools.elf.elffile.ELFFile`, or a path. Filesystem paths are
    opened only because the caller passed them explicitly; paths recorded in
    ``NT_FILE`` are never opened by the matcher.
    """

    with CoreFileMatcher(core) as matcher:
        return matcher.match(
            archives,
            candidates=candidates,
            chunk_size=chunk_size,
        )


def match_core_path(
    core: ELFFile | IO[bytes] | str | os.PathLike[str],
    path: str | bytes,
    archives: Iterable[Any],
    *,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> ModuleMatch | None:
    """Match one path, with each archive explicitly associated to that path."""

    decoded_path = _decode_path(path)
    candidates = [ArchiveCandidate(decoded_path, archive) for archive in archives]
    manifest = match_core_files(core, candidates, chunk_size=chunk_size)
    for module in manifest.modules:
        if _paths_equal(module.path, decoded_path):
            return module
    return None


# Compatibility aliases; they describe the same operation without changing
# the evidence rules.
match_core_modules = match_core_files
match_nt_file_archives = match_core_files


def _match_with_core(
    core: ELFFile,
    core_loads: Sequence[_CoreLoad],
    archives: Iterable[ArchiveCandidate] | Mapping[str, Iterable[Any]],
    *,
    chunk_size: int,
) -> CoreFileMatchManifest:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    mappings = _get_core_file_mappings(core)
    candidates = [
        ArchiveCandidate(candidate.path, candidate.source, candidate.label, index)
        for index, candidate in enumerate(_normalize_candidates(archives, mappings))
    ]

    grouped_candidates: dict[str, list[ArchiveCandidate]] = {}
    for candidate in candidates:
        if candidate.path is None:
            continue
        grouped_candidates.setdefault(candidate.path, []).append(candidate)

    modules: list[ModuleMatch] = []
    for path, path_mappings in _group_mappings_by_path(mappings):
        path_candidates = _candidates_for_path(path, grouped_candidates)
        instances: list[InstanceMatch] = []
        for instance_mappings in _split_instances(path_mappings):
            instances.append(_match_instance(
                core,
                core_loads,
                path,
                instance_mappings,
                path_candidates,
                chunk_size=chunk_size,
            ))
        status, reason = _combine_instance_results(instances, bool(path_candidates))
        selected = _common_selection(instances)
        module_candidates = _combine_candidate_assessments(path_candidates, instances)
        modules.append(ModuleMatch(
            path=path,
            instances=instances,
            status=status,
            candidates=module_candidates,
            selected=selected,
            reason=reason,
        ))

    return CoreFileMatchManifest(
        modules=modules,
        core_elfclass=core.elfclass,
        core_machine=core['e_machine'],
    )


def _get_core_file_mappings(elf: ELFFile) -> list[CoreMapping]:
    result: list[CoreMapping] = []
    seen_notes: set[int] = set()
    note_sources: list[Any] = []
    note_sources.extend(
        segment for segment in elf.iter_segments()
        if isinstance(segment, NoteSegment)
    )
    note_sources.extend(
        section for section in elf.iter_sections()
        if isinstance(section, NoteSection)
    )
    for note_source in note_sources:
        for note in note_source.iter_notes():
            if note["n_type"] != "NT_FILE":
                continue
            note_offset = int(note.get("n_offset", -1))
            if note_offset >= 0:
                if note_offset in seen_notes:
                    continue
                seen_notes.add(note_offset)
            desc = note["n_desc"]
            page_size = int(desc["page_size"])
            if page_size <= 0:
                continue
            entries = desc["Elf_Nt_File_Entry"]
            filenames = desc["filename"]
            for entry, raw_path in zip(entries, filenames):
                raw_name = bytes(raw_path)
                result.append(CoreMapping(
                    path=_decode_path(raw_name),
                    raw_path=raw_name,
                    vm_start=int(entry.vm_start),
                    vm_end=int(entry.vm_end),
                    page_offset=int(entry.page_offset),
                    page_size=page_size,
                ))
    return result


def _group_mappings_by_path(
    mappings: Sequence[CoreMapping],
) -> list[tuple[str, list[CoreMapping]]]:
    groups: dict[str, list[CoreMapping]] = {}
    order: list[str] = []
    for mapping in mappings:
        if mapping.path not in groups:
            groups[mapping.path] = []
            order.append(mapping.path)
        groups[mapping.path].append(mapping)
    return [(path, groups[path]) for path in order]


def _split_instances(mappings: Sequence[CoreMapping]) -> list[tuple[CoreMapping, ...]]:
    """Split mappings of one path by their candidate-independent load bias.

    Linux reports one load bias per mapped instance. A path can occur more than
    once in a process (and multiple processes can contribute to a combined
    core), so mapping ranges from different biases must not be treated as one
    monolithic file.
    """

    groups: dict[int, list[CoreMapping]] = {}
    order: list[int] = []
    for mapping in sorted(mappings, key=lambda item: item.vm_start):
        key = mapping.instance_key
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(mapping)
    return [tuple(groups[key]) for key in order]


def _normalize_candidates(
    archives: Iterable[ArchiveCandidate] | Mapping[str, Iterable[Any]],
    mappings: Sequence[CoreMapping],
) -> list[ArchiveCandidate]:
    if isinstance(archives, Mapping):
        normalized: list[ArchiveCandidate] = []
        for path, sources in archives.items():
            for source in _as_source_iterable(sources):
                normalized.append(_candidate_from_item(path, source))
        return normalized

    raw_candidates = list(archives)
    candidate_objects = [
        _candidate_from_item(None, item) for item in raw_candidates
    ]
    missing_paths = [item for item in candidate_objects if item.path is None]
    if not missing_paths:
        return [item for item in candidate_objects if item.path is not None]

    distinct_paths = list(dict.fromkeys(mapping.path for mapping in mappings))
    if len(distinct_paths) != 1:
        raise ValueError(
            "candidates without a path require exactly one NT_FILE path; "
            "associate every archive with the path it claims explicitly"
        )
    only_path = distinct_paths[0]
    return [
        ArchiveCandidate(only_path, item.source, item.label)
        if item.path is None else item
        for item in candidate_objects
    ]


def _as_source_iterable(sources: Any) -> list[Any]:
    if _looks_like_single_archive(sources):
        return [sources]
    return list(sources)


def _looks_like_single_archive(source: Any) -> bool:
    if isinstance(source, ArchiveCandidate):
        return True
    if isinstance(source, (str, bytes, os.PathLike)):
        return True
    if isinstance(source, ELFFile):
        return True
    if hasattr(source, 'read'):
        return True
    return False


def _candidate_from_item(path: Any, item: Any) -> ArchiveCandidate:
    if isinstance(item, ArchiveCandidate):
        if path is None:
            return item
        return ArchiveCandidate(_decode_path(path), item.source, item.label)
    if isinstance(item, Mapping):
        item_path = path if path is not None else item.get('path')
        source = _first_present(item, ('source', 'stream', 'file', 'archive'))
        label = item.get('label') or item.get('name')
        return ArchiveCandidate(
            _decode_path(item_path) if item_path is not None else None,
            source,
            label,
        )
    if isinstance(item, (tuple, list)) and len(item) == 2:
        first, second = item
        if path is None and _looks_like_path_label(first):
            return ArchiveCandidate(_decode_path(first), second)
        if path is None and _looks_like_path_label(second):
            return ArchiveCandidate(_decode_path(second), first)
    if path is not None:
        return ArchiveCandidate(_decode_path(path), item)
    return ArchiveCandidate(None, item)


def _first_present(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    raise ValueError(f"archive mapping is missing one of {keys!r}")


def _looks_like_path_label(value: Any) -> bool:
    return isinstance(value, (str, bytes, os.PathLike)) and not hasattr(value, 'read')


def _candidates_for_path(
    path: str,
    grouped_candidates: Mapping[str, list[ArchiveCandidate]],
) -> list[ArchiveCandidate]:
    result: list[ArchiveCandidate] = []
    for candidate_path, candidates in grouped_candidates.items():
        if _paths_equal(path, candidate_path):
            result.extend(candidates)
    return result


def _paths_equal(first: str, second: str) -> bool:
    if first == second:
        return True
    return _strip_deleted_suffix(first) == _strip_deleted_suffix(second)


def _strip_deleted_suffix(path: str) -> str:
    if path.endswith(_DELETED_SUFFIX):
        return path[:-len(_DELETED_SUFFIX)]
    return path


def _decode_path(path: str | bytes | os.PathLike[str]) -> str:
    if isinstance(path, str):
        return path
    if isinstance(path, bytes):
        return path.decode('utf-8', 'surrogateescape')
    return os.fsdecode(os.fspath(path))


def _coerce_elffile(
    source: ELFFile | IO[bytes] | str | os.PathLike[str],
    stack: ExitStack,
) -> ELFFile:
    if isinstance(source, ELFFile):
        return source
    if isinstance(source, (bytes, bytearray, memoryview)) and bytes(source[:4]) == b"\x7fELF":
        return ELFFile(io.BytesIO(bytes(source)))
    if isinstance(source, (str, bytes, os.PathLike)):
        stream = stack.enter_context(open(os.fspath(source), 'rb'))
        return ELFFile(stream)
    if hasattr(source, 'read'):
        return ELFFile(source)
    raise TypeError(f"expected ELFFile, binary stream or path, got {type(source)!r}")


def _core_loads(core: ELFFile) -> list[_CoreLoad]:
    loads: list[_CoreLoad] = []
    for segment in core.iter_segments(type='PT_LOAD'):
        loads.append(_CoreLoad(
            offset=int(segment['p_offset']),
            vaddr=int(segment['p_vaddr']),
            filesz=int(segment['p_filesz']),
            memsz=int(segment['p_memsz']),
        ))
    return sorted(loads, key=lambda item: item.vaddr)


def _read_core_virtual(
    core: ELFFile,
    core_loads: Sequence[_CoreLoad],
    vaddr: int,
    size: int,
) -> bytes | None:
    end = vaddr + size
    position = vaddr
    pieces: list[bytes] = []
    while position < end:
        load = next(
            (item for item in core_loads
             if item.vaddr <= position < item.vaddr_end),
            None,
        )
        if load is None:
            return None
        take = min(end, load.vaddr_end) - position
        pieces.append(_read_stream(
            core.stream,
            load.offset + position - load.vaddr,
            take,
        ))
        position += take
    return b"".join(pieces)


def _read_stream(stream: IO[bytes], offset: int, size: int) -> bytes:
    if offset < 0 or size < 0:
        raise ELFParseError("negative file range")
    stream.seek(0, io.SEEK_END)
    length = stream.tell()
    if offset + size > length:
        raise ELFParseError(
            f"file range {offset:#x}+{size:#x} exceeds file size {length:#x}"
        )
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ELFParseError(
            f"expected {size} bytes at offset {offset:#x}, found {len(data)}"
        )
    return data


def _match_instance(
    core: ELFFile,
    core_loads: Sequence[_CoreLoad],
    path: str,
    mappings: Sequence[CoreMapping],
    candidates: Sequence[ArchiveCandidate],
    *,
    chunk_size: int,
) -> InstanceMatch:
    with ExitStack() as stack:
        assessments = [
            _assess_candidate(
                core,
                core_loads,
                mappings,
                candidate,
                stack,
                chunk_size=chunk_size,
            )
            for candidate in candidates
        ]

        if not assessments:
            return InstanceMatch(
                path=path,
                mappings=tuple(mappings),
                status=CoreMatchStatus.MISSING,
                candidates=[],
                reason="no-candidate-archive",
            )

        consistent = [item for item in assessments if item.consistent]
        if not consistent:
            return InstanceMatch(
                path=path,
                mappings=tuple(mappings),
                status=CoreMatchStatus.CONTRADICTED,
                candidates=assessments,
                reason="all-candidates-contradicted",
            )
        if len(consistent) > 1:
            return InstanceMatch(
                path=path,
                mappings=tuple(mappings),
                status=CoreMatchStatus.UNCONFIRMED,
                candidates=assessments,
                reason="multiple-candidates-consistent",
            )

        selected = consistent[0]
        if selected.has_positive_evidence:
            return InstanceMatch(
                path=path,
                mappings=tuple(mappings),
                status=CoreMatchStatus.MATCHED,
                candidates=assessments,
                selected=selected,
                reason="unique-positive-match",
            )
        return InstanceMatch(
            path=path,
            mappings=tuple(mappings),
            status=CoreMatchStatus.UNCONFIRMED,
            candidates=assessments,
            reason="no-conclusive-evidence",
        )


def _assess_candidate(
    core: ELFFile,
    core_loads: Sequence[_CoreLoad],
    mappings: Sequence[CoreMapping],
    candidate: ArchiveCandidate,
    stack: ExitStack,
    *,
    chunk_size: int,
) -> CandidateAssessment:
    try:
        candidate_elf = _coerce_elffile(candidate.source, stack)
    except (ELFError, OSError, TypeError) as error:
        return CandidateAssessment(
            archive=candidate,
            consistent=False,
            contradictions=[f"archive is not a readable ELF file: {error}"],
        )

    assessment = CandidateAssessment(archive=candidate, consistent=True)
    if candidate_elf.elfclass != core.elfclass:
        assessment.contradictions.append(
            f"ELF class {candidate_elf.elfclass} does not match core class "
            f"{core.elfclass}"
        )
    if candidate_elf.little_endian != core.little_endian:
        assessment.contradictions.append("ELF byte order does not match core")
    if candidate_elf['e_machine'] != core['e_machine']:
        assessment.contradictions.append(
            f"machine {candidate_elf['e_machine']!r} does not match core "
            f"{core['e_machine']!r}"
        )
    if candidate_elf['e_type'] not in ('ET_EXEC', 'ET_DYN'):
        assessment.contradictions.append(
            f"archive ELF type {candidate_elf['e_type']!r} is not loadable"
        )

    layout_biases, layout_errors = _mapping_biases(candidate_elf, mappings)
    if layout_errors:
        assessment.contradictions.extend(layout_errors)
    if len(layout_biases) == 1:
        assessment.load_bias = next(iter(layout_biases))
    elif len(layout_biases) > 1:
        assessment.contradictions.append(
            "mapping ranges imply inconsistent load biases: "
            + ", ".join(hex(value) for value in sorted(layout_biases))
        )

    build_id = _find_build_id(candidate_elf)
    if build_id is not None:
        assessment.build_id = build_id.value
        core_build_id = _read_core_build_id(
            core,
            core_loads,
            mappings,
            build_id,
        )
        if core_build_id is not None:
            assessment.core_build_id = core_build_id.value
            assessment.build_id_match = core_build_id.value == build_id.value
            if assessment.build_id_match:
                assessment.evidence.append("build-id-match")
            else:
                assessment.contradictions.append(
                    f"build-id mismatch: archive {build_id.value}, "
                    f"core {core_build_id.value}"
                )

    compared, matched, missing, first_mismatch, content_errors = (
        _compare_mapped_bytes(
            core,
            core_loads,
            candidate_elf,
            mappings,
            chunk_size=chunk_size,
        )
    )
    assessment.compared_bytes = compared
    assessment.matched_bytes = matched
    assessment.missing_bytes = missing
    assessment.first_mismatch = first_mismatch
    if matched:
        assessment.evidence.append("mapped-byte-match")
    if missing:
        assessment.evidence.append("evidence-pages-missing")
    if first_mismatch is not None:
        assessment.contradictions.append(
            f"mapped bytes differ at virtual address {first_mismatch:#x}"
        )
    assessment.contradictions.extend(content_errors)

    assessment.consistent = not assessment.contradictions
    return assessment


def _mapping_biases(
    candidate_elf: ELFFile,
    mappings: Sequence[CoreMapping],
) -> tuple[set[int], list[str]]:
    segments = list(candidate_elf.iter_segments(type='PT_LOAD'))
    biases: set[int] | None = None
    errors: list[str] = []
    file_size = candidate_elf.stream_len

    for mapping in mappings:
        overlapping = []
        for segment in segments:
            seg_start = int(segment['p_offset'])
            seg_end = seg_start + int(segment['p_filesz'])
            if seg_start < mapping.file_end and seg_end > mapping.file_offset:
                if seg_end > file_size:
                    errors.append(
                        f"PT_LOAD at file offset {seg_start:#x} exceeds archive size"
                    )
                    continue
                overlapping.append(segment)
        if not overlapping:
            errors.append(
                f"no PT_LOAD covers mapping file range "
                f"{mapping.file_offset:#x}-{mapping.file_end:#x}"
            )
            continue

        mapping_biases = {
            mapping.vm_start - (
                int(segment['p_vaddr']) + mapping.file_offset - int(segment['p_offset'])
            )
            for segment in overlapping
        }
        if biases is None:
            biases = mapping_biases
        else:
            biases &= mapping_biases
        if not biases:
            errors.append(
                f"mapping at {mapping.vm_start:#x} has no consistent load bias"
            )
            break

    return biases or set(), errors


def _find_build_id(elf: ELFFile) -> _BuildId | None:
    seen_offsets: set[int] = set()
    for section in elf.iter_sections():
        if isinstance(section, NoteSection):
            build_id = _build_id_from_notes(
                elf,
                section.iter_notes(),
                seen_offsets,
                elf.little_endian,
            )
            if build_id is not None:
                return build_id
    for segment in elf.iter_segments():
        if isinstance(segment, NoteSegment):
            build_id = _build_id_from_notes(
                elf,
                segment.iter_notes(),
                seen_offsets,
                elf.little_endian,
            )
            if build_id is not None:
                return build_id
    return None


def _build_id_from_notes(
    elf: ELFFile,
    notes: Iterable[Any],
    seen_offsets: set[int],
    little_endian: bool,
) -> _BuildId | None:
    for note in notes:
        if note['n_type'] != 'NT_GNU_BUILD_ID':
            continue
        offset = int(note['n_offset'])
        if offset in seen_offsets:
            continue
        seen_offsets.add(offset)
        size = int(note['n_size'])
        raw_note = _read_stream(elf.stream, offset, size)
        value = note['n_desc']
        if not isinstance(value, str):
            value = bytes(value).hex()
        return _BuildId(
            value=value.lower(),
            note_offset=offset,
            note_size=size,
            raw_note=raw_note,
        )
    return None


def _read_core_build_id(
    core: ELFFile,
    core_loads: Sequence[_CoreLoad],
    mappings: Sequence[CoreMapping],
    build_id: _BuildId,
) -> _BuildId | None:
    for mapping in mappings:
        if not (
            mapping.file_offset <= build_id.note_offset
            and build_id.note_offset + build_id.note_size <= mapping.file_end
        ):
            continue
        vaddr = mapping.vm_start + (build_id.note_offset - mapping.file_offset)
        raw_note = _read_core_virtual(core, core_loads, vaddr, build_id.note_size)
        if raw_note is None:
            continue
        value = _parse_build_id_note(raw_note, core.little_endian)
        if value is not None:
            return _BuildId(
                value=value,
                note_offset=build_id.note_offset,
                note_size=build_id.note_size,
                raw_note=raw_note,
            )
    return None


def _parse_build_id_note(data: bytes, little_endian: bool = True) -> str | None:
    if len(data) < 12:
        return None
    byteorder = 'little' if little_endian else 'big'
    namesz, descsz, note_type = (
        int.from_bytes(data[0:4], byteorder),
        int.from_bytes(data[4:8], byteorder),
        int.from_bytes(data[8:12], byteorder),
    )
    if note_type != 3 or namesz not in range(1, len(data) - 11):
        return None
    name_end = 12 + namesz
    desc_start = 12 + _align4(namesz)
    desc_end = desc_start + descsz
    if desc_end > len(data):
        return None
    name = data[12:name_end].rstrip(b'\0')
    if name != b'GNU':
        return None
    return data[desc_start:desc_end].hex()


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _compare_mapped_bytes(
    core: ELFFile,
    core_loads: Sequence[_CoreLoad],
    candidate_elf: ELFFile,
    mappings: Sequence[CoreMapping],
    *,
    chunk_size: int,
) -> tuple[int, int, int, int | None, list[str]]:
    compared = 0
    matched = 0
    mismatch: int | None = None
    errors: list[str] = []
    expected_available = 0
    file_size = candidate_elf.stream_len

    for mapping in mappings:
        for load in core_loads:
            start = max(mapping.vm_start, load.vaddr)
            end = min(mapping.vm_end, load.vaddr_end)
            if start >= end:
                continue
            expected_available += end - start
            core_offset = load.offset + (start - load.vaddr)
            file_offset = mapping.file_offset + (start - mapping.vm_start)
            length = end - start

            for position in range(0, length, chunk_size):
                take = min(chunk_size, length - position)
                core_chunk = _read_stream(
                    core.stream,
                    core_offset + position,
                    take,
                )
                archive_offset = file_offset + position
                if archive_offset < file_size:
                    archive_length = min(take, file_size - archive_offset)
                    archive_chunk = _read_stream(
                        candidate_elf.stream,
                        archive_offset,
                        archive_length,
                    )
                else:
                    archive_chunk = b""

                if len(archive_chunk) < take:
                    missing_tail = core_chunk[len(archive_chunk):]
                    if any(missing_tail):
                        mismatch = start + position + len(archive_chunk)
                        errors.append(
                            f"archive ends inside mapped range at "
                            f"virtual address {mismatch:#x}"
                        )
                        break

                if archive_chunk:
                    compared += len(archive_chunk)
                    if archive_chunk == core_chunk[:len(archive_chunk)]:
                        matched += len(archive_chunk)
                    else:
                        mismatch = start + position + _first_difference(
                            archive_chunk,
                            core_chunk[:len(archive_chunk)],
                        )

                if mismatch is not None:
                    break
            if mismatch is not None:
                break
        if mismatch is not None:
            break

    missing = max(0, sum(mapping.length for mapping in mappings) - expected_available)
    return compared, matched, missing, mismatch, errors


def _first_difference(first: bytes, second: bytes) -> int:
    for index, (left, right) in enumerate(zip(first, second)):
        if left != right:
            return index
    return min(len(first), len(second))


def _combine_instance_results(
    instances: Sequence[InstanceMatch],
    has_candidates: bool,
) -> tuple[CoreMatchStatus, str]:
    if not instances:
        return CoreMatchStatus.MISSING, "no-mapping"
    if not has_candidates:
        return CoreMatchStatus.MISSING, "no-candidate-archive"
    statuses = [instance.status for instance in instances]
    if all(status is CoreMatchStatus.MATCHED for status in statuses):
        return CoreMatchStatus.MATCHED, "all-instances-uniquely-matched"
    if any(status is CoreMatchStatus.CONTRADICTED for status in statuses):
        return CoreMatchStatus.CONTRADICTED, "at-least-one-instance-contradicted"
    return CoreMatchStatus.UNCONFIRMED, "at-least-one-instance-unconfirmed"


def _common_selection(instances: Sequence[InstanceMatch]) -> CandidateAssessment | None:
    selected = [
        instance.selected for instance in instances
        if instance.selected is not None
    ]
    if len(selected) != len(instances) or not selected:
        return None
    first = selected[0]
    if all(item.archive.index == first.archive.index for item in selected):
        return first
    return None


def _combine_candidate_assessments(
    candidates: Sequence[ArchiveCandidate],
    instances: Sequence[InstanceMatch],
) -> list[CandidateAssessment]:
    if not candidates:
        return []
    if len(instances) == 1:
        return instances[0].candidates

    by_candidate: dict[int, list[CandidateAssessment]] = {}
    candidate_order: list[int] = []
    for instance in instances:
        for assessment in instance.candidates:
            key = assessment.archive.index
            if key < 0:
                key = id(assessment.archive)
            if key not in by_candidate:
                by_candidate[key] = []
                candidate_order.append(key)
            by_candidate[key].append(assessment)

    combined: list[CandidateAssessment] = []
    for candidate_key in candidate_order:
        items = by_candidate[candidate_key]
        result = CandidateAssessment(
            archive=items[0].archive,
            consistent=all(item.consistent for item in items),
        )
        result.compared_bytes = sum(item.compared_bytes for item in items)
        result.matched_bytes = sum(item.matched_bytes for item in items)
        result.missing_bytes = sum(item.missing_bytes for item in items)
        result.build_id = next(
            (item.build_id for item in items if item.build_id is not None),
            None,
        )
        result.core_build_id = next(
            (item.core_build_id for item in items if item.core_build_id is not None),
            None,
        )
        result.build_id_match = any(item.build_id_match for item in items)
        result.evidence = list(dict.fromkeys(
            evidence for item in items for evidence in item.evidence
        ))
        result.contradictions = list(dict.fromkeys(
            contradiction for item in items for contradiction in item.contradictions
        ))
        combined.append(result)
    return combined


# Singular and archives-oriented spellings are useful at API boundaries.
def match_core_file(
    core: ELFFile | IO[bytes] | str | os.PathLike[str],
    path_or_archives: Any,
    archives: Iterable[Any] | None = None,
    **kwargs: Any,
) -> Any:
    """Match one path or all paths, depending on how archives are supplied."""

    if archives is None:
        return match_core_files(core, path_or_archives, **kwargs)
    return match_core_path(core, path_or_archives, archives, **kwargs)


match_core_archives = match_core_files
match_core_mappings = match_core_files
match_nt_file = match_core_files
parse_nt_file_mappings = get_core_file_mappings
read_core_file_mappings = get_core_file_mappings
CoreFileMapping = CoreMapping
CoreFileMatchReport = CoreFileMatchManifest

__all__ = [
    "ArchiveCandidate",
    "CandidateAssessment",
    "CoreFileMatchManifest",
    "CoreFileMatchReport",
    "CoreFileMapping",
    "CoreFileMatcher",
    "CoreMapping",
    "CoreMatchStatus",
    "InstanceMatch",
    "ModuleMatch",
    "NT_FILE",
    "get_core_file_mappings",
    "iter_core_file_mappings",
    "match_core_archives",
    "match_core_file",
    "match_core_files",
    "match_core_mappings",
    "match_core_modules",
    "match_core_path",
    "match_nt_file",
    "match_nt_file_archives",
    "parse_nt_file_mappings",
    "read_core_file_mappings",
]
