#-------------------------------------------------------------------------------
# elftools: elf/preservation.py
#
# Read-only preservation planning for ELF notes.
#
# This module answers a narrow question: given a set of product claims that a
# third party must still be able to verify independently, and given a budget of
# whole file pages, which pages of the real ELF have to be kept?
#
# Notes can be exposed through two views:
#   * SHT_NOTE sections (the section-header view)
#   * PT_NOTE segments (the program-header view)
#
# The same note bytes may be reachable from both views, from only one view, or
# from more than one section.  A claim pins both the note and the provenance
# (view / owner / offset) that is allowed to prove it.  A byte-identical note at
# a different provenance is never silently substituted for the pinned one.
#
# The planner is strictly read-only: it never writes, truncates or rewrites the
# input, and verifies that the file digest is unchanged when it is done.
#-------------------------------------------------------------------------------
from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from ..common.exceptions import ELFError
from ..common.utils import preserve_stream_pos, stream_read
from .elffile import ELFFile
from .sections import NoteSection
from .segments import NoteSegment

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..construct.lib.container import Container


ViewName = Literal['section', 'segment']
ProvenanceView = Literal['section', 'segment', 'any']

DEFAULT_PAGE_SIZE = 4096


class PreservationError(ELFError):
    """Raised when a preservation request cannot be interpreted or solved."""


def pages_for_range(offset: int, size: int, page_size: int) -> tuple[int, ...]:
    """Return the file pages touched by ``[offset, offset + size)``.

    A note that straddles a page boundary needs every page it touches: a
    partial note body cannot prove anything.  ``size`` must be positive.
    """
    if page_size <= 0:
        raise ValueError('page_size must be positive')
    if offset < 0 or size <= 0:
        raise ValueError('note range must be non-empty and non-negative')
    first = offset // page_size
    last = (offset + size - 1) // page_size
    return tuple(range(first, last + 1))


@dataclass(frozen=True)
class NoteOccurrence:
    """One physical occurrence of one note, read from the real file."""

    view: ViewName
    owner: str
    owner_index: int
    note_name: str | None
    note_type: str | int
    offset: int
    size: int
    n_descsz: int
    desc_sha256: str
    desc_hex: str
    raw_sha256: str

    @property
    def provenance_label(self) -> str:
        return f'{self.view}:{self.owner}'

    def pages(self, page_size: int) -> tuple[int, ...]:
        return pages_for_range(self.offset, self.size, page_size)

    def identity(self) -> tuple[str, int, str, int, int, str]:
        return (self.view, self.owner_index, self.owner, self.offset, self.size,
                self.raw_sha256)


@dataclass(frozen=True)
class NoteSelector:
    """Selects the note payload a claim is about.

    ``offset`` pins one exact physical occurrence.  Without it, every
    occurrence with the same owner/type/descriptor can be considered, but the
    provenance check below still has to pass.
    """

    name: str | None = None
    type: str | int | None = None
    desc_sha256: str | None = None
    desc_hex: str | None = None
    offset: int | None = None

    def matches(self, occurrence: NoteOccurrence) -> bool:
        if self.name is not None and occurrence.note_name != self.name:
            return False
        if self.type is not None and occurrence.note_type != self.type:
            return False
        if self.desc_sha256 is not None:
            if occurrence.desc_sha256 != _normalize_sha256(self.desc_sha256):
                return False
        if self.desc_hex is not None:
            if occurrence.desc_hex != _normalize_hex(self.desc_hex):
                return False
        if self.offset is not None and occurrence.offset != self.offset:
            return False
        return True


@dataclass(frozen=True)
class Provenance:
    """The view and owner that is allowed to prove a claim.

    A claim that requires ``section`` provenance cannot be proven by an
    identical note that only exists in a ``PT_NOTE`` segment, and vice versa.
    """

    view: ProvenanceView = 'any'
    name: str | None = None
    index: int | None = None
    offset: int | None = None

    def matches(self, occurrence: NoteOccurrence) -> bool:
        if self.view != 'any' and occurrence.view != self.view:
            return False
        if self.name is not None and occurrence.owner != self.name:
            return False
        if self.index is not None and occurrence.owner_index != self.index:
            return False
        if self.offset is not None and occurrence.offset != self.offset:
            return False
        return True


@dataclass(frozen=True)
class ClaimSpec:
    """A product claim that a third party must be able to verify."""

    id: str
    description: str
    selector: NoteSelector
    provenance: Provenance = field(default_factory=Provenance)


@dataclass(frozen=True)
class ClaimProof:
    """One independent proof: a concrete note occurrence satisfying a claim."""

    claim_id: str
    occurrence: NoteOccurrence
    pages: tuple[int, ...]

    def identity(self) -> tuple[str, str, int, str, int, int, str]:
        return (self.claim_id, *self.occurrence.identity())

    def physical_identity(self) -> tuple[str, int, int, str]:
        """Identity of the evidence itself, independent of the view used.

        A section and a program header that point at the same bytes are one
        piece of evidence, not two independent proofs.
        """
        return (self.claim_id, self.occurrence.offset, self.occurrence.size,
                self.occurrence.raw_sha256)


@dataclass(frozen=True)
class SourceView:
    """The real bytes the plan was derived from."""

    path: str
    size: int
    sha256: str
    occurrences: tuple[NoteOccurrence, ...]


@dataclass(frozen=True)
class LicenseView:
    """The byte ranges the project permits us to retain.

    A page is retainable only when the whole page lies inside an allowed
    range.  This keeps an unlicensed byte from being smuggled in on a page that
    also happens to contain a note.
    """

    label: str
    ranges: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        previous_end = -1
        for start, end in self.ranges:
            if start < 0 or end < start:
                raise PreservationError(f'Invalid license range {start}:{end}')
            if start < previous_end:
                raise PreservationError('License ranges must be sorted and disjoint')
            previous_end = end

    @classmethod
    def whole_file(cls, file_size: int, label: str = 'whole-file') -> LicenseView:
        if file_size < 0:
            raise PreservationError('file_size must be non-negative')
        return cls(label=label, ranges=((0, file_size),))

    def allows(self, offset: int, size: int) -> bool:
        if offset < 0 or size <= 0:
            return False
        end = offset + size
        return any(start <= offset and end <= stop for start, stop in self.ranges)

    def allowed_pages(self, file_size: int, page_size: int) -> frozenset[int]:
        if page_size <= 0:
            raise ValueError('page_size must be positive')
        result: set[int] = set()
        for start, stop in self.ranges:
            start = max(0, start)
            stop = min(stop, file_size)
            if stop <= start:
                continue
            first_page = start // page_size
            last_page = (stop - 1) // page_size
            for page in range(first_page, last_page + 1):
                page_start = page * page_size
                page_end = min(page_start + page_size, file_size)
                if page_start >= start and page_end <= stop:
                    result.add(page)
        return frozenset(result)


@dataclass(frozen=True)
class PageSlot:
    """A retained page and the proofs it carries."""

    index: int
    start: int
    end: int
    claims: tuple[str, ...]
    proofs: tuple[ClaimProof, ...]


@dataclass(frozen=True)
class CutImpact:
    """What happens if one page is removed from the minimum plan."""

    page: int
    kept_claims: tuple[str, ...]
    lost_claims: tuple[str, ...]
    lost_proofs: tuple[ClaimProof, ...]


@dataclass(frozen=True)
class BudgetOutcome:
    """Best coverage achievable when the page budget is below the minimum."""

    budget: int
    pages: tuple[int, ...]
    kept_claims: tuple[str, ...]
    lost_claims: tuple[str, ...]
    kept_proofs: tuple[ClaimProof, ...]
    lost_proofs: tuple[ClaimProof, ...]
    optimal: bool


@dataclass(frozen=True)
class PreservationPlan:
    """The computed read-only preservation receipt."""

    source: SourceView
    page_size: int
    page_count: int
    license: LicenseView
    licensed_pages: frozenset[int]
    claims: tuple[ClaimSpec, ...]
    proofs_by_claim: Mapping[str, tuple[ClaimProof, ...]]
    unsatisfiable: Mapping[str, str]
    minimum_pages: tuple[int, ...] | None
    optimal: bool
    irreplaceable_pages: tuple[int, ...]
    sole_provider: Mapping[int, tuple[str, ...]]
    page_slots: tuple[PageSlot, ...]
    cut_impacts: tuple[CutImpact, ...]
    budget: int | None
    budget_outcome: BudgetOutcome | None

    @property
    def fully_satisfiable(self) -> bool:
        return not self.unsatisfiable

    def to_dict(self) -> dict[str, Any]:
        return {
            'source': {
                'path': self.source.path,
                'size': self.source.size,
                'sha256': self.source.sha256,
                'page_size': self.page_size,
                'page_count': self.page_count,
            },
            'license': {
                'label': self.license.label,
                'ranges': [list(r) for r in self.license.ranges],
                'licensed_page_count': len(self.licensed_pages),
            },
            'claims': [self._claim_dict(claim) for claim in self.claims],
            'minimum': {
                'page_count': len(self.minimum_pages) if self.minimum_pages is not None else None,
                'pages': [self._page_slot_dict(slot) for slot in self.page_slots],
                'optimal': self.optimal,
            },
            'irreplaceable_pages': [
                {
                    'page': page,
                    'sole_provider_for': list(self.sole_provider.get(page, ())),
                }
                for page in self.irreplaceable_pages
            ],
            'cut_impacts': [self._cut_dict(cut) for cut in self.cut_impacts],
            'budget': None if self.budget_outcome is None else self._budget_dict(),
            'unsatisfiable_claims': dict(self.unsatisfiable),
        }

    def format_receipt(self) -> str:
        lines: list[str] = []
        lines.append('ELF note preservation receipt (read-only)')
        lines.append(f"source : {self.source.path}")
        lines.append(f"bytes  : {self.source.size}")
        lines.append(f"sha256 : {self.source.sha256}")
        lines.append(f"pages  : {self.page_count} x {self.page_size} bytes")
        lines.append(f"license: {self.license.label} "
                     f"({len(self.licensed_pages)} retainable pages)")
        lines.append('')
        lines.append('CLAIMS')
        lines.append('  (candidate occurrences; identical bytes at the same '
                     'offset count as one proof)')
        for claim in self.claims:
            proofs = self.proofs_by_claim.get(claim.id, ())
            if claim.id in self.unsatisfiable:
                lines.append(f"  [{claim.id}] UNSATISFIABLE: {self.unsatisfiable[claim.id]}")
                continue
            lines.append(f"  [{claim.id}] {claim.description}")
            for proof in proofs:
                occ = proof.occurrence
                lines.append(
                    f"      proof {occ.provenance_label} @ {_hex(occ.offset)}"
                    f" size={occ.size} pages={_pages_text(proof.pages)}"
                    f" desc_sha256={occ.desc_sha256[:16]}...")
        lines.append('')
        if self.minimum_pages is None:
            lines.append('MINIMUM FEASIBLE PAGE SET: none (some claims are unsatisfiable)')
        else:
            lines.append(f'MINIMUM FEASIBLE PAGE SET ({len(self.minimum_pages)} pages)')
            for slot in self.page_slots:
                lines.append(
                    f"  page {slot.index} [{_hex(slot.start)}..{_hex(slot.end)}]: "
                    f"{', '.join(slot.claims)}")
            lines.append('')
            lines.append('IRREPLACEABLE PAGES')
            if not self.irreplaceable_pages:
                lines.append('  none: every proof has an alternative page')
            for page in self.irreplaceable_pages:
                providers = self.sole_provider.get(page, ())
                suffix = f": sole provider for {', '.join(providers)}" if providers else ''
                lines.append(f"  page {page}{suffix}")
            lines.append('')
            lines.append('ONE-PAGE CUT (from the minimum set)')
            for cut in self.cut_impacts:
                lost = ', '.join(cut.lost_claims) if cut.lost_claims else 'none'
                lines.append(f"  cut page {cut.page} -> lost claims: {lost}")
                for proof in cut.lost_proofs:
                    occ = proof.occurrence
                    lines.append(
                        f"      lost proof {proof.claim_id}: {occ.provenance_label}"
                        f" @ {_hex(occ.offset)}")
        if self.budget_outcome is not None:
            outcome = self.budget_outcome
            lines.append('')
            lines.append(f'BUDGET {outcome.budget} '
                         f"('optimal'={outcome.optimal})")
            if outcome.pages:
                lines.append(f"  best retained pages: {_pages_text(outcome.pages)}")
            else:
                lines.append('  best retained pages: none')
            lines.append(f"  kept claims: {', '.join(outcome.kept_claims) or 'none'}")
            lines.append(f"  lost claims: {', '.join(outcome.lost_claims) or 'none'}")
            if outcome.lost_proofs:
                lines.append('  lost independent proofs:')
                for proof in outcome.lost_proofs:
                    occ = proof.occurrence
                    lines.append(
                        f"      {proof.claim_id}: {occ.provenance_label}"
                        f" @ {_hex(occ.offset)} pages={_pages_text(proof.pages)}")
            else:
                lines.append('  lost independent proofs: none')
        return '\n'.join(lines)

    def _claim_dict(self, claim: ClaimSpec) -> dict[str, Any]:
        proofs = self.proofs_by_claim.get(claim.id, ())
        return {
            'id': claim.id,
            'description': claim.description,
            'status': 'unsatisfiable' if claim.id in self.unsatisfiable else 'satisfiable',
            'reason': self.unsatisfiable.get(claim.id),
            'proofs': [self._proof_dict(proof) for proof in proofs],
        }

    def _proof_dict(self, proof: ClaimProof) -> dict[str, Any]:
        occ = proof.occurrence
        return {
            'claim_id': proof.claim_id,
            'view': occ.view,
            'owner': occ.owner,
            'owner_index': occ.owner_index,
            'note_name': occ.note_name,
            'note_type': occ.note_type,
            'offset': occ.offset,
            'size': occ.size,
            'pages': list(proof.pages),
            'desc_sha256': occ.desc_sha256,
            'raw_sha256': occ.raw_sha256,
        }

    def _page_slot_dict(self, slot: PageSlot) -> dict[str, Any]:
        return {
            'page': slot.index,
            'start': slot.start,
            'end': slot.end,
            'claims': list(slot.claims),
            'proofs': [self._proof_dict(proof) for proof in slot.proofs],
        }

    def _cut_dict(self, cut: CutImpact) -> dict[str, Any]:
        return {
            'page': cut.page,
            'kept_claims': list(cut.kept_claims),
            'lost_claims': list(cut.lost_claims),
            'lost_proofs': [self._proof_dict(proof) for proof in cut.lost_proofs],
        }

    def _budget_dict(self) -> dict[str, Any]:
        assert self.budget_outcome is not None
        outcome = self.budget_outcome
        return {
            'budget': outcome.budget,
            'pages': list(outcome.pages),
            'kept_claims': list(outcome.kept_claims),
            'lost_claims': list(outcome.lost_claims),
            'kept_proofs': [self._proof_dict(proof) for proof in outcome.kept_proofs],
            'lost_proofs': [self._proof_dict(proof) for proof in outcome.lost_proofs],
            'optimal': outcome.optimal,
        }


@dataclass(frozen=True)
class PreservationRequest:
    """A JSON-friendly request: claims plus an optional license view."""

    claims: tuple[ClaimSpec, ...]
    page_size: int = DEFAULT_PAGE_SIZE
    budget: int | None = None
    license_label: str = 'whole-file'
    license_ranges: tuple[tuple[int, int], ...] | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PreservationRequest:
        raw_claims = data.get('claims')
        if not isinstance(raw_claims, list) or not raw_claims:
            raise PreservationError('Manifest must contain a non-empty "claims" list')
        claims = tuple(_claim_from_mapping(item) for item in raw_claims)
        page_size = int(data.get('page_size', DEFAULT_PAGE_SIZE))
        if page_size <= 0:
            raise PreservationError('page_size must be positive')
        raw_budget = data.get('budget')
        budget = None if raw_budget is None else int(raw_budget)
        if budget is not None and budget < 0:
            raise PreservationError('budget must be non-negative')
        raw_license = data.get('license')
        license_label = 'whole-file'
        license_ranges: tuple[tuple[int, int], ...] | None = None
        if raw_license is not None:
            if not isinstance(raw_license, Mapping):
                raise PreservationError('license must be an object')
            license_label = str(raw_license.get('label', 'project-license'))
            raw_ranges = raw_license.get('ranges')
            if raw_ranges is not None:
                if not isinstance(raw_ranges, list):
                    raise PreservationError('license.ranges must be a list of [start, end] pairs')
                parsed: list[tuple[int, int]] = []
                for item in raw_ranges:
                    if not isinstance(item, (list, tuple)) or len(item) != 2:
                        raise PreservationError('license range must be [start, end]')
                    parsed.append((int(item[0]), int(item[1])))
                license_ranges = tuple(parsed)
        return cls(claims=claims, page_size=page_size, budget=budget,
                   license_label=license_label, license_ranges=license_ranges)

    @classmethod
    def from_json(cls, path: str | os.PathLike[str]) -> PreservationRequest:
        with open(path, encoding='utf-8') as manifest:
            data = json.load(manifest)
        if not isinstance(data, Mapping):
            raise PreservationError('Manifest root must be a JSON object')
        return cls.from_mapping(data)

    def plan(self, source_path: str | os.PathLike[str]) -> PreservationPlan:
        license_view = None
        if self.license_ranges is not None:
            license_view = LicenseView(self.license_label, self.license_ranges)
        return plan_preservation(
            source_path,
            self.claims,
            page_size=self.page_size,
            license_view=license_view,
            budget=self.budget,
        )


def plan_preservation(
    source_path: str | os.PathLike[str],
    claims: Sequence[ClaimSpec],
    *,
    page_size: int = DEFAULT_PAGE_SIZE,
    license_view: LicenseView | None = None,
    budget: int | None = None,
) -> PreservationPlan:
    """Compute a read-only page-preservation plan for ``source_path``.

    The input file is opened read-only.  Its SHA-256 is taken before and after
    planning; if the digest changed, planning fails instead of returning a
    receipt for bytes that no longer exist.
    """
    if page_size <= 0:
        raise PreservationError('page_size must be positive')
    if not claims:
        raise PreservationError('At least one claim is required')
    claim_ids = [claim.id for claim in claims]
    if len(set(claim_ids)) != len(claim_ids):
        raise PreservationError('Claim ids must be unique')
    if budget is not None and budget < 0:
        raise PreservationError('budget must be non-negative')

    path = os.fspath(source_path)
    display_path = os.fsdecode(path)
    digest_before = _file_sha256(path)
    with ELFFile.load_from_path(path) as elf:
        file_size = elf.stream_len
        occurrences = tuple(_scan_occurrences(elf))
    digest_after = _file_sha256(path)
    if digest_before != digest_after:
        raise PreservationError(
            'Read-only preservation planning changed the input file digest')

    page_count = (file_size + page_size - 1) // page_size
    if license_view is None:
        license_view = LicenseView.whole_file(file_size)
    licensed_pages = license_view.allowed_pages(file_size, page_size)

    proofs_by_claim: dict[str, tuple[ClaimProof, ...]] = {}
    unsatisfiable: dict[str, str] = {}
    for claim in claims:
        matched = [occ for occ in occurrences
                   if claim.selector.matches(occ) and claim.provenance.matches(occ)]
        if not matched:
            proofs_by_claim[claim.id] = ()
            unsatisfiable[claim.id] = (
                'no real note occurrence matches the specified note and provenance')
            continue
        proofs: list[ClaimProof] = []
        blocked = 0
        for occ in matched:
            pages = occ.pages(page_size)
            if not license_view.allows(occ.offset, occ.size) or not all(
                    page in licensed_pages for page in pages):
                blocked += 1
                continue
            proofs.append(ClaimProof(claim.id, occ, pages))
        if not proofs:
            proofs_by_claim[claim.id] = ()
            unsatisfiable[claim.id] = (
                f'all {blocked} matching occurrence(s) fall outside the '
                f'project-licensed pages ({license_view.label})')
            continue
        proofs_by_claim[claim.id] = tuple(proofs)

    satisfiable_ids = [claim.id for claim in claims if claim.id not in unsatisfiable]
    option_sets = [_page_options(proofs_by_claim[claim_id]) for claim_id in satisfiable_ids]
    if option_sets:
        minimum, optimal = _minimum_union(option_sets)
    else:
        minimum, optimal = None, True

    minimum_pages = None if minimum is None else tuple(sorted(minimum))
    irreplaceable_pages: tuple[int, ...] = ()
    sole_provider: dict[int, tuple[str, ...]] = {}
    page_slots: tuple[PageSlot, ...] = ()
    cut_impacts: tuple[CutImpact, ...] = ()
    budget_outcome: BudgetOutcome | None = None

    if minimum_pages is not None:
        minimum_set = frozenset(minimum_pages)
        essential: list[int] = []
        for page in minimum_pages:
            alternative = _minimum_union(option_sets, banned=frozenset({page}))[0]
            if alternative is None or len(alternative) > len(minimum_set):
                essential.append(page)
        irreplaceable_pages = tuple(essential)

        provider_map: dict[int, list[str]] = {}
        for claim_id in satisfiable_ids:
            proofs = proofs_by_claim[claim_id]
            if not proofs:
                continue
            common = set(proofs[0].pages)
            for proof in proofs[1:]:
                common.intersection_update(proof.pages)
            for page in common:
                provider_map.setdefault(page, []).append(claim_id)
        sole_provider = {page: tuple(ids) for page, ids in sorted(provider_map.items())}

        page_slots = tuple(
            _page_slot(page, minimum_set, page_size, file_size, proofs_by_claim,
                       satisfiable_ids)
            for page in minimum_pages
        )

        cut_impacts = tuple(
            _cut_impact(page, minimum_set, proofs_by_claim, satisfiable_ids)
            for page in minimum_pages
        )

        if budget is not None:
            budget_outcome = _budget_outcome(
                budget, minimum_set, option_sets, proofs_by_claim,
                satisfiable_ids)

    source = SourceView(
        path=display_path,
        size=file_size,
        sha256=digest_before,
        occurrences=occurrences,
    )
    return PreservationPlan(
        source=source,
        page_size=page_size,
        page_count=page_count,
        license=license_view,
        licensed_pages=licensed_pages,
        claims=tuple(claims),
        proofs_by_claim=proofs_by_claim,
        unsatisfiable=unsatisfiable,
        minimum_pages=minimum_pages,
        optimal=optimal,
        irreplaceable_pages=irreplaceable_pages,
        sole_provider=sole_provider,
        page_slots=page_slots,
        cut_impacts=cut_impacts,
        budget=budget,
        budget_outcome=budget_outcome,
    )


def _scan_occurrences(elffile: ELFFile) -> Iterator[NoteOccurrence]:
    stream = elffile.stream
    with preserve_stream_pos(stream):
        for index, section in enumerate(elffile.iter_sections()):
            if not isinstance(section, NoteSection):
                continue
            for note in section.iter_notes():
                yield _make_occurrence('section', section.name, index, note, stream)
        for index, segment in enumerate(elffile.iter_segments()):
            if not isinstance(segment, NoteSegment):
                continue
            for note in segment.iter_notes():
                yield _make_occurrence('segment', f'PT_NOTE#{index}', index, note,
                                       stream)


def _make_occurrence(
    view: ViewName,
    owner: str,
    owner_index: int,
    note: Container,
    stream: Any,
) -> NoteOccurrence:
    offset = int(note['n_offset'])
    size = int(note['n_size'])
    raw = stream_read(stream, offset, size)
    desc = bytes(note['n_descdata'])
    return NoteOccurrence(
        view=view,
        owner=owner,
        owner_index=owner_index,
        note_name=note['n_name'],
        note_type=note['n_type'],
        offset=offset,
        size=size,
        n_descsz=int(note['n_descsz']),
        desc_sha256=hashlib.sha256(desc).hexdigest(),
        desc_hex=desc.hex(),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _file_sha256(path: str | bytes) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_sha256(value: str) -> str:
    return value.strip().lower()


def _normalize_hex(value: str) -> str:
    return value.strip().lower().removeprefix('0x').replace(' ', '').replace(':', '')


def _page_options(proofs: Iterable[ClaimProof]) -> list[frozenset[int]]:
    unique: dict[tuple[int, ...], None] = {}
    for proof in proofs:
        unique.setdefault(proof.pages, None)
    return [frozenset(pages) for pages in sorted(unique, key=lambda p: (len(p), p))]


def _unique_proofs(proofs: Iterable[ClaimProof]) -> tuple[ClaimProof, ...]:
    seen: set[tuple[str, int, int, str]] = set()
    result: list[ClaimProof] = []
    for proof in proofs:
        key = proof.physical_identity()
        if key not in seen:
            seen.add(key)
            result.append(proof)
    return tuple(result)


def _minimum_union(
    option_sets: Sequence[Sequence[frozenset[int]]],
    *,
    banned: frozenset[int] = frozenset(),
) -> tuple[frozenset[int] | None, bool]:
    """Choose one option per claim, minimizing the union of their pages.

    Returns ``(pages, optimal)``.  ``optimal`` is False if the search had to be
    cut short, in which case the returned pages are a greedy upper bound.
    """
    prepared: list[list[frozenset[int]]] = []
    for options in option_sets:
        usable = sorted(
            {option for option in options if not (option & banned)},
            key=lambda p: (len(p), tuple(sorted(p))))
        if not usable:
            return None, True
        prepared.append(usable)

    order = sorted(range(len(prepared)), key=lambda i: (len(prepared[i]), i))
    best: frozenset[int] | None = None
    best_key: tuple[int, tuple[int, ...]] | None = None
    nodes = 0
    node_limit = 500_000
    truncated = False

    def search(depth: int, union: frozenset[int]) -> None:
        nonlocal best, best_key, nodes, truncated
        if truncated:
            return
        nodes += 1
        if nodes > node_limit:
            truncated = True
            return
        if best is not None and len(union) > len(best):
            return
        if depth == len(order):
            key = (len(union), tuple(sorted(union)))
            if best_key is None or key < best_key:
                best = union
                best_key = key
            return
        for option in prepared[order[depth]]:
            combined = union | option
            if best is not None and len(combined) > len(best):
                continue
            search(depth + 1, combined)

    search(0, frozenset())
    if truncated:
        return _greedy_union(prepared, order), False
    return best, True


def _greedy_union(
    prepared: Sequence[Sequence[frozenset[int]]],
    order: Sequence[int],
) -> frozenset[int]:
    union: frozenset[int] = frozenset()
    for index in order:
        options = prepared[index]
        best = min(options, key=lambda option: (len(option - union),
                                                len(option | union),
                                                tuple(sorted(option))))
        union = union | best
    return union


def _best_coverage(
    option_sets: Sequence[Sequence[frozenset[int]]],
    proofs_by_claim: Mapping[str, tuple[ClaimProof, ...]],
    claim_ids: Sequence[str],
    budget: int,
) -> tuple[frozenset[int], tuple[str, ...], bool]:
    """Maximize kept claims, then independent proofs, within ``budget`` pages."""
    if budget <= 0:
        return frozenset(), (), True
    order = sorted(range(len(option_sets)), key=lambda i: (len(option_sets[i]), i))
    best_pages: frozenset[int] = frozenset()
    best_kept: tuple[str, ...] = ()
    best_key: tuple[int, int, int, tuple[int, ...]] | None = None
    nodes = 0
    node_limit = 500_000
    truncated = False

    def key_for(pages: frozenset[int], kept: list[str]) -> tuple[int, int, int, tuple[int, ...]]:
        proof_count = sum(
            1 for claim_id in claim_ids
            for proof in _unique_proofs(proofs_by_claim[claim_id])
            if set(proof.pages) <= pages)
        return (len(kept), proof_count, -len(pages), tuple(-p for p in sorted(pages)))

    def search(depth: int, union: frozenset[int], kept: list[str]) -> None:
        nonlocal best_pages, best_kept, best_key, nodes, truncated
        if truncated:
            return
        nodes += 1
        if nodes > node_limit:
            truncated = True
            return
        if len(union) > budget:
            return
        if best_key is not None and len(kept) + (len(order) - depth) < best_key[0]:
            return
        if depth == len(order):
            key = key_for(union, kept)
            if best_key is None or key > best_key:
                best_key = key
                best_pages = union
                best_kept = tuple(sorted(kept))
            return
        claim_index = order[depth]
        claim_id = claim_ids[claim_index]
        for option in option_sets[claim_index]:
            if len(union | option) > budget:
                continue
            search(depth + 1, union | option, kept + [claim_id])
        search(depth + 1, union, kept)

    search(0, frozenset(), [])
    return best_pages, best_kept, not truncated


def _page_slot(
    page: int,
    minimum_set: frozenset[int],
    page_size: int,
    file_size: int,
    proofs_by_claim: Mapping[str, tuple[ClaimProof, ...]],
    claim_ids: Sequence[str],
) -> PageSlot:
    proofs = _unique_proofs(
        proof for claim_id in claim_ids for proof in proofs_by_claim[claim_id]
        if set(proof.pages) <= minimum_set and page in proof.pages)
    claim_names = tuple(sorted({proof.claim_id for proof in proofs}))
    return PageSlot(
        index=page,
        start=page * page_size,
        end=min((page + 1) * page_size, file_size),
        claims=claim_names,
        proofs=proofs,
    )


def _cut_impact(
    page: int,
    minimum_set: frozenset[int],
    proofs_by_claim: Mapping[str, tuple[ClaimProof, ...]],
    claim_ids: Sequence[str],
) -> CutImpact:
    remaining = minimum_set - {page}
    kept: list[str] = []
    lost: list[str] = []
    lost_proofs: list[ClaimProof] = []
    for claim_id in claim_ids:
        before = [proof for proof in _unique_proofs(proofs_by_claim[claim_id])
                  if set(proof.pages) <= minimum_set]
        after = [proof for proof in before if set(proof.pages) <= remaining]
        if after:
            kept.append(claim_id)
        else:
            lost.append(claim_id)
        lost_proofs.extend(proof for proof in before if proof not in after)
    return CutImpact(
        page=page,
        kept_claims=tuple(sorted(kept)),
        lost_claims=tuple(sorted(lost)),
        lost_proofs=tuple(lost_proofs),
    )


def _budget_outcome(
    budget: int,
    minimum_set: frozenset[int],
    option_sets: Sequence[Sequence[frozenset[int]]],
    proofs_by_claim: Mapping[str, tuple[ClaimProof, ...]],
    claim_ids: Sequence[str],
) -> BudgetOutcome:
    minimum_proofs = _unique_proofs(
        proof for claim_id in claim_ids for proof in proofs_by_claim[claim_id]
        if set(proof.pages) <= minimum_set)
    if budget >= len(minimum_set):
        return BudgetOutcome(
            budget=budget,
            pages=tuple(sorted(minimum_set)),
            kept_claims=tuple(sorted(claim_ids)),
            lost_claims=(),
            kept_proofs=minimum_proofs,
            lost_proofs=(),
            optimal=True,
        )

    pages, kept, optimal = _best_coverage(option_sets, proofs_by_claim, claim_ids,
                                          budget)
    kept_proofs = _unique_proofs(
        proof for claim_id in claim_ids for proof in proofs_by_claim[claim_id]
        if set(proof.pages) <= pages)
    kept_ids = set(kept)
    kept_physical = {proof.physical_identity() for proof in kept_proofs}
    lost_proofs = tuple(proof for proof in minimum_proofs
                        if proof.physical_identity() not in kept_physical)
    return BudgetOutcome(
        budget=budget,
        pages=tuple(sorted(pages)),
        kept_claims=tuple(sorted(kept)),
        lost_claims=tuple(sorted(set(claim_ids) - kept_ids)),
        kept_proofs=kept_proofs,
        lost_proofs=lost_proofs,
        optimal=optimal,
    )


def _claim_from_mapping(data: Any) -> ClaimSpec:
    if not isinstance(data, Mapping):
        raise PreservationError('Each claim must be an object')
    claim_id = data.get('id')
    if not isinstance(claim_id, str) or not claim_id:
        raise PreservationError('Each claim needs a non-empty string "id"')
    raw_match = data.get('match')
    if not isinstance(raw_match, Mapping):
        raise PreservationError(f'Claim {claim_id!r} needs a "match" object')
    raw_provenance = data.get('provenance', {})
    if not isinstance(raw_provenance, Mapping):
        raise PreservationError(f'Claim {claim_id!r} provenance must be an object')
    view = raw_provenance.get('view', 'any')
    if view not in ('section', 'segment', 'any'):
        raise PreservationError(
            f'Claim {claim_id!r} has invalid provenance view {view!r}')
    note_type = raw_match.get('type')
    if isinstance(note_type, bool) or not isinstance(note_type, (str, int, type(None))):
        raise PreservationError(f'Claim {claim_id!r} note type must be a string or int')
    desc_sha256 = raw_match.get('desc_sha256')
    if desc_sha256 is not None and not isinstance(desc_sha256, str):
        raise PreservationError(f'Claim {claim_id!r} desc_sha256 must be a string')
    desc_hex = raw_match.get('desc_hex')
    if desc_hex is not None and not isinstance(desc_hex, str):
        raise PreservationError(f'Claim {claim_id!r} desc_hex must be a string')
    match_offset = raw_match.get('offset')
    if match_offset is not None and (isinstance(match_offset, bool)
                                     or not isinstance(match_offset, int)):
        raise PreservationError(f'Claim {claim_id!r} match offset must be an int')
    provenance_offset = raw_provenance.get('offset')
    if provenance_offset is not None and (isinstance(provenance_offset, bool)
                                          or not isinstance(provenance_offset, int)):
        raise PreservationError(
            f'Claim {claim_id!r} provenance offset must be an int')
    provenance_index = raw_provenance.get('index')
    if provenance_index is not None and (isinstance(provenance_index, bool)
                                         or not isinstance(provenance_index, int)):
        raise PreservationError(
            f'Claim {claim_id!r} provenance index must be an int')
    provenance_name = raw_provenance.get('name')
    if provenance_name is not None and not isinstance(provenance_name, str):
        raise PreservationError(
            f'Claim {claim_id!r} provenance name must be a string')
    return ClaimSpec(
        id=claim_id,
        description=str(data.get('description', '')),
        selector=NoteSelector(
            name=raw_match.get('name'),
            type=note_type,
            desc_sha256=desc_sha256,
            desc_hex=desc_hex,
            offset=match_offset,
        ),
        provenance=Provenance(
            view=view,
            name=provenance_name,
            index=provenance_index,
            offset=provenance_offset,
        ),
    )


def _hex(value: int) -> str:
    return f'0x{value:x}'


def _pages_text(pages: Sequence[int]) -> str:
    return '[' + ', '.join(str(page) for page in pages) + ']'
