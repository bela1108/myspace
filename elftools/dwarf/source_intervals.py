#-------------------------------------------------------------------------------
# elftools: dwarf/source_intervals.py
#
# Build address-to-source intervals from DWARF line tables and compare the
# testimony of two debug files for the same module.
#
# A line-table sequence is a set of rows terminated by an end_sequence row.
# The address of a row applies to the half-open interval beginning at that row
# and ending at the next row in the same sequence, or at the end_sequence
# address.  The end marker is therefore part of the interval boundary, not a
# source line of its own.  Gaps between sequences remain gaps: they are never
# filled by extending the last row of the preceding sequence.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import bisect
import heapq
import os
import posixpath
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import IO, TYPE_CHECKING, Any, Iterable, Sequence

from ..common.exceptions import DWARFError
from ..common.utils import bytes2str
from ..elf.elffile import ELFFile
from .descriptions import describe_form_class
from .ranges import BaseAddressEntry

if TYPE_CHECKING:
    from collections.abc import Callable

    from .compileunit import CompileUnit
    from .dwarfinfo import DWARFInfo
    from .lineprogram import LineProgram, LineProgramEntry, LineState


Attribution = str
"""How source locations are compared: 'repo', 'file' or 'location'."""

RepoRoots = Mapping[str, str] | Sequence[tuple[str, str]]
"""Prefix-to-repository-label mapping, or a sequence of such pairs."""


@dataclass(frozen=True, order=True)
class AddressInterval:
    """A non-empty half-open address interval [begin, end)."""

    begin: int
    end: int

    def __post_init__(self) -> None:
        if self.begin < 0:
            raise ValueError(f'negative address: {self.begin:#x}')
        if self.begin >= self.end:
            raise ValueError(
                f'empty address interval: [{self.begin:#x}, {self.end:#x})')

    def contains(self, address: int) -> bool:
        return self.begin <= address < self.end

    def intersection(self, other: AddressInterval) -> AddressInterval | None:
        begin = max(self.begin, other.begin)
        end = min(self.end, other.end)
        return AddressInterval(begin, end) if begin < end else None


@dataclass(frozen=True)
class SourceLocation:
    """A source position from one row of a DWARF line table."""

    repo: str
    file: str
    line: int | None
    column: int | None
    cu_offset: int
    address: int

    def attribution_key(self, attribution: Attribution = 'repo') -> tuple[Any, ...]:
        """Return the part of the location used for equality checks."""
        if attribution == 'repo':
            return (self.repo,)
        if attribution == 'file':
            return (self.repo, self.file)
        if attribution == 'location':
            return (self.repo, self.file, self.line, self.column)
        raise ValueError(f'unknown attribution mode: {attribution!r}')


@dataclass(frozen=True)
class LineInterval:
    """A line-table row's address range and the source position it names."""

    begin: int
    end: int
    location: SourceLocation
    sequence: int


@dataclass(frozen=True)
class LineTableHole:
    """A gap between two covered row ranges in one DWARF line table.

    Both sides of the hole carry a source position.  Holes at the leading or
    trailing edge of a CU extent have only one side and are deliberately not
    represented here; they are simply uncovered addresses.
    """

    begin: int
    end: int
    cu_offset: int
    before: SourceLocation
    after: SourceLocation


@dataclass(frozen=True)
class CompileUnitExtent:
    """The code address ranges declared by one compile unit."""

    cu_offset: int
    ranges: tuple[AddressInterval, ...]


@dataclass
class SourceIndex:
    """All line-table evidence read from one ELF/DWARF file.

    ``intervals`` contains one entry per non-empty row range.  ``coverage`` is
    the disjoint overlay used for address lookup; later rows win where two
    sequences overlap.  ``holes`` only contains internal gaps that have a
    source position on both sides.
    """

    filename: str
    intervals: tuple[LineInterval, ...] = ()
    holes: tuple[LineTableHole, ...] = ()
    cu_extents: tuple[CompileUnitExtent, ...] = ()
    address_bias: int = 0
    diagnostics: tuple[str, ...] = ()
    coverage: tuple[LineInterval, ...] = field(init=False, repr=False)
    hole_ranges: tuple[AddressInterval, ...] = field(init=False, repr=False)
    _coverage_starts: tuple[int, ...] = field(init=False, repr=False)
    _hole_starts: tuple[int, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.coverage = _build_coverage(self.intervals)
        self._coverage_starts = tuple(i.begin for i in self.coverage)
        self.hole_ranges = _merge_intervals(
            AddressInterval(h.begin, h.end) for h in self.holes)
        self._hole_starts = tuple(h.begin for h in self.hole_ranges)

    def location_at(self, address: int) -> SourceLocation | None:
        """Return the source row covering ``address``, or None."""
        index = bisect.bisect_right(self._coverage_starts, address) - 1
        if index < 0:
            return None
        interval = self.coverage[index]
        return interval.location if interval.begin <= address < interval.end else None

    def has_hole_at(self, address: int) -> bool:
        """Whether a legal two-sided line-table hole covers ``address``."""
        index = bisect.bisect_right(self._hole_starts, address) - 1
        return (index >= 0 and
                self.hole_ranges[index].begin <= address < self.hole_ranges[index].end)

    def code_ranges(self) -> tuple[AddressInterval, ...]:
        """Return the union of declared CU ranges, or covered ranges as fallback."""
        declared = _merge_intervals(
            r for extent in self.cu_extents for r in extent.ranges)
        if declared:
            return declared
        return _merge_intervals(
            AddressInterval(i.begin, i.end) for i in self.intervals)


@dataclass(frozen=True)
class WitnessSegment:
    """One maximal address range with a stable comparison result."""

    begin: int
    end: int
    status: str  # 'unchanged', 'changed' or 'unconfirmed'
    left: SourceLocation | None
    right: SourceLocation | None
    left_at_end: SourceLocation | None = None
    right_at_end: SourceLocation | None = None
    hole_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class HoleEvidence:
    """A clipped, per-source legal line-table hole."""

    source: str  # 'left' or 'right'
    begin: int
    end: int
    cu_offset: int
    before: SourceLocation
    after: SourceLocation


@dataclass(frozen=True)
class IntervalReport:
    """Result of comparing two source indices."""

    left: SourceIndex
    right: SourceIndex
    load_intervals: tuple[AddressInterval, ...]
    segments: tuple[WitnessSegment, ...]
    holes: tuple[HoleEvidence, ...]
    attribution: Attribution = 'repo'

    @property
    def unchanged(self) -> tuple[WitnessSegment, ...]:
        return tuple(s for s in self.segments if s.status == 'unchanged')

    @property
    def changed(self) -> tuple[WitnessSegment, ...]:
        return tuple(s for s in self.segments if s.status == 'changed')

    @property
    def unconfirmed(self) -> tuple[WitnessSegment, ...]:
        return tuple(s for s in self.segments if s.status == 'unconfirmed')


def read_source_index(
    source: str | os.PathLike[str] | IO[bytes] | ELFFile,
    *,
    repo_roots: RepoRoots = (),
    address_bias: int = 0,
) -> SourceIndex:
    """Read one ELF/DWARF source's line table into a SourceIndex.

    ``repo_roots`` is a sequence of ``(path_prefix, repository_label)`` pairs.
    The longest matching prefix decides the repository label.  If no prefix
    matches, the CU's DW_AT_comp_dir is used as the label, which keeps the
    testimony literal instead of silently treating different build roots as
    the same repository.

    ``address_bias`` is added to every DWARF address.  It is useful when the
    caller's load interval is a runtime interval and the debug file records
    link-time addresses.
    """
    if isinstance(source, ELFFile):
        return _read_elffile(
            source, _source_name(source), repo_roots, address_bias)

    if isinstance(source, (str, os.PathLike)):
        with open(source, 'rb') as stream:
            elffile = ELFFile(stream)
            return _read_elffile(
                elffile, os.fspath(source), repo_roots, address_bias)

    stream = source
    name = str(getattr(stream, 'name', '<stream>'))
    elffile = ELFFile(stream)  # type: ignore[arg-type]
    return _read_elffile(elffile, name, repo_roots, address_bias)


def compare_witnesses(
    left: SourceIndex,
    right: SourceIndex,
    load_intervals: Sequence[AddressInterval | tuple[int, int]] | None = None,
    *,
    attribution: Attribution = 'repo',
) -> IntervalReport:
    """Compare two source indices over the caller-provided load intervals.

    Addresses in ``load_intervals`` are in the same address space as the two
    indices (apply ``address_bias`` when reading them if necessary).  When no
    load interval is supplied, one interval spanning all declared CU code is
    used, which keeps gaps between CUs visible as unconfirmed ranges.

    A segment is ``unchanged`` when both sources name the same attribution,
    ``changed`` when both name different attributions or only one source names
    one, and ``unconfirmed`` when neither source has a row for the address.
    Internal line-table holes are also returned separately in ``holes``.
    """
    if attribution not in ('repo', 'file', 'location'):
        raise ValueError(f'unknown attribution mode: {attribution!r}')

    loads = _normalise_load_intervals(load_intervals, left, right)
    if not loads:
        return IntervalReport(left, right, (), (), (), attribution)

    boundaries = _boundaries(left, right, loads)
    raw: list[WitnessSegment] = []
    load_index = 0
    for begin, end in zip(boundaries, boundaries[1:]):
        if begin >= end:
            continue
        while load_index < len(loads) and loads[load_index].end <= begin:
            load_index += 1
        if load_index >= len(loads):
            break
        if not (loads[load_index].begin <= begin and end <= loads[load_index].end):
            continue

        left_loc = left.location_at(begin)
        right_loc = right.location_at(begin)
        hole_sources = tuple(
            name for name, index in (('left', left), ('right', right))
            if index.has_hole_at(begin))

        if left_loc is not None and right_loc is not None:
            status = ('unchanged'
                      if left_loc.attribution_key(attribution) ==
                         right_loc.attribution_key(attribution)
                      else 'changed')
        elif left_loc is not None or right_loc is not None:
            status = 'changed'
        else:
            status = 'unconfirmed'

        left_end = left.location_at(end - 1)
        right_end = right.location_at(end - 1)
        candidate = WitnessSegment(
            begin, end, status, left_loc, right_loc,
            left_end, right_end, hole_sources)

        if raw and _can_merge(raw[-1], candidate, attribution):
            previous = raw.pop()
            candidate = replace(
                candidate,
                begin=previous.begin,
                left=previous.left,
                right=previous.right,
                left_at_end=candidate.left_at_end,
                right_at_end=candidate.right_at_end)
        raw.append(candidate)

    holes = _clipped_holes(left, right, loads)
    return IntervalReport(
        left, right, loads, tuple(raw), holes, attribution)


# A descriptive alias for callers that think of the operation as a review of
# interval testimony rather than a comparison of two indices.
compare_sources = compare_witnesses


def report_to_dict(report: IntervalReport) -> dict[str, Any]:
    """Convert a report to a JSON-friendly structure with hex addresses."""
    return {
        'left': report.left.filename,
        'right': report.right.filename,
        'attribution': report.attribution,
        'load_intervals': [_interval_to_dict(r) for r in report.load_intervals],
        'segments': {
            'unchanged': [_segment_to_dict(s) for s in report.unchanged],
            'changed': [_segment_to_dict(s) for s in report.changed],
            'unconfirmed': [_segment_to_dict(s) for s in report.unconfirmed],
        },
        'holes': [{
            'source': hole.source,
            'begin': hex(hole.begin),
            'end': hex(hole.end),
            'cu_offset': hex(hole.cu_offset),
            'before': _location_to_dict(hole.before),
            'after': _location_to_dict(hole.after),
        } for hole in report.holes],
        'diagnostics': {
            'left': list(report.left.diagnostics),
            'right': list(report.right.diagnostics),
        },
    }


def format_report(report: IntervalReport) -> str:
    """Render a report as stable, human-readable text."""
    lines = [
        'Interval witness',
        f'  left:        {report.left.filename}',
        f'  right:       {report.right.filename}',
        f'  attribution: {report.attribution}',
    ]
    for interval in report.load_intervals:
        lines.append(f'  load:        [{interval.begin:#x}, {interval.end:#x})')

    for title, segments in (
        ('Unchanged', report.unchanged),
        ('Changed', report.changed),
        ('Unconfirmed by both', report.unconfirmed),
    ):
        lines.append('')
        lines.append(f'{title} ({len(segments)} segments)')
        if not segments:
            lines.append('  (none)')
            continue
        for segment in segments:
            suffix = ''
            if segment.hole_sources:
                suffix = '  hole=' + ','.join(segment.hole_sources)
            lines.append(
                f'  [{segment.begin:#x}, {segment.end:#x})  '
                f'left={_format_location(segment.left)}  '
                f'right={_format_location(segment.right)}{suffix}')

    lines.append('')
    lines.append(f'Line-table holes ({len(report.holes)} entries)')
    if not report.holes:
        lines.append('  (none)')
    else:
        for hole in report.holes:
            lines.append(
                f'  {hole.source}: [{hole.begin:#x}, {hole.end:#x})  '
                f'cu={hole.cu_offset:#x}  '
                f'before={_format_location(hole.before)}  '
                f'after={_format_location(hole.after)}')
    return '\n'.join(lines)


def find_line_table_holes(
    cu_offset: int,
    extent: Sequence[AddressInterval | tuple[int, int]],
    intervals: Sequence[LineInterval],
) -> tuple[LineTableHole, ...]:
    """Find internal gaps in one CU's line table within its code ranges.

    The CU's declared ranges bound the search.  A gap is only returned when a
    row covers the address immediately before it and another row covers the
    first address after it, so both sides of every reported hole have a source
    position.  Leading and trailing gaps have only one side and are left as
    ordinary uncovered addresses.
    """
    if not intervals:
        return ()

    normalised_extent = _merge_intervals(
        _as_interval(r) for r in extent)
    if not normalised_extent:
        normalised_extent = _merge_intervals(
            AddressInterval(i.begin, i.end) for i in intervals)

    cu_intervals = tuple(intervals)
    cu_coverage = _build_coverage(cu_intervals)
    coverage_starts = tuple(i.begin for i in cu_coverage)
    holes: list[LineTableHole] = []
    for component in normalised_extent:
        covered = _clip_intervals(cu_coverage, component)
        if not covered:
            continue
        cursor = component.begin
        for interval in covered:
            if interval.begin > cursor:
                _append_hole(
                    holes, cu_offset, cursor, interval.begin,
                    cu_coverage, coverage_starts)
            cursor = max(cursor, interval.end)
        # A trailing gap has no right side, so it is not a legal two-sided
        # line-table hole.  The same applies to a leading gap.
    return tuple(holes)


def _append_hole(
    holes: list[LineTableHole],
    cu_offset: int,
    begin: int,
    end: int,
    coverage: Sequence[LineInterval],
    coverage_starts: Sequence[int],
) -> None:
    before = _location_in_coverage(coverage, coverage_starts, begin - 1)
    after = _location_in_coverage(coverage, coverage_starts, end)
    if before is None or after is None:
        return
    holes.append(LineTableHole(begin, end, cu_offset, before, after))


def _read_elffile(
    elffile: ELFFile,
    name: str,
    repo_roots: RepoRoots,
    address_bias: int,
) -> SourceIndex:
    if not elffile.has_dwarf_info(strict=True):
        raise ValueError(f'{name}: no DWARF info')

    dwarfinfo = elffile.get_dwarf_info()
    roots = _normalise_repo_roots(repo_roots)
    all_intervals: list[LineInterval] = []
    all_holes: list[LineTableHole] = []
    all_extents: list[CompileUnitExtent] = []
    diagnostics: list[str] = []
    sequence_base = 0

    for cu in dwarfinfo.iter_CUs():
        cu_offset = cu.cu_offset
        comp_dir, cu_name = _cu_paths(cu)
        top_die = _top_die(cu)
        extent = _cu_code_ranges(dwarfinfo, cu, top_die, diagnostics)
        if address_bias:
            extent = tuple(
                AddressInterval(r.begin + address_bias, r.end + address_bias)
                for r in extent)
        all_extents.append(CompileUnitExtent(cu_offset, extent))

        try:
            lineprog = dwarfinfo.line_program_for_CU(cu)
            if lineprog is None:
                diagnostics.append(
                    f'CU {cu_offset:#x}: no line program')
                continue
            intervals = _intervals_from_lineprog(
                lineprog, cu_offset, comp_dir, cu_name, roots,
                sequence_base, address_bias, diagnostics)
            sequence_base += _sequence_count(lineprog)
        except (DWARFError, KeyError, IndexError) as error:
            diagnostics.append(
                f'CU {cu_offset:#x}: cannot decode line program: {error}')
            continue
        all_intervals.extend(intervals)
        all_holes.extend(find_line_table_holes(cu_offset, extent, intervals))

    return SourceIndex(
        filename=name,
        intervals=tuple(all_intervals),
        holes=tuple(all_holes),
        cu_extents=tuple(all_extents),
        address_bias=address_bias,
        diagnostics=tuple(diagnostics))


def _cu_paths(cu: CompileUnit) -> tuple[str, str]:
    top = _top_die(cu)
    comp_dir = ''
    cu_name = ''
    if top is not None:
        comp_attr = top.attributes.get('DW_AT_comp_dir')
        name_attr = top.attributes.get('DW_AT_name')
        if comp_attr is not None:
            comp_dir = _text(comp_attr.value)
        if name_attr is not None:
            cu_name = _text(name_attr.value)
    if comp_dir:
        comp_dir = _normalise_path(comp_dir)
    if cu_name and posixpath.isabs(cu_name):
        cu_name = _normalise_path(cu_name)
    return comp_dir, cu_name


def _top_die(cu: CompileUnit) -> Any | None:
    try:
        return cu.get_top_DIE()
    except (KeyError, DWARFError):
        return None


def _cu_code_ranges(
    dwarfinfo: DWARFInfo,
    cu: CompileUnit,
    top_die: Any | None,
    diagnostics: list[str],
) -> tuple[AddressInterval, ...]:
    if top_die is None:
        return ()

    ranges_attr = top_die.attributes.get('DW_AT_ranges')
    if ranges_attr is not None:
        range_lists = dwarfinfo.range_lists()
        if range_lists is None:
            diagnostics.append(
                f'CU {cu.cu_offset:#x}: DW_AT_ranges without a range section')
        else:
            try:
                entries = range_lists.get_range_list_at_offset(
                    ranges_attr.value, cu)
            except DWARFError as error:
                diagnostics.append(
                    f'CU {cu.cu_offset:#x}: cannot read DW_AT_ranges: {error}')
            else:
                low_attr = top_die.attributes.get('DW_AT_low_pc')
                base = low_attr.value if low_attr is not None else 0
                ranges: list[AddressInterval] = []
                for entry in entries:
                    if isinstance(entry, BaseAddressEntry):
                        base = entry.base_address
                        continue
                    begin = (entry.begin_offset if entry.is_absolute
                             else base + entry.begin_offset)
                    end = (entry.end_offset if entry.is_absolute
                           else base + entry.end_offset)
                    if begin < end:
                        ranges.append(AddressInterval(begin, end))
                if ranges:
                    return _merge_intervals(ranges)

    low_attr = top_die.attributes.get('DW_AT_low_pc')
    high_attr = top_die.attributes.get('DW_AT_high_pc')
    if low_attr is None or high_attr is None:
        return ()
    low = low_attr.value
    high_class = describe_form_class(high_attr.form)
    if high_class == 'address':
        high = high_attr.value
    elif high_class == 'constant':
        high = low + high_attr.value
    else:
        diagnostics.append(
            f'CU {cu.cu_offset:#x}: unsupported DW_AT_high_pc class {high_class}')
        return ()
    return (AddressInterval(low, high),) if low < high else ()


def _intervals_from_lineprog(
    lineprog: LineProgram,
    cu_offset: int,
    comp_dir: str,
    cu_name: str,
    repo_roots: Sequence[tuple[str, str]],
    sequence_base: int,
    address_bias: int,
    diagnostics: list[str],
) -> tuple[LineInterval, ...]:
    def location_for(state: LineState) -> SourceLocation | None:
        path = _line_file_path(lineprog, state.file, comp_dir, cu_name)
        if path is None:
            return None
        repo = _repo_for_path(path, comp_dir, repo_roots)
        return SourceLocation(
            repo=repo,
            file=path,
            line=state.line if state.line else None,
            column=state.column or None,
            cu_offset=cu_offset,
            address=state.address + address_bias)

    return _intervals_from_entries(
        lineprog.get_entries(),
        location_for,
        cu_offset,
        sequence_base,
        address_bias,
        diagnostics)


def _intervals_from_entries(
    entries: Iterable[LineProgramEntry],
    location_for: Callable[[LineState], SourceLocation | None],
    cu_offset: int,
    sequence_base: int,
    address_bias: int,
    diagnostics: list[str],
) -> tuple[LineInterval, ...]:
    """Turn decoded line-program entries into row intervals.

    This is the end_sequence boundary: the marker closes the current row at its
    own address.  The next row starts a new sequence, so the range between them
    is not covered by the preceding row.
    """
    intervals: list[LineInterval] = []
    previous: LineState | None = None
    sequence = sequence_base

    for entry in entries:
        state = entry.state
        if state is None:
            continue
        if state.end_sequence:
            if previous is not None:
                if state.address > previous.address:
                    location = location_for(previous)
                    if location is not None:
                        intervals.append(LineInterval(
                            previous.address + address_bias,
                            state.address + address_bias,
                            location,
                            sequence))
                elif state.address < previous.address:
                    diagnostics.append(
                        f'CU {cu_offset:#x}: end_sequence at '
                        f'{state.address:#x} precedes row at '
                        f'{previous.address:#x}')
                previous = None
            sequence += 1
            continue

        if previous is not None:
            if state.address > previous.address:
                location = location_for(previous)
                if location is not None:
                    intervals.append(LineInterval(
                        previous.address + address_bias,
                        state.address + address_bias,
                        location,
                        sequence))
            elif state.address < previous.address:
                diagnostics.append(
                    f'CU {cu_offset:#x}: line row moved backwards from '
                    f'{previous.address:#x} to {state.address:#x}; '
                    'starting a new sequence')
                sequence += 1
            # Equal addresses are legal: the later row supersedes the earlier
            # row at that address, and the zero-length range is omitted.
        previous = state

    if previous is not None:
        diagnostics.append(
            f'CU {cu_offset:#x}: line sequence without end_sequence; '
            f'row at {previous.address:#x} has no extent')
    return tuple(intervals)


def _line_file_path(
    lineprog: LineProgram,
    file_index: int,
    comp_dir: str,
    cu_name: str,
) -> str | None:
    header = lineprog.header
    file_entries = header.get('file_entry', ())
    version = header.get('version', 0)
    index = file_index if version >= 5 else file_index - 1
    if index < 0 or index >= len(file_entries):
        return None
    entry = file_entries[index]
    name = _text(entry.name)
    if not name:
        return None

    directories = header.get('include_directory', ())
    dir_index = entry.dir_index
    directory = ''
    if version >= 5:
        if 0 <= dir_index < len(directories):
            directory = _text(directories[dir_index])
        if not directory:
            directory = comp_dir
    elif dir_index == 0:
        directory = comp_dir
    elif 0 <= dir_index - 1 < len(directories):
        directory = _text(directories[dir_index - 1])

    if posixpath.isabs(name):
        return _normalise_path(name)
    path = posixpath.join(directory, name) if directory else name
    if comp_dir and not posixpath.isabs(path):
        path = posixpath.join(comp_dir, path)
    if not path:
        return _normalise_path(cu_name) if cu_name else None
    return _normalise_path(path)


def _repo_for_path(
    path: str,
    comp_dir: str,
    repo_roots: Sequence[tuple[str, str]],
) -> str:
    matches = [
        (prefix, label) for prefix, label in repo_roots
        if path == prefix or path.startswith(prefix.rstrip('/') + '/')]
    if matches:
        return max(matches, key=lambda item: len(item[0]))[1]
    if comp_dir:
        return comp_dir
    return posixpath.dirname(path) or path


def _normalise_repo_roots(repo_roots: RepoRoots) -> tuple[tuple[str, str], ...]:
    items = repo_roots.items() if isinstance(repo_roots, Mapping) else repo_roots
    return tuple(
        (_normalise_path(os.fspath(prefix)), label)
        for prefix, label in items)


def _sequence_count(lineprog: LineProgram) -> int:
    return sum(1 for entry in lineprog.get_entries()
               if entry.state is not None and entry.state.end_sequence)


def _build_coverage(intervals: Sequence[LineInterval]) -> tuple[LineInterval, ...]:
    """Overlay intervals into disjoint segments; later rows win."""
    if not intervals:
        return ()

    points = sorted({i.begin for i in intervals} | {i.end for i in intervals})
    starts = sorted(
        enumerate(intervals), key=lambda item: (item[1].begin, item[1].end))
    heap: list[tuple[int, int, int, int]] = []
    end_heap: list[tuple[int, int]] = []
    alive: set[int] = set()
    start_index = 0
    result: list[LineInterval] = []

    for point, next_point in zip(points, points[1:]):
        while start_index < len(starts) and starts[start_index][1].begin <= point:
            order, interval = starts[start_index]
            heapq.heappush(
                heap,
                (-interval.begin, -interval.end, -order, order))
            heapq.heappush(end_heap, (interval.end, order))
            alive.add(order)
            start_index += 1

        while end_heap and end_heap[0][0] <= point:
            _, order = heapq.heappop(end_heap)
            alive.discard(order)
        while heap and heap[0][3] not in alive:
            heapq.heappop(heap)

        if not heap:
            continue
        order = heap[0][3]
        chosen = intervals[order]
        piece = LineInterval(point, next_point, chosen.location, chosen.sequence)
        if (result and result[-1].end == piece.begin and
                result[-1].location == piece.location):
            previous = result.pop()
            piece = replace(piece, begin=previous.begin)
        result.append(piece)
    return tuple(result)


def _location_in_coverage(
    coverage: Sequence[LineInterval], coverage_starts: Sequence[int], address: int,
) -> SourceLocation | None:
    index = bisect.bisect_right(coverage_starts, address) - 1
    if index < 0:
        return None
    interval = coverage[index]
    return interval.location if interval.begin <= address < interval.end else None


def _normalise_load_intervals(
    load_intervals: Sequence[AddressInterval | tuple[int, int]] | None,
    left: SourceIndex,
    right: SourceIndex,
) -> tuple[AddressInterval, ...]:
    if load_intervals is not None:
        return _merge_intervals(_as_interval(r) for r in load_intervals)
    ranges = _merge_intervals((*left.code_ranges(), *right.code_ranges()))
    if not ranges:
        return ()
    return (AddressInterval(ranges[0].begin, ranges[-1].end),)


def _boundaries(
    left: SourceIndex,
    right: SourceIndex,
    loads: Sequence[AddressInterval],
) -> tuple[int, ...]:
    points: set[int] = set()
    for load in loads:
        points.add(load.begin)
        points.add(load.end)
    for index in (left, right):
        for interval in index.intervals:
            points.add(interval.begin)
            points.add(interval.end)
        for hole in index.hole_ranges:
            points.add(hole.begin)
            points.add(hole.end)
    return tuple(sorted(points))


def _clipped_holes(
    left: SourceIndex,
    right: SourceIndex,
    loads: Sequence[AddressInterval],
) -> tuple[HoleEvidence, ...]:
    result: list[HoleEvidence] = []
    for name, index in (('left', left), ('right', right)):
        for hole in index.holes:
            if hole.end <= hole.begin:
                continue
            for load in loads:
                clipped = AddressInterval(
                    max(hole.begin, load.begin), min(hole.end, load.end))
                if clipped.begin >= clipped.end:
                    continue
                result.append(HoleEvidence(
                    name, clipped.begin, clipped.end, hole.cu_offset,
                    hole.before, hole.after))
    return tuple(result)


def _can_merge(
    previous: WitnessSegment,
    current: WitnessSegment,
    attribution: Attribution,
) -> bool:
    if previous.end != current.begin or previous.status != current.status:
        return False
    if previous.hole_sources != current.hole_sources:
        return False
    return (_location_key(previous.left, attribution) ==
            _location_key(current.left, attribution) and
            _location_key(previous.right, attribution) ==
            _location_key(current.right, attribution))


def _location_key(
    start: SourceLocation | None,
    attribution: Attribution,
) -> tuple[Any, ...]:
    if start is None:
        return (None,)
    return start.attribution_key(attribution)


def _merge_intervals(
    intervals: Iterable[AddressInterval | tuple[int, int]],
) -> tuple[AddressInterval, ...]:
    normalised = sorted(_as_interval(i) for i in intervals)
    if not normalised:
        return ()
    result: list[AddressInterval] = [normalised[0]]
    for interval in normalised[1:]:
        previous = result[-1]
        if interval.begin <= previous.end:
            result[-1] = AddressInterval(
                previous.begin, max(previous.end, interval.end))
        else:
            result.append(interval)
    return tuple(result)


def _clip_intervals(
    intervals: Sequence[LineInterval], component: AddressInterval,
) -> tuple[LineInterval, ...]:
    result: list[LineInterval] = []
    for interval in intervals:
        begin = max(interval.begin, component.begin)
        end = min(interval.end, component.end)
        if begin < end:
            result.append(replace(interval, begin=begin, end=end))
    return tuple(result)


def _as_interval(value: AddressInterval | tuple[int, int]) -> AddressInterval:
    if isinstance(value, AddressInterval):
        return value
    begin, end = value
    return AddressInterval(begin, end)


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return bytes2str(value)
    return str(value)


def _normalise_path(path: str) -> str:
    path = path.replace('\\', '/') if '\\' in path else path
    return posixpath.normpath(path)


def _source_name(elffile: ELFFile) -> str:
    return str(getattr(elffile.stream, 'name', '<elf>'))


def _format_location(location: SourceLocation | None) -> str:
    if location is None:
        return '<none>'
    line = '?' if location.line is None else str(location.line)
    column = '' if location.column is None else f':{location.column}'
    return f'{location.repo}::{location.file}:{line}{column}'


def _interval_to_dict(interval: AddressInterval) -> dict[str, str]:
    return {'begin': hex(interval.begin), 'end': hex(interval.end)}


def _location_to_dict(location: SourceLocation | None) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        'repo': location.repo,
        'file': location.file,
        'line': location.line,
        'column': location.column,
        'cu_offset': hex(location.cu_offset),
        'address': hex(location.address),
    }


def _segment_to_dict(segment: WitnessSegment) -> dict[str, Any]:
    return {
        'begin': hex(segment.begin),
        'end': hex(segment.end),
        'left': _location_to_dict(segment.left),
        'right': _location_to_dict(segment.right),
        'left_at_end': _location_to_dict(segment.left_at_end),
        'right_at_end': _location_to_dict(segment.right_at_end),
        'hole_sources': list(segment.hole_sources),
    }
