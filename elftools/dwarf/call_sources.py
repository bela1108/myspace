"""Read-only attribution of report addresses to DWARF call sources.

This module combines explicit ``DW_TAG_call_site`` / GNU call-site records,
``DW_TAG_inlined_subroutine`` scopes, and return-address clues.  It never
mutates the inspected ELF or DWARF objects.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, BinaryIO, Iterable

from ..common.utils import bytes2str
from ..dwarf.descriptions import describe_form_class
from ..dwarf.dwarfinfo import DWARFInfo
from ..dwarf.ranges import BaseAddressEntry
from ..elf.elffile import ELFFile

if TYPE_CHECKING:
    from .die import DIE


CALL_SITE_TAGS = frozenset((
    "DW_TAG_call_site",
    "DW_TAG_GNU_call_site",
))
INLINE_TAG = "DW_TAG_inlined_subroutine"
SUBPROGRAM_TAG = "DW_TAG_subprogram"

TAIL_ATTRIBUTES = (
    "DW_AT_call_tail_call",
    "DW_AT_GNU_tail_call",
)
RETURN_PC_ATTRIBUTES = ("DW_AT_call_return_pc",)
CALL_PC_ATTRIBUTES = ("DW_AT_call_pc",)
ORIGIN_ATTRIBUTES = (
    "DW_AT_call_origin",
    "DW_AT_abstract_origin",
    "DW_AT_specification",
)


def hex_int(value: int | None) -> str | None:
    return None if value is None else f"{value:#x}"


def _value(die: "DIE", name: str) -> Any:
    attr = die.attributes.get(name)
    return None if attr is None else attr.value


def _has(die: "DIE", name: str) -> bool:
    return name in die.attributes


def _flag(die: "DIE", names: tuple[str, ...]) -> bool:
    for name in names:
        attr = die.attributes.get(name)
        if attr is not None and bool(attr.value):
            return True
    return False


def _safe_name(value: Any) -> str | None:
    if value is None:
        return None
    result = bytes2str(value)
    return result if result != "" else None


@dataclass(frozen=True)
class DwarfRef:
    """A globally reviewable DIE identity."""

    offset: int
    cu_offset: int
    tag: str | None = None

    @property
    def offset_hex(self) -> str:
        return f"{self.offset:#x}"

    @property
    def cu_offset_hex(self) -> str:
        return f"{self.cu_offset:#x}"


@dataclass(frozen=True)
class SymbolInfo:
    name: str | None
    ref: DwarfRef | None
    cu_offset: int | None
    cu_name: str | None = None
    comp_dir: str | None = None
    linkage_name: str | None = None
    name_resolution: str = "DW_AT_name"


@dataclass(frozen=True)
class SourceLocation:
    file: str | None
    line: int | None
    column: int | None
    resolver: str
    file_index: int | None = None
    path: str | None = None
    resolved: bool = True
    cu_offset: int | None = None
    cu_name: str | None = None


@dataclass(frozen=True)
class AddressRange:
    start: int
    end: int

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass(frozen=True)
class InlineFrame:
    symbol: SymbolInfo | None
    ref: DwarfRef
    call_location: SourceLocation | None
    ranges: tuple[AddressRange, ...] = ()


@dataclass(frozen=True)
class CallAttribution:
    category: str
    matched_by: str
    query_address: int
    call_site: DwarfRef
    target: SymbolInfo | None = None
    caller: SymbolInfo | None = None
    source_location: SourceLocation | None = None
    call_pc: int | None = None
    return_pc: int | None = None
    is_tail: bool = False
    inline_stack: tuple[InlineFrame, ...] = ()
    location_evidence: tuple[SourceLocation, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InlineScopeAttribution:
    query_address: int
    stack: tuple[InlineFrame, ...]
    matched_ref: DwarfRef
    matched_range: AddressRange


@dataclass(frozen=True)
class UnknownReason:
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AddressReport:
    address: int
    ordinary_calls: list[CallAttribution] = field(default_factory=list)
    tail_calls: list[CallAttribution] = field(default_factory=list)
    inline_scopes: list[InlineScopeAttribution] = field(default_factory=list)
    containing_subprograms: list[SymbolInfo] = field(default_factory=list)
    address_locations: list[SourceLocation] = field(default_factory=list)
    unknown_reasons: list[UnknownReason] = field(default_factory=list)

    @property
    def address_hex(self) -> str:
        return f"{self.address:#x}"

    @property
    def reasons(self) -> list[UnknownReason]:
        return self.unknown_reasons

    @property
    def status(self) -> str:
        if self.ordinary_calls or self.tail_calls or self.inline_scopes:
            return "explained"
        return "unknown"


@dataclass(frozen=True)
class ElfIdentity:
    source: str
    is_elf: bool
    has_dwarf_info: bool
    dwarf_sections: tuple[str, ...] = ()
    build_id: str | None = None
    debuglink: str | None = None
    reason: UnknownReason | None = None


@dataclass
class CallSourceReport:
    addresses: list[AddressReport]
    release: ElfIdentity | None = None
    debug: ElfIdentity | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=_json_default)


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, (DwarfRef, SymbolInfo, SourceLocation, AddressRange,
                        InlineFrame, CallAttribution, InlineScopeAttribution,
                        UnknownReason, ElfIdentity)):
        return asdict(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Object of type {type(obj)!r} is not JSON serializable")


class CallSourceAnalyzer:
    """Index one :class:`DWARFInfo` and answer call-source queries."""

    def __init__(self, dwarfinfo: DWARFInfo, source_name: str = "<dwarf>") -> None:
        self.dwarfinfo = dwarfinfo
        self.source_name = source_name
        self.cus: list[Any] = []
        self.dies: dict[int, DIE] = {}
        self.parents: dict[int, int | None] = {}
        self.cu_by_die: dict[int, Any] = {}
        self.call_sites: list[DIE] = []
        self.inline_dies: list[DIE] = []
        self.subprogram_dies: list[DIE] = []
        self._symbol_cache: dict[int, SymbolInfo | None] = {}
        self._range_cache: dict[int, tuple[tuple[AddressRange, ...], tuple[UnknownReason, ...]]] = {}
        self._line_cache: dict[int, tuple[Any, UnknownReason | None]] = {}
        self._index_dwarf()

    def _index_dwarf(self) -> None:
        for cu in self.dwarfinfo.iter_CUs():
            self.cus.append(cu)
            stack: list[int] = []
            for die in cu.iter_DIEs():
                if die.is_null():
                    if stack:
                        stack.pop()
                    continue
                self.dies[die.offset] = die
                self.cu_by_die[die.offset] = cu
                parent_offset = stack[-1] if stack else None
                self.parents[die.offset] = parent_offset
                if die.tag in CALL_SITE_TAGS:
                    self.call_sites.append(die)
                if die.tag == INLINE_TAG:
                    self.inline_dies.append(die)
                if die.tag == SUBPROGRAM_TAG:
                    self.subprogram_dies.append(die)
                if die.has_children:
                    stack.append(die.offset)

    def ref(self, die: "DIE") -> DwarfRef:
        return DwarfRef(offset=die.offset, cu_offset=die.cu.cu_offset, tag=die.tag)

    def analyze_addresses(self, addresses: list[int]) -> list[AddressReport]:
        return [self.analyze_address(address) for address in addresses]

    def analyze_address(self, address: int) -> AddressReport:
        report = AddressReport(address=address)
        matched_call_sites: set[int] = set()

        for call_site in self.call_sites:
            attribution = self._match_call_site(call_site, address)
            if attribution is None:
                continue
            matched_call_sites.add(call_site.offset)
            if attribution.category == "tail_call":
                report.tail_calls.append(attribution)
            else:
                report.ordinary_calls.append(attribution)

        inline_stacks = self._inline_stacks_containing(address)
        report.inline_scopes.extend(inline_stacks)
        report.address_locations.extend(self._address_locations(address))

        for stack_attribution in inline_stacks:
            stack_offsets = {frame.ref.offset for frame in stack_attribution.stack}
            for call_site in self.call_sites:
                if call_site.offset in matched_call_sites:
                    continue
                if not _flag(call_site, TAIL_ATTRIBUTES):
                    continue
                inline_stack = self.inline_stack_for_die(call_site)
                if not any(frame.ref.offset in stack_offsets for frame in inline_stack):
                    continue
                if any(_value(call_site, name) is not None
                       for name in RETURN_PC_ATTRIBUTES + CALL_PC_ATTRIBUTES + ("DW_AT_low_pc",)):
                    continue
                attribution = self._build_call_attribution(
                    call_site,
                    category="tail_call",
                    matched_by="enclosing_inlined_subroutine",
                    query_address=address,
                    return_pc=None,
                    call_pc=None,
                    extra_evidence={
                        "association": "inline-scope ancestry only",
                        "ordinary_return_pc": None,
                    },
                )
                report.tail_calls.append(attribution)
                matched_call_sites.add(call_site.offset)

        report.containing_subprograms.extend(self._subprograms_containing(address))
        self._add_absence_reasons(report)
        return report

    def _match_call_site(self, die: "DIE", address: int) -> CallAttribution | None:
        is_tail = _flag(die, TAIL_ATTRIBUTES)
        category = "tail_call" if is_tail else "ordinary_call"
        return_pc = _value(die, "DW_AT_call_return_pc")
        call_pc = _value(die, "DW_AT_call_pc")
        low_pc = _value(die, "DW_AT_low_pc")

        if return_pc == address:
            return self._build_call_attribution(
                die, category, "DW_AT_call_return_pc", address,
                return_pc=return_pc, call_pc=call_pc,
                extra_evidence={"address_class": "ordinary-return-pc"},
            )
        if call_pc == address:
            return self._build_call_attribution(
                die, category, "DW_AT_call_pc", address,
                return_pc=return_pc, call_pc=call_pc,
                extra_evidence={"address_class": "call-instruction-pc"},
            )
        if die.tag == "DW_TAG_GNU_call_site" and low_pc == address:
            if is_tail:
                matched_by = "DW_AT_low_pc+DW_AT_GNU_tail_call"
                address_class = "gnu-tail-site-boundary"
            else:
                matched_by = "DW_AT_low_pc"
                address_class = "gnu-return-pc"
            return self._build_call_attribution(
                die, category, matched_by, address,
                return_pc=return_pc,
                call_pc=call_pc,
                extra_evidence={
                    "address_class": address_class,
                    "gnu_low_pc": low_pc,
                },
            )
        return None

    def _build_call_attribution(
        self,
        die: "DIE",
        category: str,
        matched_by: str,
        query_address: int,
        *,
        return_pc: int | None,
        call_pc: int | None,
        extra_evidence: dict[str, Any],
    ) -> CallAttribution:
        location_evidence = self._call_location_evidence(die, call_pc, return_pc)
        source_location = location_evidence[0] if location_evidence else self._location_from_call_attributes(die)
        inline_stack = self.inline_stack_for_die(die)
        return CallAttribution(
            category=category,
            matched_by=matched_by,
            query_address=query_address,
            call_site=self.ref(die),
            target=self._target_symbol(die),
            caller=self._caller_symbol(die),
            source_location=source_location,
            call_pc=call_pc,
            return_pc=return_pc,
            is_tail=category == "tail_call",
            inline_stack=inline_stack,
            location_evidence=location_evidence,
            evidence={
                "tag": die.tag,
                "attributes": self._relevant_attributes(die),
                **extra_evidence,
            },
        )

    def _relevant_attributes(self, die: "DIE") -> dict[str, Any]:
        names = (
            "DW_AT_call_origin", "DW_AT_abstract_origin", "DW_AT_specification",
            "DW_AT_call_return_pc", "DW_AT_call_pc", "DW_AT_low_pc",
            *TAIL_ATTRIBUTES,
            "DW_AT_call_file", "DW_AT_call_line", "DW_AT_call_column",
        )
        result: dict[str, Any] = {}
        for name in names:
            attr = die.attributes.get(name)
            if attr is None:
                continue
            value = attr.value
            result[name] = {
                "form": attr.form,
                "value": bytes2str(value) if isinstance(value, bytes) else value,
            }
        return result

    def _target_symbol(self, die: "DIE") -> SymbolInfo | None:
        for name in ORIGIN_ATTRIBUTES:
            if _has(die, name):
                try:
                    origin = die.get_DIE_from_attribute(name)
                except Exception as exc:  # reviewable malformed/unsupported refs
                    return SymbolInfo(
                        name=None,
                        ref=None,
                        cu_offset=die.cu.cu_offset,
                        name_resolution=f"unresolved {name}: {type(exc).__name__}: {exc}",
                    )
                return self.symbol_info(origin)
        return self.symbol_info(die)

    def _caller_symbol(self, die: "DIE") -> SymbolInfo | None:
        offset = self.parents.get(die.offset)
        while offset is not None:
            parent = self.dies[offset]
            if parent.tag == SUBPROGRAM_TAG:
                return self.symbol_info(parent)
            offset = self.parents.get(offset)
        return None

    def symbol_info(self, die: "DIE") -> SymbolInfo | None:
        cached = self._symbol_cache.get(die.offset)
        if die.offset in self._symbol_cache:
            return cached

        current = die
        resolution = "DW_AT_name"
        try:
            for _ in range(16):
                if _has(current, "DW_AT_name"):
                    break
                ref_name = next((name for name in ORIGIN_ATTRIBUTES if _has(current, name)), None)
                if ref_name is None:
                    break
                current = current.get_DIE_from_attribute(ref_name)
                resolution = ref_name
        except Exception as exc:
            resolution = f"unresolved reference: {type(exc).__name__}: {exc}"

        top = current.cu.get_top_DIE()
        info = SymbolInfo(
            name=_safe_name(_value(current, "DW_AT_name")),
            linkage_name=_safe_name(
                _value(current, "DW_AT_linkage_name")
                or _value(current, "DW_AT_MIPS_linkage_name")
            ),
            ref=self.ref(current),
            cu_offset=current.cu.cu_offset,
            cu_name=_safe_name(_value(top, "DW_AT_name")),
            comp_dir=_safe_name(_value(top, "DW_AT_comp_dir")),
            name_resolution=resolution,
        )
        self._symbol_cache[die.offset] = info
        return info

    def inline_stack_for_die(self, die: "DIE") -> tuple[InlineFrame, ...]:
        frames: list[InlineFrame]
        if die.tag == INLINE_TAG:
            frames = [self._inline_frame(die)]
        else:
            frames = []
        offset = self.parents.get(die.offset)
        seen: set[int] = set()
        while offset is not None and offset not in seen:
            seen.add(offset)
            ancestor = self.dies.get(offset)
            if ancestor is not None and ancestor.tag == INLINE_TAG:
                frames.append(self._inline_frame(ancestor))
            offset = self.parents.get(offset)
        return tuple(reversed(frames))

    def _inline_frame(self, die: "DIE") -> InlineFrame:
        ranges, _ = self.ranges_for_die(die)
        return InlineFrame(
            symbol=self.symbol_info(die),
            ref=self.ref(die),
            call_location=self._location_from_call_attributes(die),
            ranges=ranges,
        )

    def _inline_stacks_containing(self, address: int) -> list[InlineScopeAttribution]:
        result: list[InlineScopeAttribution] = []
        seen_stacks: set[tuple[int, ...]] = set()
        for die in self.inline_dies:
            ranges, _ = self.ranges_for_die(die)
            matched_range = next((rng for rng in ranges if rng.contains(address)), None)
            if matched_range is None:
                continue
            stack = self.inline_stack_for_die(die)
            stack_key = tuple(frame.ref.offset for frame in stack)
            if stack_key in seen_stacks:
                continue
            seen_stacks.add(stack_key)
            result.append(InlineScopeAttribution(
                query_address=address,
                stack=stack,
                matched_ref=self.ref(die),
                matched_range=matched_range,
            ))
        return result

    def _subprograms_containing(self, address: int) -> list[SymbolInfo]:
        result: list[SymbolInfo] = []
        for die in self.subprogram_dies:
            ranges, _ = self.ranges_for_die(die)
            if any(rng.contains(address) for rng in ranges):
                symbol = self.symbol_info(die)
                if symbol is not None:
                    result.append(symbol)
        return result

    def _address_locations(self, address: int) -> list[SourceLocation]:
        locations: list[SourceLocation] = []
        seen: set[tuple[Any, ...]] = set()
        for cu in self.cus:
            location = self._line_location(cu, address, ".debug_line[address]")
            if location is None:
                continue
            key = (location.cu_offset, location.file_index, location.line, location.column)
            if key in seen:
                continue
            seen.add(key)
            locations.append(location)
        return locations

    def ranges_for_die(self, die: "DIE") -> tuple[tuple[AddressRange, ...], tuple[UnknownReason, ...]]:
        if die.offset in self._range_cache:
            return self._range_cache[die.offset]

        ranges: list[AddressRange] = []
        reasons: list[UnknownReason] = []
        low_pc = _value(die, "DW_AT_low_pc")
        high_attr = die.attributes.get("DW_AT_high_pc")

        if low_pc is not None:
            if high_attr is None:
                reasons.append(UnknownReason(
                    "range_high_pc_missing",
                    "DW_AT_low_pc is present without DW_AT_high_pc.",
                    {"die_offset": die.offset, "low_pc": low_pc},
                ))
            else:
                high_pc = high_attr.value
                form_class = describe_form_class(high_attr.form)
                if form_class == "address":
                    end = high_pc
                elif form_class == "constant":
                    end = low_pc + high_pc
                else:
                    end = None
                    reasons.append(UnknownReason(
                        "unsupported_high_pc_form",
                        "DW_AT_high_pc has an unsupported form.",
                        {"die_offset": die.offset, "form": high_attr.form},
                    ))
                if end is not None and end > low_pc:
                    ranges.append(AddressRange(low_pc, end))

        ranges_attr = die.attributes.get("DW_AT_ranges")
        if ranges_attr is not None:
            extra_ranges, range_reasons = self._ranges_from_attribute(die, ranges_attr.value)
            ranges.extend(extra_ranges)
            reasons.extend(range_reasons)

        if not ranges and not reasons:
            reasons.append(UnknownReason(
                "no_address_range",
                "DIE has neither decodable PC range nor DW_AT_ranges.",
                {"die_offset": die.offset, "tag": die.tag},
            ))

        value = (tuple(ranges), tuple(reasons))
        self._range_cache[die.offset] = value
        return value

    def _ranges_from_attribute(
        self, die: "DIE", ranges_offset: int,
    ) -> tuple[list[AddressRange], list[UnknownReason]]:
        ranges: list[AddressRange] = []
        reasons: list[UnknownReason] = []
        range_lists = self.dwarfinfo.range_lists()
        if range_lists is None:
            return ranges, [UnknownReason(
                "range_list_section_missing",
                "DW_AT_ranges exists but no range-list section is available.",
                {"die_offset": die.offset, "ranges_offset": ranges_offset},
            )]
        try:
            entries = range_lists.get_range_list_at_offset(ranges_offset, die.cu)
        except Exception as exc:
            return ranges, [UnknownReason(
                "range_list_unreadable",
                type(exc).__name__ + ": " + str(exc),
                {"die_offset": die.offset, "ranges_offset": ranges_offset},
            )]

        top_low = _value(die.cu.get_top_DIE(), "DW_AT_low_pc")
        base = top_low if isinstance(top_low, int) else None
        for entry in entries:
            if isinstance(entry, BaseAddressEntry):
                base = entry.base_address
                continue
            if getattr(entry, "is_absolute", False):
                ranges.append(AddressRange(entry.begin_offset, entry.end_offset))
            elif base is None:
                reasons.append(UnknownReason(
                    "range_base_unknown",
                    "Relative range entry has no known base address.",
                    {"begin_offset": entry.begin_offset, "end_offset": entry.end_offset},
                ))
            else:
                ranges.append(AddressRange(base + entry.begin_offset, base + entry.end_offset))
        return ranges, reasons

    def _line_program(self, cu: Any) -> tuple[Any, UnknownReason | None]:
        cu_offset = cu.cu_offset
        if cu_offset in self._line_cache:
            return self._line_cache[cu_offset]
        try:
            program = self.dwarfinfo.line_program_for_CU(cu)
            result = (program, None)
        except Exception as exc:
            result = (None, UnknownReason(
                "line_program_unreadable",
                type(exc).__name__ + ": " + str(exc),
                {"cu_offset": cu_offset},
            ))
        self._line_cache[cu_offset] = result
        return result

    def _location_from_call_attributes(self, die: "DIE") -> SourceLocation | None:
        file_attr = die.attributes.get("DW_AT_call_file")
        line = _value(die, "DW_AT_call_line")
        column = _value(die, "DW_AT_call_column")
        if file_attr is None and line is None and column is None:
            return None
        file_index = file_attr.value if file_attr is not None else None
        file_name = None
        path = None
        resolved = file_index is None
        if file_index is not None:
            location = self._location_from_file_index(die.cu, file_index, line, column,
                                                       "DW_AT_call_file/line/column")
            if location is not None:
                return location
        return SourceLocation(
            file=file_name,
            line=line,
            column=column,
            file_index=file_index,
            path=path,
            resolver="DW_AT_call_file/line/column",
            resolved=resolved,
        )

    def _location_from_file_index(
        self, cu: Any, file_index: int, line: int | None,
        column: int | None, resolver: str,
    ) -> SourceLocation | None:
        cu_name = _safe_name(_value(cu.get_top_DIE(), "DW_AT_name"))
        program, error = self._line_program(cu)
        if program is None:
            return SourceLocation(
                file=None, line=line, column=column, file_index=file_index,
                resolver=resolver, resolved=False,
                cu_offset=cu.cu_offset, cu_name=cu_name,
            )
        try:
            version = program.header.version
            delta = 1 if version < 5 else 0
            entries = program["file_entry"]
            entry = entries[file_index - delta]
            file_name = _safe_name(entry.name)
            directory = self._directory_for_file_entry(program, entry)
            path = None
            if file_name and directory:
                path = directory.rstrip("/") + "/" + file_name
            elif file_name:
                path = file_name
            return SourceLocation(
                file=file_name,
                line=line,
                column=column,
                file_index=file_index,
                path=path,
                resolver=resolver,
                resolved=True,
                cu_offset=cu.cu_offset, cu_name=cu_name,
            )
        except Exception:
            return SourceLocation(
                file=None, line=line, column=column, file_index=file_index,
                resolver=resolver + " (file index unresolved)", resolved=False,
                cu_offset=cu.cu_offset, cu_name=cu_name,
            )

    def _directory_for_file_entry(self, program: Any, entry: Any) -> str | None:
        dir_index = getattr(entry, "dir_index", None)
        if dir_index is None:
            return None
        try:
            directories = program["include_directory"]
            if dir_index > 0 and dir_index <= len(directories):
                return _safe_name(directories[dir_index - 1])
        except Exception:
            return None
        return None

    def _call_location_evidence(
        self, die: "DIE", call_pc: int | None, return_pc: int | None,
    ) -> tuple[SourceLocation, ...]:
        evidence: list[SourceLocation] = []
        direct = self._location_from_call_attributes(die)
        if direct is not None:
            evidence.append(direct)
        if call_pc is not None:
            location = self._line_location(die.cu, call_pc, ".debug_line[DW_AT_call_pc]")
            if location is not None:
                evidence.append(location)
        if return_pc is not None and return_pc > 0:
            before = self._line_location(die.cu, return_pc - 1,
                                         ".debug_line[DW_AT_call_return_pc-1]")
            if before is not None:
                evidence.append(before)
            at_return = self._line_location(die.cu, return_pc,
                                            ".debug_line[DW_AT_call_return_pc]")
            if at_return is not None:
                evidence.append(at_return)
        return tuple(evidence)

    def _line_location(self, cu: Any, address: int, resolver: str) -> SourceLocation | None:
        if address < 0:
            return None
        program, error = self._line_program(cu)
        if program is None:
            return None
        previous = None
        try:
            entries = list(program.get_entries())
        except Exception:
            return None
        for entry in entries:
            state = entry.state
            if state is None:
                continue
            if state.end_sequence:
                if previous is not None and previous.address <= address < state.address:
                    return self._source_location_from_state(cu, program, previous, resolver)
                previous = None
                continue
            if previous is not None and previous.address <= address < state.address:
                return self._source_location_from_state(cu, program, previous, resolver)
            previous = state
        if previous is not None and previous.address == address and not previous.end_sequence:
            return self._source_location_from_state(cu, program, previous, resolver)
        return None

    def _source_location_from_state(
        self, cu: Any, program: Any, state: Any, resolver: str,
    ) -> SourceLocation:
        version = program.header.version
        delta = 1 if version < 5 else 0
        file_index = state.file
        file_name = None
        path = None
        try:
            file_entry = program["file_entry"][file_index - delta]
            file_name = _safe_name(file_entry.name)
            directory = self._directory_for_file_entry(program, file_entry)
            path = f"{directory.rstrip('/')}/{file_name}" if directory and file_name else file_name
        except Exception:
            pass
        return SourceLocation(
            file=file_name,
            line=state.line,
            column=state.column or None,
            file_index=file_index,
            path=path,
            resolver=resolver,
            resolved=file_name is not None,
            cu_offset=cu.cu_offset,
            cu_name=_safe_name(_value(cu.get_top_DIE(), "DW_AT_name")),
        )

    def _add_absence_reasons(self, report: AddressReport) -> None:
        address = report.address
        if not report.ordinary_calls:
            report.reasons.append(UnknownReason(
                "no_ordinary_call_return_match",
                "No ordinary call-site record matches this return-address clue.",
                {"address": address, "call_sites_checked": len(self.call_sites)},
            ))
        if not report.tail_calls:
            report.reasons.append(UnknownReason(
                "no_tail_call_match",
                "No tail call-site record matches this address or enclosing inline scope.",
                {"address": address, "call_sites_checked": len(self.call_sites)},
            ))
        if not report.inline_scopes:
            report.reasons.append(UnknownReason(
                "address_not_in_inlined_subroutine",
                "No DW_TAG_inlined_subroutine range contains this address.",
                {"address": address, "inline_dies_checked": len(self.inline_dies)},
            ))
        if report.status == "unknown":
            report.reasons.append(UnknownReason(
                "unattributed_address",
                "Call-site, inline-scope, and return-address evidence does not explain this address.",
                {"address": address, "cus_checked": len(self.cus)},
            ))


def inspect_elf(stream: BinaryIO, source: str = "<stream>") -> ElfIdentity:
    """Read ELF/DWARF availability without modifying ``stream`` content."""
    elf = ELFFile(stream)
    sections = tuple(name for name in (
        ".debug_info", ".zdebug_info", ".debug_abbrev", ".debug_line",
        ".debug_ranges", ".debug_rnglists",
    ) if elf.get_section_by_name(name) is not None)
    has_dwarf = elf.has_dwarf_info()
    reason = None
    if not has_dwarf:
        reason = UnknownReason(
            "release_without_debug_records",
            "ELF has no parseable DWARF debugging sections; use a matching offline debug file.",
            {"source": source, "sections_found": sections},
        )
    return ElfIdentity(
        source=source,
        is_elf=True,
        has_dwarf_info=has_dwarf,
        dwarf_sections=sections,
        build_id=_read_build_id(elf),
        debuglink=_read_debuglink(elf),
        reason=reason,
    )


def analyze_dwarf(dwarfinfo: DWARFInfo, addresses: Iterable[int]) -> list[AddressReport]:
    """Analyze addresses against an existing pyelftools :class:`DWARFInfo`."""
    return CallSourceAnalyzer(dwarfinfo).analyze_addresses(list(addresses))


def find_call_sources(dwarfinfo: DWARFInfo, address: int) -> AddressReport:
    """Convenience wrapper for a single address query."""
    return CallSourceAnalyzer(dwarfinfo).analyze_address(address)


def analyze_paths(
    addresses: Iterable[int],
    *,
    release_path: str | os.PathLike[str] | None = None,
    debug_path: str | os.PathLike[str] | None = None,
) -> CallSourceReport:
    """Open release/debug paths read-only and analyze ``addresses``."""
    address_values = list(addresses)
    if release_path is not None:
        release_stream = open(release_path, "rb")
    else:
        release_stream = None
    if debug_path is not None:
        debug_stream = open(debug_path, "rb")
    else:
        debug_stream = None
    try:
        return analyze_elf_streams(
            address_values,
            release_stream=release_stream,
            debug_stream=debug_stream,
            release_name=os.fspath(release_path or "<release>"),
            debug_name=os.fspath(debug_path or release_path or "<debug>"),
        )
    finally:
        if release_stream is not None:
            release_stream.close()
        if debug_stream is not None:
            debug_stream.close()


def _read_build_id(elf: ELFFile) -> str | None:
    section = elf.get_section_by_name(".note.gnu.build-id")
    if section is None:
        return None
    try:
        for note in section.iter_notes():
            desc = note.get("n_desc")
            if isinstance(desc, bytes):
                return desc.hex()
            if isinstance(desc, str):
                return desc
    except Exception:
        return None
    return None


def _read_debuglink(elf: ELFFile) -> str | None:
    try:
        link = elf.get_debuglink()
    except Exception:
        return None
    if not link:
        return None
    filename = link.filename
    return bytes2str(filename) if isinstance(filename, bytes) else str(filename)


def analyze_elf_streams(
    addresses: list[int],
    *,
    release_stream: BinaryIO | None = None,
    debug_stream: BinaryIO | None = None,
    release_name: str = "<release>",
    debug_name: str = "<debug>",
) -> CallSourceReport:
    """Analyze optional release and offline debug ELF byte streams."""
    release_identity = None
    release_elf = None
    if release_stream is not None:
        release_identity = inspect_elf(release_stream, release_name)
        release_stream.seek(0)
        release_elf = ELFFile(release_stream)

    debug_identity = None
    analyzer = None
    debug_elf = None
    if debug_stream is not None:
        debug_identity = inspect_elf(debug_stream, debug_name)
        debug_stream.seek(0)
        debug_elf = ELFFile(debug_stream)
        if debug_elf.has_dwarf_info():
            analyzer = CallSourceAnalyzer(debug_elf.get_dwarf_info(), debug_name)
    elif release_elf is not None and release_elf.has_dwarf_info():
        debug_identity = release_identity
        analyzer = CallSourceAnalyzer(release_elf.get_dwarf_info(), release_name)

    if analyzer is None:
        reports = []
        for address in addresses:
            report = AddressReport(address=address)
            report.reasons.append(UnknownReason(
                "debug_source_unavailable",
                "No DWARF information is available in the offline debug or release ELF.",
                {
                    "release_has_dwarf_info": None if release_identity is None else release_identity.has_dwarf_info,
                    "debug_has_dwarf_info": None if debug_identity is None else debug_identity.has_dwarf_info,
                },
            ))
            reports.append(report)
    else:
        reports = analyzer.analyze_addresses(addresses)

    warnings: list[str] = []
    if (release_identity and release_identity.build_id and debug_identity
            and debug_identity.build_id
            and release_identity.build_id != debug_identity.build_id):
        warnings.append(
            "GNU build IDs differ: "
            f"release={release_identity.build_id} debug={debug_identity.build_id}"
        )
    return CallSourceReport(
        addresses=reports,
        release=release_identity,
        debug=debug_identity,
        warnings=warnings,
    )


def render_text(report: CallSourceReport) -> str:
    lines: list[str] = []
    if report.release and report.release.reason:
        lines.append(f"release: {report.release.source}: {report.release.reason.code}")
        lines.append(f"  reason: {report.release.reason.message}")
    if report.debug:
        lines.append(f"debug: {report.debug.source} dwarf={report.debug.has_dwarf_info}")
    for warning in report.warnings:
        lines.append(f"warning: {warning}")
    for address_report in report.addresses:
        lines.append(f"\naddress {address_report.address_hex} ({address_report.status})")
        for location in address_report.address_locations:
            source = location.path or location.file or f"file[{location.file_index}]"
            lines.append(
                f"  address line: {source}:{location.line}:{location.column} "
                f"({location.resolver})"
            )
        for call in address_report.ordinary_calls:
            lines.extend(_render_call(call, "ordinary"))
        for call in address_report.tail_calls:
            lines.extend(_render_call(call, "tail"))
        for scope in address_report.inline_scopes:
            lines.append("  inline-scope candidate:")
            lines.extend(_render_stack(scope.stack, indent=4))
        if address_report.status == "unknown":
            primary = next((r for r in address_report.reasons if r.code == "unattributed_address"), None)
            if primary:
                lines.append(f"  unknown: {primary.message}")
    return "\n".join(lines)


def _render_call(call: CallAttribution, label: str) -> list[str]:
    target = call.target.name if call.target and call.target.name else "<unresolved>"
    caller = call.caller.name if call.caller and call.caller.name else "<unknown-caller>"
    lines = [f"  {label} call via {call.matched_by}: caller={caller} target={target}"]
    if call.source_location:
        location = call.source_location.path or call.source_location.file or f"file[{call.source_location.file_index}]"
        lines.append(f"    source: {location}:{call.source_location.line}:{call.source_location.column} ({call.source_location.resolver})")
    if call.return_pc is not None:
        lines.append(f"    return_pc: {hex_int(call.return_pc)}")
    if call.call_pc is not None:
        lines.append(f"    call_pc: {hex_int(call.call_pc)}")
    if call.inline_stack:
        lines.append("    inline stack:")
        lines.extend(_render_stack(call.inline_stack, indent=6))
    return lines


def _render_stack(stack: tuple[InlineFrame, ...], indent: int) -> list[str]:
    pad = " " * indent
    lines: list[str] = []
    for index, frame in enumerate(stack, 1):
        name = frame.symbol.name if frame.symbol and frame.symbol.name else "<unresolved-inline>"
        cu = frame.symbol.cu_name if frame.symbol and frame.symbol.cu_name else f"cu@{frame.ref.cu_offset:#x}"
        lines.append(f"{pad}{index}. {name} [{cu}]")
        location = frame.call_location
        if location:
            source = location.path or location.file or f"file[{location.file_index}]"
            lines.append(f"{pad}   call location: {source}:{location.line}:{location.column}")
    return lines


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("addresses", nargs="+", help="Report addresses, e.g. 0x1018")
    parser.add_argument("--release", type=str, help="Stripped/release ELF path")
    parser.add_argument("--debug", type=str, help="Matching offline debug ELF path")
    parser.add_argument("--json", action="store_true", help="Print structured JSON")
    args = parser.parse_args(argv)

    address_values = [int(value, 0) for value in args.addresses]
    report = analyze_paths(
        address_values,
        release_path=args.release,
        debug_path=args.debug or args.release,
    )

    if args.json:
        print(report.to_json())
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
