#!/usr/bin/env python3
"""Read-only x86-64 GNU IFUNC dispatch-evidence inventory.

The tool deliberately separates two claims:

* a dynamic STT_GNU_IFUNC symbol / R_X86_64_IRELATIVE addend can locate the
  selector/resolver;
* only bytes decoded from that selector and mapped through PT_LOAD can
  provide evidence about a concrete implementation.

It uses pyelftools for ELF parsing and never modifies its input.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile


IRELATIVE_TYPE = 37
X86_64_MACHINE_VALUES = {"EM_X86_64", 62}
IFUNC_TYPE_VALUES = {"STT_GNU_IFUNC", "STT_LOOS", 10}
PF_X = 1
PF_W = 2
PF_R = 4
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SCAN_WINDOW = 96
PROBE_WINDOW = 32
MAX_SELECTOR_BYTES = 512
NL = chr(10)
BACKSLASH = chr(92)


class IfuncEvidenceError(Exception):
    """Base error for this audit tool."""


class UnsupportedArchitectureError(IfuncEvidenceError):
    """Raised when an input is not a little-endian ELF64 x86-64 file."""


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def _short_hex(data: bytes | None, limit: int = 16) -> str | None:
    if data is None:
        return None
    return data[:limit].hex()


def _signed32(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


@dataclass
class Reservation:
    """A locatable caveat or contradiction."""

    code: str
    message: str
    severity: str = "warning"
    where: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "where": _json_safe(self.where),
        }

    def render(self) -> str:
        loc = ", ".join(
            f"{key}={_format_scalar(value)}" for key, value in self.where.items()
        )
        suffix = f" ({loc})" if loc else ""
        return f"[{self.severity}:{self.code}] {self.message}{suffix}"


@dataclass
class ByteMapping:
    """One program-header or section-header mapping for a virtual address."""

    source: str
    vaddr: int
    size_requested: int
    file_offset: int | None = None
    actual_size: int = 0
    complete: bool = False
    zero_fill: bool = False
    readable_flag: bool | None = None
    writable_flag: bool | None = None
    executable_flag: bool | None = None
    segment_index: int | None = None
    section_index: int | None = None
    section_name: str | None = None
    table_vaddr: int | None = None
    data: bytes = field(default=b"", repr=False)
    sha256: str | None = None
    preview_hex: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {key: value for key, value in self.__dict__.items() if key != "data"}
        result["vaddr"] = _hex(self.vaddr)
        result["file_offset"] = _hex(self.file_offset)
        result["table_vaddr"] = _hex(self.table_vaddr)
        return result


@dataclass
class AddressResolution:
    vaddr: int
    size: int
    mappings: list[ByteMapping] = field(default_factory=list)
    reservations: list[Reservation] = field(default_factory=list)
    primary: ByteMapping | None = None
    contradictory: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "vaddr": _hex(self.vaddr),
            "size": self.size,
            "contradictory": self.contradictory,
            "primary": self.primary.to_dict() if self.primary else None,
            "mappings": [mapping.to_dict() for mapping in self.mappings],
            "reservations": [item.to_dict() for item in self.reservations],
        }


@dataclass
class SymbolInfo:
    name: str
    index: int
    source: str
    st_value: int
    st_size: int
    type_name: str | int | None
    type_value: int | None
    bind: str | int | None
    shndx: str | int | None
    is_ifunc: bool
    dynsym_section_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result = dict(self.__dict__)
        result["st_value"] = _hex(result["st_value"])
        return result

    def label(self) -> str:
        return f"{self.name or '<unnamed>'}#{self.index}"


@dataclass
class RelaOccurrence:
    source: str
    locator: str
    index: int
    entry_file_offset: int | None = None
    table_vaddr: int | None = None
    table_file_offset: int | None = None
    section_index: int | None = None
    section_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = dict(self.__dict__)
        for key in ("entry_file_offset", "table_vaddr", "table_file_offset"):
            result[key] = _hex(result[key])
        return result


@dataclass
class RelaEvidence:
    r_offset: int
    r_info: int
    r_addend: int
    r_type: int
    r_sym: int
    occurrences: list[RelaOccurrence] = field(default_factory=list)
    slot_resolution: AddressResolution | None = None
    stored_slot_value: int | None = None
    reservations: list[Reservation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "r_offset": _hex(self.r_offset),
            "r_info": _hex(self.r_info),
            "r_addend": _hex(self.r_addend),
            "r_type": self.r_type,
            "r_sym": self.r_sym,
            "stored_slot_value": _hex(self.stored_slot_value),
            "occurrences": [item.to_dict() for item in self.occurrences],
            "slot_resolution": self.slot_resolution.to_dict()
            if self.slot_resolution
            else None,
            "reservations": [item.to_dict() for item in self.reservations],
        }

    def dynamic_occurrences(self) -> list[RelaOccurrence]:
        return [item for item in self.occurrences if item.source == "dynamic_table"]

    def section_occurrences(self) -> list[RelaOccurrence]:
        return [item for item in self.occurrences if item.source == "section_header"]


@dataclass
class ImplementationCandidate:
    target_va: int
    kind: str
    instruction_offset: int
    instruction_va: int
    direct_return: bool
    resolution: AddressResolution | None = None
    implementation_symbols: list[SymbolInfo] = field(default_factory=list)
    manifest_match: dict[str, Any] | None = None

    @property
    def mapped_nonzero(self) -> bool:
        mapping = self.resolution.primary if self.resolution else None
        if mapping is None or not mapping.data:
            return False
        if mapping.zero_fill or not any(mapping.data[:16]):
            return False
        if self.resolution and self.resolution.contradictory:
            return False
        return True

    @property
    def mapped_nonzero_executable(self) -> bool:
        return (
            self.mapped_nonzero
            and self.resolution is not None
            and self.resolution.primary is not None
            and self.resolution.primary.executable_flag is not False
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_va": _hex(self.target_va),
            "kind": self.kind,
            "instruction_offset": _hex(self.instruction_offset),
            "instruction_va": _hex(self.instruction_va),
            "direct_return": self.direct_return,
            "mapped_nonzero": self.mapped_nonzero,
            "mapped_nonzero_executable": self.mapped_nonzero_executable,
            "resolution": self.resolution.to_dict() if self.resolution else None,
            "implementation_symbols": [
                item.to_dict() for item in self.implementation_symbols
            ],
            "manifest_match": self.manifest_match,
        }


@dataclass
class IfuncRecord:
    key: str
    selector_va: int | None
    selector_located: bool = False
    selector_mapping_verified: bool = False
    selector_symbols: list[SymbolInfo] = field(default_factory=list)
    aliases: list[SymbolInfo] = field(default_factory=list)
    relocations: list[RelaEvidence] = field(default_factory=list)
    selector_resolution: AddressResolution | None = None
    selector_preview_hex: str | None = None
    selector_sha256: str | None = None
    candidates: list[ImplementationCandidate] = field(default_factory=list)
    implementation_confirmed: bool = False
    implementation_status: str = "not_confirmed"
    implementation_va: int | None = None
    implementation_evidence: str = ""
    reservations: list[Reservation] = field(default_factory=list)
    manifest_matches: list[dict[str, Any]] = field(default_factory=list)
    manifest_selector_matches: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "selector_va": _hex(self.selector_va),
            "selector_located": self.selector_located,
            "selector_mapping_verified": self.selector_mapping_verified,
            "selector_symbols": [item.to_dict() for item in self.selector_symbols],
            "aliases": [item.to_dict() for item in self.aliases],
            "relocations": [item.to_dict() for item in self.relocations],
            "selector_resolution": self.selector_resolution.to_dict()
            if self.selector_resolution
            else None,
            "selector_preview_hex": self.selector_preview_hex,
            "selector_sha256": self.selector_sha256,
            "candidates": [item.to_dict() for item in self.candidates],
            "implementation_confirmed": self.implementation_confirmed,
            "implementation_status": self.implementation_status,
            "implementation_va": _hex(self.implementation_va),
            "implementation_evidence": self.implementation_evidence,
            "manifest_matches": self.manifest_matches,
            "manifest_selector_matches": self.manifest_selector_matches,
            "reservations": [item.to_dict() for item in self.reservations],
            "selector_column": self.selector_column(),
            "implementation_column": self.implementation_column(),
        }

    def selector_column(self) -> str:
        if not self.selector_located or self.selector_va is None:
            return "否：动态符号与 IRELATIVE addend 均未给出选择器地址"
        parts = [f"是：选择器 VA {_hex(self.selector_va)}"]
        if self.selector_symbols:
            parts.append(
                "符号 " + ", ".join(item.label() for item in self.selector_symbols)
            )
        dynamic = sum(len(item.dynamic_occurrences()) for item in self.relocations)
        section = sum(len(item.section_occurrences()) for item in self.relocations)
        if self.relocations:
            parts.append(
                f"IRELATIVE addend 一致；动态线索 {dynamic} 条/节头线索 {section} 条"
            )
        mapping = self.selector_resolution.primary if self.selector_resolution else None
        if mapping and mapping.file_offset is not None:
            parts.append(f"文件偏移 {_hex(mapping.file_offset)}")
        elif mapping and mapping.zero_fill:
            parts.append("地址落在零填充区")
        else:
            parts.append("未获得可读文件映射")
        return "；".join(parts)

    def implementation_column(self) -> str:
        if self.implementation_confirmed:
            return "是：" + self.implementation_evidence
        reason = self.implementation_evidence or self.implementation_status
        return f"未确认：{reason}"


@dataclass
class Inventory:
    source: str
    elf_class: int | None = None
    little_endian: bool | None = None
    machine: str | int | None = None
    has_section_headers: bool = False
    has_program_headers: bool = False
    records: list[IfuncRecord] = field(default_factory=list)
    reservations: list[Reservation] = field(default_factory=list)
    manifest_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "elf_class": self.elf_class,
            "little_endian": self.little_endian,
            "machine": self.machine,
            "has_section_headers": self.has_section_headers,
            "has_program_headers": self.has_program_headers,
            "selector_count": len(self.records),
            "implementation_confirmed_count": sum(
                item.implementation_confirmed for item in self.records
            ),
            "records": [item.to_dict() for item in self.records],
            "reservations": [item.to_dict() for item in self.reservations],
        }


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return value


def _format_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return _hex(value) or str(value)
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True)
    if hasattr(value, "to_dict"):
        return json.dumps(value.to_dict(), ensure_ascii=False, sort_keys=True)
    return str(value)


def _read_at(stream: IO[bytes], offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0:
        return b""
    stream.seek(offset)
    return stream.read(size) or b""


def _sha256(data: bytes) -> str | None:
    return hashlib.sha256(data).hexdigest() if data else None


def _make_mapping(
    *,
    source: str,
    vaddr: int,
    size: int,
    data: bytes,
    file_offset: int | None,
    zero_fill: bool,
    complete: bool,
    flags: int | None = None,
    **location: Any,
) -> ByteMapping:
    readable = None if flags is None else bool(flags & PF_R)
    writable = None if flags is None else bool(flags & PF_W)
    executable = None if flags is None else bool(flags & PF_X)
    if source == "section_header" and flags is not None:
        writable = bool(flags & SHF_WRITE)
        executable = bool(flags & SHF_EXECINSTR)
        readable = True
    return ByteMapping(
        source=source,
        vaddr=vaddr,
        size_requested=size,
        file_offset=file_offset,
        actual_size=len(data),
        complete=complete,
        zero_fill=zero_fill,
        readable_flag=readable,
        writable_flag=writable,
        executable_flag=executable,
        data=data,
        sha256=_sha256(data),
        preview_hex=_short_hex(data),
        **location,
    )


def resolve_address(
    elf: ELFFile, vaddr: int, size: int = PROBE_WINDOW
) -> AddressResolution:
    """Resolve a VA using PT_LOAD first, then allocated sections."""

    result = AddressResolution(vaddr=vaddr, size=size)
    if vaddr == 0:
        result.reservations.append(
            Reservation(
                "null_address",
                "virtual address is zero; it may be unfilled relocation data or padding",
                "warning",
                {"vaddr": 0},
            )
        )

    for segment_index, segment in enumerate(elf.iter_segments(type="PT_LOAD")):
        start = int(segment["p_vaddr"])
        file_size = int(segment["p_filesz"])
        memory_size = int(segment["p_memsz"])
        memory_end = start + memory_size
        if vaddr + size <= start or vaddr >= memory_end:
            continue

        offset_in_segment = vaddr - start
        data = bytearray()
        file_offset: int | None = None
        zero_fill = offset_in_segment >= file_size

        if 0 <= offset_in_segment < file_size:
            wanted = min(size, file_size - offset_in_segment)
            file_offset = int(segment["p_offset"]) + offset_in_segment
            raw = _read_at(elf.stream, file_offset, wanted)
            data.extend(raw)
            if len(raw) < wanted:
                result.reservations.append(
                    Reservation(
                        "short_file_read",
                        "PT_LOAD range is truncated in the delivered file",
                        "error",
                        {
                            "segment_index": segment_index,
                            "file_offset": file_offset,
                            "wanted": wanted,
                            "actual": len(raw),
                        },
                    )
                )

        if len(data) < size and vaddr + len(data) < memory_end:
            zero_count = min(size - len(data), memory_end - (vaddr + len(data)))
            if zero_count > 0:
                data.extend(b"\x00" * zero_count)

        result.mappings.append(
            _make_mapping(
                source="program_header",
                vaddr=vaddr,
                size=size,
                data=bytes(data),
                file_offset=file_offset,
                zero_fill=zero_fill,
                complete=len(data) == size,
                flags=int(segment["p_flags"]),
                segment_index=segment_index,
            )
        )

    for section_index, section in enumerate(elf.iter_sections()):
        try:
            section_type = section["sh_type"]
            flags = int(section["sh_flags"])
            address = int(section["sh_addr"])
            section_size = int(section["sh_size"])
        except (ELFError, KeyError, TypeError, ValueError):
            continue
        if not (flags & SHF_ALLOC) or address == 0 or section_size == 0:
            continue
        if vaddr + size <= address or vaddr >= address + section_size:
            continue

        offset_in_section = vaddr - address
        zero = section_type == "SHT_NOBITS"
        data = b""
        file_offset: int | None = None
        if zero:
            available = min(size, section_size - offset_in_section)
            data = b"\x00" * max(0, available)
        else:
            wanted = min(size, section_size - offset_in_section)
            file_offset = int(section["sh_offset"]) + offset_in_section
            data = _read_at(elf.stream, file_offset, wanted)

        result.mappings.append(
            _make_mapping(
                source="section_header",
                vaddr=vaddr,
                size=size,
                data=data,
                file_offset=file_offset,
                zero_fill=zero,
                complete=len(data) == size,
                flags=flags,
                section_index=section_index,
                section_name=getattr(section, "name", None),
            )
        )

    for left_index, left in enumerate(result.mappings):
        for right in result.mappings[left_index + 1 :]:
            common = min(len(left.data), len(right.data), 16)
            if (
                left.file_offset == right.file_offset
                and left.data[:common] == right.data[:common]
            ):
                continue
            offsets_differ = left.file_offset != right.file_offset
            bytes_differ = bool(common and left.data[:common] != right.data[:common])
            if bytes_differ:
                result.contradictory = True
            result.reservations.append(
                Reservation(
                    "mapping_contradiction",
                    "two address mappings disagree"
                    + ("; file offsets differ" if offsets_differ else "")
                    + ("; mapped bytes differ" if bytes_differ else ""),
                    "error" if bytes_differ else "warning",
                    {
                        "vaddr": vaddr,
                        "left": left.to_dict(),
                        "right": right.to_dict(),
                        "offsets_differ": offsets_differ,
                        "bytes_differ": bytes_differ,
                    },
                )
            )

    program_mappings = [
        item for item in result.mappings if item.source == "program_header"
    ]
    result.primary = (
        program_mappings[0]
        if program_mappings
        else result.mappings[0]
        if result.mappings
        else None
    )
    if result.primary is None:
        result.reservations.append(
            Reservation(
                "unmapped_vaddr",
                "virtual address is absent from PT_LOAD and allocated sections",
                "error",
                {"vaddr": vaddr, "size": size},
            )
        )
    return result


def _symbol_type_value(symbol: Any) -> int | None:
    type_info = symbol["st_info"]["type"]
    if isinstance(type_info, int):
        return type_info
    known = {
        "STT_NOTYPE": 0,
        "STT_OBJECT": 1,
        "STT_FUNC": 2,
        "STT_SECTION": 3,
        "STT_FILE": 4,
        "STT_COMMON": 5,
        "STT_TLS": 6,
        "STT_NUM": 7,
        "STT_RELC": 8,
        "STT_SRELC": 9,
        "STT_LOOS": 10,
        "STT_GNU_IFUNC": 10,
        "STT_HIOS": 12,
    }
    return known.get(str(type_info))


def _symbol_info(
    symbol: Any, index: int, source: str, dynsym_index: int | None
) -> SymbolInfo:
    type_value = _symbol_type_value(symbol)
    return SymbolInfo(
        name=getattr(symbol, "name", "") or "",
        index=index,
        source=source,
        st_value=int(symbol["st_value"]),
        st_size=int(symbol["st_size"]),
        type_name=symbol["st_info"]["type"],
        type_value=type_value,
        bind=symbol["st_info"]["bind"],
        shndx=symbol["st_shndx"],
        is_ifunc=type_value == 10,
        dynsym_section_index=dynsym_index,
    )


def _dynamic_segment(elf: ELFFile) -> tuple[int | None, Any]:
    for index, segment in enumerate(elf.iter_segments()):
        if segment["p_type"] == "PT_DYNAMIC":
            return index, segment
    return None, None


def _dynsym_section_index(elf: ELFFile) -> int | None:
    for index, section in enumerate(elf.iter_sections()):
        try:
            if section["sh_type"] == "SHT_DYNSYM":
                return index
        except (ELFError, KeyError):
            continue
    return None


def collect_dynamic_symbols(
    elf: ELFFile, inventory: Inventory
) -> tuple[list[SymbolInfo], Any]:
    dyn_index, dynamic = _dynamic_segment(elf)
    dynsym_index = _dynsym_section_index(elf)
    symbols: list[SymbolInfo] = []

    if dynamic is not None:
        try:
            for index, symbol in enumerate(dynamic.iter_symbols()):
                symbols.append(_symbol_info(symbol, index, "DT_SYMTAB", dynsym_index))
            return symbols, dynamic
        except (ELFError, IndexError, KeyError, ValueError) as exc:
            inventory.reservations.append(
                Reservation(
                    "dynamic_symtab_unreadable",
                    f"PT_DYNAMIC symbol table could not be parsed: {exc}",
                    "error",
                    {"segment_index": dyn_index},
                )
            )

    section = elf.get_section_by_name(".dynsym") if elf.num_sections() else None
    if section is not None and hasattr(section, "iter_symbols"):
        section_index = elf.get_section_index(".dynsym")
        for index, symbol in enumerate(section.iter_symbols()):
            symbols.append(_symbol_info(symbol, index, ".dynsym", section_index))
    elif section is not None:
        inventory.reservations.append(
            Reservation(
                "dynamic_symtab_unreadable",
                ".dynsym section exists but pyelftools did not expose a symbol table",
                "error",
                {"section_name": ".dynsym"},
            )
        )
    else:
        inventory.reservations.append(
            Reservation(
                "no_dynamic_symbols",
                "neither DT_SYMTAB nor a .dynsym section was readable",
                "error",
                {"dynamic_segment_index": dyn_index},
            )
        )
    return symbols, dynamic


def _raw_rela(
    location: int, info: int, addend: int, occurrence: RelaOccurrence
) -> dict[str, Any]:
    return {
        "r_offset": location,
        "r_info": info,
        "r_addend": addend,
        "r_sym": (info >> 32) & 0xFFFFFFFF,
        "r_type": info & 0xFFFFFFFF,
        "occurrences": [occurrence],
    }


def collect_rela_records(elf: ELFFile, inventory: Inventory) -> list[RelaEvidence]:
    raw_records: dict[tuple[int, int, int], dict[str, Any]] = {}

    def add_raw(raw: dict[str, Any]) -> None:
        key = (raw["r_offset"], raw["r_info"], raw["r_addend"])
        if key not in raw_records:
            raw_records[key] = raw
        else:
            raw_records[key]["occurrences"].extend(raw["occurrences"])

    _, dynamic = _dynamic_segment(elf)
    if dynamic is not None:
        try:
            tables = dynamic.get_relocation_tables()
        except (ELFError, StopIteration, KeyError, ValueError) as exc:
            inventory.reservations.append(
                Reservation(
                    "dynamic_relocations_unreadable",
                    f"dynamic relocation tags could not be parsed: {exc}",
                    "error",
                    {"source": "PT_DYNAMIC"},
                )
            )
            tables = {}

        for table_key, tag_name in (
            ("RELA", "DT_RELA"),
            ("JMPREL", "DT_JMPREL"),
        ):
            table = tables.get(table_key)
            if table is None or not table.is_RELA():
                continue
            try:
                table_vaddr, table_offset = dynamic.get_table_offset(tag_name)
                for index in range(table.num_relocations()):
                    reloc = table.get_relocation(index)
                    entry_offset = (
                        None if table_offset is None else table_offset + index * 24
                    )
                    occurrence = RelaOccurrence(
                        source="dynamic_table",
                        locator=f"{tag_name}[{index}]",
                        index=index,
                        entry_file_offset=entry_offset,
                        table_vaddr=table_vaddr,
                        table_file_offset=table_offset,
                    )
                    add_raw(
                        _raw_rela(
                            int(reloc["r_offset"]),
                            int(reloc["r_info"]),
                            int(reloc["r_addend"]),
                            occurrence,
                        )
                    )
            except (ELFError, IndexError, KeyError, ValueError) as exc:
                inventory.reservations.append(
                    Reservation(
                        "dynamic_rela_unreadable",
                        f"{tag_name} entry could not be parsed: {exc}",
                        "error",
                        {"tag": tag_name},
                    )
                )

    for section_index, section in enumerate(elf.iter_sections()):
        try:
            if section["sh_type"] != "SHT_RELA":
                continue
            section_offset = int(section["sh_offset"])
            section_name = getattr(section, "name", None)
            for index, reloc in enumerate(section.iter_relocations()):
                occurrence = RelaOccurrence(
                    source="section_header",
                    locator=f"{section_name or f'section#{section_index}'}[{index}]",
                    index=index,
                    entry_file_offset=section_offset + index * 24,
                    section_index=section_index,
                    section_name=section_name,
                )
                add_raw(
                    _raw_rela(
                        int(reloc["r_offset"]),
                        int(reloc["r_info"]),
                        int(reloc["r_addend"]),
                        occurrence,
                    )
                )
        except (ELFError, IndexError, KeyError, ValueError) as exc:
            inventory.reservations.append(
                Reservation(
                    "section_rela_unreadable",
                    f"SHT_RELA section could not be parsed: {exc}",
                    "error",
                    {"section_index": section_index},
                )
            )

    evidence_records: list[RelaEvidence] = []
    for raw in raw_records.values():
        occurrences: list[RelaOccurrence] = raw["occurrences"]
        distinct_offsets = {
            item.entry_file_offset
            for item in occurrences
            if item.entry_file_offset is not None
        }
        record = RelaEvidence(
            r_offset=raw["r_offset"],
            r_info=raw["r_info"],
            r_addend=raw["r_addend"],
            r_type=raw["r_type"],
            r_sym=raw["r_sym"],
            occurrences=occurrences,
        )
        if len(distinct_offsets) > 1:
            record.reservations.append(
                Reservation(
                    "rela_location_disagreement",
                    "merged RELA fields occur at different physical entry offsets",
                    "warning",
                    {
                        "r_offset": record.r_offset,
                        "r_addend": record.r_addend,
                        "entry_offsets": [
                            _hex(item) for item in sorted(distinct_offsets)
                        ],
                    },
                )
            )

        slot = resolve_address(elf, record.r_offset, 8)
        record.slot_resolution = slot
        mapping = slot.primary
        if mapping and len(mapping.data) == 8:
            record.stored_slot_value = struct.unpack("<Q", mapping.data)[0]
            if record.stored_slot_value == 0:
                record.reservations.append(
                    Reservation(
                        "zero_filled_address",
                        "IRELATIVE r_offset storage is zero in the delivered ELF; "
                        "this pre-relocation value cannot identify the implementation",
                        "info",
                        {
                            "r_offset": record.r_offset,
                            "mapped_file_offset": mapping.file_offset,
                            "zero_fill_mapping": mapping.zero_fill,
                        },
                    )
                )
            elif (
                record.stored_slot_value != record.r_addend
                and record.r_type == IRELATIVE_TYPE
            ):
                record.reservations.append(
                    Reservation(
                        "rela_addend_slot_mismatch",
                        "nonzero bytes at r_offset differ from RELA r_addend; "
                        "RELA addend remains the parsed relocation argument",
                        "warning",
                        {
                            "r_offset": record.r_offset,
                            "stored_slot_value": record.stored_slot_value,
                            "r_addend": record.r_addend,
                        },
                    )
                )
        record.reservations.extend(slot.reservations)
        evidence_records.append(record)
    return evidence_records


@dataclass
class ReturnTarget:
    target_va: int
    kind: str
    instruction_offset: int
    instruction_va: int
    direct_return: bool


def decode_direct_return_targets(code: bytes, base_va: int) -> list[ReturnTarget]:
    """Decode exact direct-return x86-64 patterns used by IFUNC selectors."""

    targets: list[ReturnTarget] = []
    for offset in range(len(code)):
        if offset + 8 <= len(code) and code[offset : offset + 3] == b"H\x8d\x05":
            displacement = _signed32(struct.unpack_from("<i", code, offset + 3)[0])
            instruction_va = base_va + offset
            target = instruction_va + 7 + displacement
            targets.append(
                ReturnTarget(
                    target,
                    "lea_rax_rip_relative",
                    offset,
                    instruction_va,
                    code[offset + 7] == 0xC3,
                )
            )

        if offset + 11 <= len(code) and code[offset : offset + 2] == b"H\xb8":
            target = struct.unpack_from("<Q", code, offset + 2)[0]
            targets.append(
                ReturnTarget(
                    target,
                    "mov_rax_imm64",
                    offset,
                    base_va + offset,
                    code[offset + 10] == 0xC3,
                )
            )

        if offset + 6 <= len(code) and code[offset] == 0xB8:
            target = struct.unpack_from("<I", code, offset + 1)[0]
            targets.append(
                ReturnTarget(
                    target,
                    "mov_eax_imm32",
                    offset,
                    base_va + offset,
                    offset + 5 < len(code) and code[offset + 5] == 0xC3,
                )
            )
    return targets


def _symbols_at_address(symbols: list[SymbolInfo], address: int) -> list[SymbolInfo]:
    return [
        symbol
        for symbol in symbols
        if symbol.st_value == address and symbol.st_value != 0
    ]


def _load_manifest(
    manifest: str | Path | dict[str, Any] | None,
) -> dict[str, Any] | None:
    if manifest is None or isinstance(manifest, dict):
        return manifest
    path = Path(manifest)
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise IfuncEvidenceError("manifest JSON must contain an object")
    return data


def _manifest_entries(manifest: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not manifest:
        return []
    for key in ("implementations", "artifacts", "entries"):
        entries = manifest.get(key)
        if isinstance(entries, list):
            return [item for item in entries if isinstance(item, dict)]
    return []


def _match_manifest(
    manifest: dict[str, Any] | None,
    target_va: int,
    resolution: AddressResolution | None,
    elf: ELFFile | None = None,
) -> dict[str, Any] | None:
    mapping = resolution.primary if resolution else None
    for entry in _manifest_entries(manifest):
        entry_va = entry.get("implementation_va", entry.get("va", entry.get("address")))
        try:
            if isinstance(entry_va, str):
                va_match = int(entry_va, 0) == target_va
            elif entry_va is not None:
                va_match = int(entry_va) == target_va
            else:
                va_match = False
        except (TypeError, ValueError):
            va_match = False

        expected_hash = entry.get("sha256")
        hash_match = False
        matched_hash_size: int | None = None
        expected_size = _address_value(entry.get("size"))
        if expected_hash:
            normalized_hash = str(expected_hash).lower()
            hash_candidates: list[tuple[int, str]] = []
            if mapping and mapping.complete and mapping.sha256:
                hash_candidates.append((resolution.size, mapping.sha256.lower()))
            if expected_size is not None and expected_size > 0:
                if mapping and len(mapping.data) >= expected_size:
                    hash_candidates.append(
                        (
                            expected_size,
                            hashlib.sha256(mapping.data[:expected_size]).hexdigest(),
                        )
                    )
                elif elf is not None:
                    sized = resolve_address(elf, target_va, expected_size)
                    sized_mapping = sized.primary
                    if (
                        sized_mapping
                        and sized_mapping.complete
                        and sized_mapping.sha256
                    ):
                        hash_candidates.append(
                            (expected_size, sized_mapping.sha256.lower())
                        )
            for candidate_size, candidate_hash in hash_candidates:
                if candidate_hash != normalized_hash:
                    continue
                if expected_size is not None and candidate_size != expected_size:
                    continue
                hash_match = True
                matched_hash_size = candidate_size
                break
        expected_preview = entry.get("preview_hex")
        preview_match = bool(
            mapping
            and expected_preview
            and mapping.preview_hex
            and str(expected_preview).lower() == mapping.preview_hex.lower()
        )
        if va_match or hash_match or preview_match:
            return {
                "entry": entry,
                "va_match": va_match,
                "hash_match": hash_match,
                "hash_size": matched_hash_size,
                "preview_match": preview_match,
            }
    return None


def _address_value(value: Any) -> int | None:
    try:
        if isinstance(value, str):
            return int(value, 0)
        if value is not None:
            return int(value)
    except (TypeError, ValueError):
        return None
    return None


def _manifest_selector_match(
    manifest: dict[str, Any] | None, selector_va: int
) -> dict[str, Any] | None:
    if not manifest:
        return None
    groups: list[Any] = []
    for key in ("selector_addresses", "selectors"):
        value = manifest.get(key)
        if isinstance(value, list):
            groups.extend(value)
    groups.extend(_manifest_entries(manifest))
    for entry in groups:
        if not isinstance(entry, dict):
            continue
        address = _address_value(
            entry.get(
                "selector_va", entry.get("selector_address", entry.get("address"))
            )
        )
        if address == selector_va:
            return {"entry": entry}
    return None


def analyze_fileobj(
    stream: IO[bytes],
    *,
    source: str = "<stream>",
    manifest: str | Path | dict[str, Any] | None = None,
) -> Inventory:
    """Build an evidence inventory from a readable binary ELF stream."""

    manifest_data = _load_manifest(manifest)
    elf = ELFFile(stream)
    machine = elf.header.get("e_machine")
    if (
        elf.elfclass != 64
        or not elf.little_endian
        or machine not in X86_64_MACHINE_VALUES
    ):
        raise UnsupportedArchitectureError(
            "supports little-endian ELF64 EM_X86_64 only; got "
            f"class={elf.elfclass}, little_endian={elf.little_endian}, machine={machine!r}"
        )

    inventory = Inventory(
        source=source,
        elf_class=elf.elfclass,
        little_endian=elf.little_endian,
        machine=machine,
        has_section_headers=elf.num_sections() > 0 and elf.header["e_shoff"] != 0,
        has_program_headers=elf.num_segments() > 0 and elf.header["e_phoff"] != 0,
        manifest_path=(
            str(manifest)
            if manifest is not None and not isinstance(manifest, dict)
            else None
        ),
    )

    symbols, _ = collect_dynamic_symbols(elf, inventory)
    relocations = collect_rela_records(elf, inventory)
    ifunc_addresses = {
        symbol.st_value
        for symbol in symbols
        if symbol.is_ifunc and symbol.st_value != 0
    }
    rela_by_addend: dict[int, list[RelaEvidence]] = {}
    for reloc in relocations:
        if reloc.r_type != IRELATIVE_TYPE:
            continue
        rela_by_addend.setdefault(reloc.r_addend, []).append(reloc)
        if reloc.r_addend != 0:
            ifunc_addresses.add(reloc.r_addend)

    for selector_va in sorted(ifunc_addresses):
        record = IfuncRecord(key=f"selector@{selector_va:x}", selector_va=selector_va)
        address_symbols = _symbols_at_address(symbols, selector_va)
        ifunc_like = [
            item
            for item in address_symbols
            if item.is_ifunc
            or item.type_value == 10
            or item.type_name in IFUNC_TYPE_VALUES
        ]
        record.selector_symbols = ifunc_like
        primary_symbol = ifunc_like[0] if ifunc_like else None
        record.aliases = [
            item for item in address_symbols if item is not primary_symbol
        ]
        record.relocations = rela_by_addend.get(selector_va, [])
        record.selector_located = bool(record.selector_symbols or record.relocations)
        for reloc in record.relocations:
            record.reservations.extend(reloc.reservations)

        selector_manifest = _manifest_selector_match(manifest_data, selector_va)
        if selector_manifest:
            record.manifest_selector_matches.append(selector_manifest)
            record.reservations.append(
                Reservation(
                    "manifest_selector_only",
                    "version manifest matches the selector address only; this cannot "
                    "confirm which implementation was dispatched",
                    "warning",
                    {
                        "selector_va": selector_va,
                        "manifest_entry": selector_manifest["entry"],
                    },
                )
            )

        if record.aliases:
            record.reservations.append(
                Reservation(
                    "symbol_aliases",
                    "multiple dynamic symbols share the selector address; "
                    "name-only conclusions are ambiguous",
                    "warning",
                    {
                        "selector_va": selector_va,
                        "aliases": [item.label() for item in record.aliases],
                        "ifunc_symbols": [
                            item.label() for item in record.selector_symbols
                        ],
                    },
                )
            )

        if not record.selector_symbols:
            record.reservations.append(
                Reservation(
                    "irelative_without_ifunc_symbol",
                    "IRELATIVE addend locates a selector but no STT_GNU_IFUNC "
                    "dynamic symbol matches it",
                    "warning",
                    {"selector_va": selector_va},
                )
            )
        if not record.relocations:
            record.reservations.append(
                Reservation(
                    "ifunc_without_irelative",
                    "no R_X86_64_IRELATIVE relocation has a matching r_addend",
                    "warning",
                    {"selector_va": selector_va},
                )
            )

        known_sizes = [
            symbol.st_size
            for symbol in record.selector_symbols
            if 0 < symbol.st_size <= MAX_SELECTOR_BYTES
        ]
        if known_sizes:
            scan_size = max(known_sizes)
        else:
            scan_size = SCAN_WINDOW
            record.reservations.append(
                Reservation(
                    "selector_size_unknown",
                    f"selector st_size absent/too large; scanned {SCAN_WINDOW} bytes",
                    "info",
                    {"selector_va": selector_va},
                )
            )

        selector_resolution = resolve_address(elf, selector_va, scan_size)
        record.selector_resolution = selector_resolution
        record.reservations.extend(selector_resolution.reservations)
        mapping = selector_resolution.primary
        if mapping and mapping.data:
            record.selector_preview_hex = mapping.preview_hex
            record.selector_sha256 = mapping.sha256
            record.selector_mapping_verified = (
                mapping.file_offset is not None
                and not selector_resolution.contradictory
                and any(mapping.data[:16])
            )
            if mapping.zero_fill or not any(mapping.data[: min(16, len(mapping.data))]):
                record.reservations.append(
                    Reservation(
                        "zero_filled_address",
                        "selector address maps to zero-filled bytes; it cannot "
                        "evidence executable dispatch code",
                        "error",
                        {
                            "selector_va": selector_va,
                            "source": mapping.source,
                            "file_offset": mapping.file_offset,
                            "zero_fill_mapping": mapping.zero_fill,
                        },
                    )
                )

            for target in decode_direct_return_targets(mapping.data, selector_va):
                resolution = resolve_address(elf, target.target_va, PROBE_WINDOW)
                candidate = ImplementationCandidate(
                    target_va=target.target_va,
                    kind=target.kind,
                    instruction_offset=target.instruction_offset,
                    instruction_va=target.instruction_va,
                    direct_return=target.direct_return,
                    resolution=resolution,
                    implementation_symbols=_symbols_at_address(
                        symbols, target.target_va
                    ),
                    manifest_match=_match_manifest(
                        manifest_data, target.target_va, resolution, elf
                    ),
                )
                record.candidates.append(candidate)
                record.reservations.extend(resolution.reservations)
                if candidate.manifest_match:
                    record.manifest_matches.append(candidate.manifest_match)
        else:
            record.reservations.append(
                Reservation(
                    "selector_bytes_unavailable",
                    "selector VA has no readable byte mapping; implementation "
                    "cannot be confirmed",
                    "error",
                    {"selector_va": selector_va},
                )
            )

        strong = [
            candidate
            for candidate in record.candidates
            if candidate.direct_return and candidate.kind.startswith(("lea_", "mov_"))
        ]
        unique_targets = sorted({candidate.target_va for candidate in strong})
        usable = [candidate for candidate in strong if candidate.mapped_nonzero]
        error_conflict = any(
            item.code == "mapping_contradiction" and item.severity == "error"
            for item in record.reservations
        )

        if selector_va == 0:
            record.implementation_status = "null_selector"
            record.implementation_evidence = "selector address is zero"
        elif error_conflict:
            record.implementation_status = "contradictory_mapping"
            record.implementation_evidence = (
                "selector/implementation mappings contain contradictory bytes"
            )
        elif not strong:
            if record.candidates:
                record.implementation_status = "indirect_or_nonterminal_reference"
                record.implementation_evidence = (
                    "found address reference but no direct LEA/MOV followed by RET; "
                    "control flow is not proven"
                )
            else:
                record.implementation_status = "direct_return_not_decoded"
                record.implementation_evidence = (
                    "no exact x86-64 LEA/MOV direct-return pattern was parsed"
                )
        elif len(unique_targets) > 1:
            record.implementation_status = "multiple_dispatch_targets"
            record.implementation_evidence = (
                "selector contains multiple directly returned targets "
                + ", ".join(_hex(item) or "?" for item in unique_targets)
                + "; static bytes do not establish which target runs on a device"
            )
        elif not usable:
            record.implementation_status = "target_not_verified"
            target_va = unique_targets[0] if unique_targets else None
            record.implementation_evidence = (
                f"direct target {_hex(target_va)} lacks a consistent "
                "readable/executable non-zero mapping"
            )
        else:
            candidate = usable[0]
            mapping = candidate.resolution.primary if candidate.resolution else None
            if mapping and mapping.executable_flag is False:
                record.reservations.append(
                    Reservation(
                        "implementation_mapping_not_executable",
                        "直接实现目标可从文件映射读取，但其 PT_LOAD/节头未声明可执行权限",
                        "warning",
                        {
                            "implementation_va": candidate.target_va,
                            "mapping_source": mapping.source,
                            "segment_index": mapping.segment_index,
                            "section_index": mapping.section_index,
                        },
                    )
                )
            record.implementation_confirmed = True
            record.implementation_status = "confirmed_direct_return"
            record.implementation_va = candidate.target_va
            offset = mapping.file_offset if mapping else None
            hash_value = mapping.sha256 if mapping else None
            source = mapping.source if mapping else "mapping"
            record.implementation_evidence = (
                f"unique direct-return target {_hex(candidate.target_va)} via "
                f"{candidate.kind} at selector+{_hex(candidate.instruction_offset)}; "
                f"{source} file offset {_hex(offset)}; sha256:{hash_value}"
            )
            if candidate.manifest_match and candidate.manifest_match.get("hash_match"):
                entry = candidate.manifest_match["entry"]
                label = entry.get("version", entry.get("name", entry.get("id", "")))
                record.implementation_evidence += f"; manifest sha256 match {label}"

        inventory.records.append(record)

    return inventory


def analyze_path(
    path: str | Path,
    *,
    manifest: str | Path | dict[str, Any] | None = None,
) -> Inventory:
    path = Path(path)
    with path.open("rb") as handle:
        return analyze_fileobj(handle, source=str(path), manifest=manifest)


def analyze_bytes(
    data: bytes,
    *,
    source: str = "<bytes>",
    manifest: dict[str, Any] | None = None,
) -> Inventory:
    return analyze_fileobj(io.BytesIO(data), source=source, manifest=manifest)


def _markdown_escape(value: Any) -> str:
    if not isinstance(value, str):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = value
    return text.replace("|", BACKSLASH + "|").replace(NL, "<br>")


def render_markdown(inventory: Inventory) -> str:
    lines = [
        "# GNU IFUNC 分派证据验收稿",
        "",
        f"- 来源：{inventory.source}",
        f"- 格式：ELF{class_name(inventory.elf_class)} {inventory.machine} "
        f"little_endian={inventory.little_endian}",
        f"- 节头：{inventory.has_section_headers}；"
        f"Program headers：{inventory.has_program_headers}",
        "- 证据边界：‘定位到选择器’只证明符号/重定位给出 resolver 地址，"
        "不能替代实际实现证据。",
        "",
        "| 对象 | 定位到选择器 | 有证据确认实际实现 | RELA 两条定位线索 | 可定位保留意见 |",
        "|---|---|---|---|---|",
    ]
    for record in inventory.records:
        names = (
            ", ".join(item.label() for item in record.selector_symbols) or record.key
        )
        rela_clues: list[str] = []
        for reloc in record.relocations:
            dynamic = (
                "; ".join(item.locator for item in reloc.dynamic_occurrences())
                or "动态表未找到"
            )
            section = (
                "; ".join(item.locator for item in reloc.section_occurrences())
                or "节头未找到"
            )
            rela_clues.append(
                f"{_hex(reloc.r_offset)} <- addend {_hex(reloc.r_addend)}; "
                f"动态: {dynamic}; 节: {section}"
            )
        reservations = [item.render() for item in record.reservations]
        row = "| {names} | {selector} | {implementation} | {rela} | {caveats} |".format(
            names=_markdown_escape(names),
            selector=_markdown_escape(record.selector_column()),
            implementation=_markdown_escape(record.implementation_column()),
            rela=_markdown_escape(NL.join(rela_clues) or "无 IRELATIVE"),
            caveats=_markdown_escape(NL.join(reservations) or "无"),
        )
        lines.append(row)
    if inventory.reservations:
        lines.extend(["", "## 文件级保留意见", ""])
        lines.extend(f"- {item.render()}" for item in inventory.reservations)
    lines.extend(
        [
            "",
            "## 结论口径",
            "",
            "- selector_located=true 不得推出 implementation_confirmed=true。",
            "- 多目标选择器只能列出静态候选；旧型号/新型号实际分支需要运行时或清单证据。",
            "- 零填充 GOT/选择器地址、别名和映射冲突均保留定位字段。",
            "",
        ]
    )
    return NL.join(lines)


def class_name(elf_class: int | None) -> str:
    return "64" if elf_class == 64 else str(elf_class)


def render_json(inventory: Inventory) -> str:
    return json.dumps(inventory.to_dict(), ensure_ascii=False, indent=2)


def render_csv(inventory: Inventory) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "object",
            "selector_located",
            "selector_column",
            "implementation_confirmed",
            "implementation_column",
            "selector_va",
            "implementation_va",
            "dynamic_rela_locators",
            "section_rela_locators",
            "reservation_codes",
        ]
    )
    for record in inventory.records:
        dynamic = [
            occurrence.locator
            for reloc in record.relocations
            for occurrence in reloc.dynamic_occurrences()
        ]
        section = [
            occurrence.locator
            for reloc in record.relocations
            for occurrence in reloc.section_occurrences()
        ]
        writer.writerow(
            [
                ",".join(item.label() for item in record.selector_symbols)
                or record.key,
                record.selector_located,
                record.selector_column(),
                record.implementation_confirmed,
                record.implementation_column(),
                _hex(record.selector_va),
                _hex(record.implementation_va),
                ";".join(dynamic),
                ";".join(section),
                ";".join(item.code for item in record.reservations),
            ]
        )
    return buffer.getvalue()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only x86-64 IFUNC dispatch evidence inventory."
    )
    parser.add_argument("elf", nargs="?", help="device ELF binary/shared object")
    parser.add_argument("--manifest", help="optional JSON version/artifact manifest")
    parser.add_argument(
        "--format", choices=("markdown", "json", "csv"), default="markdown"
    )
    parser.add_argument("-o", "--output", help="write report here instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.elf:
        build_parser().print_help(sys.stderr)
        return 2
    try:
        inventory = analyze_path(args.elf, manifest=args.manifest)
        if args.format == "json":
            report = render_json(inventory)
        elif args.format == "csv":
            report = render_csv(inventory)
        else:
            report = render_markdown(inventory)
        if args.output:
            Path(args.output).write_text(report, encoding="utf-8")
        else:
            sys.stdout.write(report)
        return 0
    except (OSError, IfuncEvidenceError, ELFError) as exc:
        print(f"ifunc-evidence: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
