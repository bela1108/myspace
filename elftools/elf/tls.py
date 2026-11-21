#-------------------------------------------------------------------------------
# elftools: elf/tls.py
#
# Static description of an ELF thread-local storage layout.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
"""Static, file-oriented description of ELF TLS.

The important distinction made here is the one between:

* the initialization template stored in the file (``PT_TLS.p_filesz`` bytes at
  ``PT_TLS.p_offset``),
* the per-thread zero-filled tail (``PT_TLS.p_memsz - PT_TLS.p_filesz`` bytes
  which have no file offset at all), and
* addresses outside the per-thread TLS block.

ELF TLS symbols (``STT_TLS``) use a TLS-block-relative ``st_value``; they do
not use the ordinary ``section address + st_value`` file mapping.  The report
therefore never falls back to a ``PT_LOAD`` base address when translating a
TLS symbol to file bytes.

The module deliberately keeps unknown information unknown.  Missing section
headers, absent symbol tables, zero-sized symbols, truncated files, and gaps
between known symbols are reported as explicit unconfirmed ranges instead of
being guessed from neighbouring bytes.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Iterable, Sequence

from ..common.exceptions import ELFError
from ..common.utils import struct_parse
from .constants import SH_FLAGS
from .elffile import ELFFile


Interval = tuple[int, int]

_STT_TLS = 'STT_TLS'
_SHT_NOBITS = 'SHT_NOBITS'
_SHT_STRTAB = 'SHT_STRTAB'
_SHT_SYMTAB_TYPES = ('SHT_SYMTAB', 'SHT_DYNSYM', 'SHT_SUNW_LDYNSYM')

__all__ = [
    'TLSDescription',
    'TLSInfo',
    'StaticTLSDescription',
    'TLSInput',
    'describe_tls',
    'get_tls_info',
    'get_tls_description',
    'tls_info',
    'analyze_tls',
    'describe_tls_layout',
    'compare_tls',
    'compare_tls_files',
    'format_tls_description',
    'format_tls_comparison',
]


def _clip_interval(start: int, end: int, low: int, high: int) -> Interval | None:
    """Return the intersection of [start, end) and [low, high), or None."""
    clipped_start = max(start, low)
    clipped_end = min(end, high)
    if clipped_start >= clipped_end:
        return None
    return clipped_start, clipped_end


def _merge_intervals(intervals: Iterable[Interval]) -> list[Interval]:
    ordered = sorted((start, end) for start, end in intervals if start < end)
    if not ordered:
        return []
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        previous_start, previous_end = merged[-1]
        if start <= previous_end:
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return merged


def _subtract_intervals(
    base: Sequence[Interval],
    covered: Sequence[Interval],
) -> list[Interval]:
    covered_merged = _merge_intervals(covered)
    result: list[Interval] = []
    for base_start, base_end in base:
        cursor = base_start
        for cover_start, cover_end in covered_merged:
            if cover_end <= cursor:
                continue
            if cover_start >= base_end:
                break
            if cover_start > cursor:
                result.append((cursor, min(cover_start, base_end)))
            cursor = max(cursor, cover_end)
            if cursor >= base_end:
                break
        if cursor < base_end:
            result.append((cursor, base_end))
    return result


def _interval_json(interval: Interval | None) -> list[int] | None:
    return None if interval is None else [interval[0], interval[1]]


def _intervals_json(intervals: Iterable[Interval]) -> list[list[int]]:
    return [[start, end] for start, end in intervals]


def _available_file_range(elf: ELFFile, offset: int, size: int) -> Interval | None:
    """Return the file-backed part of [offset, offset + size), if any."""
    if offset < 0 or size <= 0:
        return None
    end = offset + size
    available_end = min(end, elf.stream_len)
    if available_end <= offset:
        return None
    return offset, available_end


def _read_file_range(elf: ELFFile, offset: int, size: int) -> bytes:
    available = _available_file_range(elf, offset, size)
    if available is None:
        return b''
    start, end = available
    try:
        elf.stream.seek(start)
        data = elf.stream.read(end - start)
    except (OSError, ValueError):
        return b''
    return data


def _bytes_preview(data: bytes, limit: int = 32) -> str:
    return data[:limit].hex()


def _cstring_at(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ''
    end = data.find(b'\0', offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode('utf-8', errors='replace')


def _section_table(elf: ELFFile, warnings: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse section headers directly, without relying on section names.

    Direct parsing is intentional: a partially trimmed section-header table or
    an unreadable section-name string table must not hide a still-readable
    ``.tdata``/``.tbss`` header.
    """
    status: dict[str, Any] = {
        'present': False,
        'complete': False,
        'count': None,
        'parsed': 0,
        'names_available': False,
        'reason': None,
    }
    e_shoff = int(elf['e_shoff'])
    if e_shoff == 0:
        status['reason'] = 'e_shoff is 0; section headers are absent'
        return [], status

    status['present'] = True
    shdr_size = elf.structs.Elf_Shdr.sizeof()
    shentsize = int(elf['e_shentsize'])
    if shentsize < shdr_size:
        status['reason'] = f'e_shentsize ({shentsize}) is smaller than Elf_Shdr ({shdr_size})'
        return [], status

    try:
        count = int(elf.num_sections())
    except (ELFError, OSError, ValueError) as error:
        status['reason'] = f'cannot determine section count: {error}'
        warnings.append(status['reason'])
        return [], status

    status['count'] = count
    if count <= 0:
        status['complete'] = True
        status['reason'] = 'section-header table is empty'
        return [], status

    table_end = e_shoff + count * shentsize
    if table_end > elf.stream_len:
        status['reason'] = (
            f'section-header table needs bytes up to {table_end}, '
            f'but the file is only {elf.stream_len} bytes')
        warnings.append(status['reason'])

    headers: list[dict[str, Any]] = []
    for index in range(count):
        header_offset = e_shoff + index * shentsize
        if header_offset + shdr_size > elf.stream_len:
            break
        try:
            header = struct_parse(
                elf.structs.Elf_Shdr, elf.stream, stream_pos=header_offset)
        except ELFError as error:
            warnings.append(f'cannot parse section header {index}: {error}')
            break
        headers.append({'index': index, 'header': header, 'name': ''})

    # Resolve names only when the complete string table is in the file.  A
    # truncated name table does not invalidate the numeric fields above.
    records = headers
    shstrndx = int(elf.get_shstrndx()) if headers else 0
    if 0 <= shstrndx < len(records):
        shstr_header = records[shstrndx]['header']
        if shstr_header['sh_type'] == _SHT_STRTAB:
            shstr_start = int(shstr_header['sh_offset'])
            shstr_size = int(shstr_header['sh_size'])
            if _available_file_range(elf, shstr_start, shstr_size) == (
                    shstr_start, shstr_start + shstr_size):
                shstr = _read_file_range(elf, shstr_start, shstr_size)
                status['names_available'] = True
                for record in records:
                    record['name'] = _cstring_at(shstr, int(record['header']['sh_name']))
            else:
                status['reason'] = 'section-name string table is truncated'
                warnings.append(status['reason'])

    status['parsed'] = len(records)
    status['complete'] = len(records) == count and table_end <= elf.stream_len
    if not status['complete'] and status['reason'] is None:
        status['reason'] = f'only {len(records)} of {count} section headers are readable'
    return records, status


def _program_headers(elf: ELFFile, warnings: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        count = int(elf.num_segments())
    except (ELFError, OSError, ValueError) as error:
        warnings.append(f'cannot determine program-header count: {error}')
        return records

    phdr_size = elf.structs.Elf_Phdr.sizeof()
    phentsize = int(elf['e_phentsize'])
    e_phoff = int(elf['e_phoff'])
    if count and e_phoff == 0:
        warnings.append(
            'e_phoff is 0 but e_phnum is nonzero; program headers are absent')
        return records
    if count and phentsize < phdr_size:
        warnings.append(
            f'e_phentsize ({phentsize}) is smaller than Elf_Phdr ({phdr_size})')
        return records

    for index in range(count):
        header_offset = e_phoff + index * phentsize
        if header_offset + phdr_size > elf.stream_len:
            warnings.append(
                f'program header {index} lies beyond end of file '
                f'({elf.stream_len} bytes)')
            break
        try:
            header = struct_parse(
                elf.structs.Elf_Phdr, elf.stream, stream_pos=header_offset)
        except ELFError as error:
            warnings.append(f'cannot parse program header {index}: {error}')
            break
        records.append({'index': index, 'header': header})
    return records


def _segment_report(
    elf: ELFFile,
    record: dict[str, Any],
    *,
    verify: bool,
    include_bytes: bool,
) -> dict[str, Any]:
    header = record['header']
    p_offset = int(header['p_offset'])
    p_vaddr = int(header['p_vaddr'])
    p_filesz = int(header['p_filesz'])
    p_memsz = int(header['p_memsz'])
    p_align = int(header['p_align'])

    if p_filesz == 0:
        available: Interval | None = (p_offset, p_offset)
        template_complete = True
    else:
        available = _available_file_range(elf, p_offset, p_filesz)
        template_complete = (available == (p_offset, p_offset + p_filesz))
    full_range = (p_offset, p_offset + p_filesz)
    missing_range = None
    if available is None:
        missing_range = full_range
    elif available[1] < full_range[1]:
        missing_range = (available[1], full_range[1])

    template_data = b''
    sha256 = None
    sha256_available = None
    if (verify or include_bytes) and available is not None:
        template_data = _read_file_range(
            elf, available[0], available[1] - available[0])
        if verify:
            sha256_available = hashlib.sha256(template_data).hexdigest()
            if template_complete:
                sha256 = sha256_available

    effective_template_size = min(p_filesz, p_memsz)
    zero_fill_start = effective_template_size
    zero_fill_size = max(0, p_memsz - effective_template_size)

    template = {
        'tls_range': [0, p_filesz],
        'tls_size': p_filesz,
        'file_range': [p_offset, p_offset + p_filesz],
        'file_size': p_filesz,
        'available_file_range': _interval_json(available),
        'available_size': 0 if available is None else available[1] - available[0],
        'missing_file_range': _interval_json(missing_range),
        'complete_in_file': template_complete,
        'source': 'file',
        'sha256': sha256,
        'sha256_available': sha256_available,
    }
    if include_bytes:
        template['data_hex'] = _bytes_preview(template_data, limit=p_filesz)

    zero_fill = {
        'tls_range': [zero_fill_start, p_memsz],
        'tls_size': zero_fill_size,
        'file_range': None,
        'memory_range': [p_vaddr + zero_fill_start, p_vaddr + p_memsz],
        'in_file': False,
        'source': 'zero_fill',
    }

    return {
        'index': record['index'],
        'type': 'PT_TLS',
        'p_type': 'PT_TLS',
        'p_offset': p_offset,
        'p_vaddr': p_vaddr,
        'p_paddr': int(header['p_paddr']),
        'p_flags': int(header['p_flags']),
        'p_filesz': p_filesz,
        'p_memsz': p_memsz,
        'p_align': p_align,
        'offset': p_offset,
        'vaddr': p_vaddr,
        'filesz': p_filesz,
        'memsz': p_memsz,
        'align': p_align,
        'memory_range': [p_vaddr, p_vaddr + p_memsz],
        'file_backed_memory_range': [
            p_vaddr, p_vaddr + effective_template_size],
        'not_in_file_memory_range': [
            p_vaddr + effective_template_size, p_vaddr + p_memsz],
        'template': template,
        'zero_fill': zero_fill,
    }


def _section_report(
    elf: ELFFile,
    record: dict[str, Any],
    primary: dict[str, Any] | None,
    *,
    verify: bool,
) -> dict[str, Any]:
    header = record['header']
    sh_type = header['sh_type']
    sh_flags = int(header['sh_flags'])
    sh_addr = int(header['sh_addr'])
    sh_offset = int(header['sh_offset'])
    sh_size = int(header['sh_size'])
    initialized = sh_type != _SHT_NOBITS

    tls_offset = None
    if primary is not None and elf['e_type'] != 'ET_REL':
        candidate = sh_addr - int(primary['p_vaddr'])
        if candidate >= 0:
            tls_offset = candidate

    tls_range = None
    if tls_offset is not None:
        tls_range = (tls_offset, tls_offset + sh_size)

    template_overlap = None
    zero_fill_overlap = None
    outside_tls = None
    expected_file_range = None
    if primary is not None and tls_range is not None:
        template_overlap = _clip_interval(
            tls_range[0], tls_range[1], 0, int(primary['p_filesz']))
        zero_fill_overlap = _clip_interval(
            tls_range[0], tls_range[1],
            int(primary['p_filesz']), int(primary['p_memsz']))
        outside_tls = _clip_interval(
            tls_range[0], tls_range[1], int(primary['p_memsz']),
            max(tls_range[1], int(primary['p_memsz'])))
        if template_overlap is not None:
            expected_file_range = (
                int(primary['p_offset']) + template_overlap[0],
                int(primary['p_offset']) + template_overlap[1],
            )

    file_range = None
    available_file_range = None
    missing_file_range = None
    matches_pt_tls = None
    file_sha256 = None
    source = 'unavailable'
    if initialized:
        file_range = (sh_offset, sh_offset + sh_size)
        available_file_range = _available_file_range(elf, sh_offset, sh_size)
        if available_file_range is None:
            missing_file_range = file_range
        elif available_file_range[1] < file_range[1]:
            missing_file_range = (available_file_range[1], file_range[1])

        if verify and available_file_range is not None:
            section_data = _read_file_range(
                elf,
                available_file_range[0],
                available_file_range[1] - available_file_range[0])
            file_sha256 = hashlib.sha256(section_data).hexdigest()

        if (    verify and expected_file_range is not None and
                available_file_range is not None and
                available_file_range == file_range):
            expected_available = _available_file_range(
                elf, expected_file_range[0],
                expected_file_range[1] - expected_file_range[0])
            if expected_available == expected_file_range:
                expected_data = _read_file_range(
                    elf, expected_file_range[0],
                    expected_file_range[1] - expected_file_range[0])
                section_data = _read_file_range(
                    elf, file_range[0], file_range[1] - file_range[0])
                matches_pt_tls = section_data == expected_data

        if (    tls_range is not None and primary is not None and
                tls_range[0] >= 0 and
                tls_range[1] <= int(primary['p_filesz'])):
            source = 'file'
        elif template_overlap is not None and zero_fill_overlap is not None:
            source = 'mixed'
        elif zero_fill_overlap is not None:
            source = 'zero_fill'
        elif tls_offset is None and primary is None and elf['e_type'] == 'ET_REL':
            source = 'section_data'
        elif tls_offset is None:
            source = 'unknown'
    else:
        if tls_offset is None:
            source = 'zero_fill_unknown_offset'
        else:
            source = 'zero_fill'

    return {
        'index': record['index'],
        'name': record['name'],
        'type': sh_type,
        'sh_type': sh_type,
        'sh_name': int(header['sh_name']),
        'sh_flags': sh_flags,
        'sh_addr': sh_addr,
        'sh_offset': sh_offset,
        'sh_size': sh_size,
        'sh_addralign': int(header['sh_addralign']),
        'tls': bool(sh_flags & SH_FLAGS.SHF_TLS),
        'initialized': initialized,
        'file_backed': initialized,
        'tls_offset': tls_offset,
        'tls_range': _interval_json(tls_range),
        'template_overlap': _interval_json(template_overlap),
        'zero_fill_overlap': _interval_json(zero_fill_overlap),
        'outside_tls': _interval_json(outside_tls),
        'fully_within_tls': (
            None if tls_range is None or primary is None
            else outside_tls is None),
        'file_range': _interval_json(file_range),
        'available_file_range': _interval_json(available_file_range),
        'missing_file_range': _interval_json(missing_file_range),
        'expected_pt_tls_file_range': _interval_json(expected_file_range),
        'matches_pt_tls': matches_pt_tls,
        'sha256': file_sha256,
        'in_file': initialized and file_range is not None,
        'source': source,
    }


def _symbol_tables(
    elf: ELFFile,
    sections: Sequence[dict[str, Any]],
    warnings: list[str],
) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    sym_size = elf.structs.Elf_Sym.sizeof()
    for section in sections:
        header = section['header']
        if header['sh_type'] not in _SHT_SYMTAB_TYPES:
            continue
        entsize = int(header['sh_entsize'])
        if entsize < sym_size:
            warnings.append(
                f"symbol table {section['name'] or section['index']} has "
                f'invalid entry size {entsize}')
            continue

        strtab_index = int(header['sh_link'])
        strtab_data = b''
        names_available = False
        if 0 <= strtab_index < len(sections):
            strtab_header = sections[strtab_index]['header']
            if strtab_header['sh_type'] == _SHT_STRTAB:
                strtab_offset = int(strtab_header['sh_offset'])
                strtab_size = int(strtab_header['sh_size'])
                if _available_file_range(elf, strtab_offset, strtab_size) == (
                        strtab_offset, strtab_offset + strtab_size):
                    strtab_data = _read_file_range(elf, strtab_offset, strtab_size)
                    names_available = True
                else:
                    warnings.append(
                        f"string table for {section['name'] or section['index']} "
                        'is truncated')
        if not names_available:
            warnings.append(
                f"symbol names for {section['name'] or section['index']} "
                'are unavailable')

        count = int(header['sh_size']) // entsize
        entries: list[dict[str, Any]] = []
        for index in range(count):
            entry_offset = int(header['sh_offset']) + index * entsize
            if entry_offset + sym_size > elf.stream_len:
                warnings.append(
                    f"symbol table {section['name'] or section['index']} is "
                    f'truncated at symbol {index}')
                break
            try:
                entry = struct_parse(
                    elf.structs.Elf_Sym, elf.stream, stream_pos=entry_offset)
            except ELFError as error:
                warnings.append(
                    f"cannot parse symbol {index} in "
                    f"{section['name'] or section['index']}: {error}")
                break
            entries.append({
                'index': index,
                'entry': entry,
                'name': _cstring_at(strtab_data, int(entry['st_name'])),
            })
        tables.append({
            'section_index': section['index'],
            'name': section['name'],
            'type': header['sh_type'],
            'symbols': entries,
            'names_available': names_available,
            'complete': len(entries) == count,
            'count': count,
        })
    return tables


def _symbol_report(
    elf: ELFFile,
    table: dict[str, Any],
    record: dict[str, Any],
    primary: dict[str, Any] | None,
    sections: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    entry = record['entry']
    value = int(entry['st_value'])
    size = int(entry['st_size'])
    shndx = entry['st_shndx']
    section_name = None
    section_matches_pt_tls = None
    if isinstance(shndx, int) and 0 <= shndx < len(sections):
        section_name = sections[shndx]['name']
        section_matches_pt_tls = sections[shndx].get('matches_pt_tls')

    report: dict[str, Any] = {
        'table': table['name'],
        'table_section_index': table['section_index'],
        'index': record['index'],
        'name': record['name'],
        'st_name': int(entry['st_name']),
        'st_value': value,
        'st_size': size,
        'st_shndx': shndx,
        'section': section_name,
        'section_matches_pt_tls': section_matches_pt_tls,
        'type': entry['st_info']['type'],
        'bind': entry['st_info']['bind'],
        'visibility': entry['st_other']['visibility'],
        'tls_offset': value if elf['e_type'] != 'ET_REL' else None,
        'tls_range': None,
        'file_range': None,
        'file_sha256': None,
        'file_backed_tls_range': None,
        'zero_fill_tls_range': None,
        'outside_tls_range': None,
        'file_backed_size': 0,
        'zero_fill_size': 0,
        'nonexistent_size': 0,
        'extent_known': size > 0,
        'fully_within_tls': None,
        'file_backed': False,
        'in_file': False,
        'zero_filled': False,
        'nonexistent': False,
        'source': 'unknown',
        'classification': 'unknown',
        'verified_from_file': False,
    }

    if elf['e_type'] == 'ET_REL':
        report['classification'] = 'section_relative'
        report['source'] = 'section_relative'
        return report

    if primary is None:
        report['classification'] = 'no_pt_tls'
        report['source'] = 'unknown'
        return report

    report['tls_range'] = [value, value + size] if size > 0 else [value, value]
    if size == 0:
        report['classification'] = 'zero_size'
        report['source'] = 'unknown_extent'
        return report

    p_offset = int(primary['p_offset'])
    p_filesz = int(primary['p_filesz'])
    p_memsz = int(primary['p_memsz'])
    template_end = min(p_filesz, p_memsz)
    file_backed = _clip_interval(value, value + size, 0, template_end)
    zero_fill = _clip_interval(value, value + size, template_end, p_memsz)
    outside = _clip_interval(value, value + size, p_memsz, value + size)

    report['file_backed_tls_range'] = _interval_json(file_backed)
    report['zero_fill_tls_range'] = _interval_json(zero_fill)
    report['outside_tls_range'] = _interval_json(outside)
    report['file_backed_size'] = 0 if file_backed is None else file_backed[1] - file_backed[0]
    report['zero_fill_size'] = 0 if zero_fill is None else zero_fill[1] - zero_fill[0]
    report['nonexistent_size'] = 0 if outside is None else outside[1] - outside[0]

    report['fully_within_tls'] = outside is None
    report['file_backed'] = file_backed is not None
    report['in_file'] = file_backed is not None
    report['zero_filled'] = zero_fill is not None
    report['nonexistent'] = outside is not None

    if file_backed is not None:
        expected = (p_offset + file_backed[0], p_offset + file_backed[1])
        available = _available_file_range(
            elf, expected[0], expected[1] - expected[0])
        report['file_range'] = [expected[0], expected[1]]
        report['available_file_range'] = _interval_json(available)
        report['verified_from_file'] = available == expected
        if available == expected:
            file_data = _read_file_range(
                elf, expected[0], expected[1] - expected[0])
            report['file_sha256'] = hashlib.sha256(file_data).hexdigest()

    if file_backed is not None and zero_fill is not None:
        report['classification'] = 'mixed'
        report['source'] = 'mixed'
    elif file_backed is not None:
        report['classification'] = 'initialized'
        report['source'] = 'file'
    elif zero_fill is not None:
        report['classification'] = 'zero_fill'
        report['source'] = 'zero_fill'
    elif outside is not None:
        report['classification'] = 'outside_tls'
        report['source'] = 'nonexistent'
    else:
        report['classification'] = 'empty'
        report['source'] = 'none'
    return report


def _coverage_report(
    primary: dict[str, Any] | None,
    symbols: Sequence[dict[str, Any]],
    sections_available: bool,
    symbol_tables_available: bool,
) -> dict[str, Any]:
    if primary is None:
        return {
            'symbol_tables_available': symbol_tables_available,
            'sections_available': sections_available,
            'known_symbol_ranges': [],
            'template_covered': [],
            'template_uncovered': [],
            'zero_fill_covered': [],
            'zero_fill_uncovered': [],
            'template_complete': None,
            'zero_fill_complete': None,
        }

    p_filesz = int(primary['p_filesz'])
    p_memsz = int(primary['p_memsz'])
    template_end = min(p_filesz, p_memsz)
    template: list[Interval] = []
    zero_fill: list[Interval] = []
    for symbol in symbols:
        if not symbol.get('extent_known'):
            continue
        tls_range = symbol.get('tls_range')
        if not tls_range or tls_range[1] <= tls_range[0]:
            continue
        start, end = int(tls_range[0]), int(tls_range[1])
        clipped_template = _clip_interval(start, end, 0, template_end)
        clipped_zero = _clip_interval(start, end, template_end, p_memsz)
        if clipped_template is not None:
            template.append(clipped_template)
        if clipped_zero is not None:
            zero_fill.append(clipped_zero)

    template_merged = _merge_intervals(template)
    zero_fill_merged = _merge_intervals(zero_fill)
    template_all = [(0, template_end)] if template_end > 0 else []
    zero_fill_all = [(template_end, p_memsz)] if p_memsz > template_end else []
    template_uncovered = _subtract_intervals(template_all, template_merged)
    zero_fill_uncovered = _subtract_intervals(zero_fill_all, zero_fill_merged)

    return {
        'symbol_tables_available': symbol_tables_available,
        'sections_available': sections_available,
        'known_symbol_ranges': _intervals_json(_merge_intervals(template + zero_fill)),
        'template_covered': _intervals_json(template_merged),
        'template_uncovered': _intervals_json(template_uncovered),
        'zero_fill_covered': _intervals_json(zero_fill_merged),
        'zero_fill_uncovered': _intervals_json(zero_fill_uncovered),
        'template_complete': not template_uncovered,
        'zero_fill_complete': not zero_fill_uncovered,
    }


def _unconfirmed_ranges(
    primary: dict[str, Any] | None,
    section_status: dict[str, Any],
    symbol_tables_available: bool,
    symbols: Sequence[dict[str, Any]],
    coverage: dict[str, Any],
) -> list[dict[str, Any]]:
    unconfirmed: list[dict[str, Any]] = []

    if not section_status['present']:
        unconfirmed.append({
            'kind': 'section_table',
            'tls_range': None,
            'file_range': None,
            'reason': section_status['reason'] or 'section headers are absent',
        })
    elif not section_status['complete']:
        unconfirmed.append({
            'kind': 'section_table',
            'tls_range': None,
            'file_range': None,
            'reason': section_status['reason'] or 'section-header table is incomplete',
        })

    if not symbol_tables_available:
        file_range = None
        tls_range = None
        if primary is not None:
            tls_range = [0, int(primary['p_memsz'])]
            file_range = [int(primary['p_offset']),
                          int(primary['p_offset']) + int(primary['p_filesz'])]
        unconfirmed.append({
            'kind': 'symbol_table',
            'tls_range': tls_range,
            'file_range': file_range,
            'reason': 'no readable symbol table; variable extents are unknown',
        })

    for symbol in symbols:
        if not symbol['extent_known']:
            unconfirmed.append({
                'kind': 'symbol_extent',
                'symbol': symbol['name'],
                'tls_range': [symbol['st_value'], None],
                'file_range': None,
                'reason': 'st_size is 0; the symbol end cannot be confirmed',
            })

    if primary is not None and symbol_tables_available:
        p_offset = int(primary['p_offset'])
        for start, end in coverage['template_uncovered']:
            unconfirmed.append({
                'kind': 'symbol_coverage',
                'tls_range': [start, end],
                'file_range': [p_offset + start, p_offset + end],
                'reason': 'no STT_TLS symbol covers this initialization-template range',
            })
        for start, end in coverage['zero_fill_uncovered']:
            unconfirmed.append({
                'kind': 'symbol_coverage',
                'tls_range': [start, end],
                'file_range': None,
                'reason': 'no STT_TLS symbol covers this zero-fill range',
            })

    return unconfirmed


class TLSDescription(dict[str, Any]):
    """A dict-like TLS report returned by :func:`describe_tls`.

    The report is JSON-serializable (apart from no custom objects being used).
    ``__getitem__`` gives direct access to the documented keys, while
    :meth:`to_dict` returns a plain dict.
    """

    @property
    def segments(self) -> list[dict[str, Any]]:
        return self.get('tls_segments') or []

    @property
    def sections(self) -> list[dict[str, Any]]:
        return self.get('tls_sections') or []

    @property
    def symbols(self) -> list[dict[str, Any]]:
        return self.get('tls_symbols') or []

    @property
    def template(self) -> dict[str, Any] | None:
        return self.get('template')

    @property
    def zero_fill(self) -> dict[str, Any] | None:
        return self.get('zero_fill')

    @property
    def unconfirmed(self) -> list[dict[str, Any]]:
        return self.get('unconfirmed') or []

    def to_dict(self) -> dict[str, Any]:
        return dict(self)

    def to_json(self, **kwargs: Any) -> str:
        import json
        return json.dumps(self, **kwargs)

    def read_template(self, elf: ELFFile) -> bytes:
        """Read the primary PT_TLS initialization template from ``elf``."""
        segments = self.get('tls_segments') or []
        if not segments:
            return b''
        template = segments[0]['template']
        file_range = template.get('file_range')
        if not file_range:
            return b''
        return _read_file_range(elf, int(file_range[0]),
                                int(file_range[1]) - int(file_range[0]))

    def symbol_bytes(self, elf: ELFFile, name: str) -> bytes:
        """Return the file-backed bytes for the first TLS symbol named *name*.

        Zero-filled or nonexistent parts of the symbol are not returned; use
        :meth:`read_symbol` to obtain their sizes as well.
        """
        return self.read_symbol(elf, name)['file_bytes']

    def read_symbol(self, elf: ELFFile, name: str) -> dict[str, Any]:
        """Return file bytes and source sizes for the first TLS symbol named *name*."""
        for symbol in self.get('tls_symbols') or []:
            if symbol.get('name') != name:
                continue
            file_range = symbol.get('file_range')
            file_bytes = b''
            if file_range is not None:
                file_bytes = _read_file_range(
                    elf, int(file_range[0]),
                    int(file_range[1]) - int(file_range[0]))
            return {
                'name': name,
                'file_bytes': file_bytes,
                'file_size': len(file_bytes),
                'file_range': file_range,
                'zero_fill_size': int(symbol.get('zero_fill_size', 0)),
                'nonexistent_size': int(symbol.get('nonexistent_size', 0)),
                'verified_from_file': bool(symbol.get('verified_from_file')),
                'classification': symbol.get('classification'),
            }
        raise KeyError(name)

    def format_text(self) -> str:
        return format_tls_description(self)


TLSInfo = TLSDescription


def describe_tls(
    elf: ELFFile,
    *,
    verify: bool = True,
    include_bytes: bool = False,
) -> TLSDescription:
    """Build a static TLS loading description for an :class:`ELFFile`.

    ``verify`` reads the declared file-backed ranges and records their
    SHA-256 digests.  It does not execute, relocate, or load the ELF.
    ``include_bytes`` adds a hex preview of the primary PT_TLS template.
    """
    warnings: list[str] = []
    program_headers = _program_headers(elf, warnings)
    sections, section_status = _section_table(elf, warnings)

    tls_segments = [
        _segment_report(elf, record, verify=verify, include_bytes=include_bytes)
        for record in program_headers
        if record['header']['p_type'] == 'PT_TLS'
    ]
    if len(tls_segments) > 1:
        warnings.append(
            f'{len(tls_segments)} PT_TLS segments are present; '
            'the first one is used as the primary TLS block')

    primary = tls_segments[0] if tls_segments else None
    tls_sections = [
        _section_report(elf, record, primary, verify=verify)
        for record in sections
        if int(record['header']['sh_flags']) & SH_FLAGS.SHF_TLS
    ]
    for section_report in tls_sections:
        sections[section_report['index']]['matches_pt_tls'] = (
            section_report['matches_pt_tls'])

    tables = _symbol_tables(elf, sections, warnings)
    symbols: list[dict[str, Any]] = []
    for table in tables:
        for record in table['symbols']:
            if record['entry']['st_info']['type'] != _STT_TLS:
                continue
            symbols.append(
                _symbol_report(elf, table, record, primary, sections))

    symbol_tables_available = bool(tables)
    has_tls_evidence = bool(tls_segments or tls_sections or symbols)
    coverage = _coverage_report(
        primary, symbols, bool(sections), symbol_tables_available)
    unconfirmed = (
        _unconfirmed_ranges(
            primary, section_status, symbol_tables_available, symbols, coverage)
        if has_tls_evidence else [])
    if (has_tls_evidence and section_status['present'] and
            not section_status['names_available']):
        unconfirmed.append({
            'kind': 'section_names',
            'tls_range': None,
            'file_range': None,
            'reason': 'section-name string table is unavailable; '
                      'section identities are unconfirmed',
        })
    tls_range = None
    if primary is not None:
        tls_range = [0, int(primary['p_memsz'])]
    if (has_tls_evidence and tables and
            not any(table['type'] == 'SHT_SYMTAB' for table in tables)):
        unconfirmed.append({
            'kind': 'symbol_table_partial',
            'tls_range': tls_range,
            'file_range': None,
            'reason': 'only a dynamic symbol table is available; local '
                      'TLS symbols may be missing',
        })
        warnings.append(
            'only a dynamic symbol table is available; local TLS symbols '
            'may be missing')
    for table in (tables if has_tls_evidence else []):
        label = table['name'] or f"section[{table['section_index']}]"
        if not table['names_available']:
            unconfirmed.append({
                'kind': 'symbol_names',
                'table': label,
                'tls_range': tls_range,
                'file_range': None,
                'reason': 'symbol-name string table is unavailable',
            })
        if not table['complete']:
            unconfirmed.append({
                'kind': 'symbol_table_truncated',
                'table': label,
                'tls_range': tls_range,
                'file_range': None,
                'reason': 'symbol table is truncated; missing symbols are unknown',
            })

    if primary is None and (tls_sections or symbols):
        warnings.append(
            'TLS sections or symbols are present, but no PT_TLS segment '
            'provides a per-thread block layout')
    if primary is not None:
        if int(primary['p_filesz']) > int(primary['p_memsz']):
            warnings.append(
                'PT_TLS p_filesz is greater than p_memsz; the declared '
                'initialization template exceeds the per-thread block')
        if not primary['template']['complete_in_file']:
            warnings.append(
                'PT_TLS initialization template is not completely present in the file')

    primary_template = None if primary is None else primary['template']
    primary_zero_fill = None if primary is None else primary['zero_fill']
    report = TLSDescription()
    report.update({
        'has_tls': has_tls_evidence,
        'has_pt_tls': bool(tls_segments),
        'elf_class': elf.elfclass,
        'little_endian': elf.little_endian,
        'type': elf['e_type'],
        'machine': elf['e_machine'],
        'file_size': elf.stream_len,
        'section_headers': section_status,
        'segments': tls_segments,
        'tls_segments': tls_segments,
        'primary_segment': primary,
        'sections': tls_sections,
        'tls_sections': tls_sections,
        'symbol_tables': [
            {
                'section_index': table['section_index'],
                'name': table['name'],
                'count': table['count'],
                'names_available': table['names_available'],
                'complete': table['complete'],
            }
            for table in tables
        ],
        'symbols': symbols,
        'tls_symbols': symbols,
        'template': primary_template,
        'zero_fill': primary_zero_fill,
        'template_size': None if primary is None else int(primary['p_filesz']),
        'per_thread_size': None if primary is None else int(primary['p_memsz']),
        'zero_fill_size': (
            None if primary_zero_fill is None
            else int(primary_zero_fill['tls_size'])),
        'template_file_range': (
            None if primary_template is None
            else primary_template['file_range']),
        'zero_fill_tls_range': (
            None if primary_zero_fill is None
            else primary_zero_fill['tls_range']),
        'tls_memory_range': (
            None if primary is None else primary['memory_range']),
        'not_in_file_memory_range': (
            None if primary is None else primary['not_in_file_memory_range']),
        'coverage': coverage,
        'unconfirmed': unconfirmed,
        'warnings': warnings,
        'notes': [
            'STT_TLS st_value is an offset into the TLS block, not an '
            'ordinary virtual address; do not apply a section/PT_LOAD base '
            'to it.',
            'PT_TLS.p_offset/p_filesz describe the file-backed initialization '
            'template; [p_filesz, p_memsz) is per-thread zero fill and has '
            'no file offset.',
        ],
    })
    return report


# Descriptive aliases for callers that prefer a getter-style name.
get_tls_info = describe_tls
tls_info = describe_tls
analyze_tls = describe_tls
describe_tls_layout = describe_tls
get_tls_description = describe_tls
StaticTLSDescription = TLSDescription


TLSInput = ELFFile | TLSDescription | dict[str, Any] | str | bytes | os.PathLike[str]


def _as_description(value: TLSInput) -> TLSDescription:
    if isinstance(value, TLSDescription):
        return value
    if isinstance(value, ELFFile):
        return describe_tls(value)
    if isinstance(value, (str, bytes, os.PathLike)):
        with open(value, 'rb') as stream:
            return describe_tls(ELFFile(stream))
    if isinstance(value, dict):
        return TLSDescription(value)
    raise TypeError(f'unsupported TLS description input: {type(value).__name__}')


def compare_tls(
    first: TLSInput,
    second: TLSInput,
) -> dict[str, Any]:
    """Compare two TLS descriptions or ELF files.

    The comparison is byte-oriented: it reports whether the file-backed
    initialization templates have the same size and digest, and separately
    reports the per-thread sizes and zero-fill sizes.
    """
    left = _as_description(first)
    right = _as_description(second)
    left_segment = left.get('primary_segment')
    right_segment = right.get('primary_segment')

    def size_of(segment: dict[str, Any] | None, key: str) -> int | None:
        return None if segment is None else int(segment[key])

    def digest_of(segment: dict[str, Any] | None) -> str | None:
        if segment is None:
            return None
        digest = segment['template'].get('sha256')
        return None if digest is None else str(digest)

    left_template_size = size_of(left_segment, 'p_filesz')
    right_template_size = size_of(right_segment, 'p_filesz')
    left_memsz = size_of(left_segment, 'p_memsz')
    right_memsz = size_of(right_segment, 'p_memsz')
    left_digest = digest_of(left_segment)
    right_digest = digest_of(right_segment)
    left_zero = None if left_segment is None else max(
        0, int(left_segment['p_memsz']) - int(left_segment['p_filesz']))
    right_zero = None if right_segment is None else max(
        0, int(right_segment['p_memsz']) - int(right_segment['p_filesz']))

    same_template_bytes = None
    if left_digest is not None and right_digest is not None:
        same_template_bytes = left_digest == right_digest

    return {
        'template_size': [left_template_size, right_template_size],
        'per_thread_size': [left_memsz, right_memsz],
        'zero_fill_size': [left_zero, right_zero],
        'template_sha256': [left_digest, right_digest],
        'same_template_size': left_template_size == right_template_size,
        'same_template_bytes': same_template_bytes,
        'same_per_thread_size': left_memsz == right_memsz,
        'per_thread_sizes_differ': left_memsz != right_memsz,
        'file_backed_template': [
            None if left_segment is None else left_segment['template']['file_range'],
            None if right_segment is None else right_segment['template']['file_range'],
        ],
        'template_complete_in_file': [
            None if left_segment is None else bool(
                left_segment['template']['complete_in_file']),
            None if right_segment is None else bool(
                right_segment['template']['complete_in_file']),
        ],
        'template_available_size': [
            None if left_segment is None else int(
                left_segment['template']['available_size']),
            None if right_segment is None else int(
                right_segment['template']['available_size']),
        ],
        'zero_fill_is_not_in_file': [
            None if left_segment is None else left_segment['zero_fill']['file_range'] is None,
            None if right_segment is None else right_segment['zero_fill']['file_range'] is None,
        ],
    }


def compare_tls_files(first_path: str, second_path: str) -> dict[str, Any]:
    """Open two ELF paths and compare their TLS layouts."""
    with open(first_path, 'rb') as first_file:
        first = describe_tls(ELFFile(first_file))
    with open(second_path, 'rb') as second_file:
        second = describe_tls(ELFFile(second_file))
    return compare_tls(first, second)


def _hex(value: int | None) -> str:
    return '?' if value is None else f'0x{value:x}'


def _range_text(value: Sequence[int] | None) -> str:
    if value is None:
        return 'none'
    if len(value) == 1 or value[1] is None:
        return f'{_hex(int(value[0]))}..unknown'
    return f'{_hex(int(value[0]))}..{_hex(int(value[1]))}'


def format_tls_description(report: TLSInput) -> str:
    """Render a TLS report as human-readable text."""
    description = _as_description(report)
    lines: list[str] = []
    lines.append('TLS static load description')
    lines.append(
        f"  ELF{description.get('elf_class')} "
        f"{'little' if description.get('little_endian') else 'big'}-endian "
        f"{description.get('type')} {description.get('machine')}")
    section_headers = description.get('section_headers') or {}
    lines.append(
        f"  section headers: "
        f"{'present' if section_headers.get('present') else 'absent'}"
        f" ({section_headers.get('parsed', 0)}"
        f"{'' if section_headers.get('count') is None else '/' + str(section_headers.get('count'))}"
        f" readable)")
    tables = description.get('symbol_tables') or []
    if tables:
        lines.append(
            '  symbol tables: ' + ', '.join(
                str(table.get('name') or f"section[{table.get('section_index')}]")
                for table in tables))
    else:
        lines.append('  symbol tables: none readable')

    segments = description.get('tls_segments') or []
    if not segments:
        lines.append('')
        lines.append('PT_TLS: none')
    for segment in segments:
        template = segment['template']
        zero_fill = segment['zero_fill']
        lines.append('')
        lines.append(f"PT_TLS[{segment['index']}]:")
        lines.append(
            f"  memory:    {_range_text(segment['memory_range'])} "
            f"({segment['p_memsz']} bytes per thread)")
        lines.append(
            f"  file:      offset {_range_text(template['file_range'])} "
            f"({template['tls_size']} bytes initialization template)")
        lines.append(
            f"  zero fill: TLS {_range_text(zero_fill['tls_range'])} "
            f"({zero_fill['tls_size']} bytes; not in file)")
        verification = (
            'complete in file' if template['complete_in_file']
            else 'truncated; missing ' + _range_text(template['missing_file_range']))
        lines.append(
            f"  template verification: {verification}"
            f"{'' if template.get('sha256') is None else ', sha256=' + str(template['sha256'])}")

    sections = description.get('tls_sections') or []
    if sections:
        lines.append('')
        lines.append('TLS sections:')
        for section in sections:
            name = section.get('name') or f"section[{section.get('index')}]"
            if section['initialized']:
                source = (
                    f"file {_range_text(section.get('file_range'))}"
                    if section.get('in_file') else 'file range unavailable')
            else:
                source = 'zero fill, no file bytes'
            lines.append(
                f"  {name}: TLS {_range_text(section.get('tls_range'))} "
                f"<- {source}"
                f"{'' if section.get('matches_pt_tls') is None else ', matches PT_TLS=' + str(section['matches_pt_tls'])}")

    symbols = description.get('tls_symbols') or []
    if symbols:
        lines.append('')
        lines.append('TLS symbols (st_value is a TLS-block offset):')
        for symbol in symbols:
            name = symbol.get('name') or f"symbol[{symbol.get('index')}]"
            source = symbol.get('source')
            details: list[str] = []
            if symbol.get('file_backed_tls_range') is not None:
                details.append(
                    f"file TLS {_range_text(symbol['file_backed_tls_range'])}"
                    f" -> {_range_text(symbol.get('file_range'))}")
            if symbol.get('zero_fill_tls_range') is not None:
                details.append(
                    f"zero-fill TLS {_range_text(symbol['zero_fill_tls_range'])}")
            if symbol.get('outside_tls_range') is not None:
                details.append(
                    f"outside TLS {_range_text(symbol['outside_tls_range'])}")
            if not details:
                details.append('no file bytes')
            lines.append(
                f"  {name}: st_value={_hex(symbol.get('st_value'))} "
                f"size={symbol.get('st_size')} source={source}; "
                + '; '.join(details))

    unconfirmed = description.get('unconfirmed') or []
    if unconfirmed:
        lines.append('')
        lines.append('Unconfirmed ranges:')
        for item in unconfirmed:
            lines.append(
                f"  {item.get('kind')}: TLS {_range_text(item.get('tls_range'))}, "
                f"file {_range_text(item.get('file_range'))} - {item.get('reason')}")

    warnings = description.get('warnings') or []
    if warnings:
        lines.append('')
        lines.append('Warnings:')
        for warning in warnings:
            lines.append(f'  {warning}')
    return '\n'.join(lines)


def format_tls_comparison(comparison: dict[str, Any]) -> str:
    """Render :func:`compare_tls` output as text."""
    lines = [
        'TLS layout comparison:',
        f"  template size:     {comparison['template_size']}",
        f"  per-thread size:   {comparison['per_thread_size']}",
        f"  zero-fill size:    {comparison['zero_fill_size']}",
        f"  same template size: {comparison['same_template_size']}",
        f"  same template bytes: {comparison['same_template_bytes']}",
        f"  same per-thread size: {comparison['same_per_thread_size']}",
        f"  file-backed templates: {comparison['file_backed_template']}",
        f"  template complete in file: {comparison['template_complete_in_file']}",
        f"  zero fill is not in file: {comparison['zero_fill_is_not_in_file']}",
    ]
    return '\n'.join(lines)
