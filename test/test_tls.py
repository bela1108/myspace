#-------------------------------------------------------------------------------
# elftools tests
#
# Tests for static ELF TLS layout descriptions.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import io
import struct
import unittest

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.tls import compare_tls, describe_tls


_BASE = 0x400000
_PHDR_SIZE = 56
_SHDR_SIZE = 64
_EHDR_SIZE = 64
_TLS_VADDR = _BASE + 0x1000
_TEMPLATE_OFFSET = _EHDR_SIZE + 2 * _PHDR_SIZE


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _section_header(
    name_offset: int,
    sh_type: int,
    flags: int,
    addr: int,
    offset: int,
    size: int,
    *,
    link: int = 0,
    info: int = 0,
    align: int = 1,
    entsize: int = 0,
) -> bytes:
    return struct.pack(
        '<IIQQQQIIQQ',
        name_offset, sh_type, flags, addr, offset, size,
        link, info, align, entsize)


def _build_tls_elf(
    template: bytes,
    memsz: int,
    symbols: list[tuple[str, int, int, int]],
    *,
    include_sections: bool = True,
    include_symbols: bool = True,
) -> bytes:
    """Build a small valid ELF64 executable with one PT_LOAD and one PT_TLS.

    Symbol tuples are ``(name, TLS offset, size, section index)``.  The bytes
    immediately after the template are a sentinel that must never be read as
    TLS data.
    """
    tail = b'FILE-TAIL-SENTINEL'
    shstr = b'\0.tdata\0.tbss\0.shstrtab\0.strtab\0.symtab\0'
    shstr_name = {
        '.tdata': shstr.index(b'.tdata'),
        '.tbss': shstr.index(b'.tbss'),
        '.shstrtab': shstr.index(b'.shstrtab'),
        '.strtab': shstr.index(b'.strtab'),
        '.symtab': shstr.index(b'.symtab'),
    }

    strtab = bytearray(b'\0')
    name_offsets: dict[str, int] = {}
    for name, _value, _size, _shndx in symbols:
        if name not in name_offsets:
            name_offsets[name] = len(strtab)
            strtab += name.encode() + b'\0'

    symtab = bytearray(struct.pack('<IBBHQQ', 0, 0, 0, 0, 0, 0))
    for name, value, size, shndx in symbols:
        symtab += struct.pack(
            '<IBBHQQ', name_offsets[name], (1 << 4) | 6, 0, shndx, value, size)

    data = bytearray(template + tail)
    shstr_offset = _TEMPLATE_OFFSET + len(data)
    data += shstr
    strtab_offset = _TEMPLATE_OFFSET + len(data)
    data += strtab
    symtab_offset = _TEMPLATE_OFFSET + len(data)
    data += symtab

    section_count = 6 if include_sections and include_symbols else 4
    if not include_sections:
        section_count = 0
    shoff = _align_up(_TEMPLATE_OFFSET + len(data), 8)
    data += b'\0' * (shoff - (_TEMPLATE_OFFSET + len(data)))

    if include_sections:
        shdrs = [
            _section_header(0, 0, 0, 0, 0, 0),
            _section_header(
                shstr_name['.tdata'], 1,
                SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_WRITE | SH_FLAGS.SHF_TLS,
                _TLS_VADDR, _TEMPLATE_OFFSET, len(template),
                align=8),
            _section_header(
                shstr_name['.tbss'], 8,
                SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_WRITE | SH_FLAGS.SHF_TLS,
                _TLS_VADDR + len(template), _TEMPLATE_OFFSET + len(template),
                memsz - len(template), align=8),
            _section_header(
                shstr_name['.shstrtab'], 3, 0, 0, shstr_offset, len(shstr)),
        ]
        if include_symbols:
            shdrs.extend([
                _section_header(
                    shstr_name['.strtab'], 3, 0, 0, strtab_offset, len(strtab)),
                _section_header(
                    shstr_name['.symtab'], 2, 0, 0, symtab_offset, len(symtab),
                    link=4, info=1, align=8, entsize=24),
            ])
        data += b''.join(shdrs)

    total_size = _TEMPLATE_OFFSET + len(data)
    e_ident = b'\x7fELF' + bytes((2, 1, 1)) + b'\0' * 9
    ehdr = struct.pack(
        '<16sHHIQQQIHHHHHH',
        e_ident, 2, 62, 1, _BASE, _EHDR_SIZE, shoff if include_sections else 0,
        0, _EHDR_SIZE, _PHDR_SIZE, 2, _SHDR_SIZE, section_count,
        3 if include_sections else 0)
    phdrs = b''.join([
        struct.pack(
            '<IIQQQQQQ',
            1, 5, 0, _BASE, _BASE, total_size, total_size, 0x1000),
        struct.pack(
            '<IIQQQQQQ',
            7, 4, _TEMPLATE_OFFSET, _TLS_VADDR, _TLS_VADDR,
            len(template), memsz, 8),
    ])
    return ehdr + phdrs + bytes(data)


def _report(data: bytes):
    return describe_tls(ELFFile(io.BytesIO(data)))


class TestTLSLayout(unittest.TestCase):
    def test_same_template_with_different_per_thread_size(self):
        template = b'ABCDEFGH'
        symbols_a = [
            ('first', 0, 4, 1),
            ('second', 4, 4, 1),
            ('zeros', 12, 4, 2),
        ]
        symbols_b = symbols_a + [('far', 20, 4, 2)]
        report_a = _report(_build_tls_elf(template, 16, symbols_a))
        report_b = _report(_build_tls_elf(template, 24, symbols_b))

        self.assertTrue(report_a['has_tls'])
        self.assertEqual(report_a['template']['tls_size'], len(template))
        self.assertEqual(report_b['template']['tls_size'], len(template))
        self.assertEqual(report_a['zero_fill']['tls_size'], 8)
        self.assertEqual(report_b['zero_fill']['tls_size'], 16)
        self.assertEqual(report_a['template']['sha256'],
                         report_b['template']['sha256'])
        self.assertEqual(
            report_a.read_template(ELFFile(io.BytesIO(
                _build_tls_elf(template, 16, symbols_a)))), template)

        symbols_by_name = {
            symbol['name']: symbol for symbol in report_a['tls_symbols']}
        self.assertEqual(symbols_by_name['first']['classification'], 'initialized')
        self.assertEqual(symbols_by_name['first']['file_range'],
                         [_TEMPLATE_OFFSET, _TEMPLATE_OFFSET + 4])
        self.assertTrue(symbols_by_name['first']['verified_from_file'])
        self.assertEqual(
            report_a.symbol_bytes(ELFFile(io.BytesIO(
                _build_tls_elf(template, 16, symbols_a))), 'first'),
            b'ABCD')
        self.assertEqual(
            report_a.read_symbol(ELFFile(io.BytesIO(
                _build_tls_elf(template, 16, symbols_a))), 'zeros')[
                    'file_bytes'],
            b'')
        self.assertEqual(symbols_by_name['zeros']['classification'], 'zero_fill')
        self.assertIsNone(symbols_by_name['zeros']['file_range'])
        self.assertEqual(symbols_by_name['zeros']['zero_fill_tls_range'],
                         [12, 16])
        self.assertNotIn('far', {
            symbol['name'] for symbol in report_a['tls_symbols']})
        far = {
            symbol['name']: symbol for symbol in report_b['tls_symbols']}['far']
        self.assertEqual(far['classification'], 'zero_fill')
        self.assertEqual(far['zero_fill_tls_range'], [20, 24])
        self.assertIsNone(far['file_range'])

        comparison = compare_tls(report_a, report_b)
        self.assertTrue(comparison['same_template_size'])
        self.assertTrue(comparison['same_template_bytes'])
        self.assertFalse(comparison['same_per_thread_size'])
        self.assertEqual(comparison['zero_fill_size'], [8, 16])

        report_other = _report(_build_tls_elf(b'87654321', 16, symbols_a))
        other_comparison = compare_tls(report_a, report_other)
        self.assertTrue(other_comparison['same_template_size'])
        self.assertFalse(other_comparison['same_template_bytes'])

    def test_trimmed_section_headers_preserve_segment_ranges(self):
        template = b'12345678'
        report = _report(_build_tls_elf(
            template, 32, [], include_sections=False))

        self.assertFalse(report['section_headers']['present'])
        self.assertEqual(report['tls_sections'], [])
        self.assertEqual(report['tls_symbols'], [])
        self.assertEqual(report['template']['file_range'],
                         [_TEMPLATE_OFFSET, _TEMPLATE_OFFSET + len(template)])
        self.assertEqual(report['zero_fill']['tls_range'], [8, 32])
        self.assertIsNone(report['zero_fill']['file_range'])
        kinds = {item['kind'] for item in report['unconfirmed']}
        self.assertIn('section_table', kinds)
        self.assertIn('symbol_table', kinds)

    def test_missing_symbols_leave_precise_uncovered_ranges(self):
        template = b'ABCDEFGH'
        report = _report(_build_tls_elf(
            template, 24, [('first', 0, 4, 1), ('anchor', 8, 0, 1)]))

        self.assertEqual(report['coverage']['template_covered'], [[0, 4]])
        self.assertEqual(report['coverage']['template_uncovered'], [[4, 8]])
        self.assertEqual(report['coverage']['zero_fill_uncovered'], [[8, 24]])
        kinds = {item['kind'] for item in report['unconfirmed']}
        self.assertIn('symbol_extent', kinds)
        self.assertIn('symbol_coverage', kinds)
        anchor = {
            symbol['name']: symbol for symbol in report['tls_symbols']}['anchor']
        self.assertEqual(anchor['classification'], 'zero_size')
        self.assertFalse(anchor['extent_known'])

    def test_truncated_template_reports_missing_file_range(self):
        data = _build_tls_elf(b'ABCDEFGH', 16, [('first', 0, 4, 1)])
        report = _report(data[:_TEMPLATE_OFFSET + 4])

        self.assertFalse(report['template']['complete_in_file'])
        self.assertEqual(report['template']['available_size'], 4)
        self.assertEqual(report['template']['missing_file_range'],
                         [_TEMPLATE_OFFSET + 4, _TEMPLATE_OFFSET + 8])
        self.assertIsNone(report['template']['sha256'])
        self.assertTrue(report['warnings'])

    def test_all_zero_fill_template_is_complete(self):
        report = _report(_build_tls_elf(
            b'', 16, [('only_zero', 0, 4, 2)]))

        self.assertEqual(report['template']['tls_size'], 0)
        self.assertTrue(report['template']['complete_in_file'])
        self.assertEqual(report['template']['available_size'], 0)
        self.assertEqual(report['zero_fill']['tls_range'], [0, 16])
        self.assertEqual(report['tls_symbols'][0]['classification'],
                         'zero_fill')

    def test_existing_all_zero_fill_tls_fixtures(self):
        for path, expected_class in (
                ('test/testfiles_for_readelf/tls.so.elf', 32),
                ('test/testfiles_for_readelf/tls64.so.elf', 64)):
            with self.subTest(path=path), open(path, 'rb') as stream:
                report = describe_tls(ELFFile(stream))
                self.assertEqual(report['elf_class'], expected_class)
                self.assertEqual(report['template_size'], 0)
                self.assertEqual(report['per_thread_size'], 4)
                self.assertEqual(report['zero_fill_size'], 4)
                self.assertEqual(report['tls_symbols'][0]['name'], 'i')
                self.assertEqual(
                    report['tls_symbols'][0]['classification'],
                    'zero_fill')

    def test_et_rel_tls_symbols_are_section_relative(self):
        path = 'test/testfiles_for_unittests/tls_relocs_x64_gcc.o'
        with open(path, 'rb') as stream:
            report = describe_tls(ELFFile(stream))

        self.assertFalse(report['tls_segments'])
        self.assertEqual(len(report['tls_sections']), 2)
        self.assertTrue(report['tls_symbols'])
        self.assertTrue(all(
            symbol['classification'] == 'section_relative'
            for symbol in report['tls_symbols']))


if __name__ == '__main__':
    unittest.main()
