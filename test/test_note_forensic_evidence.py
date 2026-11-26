import struct
import subprocess
import sys
import unittest
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from elftools.elf.segments import NoteSegment


TESTFILES = Path(__file__).parent / 'testfiles_for_unittests'
PROJECT_ROOT = Path(__file__).parent.parent


def align4(value):
    return (value + 3) & ~3


def elf32_header(data):
    endian = '<' if data[5] == 1 else '>'
    values = struct.unpack_from(endian + 'HHIIIIIHHHHHH', data, 16)
    names = (
        'e_type', 'e_machine', 'e_version', 'e_entry', 'e_phoff',
        'e_shoff', 'e_flags', 'e_ehsize', 'e_phentsize', 'e_phnum',
        'e_shentsize', 'e_shnum', 'e_shstrndx',
    )
    result = dict(zip(names, values))
    result['endian'] = endian
    return result


def elf32_program_headers(data, header):
    headers = []
    for index in range(header['e_phnum']):
        offset = header['e_phoff'] + index * header['e_phentsize']
        values = struct.unpack_from(header['endian'] + 'IIIIIIII', data, offset)
        headers.append(dict(zip(
            ('p_type', 'p_offset', 'p_vaddr', 'p_paddr', 'p_filesz',
             'p_memsz', 'p_flags', 'p_align'), values)))
    return headers


def elf32_section_headers(data, header):
    headers = []
    for index in range(header['e_shnum']):
        offset = header['e_shoff'] + index * header['e_shentsize']
        values = struct.unpack_from(
            header['endian'] + 'IIIIIIIIII', data, offset)
        section = dict(zip(
            ('sh_name', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset',
             'sh_size', 'sh_link', 'sh_info', 'sh_addralign',
             'sh_entsize'), values))
        headers.append(section)

    shstr = headers[header['e_shstrndx']]
    strtab_offset = shstr['sh_offset']
    for section in headers:
        offset = strtab_offset + section['sh_name']
        end = data.index(b'\0', offset)
        section['name'] = data[offset:end].decode('utf-8')
    return headers


def raw_notes(data, endian, offset, size):
    notes = []
    cursor = offset
    end = offset + size
    while cursor + 12 <= end:
        namesz, descsz, ntype = struct.unpack_from(
            endian + 'III', data, cursor)
        name_offset = cursor + 12
        desc_offset = name_offset + align4(namesz)
        next_offset = desc_offset + align4(descsz)
        if next_offset > end:
            break
        name = None
        if namesz:
            name = data[name_offset:name_offset + namesz].rstrip(b'\0').decode()
        notes.append({
            'start': cursor,
            'end': next_offset,
            'namesz': namesz,
            'descsz': descsz,
            'type': ntype,
            'name': name,
            'desc_offset': desc_offset,
        })
        cursor = next_offset
    return notes, cursor


class NoteForensicEvidenceTest(unittest.TestCase):
    def test_big_endian_mips_core_boundaries_and_abi(self):
        path = TESTFILES / 'core_linux32_qemu_mips.elf'
        data = path.read_bytes()

        self.assertEqual(data[:4], b'\x7fELF')
        self.assertEqual((data[4], data[5]), (1, 2))
        header = elf32_header(data)
        self.assertEqual(header['endian'], '>')
        self.assertEqual(header['e_type'], 4)
        self.assertEqual(header['e_machine'], 8)

        phdrs = elf32_program_headers(data, header)
        note_phdr = next(ph for ph in phdrs if ph['p_type'] == 4)
        self.assertEqual(note_phdr['p_offset'], 0x114)
        self.assertEqual(note_phdr['p_vaddr'], 0)
        self.assertEqual(note_phdr['p_filesz'], 0x244)

        notes, end = raw_notes(
            data, '>', note_phdr['p_offset'], note_phdr['p_filesz'])
        self.assertEqual(end, 0x358)
        self.assertEqual([
            (n['start'], n['end'], n['namesz'], n['descsz'], n['type'], n['name'])
            for n in notes
        ], [
            (0x114, 0x228, 5, 256, 1, 'CORE'),
            (0x228, 0x2bc, 5, 128, 3, 'CORE'),
            (0x2bc, 0x358, 5, 136, 6, 'CORE'),
        ])

        desc = notes[1]['desc_offset']
        self.assertEqual(desc, 0x23c)
        self.assertEqual(
            struct.unpack_from('>IIIIIII', data, desc + 4),
            (0, 1000, 1000, 449015, 4238, 449015, 4238))
        # Applying the 16-bit uid/gid ABI used by other 32-bit machines shifts
        # pid to desc+12 and reads gid as if it were pid.
        self.assertEqual(struct.unpack_from('>I', data, desc + 12)[0], 1000)

        swapped_namesz = struct.unpack_from('<I', data, notes[0]['start'])[0]
        self.assertGreater(swapped_namesz, note_phdr['p_filesz'])

        with ELFFile(open(path, 'rb')) as elf:
            py_notes = []
            for segment in elf.iter_segments():
                if isinstance(segment, NoteSegment):
                    py_notes.extend(segment.iter_notes())

        self.assertEqual(
            [n['n_type'] for n in py_notes],
            ['NT_PRSTATUS', 'NT_PRPSINFO', 'NT_AUXV'])
        for raw, note in zip(notes, py_notes):
            self.assertEqual(raw['start'], note['n_offset'])
            self.assertEqual(raw['end'] - raw['start'], note['n_size'])
            self.assertEqual(raw['namesz'], note['n_namesz'])
            self.assertEqual(raw['descsz'], note['n_descsz'])
            self.assertEqual(raw['name'], note['n_name'])

    def test_tricore_altium_private_namespace_boundaries(self):
        path = TESTFILES / 'note_tc3xxx_blinky.elf'
        data = path.read_bytes()

        self.assertEqual(data[:4], b'\x7fELF')
        self.assertEqual((data[4], data[5]), (1, 1))
        header = elf32_header(data)
        self.assertEqual(header['endian'], '<')
        self.assertEqual(header['e_type'], 2)
        self.assertEqual(header['e_machine'], 44)
        self.assertEqual(header['e_flags'], 0x00100000)

        sections = elf32_section_headers(data, header)
        note_section = next(s for s in sections if s['name'] == '.note')
        self.assertEqual(note_section['sh_type'], 7)
        self.assertEqual(note_section['sh_addr'], 0)
        self.assertEqual(note_section['sh_offset'], 0x1cf21c)
        self.assertEqual(note_section['sh_size'], 0x14e70c)

        notes, end = raw_notes(
            data, '<', note_section['sh_offset'], note_section['sh_size'])
        self.assertEqual(len(notes), 522)
        self.assertEqual(end, 0x31d928)
        self.assertEqual(
            (notes[0]['start'], notes[0]['end'], notes[0]['type'], notes[0]['name']),
            (0x1cf21c, 0x1cf234, 10, 'Altium'))
        self.assertEqual(
            (notes[-1]['start'], notes[-1]['end'],
             notes[-1]['type'], notes[-1]['name']),
            (0x31d8d0, 0x31d928, 8, 'Altium'))

        linker_note = next(n for n in notes if n['type'] == 12)
        self.assertEqual(linker_note['start'], 0x1cf2b0)
        self.assertEqual(linker_note['desc_offset'], 0x1cf2c4)
        self.assertEqual(
            data.find(b'Blinky_LED_1_KIT_TC375_SB.elf',
                     linker_note['desc_offset'], linker_note['end']),
            0x1cf2cb)
        self.assertEqual(
            data.find(b'__CPU__=tc37x',
                     linker_note['desc_offset'], linker_note['end']),
            0x1cf30b)

        swapped_namesz = struct.unpack_from('>I', data, notes[0]['start'])[0]
        self.assertGreater(swapped_namesz, note_section['sh_size'])

        with ELFFile(open(path, 'rb')) as elf:
            note_sections = [
                section for section in elf.iter_sections()
                if isinstance(section, NoteSection)]
            self.assertEqual(len(note_sections), 1)
            py_notes = list(note_sections[0].iter_notes())

        self.assertEqual(len(py_notes), 522)
        for raw, note in zip(notes, py_notes):
            self.assertEqual(raw['start'], note['n_offset'])
            self.assertEqual(raw['end'] - raw['start'], note['n_size'])
            self.assertEqual(raw['namesz'], note['n_namesz'])
            self.assertEqual(raw['descsz'], note['n_descsz'])
            self.assertEqual(raw['name'], note['n_name'])
            self.assertIsInstance(note['n_type'], int)

    def test_dspic30f_empty_owner_does_not_break_readelf(self):
        path = TESTFILES / 'dwarf_phantombytes.elf'
        with ELFFile(open(path, 'rb')) as elf:
            self.assertEqual(elf['e_machine'], 'EM_DSPIC30F')
            self.assertTrue(elf.has_phantom_bytes())

        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / 'scripts' / 'readelf.py'),
             '-n', str(path)],
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
