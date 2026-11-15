"""
Boundary tests for MiniFAT and ministream handling.

The fixtures are small, self-contained OLE files with one ordinary FAT
sector, one directory sector, one MiniFAT sector, one root ministream
sector and (optionally) an eight-sector large stream.
"""

from __future__ import print_function

import io
import os
import struct
import sys
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
ENDOFCHAIN = olefile.ENDOFCHAIN
FREESECT = olefile.FREESECT
FATSECT = olefile.FATSECT
NOSTREAM = olefile.NOSTREAM
MAGIC = olefile.MAGIC


def _direntry(name, entry_type, start, size, child=NOSTREAM,
              left=NOSTREAM, right=NOSTREAM):
    name_bytes = name.encode('utf-16le') + b'\x00\x00'
    assert len(name_bytes) <= 64
    return struct.pack(
        '<64sHBBIII16sIQQIII',
        name_bytes.ljust(64, b'\x00'),
        len(name_bytes),
        entry_type,
        1,  # black
        left,
        right,
        child,
        b'\x00' * 16,
        0,
        0,
        0,
        start,
        size & 0xFFFFFFFF,
        (size >> 32) & 0xFFFFFFFF,
    )


def _build_ole(streams, root_size=256, minifat=None, fat_updates=None,
               include_large=True):
    """
    Build a minimal OLE file in memory.

    Sector layout:
      0: FAT
      1: directory
      2: MiniFAT
      3: root ministream
      4..11: optional large stream

    ``streams`` is a list of dicts with name/start/size/type.  Directory
    entries are linked as a right-leaning tree below the root.
    """
    minifat = dict(minifat or {})
    fat_updates = dict(fat_updates or {})
    ministream = bytearray(SECTOR_SIZE)
    for mini_index in range(SECTOR_SIZE // MINI_SECTOR_SIZE):
        value = 0x40 + mini_index
        ministream[mini_index * MINI_SECTOR_SIZE:
                   (mini_index + 1) * MINI_SECTOR_SIZE] = bytes([value]) * MINI_SECTOR_SIZE

    sectors = []
    # Sector 0: FAT
    fat = [FREESECT] * (SECTOR_SIZE // 4)
    fat[0] = FATSECT
    fat[1] = ENDOFCHAIN
    fat[2] = ENDOFCHAIN
    fat[3] = ENDOFCHAIN
    if include_large:
        for sector in range(4, 11):
            fat[sector] = sector + 1
        fat[11] = ENDOFCHAIN
    for index, value in fat_updates.items():
        fat[index] = value
    sectors.append(struct.pack('<%dI' % len(fat), *fat))

    # Sector 1: directory
    root_entry = _direntry('Root Entry', olefile.STGTY_ROOT, 3, root_size,
                           child=1 if streams else NOSTREAM)
    entries = [root_entry]
    for index, stream in enumerate(streams):
        next_sid = index + 2 if index + 1 < len(streams) else NOSTREAM
        entries.append(_direntry(
            stream['name'],
            stream.get('type', olefile.STGTY_STREAM),
            stream['start'],
            stream['size'],
            right=next_sid,
        ))
    directory = b''.join(entries[:4]).ljust(SECTOR_SIZE, b'\x00')
    sectors.append(directory)

    # Sector 2: MiniFAT
    mini_fat = [FREESECT] * 128
    for index, value in minifat.items():
        mini_fat[index] = value
    sectors.append(struct.pack('<128I', *mini_fat))

    # Sector 3: root ministream
    sectors.append(bytes(ministream))

    # Sectors 4..11: optional large stream
    if include_large:
        for sector in range(8):
            sectors.append(bytes([0x80 + sector]) * SECTOR_SIZE)

    header = bytearray(512)
    struct.pack_into(
        '<8s16sHHHHHHLLLLLLLLLL',
        header,
        0,
        MAGIC,
        b'\x00' * 16,
        0x3E,
        3,
        0xFFFE,
        9,
        6,
        0,
        0,
        0,
        1,
        1,
        0,
        0x1000,
        2,
        1,
        ENDOFCHAIN,
        0,
    )
    header[76:].ljust(436, b'\xFF')
    struct.pack_into('<I', header, 76, 0)

    return bytes(header) + b''.join(sectors)


def _open(data):
    return olefile.OleFileIO(io.BytesIO(data))


class TestMiniFatBounds(unittest.TestCase):

    def test_valid_mini_and_fat_streams_are_unchanged(self):
        data = _build_ole([
            {'name': 'A', 'start': 0, 'size': 100},
            {'name': 'B', 'start': 2, 'size': 64},
            {'name': 'BIG', 'start': 4, 'size': 4096},
        ], root_size=256, minifat={0: 1, 1: ENDOFCHAIN, 2: ENDOFCHAIN})
        ole = _open(data)
        mini_stream = data[512 + 3 * SECTOR_SIZE:512 + 4 * SECTOR_SIZE]
        large_stream = b''.join(
            bytes([0x80 + sector]) * SECTOR_SIZE for sector in range(8))

        self.assertEqual(ole.openstream('A').read(), mini_stream[:100])
        self.assertEqual(ole.openstream('B').read(), mini_stream[128:192])
        self.assertEqual(ole.openstream('BIG').read(), large_stream)
        self.assertEqual(ole.parsing_issues, [])
        ole.close()

    def test_minifat_slot_pointing_to_fat_sector_is_rejected(self):
        data = _build_ole([
            {'name': 'A', 'start': 0, 'size': 64},
        ], root_size=128, minifat={0: 4}, include_large=False)
        ole = _open(data)
        with self.assertRaises(olefile.OleFileError):
            ole.openstream('A')
        ole.close()

    def test_chain_loop_is_rejected(self):
        data = _build_ole([
            {'name': 'A', 'start': 0, 'size': 100},
        ], root_size=128, minifat={0: 1, 1: 0}, include_large=False)
        ole = _open(data)
        with self.assertRaises(olefile.OleFileError):
            ole.openstream('A')
        ole.close()

    def test_chain_past_minifat_length_is_rejected(self):
        data = _build_ole([
            {'name': 'A', 'start': 0, 'size': 200},
        ], root_size=128, minifat={0: 1, 1: 2}, include_large=False)
        ole = _open(data)
        with self.assertRaises(olefile.OleFileError):
            ole.openstream('A')
        ole.close()

    def test_overlapping_mini_chains_are_rejected(self):
        data = _build_ole([
            {'name': 'A', 'start': 0, 'size': 64},
            {'name': 'B', 'start': 1, 'size': 128},
        ], root_size=128, minifat={0: ENDOFCHAIN, 1: 0},
        include_large=False)
        ole = _open(data)
        with self.assertRaises(olefile.OleFileError):
            ole.openstream('A')
        ole.close()

    def test_root_ministream_must_be_contiguous(self):
        data = _build_ole([
            {'name': 'A', 'start': 0, 'size': 64},
        ], root_size=1024, minifat={0: ENDOFCHAIN},
        fat_updates={3: 1}, include_large=False)
        ole = _open(data)
        with self.assertRaises(olefile.OleFileError):
            ole.openstream('A')
        ole.close()

    def test_short_declared_size_keeps_tail_and_marks_defect(self):
        data = _build_ole([
            {'name': 'A', 'start': 0, 'size': 64},
        ], root_size=128, minifat={0: 1, 1: ENDOFCHAIN},
        include_large=False)
        ole = _open(data)
        stream = ole.openstream('A')
        mini_stream = data[512 + 3 * SECTOR_SIZE:512 + 4 * SECTOR_SIZE]

        self.assertEqual(stream.size, 64)
        self.assertEqual(stream.read(), mini_stream[:64])
        self.assertEqual(stream.tail, mini_stream[64:128])
        self.assertTrue(any('declared size' in message.lower()
                            for _, message in ole.parsing_issues))
        ole.close()


if __name__ == '__main__':
    unittest.main()
