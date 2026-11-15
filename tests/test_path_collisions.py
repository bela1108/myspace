"""
Tests for canonical OLE paths and path-conflict diagnostics.

The malformed OLE2 compound files used here are generated in-memory by a
minimal CFB writer (see build_ole), so no binary fixtures are required.
"""

from __future__ import print_function

import io
import os
import struct
import sys
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, ".."))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


SECTOR_SIZE = 512
# Streams smaller than the 4096-byte mini-stream cutoff would require a
# MiniFAT, which this minimal writer does not generate:
FAT_STREAM_SIZE = 4096
ENDOFCHAIN = olefile.ENDOFCHAIN
FREESECT = olefile.FREESECT
NOSTREAM = olefile.NOSTREAM
STGTY_STORAGE = olefile.STGTY_STORAGE
STGTY_STREAM = olefile.STGTY_STREAM
STGTY_ROOT = olefile.STGTY_ROOT

DIRENTRY_STRUCT = "<64sHBBIII16sIQQIII"


def _dir_entry(name, entry_type, start_sect, size,
               sid_left=NOSTREAM, sid_right=NOSTREAM, sid_child=NOSTREAM):
    encoded = name.encode("UTF-16LE")
    name_buffer = encoded[:62] + b"\x00\x00"
    namelength = min(len(encoded), 62) + 2
    return struct.pack(
        DIRENTRY_STRUCT,
        name_buffer,
        namelength,
        entry_type,
        1,
        sid_left,
        sid_right,
        sid_child,
        b"\x00" * 16,
        0,
        0,
        0,
        start_sect,
        size & 0xFFFFFFFF,
        (size >> 32) & 0xFFFFFFFF,
    )


def build_ole(entries, stream_data=None):
    """
    Build a minimal version-3 OLE2 compound file as bytes.

    :param entries: ordered list of tuples (path_tuple, entry_type, size).
        path_tuple excludes the root entry. Storages must appear before their
        children so that SIDs and the right-child chains stay consistent.
    :param stream_data: optional dict mapping the positional index of a
        stream entry to its exact bytes. Indexes are used instead of paths
        because distinct streams may share one canonical path. Streams
        without data are padded with a unique one-byte marker repeated to
        their declared size.
    :returns: bytes of a complete OLE file
    """
    stream_data = stream_data or {}

    data_blobs = []
    for index, (path_tuple, entry_type, size) in enumerate(entries):
        if entry_type != STGTY_STREAM or size == 0:
            continue
        if index in stream_data:
            data = stream_data[index]
            if len(data) != size:
                raise ValueError("stream data size mismatch for %r" % (path_tuple,))
        else:
            marker = (sum(ord(char) for char in "".join(path_tuple)) % 250) + 1
            data = bytes(bytearray([marker])) * size
        data_blobs.append((index, data))

    nb_stream_sectors = sum(len(data) // SECTOR_SIZE for _index, data in data_blobs)
    nb_dir_sectors = (len(entries) + 1 + 3) // 4
    nb_fat_sectors = 1

    fat_sector = 0
    first_dir_sector = 1
    first_data_sector = first_dir_sector + nb_dir_sectors

    fat = [FREESECT] * (1 + nb_dir_sectors + nb_stream_sectors)
    fat[fat_sector] = olefile.FATSECT
    for sect in range(first_dir_sector, first_dir_sector + nb_dir_sectors):
        fat[sect] = (sect + 1 if sect < first_dir_sector + nb_dir_sectors - 1
                     else ENDOFCHAIN)

    first_sect_by_index = {}
    next_sect = first_data_sector
    for index, data in data_blobs:
        chain_start = next_sect
        first_sect_by_index[index] = chain_start
        nb_sect = len(data) // SECTOR_SIZE
        for offset in range(nb_sect):
            fat[next_sect] = (next_sect + 1 if offset < nb_sect - 1
                              else ENDOFCHAIN)
            next_sect += 1

    # SIDs are positional: root is 0 and entries keep their declared order.
    # Path tuples cannot be used as keys because a storage and a stream may
    # share the same name in one directory.
    sid_of = [index + 1 for index in range(len(entries))]

    def parent_sid(index):
        path_tuple = entries[index][0]
        if len(path_tuple) == 1:
            return 0
        parent_path = path_tuple[:-1]
        for candidate in range(index - 1, -1, -1):
            candidate_path, candidate_type, _size = entries[candidate]
            if (candidate_path == parent_path
                    and candidate_type == STGTY_STORAGE):
                return sid_of[candidate]
        raise ValueError("missing parent storage for %r" % (path_tuple,))

    children = {}
    for index in range(len(entries)):
        children.setdefault(parent_sid(index), []).append(index)

    left_of = {}
    right_of = {}
    child_root_of = {}
    for parent, child_indexes in children.items():
        child_sids = [sid_of[index] for index in child_indexes]
        child_root_of[parent] = child_sids[0]
        for position, sid in enumerate(child_sids):
            left_of[sid] = NOSTREAM
            right_of[sid] = (child_sids[position + 1]
                             if position + 1 < len(child_sids) else NOSTREAM)

    directory_entries = []
    directory_entries.append(_dir_entry(
        "Root Entry", STGTY_ROOT, ENDOFCHAIN, 0,
        sid_left=NOSTREAM, sid_right=NOSTREAM,
        sid_child=child_root_of.get(0, NOSTREAM)))

    for index, (path_tuple, entry_type, size) in enumerate(entries):
        sid = sid_of[index]
        if entry_type == STGTY_STREAM and size > 0:
            start_sect = first_sect_by_index[index]
        elif entry_type == STGTY_STREAM:
            start_sect = ENDOFCHAIN
        else:
            start_sect = ENDOFCHAIN
        directory_entries.append(_dir_entry(
            path_tuple[-1], entry_type, start_sect, size,
            sid_left=left_of.get(sid, NOSTREAM),
            sid_right=right_of.get(sid, NOSTREAM),
            sid_child=(child_root_of.get(sid, NOSTREAM)
                       if entry_type == STGTY_STORAGE else NOSTREAM)))

    directory_blob = b"".join(directory_entries)
    directory_blob += b"\x00" * (nb_dir_sectors * SECTOR_SIZE - len(directory_blob))

    fat_blob = struct.pack("<%dI" % len(fat), *fat)
    fat_blob += b"\x00" * (SECTOR_SIZE - len(fat_blob))

    data_blob = b"".join(data for _index, data in data_blobs)

    header = struct.pack(
        "<8s16sHHHHHHLLLLLLLLLL",
        olefile.MAGIC,
        b"\x00" * 16,
        0x003E,
        3,
        0xFFFE,
        9,
        6,
        0,
        0,
        0,
        nb_fat_sectors,
        first_dir_sector,
        0,
        0x1000,
        ENDOFCHAIN,
        0,
        ENDOFCHAIN,
        0,
    )
    difat = [FREESECT] * 109
    difat[0] = fat_sector
    header += struct.pack("<109I", *difat)
    header += b"\x00" * (SECTOR_SIZE - len(header))

    return header + fat_blob + directory_blob + data_blob



# A fullwidth (compatibility) homoglyph of "Macros":
FULLWIDTH_MACROS = "Ｍａｃｒｏｓ"


def _open(entries, stream_data=None):
    data = build_ole(entries, stream_data=stream_data)
    # DEFECT_FATAL + 1 records every parsing defect instead of raising, so the
    # malformed directory can still be inspected:
    return olefile.OleFileIO(
        io.BytesIO(data),
        raise_defects=olefile.DEFECT_FATAL + 1)


def _collision_entries():
    return [
        (("Macros",), STGTY_STORAGE, 0),
        (("MACROS",), STGTY_STORAGE, 0),
        ((FULLWIDTH_MACROS,), STGTY_STORAGE, 0),
        (("Macros", "VBA"), STGTY_STREAM, FAT_STREAM_SIZE),
        (("MACROS", "VBA"), STGTY_STREAM, FAT_STREAM_SIZE),
        ((FULLWIDTH_MACROS, "VBA"), STGTY_STREAM, FAT_STREAM_SIZE),
        (("Data",), STGTY_STORAGE, 0),
        (("Data", "Data"), STGTY_STREAM, FAT_STREAM_SIZE),
        (("Data",), STGTY_STREAM, FAT_STREAM_SIZE),
        (("",), STGTY_STREAM, 0),
    ]


class CanonicalNameTest(unittest.TestCase):

    def test_nfc_and_case_folding(self):
        composed = "Macros"
        decomposed = "Macros"
        self.assertEqual(olefile.canonical_name(composed),
                         olefile.canonical_name(decomposed))
        self.assertEqual(olefile.canonical_name("MACROS"),
                         olefile.canonical_name("macros"))

    def test_fullwidth_homoglyph_is_distinct(self):
        self.assertNotEqual(olefile.canonical_name("Macros"),
                            olefile.canonical_name(FULLWIDTH_MACROS))

    def test_split_path_accepts_string_and_sequence(self):
        self.assertEqual(olefile.split_path("a/b/c"), ("a", "b", "c"))
        self.assertEqual(olefile.split_path(["a", "b"]), ("a", "b"))


class PathConflictDiagnosticsTest(unittest.TestCase):

    def setUp(self):
        self.ole = _open(_collision_entries())

    def tearDown(self):
        self.ole.close()

    def _reasons(self):
        return set(conflict.reason for conflict in self.ole.path_conflicts)

    def test_case_only_collision_is_diagnosed(self):
        conflicts = self.ole.get_path_conflicts(
            olefile.PATH_CONFLICT_CANONICAL_COLLISION)
        macros = [conflict for conflict in conflicts
                  if conflict.canonical_path == ("macros",)]
        self.assertEqual(len(macros), 1)
        self.assertEqual(
            sorted(entry.name for entry in macros[0].entries),
            ["MACROS", "Macros"])

    def test_storage_stream_same_name_is_diagnosed(self):
        conflicts = self.ole.get_path_conflicts(
            olefile.PATH_CONFLICT_TYPE_COLLISION)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].canonical_path, ("data",))
        self.assertEqual(
            set(entry.entry_type for entry in conflicts[0].entries),
            set([STGTY_STORAGE, STGTY_STREAM]))
        # the same pair also carries an exact duplicate-name diagnostic:
        duplicate = self.ole.get_path_conflicts(
            olefile.PATH_CONFLICT_DUPLICATE_NAME)
        self.assertEqual(len(duplicate), 1)
        self.assertEqual(duplicate[0].canonical_path, ("data",))

    def test_empty_component_is_diagnosed(self):
        conflicts = self.ole.get_path_conflicts(
            olefile.PATH_CONFLICT_EMPTY_COMPONENT)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].canonical_path, ("",))

    def test_fullwidth_homoglyph_has_own_identity(self):
        # The ASCII pair (Macros/MACROS) is intentionally ambiguous, so the
        # homoglyph storage is reached through its own unambiguous identity:
        fullwidth_entry = self.ole.resolve_path(
            [FULLWIDTH_MACROS, "VBA"])[0]
        ascii_vba = [entry for entry in self.ole.direntries
                     if entry is not None
                     and entry.canonical_path == ("macros", "vba")]
        self.assertEqual(len(ascii_vba), 2)
        for ascii_entry in ascii_vba:
            self.assertNotEqual(ascii_entry.sid, fullwidth_entry.sid)
        self.assertEqual(fullwidth_entry.identity,
                         olefile.PATH_SEPARATOR.join(
                             [olefile.canonical_name(FULLWIDTH_MACROS), "vba"]))
        # the original display names are always preserved:
        self.assertEqual(fullwidth_entry.display_path,
                         (FULLWIDTH_MACROS, "VBA"))
        # homoglyphs do not collide, hence no conflict for them:
        homoglyph_conflicts = [
            conflict for conflict in self.ole.path_conflicts
            if olefile.canonical_name(FULLWIDTH_MACROS)
            in conflict.canonical_path]
        self.assertEqual(homoglyph_conflicts, [])

    def test_each_conflict_reason_is_represented(self):
        reasons = self._reasons()
        for expected in (olefile.PATH_CONFLICT_CANONICAL_COLLISION,
                         olefile.PATH_CONFLICT_TYPE_COLLISION,
                         olefile.PATH_CONFLICT_DUPLICATE_NAME,
                         olefile.PATH_CONFLICT_EMPTY_COMPONENT):
            self.assertIn(expected, reasons)


class AmbiguousLookupTest(unittest.TestCase):

    def setUp(self):
        self.entries = [
            (("Macros",), STGTY_STORAGE, 0),
            (("MACROS",), STGTY_STORAGE, 0),
            (("Macros", "VBA"), STGTY_STREAM, FAT_STREAM_SIZE),
            (("MACROS", "VBA"), STGTY_STREAM, FAT_STREAM_SIZE),
        ]
        # entry indexes 2 and 3 are the two colliding VBA streams:
        self.payload = {
            2: b"1" * FAT_STREAM_SIZE,
            3: b"2" * FAT_STREAM_SIZE,
        }
        self.ole = _open(self.entries, stream_data=self.payload)

    def tearDown(self):
        self.ole.close()

    def test_openstream_does_not_pick_an_entry(self):
        with self.assertRaises(olefile.AmbiguousPathError) as context:
            self.ole.openstream("macros/vba")
        self.assertEqual(len(context.exception.entries), 2)

    def test_exists_does_not_pick_an_entry(self):
        with self.assertRaises(olefile.AmbiguousPathError):
            self.ole.exists("MACROS")

    def test_colliding_streams_keep_distinct_content(self):
        vba_entries = [entry for entry in self.ole.direntries
                       if entry is not None and entry.name == "VBA"]
        self.assertEqual(len(vba_entries), 2)
        contents = [
            self.ole._open(entry.isectStart, entry.size).read()
            for entry in vba_entries]
        self.assertNotEqual(contents[0], contents[1])
        self.assertEqual(contents[0], b"1" * FAT_STREAM_SIZE)
        self.assertEqual(contents[1], b"2" * FAT_STREAM_SIZE)

    def test_ambiguous_error_is_an_ole_path_error(self):
        with self.assertRaises(olefile.OlePathError):
            self.ole.openstream("Macros/VBA")

    def test_missing_path_is_not_ambiguous(self):
        self.assertFalse(self.ole.exists("does/not/exist"))
        with self.assertRaises(IOError):
            self.ole.openstream("does/not/exist")

    def test_get_type_propagates_ambiguity(self):
        with self.assertRaises(olefile.AmbiguousPathError):
            self.ole.get_type("macros")

    def test_get_type_still_returns_false_when_missing(self):
        self.assertFalse(self.ole.get_type("does/not/exist"))


class InvalidPathTest(unittest.TestCase):

    def setUp(self):
        self.ole = _open([
            (("Data",), STGTY_STORAGE, 0),
            (("Data", "Data"), STGTY_STREAM, FAT_STREAM_SIZE),
        ])

    def tearDown(self):
        self.ole.close()

    def test_empty_component_in_query(self):
        for invalid in ("/Data", "Data//Data", ["", "Data"]):
            with self.assertRaises(olefile.InvalidPathError):
                self.ole.openstream(invalid)

        for invalid in ("/Data", "Data//Data"):
            with self.assertRaises(olefile.InvalidPathError):
                self.ole.exists(invalid)

    def test_too_long_query_path(self):
        long_path = "/".join(["x"] * (olefile.MAX_OLE_PATH_LENGTH + 1))
        with self.assertRaises(olefile.InvalidPathError):
            self.ole.openstream(long_path)

    def test_stored_too_long_path_is_diagnosed(self):
        component = "A" * 30
        entries = []
        for depth in range(1, 10):
            entries.append((tuple([component] * depth), STGTY_STORAGE, 0))
        entries.append((tuple([component] * 9 + ["leaf"]),
                        STGTY_STREAM, FAT_STREAM_SIZE))
        ole = _open(entries)
        try:
            conflicts = ole.get_path_conflicts(
                olefile.PATH_CONFLICT_PATH_TOO_LONG)
            self.assertTrue(conflicts)
            for conflict in conflicts:
                self.assertEqual(conflict.reason,
                                 olefile.PATH_CONFLICT_PATH_TOO_LONG)
        finally:
            ole.close()


class BackwardCompatibilityTest(unittest.TestCase):

    OLE_FILE = u"tests/images/test-ole-file.doc"

    def test_unique_ascii_path_unchanged(self):
        ole = olefile.OleFileIO(self.OLE_FILE)
        try:
            self.assertEqual(ole.path_conflicts, [])
            self.assertTrue(ole.exists("worddocument"))
            # case-insensitive lookup still works for unique names:
            self.assertTrue(ole.exists("WORDDOCUMENT"))
            self.assertFalse(ole.exists("macros/vba"))
            stream = ole.openstream("WordDocument")
            self.assertGreater(stream.size, 0)
            entry = ole.resolve_path("worddocument")[0]
            self.assertEqual(entry.display_path, ("WordDocument",))
            self.assertEqual(entry.identity, "worddocument")
        finally:
            ole.close()

    def test_listdir_keeps_display_names(self):
        ole = olefile.OleFileIO(self.OLE_FILE)
        try:
            paths = ole.listdir()
            self.assertIn(["WordDocument"], paths)
            for path in paths:
                for component in path:
                    self.assertIsInstance(component, str)
        finally:
            ole.close()


if __name__ == "__main__":
    unittest.main()
