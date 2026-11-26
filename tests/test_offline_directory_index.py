import os
import struct
import tempfile
import unittest
from pathlib import Path

from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.minidumpfile import MinidumpFile
from minidump.offline_index import (
    MisappliedCursorError,
    OfflineDirectoryIndex,
    SourceIdentity,
)


def _write_dump(path, comments):
    """Write a small but structurally valid minidump directory table."""
    directory_rva = 32
    data_rva = directory_rva + len(comments) * 12
    directory = b""
    payloads = b""
    for stream_type, payload in comments:
        stream_type_value = stream_type.value if hasattr(stream_type, "value") else int(stream_type)
        directory += struct.pack("<III", stream_type_value, len(payload), data_rva + len(payloads))
        payloads += payload

    header = struct.pack(
        "<4sHHIIIII4x",
        b"MDMP",
        1,
        1,
        len(comments),
        directory_rva,
        0,
        0,
        0,
    )
    data = header + directory + payloads
    with open(path, "wb") as handle:
        handle.write(data)
    return data


def _comment_dump(path, suffix=b"one"):
    return _write_dump(
        path,
        [
            (MINIDUMP_STREAM_TYPE.CommentStreamA, b"alpha-" + suffix),
            (MINIDUMP_STREAM_TYPE.CommentStreamW, ("beta-" + suffix.decode()).encode("utf-16-le")),
        ],
    )


def _module_dump(path, module_name=b"fictitious-module.dll"):
    directory_rva = 32
    module_rva = directory_rva + 12
    name_rva = module_rva + 4 + 108
    version = struct.pack("<13I", 0xfeef04bd, 0x10000, *([0] * 11))
    module = (
        struct.pack("<QIIII", 0x10000000, 0x1000, 0, 0, name_rva)
        + version
        + struct.pack("<IIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0)
    )
    stream = (
        struct.pack("<I", 1)
        + module
        + struct.pack("<I", len(module_name) * 2)
        + module_name.decode("ascii").encode("utf-16-le")
    )
    entry = struct.pack("<III", MINIDUMP_STREAM_TYPE.ModuleListStream.value, len(stream), module_rva)
    header = struct.pack("<4sHHIIIII4x", b"MDMP", 1, 1, 1, directory_rva, 0, 0, 0)
    with open(path, "wb") as handle:
        handle.write(header + entry + stream)


class OfflineDirectoryIndexTests(unittest.TestCase):


    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_resume_original_file_after_restart(self):
        dump = self.tmp_path / "incident.dmp"
        index_path = self.tmp_path / "incident.idx.json"
        _comment_dump(dump)

        first = OfflineDirectoryIndex(dump, index_path)
        first.build(max_entries=1)
        self.assertEqual(first.next_entry, 1)
        self.assertEqual(len(first.entries), 1)
        self.assertEqual(len(first.sealed_receipts), 2)  # header + one entry
        first_source_id = first.source_id
        first_receipts = first.sealed_receipts
        first.close()

        resumed = OfflineDirectoryIndex(dump, index_path)
        resumed.build()
        self.assertEqual(resumed.source_id, first_source_id)
        self.assertEqual(resumed.next_entry, 2)
        self.assertTrue(resumed.complete)
        self.assertEqual(
            [entry.stream_type_name for entry in resumed.entries],
            ["CommentStreamA", "CommentStreamW"],
        )
        self.assertEqual(len(resumed.sealed_receipts), 3)  # header + both entries
        self.assertEqual(resumed.sealed_receipts[:2], first_receipts)
        resumed.close()

        parsed = MinidumpFile.parse(dump, index_path=index_path)
        try:
            self.assertEqual(parsed.header.NumberOfStreams, 2)
            self.assertEqual(parsed.comment_a.data, "alpha-one")
            self.assertEqual(parsed.comment_w.data, "beta-one")
        finally:
            parsed.close()

    def test_module_list_directory_is_indexed(self):
        dump = self.tmp_path / "modules.dmp"
        index_path = self.tmp_path / "modules.idx.json"
        _module_dump(dump)

        index = OfflineDirectoryIndex(dump, index_path)
        index.build()
        self.assertTrue(index.complete)
        self.assertEqual(index.entries[0].stream_type_name, "ModuleListStream")
        self.assertEqual(index.directories[0].StreamType, MINIDUMP_STREAM_TYPE.ModuleListStream)
        index.close()

        parsed = MinidumpFile.parse(dump, index_path=index_path)
        try:
            self.assertEqual(parsed.modules.modules[0].name, "fictitious-module.dll")
        finally:
            parsed.close()

    def test_same_name_replacement_is_rejected_and_receipts_are_preserved(self):
        original = self.tmp_path / "same-name.dmp"
        replacement = self.tmp_path / "replacement.dmp"
        index_path = self.tmp_path / "same-name.idx.json"
        _comment_dump(original, b"original")
        _comment_dump(replacement, b"replacement")

        first = OfflineDirectoryIndex(original, index_path)
        first.build(max_entries=1)
        old_source_id = first.source_id
        old_receipts = first.sealed_receipts
        first.close()

        os.replace(replacement, original)
        new_source_id = SourceIdentity.from_path(original).source_id
        self.assertNotEqual(new_source_id, old_source_id)

        stale = OfflineDirectoryIndex(original, index_path)
        with self.assertRaises(MisappliedCursorError) as error:
            stale.build()
        self.assertEqual(error.exception.expected_source_id, old_source_id)
        self.assertEqual(error.exception.actual_source_id, new_source_id)
        self.assertIn("Misapplied cursor", str(error.exception))
        stale.close()

        # A failed resume must not overwrite the old checkpoint or its receipts.
        preserved = OfflineDirectoryIndex.load(index_path)
        self.assertEqual(preserved.stored_source_id, old_source_id)
        self.assertEqual(preserved.receipts_by_source[old_source_id], old_receipts)
        self.assertNotIn(new_source_id, preserved.sections)

        # Starting a new section for the replacement is explicit, and keeps the
        # sealed receipts of the original source in the same index store.
        replacement_index = OfflineDirectoryIndex(
            original, index_path, allow_source_change=True
        )
        replacement_index.build()
        self.assertEqual(replacement_index.source_id, new_source_id)
        self.assertTrue(replacement_index.complete)

        combined = OfflineDirectoryIndex.load(index_path)
        self.assertEqual(combined.receipts_by_source[old_source_id], old_receipts)
        self.assertTrue(combined.receipts_by_source[new_source_id])
        self.assertEqual(combined.stored_source_id, new_source_id)
        replacement_index.close()

    def test_unconfirmed_entry_from_old_index_is_not_trusted(self):
        dump = self.tmp_path / "tampered-index.dmp"
        index_path = self.tmp_path / "tampered-index.idx.json"
        _comment_dump(dump)

        index = OfflineDirectoryIndex(dump, index_path)
        index.build(max_entries=1)
        index.close()

        # Rewind only the cursor. The next entry must be read from the source and
        # compared with the sealed entry rather than being accepted from the index.
        loaded = OfflineDirectoryIndex.load(index_path)
        loaded._store["cursor"]["next_entry"] = 0
        loaded.save()

        checkpoint = OfflineDirectoryIndex(dump, index_path)
        checkpoint.build(max_entries=1)
        self.assertEqual(checkpoint.next_entry, 1)
        self.assertIsNotNone(checkpoint.entries[0].receipt)
        self.assertEqual(
            checkpoint.entries[0].receipt.digest,
            checkpoint.entries[0].raw_sha256,
        )
        checkpoint.close()

    def test_default_sidecar_is_resumable(self):
        dump = self.tmp_path / "sidecar.dmp"
        _comment_dump(dump)

        first = OfflineDirectoryIndex(dump)
        self.assertEqual(first.index_path, str(dump) + ".offline-index.json")
        first.build(max_entries=1)
        first.close()

        second = OfflineDirectoryIndex(dump)
        second.build()
        self.assertTrue(second.complete)
        self.assertEqual(second.next_entry, 2)
        second.close()


if __name__ == "__main__":
    unittest.main()
