"""Tests for the read-only format evidence report."""

from __future__ import print_function

import os
import struct
import sys
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, ".."))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
END = 0xFFFFFFFE
FREE = 0xFFFFFFFF
FAT = 0xFFFFFFFD


def _directory_entry(name, entry_type, clsid, create_time, modify_time,
                     start=END, size=0):
    raw = bytearray(128)
    name_raw = name.encode("UTF-16LE") + b"\0\0"
    struct.pack_into("<64sHBBIII16sIQQIII", raw, 0,
                     name_raw, len(name_raw), entry_type, 1,
                     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, clsid, 0,
                     create_time, modify_time, start,
                     size & 0xFFFFFFFF, size >> 32)
    return bytes(raw)


def make_v4(create_time=0x01D0000000000000,
            modify_time=0x01D1000000000000,
            header_clsid=b"\0" * 16,
            num_dir_sectors=1):
    """Build a minimal, structurally valid version 4 compound file."""
    header = bytearray(b"\xff" * 512)
    struct.pack_into("<8s16sHHHHHHLLLLLLLLLL", header, 0,
                     MAGIC, header_clsid, 0x003E, 4, 0xFFFE, 12, 6, 0, 0,
                     num_dir_sectors, 1, 1, 0, 0x1000, END, 0, END, 0)
    struct.pack_into("<L", header, 76, 0)
    fat = [FREE] * 1024
    fat[0] = FAT
    fat[1] = END
    root = _directory_entry("Root Entry", olefile.STGTY_ROOT,
                            b"\0" * 16, create_time, modify_time)
    directory = root + b"\0" * (4096 - len(root))
    return (bytes(header) + b"\0" * 3584 +
            struct.pack("<1024L", *fat) + directory)


class TestFormatEvidence(unittest.TestCase):

    def setUp(self):
        self.ole_file = "tests/images/test-ole-file.doc"

    def test_v3_sample_still_reads_and_reports(self):
        ole = olefile.OleFileIO(self.ole_file)
        self.assertTrue(ole.exists("worddocument"))
        report = ole.get_format_evidence()
        self.assertEqual(report.version, 3)
        self.assertEqual(report.format_family, "V3")
        self.assertEqual(report.sector_size, 512)
        self.assertTrue(report.readable)
        self.assertTrue(report.valid)
        self.assertTrue(report.constraints_verified)
        self.assertEqual(report.contradictions, [])
        self.assertTrue(report.clsids["root"])
        self.assertIn("Root Entry/create_time", report.missing_timestamps)
        self.assertFalse(report.directory_times["complete"])
        self.assertFalse(report.attribute_eligibility["root.create_time"]["eligible"])
        self.assertIsNone(report.provenance["generation"])
        self.assertIsNone(report.source_generation)
        ole.close()

    def test_v4_synthetic_sample_reads(self):
        ole = olefile.OleFileIO(make_v4())
        self.assertEqual(ole.dll_version, 4)
        self.assertEqual(ole.sector_size, 4096)
        self.assertEqual(ole.listdir(), [])
        report = ole.get_format_evidence()
        self.assertEqual(report.version, 4)
        self.assertEqual(report.format_family, "V4")
        self.assertEqual(report.sector_size, 4096)
        self.assertTrue(report.valid)
        self.assertEqual(report.contradictions, [])
        self.assertTrue(report.directory_times["complete"])
        self.assertEqual(report.missing_timestamps, [])
        ole.close()

    def test_v4_missing_times_are_not_eligible(self):
        ole = olefile.OleFileIO(make_v4(create_time=0, modify_time=0))
        report = ole.get_format_evidence()
        self.assertEqual(report.version, 4)
        self.assertTrue(report.valid)
        self.assertFalse(report.directory_times["complete"])
        self.assertIn("Root Entry/create_time", report.missing_timestamps)
        self.assertIn("Root Entry/modify_time", report.missing_timestamps)
        self.assertIn("Root Entry/create_time", report.ineligible_attributes)
        self.assertIn("Root Entry/modify_time", report.ineligible_attributes)
        self.assertFalse(report.attribute_eligibility["root.create_time"]["eligible"])
        self.assertFalse(report.attribute_eligibility["root.modify_time"]["eligible"])
        self.assertEqual(report.provenance["status"], "undetermined")
        self.assertIsNone(report.provenance["generation"])
        self.assertIn("incomplete", report.summary)
        ole.close()

    def test_v4_partial_timestamps_are_not_eligible(self):
        ole = olefile.OleFileIO(make_v4(create_time=0x01D0000000000000,
                                        modify_time=0))
        report = ole.get_format_evidence()
        self.assertEqual(report.version, 4)
        self.assertTrue(report.valid)
        self.assertFalse(report.directory_times["complete"])
        self.assertTrue(report.directory_times["partial"])
        self.assertIn("Root Entry/modify_time", report.missing_timestamps)
        self.assertNotIn("Root Entry/create_time", report.missing_timestamps)
        self.assertTrue(report.attribute_eligibility["root.create_time"]["eligible"])
        self.assertFalse(report.attribute_eligibility["root.modify_time"]["eligible"])
        self.assertEqual(report.provenance["status"], "undetermined")
        ole.close()

    def test_incompatible_directory_sector_declaration(self):
        ole = olefile.OleFileIO(make_v4(num_dir_sectors=0))
        report = ole.get_format_evidence()
        self.assertFalse(report.valid)
        self.assertFalse(report.constraints_verified)
        codes = [item.code for item in report.contradictions]
        self.assertIn("header.directory_sector_count", codes)
        self.assertIn("sector.directory_chain_length", codes)
        self.assertEqual(report.provenance["status"], "conflicted")
        self.assertIsNone(report.source_generation)
        ole.close()

    def test_nonzero_header_clsid_is_a_contradiction(self):
        ole = olefile.OleFileIO(make_v4(header_clsid=b"\x11" * 16))
        report = ole.get_format_evidence()
        self.assertFalse(report.valid)
        codes = [item.code for item in report.contradictions]
        self.assertIn("header.clsid", codes)
        self.assertIn("header.clsid", report.ineligible_attributes)
        self.assertEqual(report.clsids["header"], "11111111-1111-1111-1111-111111111111")
        ole.close()

    def test_module_level_helper(self):
        data = make_v4(create_time=0, modify_time=0)
        report = olefile.get_format_evidence(data)
        self.assertEqual(report.version, 4)
        self.assertIn("Root Entry/create_time", report.not_eligible_for_provenance)
        self.assertEqual(report.to_dict()["sector"]["sector_size"], 4096)

    def test_forensics_facade(self):
        from olefile import forensics
        report = forensics.get_format_evidence(self.ole_file)
        self.assertEqual(report.version, 3)
        self.assertTrue(report.read_only)

    def test_report_is_read_only_observation(self):
        ole = olefile.OleFileIO(self.ole_file)
        before = ole.openstream("worddocument").read()
        before_list = ole.listdir()
        report = ole.get_format_evidence()
        after = ole.openstream("worddocument").read()
        self.assertEqual(before, after)
        self.assertEqual(before_list, ole.listdir())
        self.assertIsInstance(report, olefile.FormatEvidence)
        self.assertIs(report(), report)
        ole.close()


if __name__ == "__main__":
    unittest.main()
