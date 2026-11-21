"""
Regression tests for read-only sparse/partial OLE image analysis.
"""

from __future__ import print_function

import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest

_this = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent = os.path.normpath(os.path.join(_this, ".."))
if _parent not in sys.path:
    sys.path.insert(0, _parent)
if _this not in sys.path:
    sys.path.insert(0, _this)

import olefile
from olefile import sparse
import synthetic_ole as synthetic

class SparseTestBase(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = synthetic.build_container()
        self.logical_size = len(self.data)
        self.all_sectors = set(range(self.layout["nb_sect"]))
        self.digests = {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in self.layout["streams"].items()
        }

    def verifier(self, missing):
        available = self.all_sectors - set(missing)
        image = sparse.SparseOleImage(
            io.BytesIO(self.data), available=available,
            logical_size=self.logical_size)
        return sparse.SparseOleVerifier(image)

class TestSyntheticContainer(SparseTestBase):
    def test_standard_olefile_reads_all_streams(self):
        ole = olefile.OleFileIO(io.BytesIO(self.data))
        names = sorted(path[0] for path in ole.listdir())
        self.assertEqual(names, ["BigA", "BigB", "MiniX", "MiniY"])
        for name, payload in self.layout["streams"].items():
            with ole.openstream(name) as stream:
                self.assertEqual(stream.read(), payload)
        ole.close()

    def test_full_manifest_reports_complete_and_real_digests(self):
        verifier = self.verifier(missing=set())
        reports = verifier.verify_all()
        self.assertEqual(len(reports), 4)
        for path, report in reports.items():
            name = path[0]
            self.assertEqual(report.chain_status, sparse.STATUS_COMPLETE)
            self.assertEqual(report.content_status, sparse.STATUS_COMPLETE)
            self.assertEqual(report.content_digest, self.digests[name])
            self.assertEqual(report.missing_sectors, frozenset())

class TestDirectoryIdentity(SparseTestBase):
    def test_identity_reports_name_type_size_and_start(self):
        verifier = self.verifier(missing=set())
        identities = {d.name: d for d in verifier.directory_identities()}
        big_a = identities["BigA"]
        self.assertEqual(big_a.entry_type, olefile.STGTY_STREAM)
        self.assertEqual(big_a.declared_size, 4096)
        self.assertEqual(big_a.isect_start, self.layout["big_a"][0])
        self.assertFalse(big_a.is_minifat)
        mini_x = identities["MiniX"]
        self.assertTrue(mini_x.is_minifat)
        self.assertEqual(mini_x.declared_size, 200)

    def test_identity_available_flag_reflects_missing_data_page(self):
        verifier = self.verifier(missing={self.layout["big_a"][2]})
        identities = {d.name: d for d in verifier.directory_identities()}
        self.assertFalse(identities["BigA"].available)
        self.assertTrue(identities["BigB"].available)

class TestAllocationChain(SparseTestBase):
    def test_full_chain_sectors_match_layout(self):
        verifier = self.verifier(missing=set())
        report = verifier.verify_stream(("BigA",))
        self.assertEqual(report.chain_sectors, self.layout["big_a"])

    def test_chain_kept_when_data_page_missing(self):
        missing_sect = self.layout["big_a"][1]
        verifier = self.verifier(missing={missing_sect})
        report = verifier.verify_stream(("BigA",))
        self.assertEqual(report.chain_status, sparse.STATUS_PARTIAL)
        self.assertEqual(report.chain_sectors, self.layout["big_a"])
        self.assertEqual(report.missing_sectors, frozenset({missing_sect}))

    def test_unrelated_stream_chain_stays_complete(self):
        verifier = self.verifier(missing={self.layout["big_a"][1]})
        report = verifier.verify_stream(("BigB",))
        self.assertEqual(report.chain_status, sparse.STATUS_COMPLETE)
        self.assertEqual(report.missing_sectors, frozenset())

class TestContentIntegrity(SparseTestBase):
    def test_partial_content_reports_gap_and_reduced_present_bytes(self):
        missing_sect = self.layout["big_a"][2]
        verifier = self.verifier(missing={missing_sect})
        report = verifier.verify_stream(("BigA",))
        self.assertEqual(report.content_status, sparse.STATUS_PARTIAL)
        self.assertEqual(report.present_bytes, 4096 - 512)
        offset = 512 * 2
        self.assertIn((offset, offset + 512), report.missing_ranges)

    def test_missing_page_is_not_treated_as_zero_sector(self):
        target = self.layout["big_a"][2]
        zero_data = bytearray(self.data)
        start = 512 * (target + 1)
        zero_data[start:start + 512] = b"\x00" * 512
        full_image = sparse.SparseOleImage(
            io.BytesIO(bytes(zero_data)), available=self.all_sectors,
            logical_size=self.logical_size)
        full_verifier = sparse.SparseOleVerifier(full_image)
        present_report = full_verifier.verify_stream(("BigA",))
        self.assertEqual(present_report.content_status, sparse.STATUS_COMPLETE)
        self.assertEqual(present_report.missing_sectors, frozenset())
        verifier = self.verifier(missing={target})
        missing_report = verifier.verify_stream(("BigA",))
        self.assertEqual(missing_report.content_status, sparse.STATUS_PARTIAL)
        self.assertEqual(missing_report.missing_sectors, frozenset({target}))

    def test_expected_digest_mismatch_flagged_when_content_altered(self):
        target = self.layout["big_b"][0]
        altered = bytearray(self.data)
        start = 512 * (target + 1)
        altered[start] = altered[start] ^ 0xFF
        image = sparse.SparseOleImage(
            io.BytesIO(bytes(altered)), available=self.all_sectors,
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        report = verifier.verify_stream(("BigB",), self.digests["BigB"])
        self.assertEqual(report.content_status, sparse.STATUS_MISMATCH)

    def test_reading_missing_sector_raises_not_zeros(self):
        target = self.layout["big_a"][0]
        image = sparse.SparseOleImage(
            io.BytesIO(self.data),
            available=self.all_sectors - {target},
            logical_size=self.logical_size)
        with self.assertRaises(sparse.SectorUnavailable):
            image.read_sector(target)

class TestSharedMissingPage(SparseTestBase):
    def test_mini_streams_share_page_but_keep_independent_state(self):
        shared = self.layout["mini_root"]
        verifier = self.verifier(missing={shared})
        report_x = verifier.verify_stream(("MiniX",))
        report_y = verifier.verify_stream(("MiniY",))
        self.assertIsNot(report_x, report_y)
        self.assertEqual(report_x.content_status, sparse.STATUS_MISSING)
        self.assertEqual(report_y.content_status, sparse.STATUS_MISSING)
        self.assertEqual(report_x.missing_ranges, report_y.missing_ranges)
        self.assertNotEqual(report_x.gap_aware_digest,
                            report_y.gap_aware_digest)
        self.assertEqual(report_x.path, ("MiniX",))
        self.assertEqual(report_y.path, ("MiniY",))

    def test_restoring_shared_page_repairs_both_streams(self):
        shared = self.layout["mini_root"]
        image = sparse.SparseOleImage(
            io.BytesIO(self.data),
            available=self.all_sectors - {shared},
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        verifier.verify_all()
        refreshed = verifier.reverify({shared})
        names = sorted(path[0] for path in refreshed)
        self.assertEqual(names, ["MiniX", "MiniY"])
        for name in ("MiniX", "MiniY"):
            report = verifier.verify_stream((name,))
            self.assertEqual(report.content_status, sparse.STATUS_COMPLETE)
            self.assertEqual(report.content_digest, self.digests[name])

class TestIncrementalReverify(SparseTestBase):
    def test_only_dependent_stream_is_reverified(self):
        target = self.layout["big_a"][3]
        image = sparse.SparseOleImage(
            io.BytesIO(self.data),
            available=self.all_sectors - {target},
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        verifier.verify_all()
        refreshed = verifier.reverify({target})
        self.assertEqual(list(refreshed), [("BigA",)])
        report = verifier.verify_stream(("BigA",))
        self.assertEqual(report.content_status, sparse.STATUS_COMPLETE)
        self.assertEqual(report.content_digest, self.digests["BigA"])

    def test_unrelated_stream_remains_complete_after_other_page_restored(self):
        target = self.layout["big_a"][3]
        image = sparse.SparseOleImage(
            io.BytesIO(self.data),
            available=self.all_sectors - {target},
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        verifier.verify_all()
        verifier.reverify({target})
        big_b = verifier.verify_stream(("BigB",))
        self.assertEqual(big_b.content_status, sparse.STATUS_COMPLETE)

class TestSparseCopy(SparseTestBase):
    def setUp(self):
        super(TestSparseCopy, self).setUp()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sparse_copy_roundtrip_and_manifest(self):
        source = os.path.join(self.tmp, "source.ole")
        with open(source, "wb") as handle:
            handle.write(self.data)
        missing = {self.layout["big_a"][2]}
        available = sorted(self.all_sectors - missing)
        copy_path = os.path.join(self.tmp, "sparse.bin")
        sparse.write_sparse_copy(source, copy_path, available,
                                 self.logical_size)
        manifest = sparse.read_manifest_sidecar(copy_path)
        self.assertEqual(manifest["logical_size"], self.logical_size)
        self.assertEqual(set(manifest["available_sectors"]), set(available))
        self.assertEqual(os.path.getsize(copy_path), self.logical_size)
        with open(copy_path, "rb") as handle:
            verifier = sparse.open_sparse_image(
                handle, available=set(available),
                logical_size=self.logical_size)
            report = verifier.verify_stream(("BigA",))
            self.assertEqual(report.content_status, sparse.STATUS_PARTIAL)

    def test_repair_one_page_then_reverify_dependent_stream(self):
        source = os.path.join(self.tmp, "source.ole")
        with open(source, "wb") as handle:
            handle.write(self.data)
        target = self.layout["big_a"][2]
        available = sorted(self.all_sectors - {target})
        copy_path = os.path.join(self.tmp, "sparse2.bin")
        sparse.write_sparse_copy(source, copy_path, available,
                                 self.logical_size, write_manifest=False)
        handle = open(copy_path, "r+b")
        verifier = sparse.open_sparse_image(
            handle, available=set(available),
            logical_size=self.logical_size)
        before = verifier.verify_stream(("BigA",))
        self.assertEqual(before.content_status, sparse.STATUS_PARTIAL)
        offset = 512 * (target + 1)
        handle.seek(offset)
        handle.write(self.data[offset:offset + 512])
        refreshed = verifier.reverify({target})
        self.assertEqual(list(refreshed), [("BigA",)])
        after = verifier.verify_stream(("BigA",))
        self.assertEqual(after.content_status, sparse.STATUS_COMPLETE)
        self.assertEqual(after.content_digest, self.digests["BigA"])
        handle.close()

class TestEvidenceLedger(SparseTestBase):
    def test_ledger_records_offsets_and_digests_of_read_sectors(self):
        target = self.layout["big_b"][0]
        verifier = self.verifier(missing={target})
        verifier.verify_all()
        present_sect = self.layout["big_b"][1]
        evidence = verifier.evidence_for_sector(present_sect)
        self.assertEqual(evidence["offset"], 512 * (present_sect + 1))
        self.assertEqual(evidence["size"], 512)
        start = 512 * (present_sect + 1)
        expected = hashlib.sha256(self.data[start:start + 512]).hexdigest()
        self.assertEqual(evidence["sha256"], expected)
        self.assertIsNone(verifier.evidence_for_sector(target))

    def test_ledger_keeps_original_offset_after_repair(self):
        target = self.layout["big_a"][0]
        image = sparse.SparseOleImage(
            io.BytesIO(self.data),
            available=self.all_sectors - {target},
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        verifier.verify_all()
        verifier.reverify({target})
        evidence = verifier.evidence_for_sector(target)
        self.assertEqual(evidence["offset"], 512 * (target + 1))

class TestSourceManifest(SparseTestBase):
    def test_manifest_lists_missing_and_digest(self):
        missing = {self.layout["big_a"][1], self.layout["big_b"][1]}
        verifier = self.verifier(missing=missing)
        manifest = verifier.source_manifest()
        self.assertEqual(set(manifest["missing_sectors"]), missing)
        self.assertEqual(manifest["logical_sector_count"],
                         self.layout["nb_sect"])
        self.assertTrue(manifest["manifest_digest"])

    def test_report_as_dict_is_json_friendly(self):
        verifier = self.verifier(missing={self.layout["big_a"][1]})
        report = verifier.verify_stream(("BigA",))
        payload = report.as_dict()
        self.assertEqual(payload["path"], ["BigA"])
        self.assertIn("gap_aware_digest", payload)
        self.assertIn("directory", payload)

class TestMissingStructuralSectors(SparseTestBase):
    def test_missing_fat_sector_marks_chain_partial_not_complete(self):
        image = sparse.SparseOleImage(
            io.BytesIO(self.data),
            available=self.all_sectors - {self.layout["fat"],},
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        report = verifier.verify_stream(("BigA",))
        self.assertEqual(report.chain_status, sparse.STATUS_PARTIAL)
        self.assertEqual(report.content_status, sparse.STATUS_PARTIAL)
        self.assertGreater(report.present_bytes, 0)

    def test_missing_minifat_sector_marks_mini_stream_partial(self):
        image = sparse.SparseOleImage(
            io.BytesIO(self.data),
            available=self.all_sectors - {self.layout["minifat"],},
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        report = verifier.verify_stream(("MiniX",))
        self.assertEqual(report.chain_status, sparse.STATUS_PARTIAL)

    def test_missing_directory_sector_drops_only_its_entries(self):
        second_dir_sector = 2
        image = sparse.SparseOleImage(
            io.BytesIO(self.data),
            available=self.all_sectors - {second_dir_sector},
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        names = sorted(path[0] for path in verifier.stream_paths())
        self.assertNotIn("MiniY", names)
        self.assertIn("BigA", names)
class TestReadOnlyGuarantee(SparseTestBase):
    def test_source_is_never_written(self):
        digest_before = hashlib.sha256(self.data).hexdigest()

        class ReadOnly(io.BytesIO):
            def write(self, *args, **kwargs):
                raise RuntimeError("source must not be written")

            def truncate(self, *args, **kwargs):
                raise RuntimeError("source must not be truncated")

        image = sparse.SparseOleImage(
            ReadOnly(self.data), available=self.all_sectors,
            logical_size=self.logical_size)
        verifier = sparse.SparseOleVerifier(image)
        verifier.verify_all()
        verifier.reverify({self.layout["big_a"][0]})
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),
                         digest_before)

if __name__ == "__main__":
    unittest.main()
