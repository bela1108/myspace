import unittest

from export_test import PE_32

import pefile


class TestEvidenceView(unittest.TestCase):
    def setUp(self):
        self.data = bytes(PE_32)
        self.pe = pefile.PE(data=self.data, fast_load=True)
        self.target = self.pe.sections[0]
        self.target_start = self.target.get_file_offset()
        self.target_end = self.target_start + self.target.sizeof()
        self.target_range = pefile.EvidenceRange(self.target_start, self.target_end)

    def tearDown(self):
        self.pe.close()

    def _sample(self, name, start, end):
        return pefile.ReadOnlySample(
            name,
            self.data[start:end],
            disk_offset=start,
            address=0x7FF000000000 + start,
        )

    def test_full_sample_coverage_can_be_cited_exactly(self):
        sample_a = self._sample("sample-a", self.target_start - 8, self.target_end + 8)
        sample_b = self._sample("sample-b", 0x180, 0x190)
        view = self.pe.get_evidence_view(self.target, samples=[sample_a, sample_b])

        self.assertEqual(view.structure.range, self.target_range)
        self.assertEqual(view.status, "complete")
        self.assertEqual(view.sample_coverage.status, "complete")
        self.assertEqual(view.sample_coverage.gaps, [])
        self.assertEqual(view.sample_coverage.ranges, [self.target_range])

        expected = self.data[self.target_start : self.target_end]
        self.assertEqual(view.cite("disk"), expected)
        self.assertEqual(view.cite_samples(), expected)
        self.assertEqual(view.to_dict()["status"], "complete")
        self.assertEqual(
            view.to_dict()["structure"]["disk"],
            self.target_range.to_dict(),
        )
        sample_claim = next(
            claim
            for segment in view.to_dict()["evidence"]["segments"]
            for claim in segment["claims"]
            if claim["source"] == "sample-a"
        )
        self.assertEqual(sample_claim["source_range"]["offset"], 0x08)
        self.assertEqual(
            sample_claim["source_address"]["offset"],
            0x7FF000000000 + self.target_start,
        )
        self.assertIn("source address base: 0x7ff0000001a0", view.render())

    def test_gap_is_kept_as_an_exact_boundary_and_cannot_be_stitched(self):
        gap_start = self.target_start + 0x10
        gap_end = gap_start + 8
        sample_a = self._sample("sample-a", self.target_start - 8, gap_start)
        sample_b = self._sample("sample-b", gap_end, self.target_end + 8)
        view = self.pe.get_evidence_view(self.target, samples=[sample_a, sample_b])

        gap = pefile.EvidenceRange(gap_start, gap_end)
        self.assertEqual(view.status, "partial")
        self.assertEqual(view.evidence.status, "complete")
        self.assertEqual(view.sample_coverage.status, "partial")
        self.assertEqual(view.sample_coverage.gaps, [gap])
        self.assertEqual(view.sample_gaps, [gap])
        self.assertEqual(
            view.sample_coverage.ranges,
            [
                pefile.EvidenceRange(self.target_start, gap_start),
                pefile.EvidenceRange(gap_end, self.target_end),
            ],
        )
        self.assertNotEqual(view.sample_coverage.status, "complete")

        # The preserved disk copy can still be cited, but only by explicitly
        # naming that source.  The samples are not silently joined.
        self.assertEqual(
            view.cite("disk"),
            self.data[self.target_start : self.target_end],
        )
        with self.assertRaises(pefile.EvidenceUnavailable) as caught:
            view.cite_samples()
        self.assertEqual(caught.exception.boundaries, (gap,))

        with self.assertRaises(pefile.EvidenceUnavailable):
            view.cite("sample-a")

        data = view.to_dict()
        self.assertEqual(data["sample_coverage"]["gaps"], [gap.to_dict()])
        self.assertEqual(data["sample_gaps"], [gap.to_dict()])
        self.assertIn("[0x000001b8, 0x000001c0)", view.render())

    def test_mismatched_overlap_preserves_all_claims_and_blocks_citation(self):
        sample_a = self._sample("sample-a", self.target_start, self.target_end)
        altered = bytearray(self.data[self.target_start : self.target_end])
        altered[0x10] ^= 0xFF
        sample_b = pefile.ReadOnlySample(
            "sample-b",
            bytes(altered),
            disk_offset=self.target_start,
            address=0x7FF000010000,
        )
        view = self.pe.get_evidence_view(self.target, samples=[sample_a, sample_b])

        self.assertEqual(view.status, "disputed")
        self.assertEqual(view.sample_coverage.coverage_status, "complete")
        self.assertEqual(view.sample_coverage.status, "disputed")
        self.assertEqual(view.sample_coverage.integrity, "disputed")
        self.assertEqual(len(view.conflicts), 1)
        self.assertEqual(view.conflicts[0].range, self.target_range)
        self.assertEqual(len(view.conflicts[0].claims), 3)
        hashes = view.conflicts[0].claim_hashes
        self.assertEqual(len(set(hashes)), 2)
        self.assertIn("different bytes", view.conflicts[0].reason)

        with self.assertRaises(pefile.EvidenceUnavailable):
            view.cite("disk")
        with self.assertRaises(pefile.EvidenceUnavailable):
            view.cite_samples()
        self.assertIn("Conflicts preserved", view.render())

    def test_overlap_without_comparable_content_is_disputed(self):
        sample = self._sample("sample-a", self.target_start, self.target_end)
        opaque = pefile.EvidenceSource(
            "opaque-sample",
            data=None,
            spans=[pefile.EvidenceSpan(self.target_start, 0, self.target.sizeof())],
            kind="sample",
            read_only=True,
        )
        view = self.pe.get_evidence_view(self.target, samples=[sample, opaque])

        self.assertEqual(view.status, "disputed")
        self.assertEqual(view.sample_coverage.coverage_status, "complete")
        self.assertEqual(view.sample_coverage.status, "disputed")
        self.assertEqual(view.sample_coverage.integrity, "disputed")
        self.assertEqual(
            view.conflicts[0].reason,
            "overlapping claims cannot be cross-checked",
        )
        with self.assertRaises(pefile.EvidenceUnavailable):
            view.cite("disk")

    def test_disjoint_interval_model_never_fills_a_gap(self):
        view = pefile.EvidenceView(
            pefile.EvidenceStructure("opaque", 0x20, 0x10),
            [
                pefile.EvidenceSource.sample("left", b"ABCDEFGHIJKL", disk_offset=0x18),
                pefile.EvidenceSource.sample("right", b"WXYZ1234", disk_offset=0x28),
            ],
        )

        self.assertEqual(view.status, "partial")
        self.assertEqual(view.gaps, [pefile.EvidenceRange(0x24, 0x28)])
        with self.assertRaises(pefile.EvidenceUnavailable) as caught:
            view.cite_samples()
        self.assertEqual(
            caught.exception.boundaries, (pefile.EvidenceRange(0x24, 0x28),)
        )


if __name__ == "__main__":
    unittest.main()
