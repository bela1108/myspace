import base64
import logging
import unittest

from minidump.evidence import (
    EvidenceAccessDenied,
    EvidenceBundle,
    EvidenceIntegrityError,
    build_evidence_view,
    open_evidence_view,
)
from minidump.minidumpfile import MinidumpFile
from tests.synth import build_memory64_dump, build_memory_list_dump

logging.disable(logging.CRITICAL)

RANGES = [
    (0x1000, 0x1100, "raw"),
    (0x1100, 0x1200, "page_summary"),
    (0x1200, 0x1300, "page_summary"),
]


def make_view():
    dump = build_memory_list_dump()
    dump_file = MinidumpFile.parse_bytes(dump)
    view = build_evidence_view(
        dump_file,
        RANGES,
        ticket="IR-2026-001",
        page_size=0x40,
    )
    return dump, dump_file, view


class EvidenceViewTests(unittest.TestCase):
    def test_contiguous_and_descriptor_crossing_reads(self):
        _, _, view = make_view()
        expected = bytes(range(0x100))

        whole = view.read(0x1000, 0x100)
        self.assertEqual(whole, expected)
        self.assertEqual(whole.mode, "raw")
        self.assertFalse(whole.truncated)
        self.assertFalse(whole.denied)

        crossing = view.read(0x1078, 0x10)
        self.assertEqual(crossing, bytes(range(0x78, 0x88)))
        self.assertEqual(crossing.mode, "raw")
        self.assertFalse(crossing.truncated)
        self.assertEqual(len(crossing.receipt["ranges"]), 1)
        self.assertEqual(len(crossing.receipt["ranges"][0]["chunks"]), 2)

    def test_page_summary_and_cross_boundary_reads(self):
        _, _, view = make_view()

        summary = view.read(0x1100, 0x40)
        self.assertEqual(summary, b"")
        self.assertIsNone(summary.data)
        self.assertTrue(summary.suppressed)
        self.assertFalse(summary.truncated)
        self.assertEqual(summary.mode, "page_summary")
        self.assertEqual(len(summary.summary), 1)
        self.assertEqual(summary.summary[0]["start"], 0x1100)
        self.assertEqual(summary.summary[0]["covered_size"], 0x40)
        self.assertTrue(summary.summary[0]["complete"])

        with self.assertRaises(EvidenceAccessDenied):
            view.read_bytes(0x1100, 0x10)

        cross = view.read(0x10E0, 0x40)
        self.assertEqual(cross, bytes(range(0xE0, 0x100)))
        self.assertEqual(cross.mode, "mixed")
        self.assertTrue(cross.truncated)
        self.assertEqual(len(cross.summary), 1)
        self.assertIn("page-summary", cross.receipt["explanation"])
        self.assertIn("raw prefix", cross.receipt["explanation"])

        beyond = view.read(0x1100, 0x140)
        self.assertEqual(beyond, b"")
        self.assertEqual(beyond.mode, "page_summary")
        self.assertFalse(beyond.truncated)
        self.assertEqual(len(beyond.summary), 5)

        denied = view.read(0x0F80, 0x20)
        self.assertEqual(denied, b"")
        self.assertTrue(denied.denied)
        self.assertEqual(denied.receipt["status"], "denied")
        self.assertEqual(denied.receipt["unauthorized_ranges"][0]["reason"], "outside_approved_ranges")

    def test_thread_context_and_memory_reader_share_policy(self):
        _, _, view = make_view()

        thread = view.get_thread(1)
        self.assertIsNotNone(thread)
        self.assertEqual(thread.rsp, 0x1110)
        self.assertEqual(thread.Rsp, 0x1110)

        from_thread = thread.read(0, 0x10)
        self.assertEqual(from_thread.mode, "page_summary")
        self.assertIsNone(from_thread.data)

        from_context_address = view.read(thread.Rsp, 0x10)
        self.assertEqual(from_context_address.mode, "page_summary")

        from_reader = view.get_reader().read(0x1100, 0x10)
        self.assertEqual(from_reader.mode, "page_summary")
        self.assertIsNone(from_reader.data)

        buffered = view.get_buffered_reader()
        buffered.move(0x10E0)
        cross = buffered.read(0x40)
        self.assertEqual(cross, bytes(range(0xE0, 0x100)))
        self.assertEqual(cross.mode, "mixed")
        self.assertEqual(buffered.tell(), 0x1120)

    def test_receipt_preserves_original_address_mapping_and_ticket(self):
        _, dump_file, view = make_view()
        receipt = view.receipt

        self.assertEqual(len(receipt["ranges"]), 3)
        raw_entry, summary_a, summary_b = receipt["ranges"]

        self.assertEqual(raw_entry["original_address"], 0x1000)
        self.assertEqual(raw_entry["original_end"], 0x1100)
        self.assertEqual(raw_entry["ticket"], "IR-2026-001")
        self.assertEqual(raw_entry["mapping_source"]["stream"], "MemoryListStream")
        self.assertIsNotNone(raw_entry["mapping_source"]["file_rva"])
        self.assertEqual(len(raw_entry["raw_chunks"]), 2)
        self.assertEqual(receipt["ticket_id"], "IR-2026-001")

        for entry in (summary_a, summary_b):
            self.assertEqual(entry["access"], "page_summary")
            self.assertEqual(entry["raw_chunks"], [])
            self.assertTrue(entry["pages"])
            self.assertTrue(all("data" not in page for page in entry["pages"]))
            self.assertTrue(all(page["sha256"] for page in entry["pages"]))
            self.assertEqual(entry["mapping_source"]["stream"], "MemoryListStream")

        self.assertEqual(len(view.memory_segments), 3)
        self.assertEqual(view.memory_segments[0].start_address, 0x1000)
        self.assertEqual(view.memory_segments[1].access, "page_summary")
        self.assertEqual(view.memory_segments[1].mapping_source["stream"], "MemoryListStream")
        self.assertTrue(raw_entry["mapping"])
        self.assertTrue(raw_entry["provenance"])
        self.assertEqual(view.get_reader().read(0x1000, 0x10), bytes(range(0x10)))

        raw_layout = view.address_map
        self.assertEqual([item["original_address"] for item in raw_layout], [0x1000, 0x1080])
        self.assertEqual(len(raw_layout), 2)

        raw_reader = dump_file.get_reader()
        self.assertEqual(len(raw_reader.modules), 0)
        self.assertEqual(raw_reader.get_evidence_view(policy=view.policy).read(0x1100, 4).mode, "page_summary")
        constrained = dump_file.get_reader(policy=view.policy)
        self.assertEqual(constrained.read(0x1100, 4).mode, "page_summary")

    def test_handoff_acceptance_and_rehandoff(self):
        dump, _, view = make_view()
        encoded = view.to_bytes()

        self.assertNotIn(b"\xaa" * 0x20, encoded)
        self.assertNotIn(b"\xbb" * 0x20, encoded)
        self.assertNotIn(b"\xaa" * 0x10, encoded)

        bundle = open_evidence_view(encoded)
        self.assertEqual(bundle.read(0x1000, 0x10), bytes(range(0x10)))
        summary = bundle.read(0x1100, 0x10)
        self.assertEqual(summary.mode, "page_summary")
        self.assertIsNone(summary.data)

        accepted = bundle.accept("external-contractor", note="scene accepted")
        self.assertTrue(accepted.accepted)
        self.assertEqual(accepted.custody[-1]["action"], "accepted")
        reloaded = EvidenceBundle.from_bytes(accepted.to_bytes())
        self.assertTrue(reloaded.accepted)
        self.assertEqual(reloaded.custody[-1]["actor"], "external-contractor")
        self.assertEqual(reloaded.read(0x1200, 0x10).mode, "page_summary")

        rehandoff = reloaded.rehandoff("forensics-lab", from_actor="external-contractor")
        self.assertEqual(rehandoff.custody[-1]["action"], "handoff")
        self.assertEqual(rehandoff.custody[-1]["to"], "forensics-lab")
        self.assertEqual(rehandoff.read(0x1000, 0x10), bytes(range(0x10)))
        self.assertEqual(rehandoff.read(0x1100, 0x10).mode, "page_summary")
        self.assertTrue(rehandoff.verify_original(dump).ok)

    def test_verify_original_byte_by_byte_after_acceptance(self):
        dump, dump_file, view = make_view()
        accepted = view.accept("external-contractor")
        verification = accepted.verify_original(dump)
        self.assertTrue(verification.ok)
        self.assertEqual(verification.checked_bytes, len(dump))
        self.assertEqual(verification.source_sha256, view.source_sha256)
        self.assertEqual(len(verification.range_checks), 3)

        tampered = bytearray(dump)
        tampered[dump_file.memory_segments.memory_segments[0].start_file_address] ^= 0xFF
        failed = accepted.verify_original(bytes(tampered))
        self.assertFalse(failed.ok)
        self.assertEqual(failed.mismatches[0]["kind"], "source_sha256")
        with self.assertRaises(Exception):
            accepted.verify_original(bytes(tampered), strict=True)

    def test_bundle_integrity_rejects_changed_raw_data(self):
        _, _, view = make_view()
        manifest = view.to_dict()
        chunk = manifest["entries"][0]["raw_chunks"][0]
        raw = base64.b64decode(chunk["data_b64"])
        chunk["data_b64"] = base64.b64encode(b"X" + raw[1:]).decode("ascii")
        with self.assertRaises(EvidenceIntegrityError):
            EvidenceBundle.from_dict(manifest)

    def test_memory64_stream_provenance(self):
        dump = build_memory64_dump()
        dump_file = MinidumpFile.parse_bytes(dump)
        view = build_evidence_view(
            dump_file,
            [
                (0x2000, 0x2100, "raw"),
                (0x2100, 0x2200, "page_summary"),
            ],
            ticket="IR-2026-064",
            page_size=0x40,
        )
        self.assertEqual(view.read(0x2000, 8), b"raw-data")
        self.assertEqual(view.read(0x2100, 8).mode, "page_summary")
        self.assertEqual(view.receipt["ranges"][0]["mapping_source"]["stream"], "Memory64ListStream")
        self.assertEqual(view.receipt["ranges"][1]["mapping_source"]["stream"], "Memory64ListStream")
        self.assertTrue(view.verify_original(dump).ok)


    def test_unauthorized_gap_has_separate_explanation(self):
        dump = build_memory_list_dump()
        dump_file = MinidumpFile.parse_bytes(dump)
        view = build_evidence_view(
            dump_file,
            [
                (0x1000, 0x1040, "raw"),
                (0x1080, 0x10C0, "raw"),
                (0x1100, 0x1140, "page_summary"),
            ],
            ticket="IR-2026-GAP",
            page_size=0x20,
        )
        result = view.read(0x1030, 0x60)
        self.assertEqual(result, bytes(range(0x30, 0x40)))
        self.assertTrue(result.truncated)
        self.assertEqual(
            result.receipt["unauthorized_ranges"][0]["reason"],
            "outside_approved_ranges",
        )
        self.assertIn("outside every approved range", result.receipt["explanation"])

    def test_descriptor_suppressed_range_has_explanation(self):
        dump = build_memory_list_dump()
        dump_file = MinidumpFile.parse_bytes(dump)
        view = build_evidence_view(
            dump_file,
            [
                (0x1000, 0x1100, "raw"),
                (0x1100, 0x1200, "page_summary"),
                (0x1200, 0x1400, "page_summary"),
            ],
            ticket="IR-2026-DESC",
            page_size=0x40,
        )
        entry = view.receipt["ranges"][2]
        self.assertEqual(entry["status"], "page_summary_truncated")
        self.assertEqual(entry["descriptor_suppressed_size"], 0x100)
        self.assertTrue(
            any("descriptor-suppressed" in text for text in entry["explanations"])
        )
        self.assertEqual(len(entry["pages"]), 8)
        self.assertFalse(entry["pages"][-1]["complete"])

        missing = view.read(0x13C0, 0x40)
        self.assertEqual(missing.mode, "page_summary")
        self.assertEqual(missing.descriptor_suppressed_size, 0x40)
        self.assertEqual(missing.receipt["descriptor_suppressed_size"], 0x40)
        self.assertIn("descriptor-suppressed", missing.receipt["explanation"])

if __name__ == "__main__":
    unittest.main()
