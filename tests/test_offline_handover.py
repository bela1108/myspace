"""Offline wrapper evidence and deterministic handover-plan regressions."""

import copy
import io
import unittest
from pathlib import Path

from msoffcrypto.evidence import inspect_file
from msoffcrypto.handover import VirtualClock, build_plan, render_markdown, replay_plan

DATA_DIR = Path(__file__).parent / "inputs"


class OfflineEvidenceTest(unittest.TestCase):
    def test_macro_free_fixtures_are_read_from_the_wrapper(self):
        cases = (
            ("example_password.docx", "ooxml", "agile", "AES", 256, True),
            ("ecma376standard_password.docx", "ooxml", "standard", "AES", 128, True),
            ("rc4cryptoapi_password.doc", "doc97", "rc4_cryptoapi", "RC4", 128, True),
            ("rc4cryptoapi_password.xls", "xls97", "rc4_cryptoapi", "RC4", 128, True),
            ("xor_password_123456789012345.xls", "xls97", "xor", "XOR", 16, True),
            ("rc4cryptoapi_password.ppt", "ppt97", "rc4_cryptoapi", "RC4", 128, True),
            ("plain.doc", "doc97", "plain", None, None, False),
        )
        for name, format_name, scheme, cipher, key_bits, encrypted in cases:
            with self.subTest(name=name):
                evidence = inspect_file(DATA_DIR / name)
                self.assertEqual(evidence.format, format_name)
                self.assertEqual(evidence.scheme, scheme)
                self.assertEqual(evidence.cipher, cipher)
                self.assertEqual(evidence.key_bits, key_bits)
                self.assertEqual(evidence.encrypted, encrypted)
                self.assertTrue(evidence.supported, evidence.error)
                self.assertIsNone(evidence.error)
                self.assertEqual(len(evidence.file_sha256), 64)
                self.assertEqual(len(evidence.evidence_digest), 64)
                self.assertNotIn("salt", evidence.details)
                self.assertNotIn("encryptedVerifier", evidence.details)
                if encrypted:
                    self.assertTrue(evidence.protected_streams)

    def test_digest_is_reproducible_and_file_handle_is_preserved(self):
        path = DATA_DIR / "example_password.docx"
        first = inspect_file(path)
        raw = path.read_bytes()
        second = inspect_file(io.BytesIO(raw))
        self.assertEqual(first.evidence_digest, second.evidence_digest)
        self.assertEqual(first.file_sha256, second.file_sha256)
        with path.open("rb") as handle:
            handle.seek(37)
            third = inspect_file(handle)
            self.assertEqual(handle.tell(), 37)
            self.assertFalse(handle.closed)
        self.assertEqual(first.evidence_digest, third.evidence_digest)

    def test_plain_ooxml_zip_is_reported_as_plain(self):
        evidence = inspect_file(Path(__file__).parent / "outputs" / "example.docx")
        self.assertEqual(evidence.container, "zip")
        self.assertEqual(evidence.format, "ooxml")
        self.assertEqual(evidence.scheme, "plain")
        self.assertFalse(evidence.encrypted)
        self.assertTrue(evidence.supported)


def _request():
    return {
        "schema": "msoffcrypto.handover-request/v1",
        "clock_start": "2031-05-01T08:00:00Z",
        "clock_end": "2031-05-01T15:00:00Z",
        "allowed_checks": ["shell", "sealed_receipt"],
        "defaults": {
            "inspect_seconds": "60s",
            "seal_seconds": "30s",
            "handover_seconds": "90s",
        },
        "duties": [
            {
                "id": "shell-only",
                "format": "docx",
                "required_checks": ["shell"],
                "custodian": "records-desk",
                "deliver": False,
            },
            {
                "id": "doc-receipt",
                "format": "doc97",
                "required_checks": ["sealed_receipt"],
                "custodian": "evidence-custodian",
            },
            {
                "id": "xls-receipt",
                "format": "xls97",
                "required_checks": ["sealed_receipt"],
                "custodian": "evidence-custodian",
            },
            {
                "id": "payload-only",
                "format": "xlsx",
                "required_checks": ["payload_decrypt"],
                "custodian": "evidence-custodian",
            },
        ],
        "custodian_windows": {
            "evidence-custodian": [
                {"id": "slot-a", "start": "2031-05-01T10:00:00Z", "end": "2031-05-01T10:02:00Z"},
                {"id": "slot-b", "start": "2031-05-01T13:00:00Z", "end": "2031-05-01T13:05:00Z"},
            ]
        },
        "evidence": [
            {
                "id": "ev-shell",
                "path": str(DATA_DIR / "example_password.docx"),
                "duty": "shell-only",
                "available_from": "2031-05-01T08:00:00Z",
                "available_until": "2031-05-01T09:00:00Z",
                "expires_at": "2031-05-01T09:00:00Z",
            },
            {
                "id": "ev-doc",
                "path": str(DATA_DIR / "rc4cryptoapi_password.doc"),
                "duty": "doc-receipt",
                "available_from": "2031-05-01T08:00:00Z",
                "available_until": "2031-05-01T11:00:00Z",
                "expires_at": "2031-05-01T11:00:00Z",
            },
            {
                "id": "ev-xls-a",
                "path": str(DATA_DIR / "rc4cryptoapi_password.xls"),
                "duty": "xls-receipt",
                "available_from": "2031-05-01T08:00:00Z",
                "available_until": "2031-05-01T09:30:00Z",
                "expires_at": "2031-05-01T11:00:00Z",
            },
            {
                "id": "ev-xls-b",
                "path": str(DATA_DIR / "xor_password_123456789012345.xls"),
                "duty": "xls-receipt",
                "available_from": "2031-05-01T08:00:00Z",
                "available_until": "2031-05-01T09:30:00Z",
                "expires_at": "2031-05-01T11:00:00Z",
            },
            {
                "id": "ev-payload",
                "path": str(DATA_DIR / "example_password.xlsx"),
                "duty": "payload-only",
                "available_from": "2031-05-01T08:00:00Z",
                "available_until": "2031-05-01T09:00:00Z",
                "expires_at": "2031-05-01T09:00:00Z",
            },
        ],
    }


class HandoverPlanTest(unittest.TestCase):
    def test_minimal_checks_conflicts_and_extension_locations(self):
        plan = build_plan(_request())
        items = {item["id"]: item for item in plan["items"]}

        self.assertEqual(items["ev-shell"]["selected_check"], "shell")
        self.assertEqual(items["ev-shell"]["operations"], ["inspect"])
        self.assertNotIn("seal", items["ev-shell"]["operations"])
        self.assertNotIn("handover", items["ev-shell"]["operations"])

        self.assertEqual(items["ev-xls-a"]["selected_check"], "sealed_receipt")
        self.assertEqual(items["ev-xls-a"]["operations"], ["inspect", "seal", "handover"])
        self.assertEqual(items["ev-xls-a"]["status"], "complete")

        deferred = {entry["location"]: entry for entry in plan["deferred"]}
        second_handover = deferred["ev-xls-b:handover:evidence-custodian"]
        self.assertEqual(second_handover["reason"], "custodian_conflict")
        self.assertIn("ev-xls-a", second_handover["blocking"])
        self.assertGreater(second_handover["extension_seconds"], 0)

        payload = deferred["ev-payload:plan:-"]
        self.assertEqual(payload["reason"], "check_not_allowed")
        self.assertEqual(items["ev-payload"]["selected_check"], None)
        self.assertEqual(items["ev-payload"]["operations"], [])
        self.assertFalse(any(op["check"] == "payload_decrypt" for op in plan["operations"]))

        self.assertTrue(all(op["outer_wrapper_only"] for op in plan["operations"]))
        self.assertEqual(len(plan["receipts"]), 3)
        self.assertEqual(len(plan["handovers"]), 1)

    def test_plan_and_replay_are_deterministic(self):
        first = build_plan(_request())
        second = build_plan(_request())
        self.assertEqual(first["plan_digest"], second["plan_digest"])
        self.assertEqual(first["request_digest"], second["request_digest"])

        replay = replay_plan(first)
        self.assertTrue(replay["ok"], replay["errors"])
        self.assertEqual(replay["handover_count"], 1)
        self.assertTrue(replay["events"])

        tampered = copy.deepcopy(first)
        tampered["operations"][0]["start"] = "2031-05-01T07:00:00Z"
        result = replay_plan(tampered)
        self.assertFalse(result["ok"])
        self.assertIn("plan_digest mismatch", result["errors"])

    def test_virtual_clock_cannot_move_backwards(self):
        clock = VirtualClock("2031-05-01T08:00:00Z")
        clock.advance_to("2031-05-01T09:00:00Z")
        self.assertEqual(clock.now.hour, 9)
        with self.assertRaises(ValueError):
            clock.advance_to("2031-05-01T08:59:59Z")

    def test_markdown_contains_conflict_location_and_scope(self):
        text = render_markdown(build_plan(_request()))
        self.assertIn("ev-xls-b:handover:evidence-custodian", text)
        self.assertIn("仅保护外层", text)
        self.assertIn("封存回执", text)


if __name__ == "__main__":
    unittest.main()
