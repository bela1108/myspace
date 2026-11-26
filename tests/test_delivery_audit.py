import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import delivery_audit  # noqa: E402


class MinimalPeFixtureTests(unittest.TestCase):
    def test_pe32_and_pe32plus_headers(self):
        cases = [
            ("x86", "IMAGE_FILE_MACHINE_I386", "PE32", "0x014C"),
            ("x64", "IMAGE_FILE_MACHINE_AMD64", "PE32+", "0x8664"),
        ]
        for architecture, machine_name, magic_name, machine_hex in cases:
            with self.subTest(architecture=architecture):
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = Path(temp_dir) / "empty.exe"
                    path.write_bytes(delivery_audit.minimal_pe_bytes(architecture))
                    observed = delivery_audit.inspect_pe(path)

                self.assertEqual(observed["machine"]["name"], machine_name)
                self.assertEqual(observed["machine"]["hex"], machine_hex)
                self.assertEqual(observed["magic"]["name"], magic_name)
                self.assertEqual(observed["subsystem"]["name"], "IMAGE_SUBSYSTEM_WINDOWS_CUI")
                self.assertEqual(observed["subsystem_version"], "6.1")
                self.assertEqual(observed["image_version"], "1.0")
                self.assertTrue(observed["image_declaration"]["executable_image"])
                self.assertIn("checksum", observed["old_contract_uncovered_fields"])

    def test_dotted_version_floor_pads_short_versions(self):
        self.assertTrue(delivery_audit.version_at_least("1.0", "1.0.0"))
        self.assertTrue(delivery_audit.version_at_least("6.1.7601", "6.1"))
        self.assertFalse(delivery_audit.version_at_least("0.9.9", "1.0.0"))


class AcceptancePacketTests(unittest.TestCase):
    def setUp(self):
        self.report = delivery_audit.run_audit()

    def test_inventory_uses_name_and_version_floor(self):
        excluded = {item["inventory_id"]: item for item in self.report["inventory_filter"]}
        self.assertEqual(excluded["INV-BENCH-090"]["reason"], "below_version_floor")
        self.assertEqual(
            excluded["INV-CABLE-001"]["reason"], "product_name_not_in_contract"
        )
        self.assertEqual(excluded["INV-BENCH-100"]["status"], "eligible")

    def test_narrow_receipt_holds_only_unlisted_batch(self):
        self.assertEqual([item["batch_id"] for item in self.report["holds"]], ["LOT-X64-C"])
        batch_decisions = {
            item["batch_id"]: item["decision"] for item in self.report["batches"]
        }
        self.assertEqual(batch_decisions["LOT-X86-A"], "ready_to_accept")
        self.assertEqual(batch_decisions["LOT-X64-B"], "ready_to_accept")
        self.assertEqual(batch_decisions["LOT-X64-C"], "hold")

    def test_contract_clauses_are_checked(self):
        checks = {
            (batch["batch_id"], check["check_id"]): check
            for batch in self.report["batches"]
            for check in batch["checks"]
        }
        for batch_id in ["LOT-X86-A", "LOT-X64-B", "LOT-X64-C"]:
            self.assertEqual(checks[(batch_id, "machine-type")]["status"], "pass")
            self.assertEqual(checks[(batch_id, "subsystem-version")]["status"], "pass")
            self.assertEqual(checks[(batch_id, "image-declaration")]["status"], "pass")

    def test_missing_asset_binding_clause_is_unverifiable(self):
        self.assertEqual(
            [item["clause_id"] for item in self.report["unverifiable_clauses"]],
            ["CL-5.2"],
        )

    def test_equal_values_from_separate_batches_keep_provenance(self):
        amd64_groups = [
            group
            for group in self.report["provenance_groups"]
            if group["header_values"]["Machine"] == "IMAGE_FILE_MACHINE_AMD64"
        ]
        self.assertEqual(len(amd64_groups), 1)
        batch_ids = [
            source["batch_id"] for source in amd64_groups[0]["provenance"]
        ]
        seal_ids = [source["seal_id"] for source in amd64_groups[0]["provenance"]]
        self.assertEqual(batch_ids, ["LOT-X64-B", "LOT-X64-C"])
        self.assertEqual(seal_ids, ["SEAL-20261127-B2", "SEAL-20261127-C3"])

    def test_repeated_field_values_keep_each_batch_source(self):
        subsystem_versions = [
            item
            for item in self.report["field_provenance"]
            if item["field"] == "SubsystemVersion" and item["value"] == "6.1"
        ]
        self.assertEqual(len(subsystem_versions), 1)
        batch_ids = [
            source["batch_id"]
            for source in subsystem_versions[0]["provenance"]
        ]
        self.assertEqual(batch_ids, ["LOT-X86-A", "LOT-X64-B", "LOT-X64-C"])


if __name__ == "__main__":
    unittest.main()
