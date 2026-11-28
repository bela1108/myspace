import unittest
from datetime import date
from os.path import dirname, join

from msoffcrypto.archive import (
    ArchiveMaterial,
    ArchivePolicyGate,
    ArchiveService,
    CurrentPolicyTransferReviewer,
    DEFAULT_POLICY_CUTOFF_DATE,
    FIXED_POLICY_REFERENCE_DATE,
    LegacyReadPermission,
    ReadPermission,
    ReadRequest,
    TransferRejectedError,
    TransferRequest,
    TransferReview,
    identify_format,
)
from msoffcrypto.exceptions import ReadPermissionDeniedError

DATA_DIR = join(dirname(__file__), "inputs")
POLICY_DATE = FIXED_POLICY_REFERENCE_DATE
LEGACY_PASSWORD = "Password1234_"
LEGACY_FILES = (
    ("legacy-doc", "rc4cryptoapi_password.doc", "doc97"),
    ("legacy-xls", "rc4cryptoapi_password.xls", "xls97"),
)


def input_path(name):
    return join(DATA_DIR, name)


def legacy_gate(approved_ids):
    return ArchivePolicyGate(
        LegacyReadPermission(approved_material_ids=approved_ids),
        CurrentPolicyTransferReviewer(),
    )


def load_legacy_password(office_file):
    office_file.load_key(password=LEGACY_PASSWORD)


def material(material_id, filename, trusted_date=True):
    return ArchiveMaterial(
        material_id,
        open(input_path(filename), "rb"),
        source_date=date(2025, 12, 31),
        source_date_trusted=trusted_date,
    )


class ArchivePolicyTest(unittest.TestCase):
    def test_identification_is_separate_from_permission(self):
        for material_id, filename, expected_format in LEGACY_FILES:
            with self.subTest(filename=filename):
                with open(input_path(filename), "rb") as stream:
                    profile = identify_format(stream)

                    self.assertEqual(profile.format, expected_format)
                    self.assertEqual(profile.encryption_type, "rc4_cryptoapi")
                    self.assertTrue(profile.encrypted)
                    self.assertTrue(profile.uses_legacy_encryption)
                    self.assertEqual(profile.key_types, ("password",))

    def test_plain_ppt_is_not_classified_as_legacy_encryption(self):
        with open(input_path("plain.ppt"), "rb") as stream:
            profile = identify_format(stream)

        self.assertEqual(profile.format, "ppt97")
        self.assertIsNone(profile.encryption_type)
        self.assertFalse(profile.encrypted)
        self.assertFalse(profile.uses_legacy_encryption)

    def test_current_agile_result_passes_transfer_review(self):
        reviewer = CurrentPolicyTransferReviewer()
        with open(input_path("example_password.docx"), "rb") as stream:
            archive_material = ArchiveMaterial("current-docx", stream)
            source = identify_format(stream)
            review = reviewer.review_transfer(
                TransferRequest(archive_material, "new-archive", POLICY_DATE),
                source,
                source,
            )

        self.assertTrue(review.is_complete)

    def test_approved_legacy_materials_remain_readable_at_fixed_date(self):
        for material_id, filename, _ in LEGACY_FILES:
            with self.subTest(filename=filename):
                archive_material = material(material_id, filename)
                try:
                    service = ArchiveService(legacy_gate({material_id}))
                    profile, permission, output = service.read_for_investigation(
                        archive_material,
                        "investigation",
                        POLICY_DATE,
                        load_legacy_password,
                    )
                finally:
                    archive_material.stream.close()

                self.assertTrue(profile.encrypted)
                self.assertTrue(permission.allowed)
                self.assertGreater(len(output.getvalue()), 0)

    def test_untrusted_source_date_cannot_authorize_legacy_reads(self):
        for material_id, filename, _ in LEGACY_FILES:
            with self.subTest(filename=filename):
                archive_material = material(material_id, filename, trusted_date=False)
                try:
                    service = ArchiveService(legacy_gate({material_id}))
                    with self.assertRaisesRegex(
                        ReadPermissionDeniedError, "Source date"
                    ):
                        service.read_for_investigation(
                            archive_material, "investigation", POLICY_DATE, load_legacy_password
                        )
                finally:
                    archive_material.stream.close()

    def test_approval_and_trusted_cutoff_are_required_for_legacy_read(self):
        checker = LegacyReadPermission(approved_material_ids={"approved"})
        stream = open(input_path("rc4cryptoapi_password.doc"), "rb")
        try:
            profile = identify_format(stream)
            unapproved = ArchiveMaterial(
                "unapproved", stream, date(2025, 12, 31), True
            )
            decision = checker.authorize_read(
                ReadRequest(unapproved, "investigation", POLICY_DATE), profile
            )
            self.assertFalse(decision.allowed)
            self.assertIn("not approved", decision.reason)

            too_new = ArchiveMaterial("approved", stream, POLICY_DATE, True)
            decision = checker.authorize_read(
                ReadRequest(too_new, "investigation", POLICY_DATE), profile
            )
            self.assertFalse(decision.allowed)
            self.assertIn("cutoff", decision.reason)
        finally:
            stream.close()

    def test_direct_legacy_copies_are_incomplete_for_new_archive(self):
        for material_id, filename, _ in LEGACY_FILES:
            with self.subTest(filename=filename):
                archive_material = material(material_id, filename)
                try:
                    service = ArchiveService(legacy_gate({material_id}))
                    review = service.copy_for_new_archive(
                        archive_material,
                        "new-archive",
                        POLICY_DATE,
                    )
                finally:
                    archive_material.stream.close()

                self.assertFalse(review.is_complete)
                self.assertIn("legacy algorithm", review.reason)

    def test_decrypted_results_are_rejected_as_new_archives(self):
        for material_id, filename, _ in LEGACY_FILES:
            with self.subTest(filename=filename):
                archive_material = material(material_id, filename)
                try:
                    service = ArchiveService(legacy_gate({material_id}))
                    review, source, result, output = service.transfer(
                        archive_material,
                        "new-archive",
                        POLICY_DATE,
                        load_legacy_password,
                    )
                finally:
                    archive_material.stream.close()

                self.assertTrue(source.uses_legacy_encryption)
                self.assertFalse(result.encrypted)
                self.assertFalse(review.is_complete)
                self.assertIn("current encryption", review.reason)
                self.assertGreater(len(output.getvalue()), 0)
                with self.assertRaisesRegex(
                    TransferRejectedError, "current encryption"
                ):
                    legacy_gate({material_id}).review_transfer(
                        TransferRequest(
                            archive_material, "new-archive", POLICY_DATE
                        ),
                        source,
                        result,
                    )

    def test_policy_cutoff_controls_handover_between_reviews(self):
        class HandoffChecker:
            def authorize_read(self, request, profile):
                if request.effective_date < DEFAULT_POLICY_CUTOFF_DATE:
                    return ReadPermission(True, "Legacy handover window", "legacy-policy")
                return ReadPermission(
                    False,
                    "Current policy requires an approved record",
                    "current-policy",
                )

        gate = ArchivePolicyGate(HandoffChecker(), CurrentPolicyTransferReviewer())
        _material_id, filename, _format = LEGACY_FILES[0]
        with open(input_path(filename), "rb") as stream:
            archive_material = ArchiveMaterial("legacy-doc", stream)
            profile = identify_format(stream)
            before = gate.authorize_read(
                ReadRequest(archive_material, "handover", date(2025, 12, 31)), profile
            )
            self.assertEqual(before.policy_version, "legacy-policy")
            with self.assertRaisesRegex(
                ReadPermissionDeniedError, "approved record"
            ):
                gate.authorize_read(
                    ReadRequest(archive_material, "handover", POLICY_DATE), profile
                )

    def test_custom_policy_versions_support_policy_handover(self):
        legacy_permission = LegacyReadPermission(
            approved_material_ids={"legacy-doc"},
            cutoff_date=DEFAULT_POLICY_CUTOFF_DATE,
            policy_version="legacy-policy",
        )
        current_permission = LegacyReadPermission(
            approved_material_ids={"legacy-doc"},
            cutoff_date=DEFAULT_POLICY_CUTOFF_DATE,
            policy_version="current-policy",
        )
        stream = open(input_path("rc4cryptoapi_password.doc"), "rb")
        try:
            profile = identify_format(stream)
            archive_material = ArchiveMaterial(
                "legacy-doc", stream, date(2025, 12, 31), True
            )
            legacy_decision = legacy_permission.authorize_read(
                ReadRequest(
                    archive_material,
                    "handover",
                    date(2025, 12, 31),
                ),
                profile,
            )
            current_decision = current_permission.authorize_read(
                ReadRequest(archive_material, "handover", POLICY_DATE),
                profile,
            )
        finally:
            stream.close()

        self.assertEqual(legacy_decision.policy_version, "legacy-policy")
        self.assertEqual(current_decision.policy_version, "current-policy")
        self.assertTrue(legacy_decision.allowed)
        self.assertTrue(current_decision.allowed)

    def test_caller_can_configure_both_decisions(self):
        class AllowAllReadChecker:
            def authorize_read(self, request, profile):
                return ReadPermission(True, "Caller-approved read", "caller-read")

        class RejectAllTransferReviewer:
            def review_transfer(self, request, source, result):
                return TransferReview(
                    False, "Caller requires remediation", "caller-transfer"
                )

        gate = ArchivePolicyGate(AllowAllReadChecker(), RejectAllTransferReviewer())
        with open(input_path("example_password.docx"), "rb") as stream:
            archive_material = ArchiveMaterial("current-docx", stream)
            source = identify_format(stream)
            permission = gate.authorize_read(
                ReadRequest(archive_material, "caller", POLICY_DATE), source
            )
            review = gate.transfer_reviewer.review_transfer(
                TransferRequest(archive_material, "new-archive", POLICY_DATE),
                source,
                source,
            )

        self.assertEqual(permission.policy_version, "caller-read")
        self.assertEqual(review.policy_version, "caller-transfer")
        self.assertFalse(review.is_complete)


if __name__ == "__main__":
    unittest.main()
