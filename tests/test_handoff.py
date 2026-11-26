import unittest
import unittest.mock
from pathlib import Path
from tempfile import TemporaryDirectory

from msoffcrypto.handoff import (
    ExhibitAuthorization,
    HandoffPlanner,
    HandoffQueue,
    HandoffStage,
    ProtectionProfile,
    Recipient,
    inspect_protection_file,
)


DATA_DIR = Path(__file__).parent / "inputs"


LEGACY_DEPARTMENTS = [
    Recipient(
        department_id="dept-legacy-a",
        department_name="旧档处理一组",
        protection_types=frozenset({"rc4_cryptoapi", "rc4", "xor_obfuscation"}),
        stages=frozenset({HandoffStage.CONVERT, HandoffStage.VERIFY_PROTECTION}),
    ),
    Recipient(
        department_id="dept-legacy-b",
        department_name="旧档处理二组",
        protection_types=frozenset({"rc4_cryptoapi", "rc4", "xor_obfuscation"}),
        stages=frozenset({HandoffStage.CONVERT}),
    ),
]

BACKUP_TEAM = Recipient(
    department_id="backup-verify",
    department_name="备份核验组",
    protection_types=frozenset(
        {
            "ecma376_agile",
            "ecma376_standard",
            "rc4_cryptoapi",
            "rc4",
            "xor_obfuscation",
        }
    ),
    stages=frozenset({HandoffStage.VERIFY_PROTECTION}),
)


class ProtectionInspectionTest(unittest.TestCase):
    def test_identifies_legal_examples_without_decrypting(self):
        expected = {
            "example_password.docx": ("ooxml", "ecma376_agile", True),
            "ecma376standard_password.docx": ("ooxml", "ecma376_standard", True),
            "rc4cryptoapi_password.doc": ("doc97", "rc4_cryptoapi", True),
            "rc4cryptoapi_password.xls": ("xls97", "rc4_cryptoapi", True),
            "rc4cryptoapi_password.ppt": ("ppt97", "rc4_cryptoapi", True),
            "xor_password_123456789012345.xls": ("xls97", "xor_obfuscation", True),
            "plain.doc": ("doc97", "plain", False),
            "plain.xls": ("xls97", "plain", False),
            "plain.ppt": ("ppt97", "plain", False),
        }

        for filename, (office_format, protection_type, encrypted) in expected.items():
            with self.subTest(filename):
                profile = inspect_protection_file(DATA_DIR / filename)
                self.assertEqual(profile.format, office_format)
                self.assertEqual(profile.protection_type, protection_type)
                self.assertEqual(profile.encrypted, encrypted)

        agile = inspect_protection_file(DATA_DIR / "example_password.docx")
        standard = inspect_protection_file(
            DATA_DIR / "ecma376standard_password.docx"
        )
        self.assertEqual(agile.key_types, ("password", "private_key", "secret_key"))
        self.assertEqual(standard.key_types, ("password", "secret_key"))


class HandoffPlannerTest(unittest.TestCase):
    def setUp(self):
        self.doc_path = DATA_DIR / "rc4cryptoapi_password.doc"
        self.profile = inspect_protection_file(self.doc_path)

    def test_same_protection_type_can_enter_different_queues(self):
        planner = HandoffPlanner(
            recipients=LEGACY_DEPARTMENTS,
            backup_team=BACKUP_TEAM,
            authorizations=[
                ExhibitAuthorization(
                    exhibit_id="EX-LEGACY-001",
                    protection_type="rc4_cryptoapi",
                    stages=frozenset(
                        {HandoffStage.VERIFY_PROTECTION, HandoffStage.CONVERT}
                    ),
                ),
                ExhibitAuthorization(
                    exhibit_id="EX-LEGACY-002",
                    protection_type="rc4_cryptoapi",
                    stages=frozenset({HandoffStage.VERIFY_PROTECTION}),
                ),
            ],
        )

        transferable = planner.plan("EX-LEGACY-001", self.doc_path, self.profile)
        verifiable = planner.plan("EX-LEGACY-002", self.doc_path, self.profile)

        self.assertEqual(transferable.queue, HandoffQueue.TRANSFERABLE)
        self.assertEqual(
            [plan.recipient.department_id for plan in transferable.plans],
            ["dept-legacy-a", "dept-legacy-b"],
        )
        self.assertEqual(verifiable.queue, HandoffQueue.VERIFIABLE)
        self.assertEqual(verifiable.plans[0].recipient.department_id, "backup-verify")
        self.assertEqual(
            [condition.code for condition in verifiable.missing_conditions],
            ["CASE_CONVERT_AUTH"],
        )

    def test_backup_team_cannot_convert_even_when_case_is_authorized(self):
        planner = HandoffPlanner(
            recipients=[],
            backup_team=BACKUP_TEAM,
            authorizations=[
                ExhibitAuthorization(
                    exhibit_id="EX-LEGACY-003",
                    protection_type="rc4_cryptoapi",
                    stages=frozenset(
                        {HandoffStage.VERIFY_PROTECTION, HandoffStage.CONVERT}
                    ),
                )
            ],
        )

        decision = planner.plan("EX-LEGACY-003", self.doc_path, self.profile)

        self.assertEqual(decision.queue, HandoffQueue.VERIFIABLE)
        self.assertEqual(decision.plans[0].recipient.department_id, "backup-verify")
        self.assertEqual(decision.plans[0].stage, HandoffStage.VERIFY_PROTECTION)
        self.assertEqual(
            [condition.code for condition in decision.missing_conditions],
            ["DEPARTMENT_CAPABILITY"],
        )

    def test_plain_exhibit_needs_convert_authorization_for_transfer(self):
        planner = HandoffPlanner(
            recipients=[
                Recipient(
                    department_id="plain-ops",
                    department_name="普通档处理组",
                    protection_types=frozenset({"plain"}),
                    stages=frozenset({HandoffStage.CONVERT}),
                )
            ],
            backup_team=BACKUP_TEAM,
            authorizations=[
                ExhibitAuthorization(
                    exhibit_id="EX-PLAIN-001",
                    protection_type="plain",
                    stages=frozenset({HandoffStage.VERIFY_PROTECTION}),
                )
            ],
        )

        decision = planner.plan("EX-PLAIN-001", DATA_DIR / "plain.doc")

        self.assertEqual(decision.profile.protection_type, "plain")
        self.assertEqual(decision.queue, HandoffQueue.VERIFIABLE)
        self.assertEqual(
            [condition.code for condition in decision.missing_conditions],
            ["CASE_CONVERT_AUTH"],
        )
        self.assertEqual(decision.plans[0].stage, HandoffStage.VERIFY_PROTECTION)

    def test_missing_verify_authorization_requires_signature(self):
        planner = HandoffPlanner(
            recipients=LEGACY_DEPARTMENTS,
            backup_team=BACKUP_TEAM,
            authorizations=[
                ExhibitAuthorization(
                    exhibit_id="EX-LEGACY-004",
                    protection_type="rc4_cryptoapi",
                    stages=frozenset({HandoffStage.CONVERT}),
                )
            ],
        )

        decision = planner.plan("EX-LEGACY-004", self.doc_path, self.profile)

        self.assertEqual(decision.queue, HandoffQueue.SIGNATURE_REQUIRED)
        self.assertEqual(decision.plans, ())
        self.assertEqual(
            [condition.code for condition in decision.missing_conditions],
            ["CASE_VERIFY_AUTH"],
        )

    def test_authorization_type_mismatch_requires_signature(self):
        planner = HandoffPlanner(
            recipients=LEGACY_DEPARTMENTS,
            backup_team=BACKUP_TEAM,
            authorizations=[
                ExhibitAuthorization(
                    exhibit_id="EX-LEGACY-006",
                    protection_type="rc4",
                    stages=frozenset(
                        {HandoffStage.VERIFY_PROTECTION, HandoffStage.CONVERT}
                    ),
                )
            ],
        )

        decision = planner.plan("EX-LEGACY-006", self.doc_path, self.profile)

        self.assertEqual(decision.queue, HandoffQueue.SIGNATURE_REQUIRED)
        self.assertEqual(decision.plans, ())
        self.assertEqual(
            [condition.code for condition in decision.missing_conditions],
            ["CASE_PROTECTION_MISMATCH", "CASE_CONVERT_AUTH"],
        )

    def test_unrecognized_profile_requires_specialist_signature(self):
        planner = HandoffPlanner(
            recipients=LEGACY_DEPARTMENTS,
            backup_team=BACKUP_TEAM,
            authorizations=[],
        )
        profile = ProtectionProfile(
            format="unknown",
            protection_type="unrecognized",
            encrypted=False,
            key_types=(),
            detail="Unsupported container",
        )

        decision = planner.plan("EX-UNKNOWN-001", "unknown.bin", profile)

        self.assertEqual(decision.queue, HandoffQueue.SIGNATURE_REQUIRED)
        self.assertEqual(
            [condition.code for condition in decision.missing_conditions],
            ["UNRECOGNIZED_FORMAT"],
        )

    def test_unreadable_office_container_is_caught_and_queued_for_signature(self):
        planner = HandoffPlanner(
            recipients=LEGACY_DEPARTMENTS,
            backup_team=BACKUP_TEAM,
            authorizations=[],
        )

        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "not-office.bin"
            path.write_bytes(b"definitely not an office container")
            decision = planner.plan("EX-UNKNOWN-002", path)

        self.assertEqual(decision.queue, HandoffQueue.SIGNATURE_REQUIRED)
        self.assertEqual(decision.profile.protection_type, "unrecognized")

    def test_planner_never_calls_key_loading_or_decryption(self):
        planner = HandoffPlanner(
            recipients=LEGACY_DEPARTMENTS,
            backup_team=BACKUP_TEAM,
            authorizations=[
                ExhibitAuthorization(
                    exhibit_id="EX-LEGACY-005",
                    protection_type="rc4_cryptoapi",
                    stages=frozenset({HandoffStage.VERIFY_PROTECTION}),
                )
            ],
        )

        with unittest.mock.patch(
            "msoffcrypto.format.doc97.Doc97File.load_key",
            side_effect=AssertionError("load_key must not be called"),
        ), unittest.mock.patch(
            "msoffcrypto.format.doc97.Doc97File.decrypt",
            side_effect=AssertionError("decrypt must not be called"),
        ):
            decision = planner.plan("EX-LEGACY-005", self.doc_path)

        self.assertEqual(decision.queue, HandoffQueue.VERIFIABLE)


if __name__ == "__main__":
    unittest.main()
