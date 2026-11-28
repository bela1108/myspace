"""End-to-end acceptance tests with regular test keys and a fake backend."""

import json
import unittest

from securesystemslib.policy import (
    POLICY_FOR_VERSION,
    CheckOutcome,
    FakeVerifierBackend,
    LocalVerifierBackend,
    MaterialPurpose,
    Receipt,
    check_receipt,
    check_receipts,
)
from securesystemslib.signer import (
    ECDSA_SHA2_NISTP256,
    ED25519,
    RSA_PKCS1V15_SHA256,
    RSASSA_PSS_SHA256,
)
from tests.policy_utils import make_signed_receipt, tamper


class TestPolicyAcceptance(unittest.TestCase):
    """Acceptance matrix for the 2026.1 retirement policy."""

    def setUp(self):
        self.policy = POLICY_FOR_VERSION["2026.1"]
        self.local = LocalVerifierBackend()
        self.fake = FakeVerifierBackend(name="acme-backend")
        self.payload = b"acceptance payload"

    def test_modern_new_material_is_compliant(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSASSA_PSS_SHA256,
            MaterialPurpose.NEW_MATERIAL,
            self.payload,
        )
        result = check_receipt(receipt, self.policy, self.fake)
        self.assertIs(result.outcome, CheckOutcome.COMPLIANT)
        self.assertFalse(result.policy_blocks)
        self.assertFalse(result.environment_blocks)

    def test_legacy_new_material_requires_policy_change_not_env_change(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.NEW_MATERIAL,
            self.payload,
        )
        result = check_receipt(receipt, self.policy, self.fake)
        # The signature itself is perfectly verifiable: only the policy blocks
        # this usage, so re-signing or a policy change is the answer.
        self.assertIs(result.outcome, CheckOutcome.POLICY_CHANGE_REQUIRED)
        self.assertTrue(result.policy_blocks)
        self.assertFalse(result.environment_blocks)
        self.assertEqual(result.backend_name, "acme-backend")

    def test_legacy_historical_receipt_stays_readable_and_verifies(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            self.payload,
        )
        result = check_receipt(receipt, self.policy, self.fake)
        self.assertIs(result.outcome, CheckOutcome.COMPLIANT)
        self.assertTrue(result.reasons)  # review-only note is recorded

    def test_missing_capability_requires_environment_change_only(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            self.payload,
        )
        # The remote backend dropped the legacy verifier; policy permits the
        # review, so this is purely an environment problem.
        partial = FakeVerifierBackend(
            supported=self.local.supported_schemes() - {RSA_PKCS1V15_SHA256},
            name="partial-backend",
        )
        result = check_receipt(receipt, self.policy, partial)
        self.assertIs(result.outcome, CheckOutcome.ENVIRONMENT_CHANGE_REQUIRED)
        self.assertTrue(result.environment_blocks)
        self.assertFalse(result.policy_blocks)

        # Restoring the capability flips the same receipt to compliant
        # without touching the policy.
        recovered = check_receipt(receipt, self.policy, [partial, self.local])
        self.assertIs(recovered.outcome, CheckOutcome.COMPLIANT)
        self.assertEqual(recovered.backend_name, "local-offline")

    def test_unknown_historical_scheme_stays_readable(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            self.payload,
        )
        encoded = receipt.to_dict()
        # An older scheme that neither this build nor the 2026.1 policy knows.
        encoded["key"]["scheme"] = "legacy-rsa-pkcsv15-sha1"
        encoded["key"]["keytype"] = "legacy-rsa"
        old_receipt = Receipt.from_dict(encoded)

        # The policy must explicitly decide the scheme's fate first, even
        # though the receipt itself remains fully readable.
        result = check_receipt(old_receipt, self.policy, self.fake)
        self.assertIs(result.outcome, CheckOutcome.POLICY_CHANGE_REQUIRED)
        self.assertTrue(result.policy_blocks)
        # ...but the receipt content was still fully readable.
        self.assertEqual(old_receipt.payload, self.payload)
        self.assertFalse(old_receipt.verifiable_in_environment)

    def test_backend_outage_on_new_material_is_environment_change(self):
        receipt, _ = make_signed_receipt(
            "ed25519",
            ED25519,
            MaterialPurpose.NEW_MATERIAL,
            self.payload,
        )
        down = FakeVerifierBackend(available=False, name="down")
        result = check_receipt(receipt, self.policy, [down, self.local])
        # Local offline fallback keeps verification working.
        self.assertIs(result.outcome, CheckOutcome.COMPLIANT)
        self.assertEqual(result.backend_name, "local-offline")

        alone = check_receipt(receipt, self.policy, down)
        self.assertIs(alone.outcome, CheckOutcome.ENVIRONMENT_CHANGE_REQUIRED)
        self.assertIsNone(alone.backend_name)

    def test_tampered_signature_is_invalid_not_an_env_or_policy_issue(self):
        receipt, _ = make_signed_receipt(
            "ecdsa",
            ECDSA_SHA2_NISTP256,
            MaterialPurpose.NEW_MATERIAL,
            self.payload,
        )
        result = check_receipt(tamper(receipt), self.policy, self.fake)
        self.assertIs(result.outcome, CheckOutcome.SIGNATURE_INVALID)
        self.assertFalse(result.policy_blocks)
        self.assertFalse(result.environment_blocks)

    def test_report_separates_policy_and_environment_actions(self):
        legacy_new, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.NEW_MATERIAL,
            b"new legacy",
        )
        legacy_review, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            b"old legacy",
        )
        modern_new, _ = make_signed_receipt(
            "rsa",
            RSASSA_PSS_SHA256,
            MaterialPurpose.NEW_MATERIAL,
            b"new modern",
        )
        partial = FakeVerifierBackend(
            supported=self.local.supported_schemes() - {RSA_PKCS1V15_SHA256},
            name="partial-backend",
        )

        report = check_receipts(
            [legacy_new, legacy_review, modern_new],
            self.policy,
            partial,
        )
        self.assertFalse(report.compliant)
        counts = report.outcomes()
        self.assertEqual(counts[CheckOutcome.POLICY_CHANGE_REQUIRED], 1)
        self.assertEqual(counts[CheckOutcome.ENVIRONMENT_CHANGE_REQUIRED], 1)
        self.assertEqual(counts[CheckOutcome.COMPLIANT], 1)

        policy_actions = report.policy_changes()
        env_actions = report.environment_changes()
        self.assertEqual(
            [item.scheme for item in policy_actions],
            [RSA_PKCS1V15_SHA256],
        )
        self.assertEqual(
            [item.scheme for item in env_actions],
            [RSA_PKCS1V15_SHA256],
        )
        self.assertTrue(all(item.policy_blocks for item in policy_actions))
        self.assertTrue(all(item.environment_blocks for item in env_actions))

        serialized = report.to_dict()
        json.dumps(serialized)  # report is machine readable
        text = report.to_text()
        self.assertIn("policy_change_required", text)
        self.assertIn("environment_change_required", text)
        self.assertIn("ACTION REQUIRED", text)


if __name__ == "__main__":
    unittest.main()
