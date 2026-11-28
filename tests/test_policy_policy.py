"""Tests for versioned signature policies and material purposes."""

import unittest

from securesystemslib.policy import (
    LEGACY_RSA_PKCS1V15_SCHEMES,
    POLICY_FOR_VERSION,
    MaterialPurpose,
    VerificationPolicy,
)
from securesystemslib.signer import RSA_PKCS1V15_SHA256, RSASSA_PSS_SHA256


class TestVerificationPolicy(unittest.TestCase):
    def test_shipped_versions(self):
        self.assertEqual(set(POLICY_FOR_VERSION), {"2025.2", "2026.1"})
        old = POLICY_FOR_VERSION["2025.2"]
        new = POLICY_FOR_VERSION["2026.1"]

        # Legacy class is fully active in the old policy.
        self.assertTrue(
            old.is_allowed_for(RSA_PKCS1V15_SHA256, MaterialPurpose.NEW_MATERIAL)
        )
        self.assertFalse(old.is_review_only(RSA_PKCS1V15_SHA256))

        # The new policy retires the class for new material but keeps review.
        self.assertFalse(
            new.is_allowed_for(RSA_PKCS1V15_SHA256, MaterialPurpose.NEW_MATERIAL)
        )
        self.assertTrue(new.is_review_only(RSA_PKCS1V15_SHA256))
        self.assertTrue(
            new.is_allowed_for(RSA_PKCS1V15_SHA256, MaterialPurpose.HISTORICAL_REVIEW)
        )

        # Modern schemes are unaffected.
        self.assertTrue(
            new.is_allowed_for(RSASSA_PSS_SHA256, MaterialPurpose.NEW_MATERIAL)
        )
        self.assertFalse(new.is_review_only(RSASSA_PSS_SHA256))

    def test_reviewable_schemes_cover_historical_receipts(self):
        new = POLICY_FOR_VERSION["2026.1"]
        self.assertEqual(
            new.reviewable_schemes,
            new.new_material_schemes | new.review_only_schemes,
        )
        self.assertTrue(LEGACY_RSA_PKCS1V15_SCHEMES.issubset(new.reviewable_schemes))

    def test_unknown_scheme_is_a_policy_question(self):
        policy = POLICY_FOR_VERSION["2026.1"]
        self.assertTrue(policy.is_known_scheme("rsa-pkcs1v15-sha224"))
        self.assertTrue(policy.is_review_only("rsa-pkcs1v15-sha224"))
        self.assertFalse(policy.is_known_scheme("legacy-rsa-pkcsv15-sha1"))
        self.assertFalse(
            policy.is_allowed_for(
                "legacy-rsa-pkcsv15-sha1", MaterialPurpose.HISTORICAL_REVIEW
            )
        )

    def test_invalid_policy_construction(self):
        with self.assertRaises(ValueError):
            VerificationPolicy(
                version="",
                new_material_schemes=frozenset({"a"}),
            )
        with self.assertRaises(ValueError):
            VerificationPolicy(
                version="x",
                new_material_schemes=frozenset({"a"}),
                review_only_schemes=frozenset({"a"}),
            )


if __name__ == "__main__":
    unittest.main()
