"""Tests for offline and fake verification backends."""

import unittest

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.policy import (
    BackendUnavailableError,
    FakeVerifierBackend,
    LocalVerifierBackend,
    MaterialPurpose,
    VerifierCapabilityError,
)
from securesystemslib.signer import (
    ED25519,
    RSA_PKCS1V15_SHA256,
    RSASSA_PSS_SHA256,
)
from tests.policy_utils import make_signed_receipt, tamper


class TestLocalVerifierBackend(unittest.TestCase):
    def setUp(self):
        self.backend = LocalVerifierBackend()

    def test_offline_capabilities_are_registered_schemes(self):
        schemes = self.backend.supported_schemes()
        self.assertIn(RSA_PKCS1V15_SHA256, schemes)
        self.assertIn(RSASSA_PSS_SHA256, schemes)
        self.assertIn(ED25519, schemes)

    def test_verifies_real_signatures_offline(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            b"historical payload",
        )
        self.backend.verify(receipt.key, receipt.signature, receipt.payload)

        with self.assertRaises(UnverifiedSignatureError):
            bad = tamper(receipt)
            self.backend.verify(bad.key, bad.signature, bad.payload)

    def test_unsupported_scheme_is_capability_not_invalidity(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            b"x",
        )
        empty_backend = LocalVerifierBackend.__new__(LocalVerifierBackend)
        empty_backend._schemes = frozenset()
        with self.assertRaises(VerifierCapabilityError):
            empty_backend.verify(receipt.key, receipt.signature, receipt.payload)


class TestFakeVerifierBackend(unittest.TestCase):
    def setUp(self):
        self.receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            b"legacy receipt",
        )

    def test_partial_backend_missing_optional_capability(self):
        full = FakeVerifierBackend(name="full")
        partial = FakeVerifierBackend(
            supported=full.supported_schemes() - {RSA_PKCS1V15_SHA256},
            name="partial",
        )

        self.assertTrue(full.supports(RSA_PKCS1V15_SHA256))
        self.assertFalse(partial.supports(RSA_PKCS1V15_SHA256))
        with self.assertRaises(VerifierCapabilityError):
            partial.verify(
                self.receipt.key,
                self.receipt.signature,
                self.receipt.payload,
            )

    def test_backend_outage(self):
        backend = FakeVerifierBackend(available=False, name="down")
        with self.assertRaises(BackendUnavailableError):
            backend.supported_schemes()
        with self.assertRaises(BackendUnavailableError):
            backend.verify(
                self.receipt.key,
                self.receipt.signature,
                self.receipt.payload,
            )

        backend.set_available(True)
        backend.verify(
            self.receipt.key,
            self.receipt.signature,
            self.receipt.payload,
        )

    def test_configured_verification_failure_still_detects_tampering(self):
        failing = FakeVerifierBackend(
            verify_failures={RSA_PKCS1V15_SHA256}, name="failing"
        )
        with self.assertRaises(UnverifiedSignatureError):
            failing.verify(
                self.receipt.key,
                self.receipt.signature,
                self.receipt.payload,
            )

        bad = tamper(self.receipt)
        with self.assertRaises(UnverifiedSignatureError):
            FakeVerifierBackend().verify(bad.key, bad.signature, bad.payload)


if __name__ == "__main__":
    unittest.main()
