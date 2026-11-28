"""Tests for receipts that must stay readable without a verifier."""

import copy
import json
import unittest

from securesystemslib.policy import (
    MaterialPurpose,
    Receipt,
    ReceiptParseError,
    UnsupportedKey,
    VerifierCapabilityError,
)
from securesystemslib.signer import RSA_PKCS1V15_SHA256
from tests.policy_utils import make_signed_receipt


class TestReceipt(unittest.TestCase):
    def test_round_trip(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            b"archive material",
        )
        encoded = receipt.to_dict()
        # The envelope is plain JSON-serializable data.
        json.dumps(encoded)

        parsed = Receipt.from_dict(copy.deepcopy(encoded))
        self.assertEqual(parsed.to_dict(), encoded)
        self.assertEqual(parsed.purpose, MaterialPurpose.HISTORICAL_REVIEW)
        self.assertEqual(parsed.payload, b"archive material")
        self.assertTrue(parsed.verifiable_in_environment)

    def test_historical_receipt_readable_without_verifier(self):
        receipt, _ = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.HISTORICAL_REVIEW,
            b"very old material",
        )
        encoded = receipt.to_dict()
        # Simulate an environment where the scheme was never registered, e.g.
        # an optional dependency providing the algorithm is not installed.
        encoded["key"]["scheme"] = "legacy-rsa-pkcsv15-sha1"
        encoded["key"]["keytype"] = "legacy-rsa"

        parsed = Receipt.from_dict(encoded)
        self.assertIsInstance(parsed.key, UnsupportedKey)
        self.assertEqual(parsed.scheme, "legacy-rsa-pkcsv15-sha1")
        self.assertFalse(parsed.verifiable_in_environment)
        # Every original field is still exposed and re-serializable.
        self.assertEqual(parsed.to_dict(), encoded)
        with self.assertRaises(VerifierCapabilityError):
            parsed.key.verify_signature(parsed.signature, parsed.payload)

    def test_malformed_envelopes(self):
        good = make_signed_receipt(
            "rsa",
            RSA_PKCS1V15_SHA256,
            MaterialPurpose.NEW_MATERIAL,
            b"x",
        )[0].to_dict()

        for field_name in ("purpose", "payload", "key", "signature"):
            broken = copy.deepcopy(good)
            broken.pop(field_name)
            with self.assertRaises(ReceiptParseError):
                Receipt.from_dict(broken)

        with self.assertRaises(ReceiptParseError):
            Receipt.from_dict({**copy.deepcopy(good), "purpose": "mystery"})
        with self.assertRaises(ReceiptParseError):
            Receipt.from_dict({**copy.deepcopy(good), "payload": "not-hex"})
        with self.assertRaises(ReceiptParseError):
            Receipt.from_dict("not-a-dict")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
