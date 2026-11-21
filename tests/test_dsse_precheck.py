"""Test cases for dsse_precheck.py."""

import copy
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib.dsse import Envelope
from securesystemslib.dsse_precheck import (
    Category,
    ReceiverCapabilities,
    precheck_envelope,
    precheck_envelopes,
)
from securesystemslib.signer import CryptoSigner

PEMS_DIR = Path(__file__).parent / "data" / "pems"

IN_TOTO_V1 = "application/vnd.in-toto+json"
ATTESTATION_V2 = "application/vnd.dsse.attestation.v2+json"


class TestDssePrecheck(unittest.TestCase):
    """Migration precheck for two generations of archive services."""

    @classmethod
    def setUpClass(cls):
        cls.signers = {}
        for keytype in ["rsa", "ecdsa", "ed25519"]:
            path = PEMS_DIR / f"{keytype}_private.pem"
            with open(path, "rb") as f:
                private_key = load_pem_private_key(f.read(), None)
            cls.signers[keytype] = CryptoSigner(private_key)

        cls.keyring = {
            signer.public_key.keyid: signer.public_key
            for signer in cls.signers.values()
        }

        rsa_keyid = cls.signers["rsa"].public_key.keyid
        ecdsa_keyid = cls.signers["ecdsa"].public_key.keyid
        ed25519_keyid = cls.signers["ed25519"].public_key.keyid

        # First generation archive service: one approved payload
        # encoding, no support for ecdsa keys, knows a legacy
        # envelope-level audit extension.
        cls.gen1 = ReceiverCapabilities(
            name="archive-gen1",
            payload_types=frozenset({IN_TOTO_V1}),
            key_types=frozenset({"rsa", "ed25519"}),
            keyids=frozenset({rsa_keyid, ed25519_keyid}),
            envelope_extensions=frozenset({"x-legacy-audit"}),
        )

        # Second generation archive service: broader payload and key
        # support, but identifies the rsa key under a different
        # (new-style) keyid and only knows the "cert" signature
        # extension.
        cls.gen2 = ReceiverCapabilities(
            name="archive-gen2",
            payload_types=frozenset({IN_TOTO_V1, ATTESTATION_V2}),
            key_types=frozenset({"rsa", "ecdsa", "ed25519"}),
            keyids=frozenset({ecdsa_keyid, ed25519_keyid, "gen2-rsa-keyid"}),
            signature_extensions=frozenset({"cert"}),
        )

        cls.receivers = [cls.gen1, cls.gen2]

        # Envelope 1: approved payload type, ed25519 signature, no
        # extensions. Both generations accept it.
        cls.envelope_universal = cls._make_envelope_dict(
            b'{"statement": "universal"}', IN_TOTO_V1, cls.signers["ed25519"]
        )

        # Envelope 2: v2 payload encoding, ecdsa signature with a
        # "cert" signature extension. Only gen2 supports all of this.
        cls.envelope_modern_only = cls._make_envelope_dict(
            b'{"statement": "modern"}', ATTESTATION_V2, cls.signers["ecdsa"]
        )
        cls.envelope_modern_only["signatures"][0]["cert"] = "CERTIFICATE"

        # Envelope 3: approved payload type, rsa signature and a
        # legacy audit extension. Only gen1 accepts the rsa keyid and
        # understands the extension.
        cls.envelope_legacy_only = cls._make_envelope_dict(
            b'{"statement": "legacy"}', IN_TOTO_V1, cls.signers["rsa"]
        )
        cls.envelope_legacy_only["x-legacy-audit"] = {"ticket": "AUDIT-1"}

    @staticmethod
    def _make_envelope_dict(payload, payload_type, signer):
        envelope = Envelope(payload, payload_type, {})
        envelope.sign(signer)
        return envelope.to_dict()

    def _report_by_name(self, reports, name):
        for report in reports:
            if report.name == name:
                return report
        self.fail(f"no report named {name}")

    def test_three_envelope_scenario(self):
        """One envelope fits both receivers, the others exactly one."""
        reports = precheck_envelopes(
            {
                "universal": self.envelope_universal,
                "modern-only": self.envelope_modern_only,
                "legacy-only": self.envelope_legacy_only,
            },
            self.keyring,
            self.receivers,
        )
        self.assertEqual(len(reports), 3)

        universal = self._report_by_name(reports, "universal")
        self.assertTrue(universal.verified)
        self.assertEqual(universal.deliverable_to, ["archive-gen1", "archive-gen2"])

        modern_only = self._report_by_name(reports, "modern-only")
        self.assertTrue(modern_only.verified)
        self.assertEqual(modern_only.deliverable_to, ["archive-gen2"])

        legacy_only = self._report_by_name(reports, "legacy-only")
        self.assertTrue(legacy_only.verified)
        self.assertEqual(legacy_only.deliverable_to, ["archive-gen1"])

    def test_gen1_rejects_modern_envelope_for_each_capability(self):
        """gen1 fails payload type, key type, keyid and extension."""
        report = precheck_envelope(
            self.envelope_modern_only, self.keyring, self.receivers
        )
        gen1_report = report.receivers[0]
        self.assertEqual(gen1_report.receiver, "archive-gen1")
        self.assertFalse(gen1_report.compatible)

        failed_categories = {finding.category for finding in gen1_report.failures()}
        self.assertEqual(
            failed_categories,
            {
                Category.PAYLOAD_TYPE,
                Category.KEY_TYPE,
                Category.KEYID,
                Category.EXTENSION,
            },
        )

    def test_verification_does_not_imply_deliverable(self):
        """gen2 verifies the legacy envelope but cannot safely use it."""
        report = precheck_envelope(
            self.envelope_legacy_only, self.keyring, self.receivers
        )

        # Cryptographic verification succeeds for the shared keyring.
        self.assertTrue(report.verified)

        gen2_report = report.receivers[1]
        self.assertEqual(gen2_report.receiver, "archive-gen2")
        self.assertFalse(gen2_report.compatible)

        # The payload type is fine for gen2; the blockers are the
        # unrecognized rsa keyid and the unknown audit extension.
        failed_categories = {finding.category for finding in gen2_report.failures()}
        self.assertEqual(failed_categories, {Category.KEYID, Category.EXTENSION})

        self.assertEqual(report.deliverable_to, ["archive-gen1"])

    def test_precheck_is_read_only(self):
        """Envelope dicts and the keyring are not modified."""
        envelopes = {
            "universal": self.envelope_universal,
            "modern-only": self.envelope_modern_only,
            "legacy-only": self.envelope_legacy_only,
        }
        envelopes_before = copy.deepcopy(envelopes)
        keyring_before = copy.deepcopy(self.keyring)

        precheck_envelopes(envelopes, self.keyring, self.receivers)

        self.assertEqual(envelopes, envelopes_before)
        self.assertEqual(self.keyring, keyring_before)

    def test_tampered_envelope_is_not_deliverable(self):
        """A broken signature blocks delivery to every receiver."""
        tampered = copy.deepcopy(self.envelope_universal)
        tampered["payload"] = "dGFtcGVyZWQ="  # base64("tampered")

        report = precheck_envelope(tampered, self.keyring, self.receivers)

        self.assertFalse(report.verified)
        self.assertEqual(report.deliverable_to, [])

    def test_unparseable_envelope_is_not_deliverable(self):
        """A malformed envelope blocks delivery to every receiver."""
        report = precheck_envelope(
            {"payloadType": IN_TOTO_V1}, self.keyring, self.receivers
        )

        self.assertFalse(report.verified)
        self.assertEqual(report.deliverable_to, [])
        self.assertEqual(len(report.receivers), 2)

    def test_signature_without_key_in_keyring(self):
        """A signature from an unknown key blocks delivery."""
        report = precheck_envelope(self.envelope_universal, {}, self.receivers)

        self.assertFalse(report.verified)
        self.assertEqual(report.deliverable_to, [])


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
