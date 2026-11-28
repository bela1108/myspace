"""Test cases for the receipt protocol in signer/_receipt.py."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from securesystemslib.signer import (
    ReceiptSigner,
    ReceiptState,
    ReceiptStore,
    Signature,
    Signer,
    SigningReceipt,
    SSlibKey,
    sign_with_receipt,
)

PAYLOAD = b"release artifact"


def _public_key():
    return SSlibKey("aa", "ed25519", "ed25519", {"public": "ab" * 32})


class FakeSigningService:
    """Simulates a remote delegated signing service.

    fail_mode injects a dropped connection at a specific point:
    * "before_accept": drop before the request is accepted (no signing).
    * "after_sign": sign, then drop the response to the client.
    """

    def __init__(self):
        self.signatures = {}  # request_id -> hex signature
        self.sign_count = 0
        self.fail_mode = None

    def submit(self, request_id, payload):
        if self.fail_mode == "before_accept":
            raise TimeoutError("connection dropped before request was accepted")
        if request_id not in self.signatures:
            self.sign_count += 1
            self.signatures[request_id] = hashlib.sha256(
                b"fake-sig:" + payload
            ).hexdigest()
        if self.fail_mode == "after_sign":
            raise TimeoutError("connection dropped after signing")
        return "signed_pending_pickup"

    def status(self, request_id):
        if request_id in self.signatures:
            return "signed_pending_pickup"
        return "not_accepted"

    def collect(self, request_id):
        return self.signatures.pop(request_id)


class FakeReceiptSigner(ReceiptSigner):
    """ReceiptSigner implementation talking to a FakeSigningService."""

    def __init__(self, service, public_key):
        self._service = service
        self._public_key = public_key

    @classmethod
    def from_priv_key_uri(cls, priv_key_uri, public_key, secrets_handler=None):
        raise NotImplementedError

    @property
    def public_key(self):
        return self._public_key

    def submit(self, receipt, payload):
        state = self._service.submit(receipt.request_id, payload)
        return receipt.with_state(ReceiptState(state))

    def query(self, receipt):
        state = self._service.status(receipt.request_id)
        return receipt.with_state(ReceiptState(state))

    def collect(self, receipt):
        sig = self._service.collect(receipt.request_id)
        return Signature(self._public_key.keyid, sig)


class LegacySigner(Signer):
    """A plain signer without receipt protocol support."""

    def __init__(self, public_key):
        self._public_key = public_key

    @classmethod
    def from_priv_key_uri(cls, priv_key_uri, public_key, secrets_handler=None):
        raise NotImplementedError

    @property
    def public_key(self):
        return self._public_key

    def sign(self, payload):
        sig = hashlib.sha256(b"legacy:" + payload).hexdigest()
        return Signature(self._public_key.keyid, sig)


class TestReceiptProtocol(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.store_path = Path(self.tmpdir.name) / "receipts.json"
        self.store = ReceiptStore(self.store_path)
        self.digest = hashlib.sha256(PAYLOAD).hexdigest()

    def test_receipt_serialization_roundtrip(self):
        receipt = SigningReceipt.new(PAYLOAD)
        for state in ReceiptState:
            receipt = receipt.with_state(state)
            self.assertEqual(receipt, SigningReceipt.from_dict(receipt.to_dict()))

    def test_store_persists_receipts_on_disk(self):
        receipt = SigningReceipt.new(PAYLOAD).with_state(
            ReceiptState.LOCALLY_UNCONFIRMED
        )
        self.store.put(receipt)

        # A fresh store instance over the same file sees the evidence.
        other_store = ReceiptStore(self.store_path)
        self.assertEqual(receipt, other_store.get(self.digest))

        other_store.remove(self.digest)
        self.assertIsNone(self.store.get(self.digest))

    def test_happy_path_leaves_no_receipt(self):
        service = FakeSigningService()
        signer = FakeReceiptSigner(service, _public_key())

        sig = sign_with_receipt(signer, PAYLOAD, self.store)

        self.assertEqual(
            sig.signature,
            hashlib.sha256(b"fake-sig:" + PAYLOAD).hexdigest(),
        )
        self.assertEqual(service.sign_count, 1)
        self.assertIsNone(self.store.get(self.digest))

    def test_disconnect_before_accept_resubmits_on_retry(self):
        service = FakeSigningService()
        service.fail_mode = "before_accept"
        signer = FakeReceiptSigner(service, _public_key())

        with self.assertRaises(TimeoutError):
            sign_with_receipt(signer, PAYLOAD, self.store)

        # The pipeline only knows the outcome is unconfirmed.
        receipt = self.store.get(self.digest)
        self.assertEqual(receipt.state, ReceiptState.LOCALLY_UNCONFIRMED)
        self.assertEqual(service.sign_count, 0)

        # Retry: the service confirms it never accepted the request, so the
        # payload is re-submitted (with the same request id) and signed.
        service.fail_mode = None
        sig = sign_with_receipt(signer, PAYLOAD, self.store)

        self.assertEqual(service.sign_count, 1)
        self.assertEqual(
            sig.signature,
            hashlib.sha256(b"fake-sig:" + PAYLOAD).hexdigest(),
        )
        self.assertIsNone(self.store.get(self.digest))

    def test_disconnect_after_sign_collects_existing_signature(self):
        service = FakeSigningService()
        service.fail_mode = "after_sign"
        signer = FakeReceiptSigner(service, _public_key())

        with self.assertRaises(TimeoutError):
            sign_with_receipt(signer, PAYLOAD, self.store)

        # The service signed, but locally the outcome is unconfirmed.
        receipt = self.store.get(self.digest)
        self.assertEqual(receipt.state, ReceiptState.LOCALLY_UNCONFIRMED)
        self.assertEqual(service.sign_count, 1)
        produced_sig = service.signatures[receipt.request_id]

        # Retry: the query resolves to SIGNED_PENDING_PICKUP and the retry
        # picks up the already produced signature without re-signing.
        service.fail_mode = None
        sig = sign_with_receipt(signer, PAYLOAD, self.store)

        self.assertEqual(sig.signature, produced_sig)
        self.assertEqual(service.sign_count, 1)
        self.assertIsNone(self.store.get(self.digest))

    def test_legacy_signer_works_without_receipt_support(self):
        signer = LegacySigner(_public_key())

        sig = sign_with_receipt(signer, PAYLOAD, self.store)

        self.assertEqual(
            sig.signature, hashlib.sha256(b"legacy:" + PAYLOAD).hexdigest()
        )
        # The store is left completely untouched.
        self.assertFalse(self.store_path.exists())

    def test_one_shot_sign_uses_receipt_protocol(self):
        service = FakeSigningService()
        signer = FakeReceiptSigner(service, _public_key())

        sig = signer.sign(PAYLOAD)

        self.assertEqual(
            sig.signature,
            hashlib.sha256(b"fake-sig:" + PAYLOAD).hexdigest(),
        )
        self.assertEqual(service.sign_count, 1)


if __name__ == "__main__":
    unittest.main()
