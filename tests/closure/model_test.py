from datetime import timedelta

import pytest

from detect_secrets.closure.model import ReceiptStatus
from detect_secrets.closure.model import RotationWindow
from tests.closure.conftest import AS_OF
from tests.closure.conftest import FINGERPRINT
from tests.closure.conftest import make_bundle
from tests.closure.conftest import make_receipt
from tests.closure.conftest import make_scope
from tests.closure.conftest import make_window


class TestFingerprint:
    @pytest.mark.parametrize('fingerprint', ['a' * 40, 'b' * 64])
    def test_accepts_hex_digests(self, fingerprint):
        assert make_receipt(fingerprint=fingerprint).fingerprint == fingerprint

    @pytest.mark.parametrize('plaintext', [
        'hunter2',
        'AKIAIOSFODNN7EXAMPLE',
        'A' * 40,  # hex digests are lowercase
        'g' * 40,  # not hex
    ])
    def test_rejects_anything_that_is_not_a_digest(self, plaintext):
        with pytest.raises(ValueError):
            make_receipt(fingerprint=plaintext)

    def test_bundle_subject_must_be_a_digest(self):
        with pytest.raises(ValueError):
            make_bundle(fingerprint='super-secret-value')


class TestRotationWindow:
    def test_rejects_inverted_window(self):
        with pytest.raises(ValueError):
            RotationWindow(opens_at=AS_OF, closes_at=AS_OF - timedelta(days=1))

    def test_bounds_are_inclusive(self):
        window = make_window()
        assert window.contains(window.opens_at)
        assert window.contains(window.closes_at)
        assert not window.contains(window.closes_at + timedelta(seconds=1))


class TestBranchScope:
    def test_rejects_empty_scope(self):
        with pytest.raises(ValueError):
            make_scope(branches=frozenset())


class TestRotationReceipt:
    def test_rejects_self_citation(self):
        with pytest.raises(ValueError):
            make_receipt(based_on='RT-1')

    def test_revoke_returns_a_copy(self):
        receipt = make_receipt()
        revoked = receipt.revoke()
        assert receipt.status is ReceiptStatus.APPROVED
        assert revoked.status is ReceiptStatus.REVOKED
        assert revoked.receipt_id == receipt.receipt_id


class TestEvidenceBundle:
    def test_rejects_duplicate_receipt_ids(self):
        with pytest.raises(ValueError):
            make_bundle(receipts=[make_receipt('RT-1'), make_receipt('RT-1')])

    def test_rejects_version_below_one(self):
        with pytest.raises(ValueError):
            make_bundle(version=0)

    def test_with_revocation_bumps_version_and_marks_receipt(self):
        bundle = make_bundle(receipts=[make_receipt('RT-1'), make_receipt('RT-2')])
        updated = bundle.with_revocation('RT-2')

        assert updated.version == bundle.version + 1
        statuses = {receipt.receipt_id: receipt.status for receipt in updated.receipts}
        assert statuses == {'RT-1': ReceiptStatus.APPROVED, 'RT-2': ReceiptStatus.REVOKED}
        # the original bundle is untouched
        assert all(
            receipt.status is ReceiptStatus.APPROVED for receipt in bundle.receipts
        )

    def test_with_revocation_rejects_unknown_receipt(self):
        with pytest.raises(KeyError):
            make_bundle().with_revocation('RT-404')

    def test_fingerprint_constant_is_a_digest(self):
        assert make_receipt(fingerprint=FINGERPRINT)
