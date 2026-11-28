"""Tests for the key generation rotation boundary."""

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

from securesystemslib.exceptions import (
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import (
    KeyGeneration,
    LocalSigner,
    RotationBoundary,
    SignedRecord,
    SigningConfig,
    review_records,
)


class ControlledSyncPoint:
    """Deterministic, injectable synchronization point.

    The signing thread waits on :meth:`wait` until the test driver calls
    :meth:`release`. This lets a test rotate the config while the signing
    operation is paused between generation capture and the actual sign call.
    """

    def __init__(self):
        self._entered = threading.Event()
        self._released = threading.Event()
        self.calls = 0

    def __call__(self):
        self.calls += 1
        self._entered.set()
        self._released.wait(timeout=5)

    def wait_until_entered(self):
        self._entered.wait(timeout=5)

    def release(self):
        self._released.set()


def make_generations():
    """Return the two local fake-signer generations used by the tests."""
    first = KeyGeneration.for_local(1, b"maintenance-group-a-secret")
    successor = KeyGeneration.for_local(2, b"maintenance-group-b-secret")
    return first, successor


class TestLocalSigner(unittest.TestCase):
    def test_sign_and_verify_roundtrip(self):
        signer = LocalSigner(b"shared-secret")
        signature = signer.sign(b"payload")

        self.assertEqual(signature.keyid, signer.keyid)
        signer.verify(b"payload", signature)

        reloaded = LocalSigner(b"shared-secret")
        reloaded.verify(b"payload", signature)

    def test_distinct_secrets_get_distinct_keyids(self):
        first = LocalSigner(b"secret-one")
        second = LocalSigner(b"secret-two")
        self.assertNotEqual(first.keyid, second.keyid)

    def test_verify_rejects_tampered_signature(self):
        signer = LocalSigner(b"shared-secret")
        signature = signer.sign(b"payload")
        with self.assertRaises(UnverifiedSignatureError):
            signer.verify(b"different-payload", signature)

    def test_verify_rejects_foreign_keyid(self):
        signer = LocalSigner(b"shared-secret")
        other = LocalSigner(b"other-secret")
        signature = other.sign(b"payload")
        with self.assertRaises(VerificationError):
            signer.verify(b"payload", signature)

    def test_rejects_invalid_secret(self):
        with self.assertRaises(TypeError):
            LocalSigner("not-bytes")
        with self.assertRaises(ValueError):
            LocalSigner(b"")


class TestSigningConfig(unittest.TestCase):
    def test_rotation_archives_previous_generation(self):
        first, successor = make_generations()
        config = SigningConfig(first)

        self.assertTrue(config.is_active_key(first.keyid))
        self.assertFalse(config.is_archived_key(first.keyid))

        config.rotate(successor)

        self.assertTrue(config.is_active_key(successor.keyid))
        self.assertTrue(config.is_archived_key(first.keyid))
        self.assertTrue(config.is_known_key(first.keyid))
        self.assertEqual(config.get_generation_for_keyid(first.keyid).generation, 1)
        self.assertEqual(config.get_active_generation().generation, 2)

    def test_rotation_rejects_stale_or_duplicate_generation(self):
        first, successor = make_generations()
        config = SigningConfig(first)
        config.rotate(successor)

        stale = KeyGeneration.for_local(1, b"another-secret")
        with self.assertRaises(ValueError):
            config.rotate(stale)

        duplicate = KeyGeneration.for_local(3, b"maintenance-group-b-secret")
        with self.assertRaises(ValueError):
            config.rotate(duplicate)

    def test_retire_active_leaves_no_signing_generation(self):
        first, _ = make_generations()
        config = SigningConfig(first)
        config.retire_active()

        self.assertIsNone(config.active_keyid)
        self.assertTrue(config.is_archived_key(first.keyid))
        with self.assertRaises(ValueError):
            config.get_active_generation()

    def test_unknown_keyid_lookup_raises_keyerror(self):
        first, _ = make_generations()
        config = SigningConfig(first)
        with self.assertRaises(KeyError):
            config.get_generation_for_keyid("missing-keyid")


class TestRotationBoundary(unittest.TestCase):
    def test_signing_uses_active_generation(self):
        first, successor = make_generations()
        config = SigningConfig(first)
        boundary = RotationBoundary(config)

        old_signature = boundary.sign(b"document")
        self.assertEqual(old_signature.keyid, first.keyid)

        config.rotate(successor)
        new_signature = boundary.sign(b"document")
        self.assertEqual(new_signature.keyid, successor.keyid)

    def test_inflight_operation_keeps_generation_pinned_at_start(self):
        first, successor = make_generations()
        config = SigningConfig(first)
        after_capture = ControlledSyncPoint()
        boundary = RotationBoundary(config, after_capture=after_capture)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(boundary.sign, b"in-flight-document")
            after_capture.wait_until_entered()

            # The operation has pinned generation 1; rotate underneath it.
            config.rotate(successor)
            self.assertEqual(config.active_keyid, successor.keyid)

            after_capture.release()
            try:
                signature = future.result(timeout=5)
            except FutureTimeoutError:  # pragma: no cover - failure guard
                self.fail("in-flight signing did not complete after release")

        # The in-flight signature still uses the generation pinned at start.
        self.assertEqual(signature.keyid, first.keyid)
        first.verify(b"in-flight-document", signature)
        self.assertEqual(after_capture.calls, 1)

        # New operations pick up the successor generation.
        later_signature = boundary.sign(b"later-document")
        self.assertEqual(later_signature.keyid, successor.keyid)

    def test_concurrent_signers_split_across_rotation_boundary(self):
        first, successor = make_generations()
        config = SigningConfig(first)
        first_worker = ControlledSyncPoint()
        second_worker = ControlledSyncPoint()
        boundary = RotationBoundary(config, after_capture=first_worker)

        with ThreadPoolExecutor(max_workers=2) as executor:
            old_future = executor.submit(boundary.sign, b"old")
            first_worker.wait_until_entered()

            # A second boundary shares the same injected config.
            new_boundary = RotationBoundary(config, after_capture=second_worker)
            config.rotate(successor)
            new_future = executor.submit(new_boundary.sign, b"new")

            first_worker.release()
            second_worker.wait_until_entered()
            second_worker.release()

            old_signature = old_future.result(timeout=5)
            new_signature = new_future.result(timeout=5)

        self.assertEqual(old_signature.keyid, first.keyid)
        self.assertEqual(new_signature.keyid, successor.keyid)

    def test_sync_points_run_around_generation_capture(self):
        first, _ = make_generations()
        config = SigningConfig(first)
        events = []
        boundary = RotationBoundary(
            config,
            before_capture=lambda: events.append("before"),
            after_capture=lambda: events.append("after"),
        )

        boundary.sign(b"payload")
        self.assertEqual(events, ["before", "after"])


class TestReviewRecords(unittest.TestCase):
    def _records_from_generations(self, config, first, successor):
        boundary = RotationBoundary(config)
        old_record = SignedRecord(
            b"historical-document",
            boundary.sign(b"historical-document"),
        )

        config.rotate(successor)
        new_record = SignedRecord(
            b"current-document", boundary.sign(b"current-document")
        )
        return old_record, new_record

    def test_review_lists_archived_and_authorized_samples_separately(self):
        first, successor = make_generations()
        config = SigningConfig(first)
        old_record, new_record = self._records_from_generations(
            config, first, successor
        )

        report = review_records([old_record, new_record], config)

        self.assertEqual(len(report.archived_valid), 1)
        self.assertEqual(len(report.authorized_new), 1)
        self.assertEqual(report.unverifiable, [])

        archived = report.archived_valid[0]
        self.assertEqual(archived.record, old_record)
        self.assertEqual(archived.keyid, first.keyid)
        self.assertEqual(archived.generation, 1)

        authorized = report.authorized_new[0]
        self.assertEqual(authorized.record, new_record)
        self.assertEqual(authorized.keyid, successor.keyid)
        self.assertEqual(authorized.generation, 2)

    def test_review_resolves_records_with_only_keyid_remains(self):
        first, successor = make_generations()
        config = SigningConfig(first)
        old_record, new_record = self._records_from_generations(
            config, first, successor
        )

        # Persist and reload: the stored data contains no generation field,
        # only the key id embedded in the signature.
        restored = [
            SignedRecord.from_dict(old_record.to_dict()),
            SignedRecord.from_dict(new_record.to_dict()),
        ]
        self.assertEqual(restored, [old_record, new_record])
        self.assertNotIn("generation", old_record.to_dict()["signature"])

        report = review_records(restored, config)
        self.assertEqual([sample.generation for sample in report.archived_valid], [1])
        self.assertEqual([sample.generation for sample in report.authorized_new], [2])

    def test_review_marks_unknown_and_invalid_records_unverifiable(self):
        first, successor = make_generations()
        config = SigningConfig(first)
        old_record, new_record = self._records_from_generations(
            config, first, successor
        )

        orphan_signer = LocalSigner(b"removed-group-secret")
        orphan_record = SignedRecord(
            b"orphan-document", orphan_signer.sign(b"orphan-document")
        )
        tampered = SignedRecord(
            b"current-document",
            LocalSigner(b"maintenance-group-b-secret").sign(b"tampered-document"),
        )

        report = review_records(
            [orphan_record, tampered, old_record, new_record], config
        )

        self.assertEqual(len(report.archived_valid), 1)
        self.assertEqual(len(report.authorized_new), 1)
        self.assertEqual(len(report.unverifiable), 2)
        reasons = {sample.reason for sample in report.unverifiable}
        self.assertTrue(any("unknown key id" in reason for reason in reasons))
        self.assertTrue(any("invalid" in reason for reason in reasons))

    def test_archived_signature_still_verifies_after_rotation(self):
        first, successor = make_generations()
        config = SigningConfig(first)
        boundary = RotationBoundary(config)
        signature = boundary.sign(b"history")

        config.rotate(successor)
        resolved = config.get_generation_for_keyid(signature.keyid)
        resolved.verify(b"history", signature)


if __name__ == "__main__":
    unittest.main()
