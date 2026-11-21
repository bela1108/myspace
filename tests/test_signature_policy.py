"""Tests for time-aware signature policy evaluation."""

import hashlib
import hmac
import unittest
from datetime import datetime, timedelta

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import (
    ArchiveAnchor,
    EvaluationView,
    Key,
    PolicyUse,
    Receipt,
    Revocation,
    Signature,
    SignatureEvidence,
    SignaturePolicy,
    TimeClaim,
    TimeInterval,
    TrustedTime,
    replay_receipts,
    verify_and_evaluate,
)

SECRET = b"offline-handover-stub-secret"


def dt(value: str) -> datetime:
    """Parse a compact UTC test timestamp."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stub_sig(payload: bytes) -> str:
    return hmac.new(SECRET, payload, hashlib.sha256).hexdigest()


class StubKey(Key):
    """Minimal securesystemslib Key used for deterministic offline replay."""

    def __init__(self, keyid: str = "stub-key") -> None:
        super().__init__(
            keyid,
            "stub",
            "stub",
            {"public": hashlib.sha256(SECRET).hexdigest()},
        )

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict) -> "StubKey":
        return cls(keyid)

    def to_dict(self) -> dict:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        expected = stub_sig(data)
        if signature.keyid != self.keyid or not hmac.compare_digest(
            signature.signature, expected
        ):
            raise UnverifiedSignatureError("stub signature mismatch")


class TestTimeInterval(unittest.TestCase):
    def test_half_open_default_and_all_boundary_modes(self) -> None:
        start = dt("2026-01-01T00:00:00Z")
        end = dt("2026-02-01T00:00:00Z")

        half_open = TimeInterval(start, end)
        self.assertTrue(half_open.contains(start))
        self.assertFalse(half_open.contains(end))

        closed = TimeInterval(start, end, include_start=True, include_end=True)
        self.assertTrue(closed.contains(start))
        self.assertTrue(closed.contains(end))

        opened = TimeInterval(start, end, include_start=False, include_end=False)
        self.assertFalse(opened.contains(start))
        self.assertFalse(opened.contains(end))
        self.assertTrue(opened.contains(dt("2026-01-15T00:00:00Z")))

        unbounded = TimeInterval(None, None)
        self.assertTrue(unbounded.contains(dt("1970-01-01T00:00:00Z")))
        self.assertTrue(unbounded.contains(dt("2099-01-01T00:00:00Z")))

        self.assertTrue(TimeInterval(start, start).is_empty)

    def test_interval_dict_round_trip_keeps_open_bound(self) -> None:
        interval = TimeInterval(None, dt("2026-02-01T00:00:00Z"))
        self.assertEqual(TimeInterval.from_dict(interval.to_dict()), interval)


class TestSignaturePolicy(unittest.TestCase):
    def setUp(self) -> None:
        self.key = StubKey("artifact-key")
        self.payload = b"artifact:example-widget:1.0"
        self.signature = Signature(
            self.key.keyid,
            stub_sig(self.payload),
            {"signed_at": "2026-01-15T00:00:00Z"},
        )

    def evidence(self, **kwargs) -> SignatureEvidence:
        return SignatureEvidence.verify(
            self.key,
            self.signature,
            self.payload,
            artifact_id="example-widget-1.0",
            **kwargs,
        )

    def test_same_signature_changes_release_between_two_receipts(self) -> None:
        evidence = self.evidence(
            attested_at=TrustedTime("2026-02-01T00:00:00Z", "tsa"),
        )
        revocation = Revocation(
            effective_at=dt("2026-03-01T00:00:00Z"),
            known_at=dt("2026-03-05T00:00:00Z"),
            keyid=self.key.keyid,
            reason="key compromise",
            source="withdrawal-list",
        )
        policy = SignaturePolicy(
            validity=TimeInterval(
                dt("2025-12-01T00:00:00Z"),
                dt("2027-01-01T00:00:00Z"),
            ),
            revocations=(revocation,),
        )

        report = replay_receipts(
            evidence,
            policy,
            (
                Receipt("receipt-1", "2026-02-10T00:00:00Z"),
                Receipt("receipt-2", "2026-03-10T00:00:00Z"),
            ),
        )

        first, second = report.decisions
        self.assertEqual(first.signature_id, second.signature_id)

        self.assertEqual(
            first.allowed_uses,
            frozenset({PolicyUse.ARCHIVE, PolicyUse.RELEASE}),
        )
        self.assertEqual(second.allowed_uses, frozenset({PolicyUse.ARCHIVE}))

        first_release = first.uses[PolicyUse.RELEASE]
        second_release = second.uses[PolicyUse.RELEASE]
        self.assertTrue(first_release.allowed)
        self.assertEqual(first_release.reason_code, "allowed")
        self.assertEqual(
            first_release.revocations[0].status,
            "not_yet_known",
        )
        self.assertIn("2026-03-05T00:00:00Z", first_release.revocations[0].detail)

        self.assertFalse(second_release.allowed)
        self.assertEqual(second_release.reason_code, "revoked")
        self.assertEqual(second_release.revocations[0].status, "applied")

        archive = second.uses[PolicyUse.ARCHIVE]
        self.assertTrue(archive.allowed)
        self.assertEqual(archive.anchor, dt("2026-02-01T00:00:00Z"))
        self.assertEqual(archive.reason_code, "allowed")

        differences = report.differences()
        self.assertEqual(len(differences), 1)
        self.assertEqual(differences[0].use, PolicyUse.RELEASE)
        self.assertIn("receipt-1=ALLOW", report.explain())
        self.assertIn("receipt-2=DENY", report.explain())
        self.assertEqual(report.to_dict()["signature_id"], evidence.signature_id)

    def test_late_notice_is_absent_from_historical_view(self) -> None:
        evidence = self.evidence(
            attested_at=TrustedTime("2026-02-01T00:00:00Z", "tsa"),
        )
        late_notice = Revocation(
            effective_at=dt("2026-01-20T00:00:00Z"),
            known_at=dt("2026-03-05T00:00:00Z"),
            signature_id=evidence.signature_id,
            reason="signature withdrawn",
        )
        policy = SignaturePolicy(
            validity=TimeInterval(dt("2025-12-01T00:00:00Z"), None),
            revocations=(late_notice,),
        )

        first = policy.evaluate(
            evidence,
            Receipt("historical-receipt", "2026-02-10T00:00:00Z"),
        )
        later = policy.evaluate(
            evidence,
            Receipt("later-receipt", "2026-03-10T00:00:00Z"),
        )

        self.assertTrue(first.allows(PolicyUse.ARCHIVE))
        self.assertFalse(later.allows(PolicyUse.ARCHIVE))
        self.assertEqual(
            first.uses[PolicyUse.ARCHIVE].revocations[0].status,
            "not_yet_known",
        )
        self.assertEqual(
            later.uses[PolicyUse.ARCHIVE].reason_code,
            "revoked",
        )

    def test_unverified_time_declaration_is_visible_but_not_trusted(self) -> None:
        evidence = self.evidence()
        self.assertIsNotNone(evidence.claimed_signed_at)
        assert evidence.claimed_signed_at is not None
        self.assertFalse(evidence.claimed_signed_at.trusted)
        self.assertEqual(
            evidence.claimed_signed_at.value,
            dt("2026-01-15T00:00:00Z"),
        )

        strict = SignaturePolicy(
            validity=TimeInterval(dt("2025-12-01T00:00:00Z"), None),
            archive_anchor=ArchiveAnchor.ATTESTED,
        )
        view = EvaluationView("receipt-1", "2026-02-10T00:00:00Z")
        denied = strict.evaluate(evidence, view)
        self.assertFalse(denied.allows(PolicyUse.ARCHIVE))
        self.assertEqual(
            denied.uses[PolicyUse.ARCHIVE].reason_code,
            "no_trusted_attested_time",
        )
        self.assertIn(
            "unverified_time_claim_ignored",
            [check.code for check in denied.uses[PolicyUse.ARCHIVE].checks],
        )

        permissive = SignaturePolicy(
            validity=TimeInterval(dt("2025-12-01T00:00:00Z"), None),
            archive_anchor=ArchiveAnchor.ATTESTED,
            allow_unverified_claims_for_archive=True,
        )
        allowed = permissive.evaluate(evidence, view)
        archive = allowed.uses[PolicyUse.ARCHIVE]
        self.assertTrue(archive.allowed)
        self.assertEqual(archive.reason_code, "allowed_with_unverified_time")
        self.assertFalse(archive.anchor_trusted)
        self.assertIn("unverified_time_used", [check.code for check in archive.checks])

    def test_failed_verification_denies_both_uses(self) -> None:
        evidence = SignatureEvidence.from_verification(
            self.key,
            self.signature,
            self.payload,
            verified=False,
            verification_detail="signature mismatch",
        )
        policy = SignaturePolicy()
        decision = policy.evaluate(
            evidence,
            Receipt("receipt-1", "2026-02-10T00:00:00Z"),
        )
        self.assertEqual(decision.allowed_uses, frozenset())
        for use in (PolicyUse.ARCHIVE, PolicyUse.RELEASE):
            self.assertEqual(
                decision.uses[use].reason_code,
                "signature_not_verified",
            )
            self.assertIn("signature mismatch", decision.uses[use].reason)

        with self.assertRaises(UnverifiedSignatureError):
            SignatureEvidence.verify(
                self.key,
                self.signature,
                b"tampered",
            )

    def test_use_restricted_revocation_and_exact_effect_boundary(self) -> None:
        evidence = self.evidence(
            attested_at=TrustedTime("2026-02-01T00:00:00Z", "tsa"),
        )
        notice = Revocation(
            effective_at=dt("2026-03-01T00:00:00Z"),
            known_at=dt("2026-03-01T00:00:00Z"),
            keyid=self.key.keyid,
            uses=frozenset({PolicyUse.RELEASE}),
        )
        policy = SignaturePolicy(revocations=(notice,))
        at_boundary = policy.evaluate(
            evidence,
            Receipt("boundary-receipt", "2026-03-01T00:00:00Z"),
        )
        self.assertTrue(at_boundary.allows(PolicyUse.ARCHIVE))
        self.assertFalse(at_boundary.allows(PolicyUse.RELEASE))
        self.assertEqual(
            at_boundary.uses[PolicyUse.RELEASE].revocations[0].status,
            "applied",
        )

    def test_release_max_age_requires_trusted_attestation(self) -> None:
        evidence = self.evidence()
        policy = SignaturePolicy(
            release_max_age=timedelta(days=30),
        )
        decision = policy.evaluate(
            evidence,
            Receipt("receipt-1", "2026-02-10T00:00:00Z"),
        )
        self.assertFalse(decision.allows(PolicyUse.RELEASE))
        self.assertEqual(
            decision.uses[PolicyUse.RELEASE].reason_code,
            "no_trusted_attested_time_for_freshness",
        )

        trusted = evidence.with_attestation(dt("2026-01-20T00:00:00Z"), source="tsa")
        allowed = policy.evaluate(
            trusted,
            Receipt("receipt-1", "2026-02-10T00:00:00Z"),
        )
        self.assertTrue(allowed.allows(PolicyUse.RELEASE))

    def test_verify_and_evaluate_shortcut(self) -> None:
        policy = SignaturePolicy()
        decision = verify_and_evaluate(
            self.key,
            self.signature,
            self.payload,
            policy,
            dt("2026-02-10T00:00:00Z"),
            attested_at=TrustedTime("2026-02-01T00:00:00Z", "tsa"),
        )
        self.assertTrue(decision.allows(PolicyUse.ARCHIVE))
        self.assertTrue(decision.allows(PolicyUse.RELEASE))
        self.assertIsInstance(decision.attested_at, datetime)
        self.assertIsInstance(evidence := self.evidence(), SignatureEvidence)
        self.assertIsInstance(evidence.claimed_signed_at, TimeClaim)

    def test_policy_dict_round_trip(self) -> None:
        policy = SignaturePolicy(
            validity=TimeInterval(dt("2025-12-01T00:00:00Z"), None),
            revocations=(
                Revocation(
                    effective_at=dt("2026-03-01T00:00:00Z"),
                    known_at=dt("2026-03-05T00:00:00Z"),
                    uses="release",
                ),
            ),
            archive_anchor=ArchiveAnchor.RECEIPT,
            release_max_age=timedelta(days=30),
        )
        restored = SignaturePolicy.from_dict(policy.to_dict())
        self.assertEqual(restored.validity, policy.validity)
        self.assertEqual(restored.revocations, policy.revocations)
        self.assertEqual(restored.archive_anchor, policy.archive_anchor)
        self.assertEqual(restored.release_max_age, policy.release_max_age)
        self.assertEqual(
            restored.revocations[0].uses,
            frozenset({PolicyUse.RELEASE}),
        )


if __name__ == "__main__":
    unittest.main()
