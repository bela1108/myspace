Time-aware signature policy
===========================

``securesystemslib.policy`` evaluates approvals on top of a successful
``securesystemslib`` signature verification.  It does not read a wall clock:
the caller supplies every trusted time point, so an offline receipt can be
replayed deterministically and audited later.

Two uses are evaluated independently:

``archive``
    Historical evidence.  The decision is anchored at the signature proven
    (attested) time when the caller provides one, otherwise at the trusted
    receipt time.

``release``
    A new publication.  The decision is anchored at the trusted time of the
    current receipt view.

Import path
-----------

The stable public module is ``securesystemslib.policy``.  The same names are
also exported from ``securesystemslib.signer`` and the compatibility module
``securesystemslib.signature_policy``::

    from securesystemslib.policy import (
        PolicyUse,
        Receipt,
        Revocation,
        SignatureEvidence,
        SignaturePolicy,
        TimeInterval,
        TrustedTime,
        replay_receipts,
    )

Time model
----------

Every decision takes a :class:`~securesystemslib.policy.EvaluationView` (also
exported as ``Receipt``).  Its ``trusted_time`` is the receipt/evaluation time
supplied by the caller.  A signature evidence object can carry an
``attested_at`` value, also supplied by the caller, which is the proven signing
or timestamping time.

Time inputs may be aware ``datetime`` values, ISO 8601 strings, or epoch
seconds.  Naive ``datetime`` values are interpreted as UTC so comparisons are
deterministic.

A :class:`~securesystemslib.policy.Revocation` has two distinct instants:

``effective_at``
    The instant from which the key, signature, or artifact is withdrawn.

``known_at``
    The instant at which this view learned about the withdrawal.  It may be
    later than both the signature time and the receipt time.

A notice is visible in a view only when ``known_at <= view.trusted_time``.  A
visible notice blocks a use only when ``effective_at <= anchor``, where the
anchor is the attested time for archive and the view time for release.  A late
notice is therefore never injected into an earlier historical view.

Intervals and boundaries
------------------------

:class:`~securesystemslib.policy.TimeInterval` defaults to the half-open
interval ``[start, end)``.  ``None`` on either side is an open, unbounded
boundary.  All four finite boundary modes are supported::

    [start, end)    TimeInterval(start, end)
    [start, end]    TimeInterval(start, end, include_end=True)
    (start, end)    TimeInterval(start, end, include_start=False)
    (start, end]    TimeInterval(
                        start, end, include_start=False, include_end=True
                    )

The exact start is inside a default interval and the exact end is outside it.

Unverified time declarations
----------------------------

Time-like fields found in ``Signature.unrecognized_fields`` (for example
``signed_at``) are retained as untrusted ``TimeClaim`` values.  They are visible
in ``SignatureEvidence.unverified_time_claims`` and in the decision trace, but
they are not accepted as proof.  A caller can attach a trusted attestation with
``SignatureEvidence.with_attestation()`` or by passing ``attested_at`` to
``SignatureEvidence.verify()``.

For archives, a policy can opt into using an untrusted declaration with
``allow_unverified_claims_for_archive=True``.  The resulting decision is marked
with reason code ``allowed_with_unverified_time`` and trace field
``unverified_time_used``.  Release never uses an untrusted anchor.

Replaying two receipts
----------------------

The test suite uses a deterministic stub key and signature material to replay
the same verification result at two trusted receipts.  A compact version is::

    evidence = SignatureEvidence.verify(
        key,
        signature,
        payload,
        attested_at=TrustedTime("2026-02-01T00:00:00Z", "tsa"),
    )

    policy = SignaturePolicy(
        validity=TimeInterval("2025-12-01T00:00:00Z", "2027-01-01T00:00:00Z"),
        revocations=(
            Revocation(
                effective_at="2026-03-01T00:00:00Z",
                known_at="2026-03-05T00:00:00Z",
                keyid=key.keyid,
                reason="key compromise",
            ),
        ),
    )

    report = replay_receipts(
        evidence,
        policy,
        (
            Receipt("receipt-1", "2026-02-10T00:00:00Z"),
            Receipt("receipt-2", "2026-03-10T00:00:00Z"),
        ),
    )
    print(report.explain())

The first view does not see the notice because its ``known_at`` is after the
view time.  Both archive and release are allowed.  The second view sees the
notice, but its effective time is after the attestation anchor, so archive
remains allowed while release is revoked.

``report.differences()`` returns one entry per use whose allow/deny result
changed, with both reason codes and details.  Each
``decision.uses[PolicyUse.RELEASE]`` also exposes the matching
``RevocationCheck`` entries, including status values such as
``not_yet_known``, ``effective_after_anchor`` and ``applied``.

If a notice was effective before the attestation but only became known after
the first receipt, the first historical view still allows the archive use and
the later view denies it.  That difference is visible in the same trace and
demonstrates that the later knowledge was not hard-coded into the earlier view.

Serialization
-------------

``SignaturePolicy``, ``Revocation``, ``TimeInterval``, ``EvaluationView`` and
``SignatureEvidence`` provide ``to_dict()`` helpers.  ``SignaturePolicy`` and
the time-related containers also provide ``from_dict()`` for offline policy
storage.  See ``tests/test_signature_policy.py`` for the complete executable
stub replay.
