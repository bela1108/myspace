"""Signature policy enforcement and verification orchestration.

This sub-package separates three concerns that callers otherwise tend to mix:

* the *verification capability* offered by the local machine or a remote
  backend (see :mod:`securesystemslib.policy.verifier`),
* the *policy version* that decides whether a signature scheme is allowed for
  new material or restricted to review of historical material (see
  :class:`~securesystemslib.policy.policy.VerificationPolicy`), and
* the *material purpose* (new material versus historical review) attached to a
  concrete receipt (see :mod:`securesystemslib.policy.receipt`).

A :class:`~securesystemslib.policy.check.ComplianceReport` states, per
receipt, whether the policy or the verification environment has to change.
"""

from securesystemslib.policy.check import (
    CheckOutcome,
    CheckResult,
    ComplianceReport,
    check_receipt,
    check_receipts,
)
from securesystemslib.policy.policy import (
    LEGACY_RSA_PKCS1V15_SCHEMES,
    MODERN_SCHEMES,
    POLICY_2025_2,
    POLICY_2026_1,
    POLICY_FOR_VERSION,
    MaterialPurpose,
    VerificationPolicy,
)
from securesystemslib.policy.receipt import (
    Receipt,
    ReceiptParseError,
    UnsupportedKey,
    make_receipt,
)
from securesystemslib.policy.verifier import (
    BackendUnavailableError,
    FakeVerifierBackend,
    LocalVerifierBackend,
    VerifierBackend,
    VerifierCapabilityError,
)

__all__ = [
    "BackendUnavailableError",
    "CheckOutcome",
    "CheckResult",
    "ComplianceReport",
    "FakeVerifierBackend",
    "LEGACY_RSA_PKCS1V15_SCHEMES",
    "LocalVerifierBackend",
    "MaterialPurpose",
    "MODERN_SCHEMES",
    "POLICY_FOR_VERSION",
    "POLICY_2025_2",
    "POLICY_2026_1",
    "Receipt",
    "ReceiptParseError",
    "UnsupportedKey",
    "VerificationPolicy",
    "VerifierBackend",
    "VerifierCapabilityError",
    "check_receipt",
    "check_receipts",
    "make_receipt",
]
