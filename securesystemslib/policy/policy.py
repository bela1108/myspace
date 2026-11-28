"""Versioned policies for signature scheme retirement.

A policy is deliberately independent of any verifier backend: it only knows
which schemes are accepted for which :class:`MaterialPurpose`. The same policy
can therefore be enforced against an offline local backend, a partial remote
backend or a test double.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from securesystemslib.signer._constants import (
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    ED25519,
    MLDSA_44_1,
    MLDSA_65_1,
    MLDSA_87_1,
    RSA_PKCS1V15_SHA224,
    RSA_PKCS1V15_SHA256,
    RSA_PKCS1V15_SHA384,
    RSA_PKCS1V15_SHA512,
    RSASSA_PSS_SHA224,
    RSASSA_PSS_SHA256,
    RSASSA_PSS_SHA384,
    RSASSA_PSS_SHA512,
)


class MaterialPurpose(StrEnum):
    """How the signed material is used.

    Attributes:
        NEW_MATERIAL: Material currently being produced. Only schemes on the
            active allow-list may be used.
        HISTORICAL_REVIEW: Existing material that is re-checked. Schemes on
            the review-only list remain acceptable here.
    """

    NEW_MATERIAL = "new_material"
    HISTORICAL_REVIEW = "historical_review"


#: RSA PKCS#1 v1.5 schemes are the first algorithm class that the security
#: team retires: deterministic PKCS#1 v1.5 padding is retained for reading
#: historical receipts but must not protect new material.
LEGACY_RSA_PKCS1V15_SCHEMES = frozenset(
    {
        RSA_PKCS1V15_SHA224,
        RSA_PKCS1V15_SHA256,
        RSA_PKCS1V15_SHA384,
        RSA_PKCS1V15_SHA512,
    }
)

#: Schemes that remain approved for new material.
MODERN_SCHEMES = frozenset(
    {
        RSASSA_PSS_SHA224,
        RSASSA_PSS_SHA256,
        RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA512,
        ECDSA_SHA2_NISTP256,
        ECDSA_SHA2_NISTP384,
        ECDSA_SHA2_NISTP521,
        ED25519,
        MLDSA_44_1,
        MLDSA_65_1,
        MLDSA_87_1,
    }
)


@dataclass(frozen=True)
class VerificationPolicy:
    """A named, versioned decision on which schemes may be used where.

    Args:
        version: Unique policy version identifier, e.g. ``"2026.1"``.
        new_material_schemes: Schemes allowed for
            :attr:`MaterialPurpose.NEW_MATERIAL`.
        review_only_schemes: Schemes that may still be verified for
            :attr:`MaterialPurpose.HISTORICAL_REVIEW` but must not be used
            for new material.
        description: Human readable summary of the policy change.
    """

    version: str
    new_material_schemes: frozenset[str]
    review_only_schemes: frozenset[str] = field(default_factory=frozenset)
    description: str = ""

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("policy version must not be empty")
        overlap = self.new_material_schemes & self.review_only_schemes
        if overlap:
            raise ValueError(
                f"schemes cannot be both active and review-only: {sorted(overlap)}"
            )

    @property
    def reviewable_schemes(self) -> frozenset[str]:
        """All schemes whose historical receipts remain readable."""
        return self.new_material_schemes | self.review_only_schemes

    def is_known_scheme(self, scheme: str) -> bool:
        """Return whether the policy mentions ``scheme`` at all."""
        return scheme in self.reviewable_schemes

    def is_allowed_for(self, scheme: str, purpose: MaterialPurpose) -> bool:
        """Return whether ``scheme`` fits ``purpose`` under this policy."""
        if purpose is MaterialPurpose.NEW_MATERIAL:
            return scheme in self.new_material_schemes
        return scheme in self.reviewable_schemes

    def is_review_only(self, scheme: str) -> bool:
        """Return whether ``scheme`` is retired for new material."""
        return scheme in self.review_only_schemes


#: Policy version 2025.2: all currently registered schemes, including the
#: legacy RSA PKCS#1 v1.5 class, are still active for new material.
POLICY_2025_2 = VerificationPolicy(
    version="2025.2",
    new_material_schemes=MODERN_SCHEMES | LEGACY_RSA_PKCS1V15_SCHEMES,
    description="Legacy RSA PKCS#1 v1.5 schemes remain fully active.",
)

#: Policy version 2026.1: RSA PKCS#1 v1.5 becomes review-only. Historical
#: receipts stay verifiable, but new material must use a modern scheme.
POLICY_2026_1 = VerificationPolicy(
    version="2026.1",
    new_material_schemes=MODERN_SCHEMES,
    review_only_schemes=LEGACY_RSA_PKCS1V15_SCHEMES,
    description=(
        "RSA PKCS#1 v1.5 is retired for new material and kept for "
        "historical review only."
    ),
)

#: Registry of policies shipped with the library, keyed by version.
POLICY_FOR_VERSION: dict[str, VerificationPolicy] = {
    POLICY_2025_2.version: POLICY_2025_2,
    POLICY_2026_1.version: POLICY_2026_1,
}
