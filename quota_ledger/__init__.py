# SPDX-License-Identifier: Apache-2.0

"""Replayable release-quota ledger backed by verified in-toto metadata.

The package wires the existing in-toto signature verification machinery to
an append-only quota ledger. Every state change is an event derived from a
signed credential (entitlement, hold, release, revocation). Replaying the
event log from an empty state always reconstructs the same ledger, which
makes the whole flow reproducible and auditable.
"""

from quota_ledger.credentials import (
    ENTITLEMENT_TYPE,
    HOLD_TYPE,
    RELEASE_TYPE,
    REVOKE_TYPE,
    Credential,
)
from quota_ledger.exceptions import (
    CredentialError,
    LedgerError,
    PendingCredentialError,
    SignatureError,
    VerificationError,
)
from quota_ledger.intoto_verify import (
    VerifiedRelease,
    load_verified_release,
)
from quota_ledger.ledger import Ledger, LedgerState, QuotaLine, Receipt

__all__ = [
    "ENTITLEMENT_TYPE",
    "HOLD_TYPE",
    "RELEASE_TYPE",
    "REVOKE_TYPE",
    "Credential",
    "CredentialError",
    "Ledger",
    "LedgerError",
    "LedgerState",
    "PendingCredentialError",
    "QuotaLine",
    "Receipt",
    "SignatureError",
    "VerifiedRelease",
    "VerificationError",
    "load_verified_release",
]
