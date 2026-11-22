"""Offline acceptance verifier for signed delivery events.

The signing backend has already validated each signature individually; this
package adds chain-level acceptance: it follows the predecessor commitments
and checks which original material each event actually acknowledges.
"""

from signedjson.acceptance.status import (
    AWAITING_PREDECESSOR,
    BLOCKED,
    CONFIRMED,
    FORK,
    MISBOUND,
    NEEDS_REVIEW,
)
from signedjson.acceptance.verifier import (
    AcceptanceReport,
    AcceptanceVerifier,
    DuplicateEvent,
    UnknownSigner,
)

__all__ = [
    "AWAITING_PREDECESSOR",
    "BLOCKED",
    "CONFIRMED",
    "FORK",
    "MISBOUND",
    "NEEDS_REVIEW",
    "AcceptanceReport",
    "AcceptanceVerifier",
    "DuplicateEvent",
    "UnknownSigner",
]
