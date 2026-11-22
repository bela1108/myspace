"""Offline ownership reconciliation for artifact repository key registrations.

Two seal registrations may be filed against the *same public key material* while
each one labels that material with a different organization. This package
provides an offline entry point that does not decide ownership by itself:

* authorization statements (``authorization``) and handoff statements
  (``handoff``) are accepted only after their existing signatures verify
  against the registered key material, and
* the business layer then decides which statement to recognize for a given
  purpose, time interval and jurisdiction.

The design deliberately avoids two shortcuts:

* statements carrying identical payloads are merged as one piece of evidence
  rather than counted twice, and
* two independently signed statements whose claimed intervals overlap are
  never resolved by silently picking the newer one.
"""

from securesystemslib.ownership._model import (
    Authorization,
    Handoff,
    Registration,
    Statement,
)
from securesystemslib.ownership._reconcile import (
    OwnershipReconciler,
    Receipt,
    ReconciliationReport,
    Segment,
)
from securesystemslib.ownership._verify import (
    StatementVerificationError,
    make_statement,
)

__all__ = [
    "Authorization",
    "Handoff",
    "OwnershipReconciler",
    "Receipt",
    "ReconciliationReport",
    "Registration",
    "Segment",
    "Statement",
    "StatementVerificationError",
    "make_statement",
]
