"""Offline seal-number reconciliation built on securesystemslib.

The package models a paper-based issuing process:

* issuing officers own authorized seal-number ranges (optionally split with
  a substitute officer while someone is on leave);
* every settled seal impression is archived as a signed statement whose
  authenticity can be verified offline with securesystemslib;
* the reconciliation engine enforces per-category single-use accounting,
  treats identical backup copies as one usage and flags one number shared by
  different contents as a freeze candidate.
"""

from seal_reconciliation.models import (
    Authorization,
    SealStatement,
    SourceLocation,
)
from seal_reconciliation.reconciler import (
    ReconciliationReport,
    Reconciler,
)

__all__ = [
    "Authorization",
    "ReconciliationReport",
    "Reconciler",
    "SealStatement",
    "SourceLocation",
]
