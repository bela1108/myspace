"""Offline closure judgement for historical secret findings, next to the baseline.

Given fictional credential fingerprints (never the secrets themselves), a frozen
branch scope, and approved rotation receipts, this package decides whether an
alert for a fingerprint on a given branch may be closed. Window, environment and
revocation scope are validated independently. Receipts may reference other
receipts, but reference cycles never produce additional proof. Auditors may
revoke a receipt and compare reports across evidence versions.
"""
from .engine import evaluate
from .engine import validate_environment
from .engine import validate_revocation_scope
from .engine import validate_window
from .models import EvidenceBundle
from .models import FrozenBranchScope
from .models import load_fingerprints_from_baseline
from .models import RotationReceipt
from .report import ClosureJournal
from .report import ClosureReport
from .report import Decision
from .report import ReceiptFailure


__all__ = [
    'ClosureJournal',
    'ClosureReport',
    'Decision',
    'EvidenceBundle',
    'FrozenBranchScope',
    'ReceiptFailure',
    'RotationReceipt',
    'evaluate',
    'load_fingerprints_from_baseline',
    'validate_environment',
    'validate_revocation_scope',
    'validate_window',
]
