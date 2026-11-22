"""Offline closure judgement for historical secret findings.

This package operates *next to* the detect-secrets baseline: it only ever
handles fictional credential fingerprints (hex digests, e.g. the
``hashed_secret`` values stored in a baseline) and never reads secret
plaintext. Given a fingerprint, a frozen branch scope and a set of approved
rotation receipts, it decides -- per branch -- whether an alert may be
closed, and lets an auditor revoke receipts and observe the fallout.
"""
from .engine import BranchDecision
from .engine import BranchStatus
from .engine import ClosureEngine
from .engine import ClosureReport
from .engine import diff_reports
from .engine import ReportDiff
from .model import BranchScope
from .model import EvidenceBundle
from .model import ReceiptKind
from .model import ReceiptStatus
from .model import RotationReceipt
from .model import RotationWindow
from .proof import BlockedReason
from .proof import ProofResolution
from .proof import resolve_grounded
from .validation import Check
from .validation import CheckResult
from .validation import validate_environment
from .validation import validate_receipt
from .validation import validate_revocation_scope
from .validation import validate_window


__all__ = [
    'BlockedReason',
    'BranchDecision',
    'BranchScope',
    'BranchStatus',
    'Check',
    'CheckResult',
    'ClosureEngine',
    'ClosureReport',
    'EvidenceBundle',
    'ProofResolution',
    'ReceiptKind',
    'ReceiptStatus',
    'ReportDiff',
    'RotationReceipt',
    'RotationWindow',
    'diff_reports',
    'resolve_grounded',
    'validate_environment',
    'validate_receipt',
    'validate_revocation_scope',
    'validate_window',
]
