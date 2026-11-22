"""
Side-channel reconciliation of "goods receipt" evidence for pip-audit.

The normal audit flow only knows package coordinates (name plus version),
while procurement ships concrete distribution files (wheels/sdists) whose
build and platform tags make multiple distinct artifacts share one version.
This package reconciles three independent pieces of evidence:

1. the local plan (what an environment or lockfile intends to receive),
2. the repository shipping manifest (what the repository actually shipped),
3. the transit receipt (what the intermediate handoff recorded on arrival).

Comparison is always performed against the concrete distribution file and its
digest rather than the bare name/version pair. Every piece of evidence keeps
the provider that supplied it so that a disagreement between two handoffs can
be traced back to the specific stage that introduced it.
"""

from pip_audit._receipt.engine import ReceiptReconciler
from pip_audit._receipt.model import (
    ArtifactIdentity,
    EvidenceRecord,
    HandoffStage,
    MissingMaterial,
    PackageCoordinate,
    ReconciliationReport,
    ReconciliationRow,
    ReconciliationStatus,
    ReceiptError,
    ReceiptSourceError,
    StageConflict,
)
from pip_audit._receipt.report import render_pending_report, report_to_dict
from pip_audit._receipt.source import ReceiptDocument

__all__ = [
    "ArtifactIdentity",
    "EvidenceRecord",
    "HandoffStage",
    "MissingMaterial",
    "PackageCoordinate",
    "ReceiptDocument",
    "ReceiptError",
    "ReceiptReconciler",
    "ReceiptSourceError",
    "ReconciliationReport",
    "ReconciliationRow",
    "ReconciliationStatus",
    "StageConflict",
    "render_pending_report",
    "report_to_dict",
]
