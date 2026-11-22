"""Offline reconciliation of recovered LNK shortcuts against collection history.

A drive letter is not a stable identifier. When a letter is reassigned to a
new volume, the text written inside an old shortcut must not be re-interpreted
as pointing at the new volume. The package keeps three layers apart:

1. the target as written inside the LNK (``written_path`` plus the embedded
   VolumeID serial/label);
2. which volume(s) the recorded letter resolved to during each past collection
   period, with empty entries for periods where nothing was observed;
3. evidence items actually read off exhibits, matched by the stable volume
   serial number rather than a possibly-reused letter.
"""

from LnkParse3.reconcile.models import load_drive_history
from LnkParse3.reconcile.models import load_evidence
from LnkParse3.reconcile.models import make_target
from LnkParse3.reconcile.models import ReconcileInputError
from LnkParse3.reconcile.reconcile import build_reconciliation
from LnkParse3.reconcile.reconcile import reconcile_target


__all__ = [
    "ReconcileInputError",
    "build_reconciliation",
    "load_drive_history",
    "load_evidence",
    "make_target",
    "reconcile_target",
]
