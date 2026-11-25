"""Offline re-computation of credential (secret finding) incidents.

The sub-package turns detect-secrets style findings plus an explicit,
caller-supplied event history into an auditable timeline of:

* which team owns each finding occurrence (following code moves and ownership
  changes, citing the exact ownership record used),
* which finite-lived exemptions cover which occurrence, and
* when the remaining review for each occurrence is due.

Everything is offline and side-effect free: the same inputs always reproduce
the same decisions, and every decision is kept in an append-only audit trail.
"""
from detect_secrets.incident.exceptions import DuplicateEventError
from detect_secrets.incident.exceptions import EventOrderError
from detect_secrets.incident.exceptions import IncidentError
from detect_secrets.incident.exceptions import InvalidEventError
from detect_secrets.incident.exceptions import StaleExemptionError
from detect_secrets.incident.exceptions import UnknownFindingError
from detect_secrets.incident.models import AuditEntry
from detect_secrets.incident.models import Case
from detect_secrets.incident.models import Event
from detect_secrets.incident.models import Exemption
from detect_secrets.incident.models import Finding
from detect_secrets.incident.models import Occurrence
from detect_secrets.incident.models import OwnershipRule
from detect_secrets.incident.report import build_report
from detect_secrets.incident.report import render_text_report
from detect_secrets.incident.replay import ReplayEngine
from detect_secrets.incident.replay import replay_case

__all__ = [
    "AuditEntry",
    "Case",
    "DuplicateEventError",
    "Event",
    "EventOrderError",
    "Exemption",
    "Finding",
    "IncidentError",
    "InvalidEventError",
    "Occurrence",
    "OwnershipRule",
    "ReplayEngine",
    "StaleExemptionError",
    "UnknownFindingError",
    "build_report",
    "render_text_report",
    "replay_case",
]
