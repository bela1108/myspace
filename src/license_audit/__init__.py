"""Offline license-conflict review built on top of plyara rule parsing.

The review consumes locally supplied release books (YARA rule files), a sample
manifest, the approved authorization scope and a frozen rule-version manifest.
Duplicate approval receipts are only folded when they trace back to the same
conclusive authorization; identical wording from two different authorizations
must be retained as separate approvals.
"""

__all__ = [
    "AuditReport",
    "Dossier",
    "LicenseAuditError",
    "RuleReceipt",
    "load_json_input",
    "parse_book",
    "run_review",
]

from license_audit.engine import (
    AuditReport,
    Dossier,
    LicenseAuditError,
    RuleReceipt,
    load_json_input,
    parse_book,
    run_review,
)
