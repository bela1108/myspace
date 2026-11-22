"""
Advisory withdrawal impact auditing on top of CPE matching.

The package is intentionally separate from the core CPE name classes.  It
uses CPE 2.3 name and expression matching to decide, for every asset in a
caller-approved inventory scope, whether the asset is provably closed,
still affected, or unsupported by complete evidence.
"""

from .model import (
    Advisory,
    AssetSnapshot,
    ComponentRecord,
    FamilyCoverage,
    InventoryScope,
    InventorySnapshot,
    ReplacementEvidence,
    TimeInterval,
    parse_timestamp,
    format_timestamp,
)
from .matching import (
    MATCH,
    NO_MATCH,
    UNKNOWN,
    ExpressionEvaluation,
    FactResult,
    cpe_relation,
    evaluate_expression,
)
from .engine import (
    CONFIRMED_CLOSED,
    STILL_AFFECTED,
    INSUFFICIENT_EVIDENCE,
    OUT_OF_SCOPE,
    STATUS_LABELS,
    AssetAuditResult,
    AuditReport,
    FamilyAssessment,
    ReplacementCheck,
    audit_withdrawal,
)

__all__ = [
    "Advisory",
    "AssetSnapshot",
    "ComponentRecord",
    "FamilyCoverage",
    "InventoryScope",
    "InventorySnapshot",
    "ReplacementEvidence",
    "TimeInterval",
    "parse_timestamp",
    "format_timestamp",
    "MATCH",
    "NO_MATCH",
    "UNKNOWN",
    "ExpressionEvaluation",
    "FactResult",
    "cpe_relation",
    "evaluate_expression",
    "CONFIRMED_CLOSED",
    "STILL_AFFECTED",
    "INSUFFICIENT_EVIDENCE",
    "OUT_OF_SCOPE",
    "STATUS_LABELS",
    "AssetAuditResult",
    "AuditReport",
    "FamilyAssessment",
    "ReplacementCheck",
    "audit_withdrawal",
]
