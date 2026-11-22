"""
Offline handover auditing for detection notifications.

The audit layer deliberately uses the Sigma rule UUID as the permission and reporting key.
Human-readable titles are never used to merge rules or duties.
"""

from sigma.audit.handover import (
    ApprovedSubstitution,
    AuditStatus,
    BranchSteward,
    ClosedBranch,
    HandoverAuditConfig,
    HandoverAuditReport,
    HandoverAuditor,
    NotificationChain,
    OpenBranch,
    ReleaseBranch,
    ResolvedAssignment,
    Responsibility,
    ShiftDuty,
    audit_handover,
)

__all__ = [
    "ApprovedSubstitution",
    "AuditStatus",
    "BranchSteward",
    "ClosedBranch",
    "HandoverAuditConfig",
    "HandoverAuditReport",
    "HandoverAuditor",
    "NotificationChain",
    "OpenBranch",
    "ReleaseBranch",
    "ResolvedAssignment",
    "Responsibility",
    "ShiftDuty",
    "audit_handover",
]
