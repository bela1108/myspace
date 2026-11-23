"""
Offline remediation checking across two resolved lock plans.

This subpackage never installs packages and never performs dependency
resolution: it only reads already-resolved `pylock.*.toml` lock plans (PEP
751) together with existing `pip-audit` JSON audit results, and explains what
remediation work each optional group still requires.
"""

from pip_audit._remediation.auditreport import (
    AuditReport,
    AuditReportError,
    AuditVulnerability,
    read_audit_report,
)
from pip_audit._remediation.depgraph import BASE_GROUP, DependencyChain, DependencyGraph
from pip_audit._remediation.lockplan import (
    LockDependency,
    LockPackage,
    LockPlan,
    LockPlanError,
    evaluate_marker,
    load_lock_plan,
)
from pip_audit._remediation.report import (
    GroupReport,
    RemediationChecker,
    RemediationCheckError,
    RemediationFinding,
    RemediationReport,
    RemediationStatus,
)

__all__ = [
    "BASE_GROUP",
    "AuditReport",
    "AuditReportError",
    "AuditVulnerability",
    "DependencyChain",
    "DependencyGraph",
    "GroupReport",
    "LockDependency",
    "LockPackage",
    "LockPlan",
    "LockPlanError",
    "RemediationCheckError",
    "RemediationChecker",
    "RemediationFinding",
    "RemediationReport",
    "RemediationStatus",
    "evaluate_marker",
    "load_lock_plan",
    "read_audit_report",
]
