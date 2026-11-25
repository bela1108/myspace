"""
Version-aware alias approvals (exemptions) for audit results.

When a vulnerability service revises its advisories, identifiers that used to
be aliases of one another can be split apart. A blanket ID-based exemption
recorded against an older data-source version would then incorrectly cover the
newly separated risk.

The types in this module therefore bind every approval to:

* the data-source version in which it was granted,
* a concrete package and version, and
* the exact alias evidence observed at approval time.

An approval only suppresses a current result when the current advisory still
carries the approved identifier for the same package/version pair.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from packaging.utils import canonicalize_name
from packaging.version import Version

from pip_audit._service.interface import ResolvedDependency, VulnerabilityResult


class AuditVerdict(str, Enum):
    """
    The disposition of a single package/version after alias-aware checking.
    """

    EXEMPT = "exempt"
    """
    The advisory is covered by an existing, evidence-linked approval.
    """

    REPORT = "report"
    """
    The advisory is a live risk not covered by an existing approval.
    """

    WITHDRAWN = "withdrawn"
    """
    The feed lists the advisory as withdrawn (retracted), not as a live risk.
    """

    UNAVAILABLE = "unavailable"
    """
    The feed is temporarily unreachable; no advisory conclusion is available.
    """

    CONFLICT = "conflict"
    """
    Two feeds in the same batch disagree; both sides are retained as evidence.
    """


@dataclass(frozen=True)
class FeedEvidence:
    """
    One feed's contribution to an audit decision, retained for provenance.
    """

    source: str
    """
    The data source's name.
    """

    source_version: str
    """
    The data-source version that produced this evidence.
    """

    result: VulnerabilityResult | None
    """
    The advisory observed, or `None` when the feed had no matching advisory.
    """

    withdrawn: bool = False
    """
    Whether this evidence records a withdrawn advisory.
    """


@dataclass(frozen=True)
class Approval:
    """
    A previously granted exemption, bound to a package, version, and feed.

    `primary_id` is the identifier the approver actually signed off on.
    `alias_evidence` is the full set of identifiers linked to it in the
    approving snapshot; it is kept so later audits can prove which branch of a
    split still belongs to the original advisory.
    """

    package: str
    """
    The approved package's **uncanonicalized** name.
    """

    version: Version
    """
    The exact package version the approval applies to.
    """

    primary_id: str
    """
    The identifier explicitly approved.
    """

    source: str
    """
    The data source in which the approval was granted.
    """

    source_version: str
    """
    The data-source version against which the approval was granted.
    """

    alias_evidence: frozenset[str] = frozenset()
    """
    All identifiers linked to `primary_id` at approval time.
    """

    def covers(self, result: VulnerabilityResult) -> bool:
        """
        Return whether the approved identifier still links to this result.

        Coverage requires the current result to carry the approved
        `primary_id`. If a revision splits the identifiers so that the result
        no longer contains that id, the historical alias alone is not enough
        to suppress the new branch.
        """

        current_ids = result.aliases | {result.id}
        return self.primary_id in current_ids


@dataclass(frozen=True)
class AuditDecision:
    """
    The outcome of alias-aware checking for one package/version.
    """

    dependency: ResolvedDependency
    """
    The dependency that was checked.
    """

    verdict: AuditVerdict
    """
    The final disposition after applying approvals.
    """

    results: tuple[VulnerabilityResult, ...] = ()
    """
    The live advisory results associated with the decision.
    """

    evidence: tuple[FeedEvidence, ...] = ()
    """
    Per-feed evidence supporting the decision, including both sides of a
    conflict.
    """

    approvals: tuple[Approval, ...] = ()
    """
    The approvals that were applied, when the verdict is `EXEMPT`.
    """

    reason: str = ""
    """
    A short, human-readable explanation of the decision.
    """


class ApprovalRegistry:
    """
    An indexed collection of `Approval` records.

    Approvals are looked up by canonical package name and exact version, so an
    approval never spills over to another package or a different version.
    """

    def __init__(self, approvals: list[Approval] | None = None):
        """
        Create a registry, optionally pre-populated with approvals.
        """

        self._approvals: list[Approval] = list(approvals or [])
        self._index: dict[tuple[str, Version], list[Approval]] = {}
        for approval in self._approvals:
            self._index.setdefault(
                (canonicalize_name(approval.package), approval.version), []
            ).append(approval)

    def add(self, approval: Approval) -> None:
        """
        Record a new approval.
        """

        self._approvals.append(approval)
        self._index.setdefault((canonicalize_name(approval.package), approval.version), []).append(
            approval
        )

    def for_dependency(self, dep: ResolvedDependency) -> list[Approval]:
        """
        Return all approvals scoped to the given dependency.
        """

        return list(self._index.get((dep.canonical_name, dep.version), ()))

    def covering(self, result: VulnerabilityResult, dep: ResolvedDependency) -> list[Approval]:
        """
        Return approvals that both scope-match the dependency and cover the
        result via a still-linked identifier.
        """

        return [approval for approval in self.for_dependency(dep) if approval.covers(result)]

    def __len__(self) -> int:
        """
        Return the number of recorded approvals.
        """

        return len(self._approvals)


def approvals_from_results(
    dep: ResolvedDependency,
    results: list[VulnerabilityResult],
    source: str,
    source_version: str,
) -> list[Approval]:
    """
    Derive approval records from results that a human accepted on a snapshot.

    Each result's primary id becomes the approval's `primary_id`, and the
    result's aliases become the recorded evidence. The approvals are pinned to
    the dependency's package/version and the approving data-source version.
    """

    return [
        Approval(
            package=dep.name,
            version=dep.version,
            primary_id=result.id,
            source=source,
            source_version=source_version,
            alias_evidence=frozenset(result.aliases),
        )
        for result in results
    ]
