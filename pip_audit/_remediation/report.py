"""
Offline remediation checks between two resolved lock plans.

This module reconciles a "before" and an "after" lock plan, each paired with
its own previously captured `pip-audit` JSON output, and answers, per
optional group, which vulnerability alerts have actually been closed, which
have merely moved onto another dependency chain, and which cannot be decided
with the evidence on hand.

Everything here is offline: no packages are installed and no dependency
resolution or vulnerability-service queries are performed.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TypedDict

from pip_audit._remediation.auditreport import AuditReport, AuditVulnerability
from pip_audit._remediation.depgraph import BASE_GROUP, DependencyChain, DependencyGraph
from pip_audit._remediation.lockplan import LockPlan


class _CommonFinding(TypedDict):
    """
    The shared fields accumulated while classifying one alert.
    """

    group: str
    package: str
    vulnerability_id: str
    aliases: frozenset[str]
    before_version: str | None
    after_version: str | None
    before_chains: tuple[tuple[str, ...], ...]
    after_chains: tuple[tuple[str, ...], ...]


class RemediationStatus(str, enum.Enum):
    """
    The classification of a single vulnerability alert across two plans.
    """

    Closed = "closed"
    MovedChain = "moved-chain"
    Unresolved = "unresolved"
    IncompleteEvidence = "incomplete-evidence"

    def __str__(self) -> str:
        """
        Return the stable, user-facing status identifier.
        """

        return self.value


@dataclass(frozen=True)
class RemediationFinding:
    """
    A per-group verdict for a single vulnerability alert.
    """

    group: str
    package: str
    vulnerability_id: str
    status: RemediationStatus
    detail: str
    before_version: str | None
    after_version: str | None
    aliases: frozenset[str]
    before_chains: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
    after_chains: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
    evidence_notes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GroupReport:
    """
    The findings attributed to one optional group (or the base environment).
    """

    name: str
    findings: tuple[RemediationFinding, ...]

    def _count(self, status: RemediationStatus) -> int:
        """
        Count this group's findings with the given status.
        """

        return sum(1 for finding in self.findings if finding.status is status)

    @property
    def closed(self) -> int:
        """
        Number of alerts confirmed closed for this group.
        """

        return self._count(RemediationStatus.Closed)

    @property
    def moved_chain(self) -> int:
        """
        Number of alerts that moved onto another dependency chain.
        """

        return self._count(RemediationStatus.MovedChain)

    @property
    def unresolved(self) -> int:
        """
        Number of alerts that remain on an unchanged chain.
        """

        return self._count(RemediationStatus.Unresolved)

    @property
    def incomplete(self) -> int:
        """
        Number of alerts that cannot be adjudicated with the given evidence.
        """

        return self._count(RemediationStatus.IncompleteEvidence)


@dataclass(frozen=True)
class RemediationReport:
    """
    The full remediation comparison for a pair of lock plans.
    """

    before_lock: str
    after_lock: str
    before_audit: str
    after_audit: str
    before_environments: tuple[str, ...]
    after_environments: tuple[str, ...]
    groups: tuple[GroupReport, ...]

    @property
    def findings(self) -> tuple[RemediationFinding, ...]:
        """
        Every finding across every reported group.
        """

        return tuple(finding for group in self.groups for finding in group.findings)

    def findings_for_group(self, group: str) -> tuple[RemediationFinding, ...]:
        """
        Return the findings attributed to the named group.
        """

        for group_report in self.groups:
            if group_report.name == group:
                return group_report.findings
        return ()

    @property
    def exit_code(self) -> int:
        """
        A shell exit code summarizing the worst outcome in the report.

        `0` means every alert was closed; `1` means at least one alert is
        unresolved or merely moved; `2` means the only outstanding alerts
        could not be adjudicated because the evidence is incomplete.
        """

        statuses = {finding.status for finding in self.findings}
        if RemediationStatus.Unresolved in statuses or RemediationStatus.MovedChain in statuses:
            return 1
        if RemediationStatus.IncompleteEvidence in statuses:
            return 2
        return 0


@dataclass(frozen=True)
class _PlanBundle:
    """
    A lock plan paired with its graph and audit report.
    """

    plan: LockPlan
    graph: DependencyGraph
    audit: AuditReport


class RemediationCheckError(Exception):
    """
    Raised when a remediation check cannot be performed as requested.
    """


class RemediationChecker:
    """
    Compare two resolved lock plans and their audit results offline.
    """

    def __init__(
        self,
        before_plan: LockPlan,
        before_audit: AuditReport,
        after_plan: LockPlan,
        after_audit: AuditReport,
    ) -> None:
        """
        Create a new `RemediationChecker`.

        The "before" arguments describe the original lock plan and audit,
        while the "after" arguments describe the re-locked plan and audit
        that are supposed to demonstrate remediation.
        """

        self._before = _PlanBundle(before_plan, DependencyGraph(before_plan), before_audit)
        self._after = _PlanBundle(after_plan, DependencyGraph(after_plan), after_audit)

    def check(self, only_groups: list[str] | None = None) -> RemediationReport:
        """
        Produce a per-group `RemediationReport`.

        `only_groups` optionally restricts the report to the named optional
        groups; the base environment pseudo-group is always reported first.
        When `None`, every group declared by either plan is reported.
        """

        selected = self._select_groups(only_groups)
        group_reports = [self._check_group(group) for group in selected]

        return RemediationReport(
            before_lock=str(self._before.plan.source),
            after_lock=str(self._after.plan.source),
            before_audit=str(self._before.audit.source),
            after_audit=str(self._after.audit.source),
            before_environments=self._before.plan.environments,
            after_environments=self._after.plan.environments,
            groups=tuple(group_reports),
        )

    def _select_groups(self, requested: list[str] | None) -> list[str]:
        declared = set(self._before.plan.groups) | set(self._after.plan.groups)
        if requested is None:
            return [BASE_GROUP] + sorted(declared)

        selected = [BASE_GROUP]
        for group in requested:
            if group in selected:
                continue
            if group not in declared:
                raise RemediationCheckError(f"unknown optional group: {group}")
            selected.append(group)
        return selected

    def _check_group(self, group: str) -> GroupReport:
        before_roots = self._before.graph.group_roots(group)
        after_roots = self._after.graph.group_roots(group)
        reachable = self._before.graph.reachable_from(before_roots)

        findings = [
            self._classify(group, package, vulnerability, before_roots, after_roots)
            for package in sorted(reachable)
            for vulnerability in self._before.audit.vulnerabilities.get(package, [])
        ]
        return GroupReport(name=group, findings=tuple(findings))

    def _classify(
        self,
        group: str,
        package: str,
        vulnerability: AuditVulnerability,
        before_roots: frozenset[str],
        after_roots: frozenset[str],
    ) -> RemediationFinding:
        before_graph_chains = self._before.graph.chains_to(before_roots, package)
        after_graph_chains = self._after.graph.chains_to(after_roots, package)
        before_chains = self._chain_tuples(before_graph_chains)
        after_chains = self._chain_tuples(after_graph_chains)

        before_package = self._before.plan.package(package)
        before_version = before_package.version if before_package is not None else None
        after_package = self._after.plan.package(package)
        after_version = after_package.version if after_package is not None else None

        common = {
            "group": group,
            "package": package,
            "vulnerability_id": vulnerability.id,
            "aliases": frozenset(vulnerability.aliases),
            "before_version": before_version,
            "after_version": after_version,
            "before_chains": before_chains,
            "after_chains": after_chains,
        }

        if after_package is None or not after_package.resolved:
            return self._finding(
                common,
                RemediationStatus.Closed,
                f"{package} is no longer part of the resolved after lock plan",
            )

        if package in self._after.audit.skipped:
            reason = self._after.audit.skipped[package]
            return self._finding(
                common,
                RemediationStatus.IncompleteEvidence,
                f"{package} was skipped by the after audit ({reason}); its alert cannot be "
                "confirmed as closed",
                (f"after audit skip reason: {reason}",),
            )

        if package not in self._after.audit.vulnerabilities:
            return self._finding(
                common,
                RemediationStatus.IncompleteEvidence,
                f"{package} {after_version} remains in the after plan but has no after-audit "
                "entry, so the alert cannot be confirmed as closed",
                ("after audit does not cover this package",),
            )

        if not self._after_audit_matches(package, vulnerability):
            return self._finding(
                common,
                RemediationStatus.Closed,
                f"{package} {after_version} is still audited but the after audit no longer "
                f"reports {vulnerability.id}",
            )

        if not after_chains:
            return self._finding(
                common,
                RemediationStatus.IncompleteEvidence,
                f"{package} {after_version} is still vulnerable but is not reachable from the "
                f"{group} group in the after plan; another group may still pull it in",
                ("no after-plan chain from this group",),
            )

        if any(chain.marker_gated for chain in after_graph_chains):
            note = (
                "an after-plan chain is behind an environment marker; the static plans cannot "
                "prove the vulnerable chain is installed for every declared environment"
            )
            return self._finding(
                common,
                RemediationStatus.IncompleteEvidence,
                f"{package} {after_version} is reachable only through marker-gated edges",
                (note,),
            )

        before_shortest = min(before_chains, key=len)
        after_shortest = min(after_chains, key=len)
        if after_shortest != before_shortest:
            return self._finding(
                common,
                RemediationStatus.MovedChain,
                f"{vulnerability.id} remains via {self._format_chain(after_shortest)}, a "
                "different chain than in the before plan; it moved rather than being closed",
            )

        return self._finding(
            common,
            RemediationStatus.Unresolved,
            f"{package} {after_version} remains vulnerable through the unchanged chain "
            f"{self._format_chain(after_shortest)}",
        )

    def _after_audit_matches(self, package: str, vulnerability: AuditVulnerability) -> bool:
        target_ids = vulnerability.id_aliases
        for candidate in self._after.audit.vulnerabilities.get(package, []):
            if target_ids & candidate.id_aliases:
                return True
        return False

    def _chain_tuples(self, chains: list[DependencyChain]) -> tuple[tuple[str, ...], ...]:
        return tuple(chain.packages for chain in chains)

    def _format_chain(self, chain: tuple[str, ...]) -> str:
        return " -> ".join(chain)

    def _finding(
        self,
        common: _CommonFinding,
        status: RemediationStatus,
        detail: str,
        evidence_notes: tuple[str, ...] = (),
    ) -> RemediationFinding:
        return RemediationFinding(
            group=common["group"],
            package=common["package"],
            vulnerability_id=common["vulnerability_id"],
            status=status,
            detail=detail,
            before_version=common["before_version"],
            after_version=common["after_version"],
            aliases=common["aliases"],
            before_chains=common["before_chains"],
            after_chains=common["after_chains"],
            evidence_notes=evidence_notes,
        )
