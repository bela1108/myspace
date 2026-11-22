"""
Read-only reconciliation of remediation plans against resolved environments.

A remediation plan is produced independently of the environment that it is
ultimately applied to, and a second scan can therefore observe different
(often older) distributions than the ones the plan was generated from. This
module reconciles the *expected* outcome of a plan with the *actual*
distributions resolved in two environments, without performing any fixes,
filesystem access, or vulnerability-service queries.

All inputs are in-memory materials:

* the expected remediation plan, a list of `PlannedFix` entries;
* the baseline manifest, the dependencies resolved before remediation;
* the target manifest, the dependencies resolved in the selected target
  environment after remediation.

Plan names are never treated as distribution identities on their own: they
are PEP 503 canonicalized and matched against the canonicalized names of the
parsed distributions. This keeps aliases such as ``foo_bar`` and
``Foo-Bar`` from silently standing in for a different resolved package.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

from packaging.utils import canonicalize_name
from packaging.version import Version

from pip_audit._service.interface import ResolvedDependency, SkippedDependency

if TYPE_CHECKING:
    from pip_audit._fix import ResolvedFixVersion
    from pip_audit._service import Dependency


class RemediationStatus(str, enum.Enum):
    """
    The outcome of reconciling a plan entry (or an unplanned distribution)
    with the resolved target environment.
    """

    Fixed = "fixed"
    """
    The planned distribution is present in the target environment at the
    expected fixed version or a newer one.
    """

    StillVulnerable = "still-vulnerable"
    """
    The planned distribution is still present below the expected fixed
    version, typically because an indirect dependency was left behind.
    """

    Removed = "removed"
    """
    The planned distribution was present in the baseline but is absent from
    the target environment.
    """

    Downgraded = "downgraded"
    """
    The distribution present in the target environment is older than the
    version that was present in the baseline.
    """

    UnderCovered = "under-covered"
    """
    A resolved distribution has no matching entry in the remediation plan,
    so the plan does not cover it.
    """

    Unverified = "unverified"
    """
    The plan entry could not be matched to any parsed distribution in either
    manifest using its canonicalized name.
    """


@dataclass(frozen=True)
class PlannedFix:
    """
    A single expected remediation action: upgrading a named distribution to a
    version without known vulnerabilities.
    """

    name: str
    """
    The distribution name as written in the remediation plan.

    This is an untrusted, uncanonicalized alias and is never used directly as
    a distribution identity; see `canonical_name`.
    """

    fixed_version: Version
    """
    The minimum version expected once the remediation has been applied.
    """

    @property
    def canonical_name(self) -> str:
        """
        The PEP 503 canonicalized name used to match parsed distributions.
        """
        return canonicalize_name(self.name)

    @classmethod
    def from_resolved_fix_version(cls, fix_version: ResolvedFixVersion) -> PlannedFix:
        """
        Build a `PlannedFix` from a fix version produced by
        `pip_audit._fix.resolve_fix_versions`.
        """
        return cls(name=fix_version.dep.name, fixed_version=fix_version.version)


@dataclass(frozen=True)
class RemediationFinding:
    """
    A single discrepancy (or confirmation) discovered while reviewing a
    remediation plan against resolved manifests.
    """

    status: RemediationStatus
    """
    The reviewed outcome for this distribution.
    """

    canonical_name: str
    """
    The canonicalized distribution identity the finding refers to.
    """

    planned_fix: PlannedFix | None = None
    """
    The matching plan entry, or `None` when the finding concerns a
    distribution that the plan does not cover.
    """

    baseline: ResolvedDependency | None = None
    """
    The distribution as resolved in the baseline manifest, if present.
    """

    target: ResolvedDependency | None = None
    """
    The distribution as resolved in the target manifest, if present.
    """


@dataclass(frozen=True)
class RemediationReview:
    """
    The complete result of reviewing a remediation plan against two resolved
    manifests.
    """

    findings: tuple[RemediationFinding, ...]
    """
    Every finding, one per plan entry plus one per uncovered distribution.
    """

    @property
    def fixed(self) -> tuple[RemediationFinding, ...]:
        """
        The findings confirming a successfully applied plan entry.
        """
        return _filter_findings(self.findings, RemediationStatus.Fixed)

    @property
    def still_vulnerable(self) -> tuple[RemediationFinding, ...]:
        """
        The findings for distributions left below their fixed versions.
        """
        return _filter_findings(self.findings, RemediationStatus.StillVulnerable)

    @property
    def removed(self) -> tuple[RemediationFinding, ...]:
        """
        The findings for distributions that disappeared from the target.
        """
        return _filter_findings(self.findings, RemediationStatus.Removed)

    @property
    def downgraded(self) -> tuple[RemediationFinding, ...]:
        """
        The findings for distributions whose target version is older than
        their baseline version.
        """
        return _filter_findings(self.findings, RemediationStatus.Downgraded)

    @property
    def under_covered(self) -> tuple[RemediationFinding, ...]:
        """
        The findings for resolved distributions absent from the plan.
        """
        return _filter_findings(self.findings, RemediationStatus.UnderCovered)

    @property
    def unverified(self) -> tuple[RemediationFinding, ...]:
        """
        The findings for plan entries that matched no parsed distribution.
        """
        return _filter_findings(self.findings, RemediationStatus.Unverified)


def review_remediation(
    plan: list[PlannedFix],
    baseline: list[Dependency],
    target: list[Dependency],
) -> RemediationReview:
    """
    Review a remediation plan against two parsed dependency manifests.

    This function is strictly read-only: it performs no upgrades, no
    filesystem or network access, and it does not mutate its arguments. It
    only compares versions of distributions parsed from the supplied
    in-memory manifests.

    `baseline` holds the dependencies resolved before remediation and
    `target` the dependencies resolved in the selected target environment
    after remediation. `SkippedDependency` entries, which carry no resolved
    version, are ignored.

    Each plan entry is matched to parsed distributions through its
    canonicalized name, and its target version is classified as fixed,
    still vulnerable, removed, downgraded, or unverified. Any resolved
    distribution whose canonicalized name no plan entry claims is reported
    as under-covered.
    """
    baseline_deps = _index_resolved(baseline)
    target_deps = _index_resolved(target)

    findings: list[RemediationFinding] = []
    planned_names: set[str] = set()

    for planned in plan:
        canonical_name = planned.canonical_name
        planned_names.add(canonical_name)

        baseline_dep = baseline_deps.get(canonical_name)
        target_dep = target_deps.get(canonical_name)

        findings.append(
            RemediationFinding(
                status=_classify_planned(planned, baseline_dep, target_dep),
                canonical_name=canonical_name,
                planned_fix=planned,
                baseline=baseline_dep,
                target=target_dep,
            )
        )

    for canonical_name in sorted(baseline_deps.keys() | target_deps.keys()):
        if canonical_name in planned_names:
            continue
        findings.append(
            RemediationFinding(
                status=RemediationStatus.UnderCovered,
                canonical_name=canonical_name,
                baseline=baseline_deps.get(canonical_name),
                target=target_deps.get(canonical_name),
            )
        )

    return RemediationReview(findings=tuple(findings))


def _classify_planned(
    planned: PlannedFix,
    baseline_dep: ResolvedDependency | None,
    target_dep: ResolvedDependency | None,
) -> RemediationStatus:
    """
    Classify a single plan entry from its baseline and target resolutions.
    """
    if target_dep is None:
        if baseline_dep is None:
            # The plan name cannot be tied to any parsed distribution, so
            # treating it as an identity would be unsound.
            return RemediationStatus.Unverified
        return RemediationStatus.Removed

    if baseline_dep is not None and target_dep.version < baseline_dep.version:
        # A downgrade is reported even when the target remains vulnerable.
        return RemediationStatus.Downgraded

    if target_dep.version < planned.fixed_version:
        return RemediationStatus.StillVulnerable

    return RemediationStatus.Fixed


def _index_resolved(deps: list[Dependency]) -> dict[str, ResolvedDependency]:
    """
    Index resolved dependencies by their canonicalized names.

    `SkippedDependency` entries have no resolved version and are discarded.
    On duplicate names, the first parsed distribution wins.
    """
    indexed: dict[str, ResolvedDependency] = {}
    for dep in deps:
        if isinstance(dep, SkippedDependency):
            continue
        if isinstance(dep, ResolvedDependency):
            resolved = dep
        else:
            resolved = ResolvedDependency(dep.name, dep.version)
        indexed.setdefault(resolved.canonical_name, resolved)
    return indexed


def _filter_findings(
    findings: tuple[RemediationFinding, ...],
    status: RemediationStatus,
) -> tuple[RemediationFinding, ...]:
    """
    Return the findings with the given status.
    """
    return tuple(finding for finding in findings if finding.status is status)
