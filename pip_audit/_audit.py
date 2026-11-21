"""
Core auditing APIs.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from typing import Any, cast

from packaging.utils import canonicalize_name
from packaging.version import Version

from pip_audit._dependency_source import DependencySource
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._target import (
    EvidenceStatus,
    LockedDependency,
    TargetEnvironment,
    TargetEnvironmentMatrix,
)

logger = logging.getLogger(__name__)


def _add_unique_vulnerability(
    unique_vulns: list[VulnerabilityResult],
    seen_aliases: set[str],
    vuln: VulnerabilityResult,
) -> None:
    """
    Add a vulnerability result, merging it with an existing alias match.
    """

    if seen_aliases.intersection(vuln.aliases | {vuln.id}):
        idx, previous = next((i, p) for (i, p) in enumerate(unique_vulns) if p.alias_of(vuln))
        unique_vulns[idx] = previous.merge_aliases(vuln)
        return

    seen_aliases.update(vuln.aliases | {vuln.id})
    unique_vulns.append(vuln)


def _unique_vulnerabilities(vulns: Iterable[VulnerabilityResult]) -> list[VulnerabilityResult]:
    """
    Unify vulnerability results, merging aliases and prioritizing PYSEC IDs.
    """

    results = list(vulns)
    unique_vulns: list[VulnerabilityResult] = []
    seen_aliases: set[str] = set()

    # First pass, add all PYSEC vulnerabilities and track their alias sets.
    for vuln in results:
        if not vuln.id.startswith("PYSEC"):
            continue
        _add_unique_vulnerability(unique_vulns, seen_aliases, vuln)

    # Second pass: add any non-PYSEC vulnerabilities.
    for vuln in results:
        _add_unique_vulnerability(unique_vulns, seen_aliases, vuln)

    return unique_vulns


@dataclass(frozen=True)
class AuditOptions:
    """
    Settings the control the behavior of an `Auditor` instance.
    """

    dry_run: bool = False


class Auditor:
    """
    The core class of the `pip-audit` API.

    For a given dependency source and vulnerability service, supply a mapping of dependencies to
    known vulnerabilities.
    """

    def __init__(
        self,
        service: VulnerabilityService,
        options: AuditOptions = AuditOptions(),
    ):
        """
        Create a new auditor. Auditors start with no dependencies to audit;
        each `audit` step is fed a `DependencySource`.

        The behavior of the auditor can be optionally tweaked with the `options`
        parameter.
        """
        self._service = service
        self._options = options

    def audit(
        self, source: DependencySource
    ) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
        """
        Perform the auditing step, collecting dependencies from `source`.

        Individual vulnerability results are uniqued based on their `aliases` sets:
        any two results for the same dependency that share an alias are collapsed
        into a single result with a union of all aliases.

        `PYSEC`-identified results are given priority over other results.
        """
        specs = source.collect()

        if self._options.dry_run:
            # Drain the iterator in dry-run mode.
            logger.info(f"Dry run: would have audited {len(list(specs))} packages")
            yield from ()
        else:
            for dep, vulns in self._service.query_all(specs):
                yield dep, _unique_vulnerabilities(vulns)

    def audit_matrix(
        self,
        source: DependencySource,
        environments: TargetEnvironmentMatrix | Iterable[TargetEnvironment],
    ) -> EnvironmentAuditReport:
        """
        Audit a lockfile against an offline matrix of target environments.

        Each target interprets package markers and locked artifacts on its own.
        Advisory queries are reused only for the same canonical distribution
        identity (name and version); the resulting rows remain environment
        specific.
        """

        collect_for = getattr(source, "collect_for", None)
        if collect_for is None:
            raise TypeError("matrix auditing requires a source that implements collect_for()")

        if not isinstance(environments, TargetEnvironmentMatrix):
            environments = TargetEnvironmentMatrix(tuple(environments))

        query_cache: dict[
            tuple[str, Version], tuple[EvidenceStatus, str | None, list[VulnerabilityResult]]
        ] = {}
        query_count = 0
        cache_hits = 0
        queried_identities: list[tuple[str, str]] = []
        environment_results: list[EnvironmentAuditResult] = []

        for environment in environments:
            locked_entries = _select_artifacts_per_environment(list(collect_for(environment)))
            dependency_results: list[EnvironmentDependencyResult] = []
            warnings: list[str] = []

            for locked in locked_entries:
                vulns: list[VulnerabilityResult] = []
                status = locked.status
                reason = locked.reason

                if status is EvidenceStatus.CHECKED:
                    if locked.version is None:  # pragma: no cover - defensive
                        status = EvidenceStatus.MISSING_VERSION
                        reason = "no version specified"
                    else:
                        version = Version(locked.version)
                        identity = (canonicalize_name(locked.name), version)
                        if identity in query_cache:
                            cache_hits += 1
                            cached_status, cached_reason, cached_vulns = query_cache[identity]
                            status = cached_status
                            reason = cached_reason
                            vulns = list(cached_vulns)
                        elif self._options.dry_run:
                            status = EvidenceStatus.ADVISORY_SKIPPED
                            reason = "dry run: advisory query not made"
                        else:
                            dependency = ResolvedDependency(locked.name, version)
                            returned, queried_vulns = self._service.query(dependency)
                            query_count += 1
                            queried_identities.append((identity[0], str(identity[1])))
                            vulns = _unique_vulnerabilities(queried_vulns)

                            if returned.is_skipped():
                                skipped = cast(SkippedDependency, returned)
                                status = EvidenceStatus.ADVISORY_SKIPPED
                                reason = skipped.skip_reason
                                vulns = []

                            query_cache[identity] = (status, reason, vulns)

                result = EnvironmentDependencyResult(
                    name=locked.name,
                    version=locked.version,
                    status=status,
                    artifact=locked.artifact,
                    reason=reason,
                    missing=locked.missing,
                    vulnerabilities=tuple(vulns),
                )
                dependency_results.append(result)

                if result.missing_evidence:
                    warnings.append(
                        f"{result.display_name}: missing "
                        f"{', '.join(result.missing_evidence)}" + (f" ({reason})" if reason else "")
                    )

            warnings.extend(_ambiguous_version_warnings(dependency_results))
            environment_results.append(
                EnvironmentAuditResult(
                    environment=environment,
                    dependencies=tuple(dependency_results),
                    warnings=tuple(warnings),
                )
            )

        return EnvironmentAuditReport(
            environments=tuple(environment_results),
            query_count=query_count,
            cache_hits=cache_hits,
            queried_identities=tuple(queried_identities),
        )

    def audit_environments(
        self,
        source: DependencySource,
        environments: TargetEnvironmentMatrix | Iterable[TargetEnvironment],
    ) -> EnvironmentAuditReport:
        """Alias for `audit_matrix`."""
        return self.audit_matrix(source, environments)


_INCOMPLETE_STATUSES = frozenset(
    {
        EvidenceStatus.MISSING_MARKER_VARIABLE,
        EvidenceStatus.MISSING_ARTIFACT,
        EvidenceStatus.INVALID_ARTIFACT,
        EvidenceStatus.INVALID_MARKER,
        EvidenceStatus.INVALID_REQUIRES_PYTHON,
        EvidenceStatus.MISSING_VERSION,
        EvidenceStatus.ADVISORY_SKIPPED,
    }
)


@dataclass(frozen=True)
class EnvironmentDependencyResult:
    """
    The audit result for one lock entry in one target environment.
    """

    name: str
    version: str | None
    status: EvidenceStatus
    artifact: str | None = None
    reason: str | None = None
    missing: tuple[str, ...] = ()
    vulnerabilities: tuple[VulnerabilityResult, ...] = ()

    @property
    def canonical_name(self) -> str:
        """The canonical distribution name."""
        return canonicalize_name(self.name)

    @property
    def display_name(self) -> str:
        """A compact name and version for diagnostics."""
        if self.version is None:
            return self.name
        return f"{self.name} {self.version}"

    @property
    def identity(self) -> tuple[str, str] | None:
        """The distribution identity used for advisory queries."""
        if self.version is None:
            return None
        return self.canonical_name, self.version

    @property
    def vulns(self) -> tuple[VulnerabilityResult, ...]:
        """Alias for ``vulnerabilities``."""
        return self.vulnerabilities

    @property
    def dependency(self) -> Dependency:
        """Return the entry as a regular dependency object."""
        if self.version is None:
            return SkippedDependency(self.name, self.reason or "no version specified")
        return ResolvedDependency(self.name, Version(self.version))

    @property
    def missing_evidence(self) -> tuple[str, ...]:
        """
        The evidence this environment lacks for this entry.

        An empty tuple means the entry was either fully checked or explicitly
        excluded by a marker.
        """

        if self.status is EvidenceStatus.CHECKED:
            return ()
        if self.status is EvidenceStatus.EXCLUDED:
            return ()
        if self.status is EvidenceStatus.MISSING_MARKER_VARIABLE:
            return self.missing or ("marker-variable",)
        if self.status is EvidenceStatus.MISSING_ARTIFACT:
            return ("compatible-distribution",)
        if self.status is EvidenceStatus.INVALID_ARTIFACT:
            return ("valid-artifact-metadata",)
        if self.status is EvidenceStatus.INVALID_MARKER:
            return ("valid-marker",)
        if self.status is EvidenceStatus.INVALID_REQUIRES_PYTHON:
            return ("valid-requires-python",)
        if self.status is EvidenceStatus.MISSING_VERSION:
            return ("locked-version",)
        if self.status is EvidenceStatus.ADVISORY_SKIPPED:
            return ("advisory-result",)
        return ("unknown",)  # pragma: no cover

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result to a JSON-compatible mapping."""
        return {
            "name": self.canonical_name,
            "version": self.version,
            "status": str(self.status),
            "artifact": self.artifact,
            "reason": self.reason,
            "missing_evidence": list(self.missing_evidence),
            "vulns": [
                {
                    "id": vuln.id,
                    "fix_versions": [str(version) for version in vuln.fix_versions],
                    "aliases": sorted(vuln.aliases),
                    "description": vuln.description,
                }
                for vuln in self.vulnerabilities
            ],
        }


@dataclass(frozen=True)
class EnvironmentAuditResult:
    """
    Coverage and advisory conclusions for one target environment.
    """

    environment: TargetEnvironment
    dependencies: tuple[EnvironmentDependencyResult, ...]
    warnings: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        """The target environment name."""
        return self.environment.name

    @property
    def conclusion(self) -> str:
        """A short coverage conclusion for this environment."""
        return "complete" if self.complete else "incomplete"

    @property
    def checked(self) -> tuple[EnvironmentDependencyResult, ...]:
        """Entries with complete advisory evidence."""
        return tuple(d for d in self.dependencies if d.status is EvidenceStatus.CHECKED)

    @property
    def excluded(self) -> tuple[EnvironmentDependencyResult, ...]:
        """Entries excluded by markers, requires-python, or artifact selection."""
        return tuple(d for d in self.dependencies if d.status is EvidenceStatus.EXCLUDED)

    @property
    def incomplete(self) -> tuple[EnvironmentDependencyResult, ...]:
        """Entries missing evidence in this environment."""
        return tuple(d for d in self.dependencies if d.status in _INCOMPLETE_STATUSES)

    @property
    def ambiguous_versions(self) -> dict[str, tuple[str, ...]]:
        """Checked versions that collide for one distribution in this environment."""
        versions: dict[str, set[str]] = {}
        for dependency in self.checked:
            if dependency.version is not None:
                versions.setdefault(dependency.canonical_name, set()).add(dependency.version)
        return {
            name: tuple(sorted(distribution_versions))
            for name, distribution_versions in versions.items()
            if len(distribution_versions) > 1
        }

    @property
    def complete(self) -> bool:
        """Whether every applicable entry has complete evidence here."""
        return not self.incomplete and not self.ambiguous_versions

    @property
    def vulnerable(self) -> tuple[EnvironmentDependencyResult, ...]:
        """Checked entries with at least one vulnerability."""
        return tuple(d for d in self.dependencies if d.vulnerabilities)

    @property
    def missing_evidence(self) -> dict[str, tuple[str, ...]]:
        """Map each incomplete entry to the evidence it lacks."""
        return {
            dependency.display_name: dependency.missing_evidence for dependency in self.incomplete
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the environment result to a JSON-compatible mapping."""
        applicable = len(self.dependencies) - len(self.excluded)
        return {
            "environment": self.environment.name,
            "name": self.environment.name,
            "complete": self.complete,
            "conclusion": self.conclusion,
            "coverage": {
                "applicable": applicable,
                "checked": len(self.checked),
                "excluded": len(self.excluded),
                "incomplete": len(self.incomplete),
                "ambiguous": len(self.ambiguous_versions),
            },
            "missing_evidence": {
                name: list(evidence) for name, evidence in self.missing_evidence.items()
            },
            "warnings": list(self.warnings),
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
        }


@dataclass(frozen=True)
class EnvironmentAuditReport:
    """
    An environment-by-environment audit of a multi-target lockfile.
    """

    environments: tuple[EnvironmentAuditResult, ...]
    query_count: int
    cache_hits: int = 0
    queried_identities: tuple[tuple[str, str], ...] = ()

    @property
    def complete(self) -> bool:
        """Whether every environment is fully covered."""
        return all(environment.complete for environment in self.environments)

    @property
    def vulnerabilities(self) -> tuple[EnvironmentDependencyResult, ...]:
        """All environment rows with vulnerabilities."""
        return tuple(
            dependency for environment in self.environments for dependency in environment.vulnerable
        )

    @property
    def queries(self) -> tuple[tuple[str, str], ...]:
        """The canonical ``(name, version)`` identities actually queried."""
        return self.queried_identities

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a JSON-compatible mapping."""
        return {
            "complete": self.complete,
            "query_count": self.query_count,
            "cache_hits": self.cache_hits,
            "environments": [environment.to_dict() for environment in self.environments],
            "queries": {
                "count": self.query_count,
                "cache_hits": self.cache_hits,
                "identities": [
                    {"name": name, "version": version} for name, version in self.queried_identities
                ],
            },
        }

    def to_json(self) -> str:
        """Serialize the report as JSON."""
        return json.dumps(self.to_dict())


def _select_artifacts_per_environment(
    entries: Iterable[LockedDependency],
) -> list[LockedDependency]:
    """
    Treat a non-matching version as excluded when another locked version of the
    same distribution has a compatible artifact in this environment.

    This is the wheel-tag equivalent of a marker partition: the lock may carry
    different versions of one distribution for different platforms without a
    package-level marker.
    """

    checked: dict[str, set[str]] = {}
    for entry in entries:
        if entry.status is EvidenceStatus.CHECKED and entry.version is not None:
            checked.setdefault(canonicalize_name(entry.name), set()).add(entry.version)

    selected: list[LockedDependency] = []
    for entry in entries:
        name = canonicalize_name(entry.name)
        checked_versions = checked.get(name, set())
        if entry.status is EvidenceStatus.MISSING_ARTIFACT and entry.version is not None:
            if entry.version in checked_versions:
                entry = replace(
                    entry,
                    status=EvidenceStatus.EXCLUDED,
                    reason="another lock entry for the same version has a compatible artifact",
                )
            else:
                others = checked_versions - {entry.version}
                if others:
                    entry = replace(
                        entry,
                        status=EvidenceStatus.EXCLUDED,
                        reason=(
                            "another locked version "
                            f"({', '.join(sorted(others))}) provides a compatible artifact"
                        ),
                    )
        selected.append(entry)
    return selected


def _ambiguous_version_warnings(
    dependencies: Iterable[EnvironmentDependencyResult],
) -> list[str]:
    """
    Warn when a single environment selects multiple versions of one distribution.
    """

    versions: dict[str, set[str]] = {}
    for dependency in dependencies:
        if dependency.status is EvidenceStatus.EXCLUDED or dependency.version is None:
            continue
        versions.setdefault(dependency.canonical_name, set()).add(dependency.version)

    return [
        f"{name}: multiple locked versions apply in this environment: "
        f"{', '.join(sorted(distribution_versions))}"
        for name, distribution_versions in sorted(versions.items())
        if len(distribution_versions) > 1
    ]
