"""
Core auditing APIs.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from pip_audit._dependency_source import DependencySource
from pip_audit._service import Dependency, VulnerabilityResult, VulnerabilityService
from pip_audit._service.interface import (
    AdvisoryScope,
    ResolvedDependency,
    ServiceError,
    SkippedDependency,
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


def _dedupe_vulnerabilities(vulns: list[VulnerabilityResult]) -> list[VulnerabilityResult]:
    """
    Deduplicate vulnerability results by alias, preferring PYSEC identifiers.
    """
    unique_vulns: list[VulnerabilityResult] = []
    seen_aliases: set[str] = set()

    for vuln in vulns:
        if not vuln.id.startswith("PYSEC"):
            continue
        _add_unique_vulnerability(unique_vulns, seen_aliases, vuln)

    for vuln in vulns:
        _add_unique_vulnerability(unique_vulns, seen_aliases, vuln)

    return unique_vulns


def _dependency_key(dep: Dependency) -> tuple[str, str | None, str]:
    """
    Return a stable identity for a dependency across service response objects.
    """
    if dep.is_skipped():
        return dep.canonical_name, None, "skipped"
    assert isinstance(dep, ResolvedDependency)
    return dep.canonical_name, str(dep.version), "resolved"


def _dependency_version(dep: Dependency) -> str | None:
    """
    Return the resolved version for a dependency, if there is one.
    """
    if isinstance(dep, ResolvedDependency):
        return str(dep.version)
    return None


def _advisory_scope(service: VulnerabilityService, spec: Dependency | None) -> AdvisoryScope | None:
    """
    Ask a service for the advisory scope it can support for `spec`.

    A service is allowed to leave this blank; callers must not infer coverage that
    the service did not declare.
    """
    provider = getattr(service, "advisory_scope", None)
    if callable(provider):
        try:
            scope = provider(spec)
        except TypeError:
            if spec is None:
                return None
            raise
    else:
        scope = provider

    if isinstance(scope, AdvisoryScope):
        return scope
    if isinstance(scope, dict):
        source = scope.get("source") or type(service).__name__
        return AdvisoryScope(
            source=str(source),
            ecosystem=scope.get("ecosystem"),
            endpoint=scope.get("endpoint"),
            package=scope.get("package"),
            version=scope.get("version"),
            cache_group=scope.get("cache_group"),
        )
    if isinstance(scope, str):
        return AdvisoryScope(
            source=scope,
            ecosystem="pypi",
            package=spec.canonical_name if spec is not None else None,
            version=_dependency_version(spec) if spec is not None else None,
        )
    return None


@dataclass(frozen=True)
class AuditedDependency:
    """
    A dependency that the vulnerability source actually answered for.
    """

    dependency: Dependency
    vulns: list[VulnerabilityResult]
    advisory_scope: AdvisoryScope | None

    @property
    def name(self) -> str:
        """
        Return the dependency's original, uncanonicalized name.
        """
        return self.dependency.name

    @property
    def canonical_name(self) -> str:
        """
        Return the dependency's canonicalized name.
        """
        return self.dependency.canonical_name

    @property
    def version(self) -> str | None:
        """
        Return the resolved version, if any.
        """
        return _dependency_version(self.dependency)

    def to_dict(self) -> dict[str, Any]:
        """
        Render this audited item as JSON-compatible data.
        """
        return {
            "name": self.canonical_name,
            "version": self.version,
            "audited": True,
            "vulns": [vuln.id for vuln in self.vulns],
            "finding_count": len(self.vulns),
            "advisory_scope": (
                self.advisory_scope.to_dict() if self.advisory_scope is not None else None
            ),
        }


@dataclass(frozen=True)
class UncheckedDependency:
    """
    A collected dependency that could not be covered by the audit.
    """

    dependency: Dependency
    reason: str
    advisory_scope: AdvisoryScope | None = None

    @property
    def name(self) -> str:
        """
        Return the dependency's original, uncanonicalized name.
        """
        return self.dependency.name

    @property
    def canonical_name(self) -> str:
        """
        Return the dependency's canonicalized name.
        """
        return self.dependency.canonical_name

    @property
    def version(self) -> str | None:
        """
        Return the resolved version, if any.
        """
        return _dependency_version(self.dependency)

    def to_dict(self) -> dict[str, Any]:
        """
        Render this unchecked item with explicit blanks for unsupported evidence.
        """
        return {
            "name": self.canonical_name,
            "version": self.version,
            "audited": False,
            "vulns": None,
            "finding_count": None,
            "advisory_scope": (
                self.advisory_scope.to_dict() if self.advisory_scope is not None else None
            ),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class NegativeProof:
    """
    Evidence for a zero-finding or partially answered audit.

    The denominator records the collected audit set. `audited` lists only the
    dependencies the source actually answered for, while `unchecked` explicitly
    lists the remainder and why each one is missing.
    """

    audited: list[AuditedDependency]
    unchecked: list[UncheckedDependency]
    denominator: int
    advisory_scope: AdvisoryScope | None = None

    @property
    def audited_count(self) -> int:
        """
        Return the number of dependencies the source answered for.
        """
        return len(self.audited)

    @property
    def unchecked_count(self) -> int:
        """
        Return the number of dependencies left outside the audit scope.
        """
        return len(self.unchecked)

    @property
    def complete(self) -> bool:
        """
        Return whether every collected dependency is represented as audited.
        """
        return self.unchecked_count == 0 and self.audited_count == self.denominator

    @property
    def finding_count(self) -> int:
        """
        Return the number of vulnerability findings in the audited portion.
        """
        return sum(len(item.vulns) for item in self.audited)

    @property
    def zero_findings(self) -> bool:
        """
        Return whether the audited portion contains no vulnerability findings.
        """
        return self.finding_count == 0

    def to_dict(self) -> dict[str, Any]:
        """
        Render the proof as JSON-compatible data.
        """
        return {
            "kind": "negative",
            "complete": self.complete,
            "denominator": self.denominator,
            "audited_count": self.audited_count,
            "unchecked_count": self.unchecked_count,
            "finding_count": self.finding_count,
            "zero_findings": self.zero_findings,
            "advisory_scope": (
                self.advisory_scope.to_dict() if self.advisory_scope is not None else None
            ),
            "audited": [item.to_dict() for item in self.audited],
            "unchecked": [item.to_dict() for item in self.unchecked],
        }


class AuditReport(dict[Dependency, list[VulnerabilityResult]]):
    """
    A legacy dependency mapping carrying its independently checkable proof.
    """

    def __init__(
        self,
        results: dict[Dependency, list[VulnerabilityResult]] | None = None,
        *,
        proof: NegativeProof | None = None,
    ) -> None:
        """
        Create a report that remains usable as the old result mapping.
        """
        super().__init__(results or {})
        self.negative_proof = proof

    @property
    def proof(self) -> NegativeProof | None:
        """
        Alias for `negative_proof`.
        """
        return self.negative_proof

    @property
    def audited(self) -> list[AuditedDependency]:
        """
        Return the dependencies the source actually answered for.
        """
        return self.negative_proof.audited if self.negative_proof is not None else []

    @property
    def unchecked(self) -> list[UncheckedDependency]:
        """
        Return the collected dependencies the source did not answer for.
        """
        return self.negative_proof.unchecked if self.negative_proof is not None else []

    @property
    def denominator(self) -> int:
        """
        Return the size of the collected audit set.
        """
        return self.negative_proof.denominator if self.negative_proof is not None else len(self)

    @property
    def advisory_scope(self) -> AdvisoryScope | None:
        """
        Return the service-level advisory scope, if one was declared.
        """
        return self.negative_proof.advisory_scope if self.negative_proof is not None else None

    @property
    def complete(self) -> bool:
        """
        Return whether all collected dependencies are represented as audited.
        """
        return self.negative_proof.complete if self.negative_proof is not None else False

    @property
    def finding_count(self) -> int:
        """
        Return the total number of findings in the report.
        """
        if self.negative_proof is not None:
            return self.negative_proof.finding_count
        return sum(len(vulns) for vulns in self.values())

    @property
    def zero_findings(self) -> bool:
        """
        Return whether the report contains no findings.
        """
        return self.finding_count == 0

    @property
    def audited_dependencies(self) -> list[AuditedDependency]:
        """
        Alias for `audited`.
        """
        return self.audited

    @property
    def unqueried(self) -> list[UncheckedDependency]:
        """
        Alias for `unchecked`.
        """
        return self.unchecked

    @property
    def not_audited(self) -> list[UncheckedDependency]:
        """
        Alias for `unchecked`.
        """
        return self.unchecked

    @property
    def total(self) -> int:
        """
        Alias for `denominator`.
        """
        return self.denominator

    @property
    def scope(self) -> AdvisoryScope | None:
        """
        Alias for `advisory_scope`.
        """
        return self.advisory_scope


# Compatibility names for callers that describe the same evidence as a proof or
# an unqueried set rather than a negative report.
AuditProof = NegativeProof
AuditEvidence = NegativeProof
UnqueriedDependency = UncheckedDependency
AuditScope = AdvisoryScope


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
        self.last_report: AuditReport | None = None

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
                yield dep, _dedupe_vulnerabilities(vulns)

    def audit_report(self, source: DependencySource) -> AuditReport:
        """
        Audit `source` and retain the evidence needed to re-check a negative result.

        The returned report is still the legacy dependency mapping. Its
        `negative_proof` binds the collected set (the denominator) to the advisory
        scope each answered dependency actually covered. Dependencies omitted by the
        service, skipped by the source, or left unanswered by an error are listed in
        `unchecked` instead of being treated as zero-risk.
        """
        specs = list(source.collect())
        requested: dict[tuple[str, str | None, str], Dependency] = {}
        for spec in specs:
            requested.setdefault(_dependency_key(spec), spec)

        if self._options.dry_run:
            logger.info(f"Dry run: would have audited {len(requested)} packages")
            proof = NegativeProof(
                audited=[],
                unchecked=[
                    UncheckedDependency(spec, "dry run: the audit was not executed")
                    for spec in requested.values()
                ],
                denominator=len(requested),
                advisory_scope=None,
            )
            report = AuditReport(proof=proof)
            self.last_report = report
            return report

        answers: dict[
            tuple[str, str | None, str], tuple[Dependency, list[VulnerabilityResult]]
        ] = {}
        service_error: ServiceError | None = None
        try:
            for dep, vulns in self._service.query_all(iter(requested.values())):
                answers[_dependency_key(dep)] = (dep, vulns)
        except ServiceError as exc:
            service_error = exc

        results: dict[Dependency, list[VulnerabilityResult]] = {}
        audited: list[AuditedDependency] = []
        unchecked: list[UncheckedDependency] = []

        for key, spec in requested.items():
            answer = answers.get(key)
            if answer is None:
                if isinstance(spec, SkippedDependency):
                    results[spec] = []
                    reason = spec.skip_reason
                elif service_error is not None:
                    reason = f"vulnerability service did not answer: {service_error}"
                else:
                    reason = "vulnerability service returned no result for this dependency"
                unchecked.append(UncheckedDependency(spec, reason))
                continue

            returned_dep, vulns = answer
            if returned_dep.is_skipped():
                assert isinstance(returned_dep, SkippedDependency)
                results[returned_dep] = []
                unchecked.append(UncheckedDependency(spec, returned_dep.skip_reason))
                continue

            assert isinstance(returned_dep, ResolvedDependency)
            unique_vulns = _dedupe_vulnerabilities(vulns)
            results[returned_dep] = unique_vulns
            scope = _advisory_scope(self._service, returned_dep)
            audited.append(AuditedDependency(returned_dep, unique_vulns, scope))

        # A batched service may return objects that were not in the request. Keep the
        # legacy mapping faithful to the service response, while treating those extra
        # answers as audited only for the proof's scope records.
        for key, (returned_dep, vulns) in answers.items():
            if key in requested:
                continue
            unique_vulns = _dedupe_vulnerabilities(vulns)
            results[returned_dep] = unique_vulns
            if not returned_dep.is_skipped():
                scope = _advisory_scope(self._service, returned_dep)
                audited.append(AuditedDependency(returned_dep, unique_vulns, scope))

        service_scope = _advisory_scope(self._service, None) if audited else None
        if service_scope is None and audited:
            service_scope = audited[0].advisory_scope

        proof = NegativeProof(
            audited=audited,
            unchecked=unchecked,
            denominator=len(requested),
            advisory_scope=service_scope,
        )
        report = AuditReport(results, proof=proof)
        self.last_report = report
        return report

    def audit_with_proof(self, source: DependencySource) -> AuditReport:
        """
        Alias for `audit_report`.
        """
        return self.audit_report(source)

    def audit_proof(self, source: DependencySource) -> AuditReport:
        """
        Alias for `audit_report`.
        """
        return self.audit_report(source)
