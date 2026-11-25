"""
Core auditing APIs.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from pip_audit._dependency_source import DependencySource
from pip_audit._result import (
    AuditReport,
    AuditResult,
    SnapshotStore,
    UnqueriedDependency,
    fingerprint_dependencies,
)
from pip_audit._service import (
    Dependency,
    ServiceError,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._service.interface import ResolvedDependency, SkippedDependency
from pip_audit._service.status import CacheStatus, SourceAvailability, SourceSnapshot

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
        service: VulnerabilityService
        | Mapping[str, VulnerabilityService]
        | list[tuple[str, VulnerabilityService]]
        | None = None,
        options: AuditOptions = AuditOptions(),
        *,
        services: Mapping[str, VulnerabilityService]
        | list[tuple[str, VulnerabilityService]]
        | None = None,
        snapshot_store: SnapshotStore | None = None,
    ):
        """
        Create a new auditor. Auditors start with no dependencies to audit;
        each `audit` step is fed a `DependencySource`.

        The behavior of the auditor can be optionally tweaked with the `options`
        parameter.
        """
        if services is not None:
            self._services = self._normalize_services(services)
        elif isinstance(service, Mapping):
            self._services = self._normalize_services(service)
        elif isinstance(service, list) and service and isinstance(service[0], tuple):
            self._services = self._normalize_services(service)
        else:
            if service is None:
                raise TypeError("Auditor requires a vulnerability service")
            self._service = service
            self._services = [(self._source_name(service), service)]
            self._options = options
            self._snapshot_store = snapshot_store
            return

        if not self._services:
            raise ValueError("Auditor requires at least one vulnerability service")
        self._service = self._services[0][1]
        self._options = options
        self._snapshot_store = snapshot_store

    @staticmethod
    def _normalize_services(
        services: Mapping[str, VulnerabilityService] | list[tuple[str, VulnerabilityService]],
    ) -> list[tuple[str, VulnerabilityService]]:
        if isinstance(services, Mapping):
            return [(name, service) for name, service in services.items()]
        return list(services)

    @staticmethod
    def _source_name(service: VulnerabilityService) -> str:
        name = getattr(service, "source_name", None)
        if isinstance(name, str) and name:
            return name
        return service.__class__.__name__

    @staticmethod
    def _cache_status(service: VulnerabilityService, source_name: str) -> CacheStatus:
        provider = getattr(service, "cache_status", None)
        if callable(provider):
            provider = provider()
        getter = getattr(service, "get_cache_status", None)
        if provider is None and callable(getter):
            provider = getter()
        if isinstance(provider, CacheStatus):
            if provider.source == source_name:
                return provider
            return CacheStatus(
                source=source_name,
                freshness=provider.freshness,
                checked_at=provider.checked_at,
                cached_at=provider.cached_at,
                age_seconds=provider.age_seconds,
                ttl_seconds=provider.ttl_seconds,
                from_cache=provider.from_cache,
                detail=provider.detail,
            )
        return CacheStatus.unknown(source_name)

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
                unique_vulns: list[VulnerabilityResult] = []
                seen_aliases: set[str] = set()

                # First pass, add all PYSEC vulnerabilities and track their
                # alias sets.
                for v in vulns:
                    if not v.id.startswith("PYSEC"):
                        continue

                    _add_unique_vulnerability(unique_vulns, seen_aliases, v)

                # Second pass: add any non-PYSEC vulnerabilities.
                for v in vulns:
                    # If we've already seen this vulnerability by another name,
                    # don't add it. Instead, find the previous result and update
                    # its alias set.
                    _add_unique_vulnerability(unique_vulns, seen_aliases, v)

                yield dep, unique_vulns

    def audit_report(
        self,
        source: DependencySource,
        *,
        snapshot_store: SnapshotStore | None = None,
    ) -> AuditReport:
        """
        Audit `source` while keeping source, cache, vulnerability and unqueried
        state in separate result segments.
        """
        specs = list(source.collect())
        input_digest = fingerprint_dependencies(specs)

        if self._options.dry_run:
            logger.info(f"Dry run: would have audited {len(specs)} packages")
            result = AuditResult(input_digest=input_digest)
            return AuditReport(result)

        query_specs = [spec for spec in specs if not spec.is_skipped()]
        source_results: dict[
            str, dict[Dependency, tuple[Dependency, list[VulnerabilityResult]]]
        ] = {}
        unqueried: list[UnqueriedDependency] = []
        snapshots: dict[str, SourceSnapshot] = {}

        for source_name, service in self._services:
            outcomes: dict[Dependency, tuple[Dependency, list[VulnerabilityResult]]] = {}
            success_count = 0
            failure_count = 0
            last_error: ServiceError | None = None
            cache_status = self._cache_status(service, source_name)

            for spec in query_specs:
                try:
                    outcome = service.query(spec)
                except ServiceError as exc:
                    failure_count += 1
                    last_error = exc
                    unqueried.append(
                        UnqueriedDependency(
                            dependency=spec,
                            source=source_name,
                            reason=str(exc),
                        )
                    )
                else:
                    outcomes[spec] = outcome
                    success_count += 1

                observed_cache = self._cache_status(service, source_name)
                if (
                    observed_cache.freshness.value != "unknown"
                    or observed_cache.from_cache is not None
                ):
                    cache_status = observed_cache

            source_results[source_name] = outcomes

            if not query_specs or failure_count == 0:
                availability = SourceAvailability.AVAILABLE
            elif success_count == 0:
                availability = SourceAvailability.UNAVAILABLE
            else:
                availability = SourceAvailability.AVAILABLE

            source_url = getattr(service, "source_url", None)
            if source_url is None:
                source_url = getattr(service, "osv_url", None)

            snapshots[source_name] = SourceSnapshot(
                name=source_name,
                availability=availability,
                url=source_url if isinstance(source_url, str) else None,
                error=str(last_error) if last_error is not None and failure_count else None,
                cache=cache_status,
            )

        aggregated: dict[Dependency, list[VulnerabilityResult]] = {}
        for spec in specs:
            if spec.is_skipped():
                aggregated[spec] = []
                continue

            all_vulns: list[VulnerabilityResult] = []
            resolved_dep: ResolvedDependency | None = None
            skip_reasons: list[str] = []

            for source_name, _service in self._services:
                outcome = source_results[source_name].get(spec)
                if outcome is None:
                    continue
                returned_dep, vulns = outcome
                if returned_dep.is_skipped():
                    skipped_dep = returned_dep
                    assert isinstance(skipped_dep, SkippedDependency)
                    skip_reasons.append(skipped_dep.skip_reason)
                    continue

                assert isinstance(returned_dep, ResolvedDependency)
                resolved_dep = returned_dep
                all_vulns.extend(vulns)

            if resolved_dep is not None:
                unique_vulns: list[VulnerabilityResult] = []
                seen_aliases: set[str] = set()
                for vuln in all_vulns:
                    if vuln.id.startswith("PYSEC"):
                        _add_unique_vulnerability(unique_vulns, seen_aliases, vuln)
                for vuln in all_vulns:
                    _add_unique_vulnerability(unique_vulns, seen_aliases, vuln)
                aggregated[resolved_dep] = unique_vulns
            elif skip_reasons:
                aggregated[SkippedDependency(name=spec.name, skip_reason=skip_reasons[0])] = []

        store = snapshot_store if snapshot_store is not None else self._snapshot_store
        if store is None:
            store = SnapshotStore()
        preserved_snapshots = store.preserve(input_digest, snapshots)

        result = AuditResult(
            results=aggregated,
            sources=preserved_snapshots,
            cache_statuses={
                name: snapshot.cache
                for name, snapshot in preserved_snapshots.items()
                if snapshot.cache is not None
            },
            unqueried=unqueried,
            input_digest=input_digest,
        )
        return AuditReport(result)
