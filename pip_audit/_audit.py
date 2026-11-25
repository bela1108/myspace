"""
Core auditing APIs.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import cast

from pip_audit._dependency_source import DependencySource
from pip_audit._exemption import (
    Approval,
    ApprovalRegistry,
    AuditDecision,
    AuditVerdict,
    FeedEvidence,
)
from pip_audit._service import Dependency, VulnerabilityResult, VulnerabilityService
from pip_audit._service.interface import (
    ConnectionError as ServiceConnectionError,
)
from pip_audit._service.interface import (
    ResolvedDependency,
    SkippedDependency,
)
from pip_audit._service.offline import OfflineSnapshotService, SnapshotFeedResult

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


class ExemptionAuditor:
    """
    An audit-layer checker that applies version-aware alias approvals.

    Unlike `Auditor`, which simply reports service results, `ExemptionAuditor`
    consults one or more offline, versioned snapshot services and compares
    their findings against an `ApprovalRegistry`. Each dependency receives a
    single `AuditDecision` with one of five verdicts:

    * `EXEMPT` when a package/version-scoped approval still links to the live
      advisory in the current data-source version,
    * `REPORT` when the advisory is a live risk without covering approval,
      including the newly separated branch of a split advisory,
    * `WITHDRAWN` when every feed marks the advisory as retracted,
    * `UNAVAILABLE` when every feed is temporarily unreachable, and
    * `CONFLICT` when two feeds in the same batch disagree, with both sides
      retained as evidence.
    """

    def __init__(
        self,
        services: list[OfflineSnapshotService] | OfflineSnapshotService,
        registry: ApprovalRegistry | None = None,
    ):
        """
        Create an exemption auditor around one or more snapshot services.

        `registry` holds previously granted approvals; when omitted, the
        auditor starts with an empty registry (everything live is reported).
        """

        if isinstance(services, OfflineSnapshotService):
            self._services = [services]
        else:
            if not services:
                raise ValueError("ExemptionAuditor requires at least one snapshot service")
            self._services = list(services)
        self._registry = registry if registry is not None else ApprovalRegistry()

    @property
    def registry(self) -> ApprovalRegistry:
        """
        The approval registry consulted when checking results.
        """

        return self._registry

    def grant_approvals(self, approvals: list[Approval]) -> None:
        """
        Record approvals, for example those granted against an earlier run.
        """

        for approval in approvals:
            self._registry.add(approval)

    def _collect_feeds(
        self, dep: ResolvedDependency
    ) -> tuple[list[SnapshotFeedResult], list[ServiceConnectionError]]:
        """
        Query every snapshot service, separating answers from failures.
        """

        feeds: list[SnapshotFeedResult] = []
        errors: list[ServiceConnectionError] = []
        for service in self._services:
            try:
                feed = service.query_snapshot(dep)
            except ServiceConnectionError as error:
                errors.append(error)
                continue
            feeds.append(feed)
        return feeds, errors

    def _decide_single_feed(
        self,
        dep: ResolvedDependency,
        feed: SnapshotFeedResult,
    ) -> AuditDecision:
        """
        Reduce one feed answer to a decision using the approval registry.
        """

        if feed.withdrawn and not feed.active:
            evidence = tuple(
                FeedEvidence(
                    source=feed.source,
                    source_version=feed.source_version,
                    result=result,
                    withdrawn=True,
                )
                for result in feed.withdrawn
            )
            return AuditDecision(
                dependency=dep,
                verdict=AuditVerdict.WITHDRAWN,
                results=feed.withdrawn,
                evidence=evidence,
                reason=(f"{feed.source} {feed.source_version} marks the advisory as withdrawn"),
            )

        exempt: list[VulnerabilityResult] = []
        reported: list[VulnerabilityResult] = []
        applied: list[Approval] = []
        for result in feed.active:
            covering = self._registry.covering(result, dep)
            if covering:
                exempt.append(result)
                applied.extend(covering)
            else:
                reported.append(result)

        evidence = tuple(
            FeedEvidence(
                source=feed.source,
                source_version=feed.source_version,
                result=result,
            )
            for result in (*feed.active, *feed.withdrawn)
        )

        if reported:
            return AuditDecision(
                dependency=dep,
                verdict=AuditVerdict.REPORT,
                results=tuple(reported),
                evidence=evidence,
                reason=(
                    f"{feed.source} {feed.source_version} reports live advisories "
                    "not covered by an existing approval"
                ),
            )

        if exempt:
            return AuditDecision(
                dependency=dep,
                verdict=AuditVerdict.EXEMPT,
                results=tuple(exempt),
                evidence=evidence,
                approvals=tuple(applied),
                reason=(
                    "all live advisories remain linked to approvals granted "
                    "against earlier data-source versions"
                ),
            )

        return AuditDecision(
            dependency=dep,
            verdict=AuditVerdict.REPORT,
            results=(),
            evidence=evidence,
            reason=(f"{feed.source} {feed.source_version} has no advisories for this dependency"),
        )

    @staticmethod
    def _result_ids(results: tuple[VulnerabilityResult, ...]) -> set[str]:
        """
        Collect every identifier carried by the given results.
        """

        identifiers: set[str] = set()
        for result in results:
            identifiers.update(result.aliases | {result.id})
        return identifiers

    def _feeds_conflict(self, feeds: list[SnapshotFeedResult]) -> bool:
        """
        Return whether the feeds disagree on a shared advisory.

        A conflict requires a shared identifier that is active in one feed
        and withdrawn in another. Feeds with no overlapping identifiers are
        not in conflict.
        """

        tracked = [feed for feed in feeds if self._result_ids((*feed.active, *feed.withdrawn))]
        if len(tracked) < 2:
            return False

        active_per_feed = [self._result_ids(feed.active) for feed in tracked]
        withdrawn_per_feed = [self._result_ids(feed.withdrawn) for feed in tracked]
        shared = set.intersection(
            *(active | withdrawn for active, withdrawn in zip(active_per_feed, withdrawn_per_feed))
        )

        for identifier in shared:
            states = set()
            for active, withdrawn in zip(active_per_feed, withdrawn_per_feed):
                if identifier in active:
                    states.add("active")
                elif identifier in withdrawn:
                    states.add("withdrawn")
            if len(states) > 1:
                return True
        return False

    @staticmethod
    def _conflict(dep: ResolvedDependency, feeds: list[SnapshotFeedResult]) -> AuditDecision:
        """
        Build a conflict decision that retains every feed's evidence.
        """

        evidence: list[FeedEvidence] = []
        results: list[VulnerabilityResult] = []
        for feed in feeds:
            for result in feed.active:
                evidence.append(
                    FeedEvidence(
                        source=feed.source,
                        source_version=feed.source_version,
                        result=result,
                    )
                )
                results.append(result)
            for result in feed.withdrawn:
                evidence.append(
                    FeedEvidence(
                        source=feed.source,
                        source_version=feed.source_version,
                        result=result,
                        withdrawn=True,
                    )
                )
                results.append(result)

        versions = ", ".join(sorted({feed.source_version for feed in feeds}))
        return AuditDecision(
            dependency=dep,
            verdict=AuditVerdict.CONFLICT,
            results=tuple(results),
            evidence=tuple(evidence),
            reason=f"feeds disagree across data-source versions: {versions}",
        )

    def check(self, dep: Dependency) -> AuditDecision:
        """
        Apply alias-aware approval checking to one dependency.

        Withdrawn advisories and temporarily unreachable feeds produce
        distinct verdicts rather than being silently dropped. When multiple
        feeds disagree on a shared advisory, both sides are retained.
        """

        if dep.is_skipped():
            skipped = cast(SkippedDependency, dep)
            return AuditDecision(
                dependency=skipped,
                verdict=AuditVerdict.UNAVAILABLE,
                reason=f"dependency was skipped: {skipped.skip_reason}",
            )

        resolved = cast(ResolvedDependency, dep)
        feeds, errors = self._collect_feeds(resolved)

        if not feeds:
            detail = "; ".join(str(error) for error in errors) or "all feeds unreachable"
            return AuditDecision(
                dependency=resolved,
                verdict=AuditVerdict.UNAVAILABLE,
                reason=detail,
            )

        if self._feeds_conflict(feeds):
            return self._conflict(resolved, feeds)

        if len(feeds) == 1:
            return self._decide_single_feed(resolved, feeds[0])

        merged_active: list[VulnerabilityResult] = []
        seen: set[str] = set()
        for feed in feeds:
            for result in feed.active:
                _add_unique_vulnerability(merged_active, seen, result)
        merged_feed = SnapshotFeedResult(
            source=",".join(service.source for service in self._services),
            source_version=",".join(service.source_version for service in self._services),
            active=tuple(merged_active),
            withdrawn=tuple(result for feed in feeds for result in feed.withdrawn),
        )
        return self._decide_single_feed(resolved, merged_feed)

    def audit(self, source: DependencySource) -> Iterator[tuple[Dependency, AuditDecision]]:
        """
        Check every dependency collected by `source`, yielding decisions.
        """

        for dep in source.collect():
            yield dep, self.check(dep)
