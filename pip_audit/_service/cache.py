"""
Local snapshot caching for vulnerability service queries.

This module provides a caching wrapper around `VulnerabilityService` for
deployments that publish audit results offline: responses from the advisory
source are stored as snapshots, keyed by their scope (the resolved package)
and source identity, and stamped with the time of their last successful
refresh.

The wrapper distinguishes refresh failures from authoritative negative
("no advisories") responses: a failed refresh is recorded in a separate
error ledger and causes the previously cached snapshot to be served as
`RefreshStatus.STALE`, while a successful but empty response overwrites
the snapshot as `RefreshStatus.NEGATIVE`. Only the latter is eligible to
clear previously published alerts.
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import cast

from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    VulnerabilityResult,
    VulnerabilityService,
)

Clock = Callable[[], datetime]
"""
A source of "now", injectable into `CachedVulnerabilityService` so that
cache expiry and snapshot timestamps can be tested without real time.
"""


class RefreshStatus(enum.Enum):
    """
    Describes how the contents of an `AdvisorySnapshot` were obtained.
    """

    POSITIVE = "positive"
    """
    The snapshot comes from a successful refresh that returned advisories.
    """

    NEGATIVE = "negative"
    """
    The snapshot comes from a successful refresh that authoritatively
    returned no advisories for the scope.
    """

    STALE = "stale"
    """
    The snapshot comes from the local cache because the last refresh
    attempt failed; its contents may no longer reflect the source.
    """


@dataclass(frozen=True)
class AdvisorySnapshot:
    """
    A cached record of a single advisory source query.
    """

    scope: str
    """
    The scope the snapshot is authoritative for, e.g. `foo==1.0.0`.
    """

    source: str
    """
    The identity of the advisory source that produced the snapshot.
    """

    updated_at: datetime
    """
    When the snapshot's contents were last successfully refreshed,
    according to the injected `Clock`.
    """

    status: RefreshStatus
    """
    How the snapshot's contents were obtained.
    """

    results: tuple[VulnerabilityResult, ...]
    """
    The advisories known for the scope at `updated_at`.
    """

    def is_expired(self, now: datetime, max_age: timedelta) -> bool:
        """
        Returns whether the snapshot is older than `max_age` at `now`.
        """
        return now - self.updated_at >= max_age

    @property
    def clears_prior_alerts(self) -> bool:
        """
        Returns whether this snapshot entitles the publishing side to clear
        previously published alerts for the scope.

        Only a fresh, authoritative negative result qualifies; stale data
        served after a refresh failure must never clear old alerts.
        """
        return self.status is RefreshStatus.NEGATIVE

    def as_stale(self) -> AdvisorySnapshot:
        """
        Returns a copy of this snapshot marked `RefreshStatus.STALE`,
        preserving the original `updated_at` so that consumers can still
        tell how old the underlying data is.
        """
        return replace(self, status=RefreshStatus.STALE)


@dataclass(frozen=True)
class RefreshError:
    """
    A ledger entry recording a failed refresh attempt.

    Errors are booked separately from snapshots: a failed refresh never
    modifies the snapshot store.
    """

    scope: str
    """
    The scope whose refresh failed.
    """

    source: str
    """
    The identity of the advisory source that failed.
    """

    failed_at: datetime
    """
    When the refresh failed, according to the injected `Clock`.
    """

    reason: str
    """
    A human-readable description of the failure.
    """


class AdvisoryCache:
    """
    An in-memory store of `AdvisorySnapshot` records, keyed by
    `(source, scope)`, plus a separate ledger of `RefreshError` records.
    """

    def __init__(self) -> None:
        """
        Create a new, empty `AdvisoryCache`.
        """
        self._snapshots: dict[tuple[str, str], AdvisorySnapshot] = {}
        self._errors: list[RefreshError] = []

    def get(self, source: str, scope: str) -> AdvisorySnapshot | None:
        """
        Returns the snapshot stored for `(source, scope)`, if any.
        """
        return self._snapshots.get((source, scope))

    def store(self, snapshot: AdvisorySnapshot) -> None:
        """
        Stores `snapshot`, replacing any prior snapshot for its
        `(source, scope)`.
        """
        self._snapshots[(snapshot.source, snapshot.scope)] = snapshot

    def record_error(self, error: RefreshError) -> None:
        """
        Appends `error` to the error ledger, leaving all snapshots untouched.
        """
        self._errors.append(error)

    @property
    def errors(self) -> list[RefreshError]:
        """
        The ledger of refresh failures recorded so far.
        """
        return list(self._errors)


def _scope_of(spec: ResolvedDependency) -> str:
    return f"{spec.canonical_name}=={spec.version}"


class CachedVulnerabilityService(VulnerabilityService):
    """
    A `VulnerabilityService` wrapper that caches query results as
    `AdvisorySnapshot` records in an `AdvisoryCache`.

    While a snapshot is younger than `max_age`, queries are served from
    the cache without contacting the inner service. Once a snapshot
    expires, the next query attempts a refresh: a successful response
    (empty or not) replaces the snapshot, while a `ServiceError` is
    recorded in the cache's error ledger and the expired snapshot is
    served as `RefreshStatus.STALE`.
    """

    def __init__(
        self,
        inner: VulnerabilityService,
        *,
        source: str | None = None,
        cache: AdvisoryCache | None = None,
        clock: Clock = datetime.now,
        max_age: timedelta = timedelta(hours=1),
    ) -> None:
        """
        Create a new `CachedVulnerabilityService` wrapping `inner`.

        `source` identifies the advisory source in snapshots and error
        records; it defaults to the inner service's class name.

        `cache` is the snapshot store to use; a fresh `AdvisoryCache` is
        created if none is given.

        `clock` supplies the current time for snapshot timestamps and
        expiry decisions.

        `max_age` is how long a snapshot remains in effect before a
        refresh is attempted.
        """
        self._inner = inner
        self._source = source if source is not None else type(inner).__name__
        self._cache = cache if cache is not None else AdvisoryCache()
        self._clock = clock
        self._max_age = max_age

    @property
    def cache(self) -> AdvisoryCache:
        """
        The underlying snapshot store and error ledger.
        """
        return self._cache

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Queries the service for the given `Dependency` specification,
        serving cached results when they are still in effect.

        See `VulnerabilityService.query`.
        """
        dep, snapshot = self.query_snapshot(spec)
        if snapshot is None:
            return dep, []
        return dep, list(snapshot.results)

    def query_snapshot(self, spec: Dependency) -> tuple[Dependency, AdvisorySnapshot | None]:
        """
        Like `query`, but returns the `AdvisorySnapshot` behind the result
        so that callers can inspect its status, scope, source, and update
        time (and, in particular, whether it may clear prior alerts).

        Skipped dependencies are passed through without caching and yield
        a `None` snapshot.
        """
        if spec.is_skipped():
            return self._inner.query(spec)[0], None

        resolved = cast(ResolvedDependency, spec)
        scope = _scope_of(resolved)
        now = self._clock()

        cached = self._cache.get(self._source, scope)
        if cached is not None and not cached.is_expired(now, self._max_age):
            return resolved, cached

        try:
            dep, results = self._inner.query(resolved)
        except ServiceError as error:
            self._cache.record_error(
                RefreshError(
                    scope=scope,
                    source=self._source,
                    failed_at=now,
                    reason=str(error),
                )
            )
            if cached is None:
                raise
            return resolved, cached.as_stale()

        status = RefreshStatus.POSITIVE if results else RefreshStatus.NEGATIVE
        snapshot = AdvisorySnapshot(
            scope=scope,
            source=self._source,
            updated_at=now,
            status=status,
            results=tuple(results),
        )
        self._cache.store(snapshot)
        return dep, snapshot

    def query_all_snapshots(
        self, specs: Iterator[Dependency]
    ) -> Iterator[tuple[Dependency, AdvisorySnapshot | None]]:
        """
        Snapshot-returning variant of `VulnerabilityService.query_all`.
        """
        for spec in specs:
            yield self.query_snapshot(spec)
