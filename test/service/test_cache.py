from datetime import datetime, timedelta

import pytest
from packaging.version import Version

from pip_audit._service import (
    AdvisoryCache,
    AdvisorySnapshot,
    CachedVulnerabilityService,
    ConnectionError,
    RefreshStatus,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)

_T0 = datetime(2026, 11, 21, 12, 0, 0)
_MAX_AGE = timedelta(hours=1)


class FakeClock:
    def __init__(self, now=_T0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


class StubService(VulnerabilityService):
    """A scripted service: pops one queued outcome per query, never touches the network."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.queries = []

    def query(self, spec):
        self.queries.append(spec)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return spec, outcome


def _vuln(vuln_id="fake-id"):
    return VulnerabilityResult(
        id=vuln_id,
        description="this is not a real result",
        aliases=set(),
        fix_versions=[Version("1.1.0")],
    )


def _spec(version="1.0.1"):
    return ResolvedDependency(name="foo", version=Version(version))


def _service(outcomes, clock, cache=None):
    inner = StubService(outcomes)
    wrapper = CachedVulnerabilityService(
        inner, source="stub-source", cache=cache, clock=clock, max_age=_MAX_AGE
    )
    return wrapper, inner


def test_snapshot_records_scope_source_and_update_time():
    clock = FakeClock()
    service, _ = _service([[_vuln()]], clock)

    dep, snapshot = service.query_snapshot(_spec())

    assert dep == _spec()
    assert snapshot.status is RefreshStatus.POSITIVE
    assert snapshot.scope == "foo==1.0.1"
    assert snapshot.source == "stub-source"
    assert snapshot.updated_at == _T0
    assert snapshot.results == (_vuln(),)
    assert not snapshot.clears_prior_alerts


def test_fresh_negative_is_clear_eligible():
    clock = FakeClock()
    service, _ = _service([[]], clock)

    _, snapshot = service.query_snapshot(_spec())

    assert snapshot.status is RefreshStatus.NEGATIVE
    assert snapshot.results == ()
    assert snapshot.clears_prior_alerts


def test_unexpired_snapshot_served_without_refresh():
    clock = FakeClock()
    service, inner = _service([[_vuln()]], clock)

    service.query_snapshot(_spec())
    clock.advance(_MAX_AGE - timedelta(seconds=1))
    _, snapshot = service.query_snapshot(_spec())

    # The second query never reached the inner service.
    assert len(inner.queries) == 1
    assert snapshot.status is RefreshStatus.POSITIVE


def test_expired_snapshot_refresh_failure_serves_stale():
    clock = FakeClock()
    service, _ = _service([[_vuln()], ConnectionError("offline")], clock)

    service.query_snapshot(_spec())
    clock.advance(_MAX_AGE)
    _, snapshot = service.query_snapshot(_spec())

    assert snapshot.status is RefreshStatus.STALE
    assert snapshot.results == (_vuln(),)
    # The stale snapshot keeps the last successful refresh time.
    assert snapshot.updated_at == _T0
    assert not snapshot.clears_prior_alerts


def test_refresh_failure_without_cache_propagates():
    clock = FakeClock()
    service, _ = _service([ConnectionError("offline")], clock)

    with pytest.raises(ConnectionError):
        service.query_snapshot(_spec())

    # The failure is still booked in the error ledger.
    assert len(service.cache.errors) == 1


def test_errors_and_negatives_use_separate_bookkeeping():
    clock = FakeClock()
    cache = AdvisoryCache()
    service, _ = _service([[], ConnectionError("offline")], clock, cache=cache)

    # A negative refresh overwrites the snapshot store, not the error ledger.
    _, snapshot = service.query_snapshot(_spec())
    assert snapshot.status is RefreshStatus.NEGATIVE
    assert cache.errors == []
    assert cache.get("stub-source", "foo==1.0.1") == snapshot

    # A failed refresh appends to the error ledger, leaving the snapshot intact.
    clock.advance(_MAX_AGE)
    _, stale = service.query_snapshot(_spec())
    assert stale.status is RefreshStatus.STALE
    assert cache.get("stub-source", "foo==1.0.1") == snapshot

    (error,) = cache.errors
    assert error.scope == "foo==1.0.1"
    assert error.source == "stub-source"
    assert error.failed_at == _T0 + _MAX_AGE
    assert "offline" in error.reason


def test_expiry_old_positive_new_empty_chain():
    """
    The reconnection scenario: an expired positive snapshot is refreshed with
    an authoritative empty response, which is the only step that may clear
    the previously published alert; a later refresh failure must not.
    """
    clock = FakeClock()
    service, _ = _service(
        [[_vuln()], [], ConnectionError("offline")],
        clock,
    )

    # Step 1: initial scan publishes a positive result.
    _, first = service.query_snapshot(_spec())
    assert first.status is RefreshStatus.POSITIVE
    published_alerts = list(first.results)
    assert published_alerts

    # Step 2: the cache expires, the service reconnects, and the advisory is
    # gone: the fresh negative result is eligible to clear the old alert.
    clock.advance(_MAX_AGE)
    _, second = service.query_snapshot(_spec())
    assert second.status is RefreshStatus.NEGATIVE
    assert second.clears_prior_alerts
    if second.clears_prior_alerts:
        published_alerts = list(second.results)
    assert published_alerts == []

    # Step 3: the cache expires again and the refresh fails: the stale
    # snapshot is not eligible to clear anything.
    clock.advance(_MAX_AGE)
    _, third = service.query_snapshot(_spec())
    assert third.status is RefreshStatus.STALE
    assert not third.clears_prior_alerts
    if third.clears_prior_alerts:  # pragma: no cover
        published_alerts = list(third.results)
    assert published_alerts == []


def test_skipped_dependency_bypasses_cache():
    clock = FakeClock()
    service, inner = _service([[]], clock)
    skipped = SkippedDependency(name="foo", skip_reason="unit test")

    dep, snapshot = service.query_snapshot(skipped)

    assert dep is skipped
    assert snapshot is None
    assert len(inner.queries) == 1
    assert service.cache.get("stub-source", "foo") is None


def test_query_matches_plain_service_contract():
    clock = FakeClock()
    service, _ = _service([[_vuln()]], clock)

    dep, vulns = service.query(_spec())

    assert dep == _spec()
    assert vulns == [_vuln()]


def test_query_all_snapshots():
    clock = FakeClock()
    service, _ = _service([[_vuln()], []], clock)

    results = list(service.query_all_snapshots(iter([_spec("1.0.1"), _spec("1.0.2")])))

    assert [snapshot.status for _, snapshot in results] == [
        RefreshStatus.POSITIVE,
        RefreshStatus.NEGATIVE,
    ]


def test_default_source_identity_is_inner_class_name():
    clock = FakeClock()
    inner = StubService([[]])
    service = CachedVulnerabilityService(inner, clock=clock, max_age=_MAX_AGE)

    _, snapshot = service.query_snapshot(_spec())

    assert snapshot.source == "StubService"


def test_snapshot_is_expired_boundary():
    snapshot = AdvisorySnapshot(
        scope="foo==1.0.1",
        source="stub-source",
        updated_at=_T0,
        status=RefreshStatus.POSITIVE,
        results=(_vuln(),),
    )

    assert not snapshot.is_expired(_T0 + _MAX_AGE - timedelta(seconds=1), _MAX_AGE)
    assert snapshot.is_expired(_T0 + _MAX_AGE, _MAX_AGE)
