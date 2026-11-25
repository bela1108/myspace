from __future__ import annotations

import pytest
from packaging.version import Version

import pip_audit._service as service

SNAPSHOT_V1 = "offline/snapshot-v1.json"
SNAPSHOT_V2 = "offline/snapshot-v2.json"
SNAPSHOT_CONFLICT = "offline/snapshot-conflict.json"


@pytest.fixture
def v1_snapshot(asset):
    return service.AdvisorySnapshot.from_json(asset(SNAPSHOT_V1))


@pytest.fixture
def v2_snapshot(asset):
    return service.AdvisorySnapshot.from_json(asset(SNAPSHOT_V2))


@pytest.fixture
def conflict_snapshot(asset):
    return service.AdvisorySnapshot.from_json(asset(SNAPSHOT_CONFLICT))


def test_snapshot_carries_data_source_version(v1_snapshot, v2_snapshot):
    assert v1_snapshot.source == "osv-offline"
    assert v1_snapshot.version == "2026-10-01"
    assert v2_snapshot.version == "2026-11-01"


def test_snapshot_lookup_returns_active_and_withdrawn(v2_snapshot):
    dep = service.ResolvedDependency("foo", Version("1.0.1"))
    feed = v2_snapshot.lookup(dep)

    assert feed.source_version == "2026-11-01"
    assert feed.active == ()
    assert len(feed.withdrawn) == 1
    assert feed.withdrawn[0].id == "CVE-2026-0002"


def test_snapshot_lookup_split_advisory(v2_snapshot):
    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    feed = v2_snapshot.lookup(dep)
    ids = {result.id for result in feed.active}

    assert ids == {"CVE-2026-0001", "GHSA-aaaa-1111-bbbb"}
    cve = next(result for result in feed.active if result.id == "CVE-2026-0001")
    ghsa = next(result for result in feed.active if result.id == "GHSA-aaaa-1111-bbbb")
    # The two records are no longer aliases of one another.
    assert "GHSA-aaaa-1111-bbbb" not in cve.aliases
    assert "CVE-2026-0001" not in ghsa.aliases


def test_snapshot_lookup_unavailable(v2_snapshot):
    dep = service.ResolvedDependency("foo", Version("2.0.0"))
    feed = v2_snapshot.lookup(dep)

    assert feed.unavailable is True


def test_offline_service_query_filters_withdrawn(v2_snapshot):
    offline = service.OfflineSnapshotService(v2_snapshot)
    dep = service.ResolvedDependency("foo", Version("1.0.1"))

    _, results = offline.query(dep)
    assert results == []


def test_offline_service_query_raises_connection_error(v2_snapshot):
    offline = service.OfflineSnapshotService(v2_snapshot)
    dep = service.ResolvedDependency("foo", Version("2.0.0"))

    with pytest.raises(service.ConnectionError):
        offline.query(dep)


def test_offline_service_query_snapshot_exposes_version(v1_snapshot):
    offline = service.OfflineSnapshotService(v1_snapshot)
    dep = service.ResolvedDependency("foo", Version("1.0.0"))

    feed = offline.query_snapshot(dep)
    assert feed.source == "osv-offline"
    assert feed.source_version == "2026-10-01"
    assert len(feed.active) == 1
