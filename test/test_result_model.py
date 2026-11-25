from __future__ import annotations

import json

from packaging.version import Version

from pip_audit._audit import Auditor
from pip_audit._dependency_source.interface import DependencySource
from pip_audit._format.json import JsonFormat
from pip_audit._result import SnapshotStore
from pip_audit._service.interface import (
    ConnectionError,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._service.status import CacheFreshness, CacheStatus

FOO = ResolvedDependency(name="foo", version=Version("1.0.1"))
BAR = ResolvedDependency(name="bar", version=Version("2.0.0"))


class ListSource(DependencySource):
    def __init__(self, dependencies):
        self._dependencies = dependencies

    def collect(self):
        return iter(self._dependencies)

    def fix(self, _fix_version) -> None:
        return None


class GoodService(VulnerabilityService):
    source_name = "good"

    def __init__(self) -> None:
        self.cache_status = CacheStatus(
            source="good",
            freshness=CacheFreshness.FRESH,
            age_seconds=12,
            ttl_seconds=300,
            from_cache=True,
        )

    def query(self, spec):
        if spec.canonical_name == "foo":
            return spec, [
                VulnerabilityResult(
                    id="FAKE-2025-0001",
                    description="confirmed by the healthy fake source",
                    fix_versions=[Version("1.1.0")],
                    aliases={"CVE-FAKE-0001"},
                )
            ]
        return spec, []


class BadService(VulnerabilityService):
    source_name = "bad"

    def __init__(self) -> None:
        self.cache_status = CacheStatus(
            source="bad",
            freshness=CacheFreshness.STALE,
            age_seconds=3600,
            ttl_seconds=300,
            from_cache=True,
            detail="using stale cache metadata",
        )

    def query(self, spec):
        raise ConnectionError("fake bad source is unavailable")


class LaterBadService(BadService):
    source_name = "good"


def _auditor(store=None):
    return Auditor(
        services={
            "good": GoodService(),
            "bad": BadService(),
        },
        snapshot_store=store,
    )


def test_audit_report_separates_sources_cache_vulns_and_unqueried():
    report = _auditor().audit_report(ListSource([FOO, BAR]))

    assert {dep.canonical_name for dep in report} == {"foo", "bar"}
    foo_vulns = next(vulns for dep, vulns in report.items() if dep == FOO)
    assert [vuln.id for vuln in foo_vulns] == ["FAKE-2025-0001"]
    assert report[BAR] == []

    assert report.sources["good"].available is True
    assert report.sources["bad"].available is False
    assert "fake bad source is unavailable" in report.sources["bad"].error

    assert report.cache_statuses["good"].freshness is CacheFreshness.FRESH
    assert report.cache_statuses["bad"].freshness is CacheFreshness.STALE

    assert len(report.unqueried) == 2
    assert {(item.source, item.canonical_name) for item in report.unqueried} == {
        ("bad", "foo"),
        ("bad", "bar"),
    }
    assert report.incomplete is True

    output = json.loads(JsonFormat(True, True).format(report, []))
    assert output["sources"]["good"]["available"] is True
    assert output["sources"]["bad"]["availability"] == "unavailable"
    assert output["cache_freshness"]["good"]["freshness"] == "fresh"
    assert output["cache_freshness"]["bad"]["freshness"] == "stale"
    assert len(output["confirmed_vulnerabilities"]) == 1
    assert output["confirmed_vulnerabilities"][0]["name"] == "foo"
    assert output["confirmed_vulnerabilities"][0]["vulns"][0]["id"] == "FAKE-2025-0001"
    assert len(output["unqueried_objects"]) == 2
    assert {item["source"] for item in output["unqueried"]} == {"bad"}


def test_same_input_rerun_preserves_source_snapshot(tmp_path):
    snapshot_path = tmp_path / "source-snapshots.json"
    store = SnapshotStore(snapshot_path)
    source = ListSource([FOO, BAR])

    first = _auditor(store).audit_report(source)
    first_ids = {name: snap.snapshot_id for name, snap in first.sources.items()}
    first_seen = {name: snap.first_observed_at for name, snap in first.sources.items()}

    second = _auditor(SnapshotStore(snapshot_path)).audit_report(source)
    second_ids = {name: snap.snapshot_id for name, snap in second.sources.items()}
    second_seen = {name: snap.first_observed_at for name, snap in second.sources.items()}

    assert second.input_digest == first.input_digest
    assert second_ids == first_ids
    assert second_seen == first_seen

    persisted = json.loads(snapshot_path.read_text())
    assert set(persisted["inputs"]) == {first.input_digest}
    stored_sources = persisted["inputs"][first.input_digest]["sources"]
    assert stored_sources["good"]["snapshot_id"] == first_ids["good"]
    assert stored_sources["bad"]["first_observed_at"] == first_seen["bad"].isoformat()


def test_rerun_retains_last_known_good_snapshot(tmp_path):
    snapshot_path = tmp_path / "source-snapshots.json"
    source = ListSource([FOO])

    first = Auditor(
        services={"good": GoodService(), "bad": BadService()},
        snapshot_store=SnapshotStore(snapshot_path),
    ).audit_report(source)
    assert first.sources["good"].available is True

    second = Auditor(
        services={"good": LaterBadService(), "bad": BadService()},
        snapshot_store=SnapshotStore(snapshot_path),
    ).audit_report(source)

    good = second.sources["good"]
    assert good.available is False
    assert good.snapshot_id == first.sources["good"].snapshot_id
    assert good.last_known_good is not None
    assert good.last_known_good.available is True
    assert good.last_known_good.cache is not None
    assert good.last_known_good.cache.freshness is CacheFreshness.FRESH

    output = json.loads(JsonFormat(False, False).format(second, []))
    assert output["sources"]["good"]["last_known_good"]["available"] is True
    assert len(output["unqueried"]) == 2
