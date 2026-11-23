"""Security mitigation regressions for offline correlation and dashboard aggregation.

The on-call team folds several similar rules into a single security dashboard.
Two identity hazards are covered here:

* one asset triggering several similar rules must not be counted as multiple
  assets (duplicate counting), and
* two distinct assets sharing a hostname must not be merged into one entity
  (identity collision).

The aggregation under test is parameterized by the caller: entity identity,
count window and dedup boundary are supplied per invocation. An independent
oracle re-derives match ordering, alert folding and the final aggregation
directly from the raw synthetic asset events and cross-checks every scenario.
Matches without sufficient identity material are accounted for in a separate
quarantine bucket instead of being merged into a default entity.

The two ``test_counterexample_*`` tests are deterministic and can be re-run on
their own to reproduce each hazard, e.g.::

    pytest tests/test_matching_aggregation_security.py::test_counterexample_duplicate_counting_single_asset
    pytest tests/test_matching_aggregation_security.py::test_counterexample_hostname_collision_merges_distinct_assets
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Hashable, Mapping

import pytest

from sigma.collection import SigmaCollection
from sigma.matching import Event, EventLogSource, SigmaMatch, SigmaMatcher

BASE_TS = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
ASSET_LOGSOURCE = EventLogSource(category="process_creation", product="windows")

CORRELATION_RULE_NAME = "cred_access_burst"
CORRELATION_THRESHOLD = 2
CORRELATION_WINDOW = timedelta(minutes=10)

DASHBOARD_RULES_YAML = """
title: Credential Dumping Via Comsvcs
name: cred_dump_comsvcs
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "comsvcs.dll"
    condition: selection
---
title: LSASS Memory Access
name: lsass_memory_access
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "lsass.exe"
    condition: selection
---
title: Shadow Copy Abuse
name: shadow_copy_abuse
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "vssadmin"
    condition: selection
---
title: Correlated Credential Access Burst
name: cred_access_burst
status: test
correlation:
    type: event_count
    rules:
        - cred_dump_comsvcs
        - lsass_memory_access
        - shadow_copy_abuse
    group-by:
        - AssetId
    timespan: 10m
    condition:
        gte: 2
"""


def asset_event(
    minute: int,
    command_line: str,
    *,
    asset_id: str | None = None,
    hostname: str | None = None,
) -> Event:
    """Build one normal synthetic asset event; identity fields are optional."""
    data: dict[str, Any] = {"CommandLine": command_line}
    if asset_id is not None:
        data["AssetId"] = asset_id
    if hostname is not None:
        data["Hostname"] = hostname
    return Event(
        timestamp=BASE_TS + timedelta(minutes=minute),
        logsource=ASSET_LOGSOURCE,
        data=data,
    )


# Caller-supplied policy: entity identity, count window and dedup boundary.

EntityIdentity = tuple[str, str]
IdentifyFn = Callable[[Mapping[str, Any]], "EntityIdentity | None"]
DedupBoundaryFn = Callable[[EntityIdentity, str, datetime, timedelta], Hashable]


def identify_by_asset_id(material: Mapping[str, Any]) -> EntityIdentity | None:
    """Strong identity: only a stable asset id is sufficient identity material."""
    asset_id = material.get("AssetId")
    return ("asset_id", asset_id) if asset_id else None


def identify_by_hostname(material: Mapping[str, Any]) -> EntityIdentity | None:
    """Weak identity: hostname alone, known to collide across distinct assets."""
    hostname = material.get("Hostname")
    return ("hostname", hostname) if hostname else None


def windowed_dedup_boundary(
    identity: EntityIdentity,
    rule_name: str,
    timestamp: datetime,
    count_window: timedelta,
) -> Hashable:
    """Alerts fold together per entity, rule and count-window bucket."""
    bucket = int((timestamp - BASE_TS) // count_window)
    return (identity, rule_name, bucket)


@dataclass
class DashboardReport:
    """Result of folding correlated matches onto the shared dashboard."""

    match_order: list[str] = field(default_factory=list)
    folded_alerts: list[tuple[EntityIdentity, str]] = field(default_factory=list)
    entity_counts: dict[EntityIdentity, int] = field(default_factory=dict)
    quarantined_alerts: int = 0


def _match_identity_material(match: SigmaMatch) -> Mapping[str, Any]:
    if match.group_values:
        return match.group_values
    return match.events[0].data


def aggregate_dashboard(
    matches: list[SigmaMatch],
    *,
    identify: IdentifyFn,
    count_window: timedelta,
    dedup_boundary: DedupBoundaryFn,
) -> DashboardReport:
    """Fold matches into per-entity counts; quarantine matches without identity."""
    report = DashboardReport()
    seen: set[Hashable] = set()
    quarantine_seen: set[Hashable] = set()
    for match in matches:
        rule_name = match.rule.name
        report.match_order.append(rule_name)
        identity = identify(_match_identity_material(match))
        if identity is None:
            boundary = ("quarantine", rule_name, match.timestamp)
            if boundary not in quarantine_seen:
                quarantine_seen.add(boundary)
                report.quarantined_alerts += 1
            continue
        boundary = dedup_boundary(identity, rule_name, match.timestamp, count_window)
        if boundary in seen:
            continue
        seen.add(boundary)
        report.folded_alerts.append((identity, rule_name))
        report.entity_counts[identity] = report.entity_counts.get(identity, 0) + 1
    return report


# Independent oracle: re-derives everything from the raw events without using
# sigma.matching, so the aggregation above is checked against a second,
# deliberately simple implementation.

ORACLE_RULE_PREDICATES: tuple[tuple[str, Callable[[Mapping[str, Any]], bool]], ...] = (
    ("cred_dump_comsvcs", lambda data: "comsvcs.dll" in str(data.get("CommandLine", ""))),
    ("lsass_memory_access", lambda data: "lsass.exe" in str(data.get("CommandLine", ""))),
    ("shadow_copy_abuse", lambda data: "vssadmin" in str(data.get("CommandLine", ""))),
)


def oracle_dashboard(
    events: list[Event],
    *,
    identify: IdentifyFn,
    count_window: timedelta,
    dedup_boundary: DedupBoundaryFn,
) -> DashboardReport:
    """Brute-force oracle for match order, alert folding and final aggregation."""
    report = DashboardReport()
    windows: dict[Any, list[datetime]] = {}
    folded: dict[Hashable, tuple[EntityIdentity, str]] = {}
    quarantined: dict[Hashable, None] = {}

    for event in events:
        fired = [name for name, predicate in ORACLE_RULE_PREDICATES if predicate(event.data)]
        pending: list[tuple[Mapping[str, Any], str, datetime]] = [
            (event.data, name, event.timestamp) for name in fired
        ]
        if fired:
            group_key = event.data.get("AssetId")
            entries = windows.setdefault(group_key, [])
            for _ in fired:
                cutoff = event.timestamp - CORRELATION_WINDOW
                while entries and entries[0] < cutoff:
                    entries.pop(0)
                entries.append(event.timestamp)
                if len(entries) >= CORRELATION_THRESHOLD:
                    pending.append(({"AssetId": group_key}, CORRELATION_RULE_NAME, event.timestamp))
        for material, rule_name, timestamp in pending:
            report.match_order.append(rule_name)
            identity = identify(material)
            if identity is None:
                boundary = ("quarantine", rule_name, timestamp)
                if boundary not in quarantined:
                    quarantined[boundary] = None
                    report.quarantined_alerts += 1
                continue
            boundary = dedup_boundary(identity, rule_name, timestamp, count_window)
            if boundary not in folded:
                folded[boundary] = (identity, rule_name)

    report.folded_alerts = list(folded.values())
    for identity, _ in report.folded_alerts:
        report.entity_counts[identity] = report.entity_counts.get(identity, 0) + 1
    return report


def run_pipeline(
    events: list[Event],
    *,
    identify: IdentifyFn,
    count_window: timedelta,
    dedup_boundary: DedupBoundaryFn,
) -> DashboardReport:
    """Match events with pySigma and aggregate the matches for the dashboard."""
    collection = SigmaCollection.from_yaml(DASHBOARD_RULES_YAML)
    with SigmaMatcher(collection) as matcher:
        matches = matcher.bulk_match(events)
    return aggregate_dashboard(
        matches,
        identify=identify,
        count_window=count_window,
        dedup_boundary=dedup_boundary,
    )


@pytest.fixture
def strong_policy() -> dict[str, Any]:
    return {
        "identify": identify_by_asset_id,
        "count_window": timedelta(minutes=10),
        "dedup_boundary": windowed_dedup_boundary,
    }


def mixed_asset_events() -> list[Event]:
    return [
        asset_event(
            0, "rundll32.exe comsvcs.dll MiniDump", asset_id="asset-001", hostname="ws-fin-01"
        ),
        asset_event(1, "procdump.exe lsass.exe", asset_id="asset-001", hostname="ws-fin-01"),
        asset_event(2, "procdump.exe lsass.exe", asset_id="asset-002", hostname="ws-fin-01"),
        asset_event(3, "vssadmin delete shadows", asset_id="asset-001", hostname="ws-fin-01"),
        asset_event(4, "vssadmin delete shadows", hostname="ws-unknown"),
        asset_event(5, "rundll32.exe comsvcs.dll MiniDump"),
        asset_event(25, "procdump.exe lsass.exe", asset_id="asset-001", hostname="ws-fin-01"),
    ]


def test_dashboard_aggregation_matches_oracle(strong_policy):
    events = mixed_asset_events()
    report = run_pipeline(events, **strong_policy)
    expected = oracle_dashboard(events, **strong_policy)
    assert report == expected


def test_dashboard_match_order_and_folding(strong_policy):
    events = mixed_asset_events()
    report = run_pipeline(events, **strong_policy)

    assert report.match_order == [
        "cred_dump_comsvcs",
        "lsass_memory_access",
        CORRELATION_RULE_NAME,
        "lsass_memory_access",
        "shadow_copy_abuse",
        CORRELATION_RULE_NAME,
        "shadow_copy_abuse",
        "cred_dump_comsvcs",
        CORRELATION_RULE_NAME,
        "lsass_memory_access",
    ]
    asset_001 = ("asset_id", "asset-001")
    asset_002 = ("asset_id", "asset-002")
    assert report.entity_counts == {asset_001: 5, asset_002: 1}
    assert len(report.folded_alerts) == 6
    # The three identity-less matches fold into three quarantined alerts and
    # are never merged into a default entity.
    assert report.quarantined_alerts == 3
    assert all(identity is not None for identity, _ in report.folded_alerts)


def test_unattributed_matches_counted_separately(strong_policy):
    events = [
        asset_event(0, "vssadmin delete shadows", hostname="ws-unknown"),
        asset_event(1, "rundll32.exe comsvcs.dll MiniDump"),
    ]
    report = run_pipeline(events, **strong_policy)
    assert report.entity_counts == {}
    # Both base alerts plus the correlation alert fired on the shared
    # AssetId=None group land in the quarantine bucket.
    assert report.quarantined_alerts == 3
    assert report.match_order.count(CORRELATION_RULE_NAME) == 1


def test_counterexample_duplicate_counting_single_asset():
    """One asset triggering several similar rules is a single entity.

    Naively counting alerts as assets reports three "devices" here; the
    mitigated aggregation folds them into one entity. Re-runnable via::

        pytest tests/test_matching_aggregation_security.py::test_counterexample_duplicate_counting_single_asset
    """
    events = [
        asset_event(
            0, "rundll32.exe comsvcs.dll MiniDump", asset_id="asset-001", hostname="ws-fin-01"
        ),
        asset_event(1, "procdump.exe lsass.exe", asset_id="asset-001", hostname="ws-fin-01"),
        asset_event(2, "vssadmin delete shadows", asset_id="asset-001", hostname="ws-fin-01"),
    ]
    collection = SigmaCollection.from_yaml(DASHBOARD_RULES_YAML)
    with SigmaMatcher(collection) as matcher:
        matches = matcher.bulk_match(events)

    base_alerts = [m for m in matches if m.rule.name != CORRELATION_RULE_NAME]
    assert len(base_alerts) == 3  # naive per-alert counting: three "devices"
    assert any(m.rule.name == CORRELATION_RULE_NAME for m in matches)

    policy = {
        "identify": identify_by_asset_id,
        "count_window": timedelta(minutes=10),
        "dedup_boundary": windowed_dedup_boundary,
    }
    report = aggregate_dashboard(matches, **policy)
    oracle = oracle_dashboard(events, **policy)

    assert report == oracle
    assert list(report.entity_counts) == [("asset_id", "asset-001")]
    assert sum(report.entity_counts.values()) == len(report.folded_alerts)
    assert report.quarantined_alerts == 0


def test_counterexample_hostname_collision_merges_distinct_assets():
    """Two distinct assets sharing a hostname must stay two entities.

    Hostname-based identity merges both assets into one dashboard entity; the
    asset-id identity keeps them separate. Re-runnable via::

        pytest tests/test_matching_aggregation_security.py::test_counterexample_hostname_collision_merges_distinct_assets
    """
    events = [
        asset_event(0, "procdump.exe lsass.exe", asset_id="asset-001", hostname="ws-shared"),
        asset_event(1, "vssadmin delete shadows", asset_id="asset-002", hostname="ws-shared"),
    ]
    collection = SigmaCollection.from_yaml(DASHBOARD_RULES_YAML)
    with SigmaMatcher(collection) as matcher:
        matches = matcher.bulk_match(events)
    assert len(matches) == 2

    weak_report = aggregate_dashboard(
        matches,
        identify=identify_by_hostname,
        count_window=timedelta(minutes=10),
        dedup_boundary=windowed_dedup_boundary,
    )
    # The hazard: both distinct assets collapse into a single hostname entity.
    assert list(weak_report.entity_counts) == [("hostname", "ws-shared")]

    strong_policy = {
        "identify": identify_by_asset_id,
        "count_window": timedelta(minutes=10),
        "dedup_boundary": windowed_dedup_boundary,
    }
    strong_report = aggregate_dashboard(matches, **strong_policy)
    oracle = oracle_dashboard(events, **strong_policy)

    assert strong_report == oracle
    assert list(strong_report.entity_counts) == [
        ("asset_id", "asset-001"),
        ("asset_id", "asset-002"),
    ]
    assert strong_report.quarantined_alerts == 0
