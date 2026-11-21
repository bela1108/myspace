"""Replayable semantic tests for the in-memory correlation reference backend."""

from datetime import datetime, timedelta, timezone

import pytest

from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.matching import (
    Event,
    EventLogSource,
    GroupKeySkipReason,
    SemanticReferenceBackend,
    SemanticReferenceError,
    SigmaMatcher,
)

BASE_TIME = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
LOGSOURCE = EventLogSource(category="test", product="test")


def event(offset: int, event_name: str, **data: object) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=offset),
        logsource=LOGSOURCE,
        data={"event": event_name, **data},
    )


CROSS_WINDOW_RULES = """
title: Failed Login
name: failed_login
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: failed_login
    condition: selection
---
title: Successful Login
name: successful_login
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: successful_login
    condition: selection
---
title: Login Burst
name: login_burst
status: test
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - host
    timespan: 1m
    condition:
        gte: 3
---
title: Failed Then Success
name: failed_then_success
status: test
correlation:
    type: temporal_ordered
    rules:
        - failed_login
        - successful_login
    group-by:
        - host
    timespan: 1m
"""


SHARED_EVENT_RULES = """
title: Rule A
name: rule_a
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event:
            - shared
            - only_a
    condition: selection
---
title: Rule B
name: rule_b
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event:
            - shared
            - only_b
    condition: selection
---
title: Shared Event Count
name: shared_event_count
status: test
correlation:
    type: event_count
    rules:
        - rule_a
        - rule_b
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 2
---
title: Shared Ordered Sequence
name: shared_ordered_sequence
status: test
correlation:
    type: temporal_ordered
    rules:
        - rule_a
        - rule_b
    group-by:
        - host
    timespan: 5m
"""


def test_cross_window_boundary_expiry_and_missing_group_are_observable():
    backend = SemanticReferenceBackend.from_yaml(CROSS_WINDOW_RULES)
    boundary = event(60, "failed_login", host="a")
    missing_group = event(61, "failed_login")
    in_window = event(90, "failed_login", host="a")
    expired = event(121, "failed_login", host="a")
    boundary_temporal = event(200, "failed_login", host="c")
    boundary_success = event(260, "successful_login", host="c")
    tied_failure = event(300, "failed_login", host="d")
    tied_success = event(300, "successful_login", host="d")
    later_success = event(301, "successful_login", host="d")

    events = [
        event(0, "failed_login", host="a"),
        event(30, "failed_login", host="a"),
        boundary,
        missing_group,
        in_window,
        expired,
        boundary_temporal,
        boundary_success,
        tied_failure,
        tied_success,
        later_success,
    ]
    for item in events[:6]:
        backend.push(item)
    window_report = backend.report()
    for item in events[6:]:
        backend.push(item)
    report = backend.report()

    burst_hits = [hit for hit in window_report.hits if hit.rule.name == "login_burst"]
    assert [hit.count for hit in burst_hits] == [3, 3]
    assert burst_hits[0].evidence[-1].event is boundary
    assert burst_hits[1].evidence[0].event is events[1]
    assert burst_hits[0].window_start == events[0].timestamp
    assert burst_hits[1].window_start == events[1].timestamp

    group_a = next(
        count
        for count in window_report.group_counts
        if count.rule.name == "login_burst" and count.group_key == ("a",)
    )
    assert group_a.count == 2
    assert [evidence.event for evidence in group_a.evidence] == [in_window, expired]
    assert [evidence.sequence for evidence in group_a.evidence] == [4, 5]
    assert group_a.timestamp == expired.timestamp
    assert group_a.window_start == missing_group.timestamp
    final_group_a = next(
        count
        for count in report.group_counts
        if count.rule.name == "login_burst" and count.group_key == ("a",)
    )
    assert final_group_a.count == 0
    assert final_group_a.evidence == ()

    skipped = [
        item
        for item in report.skipped
        if item.rule.name == "login_burst" and item.event is missing_group
    ]
    assert len(skipped) == 1
    assert skipped[0].reason == GroupKeySkipReason.MISSING_FIELD
    assert skipped[0].missing_fields == ("host",)

    ordered_hits = [hit for hit in report.hits if hit.rule.name == "failed_then_success"]
    group_c_hit = next(hit for hit in ordered_hits if hit.group_key == ("c",))
    assert group_c_hit.timestamp == boundary_success.timestamp
    assert group_c_hit.window_start == boundary_temporal.timestamp
    assert [evidence.event for evidence in group_c_hit.evidence] == [
        boundary_temporal,
        boundary_success,
    ]

    assert all(
        not (hit.group_key == ("d",) and hit.timestamp == tied_success.timestamp)
        for hit in ordered_hits
    )
    group_d_hit = next(hit for hit in ordered_hits if hit.group_key == ("d",))
    assert group_d_hit.timestamp == later_success.timestamp
    assert [evidence.event for evidence in group_d_hit.evidence] == [
        tied_failure,
        later_success,
    ]


def test_shared_event_counts_once_and_hits_keep_exact_source_events():
    backend = SemanticReferenceBackend.from_yaml(SHARED_EVENT_RULES)
    shared = event(0, "shared", host="h")
    only_a = event(10, "only_a", host="h")
    only_b = event(20, "only_b", host="h")

    report = backend.evaluate([shared, only_a, only_b])

    count_hits = [hit for hit in report.hits if hit.rule.name == "shared_event_count"]
    assert [hit.count for hit in count_hits] == [2, 3]
    assert len(report.base_matches) == 4

    first_shared_evidence = count_hits[0].evidence[0]
    assert first_shared_evidence.event is shared
    assert first_shared_evidence.source_rules == ("rule_a", "rule_b")
    assert [evidence.sequence for evidence in count_hits[0].evidence] == [0, 1]

    final_count = next(
        count for count in report.group_counts if count.rule.name == "shared_event_count"
    )
    assert final_count.count == 3
    assert [evidence.event for evidence in final_count.evidence] == [
        shared,
        only_a,
        only_b,
    ]

    ordered_hits = [hit for hit in report.hits if hit.rule.name == "shared_ordered_sequence"]
    assert len(ordered_hits) == 1
    assert [evidence.event for evidence in ordered_hits[0].evidence] == [
        shared,
        only_b,
    ]
    assert [evidence.source_rules for evidence in ordered_hits[0].evidence] == [
        ("rule_a",),
        ("rule_b",),
    ]


def test_unsupported_correlation_operations_are_marked_not_silently_ignored():
    collection = """
title: Base
name: base
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: test
    condition: selection
---
title: Value Count
name: value_count_rule
status: test
correlation:
    type: value_count
    rules:
        - base
    group-by:
        - host
    timespan: 1m
    condition:
        gte: 2
        field: user
"""
    backend = SemanticReferenceBackend.from_yaml(collection)
    report = backend.evaluate([event(0, "test", host="h", user="alice")])

    assert [operation.operation for operation in report.unsupported] == ["correlation.type"]
    assert report.unsupported[0].rule_name == "value_count_rule"
    assert not any(hit.rule.name == "value_count_rule" for hit in report.hits)
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="correlation.type"):
        report.assert_supported()


def test_out_of_order_input_fails_instead_of_changing_window_counts():
    backend = SemanticReferenceBackend.from_yaml(CROSS_WINDOW_RULES)
    backend.push(event(10, "failed_login", host="a"))

    with pytest.raises(SemanticReferenceError, match="out of order"):
        backend.push(event(9, "failed_login", host="a"))


def test_same_timestamp_events_count_but_never_satisfy_ordering():
    backend = SemanticReferenceBackend.from_yaml(CROSS_WINDOW_RULES)
    tied = [
        event(400, "failed_login", host="e"),
        event(400, "failed_login", host="e"),
        event(400, "failed_login", host="e"),
    ]
    same_time_success = event(500, "successful_login", host="e")

    report = backend.evaluate([*tied, event(500, "failed_login", host="e"), same_time_success])

    burst_hits = [
        hit for hit in report.hits if hit.rule.name == "login_burst" and hit.group_key == ("e",)
    ]
    assert [hit.count for hit in burst_hits] == [3]
    assert [evidence.event for evidence in burst_hits[0].evidence] == tied
    assert not any(
        hit.rule.name == "failed_then_success" and hit.group_key == ("e",) for hit in report.hits
    )


def test_reference_dedup_differs_from_one_match_per_rule_legacy_counting():
    """Keep this as the migration baseline for shared-event semantic drift."""

    collection = SemanticReferenceBackend.from_yaml(SHARED_EVENT_RULES).collection
    events = [
        event(0, "shared", host="h"),
        event(10, "only_a", host="h"),
    ]

    with SigmaMatcher(collection) as legacy:
        legacy_hits = []
        for item in events:
            legacy_hits.extend(
                match for match in legacy.match(item) if match.rule.name == "shared_event_count"
            )

    reference_hits = [
        hit
        for hit in SemanticReferenceBackend(collection).evaluate(events).hits
        if hit.rule.name == "shared_event_count"
    ]

    assert len(legacy_hits[-1].events) == 3
    assert reference_hits[-1].count == 2
