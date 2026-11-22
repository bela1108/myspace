"""Tests for offline change attribution and queue replay."""

import json
from datetime import datetime
from datetime import timezone
from pathlib import Path

import pytest
import yaml

from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.matching import (
    Event,
    EventLogSource,
    QueueKind,
    ReplayStatus,
    RoutingDecision,
    RoutingPolicy,
    RuleChange,
    analyze_changes,
    attribute_changes,
    compare_replay,
    notified_queues,
)

PAIR_RULES = """
title: Redundant High A
name: redundant_high_a
level: high
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
    condition: selection
---
title: Redundant High B
name: redundant_high_b
level: high
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
    condition: selection
"""


SINGLE_LOSS_RULES = """
title: Alert A
name: alert_a
level: high
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "alpha"
    condition: selection
---
title: Alert B
name: alert_b
level: high
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "bravo"
    condition: selection
"""


SINGLE_HIGH_RULE = PAIR_RULES.split("---", maxsplit=1)[0]


def event(command_line: str, second: int = 0) -> Event:
    return Event(
        timestamp=datetime(2026, 11, 22, 10, 0, second, tzinfo=timezone.utc),
        logsource=EventLogSource(category="process_creation", product="windows"),
        data={"CommandLine": command_line},
    )


@pytest.fixture
def routing() -> RoutingPolicy:
    return RoutingPolicy(
        [
            RoutingDecision("phone", min_level="high"),
            RoutingDecision("ticket", min_level="informational", kind=QueueKind.TICKET),
        ]
    )


def test_level_downgrade_loses_phone_but_keeps_ticket(routing):
    collection = SigmaCollection.from_yaml(SINGLE_HIGH_RULE)
    report = attribute_changes(
        collection,
        [event("mimikatz.exe")],
        [RuleChange.level_changed("redundant_high_a", "medium", label="downgrade-a")],
        routing,
    )

    assert len(report.losses) == 1
    loss = report.losses[0]
    assert loss.queue == "phone"
    assert loss.queue_kind == QueueKind.NOTIFICATION
    assert loss.alert_lost is False
    assert loss.scope.value == "queue"
    assert loss.minimal_causes == (("downgrade-a",),)

    result = report.candidate.results[0]
    assert result.status == ReplayStatus.NOTIFICATION_LOST
    assert result.alert_lost is False
    assert result.candidate_queues == frozenset({"ticket"})


def test_two_changes_only_lose_phone_when_combined(routing):
    collection = SigmaCollection.from_yaml(PAIR_RULES)
    changes = [
        RuleChange.level_changed("redundant_high_a", "medium", label="downgrade-a"),
        RuleChange.archived("redundant_high_b", label="archive-b"),
    ]
    report = attribute_changes(collection, [event("mimikatz.exe")], changes, routing)

    for replay in report.single_changes.values():
        assert replay.results[0].lost_queues == frozenset()

    assert len(report.losses) == 1
    loss = report.losses[0]
    assert loss.queue == "phone"
    assert loss.requires_combination is True
    assert loss.minimal_causes == (("downgrade-a", "archive-b"),)

    assert len(report.minimal_combinations) == 1
    combination = report.minimal_combinations[0]
    assert combination.queue == "phone"
    assert combination.change_ids == ("downgrade-a", "archive-b")
    assert combination.requires_combination is True
    assert combination.baseline_queues == frozenset({"phone", "ticket"})
    assert combination.candidate_queues == frozenset({"ticket"})

    assert report.candidate.results[0].status == ReplayStatus.NOTIFICATION_LOST
    assert report.candidate.results[0].alert_lost is False
    assert report.alert_loss_events == ()
    assert len(report.partial_losses) == 1


def test_single_change_alert_loss_is_not_reported_as_combination(routing):
    collection = SigmaCollection.from_yaml(SINGLE_LOSS_RULES)
    changes = [
        RuleChange.archived("alert_a", label="archive-a"),
        RuleChange.conversion_unsupported("alert_b", label="no-conversion-b"),
    ]
    events = [event("alpha.exe"), event("bravo.exe", second=1)]
    report = attribute_changes(collection, events, changes, routing)

    assert len(report.losses) == 4
    assert all(loss.alert_lost for loss in report.losses)
    assert all(loss.scope.value == "alert" for loss in report.losses)
    assert all(loss.minimal_causes and len(loss.minimal_causes[0]) == 1 for loss in report.losses)
    assert all(not loss.requires_combination for loss in report.losses)

    assert len(report.minimal_combinations) == 2
    assert all(combo.alert_lost for combo in report.minimal_combinations)
    assert all(combo.size == 1 for combo in report.minimal_combinations)

    assert len(report.single_changes["archive-a"].alert_losses) == 1
    assert len(report.single_changes["no-conversion-b"].alert_losses) == 1


def test_combination_search_honors_limit(routing):
    collection = SigmaCollection.from_yaml(PAIR_RULES)
    changes = [
        RuleChange.level_changed("redundant_high_a", "medium", label="downgrade-a"),
        RuleChange.archived("redundant_high_b", label="archive-b"),
    ]
    report = attribute_changes(
        collection,
        [event("mimikatz.exe")],
        changes,
        routing,
        max_combination_size=1,
    )

    assert len(report.losses) == 1
    assert report.losses[0].unexplained is True
    assert report.minimal_combinations == ()


def test_compare_replay_accepts_explicit_candidate_collection(routing):
    baseline = SigmaCollection.from_yaml(SINGLE_HIGH_RULE)
    candidate_yaml = SINGLE_HIGH_RULE.replace(
        "name: redundant_high_a\nlevel: high",
        "name: redundant_high_a\nlevel: medium",
    )
    candidate = SigmaCollection.from_yaml(candidate_yaml)

    comparison = compare_replay(
        baseline,
        candidate,
        [event("mimikatz.exe")],
        routing,
        changes=("downgrade-a",),
    )

    result = comparison.results[0]
    assert result.lost_queues == frozenset({"phone"})
    assert result.retained_queues == frozenset({"ticket"})
    assert result.alert_lost is False


def test_attribute_changes_accepts_either_argument_order(routing):
    collection = SigmaCollection.from_yaml(SINGLE_LOSS_RULES)
    changes = [RuleChange.archived("alert_a", label="archive-a")]
    events = [event("alpha.exe")]

    first = attribute_changes(collection, events, changes, routing)
    second = attribute_changes(collection, changes, events, routing)

    assert first.to_dict()["losses"] == second.to_dict()["losses"]


def test_report_is_serializable(routing):
    collection = SigmaCollection.from_yaml(PAIR_RULES)
    report = analyze_changes(
        collection,
        [event("mimikatz.exe")],
        [
            RuleChange.level_changed("redundant_high_a", "medium", label="downgrade-a"),
            RuleChange.archived("redundant_high_b", label="archive-b"),
        ],
        routing,
    )

    data = report.to_dict()
    assert data["losses"][0]["queue"] == "phone"
    assert data["losses"][0]["requires_combination"] is True
    assert data["minimal_combinations"][0]["change_ids"] == ["downgrade-a", "archive-b"]
    assert "downgrade-a|archive-b" in data["combination_replays"]


def test_unknown_change_target_raises(routing):
    collection = SigmaCollection.from_yaml(SINGLE_LOSS_RULES)
    with pytest.raises(Exception, match="does not match any rule"):
        attribute_changes(
            collection,
            [event("alpha.exe")],
            [RuleChange.archived("missing-rule")],
            routing,
        )


def _load_replay_case(name: str):
    base = Path(__file__).parent / "files" / "attribution"
    collection = SigmaCollection.from_yaml((base / f"{name}_rules.yml").read_text())
    raw_events = json.loads((base / f"{name}_events.json").read_text())
    events = [
        Event(
            timestamp=datetime.fromisoformat(item["timestamp"]),
            logsource=EventLogSource(**item["logsource"]),
            data=item["data"],
        )
        for item in raw_events
    ]
    changes = [
        RuleChange.from_mapping(item)
        for item in json.loads((base / f"{name}_changes.json").read_text())
    ]
    routing = RoutingPolicy(yaml.safe_load((base / "routing.yml").read_text()))
    return collection, events, changes, routing


def test_fixture_replays_cover_individual_and_pair_losses():
    single_collection, single_events, single_changes, routing = _load_replay_case("single_loss")
    single_report = attribute_changes(single_collection, single_events, single_changes, routing)
    assert len(single_report.queue_alert_losses) == 4
    assert len(single_report.alert_losses) == 2
    assert all(combo.size == 1 for combo in single_report.minimal_combinations)
    assert all(not combo.requires_combination for combo in single_report.minimal_combinations)

    pair_collection, pair_events, pair_changes, routing = _load_replay_case("pair_loss")
    pair_report = attribute_changes(pair_collection, pair_events, pair_changes, routing)
    assert len(pair_report.losses) == 1
    assert pair_report.losses[0].queue == "phone"
    assert pair_report.losses[0].requires_combination is True
    assert pair_report.candidate.results[0].alert_lost is False
    assert len(pair_report.minimal_combinations) == 1
    assert pair_report.minimal_combinations[0].change_ids == ("downgrade-a", "archive-b")


def test_routing_mapping_accepts_level_orientation_and_infers_ticket_kind():
    policy = RoutingPolicy(
        {
            "high": ["phone", "ticket"],
            "medium": {"queue": "ticket"},
        }
    )
    assert {decision.queue: decision.kind for decision in policy.decisions} == {
        "phone": QueueKind.NOTIFICATION,
        "ticket": QueueKind.TICKET,
    }

    compact = RoutingPolicy({"phone": ["high"], "ticket": ["informational"]})
    assert compact.queue_kinds == {
        "phone": QueueKind.NOTIFICATION,
        "ticket": QueueKind.TICKET,
    }


def test_status_and_title_selectors_are_supported(routing):
    collection = SigmaCollection.from_yaml(SINGLE_HIGH_RULE)
    change = RuleChange(
        kind="status_changed",
        rule_title="Redundant High A",
        new_status="deprecated",
        label="deprecate-a",
    )
    report = attribute_changes(collection, [event("mimikatz.exe")], [change], routing)
    assert report.losses == ()


def test_alert_loss_events_are_deduplicated(routing):
    collection = SigmaCollection.from_yaml(SINGLE_LOSS_RULES)
    report = attribute_changes(
        collection,
        [event("alpha.exe")],
        [RuleChange.archived("alert_a", label="archive-a")],
        routing,
    )
    assert len(report.losses) == 2
    assert len(report.queue_alert_losses) == 2
    assert len(report.alert_losses) == 1
    assert len(report.alert_loss_events) == 1
    assert report.alert_loss_events[0].index == 0


def test_notified_queues_reports_actual_delivery(routing):
    collection = SigmaCollection.from_yaml(SINGLE_HIGH_RULE)
    assert notified_queues(collection, [event("mimikatz.exe")], routing) == (
        frozenset({"phone", "ticket"}),
    )


def test_attribution_applies_processing_pipeline(routing):
    collection = SigmaCollection.from_yaml(SINGLE_HIGH_RULE)
    pipeline = ProcessingPipeline(
        [ProcessingItem(FieldMappingTransformation({"CommandLine": "process.command_line"}))]
    )
    mapped_event = Event(
        timestamp=datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc),
        logsource=EventLogSource(category="process_creation", product="windows"),
        data={"process.command_line": "mimikatz.exe"},
    )
    report = attribute_changes(
        collection,
        [mapped_event],
        [RuleChange.level_changed("redundant_high_a", "medium", label="downgrade-a")],
        routing,
        pipeline=pipeline,
    )
    assert report.baseline.results[0].baseline_queues == frozenset({"phone", "ticket"})
    assert report.candidate.results[0].candidate_queues == frozenset({"ticket"})


def test_event_mappings_are_accepted(routing):
    collection = SigmaCollection.from_yaml(SINGLE_HIGH_RULE)
    report = attribute_changes(
        collection,
        [
            {
                "timestamp": "2026-11-22T10:00:00+00:00",
                "logsource": {
                    "category": "process_creation",
                    "product": "windows",
                },
                "data": {"CommandLine": "mimikatz.exe"},
            }
        ],
        [RuleChange.archived("redundant_high_a", label="archive-a")],
        routing,
    )
    assert report.candidate.results[0].alert_lost is True
