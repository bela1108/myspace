from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from sigma.collection import SigmaCollection
from sigma.matching.correlation_matcher import SigmaCorrelationRuleMatcher
from sigma.matching.event import Event, EventLogSource
from sigma.matching.match import SigmaMatch

SEEDS = (1729, 104729, 20261125)
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)
LOGSOURCE = EventLogSource(category="partition_order_property", product="correlation_matcher")
ITERATIONS = 48


BASE_RULES_YAML = """
title: Partition Property A
name: rule_a
status: test
logsource:
    category: partition_order_property
    product: correlation_matcher
detection:
    selection:
        kind: a
    condition: selection
---
title: Partition Property B
name: rule_b
status: test
logsource:
    category: partition_order_property
    product: correlation_matcher
detection:
    selection:
        kind: b
    condition: selection
"""


CORRELATION_RULES_YAML = {
    "global_ordered": """
title: Global ordered correlation
name: corr_global_ordered
status: test
correlation:
    type: temporal_ordered
    rules:
        - rule_a
        - rule_b
    group-by:
        - case_id
    timespan: 5m
""",
    "partition_ordered": """
title: Partition ordered correlation
name: corr_partition_ordered
status: test
correlation:
    type: temporal_ordered
    rules:
        - rule_a
        - rule_b
    group-by:
        - source
    timespan: 5m
""",
    "partition_temporal": """
title: Partition temporal correlation
name: corr_partition_temporal
status: test
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by:
        - source
    timespan: 5m
""",
    "partition_event_count": """
title: Partition event count correlation
name: corr_partition_event_count
status: test
correlation:
    type: event_count
    rules:
        - rule_a
    group-by:
        - source
    timespan: 5m
    condition:
        gte: 2
""",
    "partition_value_count": """
title: Partition value count correlation
name: corr_partition_value_count
status: test
correlation:
    type: value_count
    rules:
        - rule_a
    group-by:
        - source
    timespan: 5m
    condition:
        gte: 2
        field: nonce
""",
    "partition_value_sum": """
title: Partition value sum correlation
name: corr_partition_value_sum
status: test
correlation:
    type: value_sum
    rules:
        - rule_a
    group-by:
        - source
    timespan: 5m
    condition:
        gte: 3
        field: amount
""",
}


PARTITION_ARCHETYPES = tuple(
    name for name in CORRELATION_RULES_YAML if name.startswith("partition_")
)


@dataclass(frozen=True)
class EventSpec:
    event_id: str
    source: str
    kind: str
    ordinal: int
    nonce: int = 0
    amount: int = 0

    @property
    def timestamp(self) -> datetime:
        return EPOCH + timedelta(seconds=self.ordinal)


@dataclass(frozen=True)
class CorrelationWitness:
    """Stable evidence retained from a produced ``SigmaMatch``."""

    rule_name: str
    event_ids: tuple[str, ...]
    kinds: tuple[str, ...]
    group_values: tuple[tuple[str, str], ...]

    @classmethod
    def from_match(cls, match: SigmaMatch) -> CorrelationWitness:
        event_ids = tuple(str(event.data["event_id"]) for event in match.events)
        kinds = tuple(str(event.data["kind"]) for event in match.events)
        group_values = tuple(
            sorted(
                (key, "<none>" if value is None else str(value))
                for key, value in (match.group_values or {}).items()
            )
        )
        return cls(
            rule_name=str(match.rule.name),
            event_ids=event_ids,
            kinds=kinds,
            group_values=group_values,
        )


@dataclass(frozen=True)
class Observation:
    trigger_id: str
    witnesses: tuple[CorrelationWitness, ...]


@dataclass(frozen=True)
class RunTrace:
    schedule: tuple[str, ...]
    observations: tuple[Observation, ...]

    @property
    def firing_outcome(self) -> tuple[tuple[str, tuple[tuple[str, ...], ...]], ...]:
        return tuple(
            sorted(
                (
                    observation.trigger_id,
                    tuple(witness.event_ids for witness in observation.witnesses),
                )
                for observation in self.observations
                if observation.witnesses
            )
        )

    @property
    def witnesses(self) -> tuple[CorrelationWitness, ...]:
        return tuple(
            witness for observation in self.observations for witness in observation.witnesses
        )


@dataclass(frozen=True)
class MinimalDiscrepancy:
    seed: int
    event_ids: tuple[str, ...]
    left_schedule: tuple[str, ...]
    right_schedule: tuple[str, ...]
    left_trace: RunTrace
    right_trace: RunTrace
    witness: CorrelationWitness

    @property
    def positive_trace(self) -> RunTrace:
        return self.left_trace if self.left_trace.witnesses else self.right_trace

    @property
    def negative_trace(self) -> RunTrace:
        return self.right_trace if self.left_trace.witnesses else self.left_trace

    def explain(self) -> str:
        return (
            f"seed={self.seed}; minimal_events={list(self.event_ids)}\n"
            f"left={list(self.left_schedule)} -> {self.left_trace.firing_outcome}\n"
            f"right={list(self.right_schedule)} -> {self.right_trace.firing_outcome}\n"
            f"retained_witness={self.witness}"
        )


def build_rules(archetype: str) -> tuple[Any, dict[str, Any]]:
    collection = SigmaCollection.from_yaml(
        BASE_RULES_YAML + "\n---\n" + CORRELATION_RULES_YAML[archetype]
    )
    rules_by_name = {rule.name: rule for rule in collection.rules if getattr(rule, "name", None)}
    correlation_rule = rules_by_name[f"corr_{archetype}"]
    base_rules = {"a": rules_by_name["rule_a"], "b": rules_by_name["rule_b"]}
    return correlation_rule, base_rules


def event_index(partitions: dict[str, list[EventSpec]]) -> dict[str, EventSpec]:
    return {event.event_id: event for events in partitions.values() for event in events}


def canonical_schedule(partitions: dict[str, list[EventSpec]]) -> tuple[str, ...]:
    return tuple(event.event_id for source in sorted(partitions) for event in partitions[source])


def valid_interleaving(
    partitions: dict[str, list[EventSpec]], rng: random.Random
) -> tuple[str, ...]:
    pending = {source: list(events) for source, events in sorted(partitions.items())}
    schedule: list[str] = []
    while pending:
        source = rng.choice(sorted(pending))
        event = pending[source].pop(0)
        schedule.append(event.event_id)
        if not pending[source]:
            del pending[source]
    return tuple(schedule)


def seeded_interleavings(
    partitions: dict[str, list[EventSpec]], seed: int, count: int = ITERATIONS
) -> tuple[tuple[str, ...], ...]:
    rng = random.Random(seed)
    schedules: list[tuple[str, ...]] = []
    for _ in range(count):
        schedule = valid_interleaving(partitions, rng)
        if schedule not in schedules:
            schedules.append(schedule)
    return tuple(schedules)


def is_valid_interleaving(
    schedule: tuple[str, ...], partitions: dict[str, list[EventSpec]]
) -> bool:
    positions: dict[str, list[str]] = {}
    for source, events in partitions.items():
        positions[source] = [event.event_id for event in events]
    cursor = {source: 0 for source in positions}
    events = event_index(partitions)
    for event_id in schedule:
        source = events[event_id].source
        expected = positions[source][cursor[source]]
        if event_id != expected:
            return False
        cursor[source] += 1
    return all(cursor[source] == len(positions[source]) for source in positions)


def run_schedule(
    correlation_rule: Any,
    base_rules: dict[str, Any],
    events: dict[str, EventSpec],
    schedule: tuple[str, ...],
) -> RunTrace:
    matcher = SigmaCorrelationRuleMatcher(correlation_rule)
    observations: list[Observation] = []
    for event_id in schedule:
        spec = events[event_id]
        event = Event(
            timestamp=spec.timestamp,
            logsource=LOGSOURCE,
            data={
                "event_id": spec.event_id,
                "source": spec.source,
                "kind": spec.kind,
                "case_id": "case-1",
                "nonce": spec.nonce,
                "amount": spec.amount,
            },
        )
        match = SigmaMatch(
            rule=base_rules[spec.kind],
            events=[event],
            timestamp=spec.timestamp,
        )
        produced = matcher.receive_match(match, spec.kind)
        witnesses = tuple(CorrelationWitness.from_match(result) for result in produced)
        observations.append(Observation(trigger_id=event_id, witnesses=witnesses))
    return RunTrace(schedule=schedule, observations=tuple(observations))


def partition_signature(
    trace: RunTrace, events: dict[str, EventSpec]
) -> tuple[tuple[str, int, tuple[tuple[str, ...], ...]], ...]:
    entries = []
    for observation in trace.observations:
        spec = events[observation.trigger_id]
        witness_ids = tuple(witness.event_ids for witness in observation.witnesses)
        entries.append((spec.source, spec.ordinal, witness_ids))
    return tuple(sorted(entries))


def make_partition_scenario(seed: int, archetype: str) -> dict[str, list[EventSpec]]:
    rng = random.Random(seed)
    source_count = 2 + rng.randrange(3)
    ordered_kinds = archetype in {"partition_ordered", "partition_temporal"}
    partitions: dict[str, list[EventSpec]] = {}
    for source_index in range(source_count):
        source = f"src_{source_index}"
        kinds = ("a", "b") if ordered_kinds else ("a", "a")
        events: list[EventSpec] = []
        for ordinal, kind in enumerate(kinds):
            nonce = ordinal + 1 if archetype == "partition_value_count" else 0
            amount = ordinal + 1 if archetype == "partition_value_sum" else 0
            events.append(
                EventSpec(
                    event_id=f"{source}-event-{ordinal}",
                    source=source,
                    kind=kind,
                    ordinal=ordinal,
                    nonce=nonce,
                    amount=amount,
                )
            )
        partitions[source] = events
    return partitions


def make_global_scenario(seed: int) -> dict[str, list[EventSpec]]:
    rng = random.Random(seed ^ 0xC0FFEE)
    partitions: dict[str, list[EventSpec]] = {
        "source_a": [EventSpec("core-a", "source_a", "a", 0)],
        "source_b": [EventSpec("core-b", "source_b", "b", 0)],
    }
    noise_count = 1 + rng.randrange(3)
    for index in range(noise_count):
        source = f"noise_{index}"
        kind = rng.choice(["a", "b"])
        partitions[source] = [EventSpec(f"noise-{index}", source, kind, 0)]
    return partitions


def find_order_discrepancy_pair(
    correlation_rule: Any,
    base_rules: dict[str, Any],
    partitions: dict[str, list[EventSpec]],
    schedules: tuple[tuple[str, ...], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    events = event_index(partitions)
    traces = [
        run_schedule(correlation_rule, base_rules, events, schedule) for schedule in schedules
    ]
    fallback: tuple[tuple[str, ...], tuple[str, ...]] | None = None
    for left_index, left_trace in enumerate(traces):
        for right_index in range(left_index + 1, len(traces)):
            right_trace = traces[right_index]
            if left_trace.firing_outcome == right_trace.firing_outcome:
                continue
            pair = (schedules[left_index], schedules[right_index])
            if bool(left_trace.witnesses) != bool(right_trace.witnesses):
                return pair
            if fallback is None:
                fallback = pair
    return fallback


def find_order_discrepancy(
    correlation_rule: Any,
    base_rules: dict[str, Any],
    partitions: dict[str, list[EventSpec]],
    schedules: tuple[tuple[str, ...], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    pair = find_order_discrepancy_pair(correlation_rule, base_rules, partitions, schedules)
    if pair is None:
        raise AssertionError("fixed-seed interleavings did not produce an order discrepancy")
    return pair


@dataclass(frozen=True)
class OrderClassification:
    contract: str
    discrepancy: MinimalDiscrepancy | None


def classify_seeded_order_dependence(
    correlation_rule: Any,
    base_rules: dict[str, Any],
    partitions: dict[str, list[EventSpec]],
    seed: int,
    schedule_count: int = 64,
) -> OrderClassification:
    schedules = seeded_interleavings(partitions, seed, count=schedule_count)
    pair = find_order_discrepancy_pair(correlation_rule, base_rules, partitions, schedules)
    if pair is None:
        return OrderClassification("partition-order-only", None)
    left, right = pair
    discrepancy = minimize_discrepancy(
        correlation_rule, base_rules, partitions, left, right, seed=seed
    )
    return OrderClassification("global-order-dependent", discrepancy)


def minimize_discrepancy(
    correlation_rule: Any,
    base_rules: dict[str, Any],
    partitions: dict[str, list[EventSpec]],
    left_schedule: tuple[str, ...],
    right_schedule: tuple[str, ...],
    *,
    seed: int,
) -> MinimalDiscrepancy:
    active_partitions = {source: list(events) for source, events in partitions.items()}
    left = left_schedule
    right = right_schedule

    def still_differs(
        candidate_partitions: dict[str, list[EventSpec]],
        candidate_left: tuple[str, ...],
        candidate_right: tuple[str, ...],
    ) -> bool:
        if candidate_left == candidate_right or not candidate_left or not candidate_right:
            return False
        candidate_events = event_index(candidate_partitions)
        left_trace = run_schedule(correlation_rule, base_rules, candidate_events, candidate_left)
        right_trace = run_schedule(correlation_rule, base_rules, candidate_events, candidate_right)
        if left_trace.firing_outcome == right_trace.firing_outcome:
            return False
        return bool(left_trace.witnesses or right_trace.witnesses)

    while True:
        current_ids = event_index(active_partitions)
        removed = False
        for event_id in sorted(current_ids):
            candidate_partitions: dict[str, list[EventSpec]] = {}
            for source, events in active_partitions.items():
                kept = [event for event in events if event.event_id != event_id]
                if kept:
                    candidate_partitions[source] = kept
            candidate_left = tuple(item for item in left if item != event_id)
            candidate_right = tuple(item for item in right if item != event_id)
            if still_differs(candidate_partitions, candidate_left, candidate_right):
                active_partitions = candidate_partitions
                left = candidate_left
                right = candidate_right
                removed = True
                break
        if not removed:
            break

    events = event_index(active_partitions)
    left_trace = run_schedule(correlation_rule, base_rules, events, left)
    right_trace = run_schedule(correlation_rule, base_rules, events, right)
    witness = next(witness for trace in (left_trace, right_trace) for witness in trace.witnesses)
    minimal = MinimalDiscrepancy(
        seed=seed,
        event_ids=tuple(sorted(events)),
        left_schedule=left,
        right_schedule=right,
        left_trace=left_trace,
        right_trace=right_trace,
        witness=witness,
    )

    for event_id in minimal.event_ids:
        candidate_partitions = {
            source: [event for event in events_in_source if event.event_id != event_id]
            for source, events_in_source in active_partitions.items()
        }
        candidate_partitions = {
            source: events_in_source
            for source, events_in_source in candidate_partitions.items()
            if events_in_source
        }
        candidate_left = tuple(item for item in left if item != event_id)
        candidate_right = tuple(item for item in right if item != event_id)
        assert not still_differs(
            candidate_partitions, candidate_left, candidate_right
        ), f"minimization is not 1-minimal for seed {seed}: {minimal.explain()}"
    return minimal


def assert_partition_invariant(archetype: str, seed: int) -> None:
    correlation_rule, base_rules = build_rules(archetype)
    partitions = make_partition_scenario(seed, archetype)
    events = event_index(partitions)
    canonical = canonical_schedule(partitions)
    canonical_trace = run_schedule(correlation_rule, base_rules, events, canonical)
    expected = partition_signature(canonical_trace, events)

    rng = random.Random(f"{seed}:{archetype}")
    for _ in range(ITERATIONS):
        schedule = valid_interleaving(partitions, rng)
        trace = run_schedule(correlation_rule, base_rules, events, schedule)
        actual = partition_signature(trace, events)
        if actual != expected:
            discrepancy = minimize_discrepancy(
                correlation_rule,
                base_rules,
                partitions,
                canonical,
                schedule,
                seed=seed,
            )
            pytest.fail(
                "cross-source interleaving changed a partition-scoped rule:\n"
                f"archetype={archetype}\n{discrepancy.explain()}\n"
                f"expected_partition_signature={expected}\nactual={actual}"
            )


@pytest.mark.parametrize("archetype", PARTITION_ARCHETYPES)
@pytest.mark.parametrize("seed", SEEDS)
def test_partition_scoped_rules_ignore_global_interleaving(archetype: str, seed: int) -> None:
    assert_partition_invariant(archetype, seed)


@pytest.mark.parametrize("seed", SEEDS)
def test_global_order_rule_is_detected_minimized_and_witnessed(seed: int) -> None:
    correlation_rule, base_rules = build_rules("global_ordered")
    partitions = make_global_scenario(seed)
    schedules = seeded_interleavings(partitions, seed, count=64)
    left, right = find_order_discrepancy(correlation_rule, base_rules, partitions, schedules)
    discrepancy = minimize_discrepancy(
        correlation_rule, base_rules, partitions, left, right, seed=seed
    )

    assert len(discrepancy.event_ids) == 2, discrepancy.explain()
    assert discrepancy.left_schedule != discrepancy.right_schedule
    specs = [event_index(partitions)[event_id] for event_id in discrepancy.event_ids]
    assert len({spec.source for spec in specs}) == 2
    assert {spec.kind for spec in specs} == {"a", "b"}
    minimal_partitions: dict[str, list[EventSpec]] = {}
    for spec in specs:
        minimal_partitions.setdefault(spec.source, []).append(spec)
    assert is_valid_interleaving(discrepancy.left_schedule, minimal_partitions)
    assert is_valid_interleaving(discrepancy.right_schedule, minimal_partitions)

    positive = discrepancy.positive_trace
    negative = discrepancy.negative_trace
    assert len(positive.witnesses) == 1, discrepancy.explain()
    assert not negative.witnesses, discrepancy.explain()
    witness = positive.witnesses[0]
    assert witness.rule_name == "corr_global_ordered"
    assert witness.kinds == ("a", "b")
    assert witness.event_ids == positive.schedule
    assert dict(witness.group_values)["case_id"] == "case-1"
    assert discrepancy.witness.event_ids == witness.event_ids


def test_seeded_classifier_labels_global_and_partition_contracts() -> None:
    global_rule, global_base = build_rules("global_ordered")
    global_classification = classify_seeded_order_dependence(
        global_rule,
        global_base,
        make_global_scenario(SEEDS[0]),
        SEEDS[0],
    )
    assert global_classification.contract == "global-order-dependent"
    assert global_classification.discrepancy is not None
    assert len(global_classification.discrepancy.event_ids) == 2

    for archetype in PARTITION_ARCHETYPES:
        rule, base_rules = build_rules(archetype)
        classification = classify_seeded_order_dependence(
            rule,
            base_rules,
            make_partition_scenario(SEEDS[0], archetype),
            SEEDS[0],
        )
        assert classification.contract == "partition-order-only", archetype
        assert classification.discrepancy is None, archetype


def test_partition_order_rule_still_depends_on_intra_source_order() -> None:
    seed = 20261125
    correlation_rule, base_rules = build_rules("partition_ordered")
    partitions = {
        "only_source": [
            EventSpec("local-a", "only_source", "a", 0),
            EventSpec("local-b", "only_source", "b", 0),
        ]
    }
    ab = ("local-a", "local-b")
    ba = ("local-b", "local-a")

    discrepancy = minimize_discrepancy(correlation_rule, base_rules, partitions, ab, ba, seed=seed)

    assert len(discrepancy.event_ids) == 2
    specs = [event_index(partitions)[event_id] for event_id in discrepancy.event_ids]
    assert {spec.source for spec in specs} == {"only_source"}
    assert discrepancy.left_trace.witnesses
    assert not discrepancy.right_trace.witnesses
    witness = discrepancy.left_trace.witnesses[0]
    assert witness.event_ids == ("local-a", "local-b")
    assert witness.kinds == ("a", "b")
    assert dict(witness.group_values)["source"] == "only_source"
