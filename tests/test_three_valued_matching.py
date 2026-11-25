"""Fixed-seed three-state differential tests for the pySigma matcher."""

from __future__ import annotations

import fnmatch
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.exceptions import SigmaRuleLocation
from sigma.matching import Event, EventLogSource, SigmaMatcher
from sigma.matching.compiler import MatchCompiler
from sigma.matching.values import MISSING
from sigma.types import SigmaCasedString, SigmaExists, SigmaNull, SigmaString

SEED = 20261125041
CORRELATION_SEED = SEED + 1
FIELD = "absence_field"
GROUP_FIELD = "group_field"
RULE_NAME = "three_valued_condition"
CORRELATION_RULE_NAME = "three_state_correlation"
NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
LOGSOURCE = EventLogSource(category="three_valued_property", product="tests")
CORRELATION_LOGSOURCE = EventLogSource(category="three_valued_correlation", product="tests")


class AbsenceState(str, Enum):
    MISSING = "missing"
    EMPTY = "empty_string"
    NULL = "explicit_null"


STATES = tuple(AbsenceState)
LEAF_KINDS = ("empty", "null", "exists", "not_exists", "wildcard")

TRUTH_TABLE: dict[str, dict[AbsenceState, bool]] = {
    "empty": {
        AbsenceState.MISSING: False,
        AbsenceState.EMPTY: True,
        AbsenceState.NULL: False,
    },
    "null": {
        AbsenceState.MISSING: False,
        AbsenceState.EMPTY: False,
        AbsenceState.NULL: True,
    },
    "exists": {
        AbsenceState.MISSING: False,
        AbsenceState.EMPTY: True,
        AbsenceState.NULL: True,
    },
    "not_exists": {
        AbsenceState.MISSING: True,
        AbsenceState.EMPTY: False,
        AbsenceState.NULL: False,
    },
    "wildcard": {
        AbsenceState.MISSING: False,
        AbsenceState.EMPTY: True,
        AbsenceState.NULL: False,
    },
}


def state_data(state: AbsenceState, *, group: bool = False) -> dict[str, Any]:
    field_name = GROUP_FIELD if group else FIELD
    data: dict[str, Any] = {"event": "probe"}
    if state is AbsenceState.EMPTY:
        data[field_name] = ""
    elif state is AbsenceState.NULL:
        data[field_name] = None
    return data


def rule_source(case_id: str) -> SigmaRuleLocation:
    return SigmaRuleLocation(
        Path("three-valued-property") / f"seed-{SEED}" / f"{case_id}.yml",
        line=1,
    )


def dump_rule(rule: dict[str, Any]) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)


def parse_first_rule(yaml_text: str, source: SigmaRuleLocation) -> Any:
    collection = SigmaCollection.from_yaml(yaml_text, source=source)
    return collection.rules[0]


def leaf_definition(kind: str) -> dict[str, Any]:
    if kind == "empty":
        return {FIELD: ""}
    if kind == "null":
        return {FIELD: None}
    if kind == "exists":
        return {f"{FIELD}|exists": True}
    if kind == "not_exists":
        return {f"{FIELD}|exists": False}
    if kind == "wildcard":
        return {FIELD: "*"}
    raise AssertionError(f"unknown leaf kind: {kind}")


def single_rule_yaml(kind: str) -> tuple[str, SigmaRuleLocation]:
    source = rule_source(f"truth-table-{kind}")
    rule = {
        "title": f"Three-valued truth table: {kind}",
        "name": RULE_NAME,
        "status": "test",
        "logsource": {"category": LOGSOURCE.category, "product": LOGSOURCE.product},
        "detection": {"leaf": leaf_definition(kind), "condition": "leaf"},
    }
    return dump_rule(rule), source


def independent_leaf_result(field_name: str, value: Any, data: dict[str, Any]) -> bool:
    """Evaluate a leaf from the explicit three-state oracle."""
    present = field_name in data
    raw_value = data.get(field_name)

    if isinstance(value, SigmaNull):
        return present and raw_value is None
    if isinstance(value, SigmaExists):
        return present is bool(value.exists)
    if isinstance(value, (SigmaString, SigmaCasedString)):
        if not present or raw_value is None:
            return False
        return fnmatch.fnmatchcase(str(raw_value).lower(), str(value).lower())

    raise AssertionError(f"unsupported leaf value: {type(value)!r}")


def independent_condition_result(node: Any, data: dict[str, Any]) -> bool:
    """Independent evaluator for the parsed sigma.conditions tree."""
    if isinstance(node, ConditionAND):
        return all(independent_condition_result(arg, data) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(independent_condition_result(arg, data) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not independent_condition_result(node.args[0], data)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return independent_leaf_result(node.field, node.value, data)
    raise AssertionError(f"unsupported condition node: {type(node)!r}")


def compiler_result(yaml_text: str, source: SigmaRuleLocation, data: dict[str, Any]) -> bool:
    rule = parse_first_rule(yaml_text, source)
    compiled = MatchCompiler().compile_rule(rule)
    return bool(compiled(dict(data), None))


def matcher_result(
    yaml_text: str,
    source: SigmaRuleLocation,
    data: dict[str, Any],
    rule_name: str = RULE_NAME,
) -> bool:
    collection = SigmaCollection.from_yaml(yaml_text, source=source)
    event = Event(timestamp=NOW, logsource=LOGSOURCE, data=dict(data))
    with SigmaMatcher(collection) as matcher:
        matches = matcher.match(event)
    return any(getattr(match.rule, "name", None) == rule_name for match in matches)


def random_expression(rng: random.Random, leaf_ids: list[str], depth: int = 0) -> str:
    if depth >= 3 or rng.random() < 0.45:
        return rng.choice(leaf_ids)

    choice = rng.choice(("not", "and", "or"))
    if choice == "not":
        return f"not ({random_expression(rng, leaf_ids, depth + 1)})"

    left = random_expression(rng, leaf_ids, depth + 1)
    right = random_expression(rng, leaf_ids, depth + 1)
    operator = "and" if choice == "and" else "or"
    return f"({left} {operator} {right})"


def property_rule_yaml(
    case_id: int,
    kinds: list[str],
    expression: str,
) -> tuple[str, SigmaRuleLocation]:
    source = rule_source(f"property-{case_id}")
    detections: dict[str, Any] = {}
    for index, kind in enumerate(kinds):
        detections[f"leaf_{index}"] = leaf_definition(kind)
    detections["condition"] = expression

    rule = {
        "title": f"Three-valued property case {case_id}",
        "name": RULE_NAME,
        "status": "test",
        "logsource": {"category": LOGSOURCE.category, "product": LOGSOURCE.product},
        "detection": detections,
    }
    return dump_rule(rule), source


def condition_three_way_result(
    yaml_text: str,
    source: SigmaRuleLocation,
    data: dict[str, Any],
) -> tuple[bool, bool, bool]:
    rule = parse_first_rule(yaml_text, source)
    condition_value = independent_condition_result(
        rule.detection.parsed_condition[0].parsed,
        data,
    )
    compiled_value = compiler_result(yaml_text, source, data)
    public_value = matcher_result(yaml_text, source, data)
    return condition_value, compiled_value, public_value


@pytest.mark.parametrize("state", STATES, ids=[state.value for state in STATES])
@pytest.mark.parametrize("kind", LEAF_KINDS)
def test_independent_three_value_truth_table(kind: str, state: AbsenceState) -> None:
    yaml_text, source = single_rule_yaml(kind)
    data = state_data(state)

    condition_value, compiled_value, matcher_value = condition_three_way_result(
        yaml_text,
        source,
        data,
    )
    expected = TRUTH_TABLE[kind][state]

    assert condition_value is expected
    assert compiled_value is expected
    assert matcher_value is expected


def test_fixed_seed_condition_compiler_matcher_property() -> None:
    rng = random.Random(SEED)

    for case_id in range(250):
        state = rng.choice(STATES)
        kinds = [rng.choice(LEAF_KINDS) for _ in range(rng.randint(1, 4))]
        leaf_ids = [f"leaf_{index}" for index in range(len(kinds))]
        expression = random_expression(rng, leaf_ids)
        yaml_text, source = property_rule_yaml(case_id, kinds, expression)
        data = state_data(state)

        condition_value, compiled_value, matcher_value = condition_three_way_result(
            yaml_text,
            source,
            data,
        )
        assert condition_value == compiled_value == matcher_value, (
            "condition/compiler/matcher divergence\n"
            f"seed={SEED} case={case_id} state={state.value}\n"
            f"source={source.path}\n"
            f"event={data!r}\n"
            f"condition={expression}\n"
            f"results={condition_value=} {compiled_value=} {matcher_value=}\n"
            "rule YAML retained:\n"
            f"{yaml_text}"
        )


CORRELATION_RULE_YAML = """
title: Three state base
name: three_state_base
status: test
logsource:
    category: three_valued_correlation
    product: tests
detection:
    probe:
        event: probe
    condition: probe
---
title: Three state correlation
name: three_state_correlation
status: test
correlation:
    type: event_count
    rules:
        - three_state_base
    group-by:
        - group_field
    timespan: 5m
    condition:
        gte: 2
"""
CORRELATION_SOURCE = rule_source("correlation-property")


@dataclass(frozen=True)
class CorrelationObservation:
    index: int
    state: AbsenceState
    expected: bool
    actual: bool
    match_count: int
    group_values: dict[str, Any] | None

    @property
    def matches_oracle(self) -> bool:
        return self.expected == self.actual


def run_correlation_sequence(
    states: list[AbsenceState],
) -> list[CorrelationObservation]:
    collection = SigmaCollection.from_yaml(
        CORRELATION_RULE_YAML,
        source=CORRELATION_SOURCE,
    )
    counts = {state: 0 for state in AbsenceState}
    observations: list[CorrelationObservation] = []

    with SigmaMatcher(collection) as matcher:
        for index, state in enumerate(states):
            counts[state] += 1
            expected = counts[state] >= 2
            event = Event(
                timestamp=NOW + timedelta(seconds=index),
                logsource=CORRELATION_LOGSOURCE,
                data=state_data(state, group=True),
            )
            matches = matcher.match(event)
            correlation_matches = [
                match
                for match in matches
                if getattr(match.rule, "name", None) == CORRELATION_RULE_NAME
            ]
            observations.append(
                CorrelationObservation(
                    index=index,
                    state=state,
                    expected=expected,
                    actual=bool(correlation_matches),
                    match_count=len(matches),
                    group_values=(
                        correlation_matches[0].group_values if correlation_matches else None
                    ),
                )
            )

    return observations


def correlation_has_divergence(states: list[AbsenceState]) -> bool:
    return any(not observation.matches_oracle for observation in run_correlation_sequence(states))


def minimize_event_states(
    initial_states: list[AbsenceState],
    has_divergence: Callable[[list[AbsenceState]], bool],
) -> list[AbsenceState]:
    """Delta-debug a divergent sequence down to an event-minimal witness."""
    current = list(initial_states)

    shortest_prefix: list[AbsenceState] | None = None
    for end in range(1, len(current) + 1):
        prefix = current[:end]
        if has_divergence(prefix):
            shortest_prefix = prefix
            break
    if shortest_prefix is not None:
        current = shortest_prefix

    granularity = 2
    while len(current) > 1:
        chunk_size = max(1, (len(current) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(current), chunk_size):
            candidate = current[:start] + current[start + chunk_size :]
            if candidate and has_divergence(candidate):
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(len(current), granularity * 2)

    changed = True
    while changed:
        changed = False
        for index in range(len(current)):
            candidate = current[:index] + current[index + 1 :]
            if candidate and has_divergence(candidate):
                current = candidate
                changed = True
                break

    return current


def format_correlation_failure(
    initial: list[AbsenceState],
    minimal: list[AbsenceState],
    observations: list[CorrelationObservation],
) -> str:
    lines = [
        "three-state correlation divergence",
        f"seed={CORRELATION_SEED}",
        f"source={CORRELATION_SOURCE.path} line={CORRELATION_SOURCE.line}",
        f"source_object={CORRELATION_SOURCE!r}",
        f"initial_event_count={len(initial)}",
        f"minimal_event_count={len(minimal)}",
        f"initial_states={[state.value for state in initial]!r}",
        f"minimal_states={[state.value for state in minimal]!r}",
        "observations (minimal sequence):",
    ]
    for observation in observations:
        lines.append(
            "  "
            f"#{observation.index} state={observation.state.value} "
            f"expected={observation.expected} actual={observation.actual} "
            f"matches={observation.match_count} group_values={observation.group_values!r}"
        )
    lines.append("rule YAML retained from the original case:")
    lines.extend("    " + line for line in CORRELATION_RULE_YAML.splitlines())
    return "\n".join(lines)


@pytest.mark.parametrize("first", STATES, ids=[f"first-{s.value}" for s in STATES])
@pytest.mark.parametrize("second", STATES, ids=[f"second-{s.value}" for s in STATES])
def test_pairwise_correlation_truth_table(
    first: AbsenceState,
    second: AbsenceState,
) -> None:
    observations = run_correlation_sequence([first, second])
    expected = first is second

    assert observations[0].actual is False
    assert observations[1].expected is expected
    assert observations[1].actual is expected

    if expected:
        sentinel_value: Any
        if first is AbsenceState.MISSING:
            sentinel_value = MISSING
        elif first is AbsenceState.NULL:
            sentinel_value = None
        else:
            sentinel_value = ""
        assert observations[1].group_values == {GROUP_FIELD: sentinel_value}


def test_fixed_seed_correlation_property_minimizes_and_retains_source() -> None:
    rng = random.Random(CORRELATION_SEED)
    failures: list[str] = []

    for case_id in range(120):
        initial = [rng.choice(STATES) for _ in range(rng.randint(1, 10))]
        observations = run_correlation_sequence(initial)
        if all(observation.matches_oracle for observation in observations):
            continue

        minimal = minimize_event_states(initial, correlation_has_divergence)
        minimal_observations = run_correlation_sequence(minimal)
        failures.append(
            format_correlation_failure(initial, minimal, minimal_observations) + f"\ncase={case_id}"
        )

    assert not failures, "\n\n".join(failures)


def legacy_missing_null_key(state: AbsenceState) -> str | None:
    """The pre-fix key collapse that joined absent and explicit-null groups."""
    if state is AbsenceState.MISSING or state is AbsenceState.NULL:
        return None
    return ""


def legacy_key_has_divergence(states: list[AbsenceState]) -> bool:
    exact_counts = {state: 0 for state in AbsenceState}
    legacy_counts: dict[str | None, int] = {}

    for state in states:
        exact_counts[state] += 1
        legacy_key = legacy_missing_null_key(state)
        legacy_counts[legacy_key] = legacy_counts.get(legacy_key, 0) + 1
        exact_fired_here = exact_counts[state] >= 2
        legacy_fired_here = legacy_counts[legacy_key] >= 2
        if exact_fired_here != legacy_fired_here:
            return True

    return False


def test_minimizer_reduces_lossy_collision_to_two_events() -> None:
    initial = [
        AbsenceState.EMPTY,
        AbsenceState.MISSING,
        AbsenceState.EMPTY,
        AbsenceState.NULL,
        AbsenceState.EMPTY,
    ]

    minimal = minimize_event_states(initial, legacy_key_has_divergence)

    assert minimal == [AbsenceState.MISSING, AbsenceState.NULL]


def test_failure_report_preserves_rule_yaml_and_source() -> None:
    minimal = [AbsenceState.MISSING, AbsenceState.NULL]
    observations = run_correlation_sequence(minimal)
    report = format_correlation_failure(minimal, minimal, observations)
    collection = SigmaCollection.from_yaml(CORRELATION_RULE_YAML, source=CORRELATION_SOURCE)
    correlation_rule = next(
        rule for rule in collection.rules if getattr(rule, "name", None) == CORRELATION_RULE_NAME
    )

    assert CORRELATION_SOURCE.path.as_posix() in report
    assert "source_object=" in report
    assert "three_state_correlation" in report
    assert "title: Three state correlation" in report
    assert "minimal_states=['missing', 'explicit_null']" in report
    assert correlation_rule.source == CORRELATION_SOURCE
