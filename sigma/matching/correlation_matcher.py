from __future__ import annotations

from datetime import timedelta
from statistics import median
from typing import Any

from sigma.correlations import (
    CorrelationConditionAND,
    CorrelationConditionItem,
    CorrelationConditionNOT,
    CorrelationConditionOR,
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
    SigmaExtendedCorrelationCondition,
    SigmaRuleReference,
)
from sigma.matching.event import Event
from sigma.matching.evidence import CorrelationEvidence, RetractionResult
from sigma.matching.match import SigmaMatch
from sigma.matching.state import SlidingWindowState


class SigmaCorrelationRuleMatcher:
    """Evaluates a SigmaCorrelationRule by tracking matches from referenced base rules."""

    def __init__(
        self,
        rule: SigmaCorrelationRule,
        max_state: int | None = None,
        max_events_per_match: int | None = 100,
    ) -> None:
        self.rule = rule
        self.max_events_per_match = max_events_per_match
        self._state = SlidingWindowState(
            window_seconds=rule.timespan.seconds,
            max_entries=max_state,
        )
        # Group keys whose correlation is currently considered fired, so that a
        # continuously satisfied condition only emits a match on the rising edge.
        self._fired_groups: set[tuple[Any, ...]] = set()
        # Evidence snapshot captured at firing time, keyed by group. Retained even
        # after the contributing events leave the window so retractions can be
        # discharged against the original triggering evidence.
        self._fired_evidence: dict[tuple[Any, ...], list[CorrelationEvidence]] = {}
        # Track which base rule names are relevant
        self._rule_names: set[str] = set()
        if rule.rules:
            for ref in rule.rules:
                self._rule_names.add(ref.reference)
        elif isinstance(rule.condition, SigmaExtendedCorrelationCondition):
            for name in rule.condition.get_referenced_rules():
                self._rule_names.add(name)

    def receive_match(self, match: SigmaMatch, source_rule_name: str) -> list[SigmaMatch]:
        """Process an incoming match from a base rule and return correlation matches if any."""
        group_key = self._extract_group_key(match)
        self._state.add(group_key, match)

        window_matches = self._state.get_window(group_key, match.timestamp)
        fired = self._is_satisfied(window_matches)
        if fired and group_key not in self._fired_groups:
            self._fired_groups.add(group_key)
            result = self._evaluate(window_matches, group_key, match.timestamp)
            for correlation_match in result:
                self._fired_evidence[group_key] = list(correlation_match.evidence or [])
            return result
        if not fired:
            self._fired_groups.discard(group_key)
            self._fired_evidence.pop(group_key, None)
        return []

    def retract_event(self, event: Event) -> RetractionResult:
        """Remove an event and discharge responsibility for the groups it affected.

        Returns a :class:`RetractionResult` describing the correlation matches that
        remain active (with rebuilt evidence excluding the retracted event) and those
        that must be revoked because the condition no longer holds.
        """
        affected_keys = self._state.remove_event(event)
        if not affected_keys:
            return RetractionResult(retracted_event=event)
        active: list[SigmaMatch] = []
        revoked: list[SigmaMatch] = []
        # Every currently fired group must be re-checked: groups touched by the
        # retraction may be revoked or rebuilt, while untouched fired groups remain
        # active and still belong on the discharge checklist.
        affected_set = set(affected_keys)
        candidate_keys = list(self._fired_groups)
        for group_key in affected_set.difference(self._fired_groups):
            candidate_keys.append(group_key)
        for group_key in candidate_keys:
            was_fired = group_key in self._fired_groups
            now = self._state.latest_timestamp(group_key) or event.timestamp
            window_matches = self._state.get_window(group_key, now)
            still_fired = self._is_satisfied(window_matches)
            if still_fired:
                active.extend(self._evaluate(window_matches, group_key, now))
            if was_fired and not still_fired:
                self._fired_groups.discard(group_key)
                evidence = self._fired_evidence.pop(group_key, [])
                revoked.append(
                    SigmaMatch(
                        rule=self.rule,
                        events=[],
                        timestamp=now,
                        group_values=self._make_group_values(group_key),
                        evidence=evidence,
                    )
                )
        return RetractionResult(retracted_event=event, active=active, revoked=revoked)

    def _is_satisfied(self, window_matches: list[SigmaMatch]) -> bool:
        """Return whether the correlation condition holds for the current window."""
        ctype = self.rule.type
        condition = self.rule.condition

        if ctype == SigmaCorrelationType.EVENT_COUNT:
            return self._count_condition_holds(window_matches, condition)
        if ctype == SigmaCorrelationType.VALUE_COUNT:
            return self._value_count_holds(window_matches, condition)
        if ctype in (
            SigmaCorrelationType.VALUE_SUM,
            SigmaCorrelationType.VALUE_AVG,
            SigmaCorrelationType.VALUE_MEDIAN,
            SigmaCorrelationType.VALUE_PERCENTILE,
        ):
            return self._aggregate_holds(window_matches, condition, ctype)
        if ctype == SigmaCorrelationType.TEMPORAL:
            return self._temporal_holds(window_matches)
        if ctype == SigmaCorrelationType.TEMPORAL_ORDERED:
            return self._temporal_ordered_holds(window_matches)
        return False

    def _count_condition_holds(self, matches: list[SigmaMatch], condition: Any) -> bool:
        if not isinstance(condition, SigmaCorrelationCondition):
            return False
        return self._compare(condition.op, len(matches), condition.count)

    def _value_count_holds(self, matches: list[SigmaMatch], condition: Any) -> bool:
        if not isinstance(condition, SigmaCorrelationCondition) or condition.fieldref is None:
            return False
        values: set[Any] = set()
        for match in matches:
            for event in match.events:
                value = event.data.get(condition.fieldref)
                if value is not None:
                    values.add(value)
        return self._compare(condition.op, len(values), condition.count)

    def _aggregate_holds(
        self, matches: list[SigmaMatch], condition: Any, ctype: SigmaCorrelationType
    ) -> bool:
        if not isinstance(condition, SigmaCorrelationCondition) or condition.fieldref is None:
            return False
        values: list[float] = []
        for match in matches:
            for event in match.events:
                value = event.data.get(condition.fieldref)
                if value is not None:
                    try:
                        values.append(float(value))
                    except (ValueError, TypeError):
                        pass
        if not values:
            return False
        if ctype == SigmaCorrelationType.VALUE_SUM:
            result: float = sum(values)
        elif ctype == SigmaCorrelationType.VALUE_AVG:
            result = sum(values) / len(values)
        elif ctype == SigmaCorrelationType.VALUE_MEDIAN:
            result = median(values)
        else:
            percentile = condition.percentile or 95
            sorted_values = sorted(values)
            index = min(int(len(sorted_values) * percentile / 100), len(sorted_values) - 1)
            result = sorted_values[index]
        return self._compare(condition.op, result, condition.count)

    def _temporal_holds(self, matches: list[SigmaMatch]) -> bool:
        if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
            fired_rules = {
                name for match in matches if (name := getattr(match.rule, "name", None))
            }
            return self._eval_extended_expr(self.rule.condition.parsed, fired_rules)
        matched_rules = {
            match.rule.name
            for match in matches
            if hasattr(match.rule, "name") and match.rule.name
        }
        return bool(self._rule_names) and self._rule_names.issubset(matched_rules)

    def _temporal_ordered_holds(self, matches: list[SigmaMatch]) -> bool:
        if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
            rule_first_fire: dict[str, Any] = {}
            for match in sorted(matches, key=lambda item: item.timestamp):
                name = getattr(match.rule, "name", None)
                if name and name not in rule_first_fire:
                    rule_first_fire[name] = match.timestamp
            ok, _ = self._eval_ordered_extended_expr(self.rule.condition.parsed, rule_first_fire)
            return ok
        if not self.rule.rules:
            return False
        expected_order = [ref.reference for ref in self.rule.rules]
        seen_index = 0
        for match in sorted(matches, key=lambda item: item.timestamp):
            if hasattr(match.rule, "name") and match.rule.name == expected_order[seen_index]:
                seen_index += 1
                if seen_index >= len(expected_order):
                    return True
        return False

    def _extract_group_key(self, match: SigmaMatch) -> tuple[Any, ...]:
        """Extract group-by field values from match events."""
        if not self.rule.group_by:
            return ()

        values: list[Any] = []
        event = match.events[0] if match.events else None
        if event is None:
            return tuple(None for _ in self.rule.group_by)

        for field_name in self.rule.group_by:
            # Check aliases
            resolved_field = self._resolve_alias(field_name, match)
            values.append(event.data.get(resolved_field))
        return tuple(values)

    def _resolve_alias(self, field_name: str, match: SigmaMatch) -> str:
        """Resolve field alias to actual field name based on source rule."""
        if field_name in self.rule.aliases.aliases:
            alias = self.rule.aliases.aliases[field_name]
            # Try to find mapping for the source rule
            for ref, mapped_field in alias.mapping.items():
                if hasattr(ref, "rule") and ref.rule is match.rule:
                    return mapped_field
        return field_name

    def _evaluate(
        self,
        window_matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
    ) -> list[SigmaMatch]:
        """Evaluate the correlation condition against current window state."""
        ctype = self.rule.type
        condition = self.rule.condition

        if ctype == SigmaCorrelationType.EVENT_COUNT:
            return self._eval_event_count(window_matches, group_key, now, condition)
        elif ctype == SigmaCorrelationType.VALUE_COUNT:
            return self._eval_value_count(window_matches, group_key, now, condition)
        elif ctype == SigmaCorrelationType.TEMPORAL:
            return self._eval_temporal(window_matches, group_key, now)
        elif ctype == SigmaCorrelationType.TEMPORAL_ORDERED:
            return self._eval_temporal_ordered(window_matches, group_key, now)
        elif ctype == SigmaCorrelationType.VALUE_SUM:
            return self._eval_value_aggregate(window_matches, group_key, now, condition, "sum")
        elif ctype == SigmaCorrelationType.VALUE_AVG:
            return self._eval_value_aggregate(window_matches, group_key, now, condition, "avg")
        elif ctype == SigmaCorrelationType.VALUE_MEDIAN:
            return self._eval_value_aggregate(window_matches, group_key, now, condition, "median")
        elif ctype == SigmaCorrelationType.VALUE_PERCENTILE:
            return self._eval_value_aggregate(
                window_matches, group_key, now, condition, "percentile"
            )
        return []

    def _compare(
        self, op: SigmaCorrelationConditionOperator, value: Any, threshold: int | float
    ) -> bool:
        """Compare a value against a threshold using the given operator."""
        if value is None:
            return False
        op_map = {
            SigmaCorrelationConditionOperator.LT: lambda a, b: a < b,
            SigmaCorrelationConditionOperator.LTE: lambda a, b: a <= b,
            SigmaCorrelationConditionOperator.GT: lambda a, b: a > b,
            SigmaCorrelationConditionOperator.GTE: lambda a, b: a >= b,
            SigmaCorrelationConditionOperator.EQ: lambda a, b: a == b,
            SigmaCorrelationConditionOperator.NEQ: lambda a, b: a != b,
        }
        return bool(op_map[op](value, threshold))

    def _collect_events(self, matches: list[SigmaMatch]) -> list[Event]:
        """Collect events from matches, respecting the max_events_per_match limit."""
        events: list[Event] = []
        limit = self.max_events_per_match
        if limit is None:
            for m in matches:
                events.extend(m.events)
        else:
            for m in matches:
                for e in m.events:
                    if len(events) >= limit:
                        return events
                    events.append(e)
        return events

    def _make_group_values(self, group_key: tuple[Any, ...]) -> dict[str, Any] | None:
        if not self.rule.group_by:
            return None
        return dict(zip(self.rule.group_by, group_key))

    def _build_correlation_match(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
    ) -> SigmaMatch:
        """Build a correlation match and bind every contributing event as evidence.

        Each evidence item carries the shift / receiving window that accepted the
        underlying event, the rule that produced the contributing match, and the
        trigger window: the rule timespan looking back from the event's timestamp.
        """
        group_values = self._make_group_values(group_key)
        evidence: list[CorrelationEvidence] = []
        for contributing_match in matches:
            rule_name = getattr(contributing_match.rule, "name", None) or ""
            for event in contributing_match.events:
                event_timestamp = event.timestamp
                evidence.append(
                    CorrelationEvidence(
                        event=event,
                        rule_name=rule_name,
                        shift=event.shift,
                        event_timestamp=event_timestamp,
                        window_start=event_timestamp
                        - timedelta(seconds=self.rule.timespan.seconds),
                        window_end=event_timestamp,
                        timespan_seconds=self.rule.timespan.seconds,
                        group_values=group_values,
                    )
                )
        return SigmaMatch(
            rule=self.rule,
            events=self._collect_events(matches),
            timestamp=now,
            group_values=group_values,
            evidence=evidence,
        )

    def _eval_event_count(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
        condition: Any,
    ) -> list[SigmaMatch]:
        if not isinstance(condition, SigmaCorrelationCondition):
            return []
        count = len(matches)
        if self._compare(condition.op, count, condition.count):
            return [self._build_correlation_match(matches, group_key, now)]
        return []

    def _eval_value_count(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
        condition: Any,
    ) -> list[SigmaMatch]:
        if not isinstance(condition, SigmaCorrelationCondition):
            return []
        field_ref = condition.fieldref
        if field_ref is None:
            return []
        # Count distinct values of the field
        values: set[Any] = set()
        for m in matches:
            for e in m.events:
                val = e.data.get(field_ref)  # type: ignore[arg-type]
                if val is not None:
                    values.add(val)
        if self._compare(condition.op, len(values), condition.count):
            return [self._build_correlation_match(matches, group_key, now)]
        return []

    def _eval_extended_expr(
        self, node: CorrelationConditionItem | SigmaRuleReference, fired_rules: set[str]
    ) -> bool:
        """Recursively evaluate a boolean extended correlation condition expression."""
        if isinstance(node, SigmaRuleReference):
            return node.reference in fired_rules
        elif isinstance(node, CorrelationConditionAND):
            return all(self._eval_extended_expr(arg, fired_rules) for arg in node.args)
        elif isinstance(node, CorrelationConditionOR):
            return any(self._eval_extended_expr(arg, fired_rules) for arg in node.args)
        elif isinstance(node, CorrelationConditionNOT):
            return not self._eval_extended_expr(node.args[0], fired_rules)
        return False

    def _eval_ordered_extended_expr(
        self,
        node: CorrelationConditionItem | SigmaRuleReference,
        rule_first_fire: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Evaluate a boolean expression with ordering constraints.

        Returns (satisfied, last_timestamp) where last_timestamp is the timestamp of the
        last positively matched rule in the sub-expression (None for negated sub-expressions).
        For AND, each successive operand's first-fire timestamp must be >= previous operand's.
        """
        if isinstance(node, SigmaRuleReference):
            ts = rule_first_fire.get(node.reference)
            return ts is not None, ts
        elif isinstance(node, CorrelationConditionAND):
            last_ts: Any = None
            for arg in node.args:
                ok, ts = self._eval_ordered_extended_expr(arg, rule_first_fire)
                if not ok:
                    return False, None
                if last_ts is not None and ts is not None and ts < last_ts:
                    return False, None
                if ts is not None:
                    last_ts = ts
            return True, last_ts
        elif isinstance(node, CorrelationConditionOR):
            for arg in node.args:
                ok, ts = self._eval_ordered_extended_expr(arg, rule_first_fire)
                if ok:
                    return True, ts
            return False, None
        elif isinstance(node, CorrelationConditionNOT):
            ok, _ = self._eval_ordered_extended_expr(node.args[0], rule_first_fire)
            return not ok, None
        return False, None

    def _eval_temporal(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
    ) -> list[SigmaMatch]:
        """All referenced rules must fire within the time window."""
        if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
            fired_rules: set[str] = {
                name for m in matches if (name := getattr(m.rule, "name", None))
            }
            if self._eval_extended_expr(self.rule.condition.parsed, fired_rules):
                return [self._build_correlation_match(matches, group_key, now)]
            return []
        matched_rules: set[str] = set()
        for m in matches:
            if hasattr(m.rule, "name") and m.rule.name:
                matched_rules.add(m.rule.name)
        if self._rule_names and self._rule_names.issubset(matched_rules):
            return [self._build_correlation_match(matches, group_key, now)]
        return []

    def _eval_temporal_ordered(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
    ) -> list[SigmaMatch]:
        """All referenced rules must fire in order within the time window."""
        if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
            rule_first_fire: dict[str, Any] = {}
            for m in sorted(matches, key=lambda x: x.timestamp):
                name = getattr(m.rule, "name", None)
                if name and name not in rule_first_fire:
                    rule_first_fire[name] = m.timestamp
            ok, _ = self._eval_ordered_extended_expr(self.rule.condition.parsed, rule_first_fire)
            if ok:
                return [self._build_correlation_match(matches, group_key, now)]
            return []
        if not self.rule.rules:
            return []
        expected_order = [ref.reference for ref in self.rule.rules]
        # Find first occurrence of each in order
        seen_idx = 0
        for m in sorted(matches, key=lambda x: x.timestamp):
            if hasattr(m.rule, "name") and m.rule.name == expected_order[seen_idx]:
                seen_idx += 1
                if seen_idx >= len(expected_order):
                    return [self._build_correlation_match(matches, group_key, now)]
        return []

    def _eval_value_aggregate(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
        condition: Any,
        agg_type: str,
    ) -> list[SigmaMatch]:
        if not isinstance(condition, SigmaCorrelationCondition):
            return []
        field_ref = condition.fieldref
        if field_ref is None:
            return []

        values: list[float] = []
        for m in matches:
            for e in m.events:
                val = e.data.get(field_ref)  # type: ignore[arg-type]
                if val is not None:
                    try:
                        values.append(float(val))
                    except (ValueError, TypeError):
                        pass

        if not values:
            return []

        if agg_type == "sum":
            result = sum(values)
        elif agg_type == "avg":
            result = sum(values) / len(values)
        elif agg_type == "median":
            result = median(values)
        elif agg_type == "percentile":
            percentile = condition.percentile or 95
            sorted_vals = sorted(values)
            idx = int(len(sorted_vals) * percentile / 100)
            idx = min(idx, len(sorted_vals) - 1)
            result = sorted_vals[idx]
        else:
            return []

        if self._compare(condition.op, result, condition.count):
            return [self._build_correlation_match(matches, group_key, now)]
        return []
