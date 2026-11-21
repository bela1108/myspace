from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Iterable, Self

from sigma.collection import SigmaCollection
from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
    SigmaExtendedCorrelationCondition,
)
from sigma.exceptions import SigmaBackendError, SigmaFeatureNotSupportedByBackendError
from sigma.matching.compiler import MatchCompiler
from sigma.matching.event import Event, EventLogSource
from sigma.matching.rule_matcher import SigmaRuleMatcher
from sigma.rule.logsource import SigmaLogSource
from sigma.rule.rule import SigmaRule


class SemanticReferenceError(SigmaBackendError):
    """Raised when the semantic reference backend cannot evaluate its input unambiguously."""


class GroupKeySkipReason(StrEnum):
    """Machine-readable reasons why a base match did not enter correlation state."""

    MISSING_FIELD = "missing-group-field"
    UNHASHABLE_VALUE = "unhashable-group-value"


@dataclass(frozen=True)
class UnsupportedOperation:
    """A correlation feature that this deliberately small backend does not evaluate."""

    rule: SigmaCorrelationRule | None
    operation: str
    detail: str

    @property
    def rule_name(self) -> str | None:
        return _rule_label(self.rule) if self.rule is not None else None

    def __str__(self) -> str:
        location = f"{self.rule_name}: " if self.rule_name else ""
        return f"{location}{self.operation}: {self.detail}"


@dataclass(frozen=True)
class SkippedMatch:
    """A base-rule match rejected before it could affect a correlation count."""

    rule: SigmaCorrelationRule
    base_rule: SigmaRule
    event: Event
    sequence: int
    reason: GroupKeySkipReason
    missing_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class SemanticEvidence:
    """An original input event used by a hit or retained group count."""

    event: Event
    sequence: int
    source_rules: tuple[str, ...]


@dataclass(frozen=True)
class SemanticCorrelationHit:
    """One correlation hit with its exact witness events."""

    rule: SigmaCorrelationRule
    group_key: tuple[Any, ...]
    group_values: dict[str, Any] | None
    timestamp: datetime
    sequence: int
    count: int
    evidence: tuple[SemanticEvidence, ...]

    @property
    def window_start(self) -> datetime:
        """Inclusive lower bound of the evaluated window."""

        return self.timestamp - timedelta(seconds=self.rule.timespan.seconds)


@dataclass(frozen=True)
class GroupCount:
    """The retained window count and events for one correlation group."""

    rule: SigmaCorrelationRule
    group_key: tuple[Any, ...]
    group_values: dict[str, Any] | None
    timestamp: datetime
    count: int
    evidence: tuple[SemanticEvidence, ...]

    @property
    def window_start(self) -> datetime:
        """Inclusive lower bound of the counted window."""

        return self.timestamp - timedelta(seconds=self.rule.timespan.seconds)


@dataclass(frozen=True)
class BaseMatchObservation:
    """A base-rule match observed before correlation semantics are applied."""

    rule: SigmaRule
    event: Event
    sequence: int


@dataclass(frozen=True)
class SemanticReferenceReport:
    """Complete snapshot produced by the reference backend."""

    base_matches: tuple[BaseMatchObservation, ...] = ()
    hits: tuple[SemanticCorrelationHit, ...] = ()
    group_counts: tuple[GroupCount, ...] = ()
    skipped: tuple[SkippedMatch, ...] = ()
    unsupported: tuple[UnsupportedOperation, ...] = ()

    @property
    def unsupported_operations(self) -> tuple[UnsupportedOperation, ...]:
        """Alias that makes unsupported-operation markers easy to find in reports."""

        return self.unsupported

    def assert_supported(self) -> None:
        """Raise if any correlation feature in the collection was not evaluated."""

        if self.unsupported:
            details = "; ".join(str(operation) for operation in self.unsupported)
            raise SigmaFeatureNotSupportedByBackendError(
                f"Semantic reference backend does not support: {details}"
            )


@dataclass
class _BaseMatch:
    rule: SigmaRule
    event: Event
    sequence: int


@dataclass
class _EventEntry:
    event: Event
    sequence: int
    source_rule_ids: set[int] = field(default_factory=set)
    source_rules: list[str] = field(default_factory=list)

    def add_source(self, rule: SigmaRule) -> None:
        if id(rule) not in self.source_rule_ids:
            self.source_rule_ids.add(id(rule))
            self.source_rules.append(_rule_label(rule))

    def evidence(self, source_rules: Iterable[str] | None = None) -> SemanticEvidence:
        rules = tuple(source_rules) if source_rules is not None else tuple(self.source_rules)
        return SemanticEvidence(event=self.event, sequence=self.sequence, source_rules=rules)


@dataclass
class _GroupState:
    entries: dict[int, _EventEntry] = field(default_factory=dict)

    def add(self, base_match: _BaseMatch) -> None:
        entry = self.entries.get(base_match.sequence)
        if entry is None:
            entry = _EventEntry(event=base_match.event, sequence=base_match.sequence)
            self.entries[base_match.sequence] = entry
        entry.add_source(base_match.rule)

    def prune(self, anchor: datetime, timespan_seconds: int) -> None:
        cutoff = anchor - timedelta(seconds=timespan_seconds)
        for sequence in tuple(self.entries):
            if self.entries[sequence].event.timestamp < cutoff:
                del self.entries[sequence]

    def ordered_entries(self) -> list[_EventEntry]:
        return list(self.entries.values())


@dataclass
class _CorrelationSpec:
    rule: SigmaCorrelationRule
    referenced_rules: tuple[SigmaRule, ...]
    groups: dict[tuple[Any, ...], _GroupState] = field(default_factory=dict)

    @property
    def referenced_rule_ids(self) -> set[int]:
        return {id(rule) for rule in self.referenced_rules}

    def extract_group(
        self, base_match: _BaseMatch
    ) -> tuple[tuple[Any, ...], dict[str, Any] | None] | SkippedMatch:
        group_by = self.rule.group_by or []
        if not group_by:
            return (), None

        values: list[Any] = []
        missing: list[str] = []
        for group_field in group_by:
            resolved_field = self._resolve_alias(group_field, base_match.rule)
            if resolved_field not in base_match.event.data:
                missing.append(resolved_field)
                values.append(None)
            else:
                values.append(base_match.event.data[resolved_field])

        if missing:
            return SkippedMatch(
                rule=self.rule,
                base_rule=base_match.rule,
                event=base_match.event,
                sequence=base_match.sequence,
                reason=GroupKeySkipReason.MISSING_FIELD,
                missing_fields=tuple(missing),
            )

        group_key = tuple(values)
        try:
            hash(group_key)
        except TypeError:
            return SkippedMatch(
                rule=self.rule,
                base_rule=base_match.rule,
                event=base_match.event,
                sequence=base_match.sequence,
                reason=GroupKeySkipReason.UNHASHABLE_VALUE,
            )

        return group_key, dict(zip(group_by, group_key))

    def _resolve_alias(self, group_field: str, source_rule: SigmaRule) -> str:
        alias = self.rule.aliases.aliases.get(group_field)
        if alias is None:
            return group_field

        for rule_reference, mapped_field in alias.mapping.items():
            if rule_reference.rule is source_rule:
                return mapped_field
        return group_field


class SemanticReferenceBackend:
    """
    Small in-memory semantic oracle for pySigma correlation rules.

    The backend intentionally supports only ``event_count`` and ``temporal_ordered``.
    Other correlation features are reported in :attr:`SemanticReferenceReport.unsupported`
    instead of being silently ignored.

    Semantics:

    * A window is inclusive at both ends: ``[anchor - timespan, anchor]``.
    * ``event_count`` counts distinct input events, not base-rule matches. If one event
      matches multiple referenced rules, it has one count and all source rules are retained
      in its evidence.
    * ``temporal_ordered`` requires each step to use a distinct input event with a strictly
      later timestamp. Equal timestamps are count-compatible but never order-compatible.
    * A match missing any ``group-by`` field is excluded from state and recorded in
      :attr:`SemanticReferenceReport.skipped`.
    * Input must be in non-decreasing timestamp order. Out-of-order input raises instead of
      producing window counts that depend on accidental arrival order.
    """

    def __init__(self, collection: SigmaCollection) -> None:
        self.collection = collection
        self._compiler = MatchCompiler()
        self._rule_matchers: list[tuple[SigmaRule, SigmaRuleMatcher]] = []
        self._unsupported: list[UnsupportedOperation] = []
        self._specs: list[_CorrelationSpec] = []
        self._reset_state()
        self._build()

    @classmethod
    def from_yaml(cls, yaml_str: str | bytes, **kwargs: Any) -> Self:
        """Convenience constructor for a YAML rule collection."""

        return cls(SigmaCollection.from_yaml(yaml_str, **kwargs))

    def _build(self) -> None:
        for rule in self.collection.rules:
            if isinstance(rule, SigmaRule):
                self._rule_matchers.append((rule, SigmaRuleMatcher(rule, self._compiler)))
            elif isinstance(rule, SigmaCorrelationRule):
                spec = self._make_spec(rule)
                if spec is not None:
                    self._specs.append(spec)

    def _make_spec(self, rule: SigmaCorrelationRule) -> _CorrelationSpec | None:
        supported = True
        if rule.type not in {
            SigmaCorrelationType.EVENT_COUNT,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        }:
            self._mark_unsupported(
                rule,
                "correlation.type",
                f"'{rule.type}' is not implemented; supported types are "
                "'event_count' and 'temporal_ordered'",
            )
            supported = False

        if isinstance(rule.condition, SigmaExtendedCorrelationCondition):
            self._mark_unsupported(
                rule,
                "correlation.condition",
                "extended boolean correlation conditions are not implemented",
            )
            supported = False
        elif not isinstance(rule.condition, SigmaCorrelationCondition):
            self._mark_unsupported(
                rule,
                "correlation.condition",
                "only basic count conditions are implemented",
            )
            supported = False
        elif rule.type == SigmaCorrelationType.EVENT_COUNT and rule.condition.fieldref is not None:
            self._mark_unsupported(
                rule,
                "correlation.condition.field",
                "event_count conditions with a field selector are not implemented",
            )
            supported = False

        references = rule.rules or []
        if not references:
            self._mark_unsupported(
                rule,
                "correlation.rules",
                "the correlation rule has no resolvable rule references",
            )
            supported = False

        referenced_rules: list[SigmaRule] = []
        for reference in references:
            resolved = getattr(reference, "rule", None)
            if not isinstance(resolved, SigmaRule):
                self._mark_unsupported(
                    rule,
                    "correlation.rules",
                    f"reference '{reference.reference}' does not resolve to a base SigmaRule",
                )
                supported = False
                continue
            referenced_rules.append(resolved)

        if (
            rule.type == SigmaCorrelationType.TEMPORAL_ORDERED
            and isinstance(rule.condition, SigmaCorrelationCondition)
            and (
                rule.condition.fieldref is not None
                or rule.condition.op != SigmaCorrelationConditionOperator.GTE
                or rule.condition.count != len(references)
            )
        ):
            self._mark_unsupported(
                rule,
                "correlation.condition",
                "temporal_ordered only supports its default all-rules condition",
            )
            supported = False

        if not supported:
            return None

        return _CorrelationSpec(rule=rule, referenced_rules=tuple(referenced_rules))

    def _mark_unsupported(self, rule: SigmaCorrelationRule, operation: str, detail: str) -> None:
        self._unsupported.append(
            UnsupportedOperation(rule=rule, operation=operation, detail=detail)
        )

    def _reset_state(self) -> None:
        self._next_sequence = 0
        self._last_timestamp: datetime | None = None
        self._base_matches: list[BaseMatchObservation] = []
        self._hits: list[SemanticCorrelationHit] = []
        self._skipped: list[SkippedMatch] = []
        for spec in getattr(self, "_specs", []):
            spec.groups.clear()

    def reset(self) -> None:
        """Discard evaluated events while keeping the compiled collection."""

        self._reset_state()

    def evaluate(self, events: Iterable[Event]) -> SemanticReferenceReport:
        """Reset and evaluate a finite batch of synthetic events."""

        self.reset()
        for event in events:
            self.push(event)
        return self.report()

    def push(self, event: Event) -> tuple[SemanticCorrelationHit, ...]:
        """Evaluate one event and return only the hits triggered by that event."""

        self._validate_event(event)
        sequence = self._next_sequence
        self._next_sequence += 1

        event_matches = self._match_base_rules(event, sequence)
        self._base_matches.extend(
            BaseMatchObservation(rule=match.rule, event=event, sequence=sequence)
            for match in event_matches
        )

        hits: list[SemanticCorrelationHit] = []
        matched_rule_ids = {id(match.rule) for match in event_matches}
        for spec in self._specs:
            if not matched_rule_ids.intersection(spec.referenced_rule_ids):
                continue

            relevant = [
                match for match in event_matches if id(match.rule) in spec.referenced_rule_ids
            ]
            hits.extend(self._ingest(spec, relevant, anchor=event))

        self._last_timestamp = event.timestamp
        self._hits.extend(hits)
        return tuple(hits)

    def report(self) -> SemanticReferenceReport:
        """Return the current report, pruning retained windows to the latest timestamp."""

        group_counts: list[GroupCount] = []
        if self._last_timestamp is not None:
            for spec in self._specs:
                for group_key, state in spec.groups.items():
                    state.prune(self._last_timestamp, spec.rule.timespan.seconds)
                    entries = state.ordered_entries()
                    group_counts.append(
                        GroupCount(
                            rule=spec.rule,
                            group_key=group_key,
                            group_values=_group_values(spec.rule, group_key),
                            timestamp=self._last_timestamp,
                            count=len(entries),
                            evidence=tuple(entry.evidence() for entry in entries),
                        )
                    )

        group_counts.sort(
            key=lambda count: (
                _rule_label(count.rule),
                repr(count.group_key),
            )
        )
        return SemanticReferenceReport(
            base_matches=tuple(self._base_matches),
            hits=tuple(self._hits),
            group_counts=tuple(group_counts),
            skipped=tuple(self._skipped),
            unsupported=tuple(self._unsupported),
        )

    def _validate_event(self, event: Event) -> None:
        if not isinstance(event.timestamp, datetime):
            raise SemanticReferenceError(
                f"event {self._next_sequence} has a non-datetime timestamp"
            )
        if event.timestamp.tzinfo is None or event.timestamp.utcoffset() is None:
            raise SemanticReferenceError(
                f"event {self._next_sequence} has a timezone-naive timestamp"
            )
        if self._last_timestamp is not None and event.timestamp < self._last_timestamp:
            raise SemanticReferenceError(
                f"event {self._next_sequence} is out of order: {event.timestamp.isoformat()} "
                f"precedes {self._last_timestamp.isoformat()}"
            )

    def _match_base_rules(self, event: Event, sequence: int) -> list[_BaseMatch]:
        matches: list[_BaseMatch] = []
        for rule, matcher in self._rule_matchers:
            if not _logsource_contains(rule.logsource, event.logsource):
                continue
            if matcher.matches(event) is not None:
                matches.append(_BaseMatch(rule=rule, event=event, sequence=sequence))
        return matches

    def _ingest(
        self,
        spec: _CorrelationSpec,
        matches: list[_BaseMatch],
        anchor: Event,
    ) -> list[SemanticCorrelationHit]:
        touched_groups: set[tuple[Any, ...]] = set()
        for match in matches:
            extracted = spec.extract_group(match)
            if isinstance(extracted, SkippedMatch):
                self._skipped.append(extracted)
                continue
            group_key, _ = extracted
            state = spec.groups.get(group_key)
            if state is None:
                state = _GroupState()
                spec.groups[group_key] = state
            state.add(match)
            touched_groups.add(group_key)

        hits: list[SemanticCorrelationHit] = []
        for group_key in sorted(touched_groups, key=repr):
            state = spec.groups[group_key]
            state.prune(anchor.timestamp, spec.rule.timespan.seconds)
            entries = state.ordered_entries()
            if spec.rule.type == SigmaCorrelationType.EVENT_COUNT:
                hit = self._event_count_hit(spec, group_key, entries, anchor)
            else:
                hit = self._temporal_ordered_hit(spec, group_key, entries, anchor)
            if hit is not None:
                hits.append(hit)
        return hits

    def _event_count_hit(
        self,
        spec: _CorrelationSpec,
        group_key: tuple[Any, ...],
        entries: list[_EventEntry],
        anchor: Event,
    ) -> SemanticCorrelationHit | None:
        condition = spec.rule.condition
        if not isinstance(condition, SigmaCorrelationCondition):
            return None
        count = len(entries)
        if not _compare(condition.op, count, condition.count):
            return None
        return SemanticCorrelationHit(
            rule=spec.rule,
            group_key=group_key,
            group_values=_group_values(spec.rule, group_key),
            timestamp=anchor.timestamp,
            sequence=self._next_sequence - 1,
            count=count,
            evidence=tuple(entry.evidence() for entry in entries),
        )

    def _temporal_ordered_hit(
        self,
        spec: _CorrelationSpec,
        group_key: tuple[Any, ...],
        entries: list[_EventEntry],
        anchor: Event,
    ) -> SemanticCorrelationHit | None:
        expected_rules = spec.referenced_rules
        if not expected_rules:
            return None

        chain = _find_ordered_chain(entries, expected_rules, anchor, self._next_sequence - 1)
        if chain is None:
            return None

        evidence = tuple(entry.evidence((_rule_label(rule),)) for entry, rule in chain)
        return SemanticCorrelationHit(
            rule=spec.rule,
            group_key=group_key,
            group_values=_group_values(spec.rule, group_key),
            timestamp=anchor.timestamp,
            sequence=self._next_sequence - 1,
            count=len(evidence),
            evidence=evidence,
        )


def _find_ordered_chain(
    entries: list[_EventEntry],
    expected_rules: tuple[SigmaRule, ...],
    anchor: Event,
    anchor_sequence: int,
) -> list[tuple[_EventEntry, SigmaRule]] | None:
    """
    Find the lexicographically earliest ordered witness ending at ``anchor``.

    The timestamp comparison is strict. This makes same-timestamp events
    count-compatible but never order-compatible.
    """

    candidates = [
        [
            entry
            for entry in entries
            if id(rule) in entry.source_rule_ids and entry.event.timestamp <= anchor.timestamp
        ]
        for rule in expected_rules
    ]
    if any(not rule_candidates for rule_candidates in candidates):
        return None

    last_position = len(expected_rules) - 1
    memo: dict[tuple[int, datetime], list[tuple[_EventEntry, SigmaRule]] | None] = {}

    def search(
        position: int, previous_timestamp: datetime | None
    ) -> list[tuple[_EventEntry, SigmaRule]] | None:
        memo_key = (position, previous_timestamp)  # type: ignore[arg-type]
        if memo_key in memo:
            return memo[memo_key]

        for entry in candidates[position]:
            if previous_timestamp is not None and entry.event.timestamp <= previous_timestamp:
                continue
            if position == last_position:
                if entry.sequence != anchor_sequence:
                    continue
                result = [(entry, expected_rules[position])]
                memo[memo_key] = result
                return result

            tail = search(position + 1, entry.event.timestamp)
            if tail is not None:
                result = [(entry, expected_rules[position]), *tail]
                memo[memo_key] = result
                return result

        memo[memo_key] = None
        return None

    return search(0, None)


def _logsource_contains(rule_logsource: SigmaLogSource, event_logsource: EventLogSource) -> bool:
    event = SigmaLogSource(
        category=event_logsource.category,
        product=event_logsource.product,
        service=event_logsource.service,
    )
    return event in rule_logsource


def _group_values(rule: SigmaCorrelationRule, group_key: tuple[Any, ...]) -> dict[str, Any] | None:
    if not rule.group_by:
        return None
    return dict(zip(rule.group_by, group_key))


def _rule_label(rule: SigmaRule | SigmaCorrelationRule) -> str:
    return rule.name or rule.title or str(rule.id)


def _compare(
    operator: SigmaCorrelationConditionOperator,
    value: int,
    threshold: int | float,
) -> bool:
    if operator == SigmaCorrelationConditionOperator.LT:
        return value < threshold
    if operator == SigmaCorrelationConditionOperator.LTE:
        return value <= threshold
    if operator == SigmaCorrelationConditionOperator.GT:
        return value > threshold
    if operator == SigmaCorrelationConditionOperator.GTE:
        return value >= threshold
    if operator == SigmaCorrelationConditionOperator.EQ:
        return value == threshold
    if operator == SigmaCorrelationConditionOperator.NEQ:
        return value != threshold
    raise SemanticReferenceError(f"unsupported correlation condition operator: {operator}")
