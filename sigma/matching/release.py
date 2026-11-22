from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Iterable, Sequence

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule, SigmaExtendedCorrelationCondition
from sigma.matching.compiler import MatchCompiler
from sigma.matching.event import Event
from sigma.matching.matcher import SigmaMatcher
from sigma.rule.rule import SigmaRule


class ReleaseOrder(str, Enum):
    """Rollout order of a base-rule and correlation-rule migration."""

    BASE_FIRST = "base_first"
    CORRELATION_FIRST = "correlation_first"


class SignalStatus(str, Enum):
    """Assessment result for one demo signal in one rollout stage."""

    COMPLETE = "complete"
    """All dependencies are present and the marker events produce the signal."""

    NOT_FIRED = "not_fired"
    """All dependencies are present, but the marker events do not produce the signal."""

    INCOMPLETE = "incomplete"
    """At least one referenced base rule is missing, so the signal cannot be fully decided."""

    MISSING = "missing"
    """The correlation rule that defines the signal is not deployed in this stage."""

    ERROR = "error"
    """A rule in this stage fails to compile, so the signal cannot be evaluated."""


@dataclass(frozen=True)
class MarkerEvent:
    """A named, ordinary event used to demonstrate whether a security signal is alive."""

    name: str
    event: Event


@dataclass(frozen=True)
class DependencyStatus:
    """Static dependency check for one deployed correlation rule."""

    correlation: str
    required_rules: tuple[str, ...] = ()
    missing_rules: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.missing_rules


@dataclass(frozen=True)
class SignalAssessment:
    """Result of evaluating one demo signal against one rollout stage."""

    name: str
    status: SignalStatus
    fired: bool = False
    compiled: bool = True
    required_rules: tuple[str, ...] = ()
    missing_rules: tuple[str, ...] = ()
    matched_markers: tuple[str, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class StageAssessment:
    """Snapshot of one rollout stage and the demo signals it can decide."""

    key: str
    label: str
    start_minute: int | None
    end_minute: int | None
    rule_names: tuple[str, ...]
    base_rule_names: tuple[str, ...]
    correlation_rule_names: tuple[str, ...]
    signals: dict[str, SignalAssessment] = field(default_factory=dict)
    dependencies: tuple[DependencyStatus, ...] = ()
    compiled: bool = True
    compile_errors: tuple[str, ...] = ()
    rule_objects: tuple[SigmaRule | SigmaCorrelationRule, ...] = field(
        default=(), repr=False, compare=False
    )

    def signal(self, name: str) -> SignalAssessment:
        return self.signals[name]

    def loses(self, signal: str) -> bool:
        return self.signals[signal].status is not SignalStatus.COMPLETE

    def minute_label(self) -> str:
        if self.start_minute is None:
            return "baseline"
        start = f"{self.start_minute // 60:02d}:{self.start_minute % 60:02d}"
        if self.end_minute is None:
            return f"{start}+"
        end_minute = self.end_minute - 1
        end = f"{end_minute // 60:02d}:{end_minute % 60:02d}"
        return start if start == end else f"{start}-{end}"


@dataclass
class ReleaseOrderAssessment:
    """Result of one of the two compared rollout orders."""

    order: ReleaseOrder
    stages: tuple[StageAssessment, ...]
    first_loss: dict[str, int | None] = field(default_factory=dict)
    final_rules_identical: bool = True

    def stage_at(self, minute: int) -> StageAssessment:
        """Return the stage that is active at *minute* (minutes after effective time)."""
        for stage in self.stages:
            if stage.start_minute is None:
                continue
            if stage.start_minute <= minute and (
                stage.end_minute is None or minute < stage.end_minute
            ):
                return stage
        raise IndexError(f"No rollout stage active at minute {minute}")


@dataclass
class ReleaseOrderReport:
    """Offline verification of two possible release orders."""

    effective_at: datetime
    rollout_minutes: int
    phase_minutes: int
    signals: tuple[str, ...]
    orders: dict[ReleaseOrder, ReleaseOrderAssessment]
    old_baseline: StageAssessment
    new_baseline: StageAssessment
    final_rules_identical: bool = True

    def order(self, order: ReleaseOrder | str) -> ReleaseOrderAssessment:
        """Return the assessment for a release order (enum or value string)."""
        return self.orders[ReleaseOrder(order)]

    def first_loss(self, order: ReleaseOrder | str) -> dict[str, int | None]:
        """First minute at which each demo signal is no longer complete, for one order."""
        return self.order(order).first_loss

    def minute_rows(self) -> list[dict[str, Any]]:
        """Return one row per minute, for callers that need minute-level data."""
        rows: list[dict[str, Any]] = []
        for order, assessment in self.orders.items():
            for minute in range(self.rollout_minutes):
                stage = assessment.stage_at(minute)
                row: dict[str, Any] = {
                    "order": order,
                    "minute": minute,
                    "stage": stage.key,
                }
                for signal in self.signals:
                    row[signal] = stage.signal(signal).status
                rows.append(row)
        return rows

    def to_table(self, compact: bool = True) -> str:
        """
        Render both release orders as a compact effectiveness table.

        With *compact* (the default) consecutive minutes belonging to the same stage are
        combined into one range. With ``compact=False`` each minute gets its own row.
        """
        lines: list[str] = []
        lines.append(
            f"Release order check | effective {self.effective_at.isoformat()} | "
            f"rollout {self.rollout_minutes} min | phase boundary {self.phase_minutes} min"
        )
        lines.append(
            "Legend: OK=signal produced, NO FIRE=dependencies complete but no match, "
            "GAP=missing base rule, MISSING=correlation absent, ERR=compile error"
        )
        lines.append(
            f"Baselines: old={'OK' if self._baseline_ok(self.old_baseline) else 'GAP'} "
            f"new={'OK' if self._baseline_ok(self.new_baseline) else 'GAP'}"
        )

        for order, assessment in self.orders.items():
            lines.append("")
            lines.append(f"{order.value} ({_order_description(order)})")
            if compact:
                lines.extend(self._render_rows(assessment.stages, self.signals))
            else:
                lines.extend(self._render_minutes(assessment, self.signals))

            lost = {
                signal: minute
                for signal, minute in assessment.first_loss.items()
                if minute is not None
            }
            if lost:
                for signal, minute in lost.items():
                    stage = assessment.stage_at(minute)
                    sa = stage.signal(signal)
                    reason = sa.detail
                    if sa.missing_rules:
                        reason = f"missing base rules: {', '.join(sa.missing_rules)}"
                    lines.append(
                        f"first loss: {signal} at minute {minute} "
                        f"({_minute_text(self.effective_at, minute)}) - {reason}"
                    )
            else:
                lines.append("first loss: none")
            lines.append(
                "final rules identical to new collection: "
                f"{'yes' if assessment.final_rules_identical else 'no'}"
            )

        return "\n".join(lines)

    def render(self, compact: bool = True) -> str:
        """Alias for :meth:`to_table`."""
        return self.to_table(compact=compact)

    def __str__(self) -> str:
        return self.to_table()

    @staticmethod
    def _baseline_ok(stage: StageAssessment) -> bool:
        return (
            stage.compiled
            and all(s.status is SignalStatus.COMPLETE for s in stage.signals.values())
        )

    def _render_rows(self, stages: Sequence[StageAssessment], signals: Sequence[str]) -> list[str]:
        headers = ["minute", "stage", "compile"] + list(signals) + ["missing rules"]
        rows: list[list[str]] = []
        for stage in stages:
            row = [stage.minute_label(), stage.label, "OK" if stage.compiled else "ERR"]
            missing: set[str] = set()
            for signal in signals:
                sa = stage.signal(signal)
                row.append(_status_short(sa.status))
                missing.update(sa.missing_rules)
            row.append(", ".join(sorted(missing)) if missing else "-")
            rows.append(row)
        return _ascii_table(headers, rows)

    def _render_minutes(
        self, assessment: ReleaseOrderAssessment, signals: Sequence[str]
    ) -> list[str]:
        headers = ["minute", "stage"] + list(signals)
        rows: list[list[str]] = []
        for minute in range(self.rollout_minutes):
            stage = assessment.stage_at(minute)
            row = [_offset_text(minute), stage.key]
            row.extend(_status_short(stage.signal(signal).status) for signal in signals)
            rows.append(row)
        return _ascii_table(headers, rows)


class ReleaseOrderVerifier:
    """
    Offline release-order verification for base-rule/correlation-rule migrations.

    The verifier compares two rollout orders for the same old and new rule collections:

    * :attr:`ReleaseOrder.BASE_FIRST` installs the new base rules while the old correlation
      rule is still active, then switches the correlation rule and finally retires old rules.
    * :attr:`ReleaseOrder.CORRELATION_FIRST` switches the correlation rule before the new base
      rules exist, then installs the new base rules and finally retires old rules.

    Rules are parsed with :class:`~sigma.collection.SigmaCollection` and evaluated with the
    existing :class:`~sigma.matching.SigmaMatcher`. Marker events are replayed against every
    stage snapshot, so a correlation rule that compiles but references an undeployed base rule
    is reported as ``INCOMPLETE`` rather than silently not firing.
    """

    def __init__(
        self,
        old_rules: SigmaCollection | str | bytes | Iterable[Any],
        new_rules: SigmaCollection | str | bytes | Iterable[Any],
        effective_at: datetime,
        marker_events: Iterable[Event | MarkerEvent],
        *,
        rollout_minutes: int = 60,
        phase_minutes: int | None = None,
        signal_names: Iterable[str] | None = None,
        max_events_per_match: int | None = 100,
        max_correlation_state: int | None = None,
    ) -> None:
        if not isinstance(effective_at, datetime):
            raise TypeError("effective_at must be a datetime")

        self.old_rules = _coerce_collection(old_rules, "old_rules")
        self.new_rules = _coerce_collection(new_rules, "new_rules")
        self.effective_at = effective_at
        self.rollout_minutes = int(rollout_minutes)
        if self.rollout_minutes <= 0:
            raise ValueError("rollout_minutes must be greater than zero")
        if phase_minutes is None:
            phase_minutes = self.rollout_minutes // 2
        self.phase_minutes = int(phase_minutes)
        if not 0 < self.phase_minutes < self.rollout_minutes:
            raise ValueError("phase_minutes must be greater than 0 and less than rollout_minutes")

        self.markers = _coerce_markers(marker_events)
        self.max_events_per_match = max_events_per_match
        self.max_correlation_state = max_correlation_state
        self._compiler = MatchCompiler()

        discovered = _signal_names(self.old_rules) + _signal_names(self.new_rules)
        if signal_names is None:
            self.signal_names = tuple(dict.fromkeys(discovered))
        else:
            self.signal_names = tuple(dict.fromkeys(str(name) for name in signal_names))

    def verify(self) -> ReleaseOrderReport:
        """Run the verification and return a structured report."""
        old_baseline = self._assess_stage(
            key="old_baseline",
            label="old rule set",
            start_minute=None,
            end_minute=None,
            rules=list(self.old_rules.rules),
        )
        new_baseline = self._assess_stage(
            key="new_baseline",
            label="new rule set",
            start_minute=None,
            end_minute=None,
            rules=list(self.new_rules.rules),
        )

        old_split = _split_rules(self.old_rules.rules)
        new_split = _split_rules(self.new_rules.rules)
        merged_bases = dict(old_split.bases)
        merged_bases.update(new_split.bases)

        final_signature = _collection_signature(self.new_rules.rules)
        orders: dict[ReleaseOrder, ReleaseOrderAssessment] = {}

        for order in (ReleaseOrder.BASE_FIRST, ReleaseOrder.CORRELATION_FIRST):
            if order is ReleaseOrder.BASE_FIRST:
                first_rules = list(merged_bases.values()) + list(
                    old_split.correlations.values()
                )
                second_rules = list(merged_bases.values()) + list(
                    new_split.correlations.values()
                )
                first_label = "new base rules installed; old correlation still active"
                second_label = "correlation switched to new base rules"
            else:
                first_rules = list(old_split.bases.values()) + list(
                    new_split.correlations.values()
                )
                second_rules = list(merged_bases.values()) + list(
                    new_split.correlations.values()
                )
                first_label = "correlation switched first; new base rules missing"
                second_label = "new base rules installed"

            first_stage = self._assess_stage(
                key=f"{order.value}_phase_1",
                label=first_label,
                start_minute=0,
                end_minute=self.phase_minutes,
                rules=first_rules,
            )
            second_stage = self._assess_stage(
                key=f"{order.value}_phase_2",
                label=second_label,
                start_minute=self.phase_minutes,
                end_minute=self.rollout_minutes,
                rules=second_rules,
            )
            final_rules = list(self.new_rules.rules)
            final_stage = self._assess_stage(
                key=f"{order.value}_final",
                label="old rules retired; final rule set",
                start_minute=self.rollout_minutes,
                end_minute=None,
                rules=final_rules,
            )
            stages = (first_stage, second_stage, final_stage)
            first_loss = {
                signal: _first_loss_minute(stages, signal) for signal in self.signal_names
            }
            orders[order] = ReleaseOrderAssessment(
                order=order,
                stages=stages,
                first_loss=first_loss,
                final_rules_identical=(
                    _collection_signature(final_stage.rule_objects) == final_signature
                ),
            )

        final_identical = all(a.final_rules_identical for a in orders.values())
        return ReleaseOrderReport(
            effective_at=self.effective_at,
            rollout_minutes=self.rollout_minutes,
            phase_minutes=self.phase_minutes,
            signals=self.signal_names,
            orders=orders,
            old_baseline=old_baseline,
            new_baseline=new_baseline,
            final_rules_identical=final_identical,
        )

    def render(self) -> str:
        """Run the verification and render the effectiveness table."""
        return self.verify().to_table()

    def _assess_stage(
        self,
        key: str,
        label: str,
        start_minute: int | None,
        end_minute: int | None,
        rules: Sequence[SigmaRule | SigmaCorrelationRule],
    ) -> StageAssessment:
        deduped = _dedupe_rules(rules)
        collection = SigmaCollection(init_rules=list(deduped), resolve_references=False)

        base_rules = [rule for rule in deduped if isinstance(rule, SigmaRule)]
        correlation_rules = [
            rule for rule in deduped if isinstance(rule, SigmaCorrelationRule)
        ]
        active_names = {
            name for rule in deduped if (name := getattr(rule, "name", None)) is not None
        }
        corr_by_name: dict[str, SigmaCorrelationRule] = {}
        for rule in correlation_rules:
            corr_by_name.setdefault(_correlation_name(rule), rule)

        dependencies = tuple(
            DependencyStatus(
                correlation=_correlation_name(rule),
                required_rules=tuple(_correlation_required_rules(rule)),
                missing_rules=tuple(
                    sorted(
                        _missing_dependency_rules(
                            _correlation_name(rule),
                            active_names,
                            corr_by_name,
                            _correlation_required_rules(rule),
                            set(),
                        )
                    )
                ),
            )
            for rule in correlation_rules
        )

        compile_errors: list[str] = []
        for rule in base_rules:
            try:
                self._compiler.compile_rule(rule)
            except Exception as e:  # noqa: BLE001 - surfaced to the report
                compile_errors.append(f"{rule.name or rule.title}: {e}")
        compiled = not compile_errors

        fired: dict[str, set[str]] = {}
        if compiled:
            try:
                matcher = SigmaMatcher(
                    collection,
                    max_events_per_match=self.max_events_per_match,
                    max_correlation_state=self.max_correlation_state,
                )
            except Exception as e:  # noqa: BLE001 - surfaced to the report
                compile_errors.append(f"matcher: {e}")
                compiled = False
            else:
                marker_by_id = {id(marker.event): marker.name for marker in self.markers}
                events = [marker.event for marker in self.markers]
                try:
                    matches = matcher.bulk_match(
                        sorted(events, key=lambda event: event.timestamp)
                    )
                except Exception as e:  # noqa: BLE001 - surfaced to the report
                    compile_errors.append(f"matching: {e}")
                    compiled = False
                else:
                    for match in matches:
                        if not isinstance(match.rule, SigmaCorrelationRule):
                            continue
                        name = _correlation_name(match.rule)
                        matched = fired.setdefault(name, set())
                        for event in match.events:
                            marker_name = marker_by_id.get(id(event))
                            if marker_name is not None:
                                matched.add(marker_name)

        signal_assessments: dict[str, SignalAssessment] = {}
        for signal in self.signal_names:
            present = [
                rule for rule in correlation_rules if _correlation_name(rule) == signal
            ]
            if not present:
                signal_assessments[signal] = SignalAssessment(
                    name=signal,
                    status=SignalStatus.MISSING,
                    compiled=compiled,
                    detail="correlation rule is not deployed in this stage",
                )
                continue

            required: list[str] = []
            missing: list[str] = []
            for rule in present:
                required.extend(_correlation_required_rules(rule))
                missing.extend(
                    _missing_dependency_rules(
                        _correlation_name(rule),
                        active_names,
                        corr_by_name,
                        _correlation_required_rules(rule),
                        set(),
                    )
                )
            required = list(dict.fromkeys(required))
            missing = sorted(set(missing))

            if missing:
                status = SignalStatus.INCOMPLETE
                detail = "missing base rules: " + ", ".join(missing)
            elif not compiled:
                status = SignalStatus.ERROR
                detail = "; ".join(compile_errors)
            elif signal in fired:
                status = SignalStatus.COMPLETE
                detail = "signal produced"
            else:
                status = SignalStatus.NOT_FIRED
                detail = "dependencies complete but marker events do not produce the signal"

            signal_assessments[signal] = SignalAssessment(
                name=signal,
                status=status,
                fired=signal in fired,
                compiled=compiled,
                required_rules=tuple(required),
                missing_rules=tuple(missing),
                matched_markers=tuple(sorted(fired.get(signal, set()))),
                detail=detail,
            )

        return StageAssessment(
            key=key,
            label=label,
            start_minute=start_minute,
            end_minute=end_minute,
            rule_names=tuple(sorted(rule.name or rule.title for rule in deduped)),
            base_rule_names=tuple(sorted(rule.name or rule.title for rule in base_rules)),
            correlation_rule_names=tuple(
                sorted(_correlation_name(rule) for rule in correlation_rules)
            ),
            signals=signal_assessments,
            dependencies=dependencies,
            compiled=compiled,
            compile_errors=tuple(compile_errors),
            rule_objects=tuple(deduped),
        )


def verify_release_order(
    old_rules: SigmaCollection | str | bytes | Iterable[Any],
    new_rules: SigmaCollection | str | bytes | Iterable[Any],
    effective_at: datetime,
    marker_events: Iterable[Event | MarkerEvent],
    **kwargs: Any,
) -> ReleaseOrderReport:
    """
    Convenience wrapper around :class:`ReleaseOrderVerifier`.

    The keyword arguments are forwarded to the verifier constructor.
    """
    return ReleaseOrderVerifier(
        old_rules, new_rules, effective_at, marker_events, **kwargs
    ).verify()


@dataclass
class _RuleSplit:
    bases: dict[str, SigmaRule] = field(default_factory=dict)
    correlations: dict[str, SigmaCorrelationRule] = field(default_factory=dict)


def _coerce_collection(
    rules: SigmaCollection | str | bytes | Iterable[Any], name: str
) -> SigmaCollection:
    if isinstance(rules, SigmaCollection):
        return rules
    if isinstance(rules, (str, bytes)):
        return SigmaCollection.from_yaml(rules)
    if isinstance(rules, Iterable):
        return SigmaCollection(init_rules=list(rules), resolve_references=False)
    raise TypeError(f"{name} must be a SigmaCollection, YAML string, or iterable of rules")


def _coerce_markers(marker_events: Iterable[Event | MarkerEvent]) -> list[MarkerEvent]:
    markers: list[MarkerEvent] = []
    for index, item in enumerate(marker_events, start=1):
        if isinstance(item, MarkerEvent):
            markers.append(item)
        elif isinstance(item, Event):
            markers.append(MarkerEvent(name=f"marker_{index}", event=item))
        else:
            raise TypeError("marker_events must contain Event or MarkerEvent objects")
    if not markers:
        raise ValueError("marker_events must contain at least one event")
    return markers


def _split_rules(rules: Iterable[SigmaRule | SigmaCorrelationRule]) -> _RuleSplit:
    split = _RuleSplit()
    for rule in rules:
        if isinstance(rule, SigmaRule):
            split.bases[rule.name or rule.title] = rule
        elif isinstance(rule, SigmaCorrelationRule):
            split.correlations[_correlation_name(rule)] = rule
    return split


def _dedupe_rules(
    rules: Iterable[SigmaRule | SigmaCorrelationRule],
) -> list[SigmaRule | SigmaCorrelationRule]:
    seen: set[tuple[str, str | None]] = set()
    result: list[SigmaRule | SigmaCorrelationRule] = []
    for rule in rules:
        key = (
            "base" if isinstance(rule, SigmaRule) else "correlation",
            getattr(rule, "name", None) or getattr(rule, "title", None),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(rule)
    return result


def _correlation_name(rule: SigmaCorrelationRule) -> str:
    return rule.name or rule.title or f"correlation_{id(rule)}"


def _signal_names(collection: SigmaCollection) -> list[str]:
    return [
        _correlation_name(rule)
        for rule in collection.rules
        if isinstance(rule, SigmaCorrelationRule)
    ]


def _correlation_required_rules(rule: SigmaCorrelationRule) -> list[str]:
    referenced: list[str] = []
    if rule.rules:
        referenced.extend(ref.reference for ref in rule.rules)
    if isinstance(rule.condition, SigmaExtendedCorrelationCondition):
        referenced.extend(rule.condition.get_referenced_rules())
    if not referenced:
        referenced.extend(ref.reference for ref in rule.referenced_rules)
    return list(dict.fromkeys(referenced))


def _missing_dependency_rules(
    correlation_name: str,
    active_names: set[str],
    corr_by_name: dict[str, SigmaCorrelationRule],
    required_rules: Sequence[str],
    visited: set[str],
) -> list[str]:
    if correlation_name in visited:
        return []
    visited = visited | {correlation_name}
    missing: list[str] = []
    for required in required_rules:
        if required not in active_names:
            missing.append(required)
            continue
        nested = corr_by_name.get(required)
        if nested is not None:
            missing.extend(
                _missing_dependency_rules(
                    required,
                    active_names,
                    corr_by_name,
                    _correlation_required_rules(nested),
                    visited,
                )
            )
    return list(dict.fromkeys(missing))


def _first_loss_minute(stages: Sequence[StageAssessment], signal: str) -> int | None:
    for stage in stages:
        if stage.start_minute is None:
            continue
        if stage.signal(signal).status is not SignalStatus.COMPLETE:
            return stage.start_minute
    return None


def _collection_signature(
    rules: Iterable[SigmaRule | SigmaCorrelationRule],
) -> list[str]:
    signatures: list[str] = []
    for rule in rules:
        try:
            payload = rule.to_dict()
        except Exception:  # noqa: BLE001 - fall back to a stable representation
            payload = repr(rule)
        signatures.append(json.dumps(payload, sort_keys=True, default=repr, ensure_ascii=False))
    signatures.sort()
    return signatures


def _status_short(status: SignalStatus) -> str:
    return {
        SignalStatus.COMPLETE: "OK",
        SignalStatus.NOT_FIRED: "NO FIRE",
        SignalStatus.INCOMPLETE: "GAP",
        SignalStatus.MISSING: "MISSING",
        SignalStatus.ERROR: "ERR",
    }[status]


def _order_description(order: ReleaseOrder) -> str:
    if order is ReleaseOrder.BASE_FIRST:
        return "install new base rules -> switch correlation -> retire old rules"
    return "switch correlation -> install new base rules -> retire old rules"


def _minute_text(effective_at: datetime, minute: int) -> str:
    moment = effective_at + timedelta(minutes=minute)
    return moment.strftime("%H:%M")


def _offset_text(minute: int) -> str:
    return f"{minute // 60:02d}:{minute % 60:02d}"


def _ascii_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    widths = [len(str(header)) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))

    def render_row(row: Sequence[str]) -> str:
        return (
            "| "
            + " | ".join(str(cell).ljust(widths[index]) for index, cell in enumerate(row))
            + " |"
        )

    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    lines = [separator, render_row(headers), separator]
    lines.extend(render_row(row) for row in rows)
    lines.append(separator)
    return lines
