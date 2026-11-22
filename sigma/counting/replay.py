"""Offline replay of a fixed event set under different collection modes.

The replay engine takes a small, canonical set of *logical operations* and
materializes them into raw events for three collection scenarios that matter
for a SOC dual-write migration:

* :data:`ReplayScenario.SINGLE_WRITE` -- one event per operation;
* :data:`ReplayScenario.DUAL_WRITE` -- every operation is emitted twice, once
  per collector/pipeline;
* :data:`ReplayScenario.MISSING_IDENTITY` -- the identity field is absent on
  every emitted event (operations without an event number).

For every scenario the engine evaluates a correlation rule twice:

1. a *naive* evaluation that counts raw events, mirroring what a backend query
   without de-duplication would compute, and
2. a *contract-aware* evaluation that de-duplicates on the canonical identity
   described by the log source counting contract, falling back to an explicit
   undetermined marker when the identity is missing.

The resulting :class:`ReplayOutcome` records raw counts, de-duplicated counts,
the distinct-value cardinality and whether the correlation threshold fires.
This makes inflation (one operation counted twice) and collapse (operations
merged into one) directly observable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.counting.contract import LogSourceCountingContract
from sigma.counting.checker import CountingBasis


class ReplayScenario(str, Enum):
    """Collection scenario under which a logical operation is materialized."""

    SINGLE_WRITE = "single_write"
    DUAL_WRITE = "dual_write"
    MISSING_IDENTITY = "missing_identity"


class ReplayVerdict(str, Enum):
    """Whether contract-aware counting could be decided for a scenario."""

    DETERMINED = "determined"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True)
class LogicalOperation:
    """One logical operation expressed in canonical, contract-level terms.

    ``identity`` holds the value of the canonical identity field.  ``fields``
    holds every other field the correlation rule reads (including group-by and
    unique-value fields).  ``timestamp`` is the canonical operation time.
    """

    identity: Any
    timestamp: float
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class MaterializedEvent:
    """An event produced by a collector for a logical operation."""

    operation_identity: Any
    timestamp: float
    data: dict[str, Any]
    collector: str | None = None


@dataclass
class ReplayOutcome:
    """Counting result of one scenario against one correlation rule."""

    rule_name: str
    scenario: ReplayScenario
    basis: CountingBasis
    operations: int
    raw_events: int
    raw_count: int
    dedup_count: int | None
    unique_values: int | None
    naive_alert: bool
    contract_alert: bool | None
    verdict: ReplayVerdict
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule_name,
            "scenario": self.scenario.value,
            "counting_basis": self.basis.value,
            "verdict": self.verdict.value,
            "operations": self.operations,
            "raw_events": self.raw_events,
            "raw_count": self.raw_count,
            "dedup_count": self.dedup_count,
            "unique_values": self.unique_values,
            "naive_alert": self.naive_alert,
            "contract_alert": self.contract_alert,
            "reason": self.reason,
        }


class ScenarioRunner:
    """Materializes logical operations and evaluates correlation counting."""

    def __init__(self, contract: LogSourceCountingContract) -> None:
        self.contract = contract

    def materialize(
        self, operations: list[LogicalOperation], scenario: ReplayScenario
    ) -> list[MaterializedEvent]:
        identity_fields = self.contract.identity_fields
        events: list[MaterializedEvent] = []
        for operation in operations:
            data = dict(operation.fields)
            if scenario is ReplayScenario.MISSING_IDENTITY:
                for identity_field in identity_fields:
                    data.pop(identity_field, None)
            else:
                if len(identity_fields) == 1:
                    data[identity_fields[0]] = operation.identity
                elif isinstance(operation.identity, dict):
                    for identity_field in identity_fields:
                        data[identity_field] = operation.identity[identity_field]

            if scenario is ReplayScenario.DUAL_WRITE:
                for collector in ("collector_a", "collector_b"):
                    events.append(
                        MaterializedEvent(
                            operation_identity=operation.identity,
                            timestamp=operation.timestamp,
                            data=dict(data),
                            collector=collector,
                        )
                    )
            else:
                events.append(
                    MaterializedEvent(
                        operation_identity=operation.identity,
                        timestamp=operation.timestamp,
                        data=data,
                    )
                )
        return events

    def run(
        self,
        rule: SigmaCorrelationRule,
        operations: list[LogicalOperation],
        scenario: ReplayScenario,
    ) -> ReplayOutcome:
        events = self.materialize(operations, scenario)
        basis = (
            CountingBasis.UNIQUE_VALUE
            if rule.type is SigmaCorrelationType.VALUE_COUNT
            else CountingBasis.EVENT_COUNT
        )
        identity_fields = self.contract.identity_fields
        condition = (
            rule.condition if isinstance(rule.condition, SigmaCorrelationCondition) else None
        )

        raw_count = len(events)

        identity_available = all(
            all(identity_field in event.data for identity_field in identity_fields)
            for event in events
        )
        if not identity_available:
            # Naive evaluation still produces a number -- and that is exactly
            # the dangerous collapse/inflation surface.
            naive_alert = self._threshold_fires(rule, condition, raw_count, basis, events)
            unique_values = (
                self._distinct_values(rule, events)
                if basis is CountingBasis.UNIQUE_VALUE
                else None
            )
            return ReplayOutcome(
                rule_name=getattr(rule, "name", None) or rule.title,
                scenario=scenario,
                basis=basis,
                operations=len(operations),
                raw_events=raw_count,
                raw_count=raw_count,
                dedup_count=None,
                unique_values=unique_values,
                naive_alert=naive_alert,
                contract_alert=None,
                verdict=ReplayVerdict.UNDETERMINED,
                reason=(
                    f"Identity field(s) {list(identity_fields)} are absent; "
                    "distinct operations "
                    "cannot be proven apart, so de-duplication is undecidable."
                ),
            )

        # Contract-aware de-duplication: one record per canonical identity.
        distinct_identities = {
            tuple(
                event.data[identity_field] for identity_field in identity_fields
            )
            if len(identity_fields) > 1
            else event.data[identity_fields[0]]
            for event in events
        }
        dedup_count = len(distinct_identities)
        unique_values = (
            self._distinct_values(rule, events) if basis is CountingBasis.UNIQUE_VALUE else None
        )

        naive_alert = self._threshold_fires(rule, condition, raw_count, basis, events)
        contract_value = unique_values if basis is CountingBasis.UNIQUE_VALUE else dedup_count
        contract_alert = (
            self._threshold_fires(rule, condition, contract_value, basis, events)
            if condition is not None
            else False
        )

        reason = self._explain(
            scenario, basis, raw_count, dedup_count, unique_values, naive_alert, contract_alert
        )
        return ReplayOutcome(
            rule_name=getattr(rule, "name", None) or rule.title,
            scenario=scenario,
            basis=basis,
            operations=len(operations),
            raw_events=raw_count,
            raw_count=raw_count,
            dedup_count=dedup_count,
            unique_values=unique_values,
            naive_alert=naive_alert,
            contract_alert=contract_alert,
            verdict=ReplayVerdict.DETERMINED,
            reason=reason,
        )

    def run_all(
        self,
        rule: SigmaCorrelationRule,
        operations: list[LogicalOperation],
    ) -> list[ReplayOutcome]:
        return [
            self.run(rule, operations, scenario)
            for scenario in (
                ReplayScenario.SINGLE_WRITE,
                ReplayScenario.DUAL_WRITE,
                ReplayScenario.MISSING_IDENTITY,
            )
        ]

    def _threshold_fires(
        self,
        rule: SigmaCorrelationRule,
        condition: SigmaCorrelationCondition | None,
        value: int,
        basis: CountingBasis,
        events: list[MaterializedEvent],
    ) -> bool:
        if condition is None:
            return False
        if basis is CountingBasis.UNIQUE_VALUE:
            compared = self._distinct_values(rule, events)
        else:
            compared = value
        return self._compare(condition.op, compared, condition.count)

    @staticmethod
    def _compare(op: SigmaCorrelationConditionOperator, value: int, threshold: int | float) -> bool:
        comparisons = {
            SigmaCorrelationConditionOperator.LT: lambda a, b: a < b,
            SigmaCorrelationConditionOperator.LTE: lambda a, b: a <= b,
            SigmaCorrelationConditionOperator.GT: lambda a, b: a > b,
            SigmaCorrelationConditionOperator.GTE: lambda a, b: a >= b,
            SigmaCorrelationConditionOperator.EQ: lambda a, b: a == b,
            SigmaCorrelationConditionOperator.NEQ: lambda a, b: a != b,
        }
        return bool(comparisons[op](value, threshold))

    def _distinct_values(self, rule: SigmaCorrelationRule, events: list[MaterializedEvent]) -> int:
        condition = rule.condition
        fieldref = getattr(condition, "fieldref", None)
        if fieldref is None:
            return 0
        fields = [fieldref] if isinstance(fieldref, str) else list(fieldref)
        values = {
            tuple(event.data.get(name) for name in fields)
            for event in events
            if all(event.data.get(name) is not None for name in fields)
        }
        return len(values)

    @staticmethod
    def _explain(
        scenario: ReplayScenario,
        basis: CountingBasis,
        raw_count: int,
        dedup_count: int,
        unique_values: int | None,
        naive_alert: bool,
        contract_alert: bool,
    ) -> str:
        if basis is CountingBasis.UNIQUE_VALUE:
            metric = f"{unique_values} distinct value(s) vs {raw_count} raw event(s)"
        else:
            metric = f"{dedup_count} de-duplicated operation(s) vs {raw_count} raw event(s)"
        if naive_alert != contract_alert:
            delta = "spurious alert" if naive_alert else "missed alert"
            return (
                f"{scenario.value}: {metric}; naive and contract-aware "
                f"decisions differ -> {delta}."
            )
        return f"{scenario.value}: {metric}; decisions agree."
