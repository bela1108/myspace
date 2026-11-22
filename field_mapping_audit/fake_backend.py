"""Fake backend used for the field-mapping audit.

A thin TextQueryTestBackend without any built-in pipeline.  It converts each
rule with an explicitly supplied audit pipeline in two phases:

1. During conversion every field-equality leaf is captured raw (converted
   field, value, AND/OR branch, applied processing items).
2. After a rule finished converting, the leaves are globally matched back to
   the pre-pipeline conditions via the pipeline field-mapping index.  Global
matching is required because fan-out produces more leaves than sources and
many-to-one merges make several sources reach the same target field.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionIdentifier,
    ConditionItem,
    ConditionOR,
)
from sigma.backends.test.backend import TextQueryTestBackend
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule


@dataclass
class OriginalCondition:
    """A field-equality condition as it existed before any transformation."""

    selector: str
    field: str | None
    value_repr: str


@dataclass
class ConvertedLeaf:
    """Raw post-conversion leaf collected during backend conversion."""

    converted_field: str | None
    value_repr: str
    boolean_branch: str
    applied_processing_item_ids: frozenset[str]


@dataclass
class ConvertedItemTrace:
    """One converted condition paired with its originating condition."""

    rule_id: str
    rule_name: str
    selector: str
    original_field: str | None
    converted_field: str | None
    value_repr: str
    applied_processing_item_ids: frozenset[str]
    boolean_branch: str


class AuditBackend(TextQueryTestBackend):
    """Text query backend recording condition-level conversion evidence."""

    name: ClassVar[str] = "Audit fake backend"
    backend_processing_pipeline: ClassVar[ProcessingPipeline] = ProcessingPipeline()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.processed_rules: list[SigmaRule] = []
        self.traces: list[ConvertedItemTrace] = []
        self._original_conditions: dict[str, list[OriginalCondition]] = {}
        self._leaves: dict[str, list[ConvertedLeaf]] = {}
        self._current_rule_stack: list[SigmaRule] = []

    def convert_rule(self, rule: SigmaRule, output_format: str | None = None) -> list[str]:
        self.processed_rules.append(rule)
        key = str(rule.id)
        self._original_conditions[key] = self._extract_original_conditions(rule)
        self._leaves[key] = []
        self._current_rule_stack.append(rule)
        try:
            queries = super().convert_rule(rule, output_format)
        finally:
            self._current_rule_stack.pop()
        self._build_traces(rule)
        return queries

    def convert_condition(self, cond: ConditionItem, state: ConversionState) -> Any:
        if self._current_rule_stack and isinstance(cond, ConditionFieldEqualsValueExpression):
            key = str(self._current_rule_stack[-1].id)
            self._leaves[key].append(
                ConvertedLeaf(
                    converted_field=cond.field,
                    value_repr=self._render_value(cond.value),
                    boolean_branch=self._boolean_branch(cond),
                    applied_processing_item_ids=self._applied_items(cond),
                )
            )
        return super().convert_condition(cond, state)

    def convert_condition_as_in_expression(self, cond, state: ConversionState) -> Any:
        if self._current_rule_stack:
            key = str(self._current_rule_stack[-1].id)
            for arg in cond.args:
                if isinstance(arg, ConditionFieldEqualsValueExpression):
                    self._leaves[key].append(
                        ConvertedLeaf(
                            converted_field=arg.field,
                            value_repr=self._render_value(arg.value),
                            boolean_branch=self._boolean_branch(arg),
                            applied_processing_item_ids=self._applied_items(arg),
                        )
                    )
        return super().convert_condition_as_in_expression(cond, state)

    def _build_traces(self, rule: SigmaRule) -> None:
        key = str(rule.id)
        available = list(self._original_conditions[key])
        mapping_index = self._source_target_index()
        field_item_index = self._field_item_index()
        actually_applied = self.last_processing_pipeline.applied_ids
        rule_name = rule.title or rule.name or key
        for leaf in self._leaves[key]:
            original = self._best_original(available, leaf, mapping_index)
            candidate_items = field_item_index.get((original.field, leaf.converted_field), frozenset())
            fired_items = frozenset(candidate_items & actually_applied)
            self.traces.append(
                ConvertedItemTrace(
                    rule_id=key,
                    rule_name=rule_name,
                    selector=original.selector,
                    original_field=original.field,
                    converted_field=leaf.converted_field,
                    value_repr=leaf.value_repr,
                    applied_processing_item_ids=fired_items,
                    boolean_branch=leaf.boolean_branch,
                )
            )

    def _best_original(
        self,
        available: list[OriginalCondition],
        leaf: ConvertedLeaf,
        mapping_index: dict[str, set[str]],
    ) -> OriginalCondition:
        def score(original: OriginalCondition) -> tuple[int, int]:
            targets = mapping_index.get(original.field, set())
            field_ok = int(
                leaf.converted_field in targets
                or original.field == leaf.converted_field
            )
            value_ok = int(self._value_matches(original.value_repr, leaf.value_repr))
            return (field_ok, value_ok)

        ranked = max(available, key=lambda item: score(item))
        if score(ranked) == (0, 0):
            return available[0]
        if self._consumed_all_targets(ranked, leaf, mapping_index):
            available.remove(ranked)
        return ranked

    def _consumed_all_targets(
        self,
        original: OriginalCondition,
        leaf: ConvertedLeaf,
        mapping_index: dict[str, set[str]],
    ) -> bool:
        targets = mapping_index.get(original.field, {original.field})
        seen = {
            trace.converted_field
            for trace in self.traces
            if trace.original_field == original.field and trace.selector == original.selector
        }
        seen.add(leaf.converted_field)
        return targets.issubset(seen)

    def _source_target_index(self) -> dict[str | None, set[str | None]]:
        tracking = self.last_processing_pipeline.field_mappings
        index: dict[str | None, set[str | None]] = {}
        for source, targets in tracking.items():
            index[source] = set(targets)
        return index

    def _field_item_index(self) -> dict[tuple[str, str], frozenset[str]]:
        index: dict[tuple[str, str], set[str]] = {}
        for item in self.last_processing_pipeline.items:
            transformation = getattr(item.transformation, "mapping", None)
            if not transformation or item.identifier is None:
                continue
            for source, destination in transformation.items():
                targets = (destination,) if isinstance(destination, str) else tuple(destination)
                for target in targets:
                    index.setdefault((source, target), set()).add(item.identifier)
        return {key: frozenset(ids) for key, ids in index.items()}

    @staticmethod
    def _value_matches(original_value: str, converted_value: str) -> bool:
        left = original_value.strip(chr(39))
        right = converted_value.strip(chr(39))
        if left == right:
            return True
        return left in right or right in left

    @staticmethod
    def _applied_items(cond: ConditionFieldEqualsValueExpression) -> frozenset[str]:
        node = cond.parent
        while node is not None and not hasattr(node, "applied_processing_items"):
            node = node.parent
        if node is None:
            return frozenset()
        return frozenset(node.applied_processing_items)

    @staticmethod
    def _extract_original_conditions(rule: SigmaRule) -> list[OriginalCondition]:
        results: list[OriginalCondition] = []
        for parsed in rule.detection.parsed_condition:
            AuditBackend._walk_conditions(parsed.parsed, results)
        return results

    @staticmethod
    def _walk_conditions(node: ConditionItem, results: list[OriginalCondition]) -> None:
        if isinstance(node, ConditionFieldEqualsValueExpression):
            results.append(
                OriginalCondition(
                    selector=AuditBackend._selector_of(node),
                    field=node.field,
                    value_repr=AuditBackend._render_value(node.value),
                )
            )
        for child in getattr(node, "args", []) or []:
            AuditBackend._walk_conditions(child, results)

    @staticmethod
    def _selector_of(node: ConditionItem) -> str:
        for parent in node.parent_chain():
            if isinstance(parent, ConditionIdentifier):
                return parent.identifier
        return "<unknown>"


    @staticmethod
    def _render_value(value: Any) -> str:
        text = str(value)
        if text.startswith("<sigma.types.SigmaNull"):
            return "null"
        return text
    @staticmethod
    def _boolean_branch(cond: ConditionItem) -> str:
        operators: list[str] = []
        for node in cond.parent_chain():
            if isinstance(node, ConditionOR):
                operators.append("OR")
            elif isinstance(node, ConditionAND):
                operators.append("AND")
        return " > ".join(operators) if operators else "ROOT"


def run_audit_backend(
    rules_yaml: str, pipeline: ProcessingPipeline
) -> tuple[AuditBackend, list[str]]:
    """Convert rules with the fake backend, tracking original vs mapped fields."""
    collection = SigmaCollection.from_yaml(rules_yaml)
    backend = AuditBackend(processing_pipeline=pipeline)
    queries: list[str] = []
    for rule in collection.rules:
        queries.extend(backend.convert_rule(rule))
    return backend, queries
