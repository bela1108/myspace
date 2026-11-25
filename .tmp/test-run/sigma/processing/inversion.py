from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline


class FieldMappingInversionStatus(str, Enum):
    REVERSIBLE = "reversible"
    MERGED_IRREVERSIBLE = "merged_irreversible"
    UNCOVERED = "uncovered"


@dataclass(frozen=True)
class FieldMappingInversionResult:
    source_field: str
    target_fields: frozenset[str]
    status: FieldMappingInversionStatus
    event_source: str | None = None


@dataclass(frozen=True)
class RuleFieldMappingEvidence:
    rule_identifier: str
    event_source: str
    source_fields: frozenset[str]
    target_field: str


@dataclass(frozen=True)
class UncoveredFieldEvidence:
    rule_identifier: str
    event_source: str
    field: str


@dataclass(frozen=True)
class FieldMappingInversionReport:
    reversible: tuple[FieldMappingInversionResult, ...]
    merged_irreversible: tuple[FieldMappingInversionResult, ...]
    uncovered: tuple[FieldMappingInversionResult, ...]
    merge_evidence: tuple[RuleFieldMappingEvidence, ...]
    blocking_evidence: tuple[RuleFieldMappingEvidence | UncoveredFieldEvidence, ...]
    release_blocked: bool


def _rule_identifier(rule: SigmaRule) -> str:
    return rule.name or str(rule.id) or rule.title


def _event_source(rule: SigmaRule) -> str:
    location = "/".join(
        part
        for part in (rule.logsource.product, rule.logsource.service or rule.logsource.category)
        if part is not None
    )
    return location or "default"


def _detection_items(
    detection: SigmaDetection | SigmaDetectionItem,
) -> tuple[SigmaDetectionItem, ...]:
    if isinstance(detection, SigmaDetectionItem):
        return (detection,)
    return tuple(
        item
        for detection_item in detection.detection_items
        for item in _detection_items(detection_item)
    )


def _rule_detection_fields(rule: SigmaRule) -> frozenset[str]:
    return frozenset(
        detection_item.field
        for detection in rule.detection.detections.values()
        for detection_item in _detection_items(detection)
        if detection_item.field is not None
    )


def check_field_mapping_inversion(
    pipeline: ProcessingPipeline,
    rules: list[SigmaRule] | tuple[SigmaRule, ...],
) -> FieldMappingInversionReport:
    """Check whether rule field mappings can be inverted without losing detection semantics."""
    rule_fields = {rule: _rule_detection_fields(rule) for rule in rules}
    rule_mappings: dict[SigmaRule, dict[str, frozenset[str]]] = {}
    aggregate_mappings: dict[str, set[str]] = defaultdict(set)
    aggregate_sources: dict[str, set[str]] = defaultdict(set)

    for rule in rules:
        pipeline.apply(rule)
        mappings = {
            source_field: frozenset(target_fields)
            for source_field, target_fields in pipeline.field_mappings.items()
            if source_field is not None
        }
        rule_mappings[rule] = mappings
        for source_field, target_fields in mappings.items():
            aggregate_mappings[source_field].update(target_fields)
            for target_field in target_fields:
                aggregate_sources[target_field].add(source_field)

    reversible: list[FieldMappingInversionResult] = []
    merged_irreversible: list[FieldMappingInversionResult] = []
    uncovered: list[FieldMappingInversionResult] = []
    merge_evidence: list[RuleFieldMappingEvidence] = []
    blocking_evidence: list[RuleFieldMappingEvidence | UncoveredFieldEvidence] = []

    for source_field in sorted(aggregate_mappings):
        target_fields = frozenset(aggregate_mappings[source_field])
        merged_targets = frozenset(
            target_field
            for target_field in target_fields
            if len(aggregate_sources[target_field]) > 1
        )
        result = FieldMappingInversionResult(
            source_field=source_field,
            target_fields=target_fields,
            status=(
                FieldMappingInversionStatus.MERGED_IRREVERSIBLE
                if merged_targets
                else FieldMappingInversionStatus.REVERSIBLE
            ),
        )
        if merged_targets:
            merged_irreversible.append(result)
        else:
            reversible.append(result)

    for rule in rules:
        identifier = _rule_identifier(rule)
        event_source = _event_source(rule)
        mappings = rule_mappings[rule]
        target_sources: dict[str, set[str]] = defaultdict(set)

        for source_field, target_fields in mappings.items():
            for target_field in target_fields:
                target_sources[target_field].add(source_field)

        for target_field in sorted(target_sources):
            source_fields = frozenset(target_sources[target_field])
            evidence = RuleFieldMappingEvidence(
                rule_identifier=identifier,
                event_source=event_source,
                source_fields=source_fields,
                target_field=target_field,
            )
            merge_evidence.append(evidence)
            if len(source_fields) > 1:
                blocking_evidence.append(evidence)

        for field in sorted(rule_fields[rule] - mappings.keys()):
            evidence = UncoveredFieldEvidence(
                rule_identifier=identifier,
                event_source=event_source,
                field=field,
            )
            uncovered.append(
                FieldMappingInversionResult(
                    source_field=field,
                    target_fields=frozenset(),
                    status=FieldMappingInversionStatus.UNCOVERED,
                    event_source=event_source,
                )
            )
            blocking_evidence.append(evidence)

    return FieldMappingInversionReport(
        reversible=tuple(reversible),
        merged_irreversible=tuple(merged_irreversible),
        uncovered=tuple(uncovered),
        merge_evidence=tuple(merge_evidence),
        blocking_evidence=tuple(blocking_evidence),
        release_blocked=bool(blocking_evidence),
    )
