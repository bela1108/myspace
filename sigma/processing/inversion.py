from __future__ import annotations

import copy
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from sigma.rule import SigmaDetection, SigmaDetectionItem

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.rule import SigmaRule


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


def _detection_items(detection: SigmaDetection | SigmaDetectionItem) -> tuple[SigmaDetectionItem, ...]:
    if isinstance(detection, SigmaDetectionItem):
        return (detection,)
    return tuple(item for child in detection.detection_items for item in _detection_items(child))


def _rule_detection_fields(rule: SigmaRule) -> frozenset[str]:
    return frozenset(
        detection_item.field
        for detection in rule.detection.detections.values()
        for detection_item in _detection_items(detection)
        if detection_item.field is not None
    )
