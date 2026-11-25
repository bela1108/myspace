from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from sigma.matching.event import Event
    from sigma.processing.provenance import FieldProvenanceGraph
    from sigma.processing.tracking import FieldMappingTracking
    from sigma.rule.base import SigmaRuleBase


@dataclass(init=False)
class SigmaMatch:
    """Result of a successful Sigma rule match against one or more events."""

    rule: SigmaRuleBase
    events: list[Event]
    timestamp: datetime
    group_values: dict[str, Any] | None = None
    processing_tracking: FieldMappingTracking | None = None
    field_mappings: FieldMappingTracking | None = None
    field_mapping_tracking: FieldMappingTracking | None = None
    tracking: FieldMappingTracking | None = None
    provenance: FieldProvenanceGraph | None = None
    processing_items: set[str] = field(default_factory=set)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        rule: SigmaRuleBase,
        events: list[Event],
        timestamp: datetime,
        group_values: dict[str, Any] | None = None,
        processing_tracking: FieldMappingTracking | None = None,
        field_mappings: FieldMappingTracking | None = None,
        field_mapping_tracking: FieldMappingTracking | None = None,
        tracking: FieldMappingTracking | None = None,
        field_mapping: FieldMappingTracking | None = None,
        provenance: FieldProvenanceGraph | None = None,
        processing_provenance: FieldProvenanceGraph | None = None,
        processing_items: Iterable[str] | None = None,
        applied_processing_items: Iterable[str] | None = None,
        processing_pipeline: Any | None = None,
        pipeline: Any | None = None,
        evidence: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        tracker = (
            processing_tracking
            or field_mappings
            or field_mapping_tracking
            or tracking
            or field_mapping
            or kwargs.pop("processing_track", None)
        )
        provenance = provenance or processing_provenance
        if provenance is None and tracker is not None:
            provenance = getattr(tracker, "provenance", None)

        self.rule = rule
        self.events = events
        self.timestamp = timestamp
        self.group_values = group_values
        self.processing_tracking = tracker
        self.field_mappings = tracker
        self.field_mapping_tracking = tracker
        self.tracking = tracker
        self.field_mapping = tracker
        self.provenance = provenance
        self.processing_provenance = provenance
        self.field_provenance = provenance
        self.source_provenance = provenance
        item_ids = set(processing_items or applied_processing_items or ())
        if not item_ids:
            item_ids = set(kwargs.pop("processing_item_ids", ()) or ())
        self.processing_items = item_ids
        self.applied_processing_items = item_ids
        self.processing_pipeline = processing_pipeline or pipeline
        self.pipeline = self.processing_pipeline
        self.evidence = list(evidence or [])
        metadata_payload = {**kwargs, **(metadata or {})}
        metadata_payload.setdefault("processing_items", sorted(item_ids))
        self.metadata = metadata_payload

    def to_report(self, audience: str = "internal", **kwargs: Any) -> Any:
        """Build an audience report from this match."""
        from sigma.reporting import build_report

        return build_report(self, audience, **kwargs)

    def to_audience_reports(self, **kwargs: Any) -> Any:
        """Build linked internal and external reports from this match."""
        from sigma.reporting import build_audience_reports

        return build_audience_reports(self, **kwargs)

    build_report = to_report
    generate_report = to_report
    build_reports = to_audience_reports
    generate_reports = to_audience_reports

    def merge_source_tracking(self, matches: list["SigmaMatch"]) -> None:
        """Merge processing tracking from base matches into this correlation match."""
        from sigma.processing.tracking import FieldMappingTracking

        merged = FieldMappingTracking()
        found = False
        for source_match in matches:
            source_tracking = source_match.processing_tracking
            if source_tracking is not None:
                merged.merge(source_tracking)
                found = True
            if source_match.provenance is not None:
                merged.provenance.merge(source_match.provenance)
                found = True
        if found:
            self.processing_tracking = merged
            self.field_mappings = merged
            self.field_mapping_tracking = merged
            self.field_mapping = merged
            self.tracking = merged
            self.provenance = merged.provenance
            self.field_provenance = merged.provenance
            self.source_provenance = merged.provenance
            item_ids: set[str] = set()
            for source_match in matches:
                item_ids.update(getattr(source_match, "processing_items", set()) or set())
            self.processing_items = item_ids
            self.applied_processing_items = item_ids
            self.metadata["processing_items"] = sorted(item_ids)


def merge_match_tracking(matches: list[SigmaMatch]) -> FieldMappingTracking | None:
    """Merge all field tracking objects attached to *matches*."""
    from sigma.processing.tracking import FieldMappingTracking

    merged: FieldMappingTracking | None = None
    for source_match in matches:
        tracking = source_match.processing_tracking
        if tracking is None:
            continue
        if merged is None:
            merged = FieldMappingTracking()
        merged.merge(tracking)
    return merged
