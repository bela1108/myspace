from __future__ import annotations

from collections import UserDict, defaultdict
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from sigma.processing.provenance import (
    AliasMergeRecord,
    DerivedFieldRecord,
    FieldOrigin,
    FieldProvenanceGraph,
    ProvenanceEdge,
    ProvenanceTracker,
)

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingItemBase


@dataclass
class ProcessingItemTrackingMixin:
    """
    Provides attributes and methods for tracking processing items applied to Sigma rule objects
    like detection items and conditions.
    """

    applied_processing_items: set[str] = field(init=False, compare=False, default_factory=set)

    def add_applied_processing_item(self, processing_item: "ProcessingItemBase" | None) -> None:
        """Add identifier of processing item to set of applied processing items."""
        if processing_item is not None and processing_item.identifier is not None:
            self.applied_processing_items.add(processing_item.identifier)

    def was_processed_by(self, processing_item_id: str) -> bool:
        """Determines if detection item was processed by a processing item with the given id."""
        return processing_item_id in self.applied_processing_items


class FieldMappingTracking(UserDict[str | None, set[str]]):
    """
    Tracking class for field mappings. Tracks initial field name to finally mapped name after a
    processing pipeline was applied. Each key maps the source field to a set of target fields.

    Currently this class is intentionally only used to track field mappings in detection items and
    the fields list is excluded from it. This might change in the future depending on use cases.
    """

    def __init__(self, *args: list[Any], **kwargs: dict[str, Any]) -> None:
        super().__init__(*args, **kwargs)
        self.target_fields: defaultdict[str | None, set[str | None]] = defaultdict(
            set
        )  # Create reverse mapping
        self.provenance = FieldProvenanceGraph()
        self.records = self.provenance.edges
        for source, target_set in self.items():
            for target in target_set:
                if target is not None:
                    self.target_fields[target].add(source)
            self.provenance.record_mapping(source, list(target_set))

    def add_mapping(
        self,
        source: str | None,
        target: str | list[str] | tuple[str | None, ...] | None,
        *,
        processing_item_id: str | None = None,
        operation: str = "mapping",
    ) -> None:
        """
        This method must be invoked for each field name mapping applied in a processing pipeline to
        get a precise result of the final mapping.
        """
        if target is None:
            targets: list[str | None] = []
        elif isinstance(target, str):
            targets = [target]
        else:
            targets = list(target)

        self.provenance.record_mapping(
            source,
            targets,
            operation=operation,
            processing_item_id=processing_item_id,
        )

        if not isinstance(target, list):  # Ensure that the target is a list.
            target = [target] if target is not None else []

        if source in self.target_fields:  # Source field was already mapping target.
            # Replace each occurrence of a mapping to the source with the target field.
            for source_field in self.target_fields[source]:
                target_set = self[source_field]
                if source is not None:
                    target_set.remove(source)
                target_set.update(targets)

            # Update reverse mapping: remove source and add new target
            del self.target_fields[source]
            for t in targets:
                self.target_fields[t].add(source_field)

        if source not in self:
            self[source] = set(targets)
        else:
            self[source].update(targets)
        for t in targets:
            self.target_fields[t].add(source)

    def merge(self, other: "FieldMappingTracking") -> None:
        """Merge another FieldMappingTracking into this one."""
        for source, target_set in other.items():
            self.add_mapping(source, list(target_set))
        other_provenance = getattr(other, "provenance", None)
        if other_provenance is not None:
            self.provenance.merge(other_provenance)

    def add_alias_merge(self, *args: Any, **kwargs: Any) -> Any:
        """Record an alias merge in the provenance graph."""
        record = self.provenance.add_alias_merge(*args, **kwargs)
        processing_item_id = kwargs.get("processing_item_id")
        for source in record.sources:
            self.add_mapping(
                source,
                record.alias,
                processing_item_id=processing_item_id,
                operation="alias_merge",
            )
        return record

    record_alias_merge = add_alias_merge
    merge_alias = add_alias_merge
    track_alias_merge = add_alias_merge

    def add_derived_field(self, *args: Any, **kwargs: Any) -> Any:
        """Record the origin of a derived field."""
        record = self.provenance.add_derived_field(*args, **kwargs)
        processing_item_id = kwargs.get("processing_item_id")
        for source in record.sources:
            self.add_mapping(
                source,
                record.name,
                processing_item_id=processing_item_id,
                operation="derived_field",
            )
        return record

    record_derived_field = add_derived_field
    track_derived_field = add_derived_field
    derive_field = add_derived_field

    def trace_field(self, field_name: str) -> Any:
        """Trace a final field back to its known origins."""
        return self.provenance.trace(field_name)

    @property
    def alias_merges(self) -> dict[str, Any]:
        return self.provenance.alias_merges

    @property
    def derived_fields(self) -> dict[str, Any]:
        return self.provenance.derived_fields
