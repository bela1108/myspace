from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


@dataclass
class ProvenanceEdge:
    """A single source-to-target field transformation edge."""

    source: str | None
    targets: tuple[str | None, ...]
    operation: str = "mapping"
    processing_items: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AliasMergeRecord:
    """Record that several rule-specific fields were merged under one alias."""

    alias: str
    sources: tuple[str, ...] = field(default_factory=tuple)
    mapping: dict[str, str] = field(default_factory=dict)
    rule_reference: str | None = None
    processing_items: tuple[str, ...] = field(default_factory=tuple)
    complete: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DerivedFieldRecord:
    """Origin of a field whose value is derived from one or more source fields."""

    name: str
    sources: tuple[str, ...] = field(default_factory=tuple)
    expression: str | None = None
    transformation: str | None = None
    processing_items: tuple[str, ...] = field(default_factory=tuple)
    complete: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceGap:
    """A missing or unverifiable provenance link."""

    code: str
    message: str
    field: str | None = None


@dataclass
class ProvenanceTrace:
    """Resolved origins and records participating in a field's history."""

    field: str
    origins: tuple[str, ...]
    mapping_sources: tuple[str, ...] = field(default_factory=tuple)
    aliases: tuple[AliasMergeRecord, ...] = field(default_factory=tuple)
    derivations: tuple[DerivedFieldRecord, ...] = field(default_factory=tuple)
    gaps: tuple[ProvenanceGap, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        return not self.gaps

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "origins": list(self.origins),
            "mapping_sources": list(self.mapping_sources),
            "aliases": [asdict(item) for item in self.aliases],
            "derivations": [asdict(item) for item in self.derivations],
            "gaps": [asdict(item) for item in self.gaps],
            "complete": self.complete,
        }


class FieldProvenanceGraph:
    """Directed provenance graph for field mappings, aliases and derivations."""

    def __init__(self) -> None:
        self.source_fields: dict[str, dict[str, Any]] = {}
        self.edges: list[ProvenanceEdge] = []
        self.alias_merges: dict[str, AliasMergeRecord] = {}
        self.derived_fields: dict[str, DerivedFieldRecord] = {}
        self.gaps: list[ProvenanceGap] = []

    @staticmethod
    def _values(value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, dict):
            return tuple(str(item) for item in value.values() if item is not None)
        try:
            return tuple(str(item) for item in value if item is not None)
        except TypeError:
            return (str(value),)

    def record_source(self, field_name: str | None = None, **metadata: Any) -> None:
        """Mark a field as an original source field."""
        name = metadata.pop("name", field_name)
        if name is None:
            return
        source = self.source_fields.setdefault(str(name), {})
        source.update(metadata)

    add_source = record_source

    def record_mapping(
        self,
        source: str | None = None,
        target: str | Iterable[str | None] | None = None,
        targets: Iterable[str | None] | None = None,
        *,
        operation: str = "mapping",
        processing_item_id: str | None = None,
        processing_items: Iterable[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ProvenanceEdge:
        """Record a mapping edge from one field to one or more targets."""
        if source is None:
            source = kwargs.get("source_field") or kwargs.get("src")
        if target is None and targets is None:
            target = kwargs.get("dest") or kwargs.get("destination") or kwargs.get("mapped")
        target_values: list[str | None]
        if targets is not None:
            target_values = list(targets)
        elif target is None:
            target_values = []
        elif isinstance(target, str):
            target_values = [target]
        else:
            target_values = list(target)

        item_ids: list[str] = list(processing_items or ())
        if processing_item_id is not None:
            item_ids.append(processing_item_id)
        item_ids.extend(str(item) for item in kwargs.get("applied_processing_items", ()))

        edge = ProvenanceEdge(
            source=source,
            targets=tuple(target_values),
            operation=str(kwargs.get("transformation") or operation),
            processing_items=tuple(dict.fromkeys(item_ids)),
            metadata={
                **(metadata or {}),
                **{
                    k: v
                    for k, v in kwargs.items()
                    if k
                    not in {
                        "source_field",
                        "src",
                        "dest",
                        "destination",
                        "mapped",
                        "transformation",
                        "applied_processing_items",
                    }
                },
            },
        )
        self.edges.append(edge)
        if source is not None:
            self.record_source(source)
        for target_name in target_values:
            if target_name is not None:
                self.source_fields.setdefault(target_name, {"mapped": True})
        return edge

    add_mapping = record_mapping

    def add_alias_merge(
        self,
        alias: str | dict[str, Any] | None = None,
        sources: Iterable[str] | None = None,
        mapping: dict[str, str] | None = None,
        *,
        source_fields: Iterable[str] | None = None,
        merged_fields: Iterable[str] | None = None,
        aliases: Iterable[str] | None = None,
        canonical: str | None = None,
        rule_reference: str | None = None,
        processing_item_id: str | None = None,
        processing_items: Iterable[str] | None = None,
        complete: bool = True,
        **metadata: Any,
    ) -> AliasMergeRecord:
        """Record an alias that merges multiple field identities."""
        if isinstance(alias, dict):
            metadata.update(alias)
            alias_name = str(metadata.pop("alias", metadata.pop("name", "alias")))
            mapping = metadata.pop("mapping", mapping)
            sources = metadata.pop("sources", metadata.pop("source_fields", sources))
        else:
            alias_name = str(
                alias
                or metadata.pop("name", None)
                or metadata.pop("alias_name", None)
                or canonical
                or ""
            )
        if not alias_name:
            raise ValueError("alias name is required")

        resolved_mapping = dict(mapping or {})
        source_values: list[str] = []
        for value in (
            *self._values(sources),
            *self._values(source_fields),
            *self._values(merged_fields),
            *self._values(aliases),
            *resolved_mapping.values(),
        ):
            if value and value not in source_values and value != alias_name:
                source_values.append(value)

        item_ids = list(processing_items or ())
        if processing_item_id:
            item_ids.append(processing_item_id)
        record = AliasMergeRecord(
            alias=alias_name,
            sources=tuple(source_values),
            mapping=resolved_mapping,
            rule_reference=rule_reference or metadata.pop("source_rule", None),
            processing_items=tuple(dict.fromkeys(item_ids)),
            complete=complete and not metadata.pop("incomplete", False),
            metadata=metadata,
        )
        self.alias_merges[alias_name] = record
        for source_name in source_values:
            self.record_source(source_name, alias_of=alias_name)
        if not record.complete or not source_values:
            self.add_gap(
                alias_name,
                "alias_merge_incomplete",
                f"Alias {alias_name!r} does not resolve to source fields",
            )
        return record

    record_alias_merge = add_alias_merge
    merge_alias = add_alias_merge
    track_alias_merge = add_alias_merge

    def add_derived_field(
        self,
        name: str | None = None,
        sources: Iterable[str] | None = None,
        *,
        source_fields: Iterable[str] | None = None,
        origin_fields: Iterable[str] | None = None,
        input_fields: Iterable[str] | None = None,
        expression: str | None = None,
        derivation: str | None = None,
        transformation: str | None = None,
        processing_item_id: str | None = None,
        processing_items: Iterable[str] | None = None,
        complete: bool = True,
        **metadata: Any,
    ) -> DerivedFieldRecord:
        """Record the source fields used to derive another field."""
        field_name = str(name or metadata.pop("field", metadata.pop("field_name", "")))
        if not field_name:
            raise ValueError("derived field name is required")
        source_values: list[str] = []
        for value in (
            *self._values(sources),
            *self._values(source_fields),
            *self._values(origin_fields),
            *self._values(input_fields),
        ):
            if value and value not in source_values and value != field_name:
                source_values.append(value)
        item_ids = list(processing_items or ())
        if processing_item_id:
            item_ids.append(processing_item_id)
        record = DerivedFieldRecord(
            name=field_name,
            sources=tuple(source_values),
            expression=expression or derivation or metadata.pop("formula", None),
            transformation=transformation or metadata.pop("transform", None),
            processing_items=tuple(dict.fromkeys(item_ids)),
            complete=complete and not metadata.pop("incomplete", False),
            metadata=metadata,
        )
        self.derived_fields[field_name] = record
        if not record.complete:
            self.add_gap(
                field_name,
                "derived_field_incomplete",
                f"Derived field {field_name!r} has incomplete provenance",
            )
        return record

    record_derived_field = add_derived_field
    track_derived_field = add_derived_field
    derive = add_derived_field

    def add_gap(self, field_name: str | None, code: str, message: str) -> ProvenanceGap:
        gap = ProvenanceGap(code=code, message=message, field=field_name)
        if gap not in self.gaps:
            self.gaps.append(gap)
        return gap

    def merge(self, other: "FieldProvenanceGraph | None") -> None:
        """Merge another provenance graph into this graph."""
        if other is None:
            return
        for name, metadata in other.source_fields.items():
            self.record_source(name, **metadata)
        self.edges.extend(other.edges)
        for name, record in other.alias_merges.items():
            if name in self.alias_merges and self.alias_merges[name] != record:
                existing = self.alias_merges[name]
                merged_sources = tuple(dict.fromkeys((*existing.sources, *record.sources)))
                merged_mapping = {**existing.mapping, **record.mapping}
                self.add_alias_merge(
                    name,
                    merged_sources,
                    merged_mapping,
                    rule_reference=record.rule_reference or existing.rule_reference,
                    processing_items=(*existing.processing_items, *record.processing_items),
                    complete=existing.complete and record.complete,
                    **{**existing.metadata, **record.metadata},
                )
            else:
                self.alias_merges[name] = record
        for name, record in other.derived_fields.items():
            if name in self.derived_fields and self.derived_fields[name] != record:
                existing = self.derived_fields[name]
                self.add_derived_field(
                    name,
                    tuple(dict.fromkeys((*existing.sources, *record.sources))),
                    expression=record.expression or existing.expression,
                    transformation=record.transformation or existing.transformation,
                    processing_items=(
                        *existing.processing_items,
                        *record.processing_items,
                    ),
                    complete=existing.complete and record.complete,
                    **{**existing.metadata, **record.metadata},
                )
            else:
                self.derived_fields[name] = record
        for gap in other.gaps:
            if gap not in self.gaps:
                self.gaps.append(gap)

    def trace(self, field_name: str) -> ProvenanceTrace:
        """Resolve all known original sources for a final field name."""
        origins: list[str] = []
        mapping_sources: list[str] = []
        aliases: list[AliasMergeRecord] = []
        derivations: list[DerivedFieldRecord] = []
        gaps: list[ProvenanceGap] = [gap for gap in self.gaps if gap.field == field_name]
        pending = [field_name]
        seen: set[str] = set()

        while pending:
            current = pending.pop(0)
            if current in seen:
                continue
            seen.add(current)

            if current in self.derived_fields:
                derivation = self.derived_fields[current]
                derivations.append(derivation)
                if not derivation.complete:
                    gaps.append(
                        ProvenanceGap(
                            "derived_field_incomplete",
                            f"Derived field {current!r} has incomplete provenance",
                            current,
                        )
                    )
                for source in derivation.sources:
                    if source not in mapping_sources:
                        mapping_sources.append(source)
                    pending.append(source)

            if current in self.alias_merges:
                alias = self.alias_merges[current]
                aliases.append(alias)
                if not alias.complete or not alias.sources:
                    gaps.append(
                        ProvenanceGap(
                            "alias_merge_incomplete",
                            f"Alias {current!r} has incomplete provenance",
                            current,
                        )
                    )
                for source in alias.sources:
                    if source not in mapping_sources:
                        mapping_sources.append(source)
                    pending.append(source)

            edge_sources = [
                edge.source
                for edge in self.edges
                if current in tuple(target for target in edge.targets if target is not None)
                and edge.source is not None
            ]
            for source in edge_sources:
                if source is None:
                    continue
                if source not in mapping_sources:
                    mapping_sources.append(source)
                pending.append(source)

            if (
                not edge_sources
                and current not in self.alias_merges
                and current not in self.derived_fields
            ):
                if current not in origins:
                    origins.append(current)

        for source in mapping_sources:
            if source not in origins and source not in seen:
                origins.append(source)
        if not origins:
            origins = mapping_sources or [field_name]
        unique_gaps = list({(gap.code, gap.field, gap.message): gap for gap in gaps}.values())
        return ProvenanceTrace(
            field=field_name,
            origins=tuple(dict.fromkeys(origins)),
            mapping_sources=tuple(mapping_sources),
            aliases=tuple(aliases),
            derivations=tuple(derivations),
            gaps=tuple(unique_gaps),
        )

    def missing_links(self, fields: Iterable[str] | None = None) -> list[ProvenanceGap]:
        """Return gaps for all known fields or the supplied fields."""
        if fields is None:
            return list(self.gaps)
        result: list[ProvenanceGap] = []
        for field_name in fields:
            result.extend(self.trace(field_name).gaps)
        return result

    def is_complete(self, fields: Iterable[str] | None = None) -> bool:
        if fields is None:
            return not self.gaps
        return not self.missing_links(fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_fields": self.source_fields,
            "edges": [asdict(edge) for edge in self.edges],
            "alias_merges": {name: asdict(record) for name, record in self.alias_merges.items()},
            "derived_fields": {
                name: asdict(record) for name, record in self.derived_fields.items()
            },
            "gaps": [asdict(gap) for gap in self.gaps],
        }


ProvenanceTracker = FieldProvenanceGraph
ProvenanceGraph = FieldProvenanceGraph
Provenance = FieldProvenanceGraph
FieldProvenance = FieldProvenanceGraph
FieldProvenanceTracker = FieldProvenanceGraph
AliasMerge = AliasMergeRecord
AliasMergeRecordModel = AliasMergeRecord
DerivedField = DerivedFieldRecord
DerivedFieldRecordModel = DerivedFieldRecord
FieldOrigin = ProvenanceEdge
ProvenanceRecord = ProvenanceEdge
OriginRecord = ProvenanceEdge
