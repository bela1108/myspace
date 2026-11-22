from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Mapping

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.processing.tracking import FieldMappingTracking


#: Pseudo field used for value-only ("keyword") detections and raw log searches.
RAW_LOG_FIELD = "__raw__"


@dataclass(frozen=True)
class FieldResolution:
    """Result of resolving one field through the provenance graph."""

    field: str
    sources: frozenset[str]
    """All root fields that ``field`` may have been derived from."""
    required: frozenset[str]
    """Root fields that actually contributed to the observed value."""
    missing: frozenset[str]
    """Required root fields that were not present in the supplied event data."""

    @property
    def complete(self) -> bool:
        return not self.missing


@dataclass
class FieldProvenance:
    """
    Tracks where the fields used by a converted rule came from.

    A provenance edge points from a *derived* or *renamed* field back to the fields it
    depends on.  Two kinds of edges are supported:

    * ``add_mapping`` / ``add_alias`` describe alternative names for the same information
      (for example ``user -> src_user`` or ``user -> dst_user``).  If event data contains
      one of the equivalent names, that branch is considered available.
    * ``add_derived`` describes a field that combines several sources.  All sources are
      required before the derived statement can be independently confirmed.

    The graph is resolved transitively, so an alias of a renamed field, or a derived field
    that consumes another derived field, still reports every root source.
    """

    dependencies: dict[str, set[str]] = field(default_factory=dict)
    require_all: set[str] = field(default_factory=set)
    equivalents: dict[str, set[str]] = field(default_factory=dict)
    aliases: dict[str, set[str]] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def add_mapping(self, source: str | None, target: str | None) -> None:
        """Register a rename/alias edge ``target`` depends on ``source``."""
        if not source or not target or source == target:
            return
        self.dependencies.setdefault(target, set()).add(source)
        self._link_equivalents(source, target)

    def add_alias(self, alias: str, sources: Iterable[str]) -> None:
        """Register ``alias`` as an alternative name for one or more source fields."""
        source_fields = {source for source in sources if source and source != alias}
        if not source_fields:
            return
        self.dependencies.setdefault(alias, set()).update(source_fields)
        self.aliases[alias] = set(source_fields)

    def add_derived(self, field_name: str, sources: Iterable[str]) -> None:
        """Register ``field_name`` as a value derived from *all* ``sources``."""
        source_fields = {source for source in sources if source and source != field_name}
        if not source_fields:
            return
        self.dependencies.setdefault(field_name, set()).update(source_fields)
        self.require_all.add(field_name)

    def add_rename(self, source: str | None, target: str | None) -> None:
        """Alias for :meth:`add_mapping`."""
        self.add_mapping(source, target)

    # Explicit *_field spellings are convenient in pipeline-building code.
    add_mapping_field = add_mapping
    add_alias_field = add_alias
    add_derived_field = add_derived

    def merge(self, other: FieldProvenance | None) -> FieldProvenance:
        """Merge another provenance graph into this one and return ``self``."""
        if other is None:
            return self
        for target, sources in other.dependencies.items():
            self.dependencies.setdefault(target, set()).update(sources)
        self.require_all.update(other.require_all)
        for alias, sources in other.aliases.items():
            self.aliases.setdefault(alias, set()).update(sources)
        for source, group in other.equivalents.items():
            for item in group:
                self._link_equivalents(source, item)
        return self

    def copy(self) -> FieldProvenance:
        cloned = FieldProvenance()
        cloned.merge(self)
        return cloned

    @classmethod
    def from_field_mappings(
        cls,
        mappings: Mapping[str | None, Iterable[str | None]] | FieldMappingTracking,
    ) -> FieldProvenance:
        """
        Build provenance from pySigma's ``FieldMappingTracking``.

        ``FieldMappingTracking`` maps an original rule field to the field name(s) used in
        the converted query.  The query field therefore depends on the original field.
        """
        provenance = cls()
        for source, targets in mappings.items():
            if targets is None:
                continue
            if isinstance(targets, str):
                targets = [targets]
            for target in targets:
                provenance.add_mapping(source, target)
        return provenance

    @classmethod
    def from_processing_pipeline(cls, pipeline: ProcessingPipeline | None) -> FieldProvenance:
        """Build provenance from the field mappings of an applied processing pipeline."""
        if pipeline is None:
            return cls()
        return cls.from_field_mappings(pipeline.field_mappings)

    @classmethod
    def from_correlation_aliases(cls, aliases: Any) -> FieldProvenance:
        """
        Build provenance from ``SigmaCorrelationFieldAliases``.

        Every correlation alias is treated as the union of the fields it maps to across
        the referenced rules.  That makes an alias-based external statement report all
        source columns, even when the underlying rules use different names.
        """
        provenance = cls()
        alias_items = getattr(aliases, "aliases", aliases)
        if isinstance(alias_items, Mapping):
            for alias, definition in alias_items.items():
                mapping = getattr(definition, "mapping", definition)
                if isinstance(mapping, Mapping):
                    provenance.add_alias(str(alias), [str(field) for field in mapping.values()])
        return provenance

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------
    def root_sources(self, field_name: str) -> frozenset[str]:
        """Return every root field that ``field_name`` can be traced back to."""
        return frozenset(self._root_sources(field_name, set()))

    def resolve(
        self,
        field_name: str,
        data: Mapping[str, Any] | Iterable[Mapping[str, Any]] | None = None,
    ) -> FieldResolution:
        """
        Resolve ``field_name`` against optional event data.

        ``data`` may be one event mapping or an iterable of event mappings.  When it is
        omitted the caller is assumed to have all source values available.
        """
        datasets = self._normalize_data(data)
        return self._resolve(field_name, datasets, set())

    def resolve_sources(self, field_name: str) -> frozenset[str]:
        """Alias for :meth:`root_sources`."""
        return self.root_sources(field_name)

    def is_available(
        self,
        field_name: str,
        data: Mapping[str, Any] | Iterable[Mapping[str, Any]] | None = None,
    ) -> bool:
        """Return True if ``field_name`` or an equivalent name is present in ``data``."""
        datasets = self._normalize_data(data)
        if datasets is None:
            return True
        return self._field_present(field_name, datasets)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _link_equivalents(self, first: str, second: str) -> None:
        group = {first, second}
        group.update(self.equivalents.get(first, set()))
        group.update(self.equivalents.get(second, set()))
        for member in group:
            self.equivalents[member] = group

    @staticmethod
    def _normalize_data(
        data: Mapping[str, Any] | Iterable[Mapping[str, Any]] | None,
    ) -> list[Mapping[str, Any]] | None:
        if data is None:
            return None
        if isinstance(data, Mapping):
            return [data]
        return list(data)

    def _field_present(self, field_name: str, datasets: list[Mapping[str, Any]]) -> bool:
        if field_name == RAW_LOG_FIELD:
            return True
        candidates = set(self.equivalents.get(field_name, {field_name}))
        candidates.add(field_name)
        for alias, members in self.aliases.items():
            if field_name in members:
                candidates.add(alias)
        return any(candidate in dataset for candidate in candidates for dataset in datasets)

    def _root_sources(self, field_name: str, seen: set[str]) -> set[str]:
        if field_name in seen:
            return {field_name}
        parents = self.dependencies.get(field_name)
        if not parents:
            return {field_name}
        seen = seen | {field_name}
        sources: set[str] = set()
        for parent in parents:
            sources.update(self._root_sources(parent, seen))
        return sources or {field_name}

    def _resolve(
        self,
        field_name: str,
        datasets: list[Mapping[str, Any]] | None,
        seen: set[str],
    ) -> FieldResolution:
        if field_name in seen:
            return self._leaf_resolution(field_name, datasets)

        parents = self.dependencies.get(field_name)
        if not parents:
            return self._leaf_resolution(field_name, datasets)

        seen = seen | {field_name}
        child_resolutions = [self._resolve(parent, datasets, seen) for parent in sorted(parents)]
        all_sources: set[str] = set()
        for resolution in child_resolutions:
            all_sources.update(resolution.sources)

        if field_name in self.require_all:
            required: set[str] = set()
            missing: set[str] = set()
            for resolution in child_resolutions:
                required.update(resolution.required)
                missing.update(resolution.missing)
        else:
            usable = [resolution for resolution in child_resolutions if resolution.complete]
            if usable:
                required = set()
                for resolution in usable:
                    required.update(resolution.required)
                missing = set()
            else:
                required = set()
                missing = set()
                for resolution in child_resolutions:
                    required.update(resolution.required)
                    missing.update(resolution.missing)

        return FieldResolution(
            field=field_name,
            sources=frozenset(all_sources or {field_name}),
            required=frozenset(required),
            missing=frozenset(missing),
        )

    def _leaf_resolution(
        self,
        field_name: str,
        datasets: list[Mapping[str, Any]] | None,
    ) -> FieldResolution:
        if datasets is None:
            return FieldResolution(
                field=field_name,
                sources=frozenset({field_name}),
                required=frozenset({field_name}),
                missing=frozenset(),
            )

        # Renamed fields and aliases are alternative names for the same information.
        present = self._field_present(field_name, datasets)
        return FieldResolution(
            field=field_name,
            sources=frozenset({field_name}),
            required=frozenset({field_name}),
            missing=frozenset() if present else frozenset({field_name}),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the provenance graph."""
        return {
            "dependencies": {
                target: sorted(sources) for target, sources in sorted(self.dependencies.items())
            },
            "require_all": sorted(self.require_all),
            "equivalents": {
                field_name: sorted(group) for field_name, group in sorted(self.equivalents.items())
            },
        }
