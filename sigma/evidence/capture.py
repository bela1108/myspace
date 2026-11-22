from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sigma.evidence.provenance import FieldProvenance


@dataclass
class ConversionRecord:
    """
    The conversion-side half of an evidence review.

    A backend produces queries after applying its processing pipeline.  The pipeline's
    ``field_mappings`` are the link between the rule's original field names and the
    fields used by the converted query.  Keeping that snapshot with the converted
    queries allows the offline reviewer to resolve aliases and derived fields without
    re-running the conversion.
    """

    rule: Any
    queries: list[Any] = field(default_factory=list)
    field_provenance: FieldProvenance = field(default_factory=FieldProvenance)
    output_format: str | None = None

    @property
    def provenance(self) -> FieldProvenance:
        return self.field_provenance

    @classmethod
    def capture(
        cls,
        backend: Any,
        rule: Any = None,
        *,
        queries: list[Any] | None = None,
        output_format: str | None = None,
    ) -> ConversionRecord:
        """Capture the field provenance left by a backend conversion."""
        if queries is None and rule is not None:
            getter = getattr(rule, "get_conversion_result", None)
            if getter is not None:
                try:
                    queries = list(getter())
                except Exception:
                    queries = []
            else:
                queries = []

        pipeline = getattr(backend, "last_processing_pipeline", None)
        provenance = FieldProvenance.from_processing_pipeline(pipeline)
        if rule is not None:
            provenance.merge(
                FieldProvenance.from_correlation_aliases(getattr(rule, "aliases", None))
            )
        return cls(
            rule=rule,
            queries=list(queries or []),
            field_provenance=provenance,
            output_format=output_format,
        )

    @classmethod
    def from_pipeline(
        cls,
        pipeline: Any,
        *,
        rule: Any = None,
        queries: list[Any] | None = None,
        output_format: str | None = None,
    ) -> ConversionRecord:
        """Capture provenance directly from an applied processing pipeline."""
        provenance = FieldProvenance.from_processing_pipeline(pipeline)
        if rule is not None:
            provenance.merge(
                FieldProvenance.from_correlation_aliases(getattr(rule, "aliases", None))
            )
        return cls(
            rule=rule,
            queries=list(queries or []),
            field_provenance=provenance,
            output_format=output_format,
        )


def capture_conversion(
    backend: Any,
    rule: Any = None,
    *,
    queries: list[Any] | None = None,
    output_format: str | None = None,
) -> ConversionRecord:
    """Convenience wrapper around :meth:`ConversionRecord.capture`."""
    return ConversionRecord.capture(backend, rule, queries=queries, output_format=output_format)
