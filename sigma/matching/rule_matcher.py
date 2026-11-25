from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sigma.matching.compiler import CompiledMatcher, MatchCompiler
from sigma.matching.event import Event
from sigma.matching.match import SigmaMatch
from sigma.processing.provenance import FieldProvenanceGraph
from sigma.processing.tracking import FieldMappingTracking

if TYPE_CHECKING:
    from sigma.rule.rule import SigmaRule


class SigmaRuleMatcher:
    """Evaluates a single SigmaRule against events using a precompiled matcher."""

    def __init__(
        self,
        rule: SigmaRule,
        compiler: MatchCompiler,
        processing_tracking: FieldMappingTracking | None = None,
        provenance: FieldProvenanceGraph | None = None,
        processing_items: set[str] | None = None,
        processing_pipeline: Any | None = None,
    ) -> None:
        self.rule = rule
        self._matcher: CompiledMatcher = compiler.compile_rule(rule)
        self.processing_tracking = processing_tracking
        self.provenance = provenance or getattr(processing_tracking, "provenance", None)
        self.processing_items = set(processing_items or ())
        self.processing_pipeline = processing_pipeline

    def matches(self, event: Event) -> SigmaMatch | None:
        """Return a SigmaMatch if the event matches this rule, else None."""
        raw = event.get_raw()
        if self._matcher(event.data, raw):
            return SigmaMatch(
                rule=self.rule,
                events=[event],
                timestamp=event.timestamp,
                processing_tracking=self.processing_tracking,
                provenance=self.provenance,
                processing_items=self.processing_items,
                processing_pipeline=self.processing_pipeline,
            )
        return None
