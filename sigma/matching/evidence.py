from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sigma.matching.event import Event
    from sigma.matching.match import SigmaMatch


@dataclass
class CorrelationEvidence:
    """A single evidence item binding a contributing event to the rule and window.

    Each piece of evidence records which rule produced the contributing match, the
    shift / receiving window that accepted the underlying event, and the trigger
    window (correlation timespan) of the correlation rule that consumed it.
    """

    event: Event
    rule_name: str
    shift: str | None
    event_timestamp: datetime
    window_start: datetime
    window_end: datetime
    timespan_seconds: int
    group_values: dict[str, Any] | None = None


@dataclass
class RetractionResult:
    """Outcome of retracting one event from a correlation matcher.

    ``active`` holds the correlation matches that still hold after retraction,
    each carrying an updated evidence list without the retracted event.
    ``revoked`` holds the matches that no longer hold, preserving the evidence
    that supported them at firing time so responsibility can be discharged.
    """

    retracted_event: Event
    active: list[SigmaMatch] = field(default_factory=list)
    revoked: list[SigmaMatch] = field(default_factory=list)

    @property
    def matches(self) -> list[SigmaMatch]:
        """All correlation matches involved in the retraction (active then revoked)."""
        return [*self.active, *self.revoked]
