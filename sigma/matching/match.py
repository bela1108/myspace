from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sigma.matching.event import Event
    from sigma.matching.explanation import MatchExplanation
    from sigma.rule.base import SigmaRuleBase


@dataclass
class SigmaMatch:
    """Result of a successful Sigma rule match against one or more events."""

    rule: SigmaRuleBase
    events: list[Event]
    timestamp: datetime
    group_values: dict[str, Any] | None = None

    def explain(self, event: Event | None = None) -> MatchExplanation:
        """Return a minimal-field explanation for this match."""
        from sigma.matching.explanation import explain_match

        return explain_match(self, event)

    def explanation(self, event: Event | None = None) -> MatchExplanation:
        """Alias for :meth:`explain`."""
        return self.explain(event)
