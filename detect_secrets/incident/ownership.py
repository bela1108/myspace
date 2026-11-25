"""Time-aware responsibility resolution over explicit ownership history.

Responsibility follows the code path.  When code moves, the rule matching the
*new* path at that moment determines the owning team, and the exact ownership
record id is always returned so every later decision can cite it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from typing import List
from typing import Optional

from detect_secrets.incident.models import OwnershipRule


@dataclass(frozen=True)
class OwnershipResolution:
    team: str
    record_id: str
    source: str
    path_prefix: str


class OwnershipBook:
    """In-memory lookup over the repository ownership history table."""

    def __init__(self, rules: Iterable[OwnershipRule]) -> None:
        self.rules: List[OwnershipRule] = list(rules)
        seen = set()
        for rule in self.rules:
            if rule.record_id in seen:
                raise ValueError(f"duplicate ownership record id: {rule.record_id}")
            seen.add(rule.record_id)

    def _candidates(self, path: str, at: str) -> List[OwnershipRule]:
        candidates = [
            rule
            for rule in self.rules
            if rule.in_force_at(at) and rule.covers_path(path)
        ]
        # Longest matching prefix wins; record id is a deterministic tie-break.
        candidates.sort(
            key=lambda rule: (len(rule.path_prefix.rstrip("/")), rule.record_id),
        )
        return candidates

    def resolve(
        self,
        path: str,
        at: str,
        fallback_team: Optional[str] = None,
        fallback_record_id: Optional[str] = None,
    ) -> OwnershipResolution:
        """Return the responsible team for ``path`` at time ``at``.

        If no ownership record covers the path, the carried-over fallback
        (the previous owner on a move) is used and clearly labelled as such.
        """
        candidates = self._candidates(path, at)
        if candidates:
            chosen = candidates[-1]
            return OwnershipResolution(
                team=chosen.team,
                record_id=chosen.record_id,
                source="ownership_table",
                path_prefix=chosen.path_prefix,
            )
        if fallback_team is not None:
            return OwnershipResolution(
                team=fallback_team,
                record_id=fallback_record_id or "carried-over",
                source="code_move",
                path_prefix=path,
            )
        raise LookupError(f"no ownership record covers {path} at {at}")
