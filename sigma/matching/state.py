from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

from sigma.matching.event import Event
from sigma.matching.match import SigmaMatch


class SlidingWindowState:
    """Manages sliding time window state for correlation rules."""

    def __init__(self, window_seconds: int, max_entries: int | None = None) -> None:
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        # group_key -> deque of (timestamp, match)
        self._state: dict[tuple[Any, ...], deque[tuple[datetime, SigmaMatch]]] = defaultdict(deque)

    def add(self, group_key: tuple[Any, ...], match: SigmaMatch) -> None:
        """Add a match to the state for the given group key."""
        entries = self._state[group_key]
        entries.append((match.timestamp, match))
        if self.max_entries is not None and len(entries) > self.max_entries:
            entries.popleft()

    def get_window(self, group_key: tuple[Any, ...], now: datetime) -> list[SigmaMatch]:
        """Get all matches within the time window for the given group key."""
        self._evict_group(group_key, now)
        return [match for _, match in self._state[group_key]]

    def latest_timestamp(self, group_key: tuple[Any, ...]) -> datetime | None:
        """Return the newest timestamp tracked for a group, or None if it is empty."""
        entries = self._state.get(group_key)
        if entries:
            return entries[-1][0]
        return None

    def remove_event(self, event: Event) -> list[tuple[Any, ...]]:
        """Remove every match carrying ``event`` and return the affected group keys.

        A single event may back more than one stored match (for example when several
        base rules match it), so all entries referencing it are removed. Empty groups
        are pruned the same way window eviction prunes them.
        """
        affected: list[tuple[Any, ...]] = []
        for group_key, entries in list(self._state.items()):
            remaining = deque(
                (timestamp, match)
                for timestamp, match in entries
                if event not in match.events
            )
            if len(remaining) != len(entries):
                affected.append(group_key)
                if remaining:
                    self._state[group_key] = remaining
                else:
                    del self._state[group_key]
        return affected

    def _evict_group(self, group_key: tuple[Any, ...], now: datetime) -> None:
        """Remove entries outside the time window."""
        entries = self._state[group_key]
        cutoff = now - timedelta(seconds=self.window_seconds)
        while entries and entries[0][0] < cutoff:
            entries.popleft()

    def evict(self) -> None:
        """Remove empty groups."""
        empty_keys = [k for k, v in self._state.items() if not v]
        for k in empty_keys:
            del self._state[k]
