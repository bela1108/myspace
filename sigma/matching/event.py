from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


_UNSET: Any = object()


@dataclass(frozen=True)
class EventLogSource:
    """Lightweight logsource descriptor for events."""

    category: str | None = None
    product: str | None = None
    service: str | None = None

    def as_tuple(self) -> tuple[str | None, str | None, str | None]:
        return (self.category, self.product, self.service)


@dataclass
class Event:
    """A parsed log event to be matched against Sigma rules."""

    timestamp: datetime
    logsource: EventLogSource
    data: dict[str, Any]
    raw: str | None = None
    _raw_cache: str | None = field(init=False, default=None, repr=False, compare=False)
    # Shift / receiving window that accepted the event. Used to attribute
    # correlation evidence to the shift that originally received the event.
    shift: str | None = None
    # Identity of the operator that confirmed this event, if anyone did.
    confirmed_by: str | None = None
    # Immutable audit trail of prior revisions: (revision, data, confirmed_by).
    revision_history: list[EventRevision] = field(default_factory=list)

    def get_raw(self) -> str:
        """Return raw log representation, falling back to JSON-serialized data."""
        if self.raw is not None:
            return self.raw
        if self._raw_cache is None:
            self._raw_cache = json.dumps(self.data)
        return self._raw_cache

    def revise(
        self,
        data: dict[str, Any],
        *,
        confirmed_by: str | None = None,
        raw: Any = _UNSET,
    ) -> Event:
        """Apply a revision while preserving the original confirmation trail.

        The currently visible state (including whoever originally confirmed it) is
        appended to ``revision_history`` before the new data is applied. Subsequent
        revisions therefore keep reachable the identity that confirmed every prior
        version of the event.
        """
        self.revision_history.append(
            EventRevision(
                revision=len(self.revision_history) + 1,
                data=dict(self.data),
                confirmed_by=self.confirmed_by,
            )
        )
        self.data = data
        if raw is not _UNSET:
            self.raw = raw
        self._raw_cache = None
        if confirmed_by is not None:
            self.confirmed_by = confirmed_by
        return self

    def original_confirmer(self) -> str | None:
        """Return whoever confirmed the first version of the event, if anyone."""
        if self.revision_history:
            return self.revision_history[0].confirmed_by
        return self.confirmed_by


@dataclass(frozen=True)
class EventRevision:
    """An immutable record of a prior revision of an Event."""

    revision: int
    data: dict[str, Any]
    confirmed_by: str | None = None
