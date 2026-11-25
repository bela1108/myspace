class IncidentError(Exception):
    """Base class for offline incident re-computation failures."""


class InvalidEventError(IncidentError):
    """Raised when an event in the history cannot be applied as written."""


class StaleExemptionError(IncidentError):
    """Raised when an expired or path-mismatched exemption is used to close
    a finding occurrence.

    The engine never raises this out of :meth:`ReplayEngine.run`; a bad
    suppression attempt is instead recorded as a rejected decision so the
    failed attempt itself remains auditable.
    """


class DuplicateEventError(InvalidEventError):
    """Raised when the same event id appears twice in the event stream."""


class EventOrderError(InvalidEventError):
    """Raised when events are not ordered or reference unknown entities."""


class UnknownFindingError(InvalidEventError):
    """Raised when an event references a finding id that was never registered."""
