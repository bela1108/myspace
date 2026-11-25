import enum


class EventType(str, enum.Enum):
    """The kinds of events understood by the replay engine."""

    FINDING_INTRODUCED = 'finding_introduced'
    CODE_MOVED = 'code_moved'
    FINDING_FORKED = 'finding_forked'
    OWNERSHIP_CHANGED = 'ownership_changed'
    EXEMPTION_GRANTED = 'exemption_granted'
    EXEMPTION_REVOKED = 'exemption_revoked'
    SUPPRESS = 'suppress'


class OwnerSource(str, enum.Enum):
    """Where the responsibility recorded for a decision came from."""

    OWNERSHIP_TABLE = 'ownership_table'
    CODE_MOVE = 'code_move'
    EVENT = 'event'


class Decision(str, enum.Enum):
    """Outcome recorded for each applied event."""

    REGISTERED = 'registered'
    MOVED = 'moved'
    FORKED = 'forked'
    OWNER_ASSIGNED = 'owner_assigned'
    EXEMPTION_APPLIED = 'exemption_applied'
    EXEMPTION_REVOKED = 'exemption_revoked'
    SUPPRESSED = 'suppressed'
    SUPPRESSION_REJECTED = 'suppression_rejected'


class OccurrenceStatus(str, enum.Enum):
    """Lifecycle state of one finding occurrence."""

    OPEN = 'open'
    SUPPRESSED = 'suppressed'


class ExemptionStatus(str, enum.Enum):
    """Time-aware state of an exemption record."""

    NOT_YET_VALID = 'not_yet_valid'
    ACTIVE = 'active'
    EXPIRED = 'expired'
    REVOKED = 'revoked'


class ReviewState(str, enum.Enum):
    """Whether an occurrence still has review work and time left."""

    OPEN = 'open'
    EXEMPT = 'exempt'
    PENDING = 'pending'
    OVERDUE = 'overdue'
    SUPPRESSED = 'suppressed'
