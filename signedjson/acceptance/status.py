"""Event acceptance statuses.

``NEEDS_REVIEW`` collects the statuses that cannot be resolved without a
human: misbound originals and mutually exclusive (but both validly signed)
branches.
"""

CONFIRMED = "confirmed"
AWAITING_PREDECESSOR = "awaiting_predecessor"
BLOCKED = "blocked"
MISBOUND = "misbound"
FORK = "fork"

NEEDS_REVIEW = (MISBOUND, FORK)

# Precedence used when more than one condition applies to one event.
ORDER = (
    MISBOUND,
    FORK,
    AWAITING_PREDECESSOR,
    BLOCKED,
    CONFIRMED,
)
