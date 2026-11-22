"""The second submission cannot be reduced to a finite static tuple.

``dynamic_fields`` delegates to a call that Bandit cannot evaluate, so the
analysis retains an ``unprovable`` judgment and the concrete reason instead of
claiming that B was or was not exported.
"""

RECIPIENT = "partner-floor-planning"


def export(recipient, fields):
    """Stand-in for the application's own outbound export API."""
    return recipient, fields


def dynamic_fields():
    return load_fields()


def send_report():
    export(RECIPIENT, ("A",))
    export(RECIPIENT, dynamic_fields())
