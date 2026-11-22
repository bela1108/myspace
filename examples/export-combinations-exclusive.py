"""A and B are exported from mutually exclusive branches.

The protected pair is A+B.  Even though both labels use the same recipient,
only one branch can run for a given report.
"""

RECIPIENT = "partner-floor-planning"


def export(recipient, fields):
    """Stand-in for the application's own outbound export API."""
    return recipient, fields


def send_report(include_shift):
    if include_shift:
        export(RECIPIENT, ("A",))
    else:
        export(RECIPIENT, ("B",))
