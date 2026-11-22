"""A and B can leave through two co-executable submissions.

``FLOOR_FIELDS`` is a static tuple.  ``shift_fields`` uses tuple unpacking and
a finite same-module return.  Both export calls use the same outbound
recipient and can run during the same report generation.
"""

RECIPIENT = "partner-floor-planning"
FLOOR_FIELDS = ("A",)


def export(recipient, fields):
    """Stand-in for the application's own outbound export API."""
    return recipient, fields


def shift_fields():
    floor, shift = ("A", "B")
    return (shift,)


def send_report():
    export(RECIPIENT, FLOOR_FIELDS)
    export(RECIPIENT, shift_fields())
