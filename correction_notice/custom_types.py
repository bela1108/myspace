"""Custom STIX 2.1 SDOs used to model local, non-shared workflow data.

Both types are prefixed with ``x-`` as required by the STIX 2.1 spec for
custom objects and are only ever instantiated from local synthetic data.
"""

from stix2 import CustomObject
from stix2.properties import (
    BooleanProperty,
    ListProperty,
    ReferenceProperty,
    StringProperty,
    TimestampProperty,
)


@CustomObject(
    "x-delivery-receipt",
    [
        ("created", TimestampProperty(required=True)),
        ("modified", TimestampProperty(required=True)),
        # The recipient (an identity) this receipt belongs to.
        (
            "x_recipient_ref",
            ReferenceProperty(valid_types="identity", required=True),
        ),
        # The original notice the recipient was asked to sign for.
        (
            "x_notice_ref",
            ReferenceProperty(valid_types="report", required=True),
        ),
        # Section identifiers actually signed for, e.g. ["section-a"].
        (
            "x_signed_sections",
            ListProperty(StringProperty()),
        ),
        # False models a recipient that explicitly refused/never signed.
        ("x_signed", BooleanProperty(required=True)),
    ],
)
class DeliveryReceipt:
    """Local fake acknowledgement of which notice sections were received."""


@CustomObject(
    "x-recipient-decision",
    [
        ("created", TimestampProperty(required=True)),
        ("modified", TimestampProperty(required=True)),
        (
            "x_recipient_ref",
            ReferenceProperty(valid_types="identity", required=True),
        ),
        (
            "x_notice_ref",
            ReferenceProperty(valid_types="report", required=True),
        ),
        # "included" (must receive the correction) or "excluded".
        ("x_decision", StringProperty(required=True)),
        # Machine-readable reason, e.g. "missing-section-a-signature".
        ("x_reason", StringProperty(required=True)),
        # Human-readable explanation, so the same list answers "why not?".
        ("x_explanation", StringProperty(required=True)),
        ("x_signed_sections", ListProperty(StringProperty())),
    ],
)
class RecipientDecision:
    """Audit record of the include/exclude decision for one recipient."""
