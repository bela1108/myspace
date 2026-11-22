"""Custom STIX 2.1 SDOs for the forensic evidence-comparison review.

* ``x-hash-capability-table`` — algorithm x review-date capability matrix.
* ``x-digest-cross-date-review`` — same short-text digest compared at the
  historical judgment date and at the current review date.
"""

import stix2.v21
from stix2.properties import (
    DictionaryProperty,
    ListProperty,
    ReferenceProperty,
    StringProperty,
)

CAPABILITY_VALUES = ("confirm", "lead", "inconclusive", "not_recorded")
RECOMPUTATION_WINDOW_VALUES = (
    "not_available_sample_never_retained",
    "not_applicable_report_not_yet_signed",
    "blocked_version_alignment_pending",
)
REVIEW_CLASSIFICATION_VALUES = (
    "lead_only",
    "recomputed",
    "missing_original_or_version",
)

@stix2.v21.CustomObject(
    "x-hash-capability-table",
    [
        ("name", StringProperty(required=True)),
        ("description", StringProperty(required=True)),
        ("x_review_date", StringProperty(required=True)),
        ("x_historical_judgment_date", StringProperty(required=True)),
        (
            "x_report_refs",
            ListProperty(ReferenceProperty(valid_types=["report"]), required=True),
        ),
        (
            "x_evidence_refs",
            ListProperty(
                ReferenceProperty(valid_types=["file", "artifact"]),
                required=True,
            ),
        ),
        (
            "x_algorithm_capability_entries",
            ListProperty(DictionaryProperty(), required=True),
        ),
    ],
)
class HashCapabilityTable:
    """Capability matrix: which algorithm can confirm, only lead, or is inconclusive."""


@stix2.v21.CustomObject(
    "x-digest-cross-date-review",
    [
        ("name", StringProperty(required=True)),
        ("description", StringProperty(required=True)),
        (
            "x_evidence_refs",
            ListProperty(
                ReferenceProperty(valid_types=["file", "artifact"]),
                required=True,
            ),
        ),
        (
            "x_report_refs",
            ListProperty(ReferenceProperty(valid_types=["report"]), required=True),
        ),
        (
            "x_capability_table_ref",
            ReferenceProperty(valid_types=["x-hash-capability-table"], required=True),
        ),
        (
            "x_short_text_ref",
            ReferenceProperty(valid_types=["artifact"], required=True),
        ),
        ("x_historical_judgment_date", StringProperty(required=True)),
        ("x_review_date", StringProperty(required=True)),
        (
            "x_algorithm_date_entries",
            ListProperty(DictionaryProperty(), required=True),
        ),
    ],
)
class DigestCrossDateReview:
    """Same short-text digest values assessed at two judgment dates."""
