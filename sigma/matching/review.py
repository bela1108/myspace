"""Pre-conversion review entry points.

The review surface intentionally mirrors :mod:`sigma.matching.attribution` so
callers can choose either terminology. Nothing here converts Sigma rules to a
query language; the event set is replayed directly against the matching engine.
"""

from sigma.matching.attribution import (
    AttributionReport,
    ChangeAttribution,
    ChangeAttributionReport,
    ChangeAttributor,
    ChangeKind,
    ChangeType,
    OfflineAttribution,
    PreConversionReview,
    RuleChange,
    analyze_changes,
    notified_queues,
    attribute_changes,
    replay_changes,
    replay_comparison,
)

__all__ = [
    "AttributionReport",
    "ChangeAttribution",
    "ChangeAttributionReport",
    "ChangeAttributor",
    "ChangeKind",
    "ChangeType",
    "OfflineAttribution",
    "PreConversionReview",
    "RuleChange",
    "analyze_changes",
    "notified_queues",
    "attribute_changes",
    "replay_changes",
    "replay_comparison",
]
