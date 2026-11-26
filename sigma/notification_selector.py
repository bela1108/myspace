"""Convenience import path for the post-match notification selector."""

from sigma.matching.notification_selector import *  # noqa: F403
from sigma.matching.notification_selector import (
    DeduplicationSelector,
    NotificationDeduplicator,
    NotificationSelector,
    select_deduplicated_notifications,
    select_notifications,
)

__all__ = [  # noqa: F405
    "NotificationSelector",
    "select_notifications",
    "NotificationDeduplicator",
    "DeduplicationSelector",
    "select_deduplicated_notifications",
]
