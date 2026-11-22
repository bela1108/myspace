"""Backwards/forwards friendly alias for :mod:`regipy.snapshots`."""

from regipy.snapshots import (  # noqa: F401
    KEY_CLOCK_NOTE,
    SCHEMA_VERSION,
    VALUE_TIMESTAMP_NOTE,
    Snapshot,
    build_value_timelines,
    compare_snapshots,
)

__all__ = [
    "KEY_CLOCK_NOTE",
    "SCHEMA_VERSION",
    "VALUE_TIMESTAMP_NOTE",
    "Snapshot",
    "build_value_timelines",
    "compare_snapshots",
]
