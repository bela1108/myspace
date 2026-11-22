"""Slot-scoped advisory adjudication for CPE inventories."""

from .engine import EvidenceTimeline, SlotAdjudicator
from .model import (
    Advisory,
    Cabinet,
    ClosureRecord,
    Component,
    Condition,
    QueryReport,
    Slot,
    Snapshot,
    Witness,
)
from .query import (
    AdvisoryCase,
    format_report,
    load_case,
    query,
    query_case,
    report_to_dict,
)

__all__ = [
    "Advisory",
    "AdvisoryCase",
    "Cabinet",
    "ClosureRecord",
    "Component",
    "Condition",
    "EvidenceTimeline",
    "QueryReport",
    "Slot",
    "SlotAdjudicator",
    "Snapshot",
    "Witness",
    "format_report",
    "load_case",
    "query",
    "query_case",
    "report_to_dict",
]
