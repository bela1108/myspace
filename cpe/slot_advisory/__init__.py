"""Application-slot-scoped advisory adjudication for CPE inventories."""

from .engine import (
    ClosureNotAllowedError,
    SlotAdvisoryError,
    adjudicate_slot,
    create_closure,
    verify_closure,
)
from .lifecycle import migrate_slot, supplement_evidence
from .model import Advisory, Cabinet, Component, Condition, SlotSnapshot
from .query import query_file, run_query

__all__ = [
    "Advisory",
    "Cabinet",
    "Component",
    "Condition",
    "SlotSnapshot",
    "SlotAdvisoryError",
    "ClosureNotAllowedError",
    "adjudicate_slot",
    "create_closure",
    "verify_closure",
    "supplement_evidence",
    "migrate_slot",
    "run_query",
    "query_file",
]
