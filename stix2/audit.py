"""Audit-oriented alias for testimony reconciliation."""

from .testimony_review import (
    hearsay_demo,
    reconcile_testimonies,
    review_testimony,
)

reconcile = reconcile_testimonies
review = review_testimony

__all__ = ["hearsay_demo", "reconcile", "reconcile_testimonies", "review", "review_testimony"]
