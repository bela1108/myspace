"""Reconciliation-oriented alias for testimony review."""

from .testimony_review import reconcile_testimonies, review_testimony

reconcile = reconcile_testimonies

__all__ = ["reconcile", "reconcile_testimonies", "review_testimony"]
