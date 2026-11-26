"""Short import path for the local review process."""

from .testimony_review import *  # noqa: F401,F403
from .testimony_review import (
    TestimonyReview,
    hearsay_demo,
    hearsay_fixture,
    maximal_coexisting_evidence_sets,
    review_testimonies,
    review_testimony,
)

review = review_testimony
__all__ = [
    "TestimonyReview", "hearsay_demo", "hearsay_fixture",
    "maximal_coexisting_evidence_sets", "review", "review_testimony",
    "review_testimonies",
]
