"""Offline attribution for pre-conversion review.

Kept as a compatibility import surface; the engine is implemented in
:mod:`sigma.matching.attribution`.
"""

from sigma.review import *  # noqa: F401,F403
from sigma.review import __all__ as _review_all

__all__ = list(_review_all)
