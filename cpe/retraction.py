# -*- coding: utf-8 -*-

"""Retraction-impact review entry points.

This module re-exports :mod:`cpe.impact` for callers that organise the review
around the retraction lifecycle rather than the advisory object.
"""

from .impact import *  # noqa: F401,F403
from .impact import __all__ as _impact_all

__all__ = list(_impact_all)
