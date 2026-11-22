# -*- coding: utf-8 -*-

"""Advisory-condition helpers.

This module re-exports the advisory and conditional-expression objects from
:mod:`cpe.impact` so callers can import the advisory vocabulary directly.
"""

from .impact import Advisory, ConditionResult, Reason, ReasonCode

__all__ = ["Advisory", "ConditionResult", "Reason", "ReasonCode"]
