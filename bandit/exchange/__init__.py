#
# Copyright 2026 Bandit Authors
#
# SPDX-License-Identifier: Apache-2.0
"""Security exception exchange between Bandit findings and external rules.

This package converts a Bandit scan report into two views of the same
findings:

* a *local* view keyed on Bandit rule IDs (``Bxxx``), which keeps the
  historical baseline readable; and
* an *exchange* view keyed on the rule numbering used by an external
  scanner.

Callers describe how local rules translate into external rules through an
exception mapping document.  Each mapping may target several external rules
(one-to-many), carries a validity period and states the context conditions
that every target finding has to satisfy before the exception is approved.
"""
from bandit.exchange.engine import ExceptionExchange
from bandit.exchange.model import (
    DECISION_STATES,
    APPROVED,
    CONFLICT,
    EXPIRED,
    MISSING_EVIDENCE,
    NO_MATCH,
    ContextMatcher,
    ExceptionMapping,
    Finding,
    TargetRule,
)

__all__ = [
    "DECISION_STATES",
    "APPROVED",
    "CONFLICT",
    "EXPIRED",
    "MISSING_EVIDENCE",
    "NO_MATCH",
    "ContextMatcher",
    "ExceptionExchange",
    "ExceptionMapping",
    "Finding",
    "TargetRule",
]
