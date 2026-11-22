"""Offline counting contract checking for Sigma correlation rules.

This package implements an *offline* contract layer that sits between the
parsing of :class:`~sigma.correlations.SigmaCorrelationRule` objects and their
backend conversion.  A :term:`counting contract` declares, per log source:

* the field(s) that uniquely identify an operation (identity fields),
* field mappings that are *provably equivalent* for correlation purposes, and
* the minimum time precision the source can guarantee.

With these declarations the checker can decide for every branch of a
correlation rule whether a counting operation (event counting or unique-value
counting) is deterministically de-duplicable when the same logical operation is
ingested more than once (e.g. dual-write collection) or arrives without a
stable event identifier.  A single branch that cannot be decided makes the
whole correlation rule report a *locatable* undetermined result instead of
silently producing an inflated or collapsed count.
"""

from sigma.counting.contract import (
    CountingContractError,
    FieldEquivalence,
    LogSourceCountingContract,
    TimePrecision,
)
from sigma.counting.registry import CountingContractRegistry
from sigma.counting.checker import (
    BranchVerdict,
    ContractCheckResult,
    CountingContractChecker,
    CountingVerdict,
)
from sigma.counting.replay import (
    ReplayOutcome,
    ReplayScenario,
    ScenarioRunner,
)
from sigma.counting.report import CountingReport, CorrelationReportRecord

__all__ = [
    "CountingContractError",
    "FieldEquivalence",
    "LogSourceCountingContract",
    "TimePrecision",
    "CountingContractRegistry",
    "BranchVerdict",
    "ContractCheckResult",
    "CountingContractChecker",
    "CountingVerdict",
    "ReplayOutcome",
    "ReplayScenario",
    "ScenarioRunner",
    "CountingReport",
    "CorrelationReportRecord",
]
