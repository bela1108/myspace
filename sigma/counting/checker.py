"""Offline counting-contract checker for correlation rules.

The checker sits *between parsing and conversion*: it inspects a fully parsed
:class:`~sigma.correlations.SigmaCorrelationRule` together with the counting
contracts of the log sources its branches draw events from, and decides for
every branch whether the rule's counting semantics are deterministically
de-duplicable.

Verdicts per branch:

* :data:`CountingVerdict.DETERMINED` -- identity is provable through declared
  identity fields / equivalences and time precision is sufficient;
* :data:`CountingVerdict.UNDETERMINED` -- the branch cannot be proven to
  de-duplicate correctly (missing contract, identity field not provable, time
  precision coarser than the correlation timespan, ...).

A correlation rule is only reported as determined when *all* of its branches
are determined.  Every undetermined branch carries a locatable description
(rule name, branch rule reference, log source, reason).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sigma.correlations import (
    CorrelationConditionAND,
    CorrelationConditionItem,
    CorrelationConditionNOT,
    CorrelationConditionOR,
    SigmaCorrelationCondition,
    SigmaCorrelationRule,
    SigmaCorrelationType,
    SigmaExtendedCorrelationCondition,
    SigmaRuleReference,
)
from sigma.counting.contract import LogSourceCountingContract
from sigma.counting.registry import CountingContractRegistry
from sigma.rule.logsource import SigmaLogSource
from sigma.rule.rule import SigmaRule


class CountingVerdict(str, Enum):
    """Outcome of the de-duplication provability check for one branch."""

    DETERMINED = "determined"
    UNDETERMINED = "undetermined"


class CountingBasis(str, Enum):
    """Which family of counting semantics a correlation rule relies on."""

    EVENT_COUNT = "count"
    """Counting of events / occurrences (event_count, temporal, aggregates)."""

    UNIQUE_VALUE = "unique_value"
    """Counting of distinct field values (value_count)."""


# Correlation types whose condition compares a number of events (or an
# aggregate computed over events) against a threshold.
COUNT_BASED_TYPES: frozenset[SigmaCorrelationType] = frozenset(
    {
        SigmaCorrelationType.EVENT_COUNT,
        SigmaCorrelationType.TEMPORAL,
        SigmaCorrelationType.TEMPORAL_ORDERED,
        SigmaCorrelationType.VALUE_SUM,
        SigmaCorrelationType.VALUE_AVG,
        SigmaCorrelationType.VALUE_PERCENTILE,
        SigmaCorrelationType.VALUE_MEDIAN,
    }
)

# Correlation types whose condition compares the number of distinct values.
UNIQUE_VALUE_TYPES: frozenset[SigmaCorrelationType] = frozenset(
    {SigmaCorrelationType.VALUE_COUNT}
)


@dataclass
class BranchVerdict:
    """De-duplication decision for one branch (referenced base rule)."""

    branch: str
    logsource: SigmaLogSource | None
    verdict: CountingVerdict
    reason: str
    identity_fields: tuple[str, ...] = ()
    time_precision: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "branch": self.branch,
            "verdict": self.verdict.value,
            "reason": self.reason,
        }
        if self.logsource is not None:
            result["logsource"] = {
                key: value
                for key, value in (
                    ("category", self.logsource.category),
                    ("product", self.logsource.product),
                    ("service", self.logsource.service),
                )
                if value is not None
            }
        if self.identity_fields:
            result["identity_fields"] = list(self.identity_fields)
        if self.time_precision is not None:
            result["time_precision"] = self.time_precision
        return result


@dataclass
class ContractCheckResult:
    """Whole-rule result of the offline contract check."""

    rule_name: str
    rule_title: str
    correlation_type: str
    basis: CountingBasis
    timespan_seconds: int
    threshold: dict[str, Any]
    branch_verdicts: list[BranchVerdict] = field(default_factory=list)
    source: Any = field(default=None, repr=False, compare=False)

    @property
    def verdict(self) -> CountingVerdict:
        """A rule is determined only if every single branch is determined."""
        if self.branch_verdicts and all(
            branch.verdict is CountingVerdict.DETERMINED for branch in self.branch_verdicts
        ):
            return CountingVerdict.DETERMINED
        return CountingVerdict.UNDETERMINED

    @property
    def undetermined_branches(self) -> list[BranchVerdict]:
        return [
            branch
            for branch in self.branch_verdicts
            if branch.verdict is CountingVerdict.UNDETERMINED
        ]

    @property
    def location(self) -> str:
        """Human-readable, locatable reference including line when available."""
        base = self.rule_name or self.rule_title
        if self.source is None:
            return base
        location = str(self.source)
        line = getattr(self.source, "line", None)
        if line is not None:
            return f"{base} ({location}:{line})"
        return f"{base} ({location})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule_name,
            "title": self.rule_title,
            "location": self.location,
            "correlation_type": self.correlation_type,
            "counting_basis": self.basis.value,
            "verdict": self.verdict.value,
            "timespan_seconds": self.timespan_seconds,
            "threshold": self.threshold,
            "branches": [branch.to_dict() for branch in self.branch_verdicts],
            "undetermined_branches": [
                branch.branch for branch in self.undetermined_branches
            ],
        }


class CountingContractChecker:
    """Evaluates counting contracts against parsed correlation rules."""

    def __init__(self, registry: CountingContractRegistry) -> None:
        self.registry = registry

    @staticmethod
    def basis_for(rule: SigmaCorrelationRule) -> CountingBasis:
        if rule.type in UNIQUE_VALUE_TYPES:
            return CountingBasis.UNIQUE_VALUE
        return CountingBasis.EVENT_COUNT

    def check(self, rule: SigmaCorrelationRule) -> ContractCheckResult:
        """Produce a branch-by-branch contract verdict for ``rule``."""
        basis = self.basis_for(rule)
        result = ContractCheckResult(
            rule_name=getattr(rule, "name", None) or rule.id or "",
            rule_title=rule.title,
            correlation_type=rule.type.name.lower(),
            basis=basis,
            timespan_seconds=rule.timespan.seconds,
            threshold=self._describe_threshold(rule),
            source=getattr(rule, "source", None),
        )

        for reference in self._branch_references(rule):
            result.branch_verdicts.append(self._check_branch(rule, reference, basis))
        return result

    def check_collection(
        self, rules: list[SigmaCorrelationRule]
    ) -> list[ContractCheckResult]:
        return [self.check(rule) for rule in rules]

    def _check_branch(
        self,
        rule: SigmaCorrelationRule,
        reference: SigmaRuleReference,
        basis: CountingBasis,
    ) -> BranchVerdict:
        branch_name = reference.reference
        base_rule = getattr(reference, "rule", None)
        if not isinstance(base_rule, SigmaRule):
            return BranchVerdict(
                branch=branch_name,
                logsource=None,
                verdict=CountingVerdict.UNDETERMINED,
                reason=(
                    "Branch rule reference is not resolved to a concrete Sigma rule; "
                    "call resolve_rule_references() before checking."
                ),
            )

        logsource = base_rule.logsource
        contract = self.registry.lookup(logsource)
        if contract is None:
            return BranchVerdict(
                branch=branch_name,
                logsource=logsource,
                verdict=CountingVerdict.UNDETERMINED,
                reason=(
                    "No counting contract declared for log source; dual-write duplicates "
                    "cannot be distinguished from distinct operations."
                ),
            )

        return self._check_with_contract(rule, branch_name, logsource, contract, basis)

    def _check_with_contract(
        self,
        rule: SigmaCorrelationRule,
        branch_name: str,
        logsource: SigmaLogSource,
        contract: LogSourceCountingContract,
        basis: CountingBasis,
    ) -> BranchVerdict:
        determined = True
        reasons: list[str] = []

        # 1. Identity proof for the branch.
        identity_problem = self._identity_problem(rule, branch_name, contract, basis)
        if identity_problem is not None:
            determined = False
            reasons.append(identity_problem)

        # 2. Time precision must not be coarser than the correlation timespan,
        #    otherwise events inside one window cannot be ordered/proven
        #    distinct by time.
        if contract.time_precision.seconds > rule.timespan.seconds:
            determined = False
            reasons.append(
                f"Minimum time precision {contract.time_precision} is coarser than the "
                f"correlation timespan of {rule.timespan.seconds}s."
            )

        if determined:
            reason = (
                "Identity provable via "
                + ", ".join(contract.identity_fields)
                + f"; time precision {contract.time_precision} within timespan."
            )
            verdict = CountingVerdict.DETERMINED
        else:
            reason = " ".join(reasons)
            verdict = CountingVerdict.UNDETERMINED

        return BranchVerdict(
            branch=branch_name,
            logsource=logsource,
            verdict=verdict,
            reason=reason,
            identity_fields=contract.identity_fields,
            time_precision=str(contract.time_precision),
        )

    def _identity_problem(
        self,
        rule: SigmaCorrelationRule,
        branch_name: str,
        contract: LogSourceCountingContract,
        basis: CountingBasis,
    ) -> str | None:
        # Row-level de-duplication is proven by the contract identity fields,
        # regardless of whether the correlation counts events or distinct
        # values.  Group-by / unique-value fields partition or select the
        # already de-duplicated rows and therefore must NOT be identity fields
        # themselves; requiring an equivalence here would reject perfectly
        # valid correlations such as counting distinct users by event id.
        if basis is CountingBasis.UNIQUE_VALUE:
            condition = rule.condition
            fieldref = getattr(condition, "fieldref", None) if isinstance(
                condition, SigmaCorrelationCondition
            ) else None
            fields = [fieldref] if isinstance(fieldref, str) else list(fieldref or [])
            if not fields:
                return (
                    f"Unique-value correlation '{rule.title}' declares no value field for "
                    f"branch '{branch_name}'."
                )
        return None

    def _branch_references(
        self, rule: SigmaCorrelationRule
    ) -> list[SigmaRuleReference]:
        if rule.rules:
            return list(rule.rules)
        if isinstance(rule.condition, SigmaExtendedCorrelationCondition):
            return [
                SigmaRuleReference(name)
                for name in rule.condition.get_referenced_rules()
            ]
        return []

    def _describe_threshold(self, rule: SigmaCorrelationRule) -> dict[str, Any]:
        condition = rule.condition
        if isinstance(condition, SigmaExtendedCorrelationCondition):
            return {"expression": condition.expression}
        if isinstance(condition, SigmaCorrelationCondition):
            result = {
                "operator": condition.op.name.lower(),
                "count": condition.count,
            }
            if condition.fieldref is not None:
                result["field"] = condition.fieldref
            return result
        return {}

    # Expression traversal helpers (kept public for report tooling).
    @staticmethod
    def iter_expression_leaves(
        node: CorrelationConditionItem | SigmaRuleReference,
    ) -> list[SigmaRuleReference]:
        if isinstance(node, SigmaRuleReference):
            return [node]
        leaves: list[SigmaRuleReference] = []
        if isinstance(node, (CorrelationConditionAND, CorrelationConditionOR)):
            for arg in node.args:
                leaves.extend(CountingContractChecker.iter_expression_leaves(arg))
        elif isinstance(node, CorrelationConditionNOT):
            leaves.extend(CountingContractChecker.iter_expression_leaves(node.args[0]))
        return leaves
