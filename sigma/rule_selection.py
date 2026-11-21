"""Compatibility import for :mod:`sigma.selection`."""

from sigma.selection import (
    RuleCandidate,
    RuleSelection,
    RuleSelector,
    SelectionResult,
    SigmaRuleSelector,
    UncoveredRisk,
    brute_force_select,
    select_rules,
    select_rules_by_score,
    select_rules_exact,
    select_rules_exhaustive,
    select_rules_greedy,
    select_sigma_rules,
)

__all__ = [
    "RuleCandidate",
    "RuleSelection",
    "RuleSelector",
    "SelectionResult",
    "SigmaRuleSelector",
    "UncoveredRisk",
    "brute_force_select",
    "select_rules",
    "select_rules_by_score",
    "select_rules_exact",
    "select_rules_exhaustive",
    "select_rules_greedy",
    "select_sigma_rules",
]
