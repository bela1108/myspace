#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Three-valued CPE matching for advisory impact decisions.

The core CPE package exposes boolean helpers.  Boolean matching is not enough
for an audit: a missing or wildcard inventory value must remain ``UNKNOWN``,
because a failed match is not evidence of absence.  This module combines the
pairwise relations from :class:`CPESet2_3` into MATCH / NO_MATCH / UNKNOWN and
evaluates CPE Language style logical expressions with the same three values.
"""

from dataclasses import dataclass, field
from typing import List

from ..cpe2_3 import CPE2_3
from ..cpe2_3_wfn import CPE2_3_WFN
from ..cpeset2_3 import CPESet2_3


MATCH = "MATCH"
NO_MATCH = "NO_MATCH"
UNKNOWN = "UNKNOWN"


@dataclass
class FactResult:
    """Result of one advisory CPE selector against one inventory record."""

    selector: str
    value: str
    detail: str = ""

    def to_dict(self):
        return {
            "selector": self.selector,
            "value": self.value,
            "detail": self.detail,
        }


@dataclass
class ExpressionEvaluation:
    """Three-valued result plus the facts that justify it."""

    value: str
    basis: List[str] = field(default_factory=list)
    facts: List[FactResult] = field(default_factory=list)

    @property
    def matched_selectors(self):
        return [fact.selector for fact in self.facts if fact.value == MATCH]

    @property
    def unknown_selectors(self):
        return [fact.selector for fact in self.facts if fact.value == UNKNOWN]

    @property
    def disjoint_selectors(self):
        return [fact.selector for fact in self.facts if fact.value == NO_MATCH]

    def to_dict(self):
        return {
            "value": self.value,
            "basis": list(self.basis),
            "facts": [fact.to_dict() for fact in self.facts],
        }


def _as_wfn(cpe_name):
    """Convert any accepted CPE 2.3 style into a WFN object."""

    parsed = CPE2_3(cpe_name)
    if isinstance(parsed, CPE2_3_WFN):
        return parsed
    return CPE2_3_WFN(parsed.as_wfn())


def _normalise_part(value):
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


def cpe_part(cpe_name):
    """Return the CPE part (a/h/o) for ``cpe_name``; None if malformed."""

    try:
        values = _as_wfn(cpe_name).get_attribute_values("part")
    except Exception:
        return None
    if not values:
        return "ANY"
    return _normalise_part(values[0]) or "ANY"


def cpe_relation(selector, target):
    """
    Compare an advisory selector with an inventory CPE name.

    The selector is the broad advisory description; the target is the
    concrete asset component.  The result is:

    * ``MATCH`` when every pairwise relation is EQUAL or SUPERSET;
    * ``NO_MATCH`` when at least one attribute is provably DISJOINT;
    * ``UNKNOWN`` otherwise, including SUBSET and UNDEFINED relations.

    The distinction matters: only DISJOINT is proof of absence.  A wildcard
    or missing value in the inventory produces UNKNOWN, not NO_MATCH.
    """

    try:
        selector_wfn = _as_wfn(selector)
        target_wfn = _as_wfn(target)
    except Exception as exc:
        return UNKNOWN, "CPE 无法解析：{0}".format(exc)

    pairs = list(CPESet2_3.compare_wfns(selector_wfn, target_wfn))
    disjoint = [attribute for attribute, relation in pairs
                if relation == CPESet2_3.LOGICAL_VALUE_DISJOINT]
    if disjoint:
        return NO_MATCH, "属性 {0} 可证明不相交".format(", ".join(disjoint))

    allowed = (CPESet2_3.LOGICAL_VALUE_SUPERSET,
               CPESet2_3.LOGICAL_VALUE_EQUAL)
    if all(relation in allowed for _, relation in pairs):
        return MATCH, "所有属性均为 EQUAL 或 SUPERSET"

    undefined = [attribute for attribute, relation in pairs
                 if relation == CPESet2_3.LOGICAL_VALUE_UNDEFINED]
    subset = [attribute for attribute, relation in pairs
              if relation == CPESet2_3.LOGICAL_VALUE_SUBSET]
    if undefined or subset:
        detail = []
        if undefined:
            detail.append("UNDEFINED({0})".format(", ".join(undefined)))
        if subset:
            detail.append("SUBSET({0})".format(", ".join(subset)))
        return UNKNOWN, "关系不足以判定：" + "; ".join(detail)

    return UNKNOWN, "关系不足以判定"


def _negate(value):
    if value == MATCH:
        return NO_MATCH
    if value == NO_MATCH:
        return MATCH
    return UNKNOWN


def _combine(operator, values):
    if not values:
        return NO_MATCH
    operator = (operator or "OR").upper()
    if operator == "AND":
        if NO_MATCH in values:
            return NO_MATCH
        if UNKNOWN in values:
            return UNKNOWN
        return MATCH
    if operator == "OR":
        if MATCH in values:
            return MATCH
        if UNKNOWN in values:
            return UNKNOWN
        return NO_MATCH
    raise ValueError("unsupported logical operator: {0}".format(operator))


def _component_value(selector, components, manifest_complete):
    """
    Evaluate one selector against the matching parts of an asset.

    A matching component is existential: one MATCH proves the selector.
    If no component matches, NO_MATCH is proved only when the installation
    manifest is complete.  Otherwise an unlisted component could still match.
    """

    try:
        selector_part = cpe_part(selector)
    except Exception as exc:
        fact = FactResult(selector, UNKNOWN, "选择器无法解析：{0}".format(exc))
        return fact

    relevant = [component for component in components
                if selector_part == "ANY" or cpe_part(component.cpe) in (selector_part, "ANY", None)]
    if not relevant:
        if manifest_complete:
            return FactResult(
                selector, NO_MATCH,
                "安装清单完整，但没有 part={0} 的组件".format(selector_part))
        return FactResult(
            selector, UNKNOWN,
            "安装清单不完整，缺少 part={0} 的组件记录".format(selector_part))

    results = []
    details = []
    for component in relevant:
        value, detail = cpe_relation(selector, component.cpe)
        results.append((component, value, detail))
        details.append("{0}[{1}]={2} ({3})".format(
            component.slot, component.cpe, value, detail))
        if value == MATCH:
            return FactResult(selector, MATCH, "; ".join(details))

    unknown = [item for item in results if item[1] == UNKNOWN]
    if unknown:
        return FactResult(selector, UNKNOWN, "; ".join(details))
    if manifest_complete:
        return FactResult(selector, NO_MATCH, "; ".join(details))
    return FactResult(
        selector, UNKNOWN,
        "; ".join(details) + "; 已知组件均不相交，但清单不完整")


def _selector_from_match(cpe_match):
    for key in ("cpe23Uri", "cpe22Uri", "cpe"):
        if cpe_match.get(key):
            return cpe_match[key]
    raise ValueError("cpe_match entry has no CPE name")


def _eval_node(node, components, manifest_complete):
    operator = node.get("operator", "OR")
    basis = []
    facts = []
    values = []

    for child in node.get("children", []) or []:
        child_result = _eval_node(child, components, manifest_complete)
        values.append(child_result.value)
        facts.extend(child_result.facts)
        basis.extend(child_result.basis)

    exclusions = []
    for cpe_match in node.get("cpe_match", []) or []:
        selector = _selector_from_match(cpe_match)
        fact = _component_value(selector, components, manifest_complete)
        facts.append(fact)
        basis.append(fact.detail)
        if cpe_match.get("vulnerable", True):
            values.append(fact.value)
        elif fact.value == MATCH:
            exclusions.append(fact)

    if exclusions:
        value = NO_MATCH
        basis.append("命中显式非脆弱条目，排除匹配")
    else:
        value = _combine(operator, values)
        basis.append("{0} 组合 {1} 个判断 -> {2}".format(
            operator.upper(), len(values), value))

    negate = node.get("negate", False)
    if negate is True or str(negate).upper() == "TRUE":
        value = _negate(value)
        basis.append("逻辑取反 -> {0}".format(value))

    return ExpressionEvaluation(value=value, basis=basis, facts=facts)


def evaluate_expression(expression, components, manifest_complete):
    """
    Evaluate a CPE Language / NVD-style expression against inventory.

    ``expression`` may be one logical-test node or a list of nodes.  A list
    is treated as an implicit OR, matching the root used by NVD JSON
    configurations.
    """

    if not expression:
        return ExpressionEvaluation(
            value=UNKNOWN,
            basis=["公告没有提供 CPE 适用表达式"],
            facts=[])

    nodes = expression if isinstance(expression, list) else [expression]
    if not all(isinstance(node, dict) for node in nodes):
        return ExpressionEvaluation(
            value=UNKNOWN,
            basis=["公告表达式节点格式不受支持；仅接受 JSON 对象或对象列表"],
            facts=[])
    node_results = [_eval_node(node, components, manifest_complete)
                    for node in nodes]
    values = [result.value for result in node_results]
    value = _combine("OR", values)
    basis = []
    facts = []
    for result in node_results:
        basis.extend(result.basis)
        facts.extend(result.facts)
    basis.append("根表达式 OR 组合 {0} 个分支 -> {1}".format(len(values), value))
    return ExpressionEvaluation(value=value, basis=basis, facts=facts)
