#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Finite-domain overlap checking for CPE-based rules.

The CPE package already answers "does this concrete CPE Name match this
pattern?".  This module answers the neighbouring catalog/policy question:
"can these two patterns match the same asset?".

The check is deliberately scoped to a caller-supplied attribute domain.  It
first looks for a concrete witness in that domain.  If no witness can be
found, an attribute whose match result is unknown is reported for manual
review instead of being silently treated as disjoint.

The logical values are kept distinct:

* ``ANY`` means an unconstrained CPE wildcard (``*`` / ``ANY``).
* ``NA`` means the CPE "not applicable" value (``-`` / ``NA``).
* ``MISSING`` means the attribute was not supplied (undefined), which is not
  the same thing as an explicit wildcard.
"""

from __future__ import unicode_literals

import re

try:
    from collections.abc import Mapping
except ImportError:  # pragma: no cover - Python 2 compatibility
    from collections import Mapping

try:
    string_types = (basestring,)  # noqa: F821 - Python 2
except NameError:  # pragma: no cover - Python 3
    string_types = (str,)

from .cpe import CPE
from .comp.cpecomp_anyvalue import CPEComponentAnyValue
from .comp.cpecomp_empty import CPEComponentEmpty
from .comp.cpecomp_notapplicable import CPEComponentNotApplicable
from .comp.cpecomp_undefined import CPEComponentUndefined


#: Attributes covered by the overlap check.
ATTRIBUTES = ("vendor", "product", "version", "edition")

#: Status returned when both rules match at least one concrete asset.
STATUS_OVERLAP = "overlap"

#: Status returned when the declared domain proves there is no common asset.
STATUS_DISJOINT = "disjoint"

#: Status returned when the domain is empty or an attribute cannot be compared.
STATUS_REVIEW = "review"


class LogicalValue(object):
    """A named logical value used by :mod:`cpe.overlap`."""

    __slots__ = ("_name",)

    def __init__(self, name):
        self._name = name

    def __repr__(self):
        return self._name

    __str__ = __repr__

    def __eq__(self, other):
        return isinstance(other, LogicalValue) and self._name == other._name

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(("CPEOverlapLogicalValue", self._name))


#: Unconstrained CPE value (``*`` or ``ANY``).
ANY = LogicalValue("ANY")
#: CPE not-applicable value (``-`` or ``NA``).
NA = LogicalValue("NA")
#: Attribute not present in the rule or the asset.
MISSING = LogicalValue("MISSING")


_LOGICAL_VALUES = (ANY, NA, MISSING)

_MATCH = "match"
_NO_MATCH = "no_match"
_UNKNOWN = "unknown"


def _display(value):
    """Return a JSON-friendly display value for a rule or domain value."""

    if value in _LOGICAL_VALUES:
        return str(value)
    return value


def _normalise_literal(value):
    """Normalise a plain CPE value for case-insensitive comparison."""

    if not isinstance(value, string_types):
        value = str(value)
    return value.strip().lower()


def _decode_cpe_escapes(value):
    """Remove CPE quoting from punctuation while preserving literal wildcards."""

    result = []
    idx = 0
    while idx < len(value):
        char = value[idx]
        if char == "\\" and idx + 1 < len(value):
            following = value[idx + 1]
            if following in ("\\", "*", "?"):
                result.append(char)
                result.append(following)
            else:
                result.append(following)
            idx += 2
        else:
            result.append(char)
            idx += 1
    return "".join(result)


def _normalise_rule_value(value, aliases=True):
    """
    Normalise a value supplied in a rule mapping.

    ``aliases`` is disabled for values extracted from a parsed CPE Name, where
    a quoted ``"ANY"`` is a literal value rather than the logical wildcard.
    """

    if value in _LOGICAL_VALUES:
        return value
    if value is None:
        return MISSING
    if isinstance(value, LogicalValue):
        raise ValueError("Unsupported logical value: {0!r}".format(value))

    value = _normalise_literal(value)
    if value == "":
        return MISSING
    if aliases:
        upper = value.upper()
        if value == "*" or upper == "ANY":
            return ANY
        if value == "-" or upper == "NA":
            return NA
        if upper in ("MISSING", "UNDEFINED"):
            return MISSING
    return _decode_cpe_escapes(value)


def _normalise_asset_value(value):
    """Normalise a value from an asset domain."""

    if value in _LOGICAL_VALUES:
        if value is ANY:
            raise ValueError("ANY is a pattern, not a concrete asset value")
        return value
    if value is None:
        return MISSING
    if isinstance(value, LogicalValue):
        raise ValueError("Unsupported logical value: {0!r}".format(value))

    value = _normalise_literal(value)
    if value == "":
        return MISSING
    if value == "-" or value.upper() == "NA":
        return NA
    return value


def _tokenize_pattern(value):
    """
    Split a CPE value into literal and wildcard tokens.

    Backslash escapes a literal character.  Unescaped ``*`` and ``?`` retain
    their CPE wildcard meaning.
    """

    tokens = []
    idx = 0
    while idx < len(value):
        char = value[idx]
        if char == "\\":
            if idx + 1 >= len(value):
                return None
            tokens.append(("literal", value[idx + 1]))
            idx += 2
        elif char in ("*", "?"):
            tokens.append(("wildcard", char))
            idx += 1
        else:
            tokens.append(("literal", char))
            idx += 1
    return tokens


def _wildcards_are_supported(tokens):
    """
    Return True when all wildcards are at an edge, as required by CPE 2.3.

    A wildcard in the middle of a value (for example ``1.*.0``) cannot be
    compared by the CPE matching algorithm and is therefore left for review.
    """

    literal_positions = [i for i, token in enumerate(tokens)
                         if token[0] == "literal"]
    if not literal_positions:
        return True

    first_literal = literal_positions[0]
    last_literal = literal_positions[-1]
    for idx, token in enumerate(tokens):
        if token[0] != "wildcard":
            continue
        if first_literal < idx < last_literal:
            return False
    return True


def _pattern_matches(pattern, asset):
    """Return ``_MATCH``, ``_NO_MATCH`` or ``_UNKNOWN`` for two strings."""

    tokens = _tokenize_pattern(pattern)
    if tokens is None:
        return _UNKNOWN, "invalid trailing escape"
    if not _wildcards_are_supported(tokens):
        return _UNKNOWN, "wildcard in the middle of the value"

    regex = []
    for kind, value in tokens:
        if kind == "wildcard":
            regex.append(".*" if value == "*" else ".")
        else:
            regex.append(re.escape(value))
    expression = re.compile("^" + "".join(regex) + "$", re.IGNORECASE)
    if expression.match(asset) is not None:
        return _MATCH, None
    return _NO_MATCH, None


def _has_wildcard(value):
    tokens = _tokenize_pattern(value)
    return tokens is not None and any(
        kind == "wildcard" for kind, _ in tokens)


def _match_attribute(pattern_value, asset_value):
    """
    Compare one rule attribute value with one concrete asset value.

    Returns a ``(result, reason)`` pair.  ``_UNKNOWN`` is intentionally
    distinct from ``_NO_MATCH`` so that missing information is routed to
    manual review rather than turned into a false disjoint result.
    """

    if pattern_value is ANY:
        if asset_value is MISSING:
            return _UNKNOWN, "asset value is missing"
        return _MATCH, None

    if pattern_value is MISSING:
        return _UNKNOWN, "rule value is missing"

    if pattern_value is NA:
        if asset_value is NA:
            return _MATCH, None
        if asset_value is MISSING:
            return _UNKNOWN, "asset value is missing"
        return _NO_MATCH, None

    if asset_value is NA:
        return _NO_MATCH, None
    if asset_value is MISSING:
        return _UNKNOWN, "asset value is missing"

    return _pattern_matches(pattern_value, asset_value)


def _component_value(component):
    """Convert a parsed CPE component to an overlap value."""

    if isinstance(component, (CPEComponentAnyValue, CPEComponentEmpty)):
        return ANY
    if isinstance(component, CPEComponentNotApplicable):
        return NA
    if isinstance(component, CPEComponentUndefined):
        return MISSING

    value = component._standard_value
    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("Rule has multiple alternative values")
        value = value[0]
    if (isinstance(value, string_types) and len(value) >= 2 and
            value.startswith('"') and value.endswith('"')):
        value = value[1:-1]
    return _normalise_rule_value(value, aliases=False)


class Rule(object):
    """
    A vendor/product/version/edition pattern.

    A rule can be supplied as a mapping (for example ``{"vendor": "acme",
    "version": "1.0"}``) or as any CPE Name string accepted by :class:`CPE`.
    Omitted mapping keys become :data:`MISSING`.
    """

    def __init__(self, pattern, name=None):
        self.name = name
        self.source = pattern
        self.values = {}

        if isinstance(pattern, Rule):
            self.name = name or pattern.name
            self.source = pattern.source
            self.values = dict(pattern.values)
            return

        if isinstance(pattern, CPE):
            self._from_cpe(pattern)
            return

        if isinstance(pattern, string_types):
            if pattern.lower().startswith(("cpe:", "wfn:")):
                self._from_cpe(CPE(pattern))
                return
            raise TypeError("A string rule must be a CPE Name")

        if isinstance(pattern, Mapping):
            for attribute in ATTRIBUTES:
                self.values[attribute] = _normalise_rule_value(
                    pattern.get(attribute, MISSING))
            return

        raise TypeError(
            "Rule must be a mapping, CPE Name string or CPE object")

    def _from_cpe(self, cpe):
        for attribute in ATTRIBUTES:
            components = cpe._get_attribute_components(attribute)
            if not components:
                self.values[attribute] = MISSING
                continue

            values = [_component_value(component) for component in components]
            first = values[0]
            if any(value != first for value in values[1:]):
                raise ValueError(
                    "Rule has multiple different '{0}' components".format(
                        attribute))
            self.values[attribute] = first

    def get(self, attribute):
        return self.values.get(attribute, MISSING)

    def as_dict(self):
        return dict((attribute, _display(self.get(attribute)))
                    for attribute in ATTRIBUTES)

    def __repr__(self):
        label = "{0}: ".format(self.name) if self.name else ""
        return "Rule({0}{1!r})".format(label, self.as_dict())


class Domain(object):
    """
    An explicit finite asset domain.

    Two forms are accepted:

    * A mapping of attribute to values, representing the Cartesian product of
      the per-attribute values.
    * A sequence of concrete asset mappings, for domains whose attributes are
      correlated.
    """

    def __init__(self, values):
        self._by_attribute = None
        self._assets = None

        if isinstance(values, Mapping):
            unknown = set(values) - set(ATTRIBUTES)
            if unknown:
                raise ValueError(
                    "Unknown domain attribute(s): {0}".format(
                        ", ".join(sorted(unknown))))
            self._by_attribute = {}
            for attribute in ATTRIBUTES:
                raw_values = values.get(attribute, ())
                if raw_values is None:
                    raw_values = (None,)
                elif isinstance(raw_values, string_types):
                    raw_values = (raw_values,)
                normalised = [_normalise_asset_value(value)
                              for value in raw_values]
                self._by_attribute[attribute] = _deduplicate(normalised)
            return

        if isinstance(values, (list, tuple)):
            assets = []
            for asset in values:
                if not isinstance(asset, Mapping):
                    raise TypeError("Each concrete asset must be a mapping")
                unknown = set(asset) - set(ATTRIBUTES)
                if unknown:
                    raise ValueError(
                        "Unknown asset attribute(s): {0}".format(
                            ", ".join(sorted(unknown))))
                normalised_asset = {}
                for attribute in ATTRIBUTES:
                    normalised_asset[attribute] = _normalise_asset_value(
                        asset.get(attribute, MISSING))
                assets.append(normalised_asset)
            self._assets = assets
            return

        raise TypeError(
            "Domain must be a mapping of attributes or a list of assets")

    def values_for(self, attribute):
        if self._by_attribute is None:
            return tuple(asset.get(attribute, MISSING)
                         for asset in self._assets)
        return self._by_attribute.get(attribute, ())

    def is_empty(self):
        """Return True when the domain contains no concrete asset."""

        if self._assets is not None:
            return len(self._assets) == 0
        return any(not self._by_attribute.get(attribute)
                   for attribute in ATTRIBUTES)

    def assets(self):
        if self._assets is not None:
            return list(self._assets)

        # Small domains are intentional: materialising the product makes the
        # witness search explicit and keeps the result deterministic.
        assets = [{}]
        for attribute in ATTRIBUTES:
            values = self._by_attribute.get(attribute, ())
            if not values:
                return []
            assets = [dict(asset, **{attribute: value})
                      for asset in assets for value in values]
        return assets


def _deduplicate(values):
    result = []
    seen = set()
    for value in values:
        key = (_display(value), isinstance(value, LogicalValue))
        if key not in seen:
            seen.add(key)
            result.append(value)
    return tuple(result)


class AttributeResult(object):
    """Per-attribute evidence for an overlap check."""

    def __init__(self, attribute, left, right):
        self.attribute = attribute
        self.left = left
        self.right = right
        self.left_candidates = []
        self.right_candidates = []
        self.common = []
        self.uncertain_assets = []
        self.relation = STATUS_REVIEW
        self.reason = None

    def as_dict(self):
        return {
            "attribute": self.attribute,
            "left": _display(self.left),
            "right": _display(self.right),
            "left_candidates": [_display(value)
                                for value in self.left_candidates],
            "right_candidates": [_display(value)
                                 for value in self.right_candidates],
            "common": [_display(value) for value in self.common],
            "uncertain_assets": [
                {"value": _display(value), "reason": reason}
                for value, reason in self.uncertain_assets],
            "relation": self.relation,
            "reason": self.reason,
        }

    def __repr__(self):
        return "AttributeResult({0!r})".format(self.as_dict())


class OverlapResult(object):
    """The result of comparing two rules over an explicit asset domain."""

    def __init__(self, left, right, domain, status, witness, attributes,
                 explanation):
        self.left = left
        self.right = right
        self.domain = domain
        self.status = status
        self.witness = witness
        self.attributes = attributes
        self.explanation = explanation

    @property
    def overlaps(self):
        return self.status == STATUS_OVERLAP

    @property
    def requires_decision(self):
        """True only when a real conflict was witnessed."""

        return self.status == STATUS_OVERLAP

    @property
    def needs_review(self):
        """True when the library/domain could not settle the question."""

        return self.status == STATUS_REVIEW

    @property
    def requires_human(self):
        return self.requires_decision or self.needs_review

    @property
    def overlap(self):
        return self.overlaps

    @property
    def review(self):
        return self.needs_review

    @property
    def requires_human_review(self):
        return self.requires_human

    @property
    def reason(self):
        return self.explanation

    @property
    def witness_display(self):
        if self.witness is None:
            return None
        return dict((attribute, _display(value))
                    for attribute, value in self.witness.items())

    def unresolved_attributes(self):
        return [item.attribute for item in self.attributes
                if item.relation == STATUS_REVIEW]

    def uncertain_attributes(self):
        return [item.attribute for item in self.attributes
                if item.uncertain_assets]

    def disjoint_attributes(self):
        return [item.attribute for item in self.attributes
                if item.relation == STATUS_DISJOINT]

    def as_dict(self):
        return {
            "status": self.status,
            "overlaps": self.overlaps,
            "requires_decision": self.requires_decision,
            "needs_review": self.needs_review,
            "witness": self.witness_display,
            "unresolved_attributes": self.unresolved_attributes(),
            "uncertain_attributes": self.uncertain_attributes(),
            "disjoint_attributes": self.disjoint_attributes(),
            "attributes": [item.as_dict() for item in self.attributes],
            "explanation": self.explanation,
        }

    def to_dict(self):
        return self.as_dict()

    def __repr__(self):
        return "OverlapResult({0!r})".format(self.as_dict())


def _check_over_domain(left, right, domain):
    witnesses = []
    possible = []
    details = []

    if domain.is_empty():
        for attribute in ATTRIBUTES:
            detail = AttributeResult(attribute, left.get(attribute),
                                     right.get(attribute))
            values = domain.values_for(attribute)
            if not values:
                detail.relation = STATUS_REVIEW
                detail.reason = "the declared domain is empty for this attribute"
            details.append(detail)
        return OverlapResult(
            left, right, domain, STATUS_REVIEW, None, details,
            "The declared asset domain is empty, so no concrete witness can "
            "be found. Leave the pair for manual review.")

    for asset in domain.assets():
        asset_possible = False
        asset_unknown = []
        for attribute in ATTRIBUTES:
            left_result, left_reason = _match_attribute(
                left.get(attribute), asset.get(attribute, MISSING))
            right_result, right_reason = _match_attribute(
                right.get(attribute), asset.get(attribute, MISSING))

            if left_result == _NO_MATCH or right_result == _NO_MATCH:
                break
            if left_result == _UNKNOWN or right_result == _UNKNOWN:
                asset_possible = True
                reason = left_reason or right_reason
                asset_unknown.append((attribute, reason))

        else:
            if asset_possible:
                possible.append((asset, asset_unknown))
            else:
                witnesses.append(asset)
                break

    for attribute in ATTRIBUTES:
        detail = AttributeResult(attribute, left.get(attribute),
                                 right.get(attribute))
        for asset in domain.assets():
            value = asset.get(attribute, MISSING)
            left_result, left_reason = _match_attribute(
                left.get(attribute), value)
            right_result, right_reason = _match_attribute(
                right.get(attribute), value)

            if left_result == _MATCH:
                if value not in detail.left_candidates:
                    detail.left_candidates.append(value)
            if right_result == _MATCH:
                if value not in detail.right_candidates:
                    detail.right_candidates.append(value)
            if left_result == _MATCH and right_result == _MATCH:
                if value not in detail.common:
                    detail.common.append(value)
            elif (left_result != _NO_MATCH and
                  right_result != _NO_MATCH and
                  (left_result == _UNKNOWN or right_result == _UNKNOWN)):
                detail.uncertain_assets.append(
                    (value, left_reason or right_reason))

        if detail.common:
            detail.relation = STATUS_OVERLAP
        elif detail.uncertain_assets:
            detail.relation = STATUS_REVIEW
            detail.reason = detail.uncertain_assets[0][1]
        elif not domain.values_for(attribute):
            detail.relation = STATUS_REVIEW
            detail.reason = "the declared domain is empty for this attribute"
        else:
            detail.relation = STATUS_DISJOINT
            detail.reason = "no domain value is common to both rules"
        details.append(detail)

    witness = None
    if witnesses:
        witness = witnesses[0]
        status = STATUS_OVERLAP
        explanation = _overlap_explanation(witness)
    elif possible:
        status = STATUS_REVIEW
        unresolved = [item.attribute for item in details
                      if item.relation == STATUS_REVIEW]
        explanation = _review_explanation(unresolved, details)
    else:
        status = STATUS_DISJOINT
        disjoint = [item.attribute for item in details
                    if item.relation == STATUS_DISJOINT]
        explanation = _disjoint_explanation(disjoint, details)

    return OverlapResult(left, right, domain, status, witness, details,
                         explanation)


def _overlap_explanation(witness):
    values = ", ".join("{0}={1!r}".format(attribute, _display(witness[attribute]))
                       for attribute in ATTRIBUTES)
    return (
        "Common asset found in the declared domain: {0}. Both rules match "
        "this asset, so their exceptions conflict and a human must decide "
        "which one takes precedence.".format(values))


def _disjoint_explanation(disjoint, details):
    if disjoint:
        text = (
            "No common asset exists in the declared domain: the rules are "
            "disjoint on {0}.".format(", ".join(disjoint)))
    else:
        text = (
            "No complete asset in the declared domain satisfies both rules. "
            "The per-attribute value lists overlap, but the domain's "
            "attribute combinations do not.")
    version = next((item for item in details if item.attribute == "version"),
                   None)
    if (version is not None and version.relation == STATUS_DISJOINT and
            isinstance(version.left, string_types) and
            isinstance(version.right, string_types) and
            version.left != version.right and
            not _has_wildcard(version.left) and
            not _has_wildcard(version.right)):
        text += (
            " CPE treats version as a literal string; spellings such as "
            "'1.0' and '1.0.0' are not normalized into the same version.")
    text += " No policy decision is required for these two rules."
    return text


def _review_explanation(unresolved, details):
    reasons = []
    for item in details:
        if item.attribute not in unresolved:
            continue
        if item.reason:
            reasons.append("{0}: {1}".format(item.attribute, item.reason))
        else:
            reasons.append(item.attribute)
    return (
        "No concrete witness was found in the declared domain, and the "
        "remaining attribute(s) cannot be decided by the library ({0}). "
        "Leave the pair for manual review; do not treat it as disjoint."
        .format("; ".join(reasons)))


def check_overlap(left, right, domain):
    """
    Check whether two rules have a common asset in ``domain``.

    :param left: first rule (mapping, CPE Name string or :class:`Rule`)
    :param right: second rule (mapping, CPE Name string or :class:`Rule`)
    :param domain: :class:`Domain` or the values accepted by it
    :returns: :class:`OverlapResult`

    The witness search happens before the result is classified.  A concrete
    witness produces ``overlap``; exhausting the whole domain produces
    ``disjoint``; missing values, empty attribute domains and unsupported
    wildcard positions produce ``review``.
    """

    left_rule = left if isinstance(left, Rule) else Rule(left)
    right_rule = right if isinstance(right, Rule) else Rule(right)
    if not isinstance(domain, Domain):
        domain = Domain(domain)
    return _check_over_domain(left_rule, right_rule, domain)


def rules_overlap(left, right, domain):
    """Return True only when a concrete common asset was witnessed."""

    return check_overlap(left, right, domain).overlaps


def find_witness(left, right, domain):
    """Return a concrete common asset, or None when none was witnessed."""

    return check_overlap(left, right, domain).witness


class RuleOverlapChecker(object):
    """Convenience wrapper around :func:`check_overlap` for a fixed domain."""

    def __init__(self, domain):
        self.domain = domain if isinstance(domain, Domain) else Domain(domain)

    def check(self, left, right):
        return check_overlap(left, right, self.domain)

    def find_witness(self, left, right):
        return find_witness(left, right, self.domain)


#: Backwards-friendly spelling for callers that prefer a verb first.
check_rule_overlap = check_overlap


__all__ = [
    "ANY", "NA", "MISSING",
    "ATTRIBUTES",
    "STATUS_OVERLAP", "STATUS_DISJOINT", "STATUS_REVIEW",
    "Rule", "Domain", "AttributeResult", "OverlapResult",
    "RuleOverlapChecker",
    "check_overlap", "check_rule_overlap", "rules_overlap", "find_witness",
]
