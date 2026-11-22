#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
"""Data model for the security exception exchange layer.

The model deliberately stays independent of the :class:`bandit.core.issue`
class so that it can be built straight from a persisted JSON scan report.
"""
import datetime
import fnmatch
import re

from bandit.exchange.errors import MappingValidationError

# Decision states recorded for every (mapping, target rule) combination.
APPROVED = "APPROVED"
EXPIRED = "EXPIRED"
NO_MATCH = "NO_MATCH"
CONFLICT = "CONFLICT"
MISSING_EVIDENCE = "MISSING_EVIDENCE"

#: Every state the exchange engine is allowed to emit.
DECISION_STATES = (
    APPROVED,
    EXPIRED,
    NO_MATCH,
    CONFLICT,
    MISSING_EVIDENCE,
)

#: Context fields that can be constrained on a finding.
CONTEXT_FIELDS = (
    "filename",
    "test_id",
    "test_name",
    "severity",
    "confidence",
    "line_number",
    "line_range",
    "col_offset",
    "issue_text",
    "code",
)

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _parse_timestamp(value, field_name):
    """Parse an ISO-8601 UTC timestamp used in a mapping document."""
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc)
    if not isinstance(value, str):
        raise MappingValidationError(
            f"Field '{field_name}' must be an ISO-8601 timestamp string"
        )
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError as exc:
        raise MappingValidationError(
            f"Field '{field_name}' is not a valid ISO-8601 timestamp: {value}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def utcnow():
    """Return the current time as a timezone aware UTC datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


class Finding:
    """A single Bandit finding reconstructed from a JSON report.

    Findings are value objects: equality only depends on the locating
    attributes (rule, file, line and issue text), never on the decision
    recorded against the finding.
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise MappingValidationError(
                "Each finding must be a JSON object/dictionary"
            )
        self.filename = data.get("filename", "")
        self.test_id = data.get("test_id", "")
        self.test_name = data.get("test_name", "")
        self.severity = data.get("issue_severity", "")
        self.confidence = data.get("issue_confidence", "")
        self.issue_text = data.get("issue_text", "")
        self.line_number = data.get("line_number")
        self.line_range = data.get("line_range", []) or []
        self.col_offset = data.get("col_offset")
        self.end_col_offset = data.get("end_col_offset")
        self.code = data.get("code", "")
        self.cwe = data.get("issue_cwe", {}) or {}
        self.more_info = data.get("more_info", "")
        self._raw = dict(data)

    @property
    def identity_key(self):
        """Stable tuple identifying a finding inside a single report."""
        return (
            self.test_id,
            self.filename,
            self.line_number,
            self.issue_text,
        )

    def context_value(self, field):
        """Return the value of a context field by its report name."""
        aliases = {
            "filename": self.filename,
            "test_id": self.test_id,
            "test_name": self.test_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "line_number": self.line_number,
            "line_range": list(self.line_range),
            "col_offset": self.col_offset,
            "issue_text": self.issue_text,
            "code": self.code,
        }
        if field not in aliases:
            raise MappingValidationError(f"Unknown context field: {field}")
        return aliases[field]

    def as_dict(self):
        """Return the original report fragment plus normalised fields."""
        return dict(self._raw)

    def __eq__(self, other):
        if not isinstance(other, Finding):
            return NotImplemented
        return self.identity_key == other.identity_key

    def __hash__(self):
        return hash(self.identity_key)

    def __repr__(self):
        return (
            f"Finding(test_id={self.test_id!r}, filename={self.filename!r},"
            f" line_number={self.line_number!r})"
        )


class ContextMatcher:
    """Evaluate the context conditions attached to a mapping target."""

    def __init__(self, conditions):
        if conditions is None:
            conditions = {}
        if not isinstance(conditions, dict):
            raise MappingValidationError(
                "Context conditions must be a mapping of field -> condition"
            )
        for field in conditions:
            if field not in CONTEXT_FIELDS:
                raise MappingValidationError(
                    f"Context condition references unknown field: {field}"
                )
        self.conditions = conditions
        self._compiled = {
            field: self._compile(field, condition)
            for field, condition in conditions.items()
        }

    @staticmethod
    def _compile(field, condition):
        """Turn a condition into a callable predicate.

        A bare scalar is treated as an equality check.  Dictionaries select
        an explicit operator, which keeps conditions readable in JSON while
        still supporting ranges, glob patterns and regular expressions.
        """
        if isinstance(condition, dict):
            operator = condition.get("op", "eq")
            value = condition.get("value")
        else:
            operator = "eq"
            value = condition

        def predicate(actual):
            return ContextMatcher._apply(operator, field, actual, value)

        return predicate

    @staticmethod
    def _apply(operator, field, actual, expected):
        if operator == "eq":
            return actual == expected
        if operator == "ne":
            return actual != expected
        if operator == "in":
            if not isinstance(expected, (list, tuple, set)):
                raise MappingValidationError(
                    f"Operator 'in' on '{field}' requires a list value"
                )
            return actual in expected
        if operator in ("gt", "gte", "lt", "lte"):
            if actual is None or expected is None:
                return False
            comparisons = {
                "gt": actual > expected,
                "gte": actual >= expected,
                "lt": actual < expected,
                "lte": actual <= expected,
            }
            return comparisons[operator]
        if operator == "glob":
            return bool(actual) and fnmatch.fnmatch(str(actual), str(expected))
        if operator == "regex":
            return (
                bool(actual)
                and re.search(str(expected), str(actual)) is not None
            )
        if operator == "contains":
            if actual is None:
                return False
            if isinstance(actual, (list, tuple)):
                return expected in actual
            return str(expected) in str(actual)
        raise MappingValidationError(
            f"Unsupported context operator '{operator}' on field '{field}'"
        )

    def evaluate(self, finding):
        """Return True only when every condition matches the finding."""
        for field, predicate in self._compiled.items():
            if not predicate(finding.context_value(field)):
                return False
        return True

    def as_dict(self):
        return {
            field: condition
            for field, condition in self.conditions.items()
        }


class TargetRule:
    """One external rule covered by an :class:`ExceptionMapping`."""

    def __init__(self, rule_id, conditions=None):
        self.rule_id = str(rule_id)
        self.matcher = ContextMatcher(conditions)

    @property
    def conditions(self):
        return self.matcher.conditions

    def as_dict(self):
        return {"rule_id": self.rule_id, "conditions": self.matcher.as_dict()}


class ExceptionMapping:
    """A one-to-many exception mapping with a validity period.

    A mapping connects one Bandit rule (``source_rule``) to one or more
    external scanner rule IDs.  It is active between ``valid_from`` and
    ``valid_until`` and may carry shared context conditions that every
    target rule inherits in addition to its own conditions.
    """

    def __init__(
        self,
        mapping_id,
        source_rule,
        target_rules,
        valid_from=None,
        valid_until=None,
        rationale="",
        owner="",
        context=None,
    ):
        if not mapping_id:
            raise MappingValidationError(
                "Every mapping needs a non-empty 'id'"
            )
        if not source_rule:
            raise MappingValidationError(
                f"Mapping '{mapping_id}' is missing 'source_rule'"
            )
        if not target_rules:
            raise MappingValidationError(
                f"Mapping '{mapping_id}' must list at least one target rule"
            )
        self.mapping_id = str(mapping_id)
        self.source_rule = str(source_rule)
        self.target_rules = list(target_rules)
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.rationale = rationale
        self.owner = owner
        self.shared_matcher = ContextMatcher(context)
        if self.valid_from and self.valid_until:
            if self.valid_until < self.valid_from:
                raise MappingValidationError(
                    f"Mapping '{mapping_id}' has valid_until before valid_from"
                )

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise MappingValidationError("Each mapping must be a JSON object")
        mapping_id = data.get("id")
        source_rule = data.get("source_rule")
        raw_targets = data.get("target_rules")
        if not isinstance(raw_targets, list):
            raise MappingValidationError(
                f"Mapping '{mapping_id}' needs a 'target_rules' list"
            )
        targets = []
        for raw_target in raw_targets:
            if isinstance(raw_target, dict):
                rule_id = raw_target.get("rule_id")
                conditions = raw_target.get("conditions", {})
            else:
                rule_id = raw_target
                conditions = {}
            if not rule_id:
                raise MappingValidationError(
                    f"Mapping '{mapping_id}' contains a target without rule_id"
                )
            targets.append(TargetRule(rule_id, conditions))
        return cls(
            mapping_id=mapping_id,
            source_rule=source_rule,
            target_rules=targets,
            valid_from=_parse_timestamp(data.get("valid_from"), "valid_from"),
            valid_until=_parse_timestamp(
                data.get("valid_until"), "valid_until"
            ),
            rationale=data.get("rationale", ""),
            owner=data.get("owner", ""),
            context=data.get("context", {}),
        )

    def is_active(self, now=None):
        """Check the validity period at ``now`` (defaults to current time)."""
        moment = now or utcnow()
        if self.valid_from and moment < self.valid_from:
            return False
        if self.valid_until and moment > self.valid_until:
            return False
        return True

    def target_ids(self):
        return [target.rule_id for target in self.target_rules]

    def as_dict(self):
        return {
            "id": self.mapping_id,
            "source_rule": self.source_rule,
            "target_rules": [target.as_dict() for target in self.target_rules],
            "valid_from": _format_timestamp(self.valid_from),
            "valid_until": _format_timestamp(self.valid_until),
            "rationale": self.rationale,
            "owner": self.owner,
            "context": self.shared_matcher.as_dict(),
        }


def _format_timestamp(value):
    if value is None:
        return None
    return value.strftime(_TS_FORMAT)
