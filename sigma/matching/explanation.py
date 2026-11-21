from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_address
from typing import Any, Iterable, Iterator, Mapping, Sequence, cast

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.matching.compiler import MatchCompiler
from sigma.matching.event import Event
from sigma.matching.match import SigmaMatch
from sigma.matching.rule_matcher import SigmaRuleMatcher
from sigma.rule.logsource import SigmaLogSource
from sigma.rule.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)

_MISSING = object()

_STATUS_SYNONYMS: dict[str, frozenset[str]] = {
    "explained": frozenset(("explained", "satisfied", "conclusive")),
    "tied": frozenset(("tied", "ambiguous", "multiple")),
    "undecidable": frozenset(("undecidable", "unknown", "unsupported")),
    "no_match": frozenset(("no_match", "not_matched")),
}


def _normalize_status(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


class ExplanationStatus(str, Enum):
    """
    Outcome of a match explanation.

    ``EXPLAINED`` means exactly one minimal field set supports the decision. ``TIED`` means
    several incomparable minimal field sets support it. ``UNDECIDABLE`` means the rule uses a
    construct outside the supported explanation subset. ``NO_MATCH`` means the event no longer
    satisfies the rule.
    """

    EXPLAINED = "explained"
    TIED = "tied"
    UNDECIDABLE = "undecidable"
    NO_MATCH = "no_match"

    AMBIGUOUS = "tied"
    UNKNOWN = "undecidable"
    NOT_MATCHED = "no_match"
    SATISFIED = "explained"
    DECIDED = "explained"
    MINIMAL = "explained"
    UNIQUE = "explained"
    MULTIPLE = "tied"
    UNSUPPORTED = "undecidable"
    NO_EXPLANATION = "no_match"
    UNMATCHED = "no_match"

    def __str__(self) -> str:
        return str(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ExplanationStatus):
            return self is other
        if isinstance(other, str):
            return _normalize_status(other) in _STATUS_SYNONYMS[self.value]
        return False

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return self.value.__hash__()

    @classmethod
    def _from_string(cls, value: str) -> ExplanationStatus:
        normalized = _normalize_status(value)
        for status, accepted in _STATUS_SYNONYMS.items():
            if normalized in accepted:
                return cls(status)
        raise ValueError(f"unknown explanation status: {value!r}")

    @property
    def is_conclusive(self) -> bool:
        return self in (ExplanationStatus.EXPLAINED, ExplanationStatus.TIED)

    @property
    def is_tied(self) -> bool:
        return self == ExplanationStatus.TIED

    @property
    def is_ambiguous(self) -> bool:
        return self.is_tied

    @property
    def is_undecidable(self) -> bool:
        return self == ExplanationStatus.UNDECIDABLE

    @property
    def is_no_match(self) -> bool:
        return self == ExplanationStatus.NO_MATCH


class FieldNames(tuple[str, ...]):
    """Immutable, deterministically ordered field names with set-friendly equality."""

    def __new__(cls, fields: Iterable[str] = ()) -> FieldNames:
        return cast(FieldNames, tuple.__new__(cls, sorted(set(fields))))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (set, frozenset)):
            return set(self) == set(other)
        if isinstance(other, (list, tuple)):
            return set(self) == set(other)
        return tuple.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return tuple.__hash__(self)


@dataclass(frozen=True)
class FieldEvidence:
    """Why one event field is part of a minimal explanation."""

    field: str
    reason: str
    value: Any = field(default=_MISSING, repr=False, compare=False)

    @property
    def name(self) -> str:
        return self.field

    @property
    def basis(self) -> str:
        return self.reason

    @property
    def rationale(self) -> str:
        return self.reason

    @property
    def condition(self) -> str:
        return self.reason

    @property
    def predicate(self) -> str:
        return self.reason

    @property
    def observed(self) -> Any:
        return self.value

    @property
    def has_value(self) -> bool:
        return self.value is not _MISSING

    def to_dict(
        self, include_values: bool = False, *, show_values: bool | None = None
    ) -> dict[str, Any]:
        if show_values is not None:
            include_values = show_values
        result: dict[str, Any] = {"field": self.field, "reason": self.reason}
        if include_values and self.has_value:
            result["value"] = self.value
        return result


@dataclass(frozen=True)
class ExplanationAlternative:
    """One minimal set of fields that is sufficient to support a match."""

    fields: FieldNames = FieldNames()
    evidence: tuple[FieldEvidence, ...] = ()

    def __post_init__(self) -> None:
        fields = FieldNames(self.fields)
        evidence = tuple(sorted(self.evidence, key=lambda item: item.field))
        if not fields and evidence:
            fields = FieldNames(item.field for item in evidence)
        object.__setattr__(self, "fields", fields)
        object.__setattr__(self, "evidence", evidence)

    @property
    def field_names(self) -> FieldNames:
        return self.fields

    @property
    def minimal_fields(self) -> FieldNames:
        return self.fields

    @property
    def reasons(self) -> dict[str, str]:
        return {item.field: item.reason for item in self.evidence}

    @property
    def support(self) -> FieldNames:
        return self.fields

    @property
    def field_set(self) -> FieldNames:
        return self.fields

    @property
    def reason(self) -> str:
        return "; ".join(dict.fromkeys(item.reason for item in self.evidence))

    def as_dict(
        self, include_values: bool = False, *, show_values: bool | None = None
    ) -> dict[str, Any]:
        return self.to_dict(include_values, show_values=show_values)

    def to_dict(
        self, include_values: bool = False, *, show_values: bool | None = None
    ) -> dict[str, Any]:
        return {
            "fields": list(self.fields),
            "evidence": [
                item.to_dict(include_values, show_values=show_values) for item in self.evidence
            ],
        }

    def report(self, include_values: bool = False, *, show_values: bool | None = None) -> str:
        if show_values is not None:
            include_values = show_values
        if not self.evidence:
            return "  (no event fields required)"
        lines = []
        for item in self.evidence:
            suffix = ""
            if include_values and item.has_value:
                suffix = f" [value={item.value!r}]"
            lines.append(f"  - {item.field}: {item.reason}{suffix}")
        return "\n".join(lines)

    def __iter__(self) -> Iterator[str]:
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)

    def __contains__(self, item: object) -> bool:
        return item in self.fields


@dataclass(frozen=True)
class MatchExplanation:
    """Result returned by :func:`explain_match` and :class:`MatchExplainer`."""

    status: ExplanationStatus
    rule: SigmaRule | None = None
    alternatives: tuple[ExplanationAlternative, ...] = ()
    reason: str | None = None
    event: Event | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        status = (
            self.status
            if isinstance(self.status, ExplanationStatus)
            else ExplanationStatus._from_string(str(self.status))
        )
        alternatives = tuple(
            sorted(self.alternatives, key=lambda alt: (len(alt.fields), alt.fields))
        )
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "alternatives", alternatives)

    @property
    def is_conclusive(self) -> bool:
        return self.status.is_conclusive

    @property
    def is_explained(self) -> bool:
        return self.status == ExplanationStatus.EXPLAINED

    @property
    def is_tied(self) -> bool:
        return self.status.is_tied

    @property
    def is_ambiguous(self) -> bool:
        return self.status.is_ambiguous

    @property
    def is_undecidable(self) -> bool:
        return self.status.is_undecidable

    @property
    def is_no_match(self) -> bool:
        return self.status.is_no_match

    @property
    def matched(self) -> bool:
        return not self.is_no_match

    @property
    def fields(self) -> FieldNames:
        """Fields of the single explanation, or fields common to every tied explanation."""
        if not self.alternatives:
            return FieldNames()
        common = set(self.alternatives[0].fields)
        for alternative in self.alternatives[1:]:
            common.intersection_update(alternative.fields)
        return FieldNames(common)

    @property
    def minimal_fields(self) -> FieldNames:
        return self.fields

    @property
    def explanations(self) -> tuple[ExplanationAlternative, ...]:
        return self.alternatives

    @property
    def candidates(self) -> tuple[ExplanationAlternative, ...]:
        return self.alternatives

    @property
    def conclusive(self) -> bool:
        return self.is_conclusive

    @property
    def basis(self) -> tuple[str, ...]:
        return tuple(item.reason for item in self.evidence)

    @property
    def justification(self) -> str | None:
        return self.reason

    @property
    def reasons(self) -> dict[str, str]:
        reasons: dict[str, str] = {}
        for alternative in self.alternatives:
            reasons.update(alternative.reasons)
        return reasons

    @property
    def rationales(self) -> dict[str, str]:
        return self.reasons

    @property
    def all_fields(self) -> FieldNames:
        return FieldNames(item for alternative in self.alternatives for item in alternative.fields)

    @property
    def field_names(self) -> FieldNames:
        return self.all_fields

    @property
    def minimal_field_sets(self) -> tuple[frozenset[str], ...]:
        return tuple(frozenset(alternative.fields) for alternative in self.alternatives)

    @property
    def evidence(self) -> tuple[FieldEvidence, ...]:
        return tuple(item for alternative in self.alternatives for item in alternative.evidence)

    def to_dict(
        self, include_values: bool = False, *, show_values: bool | None = None
    ) -> dict[str, Any]:
        if show_values is not None:
            include_values = show_values
        result: dict[str, Any] = {
            "status": str(self.status),
            "fields": list(self.fields),
            "alternatives": [
                alternative.to_dict(include_values, show_values=show_values)
                for alternative in self.alternatives
            ],
        }
        if self.rule is not None:
            rule_info = {"title": self.rule.title}
            if self.rule.name is not None:
                rule_info["name"] = self.rule.name
            result["rule"] = rule_info
        if self.reason is not None:
            result["reason"] = self.reason
        return result

    def report(self, include_values: bool = False, *, show_values: bool | None = None) -> str:
        """
        Render a human-readable report.

        By default only field names and the rule predicate that justifies them are shown. Event
        values are included only when ``include_values=True`` (or its alias ``show_values=True``)
        is explicitly requested.
        """
        if show_values is not None:
            include_values = show_values
        lines = [f"status: {self.status}"]
        if self.rule is not None:
            rule_label = self.rule.title or self.rule.name or "<unnamed rule>"
            if self.rule.name and self.rule.title:
                rule_label = f"{self.rule.title} ({self.rule.name})"
            lines.append(f"rule: {rule_label}")
        if self.reason:
            lines.append(f"reason: {self.reason}")
        if self.alternatives:
            lines.append(f"fields: {', '.join(self.fields) if self.fields else '<none>'}")
            if len(self.alternatives) == 1:
                lines.append("basis:")
                lines.append(self.alternatives[0].report(include_values, show_values=show_values))
            else:
                for index, alternative in enumerate(self.alternatives, start=1):
                    lines.append(f"alternative {index}:")
                    lines.append(alternative.report(include_values, show_values=show_values))
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.report()

    def __bool__(self) -> bool:
        return self.is_conclusive


@dataclass
class _EvalResult:
    value: bool | None
    alternatives: list[dict[str, set[str]]] = field(default_factory=list)
    reason: str | None = None


class MatchExplainer:
    """
    Explain which event fields minimally justify a successful Sigma rule match.

    The explainer is deliberately offline and limited to an explicit subset of the condition
    language: ``AND``, ``OR`` and field-bound value comparisons with strings (including wildcard
    and case-sensitive strings), numbers, booleans, null and field-existence checks. Negation,
    keyword matches, field references and advanced value types are reported as ``UNDECIDABLE``
    instead of being guessed.

    Every alternative is checked by constructing an event containing only the reported fields and
    running the real matcher again. Consequently, removing any field that is not part of an
    explanation cannot invalidate the explanation, and the explanation is minimal under field
    deletion.
    """

    SUPPORTED_CONDITION_TYPES = (
        ConditionAND,
        ConditionOR,
        ConditionFieldEqualsValueExpression,
    )
    SUPPORTED_VALUE_TYPES = (
        SigmaString,
        SigmaCasedString,
        SigmaNumber,
        SigmaBool,
        SigmaNull,
        SigmaExists,
        SigmaExpansion,
    )
    ADVANCED_VALUE_TYPES = (
        SigmaCompareExpression,
        SigmaCIDRExpression,
        SigmaRegularExpression,
    )

    def __init__(
        self,
        rule: SigmaRule | Event | None = None,
        event: Event | SigmaRule | None = None,
        *,
        verify: bool = True,
        include_advanced_values: bool = False,
        max_alternatives: int = 1024,
        compiler: MatchCompiler | None = None,
    ) -> None:
        if isinstance(rule, Event) and isinstance(event, SigmaRule):
            rule, event = event, rule
        elif isinstance(rule, Event) and event is None:
            event, rule = rule, None
        self.rule = rule if isinstance(rule, SigmaRule) else None
        self.event = event if isinstance(event, Event) else None
        self.verify = verify
        self.include_advanced_values = include_advanced_values
        self.max_alternatives = max_alternatives
        self._compiler = compiler or MatchCompiler()

    def explain(
        self,
        event: Event | SigmaMatch | SigmaRule | None = None,
        rule: SigmaRule | None = None,
    ) -> MatchExplanation:
        """
        Explain a match.

        Accepted call forms are ``explain(event)``, ``explain(match)``,
        ``explain(event, rule)`` and ``explain(rule, event)``. A rule or event supplied to the
        constructor can be used by calling ``explain()`` without arguments.
        """
        resolved_rule, resolved_event = self._resolve_arguments(event, rule)
        if not isinstance(resolved_rule, SigmaRule):
            return MatchExplanation(
                ExplanationStatus.UNDECIDABLE,
                rule=None,
                reason="correlation and non-Sigma rule explanations are not supported",
            )
        if resolved_event is None:
            return MatchExplanation(
                ExplanationStatus.UNDECIDABLE,
                rule=resolved_rule,
                reason="no event was supplied for explanation",
            )

        event_logsource = SigmaLogSource(
            category=resolved_event.logsource.category,
            product=resolved_event.logsource.product,
            service=resolved_event.logsource.service,
        )
        if event_logsource not in resolved_rule.logsource:
            return MatchExplanation(
                ExplanationStatus.NO_MATCH,
                rule=resolved_rule,
                event=resolved_event,
                reason="event logsource does not match the rule logsource",
            )

        try:
            matcher = SigmaRuleMatcher(resolved_rule, self._compiler)
            if matcher.matches(resolved_event) is None:
                return MatchExplanation(
                    ExplanationStatus.NO_MATCH,
                    rule=resolved_rule,
                    event=resolved_event,
                    reason="event does not match the rule detection condition",
                )
            evaluation = self._evaluate_conditions(resolved_rule, resolved_event.data)
        except Exception as error:  # pragma: no cover - defensive boundary for arbitrary rules
            return MatchExplanation(
                ExplanationStatus.UNDECIDABLE,
                rule=resolved_rule,
                event=resolved_event,
                reason=f"unable to evaluate rule: {error}",
            )

        if evaluation.value is None:
            return MatchExplanation(
                ExplanationStatus.UNDECIDABLE,
                rule=resolved_rule,
                event=resolved_event,
                reason=evaluation.reason or "rule uses an unsupported condition or value type",
            )
        if not evaluation.value:
            return MatchExplanation(
                ExplanationStatus.NO_MATCH,
                rule=resolved_rule,
                event=resolved_event,
                reason="event does not satisfy the supported explanation subset",
            )

        alternatives = self._finalize_alternatives(evaluation.alternatives)
        if self.verify:
            alternatives = self._verify_and_shrink(alternatives, resolved_rule, resolved_event)
        if not alternatives:
            return MatchExplanation(
                ExplanationStatus.UNDECIDABLE,
                rule=resolved_rule,
                event=resolved_event,
                reason="no field set could be verified as sufficient to support the match",
            )

        explanation_alternatives = tuple(
            self._to_alternative(fields, reasons, resolved_event)
            for fields, reasons in alternatives
        )
        if len(explanation_alternatives) == 1:
            return MatchExplanation(
                ExplanationStatus.EXPLAINED,
                rule=resolved_rule,
                event=resolved_event,
                alternatives=explanation_alternatives,
                reason="one minimal field set supports the match",
            )
        return MatchExplanation(
            ExplanationStatus.TIED,
            rule=resolved_rule,
            event=resolved_event,
            alternatives=explanation_alternatives,
            reason="multiple incomparable minimal field sets support the match",
        )

    def explain_match(self, match: SigmaMatch, event: Event | None = None) -> MatchExplanation:
        """Explain an existing :class:`SigmaMatch`."""
        return self.explain(match, event)

    def explanation(self, event: Event | SigmaMatch | SigmaRule | None = None) -> MatchExplanation:
        """Alias for :meth:`explain`."""
        return self.explain(event)

    def _resolve_arguments(
        self,
        first: Event | SigmaMatch | SigmaRule | None,
        second: Event | SigmaRule | None,
    ) -> tuple[Any, Event | None]:
        rule: Any = self.rule
        event: Event | None = self.event

        if isinstance(first, SigmaMatch):
            rule = first.rule
            if second is None:
                event = first.events[-1] if first.events else None
        elif isinstance(first, SigmaRule):
            rule = first
            if isinstance(second, Event):
                event = second
            elif second is None:
                event = self.event
        elif isinstance(first, Event):
            event = first
            if isinstance(second, SigmaRule):
                rule = second
            elif second is None:
                rule = self.rule
        elif first is None:
            if isinstance(second, SigmaRule):
                rule = second
            elif isinstance(second, Event):
                event = second

        if isinstance(second, Event):
            event = second
        elif isinstance(second, SigmaRule):
            rule = second
        return rule, event

    def _evaluate_conditions(self, rule: SigmaRule, data: Mapping[str, Any]) -> _EvalResult:
        true_alternatives: list[dict[str, set[str]]] = []
        unknown_reasons: list[str] = []
        for condition in rule.detection.parsed_condition:
            parsed = condition.parsed
            if parsed is None:
                continue
            result = self._evaluate_node(parsed, data)
            if result.value:
                true_alternatives.extend(result.alternatives or [{}])
            elif result.value is None:
                unknown_reasons.append(result.reason or "unsupported condition")
        if true_alternatives:
            return _EvalResult(True, true_alternatives)
        if unknown_reasons:
            return _EvalResult(None, reason="; ".join(dict.fromkeys(unknown_reasons)))
        return _EvalResult(False)

    def _evaluate_node(
        self,
        node: ConditionItem | ConditionFieldEqualsValueExpression | ConditionValueExpression,
        data: Mapping[str, Any],
    ) -> _EvalResult:
        if isinstance(node, ConditionAND):
            results = [self._evaluate_node(argument, data) for argument in node.args]  # type: ignore[arg-type]
            if any(result.value is False for result in results):
                return _EvalResult(False)
            unknown = next((result for result in results if result.value is None), None)
            if unknown is not None:
                return _EvalResult(None, reason=unknown.reason)
            alternatives = [{}]
            for result in results:
                alternatives = self._combine_alternatives(alternatives, result.alternatives or [{}])
            return _EvalResult(True, alternatives)

        if isinstance(node, ConditionOR):
            results = [self._evaluate_node(argument, data) for argument in node.args]  # type: ignore[arg-type]
            true_results = [result for result in results if result.value is True]
            if true_results:
                alternatives: list[dict[str, set[str]]] = []
                for result in true_results:
                    alternatives.extend(result.alternatives or [{}])
                return _EvalResult(True, alternatives)
            unknown = next((result for result in results if result.value is None), None)
            if unknown is not None:
                return _EvalResult(None, reason=unknown.reason)
            return _EvalResult(False)

        if isinstance(node, ConditionNOT):
            return _EvalResult(
                None,
                reason="unsupported condition: negated expressions cannot be reduced to fields",
            )

        if isinstance(node, ConditionFieldEqualsValueExpression):
            result, reasons = self._evaluate_field_value(node.field, node.value, data)
            if result is None:
                return _EvalResult(
                    None,
                    reason=(
                        reasons[0]
                        if reasons
                        else f"unsupported value type: {type(node.value).__name__}"
                    ),
                )
            if result:
                return _EvalResult(True, [{node.field: set(reasons)}])
            return _EvalResult(False)

        if isinstance(node, ConditionValueExpression):
            return _EvalResult(
                None,
                reason=("unsupported condition: keyword matches are not bound to an event field"),
            )

        return _EvalResult(
            None,
            reason=f"unsupported condition type: {type(node).__name__}",
        )

    def _evaluate_field_value(
        self, field_name: str, value: Any, data: Mapping[str, Any]
    ) -> tuple[bool | None, list[str]]:
        if isinstance(value, SigmaExpansion):
            true_reasons: list[str] = []
            saw_unknown = False
            for expanded_value in value.values:
                result, reasons = self._evaluate_field_value(field_name, expanded_value, data)
                if result is True:
                    true_reasons.extend(reasons)
                elif result is None:
                    saw_unknown = True
            if true_reasons:
                return True, list(dict.fromkeys(true_reasons))
            if saw_unknown:
                return None, ["unsupported value type inside expansion"]
            return False, []

        if not self._is_supported_value(value):
            return None, [f"unsupported value type: {type(value).__name__}"]

        reason = self._field_reason(field_name, value)
        if isinstance(value, SigmaNull):
            return data.get(field_name) is None, [reason]
        if isinstance(value, SigmaBool):
            return data.get(field_name) is bool(value), [reason]
        if isinstance(value, SigmaExists):
            return (field_name in data) == value.exists, [reason]
        if isinstance(value, SigmaNumber):
            return data.get(field_name) == value.number, [reason]
        if isinstance(value, SigmaCasedString):
            return self._match_string(str(data.get(field_name, "")), value, True), [reason]
        if isinstance(value, SigmaString):
            return self._match_string(str(data.get(field_name, "")), value, False), [reason]
        if isinstance(value, SigmaCompareExpression):
            return self._compare(data.get(field_name, 0), value), [reason]
        if isinstance(value, SigmaCIDRExpression):
            try:
                return ip_address(str(data.get(field_name, ""))) in value.network, [reason]
            except (TypeError, ValueError):
                return False, [reason]
        if isinstance(value, SigmaRegularExpression):
            flags = 0
            for flag in value.flags:
                flags |= value.sigma_to_python_flags[flag]
            pattern = re.compile(str(value.regexp), flags)
            return pattern.search(str(data.get(field_name, ""))) is not None, [reason]
        return None, [f"unsupported value type: {type(value).__name__}"]

    def _is_supported_value(self, value: Any) -> bool:
        if isinstance(value, SigmaFieldReference):
            return False
        if isinstance(value, self.SUPPORTED_VALUE_TYPES):
            return True
        return self.include_advanced_values and isinstance(value, self.ADVANCED_VALUE_TYPES)

    def _match_string(self, candidate: str, value: SigmaString, case_sensitive: bool) -> bool:
        if not value.contains_special():
            expected = str(value)
            if case_sensitive:
                return candidate == expected
            return candidate.lower() == expected.lower()
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(self._compiler._sigma_string_to_regex(value), flags)
        return pattern.search(candidate) is not None

    def _compare(self, candidate: Any, value: SigmaCompareExpression) -> bool:
        operators = {
            CompareOperators.LT: lambda a, b: a < b,
            CompareOperators.LTE: lambda a, b: a <= b,
            CompareOperators.GT: lambda a, b: a > b,
            CompareOperators.GTE: lambda a, b: a >= b,
            CompareOperators.NEQ: lambda a, b: a != b,
        }
        try:
            return bool(operators[value.op](candidate, value.number.number))
        except (TypeError, ValueError):
            return False

    def _field_reason(self, field_name: str, value: Any) -> str:
        if isinstance(value, SigmaNull):
            return f"{field_name} is null or absent"
        if isinstance(value, SigmaBool):
            return f"{field_name} is {str(value).lower()}"
        if isinstance(value, SigmaExists):
            return f"{field_name} exists" if value.exists else f"{field_name} does not exist"
        if isinstance(value, SigmaNumber):
            return f"{field_name} equals {value.number}"
        if isinstance(value, SigmaCasedString):
            return f"{field_name} matches {str(value)!r} case-sensitively"
        if isinstance(value, SigmaString):
            if value.contains_special():
                return f"{field_name} matches wildcard pattern {str(value)!r}"
            return f"{field_name} equals {str(value)!r} case-insensitively"
        if isinstance(value, SigmaCompareExpression):
            operator = {
                CompareOperators.LT: "<",
                CompareOperators.LTE: "<=",
                CompareOperators.GT: ">",
                CompareOperators.GTE: ">=",
                CompareOperators.NEQ: "!=",
            }[value.op]
            return f"{field_name} {operator} {value.number.number}"
        if isinstance(value, SigmaCIDRExpression):
            return f"{field_name} is within {value.cidr}"
        if isinstance(value, SigmaRegularExpression):
            return f"{field_name} matches regular expression {str(value.regexp)!r}"
        return f"{field_name} matches {type(value).__name__}"

    def _combine_alternatives(
        self,
        left: Sequence[dict[str, set[str]]],
        right: Sequence[dict[str, set[str]]],
    ) -> list[dict[str, set[str]]]:
        combined: list[dict[str, set[str]]] = []
        for left_alternative in left:
            for right_alternative in right:
                merged = {
                    field_name: set(reasons) for field_name, reasons in left_alternative.items()
                }
                for field_name, reasons in right_alternative.items():
                    merged.setdefault(field_name, set()).update(reasons)
                combined.append(merged)
                if len(combined) > self.max_alternatives:
                    return combined[: self.max_alternatives]
        return combined

    def _finalize_alternatives(
        self, alternatives: Sequence[dict[str, set[str]]]
    ) -> list[tuple[frozenset[str], dict[str, set[str]]]]:
        merged: dict[frozenset[str], dict[str, set[str]]] = {}
        for alternative in alternatives:
            fields = frozenset(alternative)
            target = merged.setdefault(fields, {})
            for field_name, reasons in alternative.items():
                target.setdefault(field_name, set()).update(reasons)

        minimal: list[tuple[frozenset[str], dict[str, set[str]]]] = []
        for fields, reasons in merged.items():
            if any(other_fields < fields for other_fields in merged):
                continue
            minimal.append((fields, reasons))
        minimal.sort(key=lambda item: (len(item[0]), sorted(item[0])))
        return minimal

    def _verify_and_shrink(
        self,
        alternatives: Sequence[tuple[frozenset[str], dict[str, set[str]]]],
        rule: SigmaRule,
        event: Event,
    ) -> list[tuple[frozenset[str], dict[str, set[str]]]]:
        verified: list[dict[str, set[str]]] = []
        for fields, reasons in alternatives:
            reduced = self._shrink_fields(set(fields), reasons, rule, event)
            if reduced is None:
                continue
            reduced_reasons = {
                field_name: set(field_reasons)
                for field_name, field_reasons in reasons.items()
                if field_name in reduced
            }
            verified.append(reduced_reasons)
        return self._finalize_alternatives(verified)

    def _shrink_fields(
        self,
        fields: set[str],
        reasons: Mapping[str, set[str]],
        rule: SigmaRule,
        event: Event,
    ) -> frozenset[str] | None:
        if not self._matches_subset(fields, rule, event):
            return None
        changed = True
        while changed:
            changed = False
            for field_name in sorted(fields):
                candidate = fields - {field_name}
                if self._matches_subset(candidate, rule, event):
                    fields = candidate
                    changed = True
                    break
        return frozenset(fields)

    def _matches_subset(self, fields: set[str], rule: SigmaRule, event: Event) -> bool:
        data = {
            field_name: event.data[field_name] for field_name in fields if field_name in event.data
        }
        subset = Event(
            timestamp=event.timestamp,
            logsource=event.logsource,
            data=data,
            raw=None,
        )
        try:
            return SigmaRuleMatcher(rule, self._compiler).matches(subset) is not None
        except Exception:
            return False

    def _to_alternative(
        self,
        fields: frozenset[str],
        reasons: Mapping[str, set[str]],
        event: Event,
    ) -> ExplanationAlternative:
        evidence = []
        for field_name in sorted(fields):
            reason = " and ".join(sorted(reasons.get(field_name, {"matched rule condition"})))
            value = event.data[field_name] if field_name in event.data else _MISSING
            evidence.append(FieldEvidence(field_name, reason, value))
        return ExplanationAlternative(FieldNames(fields), tuple(evidence))


def explain_match(
    rule_or_match: SigmaRule | SigmaMatch | Event | None = None,
    event: Event | SigmaRule | None = None,
    *,
    rule: SigmaRule | None = None,
    verify: bool = True,
    include_advanced_values: bool = False,
) -> MatchExplanation:
    """
    Explain a matched synthetic event using a minimal set of event fields.

    ``rule_or_match`` may be a :class:`SigmaRule`, a :class:`SigmaMatch`, or an
    :class:`Event` when the rule is supplied as the second argument. The function is fully
    offline and does not access network or external state.
    """
    if rule_or_match is None and rule is not None:
        rule_or_match = rule
    elif rule is not None and isinstance(rule_or_match, Event):
        event = rule
    explainer = MatchExplainer(verify=verify, include_advanced_values=include_advanced_values)
    if isinstance(rule_or_match, SigmaMatch):
        return explainer.explain(rule_or_match, event if isinstance(event, Event) else None)
    if isinstance(rule_or_match, Event) and isinstance(event, SigmaRule):
        return explainer.explain(rule_or_match, event)
    if isinstance(rule_or_match, SigmaRule) and isinstance(event, Event):
        return explainer.explain(rule_or_match, event)
    if isinstance(rule_or_match, SigmaRule):
        return explainer.explain(rule=rule_or_match)
    if isinstance(rule_or_match, Event):
        return explainer.explain(rule_or_match)
    return MatchExplanation(
        ExplanationStatus.UNDECIDABLE,
        reason="expected a SigmaRule, SigmaMatch or Event",
    )


explain = explain_match
explain_event = explain_match
explain_rule = explain_match
explain_rule_match = explain_match
get_explanation = explain_match
find_minimal_explanation = explain_match
minimal_explanation = explain_match

Explanation = MatchExplanation
SigmaMatchExplanation = MatchExplanation
MatchExplanationResult = MatchExplanation
SigmaExplainer = MatchExplainer
ExplanationEngine = MatchExplainer
MatchExplanationEngine = MatchExplainer
FieldExplanation = FieldEvidence
FieldJustification = FieldEvidence
MinimalFieldSet = ExplanationAlternative
ExplanationSet = ExplanationAlternative
SupportSet = ExplanationAlternative
ExplanationState = ExplanationStatus

__all__ = [
    "Explanation",
    "ExplanationAlternative",
    "ExplanationState",
    "ExplanationStatus",
    "FieldEvidence",
    "FieldExplanation",
    "FieldJustification",
    "FieldNames",
    "MatchExplanation",
    "MatchExplanationResult",
    "MatchExplainer",
    "MatchExplanationEngine",
    "ExplanationEngine",
    "ExplanationSet",
    "MinimalFieldSet",
    "SigmaExplainer",
    "SigmaMatchExplanation",
    "SupportSet",
    "explain",
    "explain_event",
    "explain_match",
    "explain_rule",
    "explain_rule_match",
    "find_minimal_explanation",
    "get_explanation",
    "minimal_explanation",
]
