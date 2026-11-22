from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.evidence.provenance import RAW_LOG_FIELD
from sigma.matching.compiler import MatchCompiler
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

if TYPE_CHECKING:
    from sigma.conditions import ConditionItem
    from sigma.matching.event import Event
    from sigma.matching.match import SigmaMatch


@dataclass(frozen=True)
class EvidenceFact:
    """
    A statement that is (or should be) supported by the matched telemetry.

    ``sources`` names the fields the statement directly uses.  A reviewer expands them
    through :class:`~sigma.evidence.provenance.FieldProvenance` before deciding whether
    the fact may be published.
    """

    id: str
    statement: str
    sources: frozenset[str]
    kind: str = "claim"
    public_statement: str | None = None
    event_index: int | None = None
    observed: bool = True
    required: bool = True
    requires_presence: bool = True
    absent_sources: frozenset[str] = frozenset()
    value: Any = field(default=None, compare=False)
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.sources, str):
            object.__setattr__(self, "sources", frozenset({self.sources}))
        else:
            object.__setattr__(self, "sources", frozenset(self.sources))
        object.__setattr__(self, "absent_sources", frozenset(self.absent_sources))
        if self.event_index is not None and self.event_index < 0:
            raise ValueError("event_index must be zero or greater")

    @property
    def fact_id(self) -> str:
        return self.id

    @property
    def fields(self) -> frozenset[str]:
        return self.sources

    def __str__(self) -> str:
        return self.statement


# Convenient synonym for callers that prefer "claim" terminology.
EvidenceClaim = EvidenceFact


class FactExtractor:
    """
    Extract small, independently checkable facts from a successful match.

    Only condition branches that actually evaluate to true are emitted.  This matters for
    OR conditions: fields in an unused branch are not treated as evidence that a public
    report relied on.
    """

    def __init__(self) -> None:
        self._compiler = MatchCompiler()
        self._ordinal = 0

    def extract(self, match: SigmaMatch) -> list[EvidenceFact]:
        self._ordinal = 0
        from sigma.correlations import SigmaCorrelationRule

        if isinstance(match.rule, SigmaCorrelationRule):
            return self._extract_correlation_facts(match)
        return self._extract_detection_facts(match)

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------
    def _extract_detection_facts(self, match: SigmaMatch) -> list[EvidenceFact]:
        facts: list[EvidenceFact] = []
        rule_name = getattr(match.rule, "name", None) or getattr(match.rule, "title", "rule")

        for event_index, event in enumerate(match.events):
            conditions = getattr(getattr(match.rule, "detection", None), "parsed_condition", [])
            for condition in conditions:
                parsed = getattr(condition, "parsed", None)
                if parsed is None:
                    continue
                support = self._support(
                    parsed,
                    event,
                    rule_name=rule_name,
                    event_index=event_index,
                )
                if support:
                    facts.extend(support)

        if not facts:
            # A rule can legitimately match without exposing a simple field expression
            # (for example a deferred or backend-specific construct).  Keep a marker so
            # that the match itself can still be reviewed.
            fallback_sources: set[str] = set()
            conditions = getattr(getattr(match.rule, "detection", None), "parsed_condition", [])
            for condition in conditions:
                parsed = getattr(condition, "parsed", None)
                if parsed is not None:
                    fallback_sources.update(self._node_fields(parsed))
            facts.append(
                EvidenceFact(
                    id=f"{rule_name}:match",
                    statement=f"Rule '{rule_name}' matched the event",
                    sources=frozenset(fallback_sources or {RAW_LOG_FIELD}),
                    kind="match",
                )
            )
        else:
            sources: set[str] = set()
            absent_sources: set[str] = set()
            for fact in facts:
                sources.update(fact.sources)
                absent_sources.update(fact.absent_sources)
            facts.append(
                EvidenceFact(
                    id=f"{rule_name}:match",
                    statement=f"Rule '{rule_name}' matched the event",
                    sources=frozenset(sources),
                    kind="match",
                    absent_sources=frozenset(absent_sources),
                )
            )
        return self._deduplicate(facts)

    # ------------------------------------------------------------------
    # Correlation rules
    # ------------------------------------------------------------------
    def _extract_correlation_facts(self, match: SigmaMatch) -> list[EvidenceFact]:
        rule = match.rule
        rule_name = getattr(rule, "name", None) or getattr(rule, "title", "rule")
        facts: list[EvidenceFact] = []

        for group_name, group_value in (match.group_values or {}).items():
            facts.append(
                EvidenceFact(
                    id=f"{rule_name}:group:{group_name}",
                    statement=f"{group_name} = {group_value!r}",
                    sources=frozenset({group_name}),
                    kind="group",
                    value=group_value,
                    event_index=0 if match.events else None,
                )
            )

        sources: set[str] = set(match.group_values or {})
        condition = getattr(rule, "condition", None)
        fieldref = getattr(condition, "fieldref", None)
        if isinstance(fieldref, str):
            sources.add(fieldref)
        elif isinstance(fieldref, Iterable):
            sources.update(str(field) for field in fieldref)
        if not sources and match.events:
            # Without a narrower support description, a correlation statement depends on
            # every field in the correlated events.  Failing closed is preferable to
            # publishing a conclusion that cannot be traced.
            for event in match.events:
                sources.update(event.data.keys())

        facts.append(
            EvidenceFact(
                id=f"{rule_name}:correlation",
                statement=f"Correlation rule '{rule_name}' matched",
                sources=frozenset(sources),
                kind="correlation",
            )
        )
        return self._deduplicate(facts)

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------
    def _support(
        self,
        node: ConditionItem,
        event: Event,
        *,
        rule_name: str,
        event_index: int,
    ) -> list[EvidenceFact] | None:
        if isinstance(node, ConditionAND):
            results = [
                self._support(arg, event, rule_name=rule_name, event_index=event_index)
                for arg in node.args
            ]
            if any(result is None for result in results):
                return None
            facts: list[EvidenceFact] = []
            for result in results:
                facts.extend(result or [])
            return facts

        if isinstance(node, ConditionOR):
            results = [
                self._support(arg, event, rule_name=rule_name, event_index=event_index)
                for arg in node.args
            ]
            true_results = [result for result in results if result is not None]
            if not true_results:
                return None
            facts = []
            for result in true_results:
                facts.extend(result)
            return facts

        if isinstance(node, ConditionNOT):
            inner = self._support(node.args[0], event, rule_name=rule_name, event_index=event_index)
            if inner is not None:
                return None
            return [
                EvidenceFact(
                    id=f"{rule_name}:detection:{event_index}:not:{self._next_ordinal()}",
                    statement=f"not ({self._describe_node(node.args[0])})",
                    sources=frozenset(self._node_fields(node.args[0])),
                    kind="detection",
                    event_index=event_index,
                    requires_presence=False,
                    absent_sources=frozenset(self._node_fields(node.args[0])),
                )
            ]

        if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
            if not self._leaf_matches(node, event):
                return None
            return [
                self._fact_for_leaf(
                    node,
                    event,
                    rule_name=rule_name,
                    event_index=event_index,
                )
            ]

        return None

    def _leaf_matches(
        self,
        node: ConditionFieldEqualsValueExpression | ConditionValueExpression,
        event: Event,
    ) -> bool:
        closures: dict[str, Any] = {}
        if isinstance(node, ConditionFieldEqualsValueExpression):
            expression = self._compiler._compile_field_value(  # noqa: SLF001
                node.field, node.value, closures
            )
        else:
            expression = self._compiler._compile_keyword(node.value, closures)  # noqa: SLF001
        namespace = {"__builtins__": {"str": str, "bool": bool}}
        namespace.update(closures)
        predicate = eval(f"lambda data, raw: bool({expression})", namespace)  # noqa: S307
        return bool(predicate(event.data, event.get_raw()))

    def _fact_for_leaf(
        self,
        node: ConditionFieldEqualsValueExpression | ConditionValueExpression,
        event: Event,
        *,
        rule_name: str,
        event_index: int,
    ) -> EvidenceFact:
        if isinstance(node, ConditionFieldEqualsValueExpression):
            field = node.field
            sources = {field}
            if isinstance(node.value, SigmaFieldReference):
                sources.add(node.value.field)
            statement = f"{field} {self._relation(node.value)} {self._describe_value(node.value)}"
            value = event.data.get(field)
        else:
            field = RAW_LOG_FIELD
            sources = {RAW_LOG_FIELD}
            statement = f"raw log {self._relation(node.value)} {self._describe_value(node.value)}"
            value = event.get_raw()

        return EvidenceFact(
            id=f"{rule_name}:detection:{event_index}:{self._next_ordinal()}:{field}",
            statement=statement,
            sources=frozenset(sources),
            kind="detection",
            event_index=event_index,
            requires_presence=self._requires_presence(node),
            absent_sources=(
                frozenset(sources) if not self._requires_presence(node) else frozenset()
            ),
            value=value,
            metadata={"field": field},
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _next_ordinal(self) -> int:
        self._ordinal += 1
        return self._ordinal

    @staticmethod
    def _deduplicate(facts: list[EvidenceFact]) -> list[EvidenceFact]:
        seen: set[str] = set()
        result: list[EvidenceFact] = []
        for fact in facts:
            if fact.id in seen:
                continue
            seen.add(fact.id)
            result.append(fact)
        return result

    @staticmethod
    def _field_references(value: Any) -> set[str]:
        if isinstance(value, SigmaFieldReference):
            return {value.field}
        if isinstance(value, SigmaExpansion):
            fields: set[str] = set()
            for item in value.values:
                fields.update(FactExtractor._field_references(item))
            return fields
        return set()

    @classmethod
    def _node_fields(cls, node: Any) -> set[str]:
        if isinstance(node, ConditionFieldEqualsValueExpression):
            fields = {node.field}
            fields.update(cls._field_references(node.value))
            return fields
        if isinstance(node, ConditionValueExpression):
            return {RAW_LOG_FIELD}
        if isinstance(node, (ConditionAND, ConditionOR, ConditionNOT)):
            fields = set()
            for arg in node.args:
                fields.update(cls._node_fields(arg))
            return fields
        return set()

    @staticmethod
    def _requires_presence(node: Any) -> bool:
        value = getattr(node, "value", None)
        if isinstance(value, SigmaNull):
            return False
        if isinstance(value, SigmaExists):
            return bool(value.exists)
        return True

    @staticmethod
    def _relation(value: Any) -> str:
        if isinstance(value, SigmaRegularExpression):
            return "matches regex"
        if isinstance(value, SigmaCIDRExpression):
            return "is in CIDR"
        if isinstance(value, SigmaCompareExpression):
            return {
                "lt": "<",
                "lte": "<=",
                "gt": ">",
                "gte": ">=",
                "neq": "!=",
            }.get(getattr(value.op, "name", "").lower(), "compares to")
        if isinstance(value, SigmaExists):
            return "exists" if value.exists else "does not exist"
        if isinstance(value, SigmaNull):
            return "is"
        if isinstance(value, SigmaFieldReference):
            if value.starts_with and value.ends_with:
                return "contains the value of"
            if value.starts_with:
                return "starts with the value of"
            if value.ends_with:
                return "ends with the value of"
            return "equals"
        if isinstance(value, SigmaString) and value.contains_special():
            starts = value.startswith(SpecialChars.WILDCARD_MULTI)
            ends = value.endswith(SpecialChars.WILDCARD_MULTI)
            if starts and ends:
                return "contains"
            if starts:
                return "ends with"
            if ends:
                return "starts with"
        return "equals"

    @staticmethod
    def _describe_value(value: Any) -> str:
        if isinstance(value, SigmaNull):
            return "null"
        if isinstance(value, SigmaBool):
            return "true" if bool(value) else "false"
        if isinstance(value, SigmaNumber):
            return str(value.number)
        if isinstance(value, SigmaString):
            text = str(value)
            return repr(text if len(text) <= 120 else text[:117] + "...")
        if isinstance(value, SigmaRegularExpression):
            text = str(value.regexp)
            return repr(text if len(text) <= 120 else text[:117] + "...")
        if isinstance(value, SigmaCIDRExpression):
            return repr(str(value.network))
        if isinstance(value, SigmaFieldReference):
            return f"field {value.field!r}"
        if isinstance(value, SigmaExpansion):
            return (
                "(" + ", ".join(FactExtractor._describe_value(item) for item in value.values) + ")"
            )
        if isinstance(value, SigmaCompareExpression):
            return str(value.number.number)
        if isinstance(value, SigmaExists):
            return "exists" if value.exists else "does not exist"
        return repr(value)

    @classmethod
    def _describe_node(cls, node: Any) -> str:
        if isinstance(node, ConditionFieldEqualsValueExpression):
            return f"{node.field} {cls._relation(node.value)} {cls._describe_value(node.value)}"
        if isinstance(node, ConditionValueExpression):
            return f"raw log {cls._relation(node.value)} {cls._describe_value(node.value)}"
        if isinstance(node, ConditionAND):
            return " and ".join(f"({cls._describe_node(arg)})" for arg in node.args)
        if isinstance(node, ConditionOR):
            return " or ".join(f"({cls._describe_node(arg)})" for arg in node.args)
        if isinstance(node, ConditionNOT):
            return f"not ({cls._describe_node(node.args[0])})"
        return "condition"
