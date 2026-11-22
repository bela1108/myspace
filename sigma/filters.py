from __future__ import annotations

import copy
import hashlib
import re
import string
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from typing import Self

from sigma import exceptions as sigma_exceptions
from sigma.conditions import ConditionNOT
from sigma.correlations import SigmaCorrelationRule, SigmaRuleReference
from sigma.rule import SigmaDetection, SigmaDetections, SigmaLogSource, SigmaRule, SigmaRuleBase
from sigma.rule.logsource import EmptyLogSource

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from sigma.exceptions import SigmaRuleLocation
    from sigma.policy import SigmaPolicy


_CONDITION_KEYWORDS: frozenset[str] = frozenset({"not", "and", "or", "all", "any", "of", "1"})

# A single condition token: a detection identifier or an identifier pattern. It mirrors the
# character sets of ``identifier`` (alphanumerics, ``_`` and ``-``) and ``identifier_pattern``
# (the same characters plus ``*``) in sigma.conditions.
_CONDITION_TOKEN: re.Pattern[str] = re.compile(r"[a-zA-Z0-9_*-]+")


def _source_string(source: "SigmaRuleLocation | None") -> str | None:
    """Return a stable, human readable representation of a Sigma source location."""
    return str(source) if source is not None else None


def _condition_tokens(condition: str) -> list[str]:
    """Return condition identifiers and identifier patterns, without Sigma keywords."""
    return [
        token for token in _CONDITION_TOKEN.findall(condition) if token not in _CONDITION_KEYWORDS
    ]


def _matches_identifier_pattern(identifier: str, pattern: str) -> bool:
    """Match a Sigma identifier against an identifier pattern that may contain ``*``."""
    if pattern == "them":
        return True
    if "*" not in pattern:
        return identifier == pattern
    return re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), identifier) is not None


def _reference_value(reference: SigmaRuleReference | str) -> str:
    """Return the string value of a rule reference declaration."""
    if isinstance(reference, SigmaRuleReference):
        return reference.reference
    return str(reference)


def _contains_negation(condition: Any) -> bool:
    """Return True if a parsed condition tree contains a NOT node."""
    if isinstance(condition, ConditionNOT):
        return True
    return any(_contains_negation(arg) for arg in getattr(condition, "args", ()))


@dataclass(frozen=True)
class SigmaFilterScope:
    """
    Inspectable applicability contract of a :class:`SigmaFilter`.

    The scope binds the objects a filter was explicitly declared for (rule references and a
    logsource), the filter condition, and the detections that condition may reference.  It is
    intentionally independent of a concrete rule collection: :meth:`resolve` turns the declared
    references into concrete rule objects, while :meth:`resolve_detections` resolves every
    condition token against the filter's *own* detections.  A filter condition therefore never
    borrows a same-named detection from a rule it is applied to.
    """

    rules: Sequence[SigmaRuleReference] | str
    logsource: SigmaLogSource
    condition: str
    detections: Mapping[str, SigmaDetection] = field(repr=False, compare=False)
    source: "SigmaRuleLocation | None" = field(default=None, repr=False, compare=False)

    @property
    def any_rule(self) -> bool:
        """True if the filter explicitly targets all matching rules."""
        return isinstance(self.rules, str) and self.rules.lower() == "any"

    @property
    def rule_references(self) -> tuple[str, ...]:
        """Rule references exactly as declared by the caller."""
        if isinstance(self.rules, str):
            return ()
        return tuple(_reference_value(reference) for reference in self.rules)

    @property
    def targets(self) -> tuple[str, ...]:
        """Alias for :attr:`rule_references`."""
        return self.rule_references

    @property
    def detection_names(self) -> tuple[str, ...]:
        """Names of the detections owned by this filter."""
        return tuple(self.detections)

    @property
    def condition_tokens(self) -> tuple[str, ...]:
        """Identifiers and patterns referenced by the filter condition."""
        return tuple(_condition_tokens(self.condition))

    def matches_logsource(self, rule: SigmaRule | SigmaCorrelationRule) -> bool:
        """Return True if the rule's logsource is covered by this filter's logsource."""
        return rule.logsource in self.logsource

    def matching_reference(
        self, rule: SigmaRule | SigmaCorrelationRule
    ) -> SigmaRuleReference | str | None:
        """
        Return the explicit reference that binds this filter to *rule*, or ``None``.

        Matching is performed against the rule object supplied by the caller and never by
        looking the reference up in a collection.  This keeps the mapping deterministic even
        if two rules share a name or a detection identifier.
        """
        if isinstance(rule, SigmaCorrelationRule) or not self.matches_logsource(rule):
            return None
        if self.any_rule:
            return "any"
        assert not isinstance(self.rules, str)
        for reference in self.rules:
            if getattr(reference, "rule", None) is rule:
                return reference
            value = _reference_value(reference)
            if rule.id is not None and value == str(rule.id):
                return reference
            if rule.name is not None and value == rule.name:
                return reference
            if value == rule.title:
                return reference
        return None

    def applies_to(self, rule: SigmaRule | SigmaCorrelationRule) -> bool:
        """Return True if *rule* is in the filter's declared object scope."""
        return self.matching_reference(rule) is not None

    def resolve(
        self, rules: Iterable[SigmaRule | SigmaCorrelationRule]
    ) -> list[tuple[SigmaRule, SigmaRuleReference | str]]:
        """
        Bind the declared scope to concrete rule objects.

        The returned pairs retain object identity (the exact rule instance passed by the
        caller) together with the declaration that selected it.  Duplicate views of the same
        object are only returned once.
        """
        resolved: list[tuple[SigmaRule, SigmaRuleReference | str]] = []
        seen: set[int] = set()
        for rule in rules:
            if not isinstance(rule, SigmaRule) or id(rule) in seen:
                continue
            reference = self.matching_reference(rule)
            if reference is not None:
                resolved.append((rule, reference))
                seen.add(id(rule))
        return resolved

    def resolve_detections(self, condition: str | None = None) -> dict[str, tuple[str, ...]]:
        """
        Resolve every condition token against the filter's own detections.

        The result maps the token as written in the condition (for example ``selection`` or
        ``1 of selection_*``'s pattern ``selection_*``) to the filter detection names it
        selects.  An empty tuple means the token does not resolve inside this filter.
        """
        condition = self.condition if condition is None else condition
        return {
            token: tuple(
                name for name in self.detections if _matches_identifier_pattern(name, token)
            )
            for token in _condition_tokens(condition)
        }

    @property
    def resolved_detections(self) -> dict[str, tuple[str, ...]]:
        """Alias for :meth:`resolve_detections` with the filter's own condition."""
        return self.resolve_detections()

    def unresolved_tokens(self, condition: str | None = None) -> tuple[str, ...]:
        """Return condition tokens that have no corresponding detection in this filter."""
        return tuple(
            token for token, names in self.resolve_detections(condition).items() if not names
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the applicability contract into an inspectable plain data structure."""
        return {
            "rules": "any" if self.any_rule else list(self.rule_references),
            "logsource": self.logsource.to_dict(),
            "condition": self.condition,
            "detections": list(self.detection_names),
            "condition_tokens": list(self.condition_tokens),
            "resolved_detections": {
                token: list(names) for token, names in self.resolve_detections().items()
            },
            "source": _source_string(self.source),
        }


@dataclass
class SigmaFilterApplication:
    """
    One application of a filter to one concrete rule object.

    The record is the provenance contract between a converted rule and the material that
    contributed an exception.  It keeps the exact rule instance, the filter object, the
    declared reference, the allocated detection namespace and the filter source location.
    Records remain attached to their rule across ``SigmaCollection.merge`` and are appended
    for every filter application, so multiple materials stay distinguishable.
    """

    filter: "SigmaFilter" = field(repr=False, compare=False)
    rule: SigmaRule = field(repr=False, compare=False)
    reference: str | None = None
    namespace: str = ""
    source_condition: str = ""
    condition: str = ""
    detections: dict[str, str] = field(default_factory=dict)
    negated: bool = False
    excludes: bool = False

    @property
    def source(self) -> "SigmaRuleLocation | None":
        """Source location of the material that defined the filter."""
        return self.filter.source

    @property
    def filter_source(self) -> "SigmaRuleLocation | None":
        """Alias for :attr:`source`."""
        return self.source

    @property
    def origin(self) -> "SigmaRuleLocation | None":
        """Alias for :attr:`source`."""
        return self.source

    @property
    def source_str(self) -> str | None:
        """Human readable source location of the filter material."""
        return _source_string(self.source)

    @property
    def source_path(self) -> Path | None:
        """Path of the filter material, if the filter came from a file."""
        return self.source.path if self.source is not None else None

    @property
    def filter_scope(self) -> SigmaFilterScope:
        """The applicability contract that produced this application."""
        return self.filter.filter_scope

    @property
    def namespace_detections(self) -> dict[str, str]:
        """Alias for :attr:`detections` (original name -> qualified name)."""
        return self.detections

    @property
    def rule_source(self) -> "SigmaRuleLocation | None":
        """Source location of the rule the filter was applied to."""
        return self.rule.source

    @property
    def filter_id(self) -> UUID | None:
        return self.filter.id

    @property
    def filter_title(self) -> str:
        return self.filter.title

    @property
    def filter_name(self) -> str | None:
        return self.filter.name

    @property
    def rule_id(self) -> UUID | None:
        return self.rule.id

    @property
    def rule_title(self) -> str:
        return self.rule.title

    @property
    def rule_name(self) -> str | None:
        return self.rule.name

    @property
    def polarity(self) -> str:
        """``exclude`` for a negated filter condition, otherwise ``include``."""
        return "exclude" if self.excludes else "include"

    def to_dict(self) -> dict[str, Any]:
        """Convert the application into a plain, inspectable data structure."""
        return {
            "filter": {
                "title": self.filter.title,
                "id": str(self.filter.id) if self.filter.id is not None else None,
                "name": self.filter.name,
                "source": _source_string(self.source),
            },
            "rule": {
                "title": self.rule.title,
                "id": str(self.rule.id) if self.rule.id is not None else None,
                "name": self.rule.name,
                "source": _source_string(self.rule_source),
            },
            "reference": self.reference,
            "namespace": self.namespace,
            "condition": self.condition,
            "source_condition": self.source_condition,
            "detections": dict(self.detections),
            "negated": self.negated,
            "excludes": self.excludes,
            "polarity": self.polarity,
            "source": _source_string(self.source),
            "filter_source": _source_string(self.source),
            "rule_source": _source_string(self.rule_source),
        }

    def as_dict(self) -> dict[str, Any]:
        """Alias for :meth:`to_dict`."""
        return self.to_dict()

    def describe(self) -> str:
        """Return a one-line provenance description of this application."""
        source = _source_string(self.source) or "<memory>"
        return (
            f"filter '{self.filter.title}' from {source} "
            f"applied to rule '{self.rule.title}'"
            + (f" ({self.reference})" if self.reference else "")
            + f" via {self.namespace}: {self.condition}"
        )


# Short aliases for callers that do not need the ``Sigma`` prefix.
FilterScope = SigmaFilterScope
SigmaFilterScopeContract = SigmaFilterScope
FilterApplication = SigmaFilterApplication


@dataclass
class SigmaGlobalFilter(SigmaDetections):
    rules: list[SigmaRuleReference] | str = field(default_factory=list)

    @classmethod
    def from_dict(
        cls: type[Self],
        detections: dict[str, Any],
        source: SigmaRuleLocation | None = None,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        try:
            if isinstance(detections["condition"], str):
                condition = [detections["condition"]]
            else:
                raise sigma_exceptions.SigmaFilterConditionError(
                    "Sigma filter condition must be a string", source=source
                )
        except KeyError:
            raise sigma_exceptions.SigmaFilterConditionError(
                "Sigma filter must contain exactly one condition", source=source
            )

        scope_is_rules_alias = "rules" not in detections and "scope" in detections
        try:
            rules_spec = detections["rules"]
        except KeyError:
            if not scope_is_rules_alias:
                # Rules field is required - must explicitly specify "any" or specific rule references
                raise sigma_exceptions.SigmaFilterRuleReferenceError(
                    "Sigma filter must have a 'rules' field (use 'any' to apply to all rules matching the logsource)",
                    source=source,
                )
            rules_spec = detections["scope"]

        if isinstance(rules_spec, Mapping):
            rules_spec = (
                rules_spec.get("rules")
                or rules_spec.get("references")
                or rules_spec.get("rule")
                or ("any" if rules_spec.get("any") else None)
            )

        rules: list[SigmaRuleReference] | str
        if isinstance(rules_spec, str):
            # Check if it's "any" keyword
            if rules_spec.lower() == "any":
                rules = rules_spec.lower()
            else:
                # Single rule reference
                rules = [SigmaRuleReference(rules_spec)]
        elif isinstance(rules_spec, list):
            # Empty list is treated as "any"
            if not rules_spec:
                rules = "any"
            else:
                rules = [SigmaRuleReference(detection) for detection in rules_spec]
        else:
            raise sigma_exceptions.SigmaFilterRuleReferenceError(
                "Sigma filter rules field must be 'any', a rule ID/name, or a list of rule IDs/names",
                source=source,
            )

        return cls(
            detections={
                name: SigmaDetection.from_definition(definition, source, policy)
                for name, definition in detections.items()
                if name not in ("condition", "rules")
                and not (scope_is_rules_alias and name == "scope")
            },
            rules=rules,
            condition=condition,
            source=source,
            policy=policy,
        )

    def to_dict(self: Self) -> dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "rules": (
                    self.rules
                    if isinstance(self.rules, str)
                    else [ref.reference for ref in self.rules]
                ),
            }
        )

        return d


@dataclass
class EmptySigmaGlobalFilter(SigmaGlobalFilter):
    """
    Empty Sigma global filter used as a placeholder for error handling purposes.
    """

    detections: dict[str, SigmaDetection] = field(default_factory=dict)
    condition: list[str] = field(default_factory=list)
    rules: list[SigmaRuleReference] | str = field(default_factory=list)

    def __post_init__(self: Self) -> None:
        # Skip all checks and initializations
        pass


@dataclass
class SigmaFilter(SigmaRuleBase):
    """
    SigmaFilter class is used to represent a Sigma filter object.
    """

    logsource: SigmaLogSource = field(default_factory=SigmaLogSource)
    filter: SigmaGlobalFilter = field(
        default_factory=lambda: SigmaGlobalFilter({}, []),
    )

    @classmethod
    def from_dict(  # type: ignore[override]
        cls: type[Self],
        sigma_filter: dict[str, Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        """
        Converts from a dictionary object to a SigmaFilter object.
        """
        kwargs, errors = super().from_dict_common_params(
            sigma_filter, collect_errors, source, policy=policy
        )

        # parse log source
        try:
            filter_logsource = SigmaLogSource.from_dict(sigma_filter["logsource"], source)
        except KeyError:
            filter_logsource = EmptyLogSource()
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma filter must have a log source", source=source
                )
            )
        except AttributeError:
            filter_logsource = EmptyLogSource()
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma logsource must be a valid YAML map", source=source
                )
            )
        except sigma_exceptions.SigmaError as e:
            filter_logsource = EmptyLogSource()
            errors.append(e)

        # parse detections
        try:
            filter_global_filter = SigmaGlobalFilter.from_dict(
                sigma_filter["filter"], source, policy=policy
            )
        except KeyError:
            filter_global_filter = EmptySigmaGlobalFilter()
            errors.append(
                sigma_exceptions.SigmaFilterError(
                    "Sigma filter must have a filter defined", source=source
                )
            )
        except TypeError:
            filter_global_filter = EmptySigmaGlobalFilter()
            errors.append(
                sigma_exceptions.SigmaFilterError(
                    "Sigma filter must be a dictionary", source=source
                )
            )
        except sigma_exceptions.SigmaError as e:
            filter_global_filter = EmptySigmaGlobalFilter()
            errors.append(e)

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            logsource=filter_logsource,
            filter=filter_global_filter,
            errors=errors,
            **kwargs,
        )

    def to_dict(self: Self) -> dict[str, Any]:
        """Convert filter object into dict."""
        d = super().to_dict()
        d.update(
            {
                "logsource": self.logsource.to_dict(),
                "filter": self.filter.to_dict(),
            }
        )

        return d

    def _should_apply_on_rule(self: Self, rule: SigmaRule | SigmaCorrelationRule) -> bool:
        """Return True if the filter's declared scope contains this rule."""
        return self.applies_to(rule)

    @property
    def filter_scope(self: Self) -> SigmaFilterScope:
        """
        Inspectable applicability contract of this filter.

        The scope connects the declared rule objects and logsource to the exact detections
        that the filter condition may reference.  It can be inspected without applying the
        filter and is the authoritative source for :meth:`applies_to`.
        """
        condition = self.filter.condition[0] if self.filter.condition else ""
        return SigmaFilterScope(
            rules=self.filter.rules,
            logsource=self.logsource,
            condition=condition,
            detections=dict(self.filter.detections),
            source=self.source,
        )

    def get_filter_scope(
        self: Self, rules: Iterable[SigmaRule | SigmaCorrelationRule] | None = None
    ) -> SigmaFilterScope | list[tuple[SigmaRule, SigmaRuleReference | str]]:
        """Return the inspectable applicability contract for this filter."""
        return self.filter_scope if rules is None else self.resolve_scope(rules)

    def get_scope(
        self: Self, rules: Iterable[SigmaRule | SigmaCorrelationRule] | None = None
    ) -> SigmaFilterScope | list[tuple[SigmaRule, SigmaRuleReference | str]]:
        """Alias for :meth:`get_filter_scope`."""
        return self.get_filter_scope(rules)

    @property
    def applicability(self: Self) -> SigmaFilterScope:
        """Alias for :attr:`filter_scope`."""
        return self.filter_scope

    @property
    def scope_contract(self: Self) -> SigmaFilterScope:
        """Alias for :attr:`filter_scope`."""
        return self.filter_scope

    def get_applicability(self: Self) -> SigmaFilterScope:
        """Alias for :meth:`get_filter_scope`."""
        return self.filter_scope

    def applies_to(self: Self, rule: SigmaRule | SigmaCorrelationRule) -> bool:
        """Return True if this filter explicitly applies to *rule*."""
        return self.filter_scope.applies_to(rule)

    # Alias kept for callers that prefer condition-style naming.
    matches_rule = applies_to

    def resolve_scope(
        self: Self, rules: Iterable[SigmaRule | SigmaCorrelationRule]
    ) -> list[tuple[SigmaRule, SigmaRuleReference | str]]:
        """
        Bind this filter's declared scope to the passed rule objects.

        Returns the exact rule instances together with the declaration that selected each
        rule.  This is the explicit object mapping used by
        :meth:`SigmaCollection.apply_filters`.
        """
        return self.filter_scope.resolve(rules)

    def apply_to_rules(
        self: Self, rules: Iterable[SigmaRule | SigmaCorrelationRule]
    ) -> list[SigmaRule]:
        """Apply this filter to the explicitly passed rules and return the affected rules."""
        applied: list[SigmaRule] = []
        for rule, reference in self.resolve_scope(rules):
            self.apply_on_rule(rule, reference=reference)
            applied.append(rule)
        return applied

    # Keywords that must not be prefixed when rewriting filter conditions. They are compared
    # case-sensitively, like in the condition grammar in sigma.conditions, where e.g. "NOT" is
    # an ordinary identifier and not the negation operator. "them" is deliberately absent:
    # it is rewritten to the namespace wildcard.
    _CONDITION_KEYWORDS: ClassVar[frozenset[str]] = _CONDITION_KEYWORDS

    # A single condition token: a detection identifier or an identifier pattern. Mirrors the
    # character sets of ``identifier`` (alphanumerics, ``_`` and ``-``) and ``identifier_pattern``
    # (the same characters plus ``*``) in sigma.conditions. Identifiers may start with any of
    # these characters, e.g. ``_filter`` or ``2nd_filter``.
    _CONDITION_TOKEN: ClassVar[re.Pattern[str]] = _CONDITION_TOKEN

    def _filter_condition(self: Self) -> str:
        """Return the filter condition string, tolerating empty error placeholders."""
        return self.filter.condition[0] if self.filter.condition else ""

    def _condition_negation(self: Self) -> tuple[bool, bool]:
        """
        Return ``(contains_negation, is_exclusion)`` for the filter condition.

        ``contains_negation`` reports any NOT in the condition tree, while ``is_exclusion``
        is true only if the condition as a whole is negated (the usual false-positive
        filter form, e.g. ``not selection``).
        """
        try:
            parsed = self.filter.parsed_condition[0].parse(postprocess=False)
        except (AttributeError, IndexError):
            condition = self._filter_condition()
            negated = re.search(r"\bnot\b", condition) is not None
            return negated, negated
        return _contains_negation(parsed), isinstance(parsed, ConditionNOT)

    def _namespace_token(self: Self, index: int = 0) -> str:
        """
        Derive a deterministic namespace token from the filter's source identity.

        The token stays in the historical ``_filt_<10 lowercase letters>`` format, but is
        derived from the source location, filter identity and condition instead of random
        data.  The same filter material therefore receives the same namespace across runs
        and across merges.
        """
        source = ""
        if self.source is not None:
            try:
                source = str(self.source.path.resolve())
            except OSError:
                source = str(self.source.path)
        identity = "\x1f".join(
            (
                source,
                str(self.id) if self.id is not None else "",
                self.name or "",
                self.title or "",
                self._filter_condition(),
                ",".join(self.filter.detections),
                str(index),
            )
        )
        digest = hashlib.sha256(identity.encode("utf-8")).digest()
        token = "".join(
            string.ascii_lowercase[byte % len(string.ascii_lowercase)] for byte in digest[:10]
        )
        return "_filt_" + token

    def _allocate_namespace(self: Self, rule: SigmaRule) -> str:
        """Allocate a namespace that does not collide with detections already on *rule*."""
        index = 0
        while True:
            token = self._namespace_token(index)
            if not any(name.startswith(token + "_") for name in rule.detection.detections):
                return token
            index += 1

    def apply_on_rule(
        self: Self,
        rule: SigmaRule | SigmaCorrelationRule,
        reference: SigmaRuleReference | str | None = None,
    ) -> SigmaRule | SigmaCorrelationRule:
        if isinstance(rule, SigmaCorrelationRule):
            return rule
        if reference is None:
            reference = self.filter_scope.matching_reference(rule)
        if reference is None:
            return rule

        # Re-applying the same filter object after a merge must not duplicate its negation.
        # Distinct filter objects with identical content (e.g. the same file loaded twice)
        # are still applied independently.
        for application in getattr(rule, "applied_filters", ()):
            if application.filter is self:
                return rule

        filter_condition = self._filter_condition()
        if not filter_condition or not self.filter.detections:
            return rule

        # Allocate one namespace shared by all filter identifiers in this application. The
        # namespace is derived from the filter source, so the resulting exception remains
        # attributable to the material it came from after merging and negating.
        prefix = self._allocate_namespace(rule)
        detection_map: dict[str, str] = {}

        # Rename every filter detection identifier with the shared namespace. Each rule gets its
        # own copy of the filter detections: processing pipelines modify detections in place, so
        # a detection object shared between rules would be transformed again for every rule.
        for original_cond_name, condition in self.filter.detections.items():
            qualified_name = prefix + "_" + original_cond_name
            detection = copy.deepcopy(condition)
            detection.scope = prefix
            rule.detection.detections[qualified_name] = detection
            rule.detection.detection_scopes[qualified_name] = prefix
            detection_map[original_cond_name] = qualified_name

        # Rewrite the filter condition string so that every identifier/pattern token is
        # prefixed.  This handles:
        #   - exact names:        "selection"    -> "PREFIX_selection"
        #   - suffix wildcards:   "selection_*"  -> "PREFIX_selection_*"
        #   - prefix wildcards:   "*_allow"      -> "PREFIX_*_allow"
        #   - the "them" keyword: "1 of them"    -> "1 of PREFIX_*"
        #   - leading "_"/digits: "_filter"      -> "PREFIX__filter"
        # Sigma keywords (not, and, or, all, any, of, 1) are left unchanged.
        #
        # Each token is a maximal run of the characters allowed in Sigma identifiers and
        # identifier patterns (see _CONDITION_TOKEN). Wildcards are only valid at the start or
        # end of a Sigma identifier pattern but the regex accepts any occurrence; the Sigma
        # condition parser is responsible for rejecting syntactically invalid patterns at parse
        # time.
        def _replace_token(m: re.Match[str]) -> str:
            token = m.group(0)
            if token in self._CONDITION_KEYWORDS:
                return token
            if token == "them":
                # "them" means all detections; replace with a pattern that matches all
                # filter identifiers carrying the current prefix.
                return prefix + "_*"
            return prefix + "_" + token

        rewritten_condition = self._CONDITION_TOKEN.sub(_replace_token, filter_condition)

        for i, condition_str in enumerate(rule.detection.condition):
            rule.detection.condition[i] = f"({condition_str}) and " + f"({rewritten_condition})"

        # Reparse the rule to update the parsed conditions
        rule.detection.__post_init__()

        contains_negation, excludes = self._condition_negation()
        rule.applied_filters.append(
            SigmaFilterApplication(
                filter=self,
                rule=rule,
                reference=reference if isinstance(reference, str) else reference.reference,
                namespace=prefix,
                source_condition=filter_condition,
                condition=rewritten_condition,
                detections=detection_map,
                negated=contains_negation,
                excludes=excludes,
            )
        )

        return rule

    @classmethod
    def from_yaml(
        cls: type[Self],
        rule: str,
        collect_errors: bool = False,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        """Convert YAML input string with single document into SigmaFilter object."""
        return super().from_yaml(rule, collect_errors, policy=policy)
