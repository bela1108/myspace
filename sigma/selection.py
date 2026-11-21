from __future__ import annotations

import math
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import UUID

import sigma.exceptions as sigma_exceptions
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionItem, SigmaCondition
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule, SigmaRuleTag, SigmaStatus
from sigma.rule.detection import EmptySigmaDetections
from sigma.rule.logsource import EmptyLogSource

RuleSelectionAlgorithm = Literal["exact", "exhaustive", "greedy"]

_EPSILON = 1e-9


def _as_strings(value: Any) -> Iterator[str]:
    """Normalize a scalar or iterable of tag-like values into strings."""
    if value is None:
        return
    if isinstance(value, (str, SigmaRuleTag, UUID)):
        yield str(value).strip()
        return
    try:
        items = iter(value)
    except TypeError:
        yield str(value).strip()
        return
    for item in items:
        yield str(item).strip()


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate values while retaining their input order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _as_str_set(value: Any) -> frozenset[str] | None:
    if value is None:
        return None
    return frozenset(item for item in _as_strings(value) if item)


def _one_line(value: Any) -> str:
    return " ".join(str(value).split())


def _validate_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise sigma_exceptions.SigmaSelectionError(f"{label} must be a number")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise sigma_exceptions.SigmaSelectionError(f"{label} must be a finite non-negative number")
    return number


@dataclass(frozen=True)
class RuleCandidate:
    """
    A rule candidate for selection.

    The ``rule`` attribute is optional so callers can use the selector with an already
    normalized catalog. If it is present, fields are extracted from the detections that are
    actually referenced by the rule condition and risks default to the rule's tags.

    ``risks`` contains already reviewed risk labels. Supplying it overrides the rule tags,
    which is useful when tags have been curated or normalized by another system. ``fields``
    likewise overrides field extraction.

    ``collection_conditions`` are collection capabilities required by this candidate, for
    example ``{"sysmon", "dns"}.`` The availability of these conditions is supplied to
    :func:`select_rules`. Related rules can be kept atomic either by giving them the same
    ``group`` label or by passing explicit groups to the selector.
    """

    rule: SigmaRule | None = None
    reference: str | None = None
    risks: frozenset[str] | None = None
    fields: frozenset[str] | None = None
    group: str | None = None
    collection_conditions: frozenset[str] = frozenset()
    missing_collection_conditions: frozenset[str] = frozenset()
    collection_available: bool = True
    invalid_reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.risks is not None:
            object.__setattr__(self, "risks", _as_str_set(self.risks) or frozenset())
        if self.fields is not None:
            object.__setattr__(self, "fields", _as_str_set(self.fields) or frozenset())
        object.__setattr__(
            self, "collection_conditions", _as_str_set(self.collection_conditions) or frozenset()
        )
        object.__setattr__(
            self,
            "missing_collection_conditions",
            _as_str_set(self.missing_collection_conditions) or frozenset(),
        )
        object.__setattr__(
            self,
            "invalid_reasons",
            tuple(
                reason
                for reason in (_one_line(r) for r in _as_strings(self.invalid_reasons))
                if reason
            ),
        )
        if self.group is not None:
            object.__setattr__(self, "group", str(self.group))
        if self.reference is not None:
            object.__setattr__(self, "reference", str(self.reference))

    @classmethod
    def from_rule(
        cls,
        rule: SigmaRule,
        *,
        reference: str | None = None,
        risks: Iterable[str] | None = None,
        fields: Iterable[str] | None = None,
        group: str | None = None,
        collection_conditions: Iterable[str] = (),
        missing_collection_conditions: Iterable[str] = (),
        collection_available: bool = True,
        invalid_reasons: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> "RuleCandidate":
        """Create a candidate from a parsed Sigma rule."""
        return cls(
            rule=rule,
            reference=reference,
            risks=_as_str_set(risks),
            fields=_as_str_set(fields),
            group=group,
            collection_conditions=_as_str_set(collection_conditions) or frozenset(),
            missing_collection_conditions=_as_str_set(missing_collection_conditions) or frozenset(),
            collection_available=collection_available,
            invalid_reasons=tuple(invalid_reasons),
            metadata=metadata or {},
        )


@dataclass(frozen=True)
class UncoveredRisk:
    """Reason why a required risk is not covered by the returned selection."""

    risk: str
    reason: str
    message: str
    candidate_keys: tuple[str, ...] = ()


@dataclass
class RuleSelection:
    """Result of a rule selection run."""

    selected: list[RuleCandidate]
    selected_keys: tuple[str, ...]
    required_risks: tuple[str, ...]
    covered_risks: frozenset[str]
    all_covered_risks: frozenset[str]
    uncovered_risks: dict[str, str]
    diagnostics: list[UncoveredRisk]
    total_cost: float
    budget: float
    used_fields: frozenset[str]
    field_costs_used: dict[str, float]
    excluded_candidates: dict[str, tuple[str, ...]]
    algorithm: str

    @property
    def selected_rules(self) -> list[SigmaRule]:
        """Selected Sigma rules, omitting catalog-only candidates."""
        rules: list[SigmaRule] = []
        for candidate in self.selected:
            if candidate.rule is not None:
                rules.append(candidate.rule)
        return rules

    @property
    def covered_required_risks(self) -> frozenset[str]:
        """Alias emphasizing that ``covered_risks`` only contains required risks."""
        return self.covered_risks

    @property
    def additional_risks(self) -> frozenset[str]:
        """Risks covered by selected rules but not requested as required."""
        return self.all_covered_risks - self.covered_risks

    @property
    def remaining_budget(self) -> float:
        return self.budget - self.total_cost

    @property
    def is_complete(self) -> bool:
        return not self.uncovered_risks

    @property
    def uncovered(self) -> list[UncoveredRisk]:
        return self.diagnostics

    @property
    def uncovered_reasons(self) -> dict[str, str]:
        return self.uncovered_risks

    @property
    def invalid_candidates(self) -> dict[str, tuple[str, ...]]:
        return self.excluded_candidates

    def reason_for(self, risk: str) -> str | None:
        """Return the human-readable reason for an uncovered risk, if any."""
        return self.uncovered_risks.get(risk)


@dataclass
class _ResolvedCandidate:
    key: str
    candidate: RuleCandidate
    risks: frozenset[str]
    fields: frozenset[str]
    invalid_reasons: tuple[str, ...]
    collection_missing: frozenset[str]
    order: int

    @property
    def deliverable(self) -> bool:
        return not self.invalid_reasons and not self.collection_missing


@dataclass
class _DeliveryUnit:
    keys: tuple[str, ...]
    candidates: tuple[_ResolvedCandidate, ...]
    risks: frozenset[str]
    fields: frozenset[str]
    cost: float
    blocked_reasons: tuple[str, ...]
    is_group: bool = False

    @property
    def deliverable(self) -> bool:
        return not self.blocked_reasons


def _candidate_from_mapping(item: Mapping[str, Any], index: int) -> RuleCandidate:
    data = dict(item)
    nested_rule = "rule" in data or "sigma_rule" in data
    raw_sigma_rule = not nested_rule and any(
        key in data for key in ("title", "detection", "logsource")
    )

    if nested_rule:
        rule_value = data.pop("rule", data.pop("sigma_rule", None))
        reference = data.pop("reference", data.pop("key", None))
        risks = data.pop("risks", data.pop("required_risks", None))
        fields = data.pop("fields", data.pop("required_fields", None))
        group = data.pop("group", data.pop("group_id", data.pop("delivery_group", None)))
        conditions = data.pop(
            "collection_conditions", data.pop("required_collection_conditions", ())
        )
        missing = data.pop("missing_collection_conditions", ())
        collection_available = data.pop("collection_available", True)
        invalid_reasons = list(
            _as_strings(data.pop("invalid_reasons", data.pop("invalid_reason", ())))
        )
        if data.pop("invalid", False) is True or data.pop("valid", True) is False:
            invalid_reasons.append("candidate is marked invalid")
        metadata = data
    elif raw_sigma_rule:
        reference = data.pop("reference", data.pop("key", None))
        risks = data.pop("risks", data.pop("required_risks", None))
        fields = data.pop("required_fields", None)
        group = data.pop("group", data.pop("group_id", data.pop("delivery_group", None)))
        conditions = data.pop(
            "collection_conditions", data.pop("required_collection_conditions", ())
        )
        missing = data.pop("missing_collection_conditions", ())
        collection_available = data.pop("collection_available", True)
        invalid_reasons = list(
            _as_strings(data.pop("invalid_reasons", data.pop("invalid_reason", ())))
        )
        if data.pop("invalid", False) is True or data.pop("valid", True) is False:
            invalid_reasons.append("candidate is marked invalid")
        rule_value = data
        if risks is None:
            risks = data.get("tags", ())
        metadata = {}
    else:
        rule_value = None
        reference = data.pop("reference", data.pop("key", data.pop("id", None)))
        risks = data.pop("risks", data.pop("required_risks", data.pop("tags", None)))
        fields = data.pop("fields", data.pop("required_fields", ()))
        group = data.pop("group", data.pop("group_id", data.pop("delivery_group", None)))
        conditions = data.pop(
            "collection_conditions", data.pop("required_collection_conditions", ())
        )
        missing = data.pop("missing_collection_conditions", ())
        collection_available = data.pop("collection_available", True)
        invalid_reasons = list(
            _as_strings(data.pop("invalid_reasons", data.pop("invalid_reason", ())))
        )
        if data.pop("invalid", False) is True or data.pop("valid", True) is False:
            invalid_reasons.append("candidate is marked invalid")
        metadata = data

    rule: SigmaRule | None
    if isinstance(rule_value, SigmaRule):
        rule = rule_value
    elif isinstance(rule_value, Mapping):
        try:
            rule = SigmaRule.from_dict(dict(rule_value), collect_errors=True)
        except (SigmaError, TypeError, ValueError) as error:
            rule = None
            invalid_reasons.append(f"could not parse rule: {_one_line(error)}")
    elif rule_value is None:
        rule = None
    else:
        rule = None
        invalid_reasons.append(
            f"unsupported rule object {type(rule_value).__name__} at position {index}"
        )

    return RuleCandidate(
        rule=rule,
        reference=str(reference) if reference is not None else None,
        risks=_as_str_set(risks),
        fields=_as_str_set(fields),
        group=str(group) if group is not None else None,
        collection_conditions=_as_str_set(conditions) or frozenset(),
        missing_collection_conditions=_as_str_set(missing) or frozenset(),
        collection_available=bool(collection_available),
        invalid_reasons=tuple(invalid_reasons),
        metadata=metadata,
    )


def _coerce_candidate(item: Any, index: int) -> RuleCandidate:
    if isinstance(item, RuleCandidate):
        return item
    if isinstance(item, SigmaRule):
        return RuleCandidate(rule=item)
    if isinstance(item, Mapping):
        return _candidate_from_mapping(item, index)
    raise sigma_exceptions.SigmaSelectionError(
        f"rule at position {index} must be a SigmaRule, RuleCandidate or mapping"
    )


def _normalize_excluded_statuses(
    statuses: Iterable[SigmaStatus | str],
) -> frozenset[SigmaStatus]:
    result: set[SigmaStatus] = set()
    for status in statuses:
        if isinstance(status, SigmaStatus):
            result.add(status)
        else:
            try:
                result.add(SigmaStatus[str(status).upper()])
            except KeyError:
                raise sigma_exceptions.SigmaSelectionError(
                    f"unknown excluded rule status '{status}'"
                )
    return frozenset(result)


def _validate_rule(
    rule: SigmaRule, excluded_statuses: frozenset[SigmaStatus]
) -> tuple[list[str], set[str]]:
    """Validate that a rule can actually detect something and collect referenced fields."""
    reasons: list[str] = []
    fields: set[str] = set()

    for error in rule.errors:
        reasons.append(f"parse error: {_one_line(error)}")

    if isinstance(rule.logsource, EmptyLogSource) or not any(
        (rule.logsource.category, rule.logsource.product, rule.logsource.service)
    ):
        reasons.append("rule has no usable log source")

    if rule.status is not None:
        status = rule.status
        if isinstance(status, str):
            try:
                status = SigmaStatus[status.upper()]
            except KeyError:
                reasons.append(f"unknown rule status '{status}'")
                status = None
        if status in excluded_statuses:
            reasons.append(f"rule status '{status}' is not deliverable")

    detection = rule.detection
    if isinstance(detection, EmptySigmaDetections) or not detection.detections:
        reasons.append("rule has no detection logic")
        return reasons, fields
    if not detection.condition:
        reasons.append("rule has no detection condition")
        return reasons, fields

    parsed_any = False
    for condition in detection.condition:
        if not isinstance(condition, str) or not condition.strip():
            reasons.append("rule contains an empty detection condition")
            continue
        try:
            parsed = SigmaCondition(condition, detection).parse()
        except SigmaError as error:
            reasons.append(f"invalid detection condition: {_one_line(error)}")
            continue
        if parsed is None:
            reasons.append(f"detection condition '{condition}' resolves to nothing")
            continue
        parsed_any = True
        fields.update(_condition_fields(parsed))

    if not parsed_any:
        reasons.append("rule has no usable detection condition")

    return list(dict.fromkeys(reasons)), fields


def _condition_fields(node: Any) -> set[str]:
    """Collect field names from a postprocessed condition tree."""
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return {node.field} if node.field else set()
    if isinstance(node, ConditionItem):
        fields: set[str] = set()
        for argument in node.args:
            if argument is not None:
                fields.update(_condition_fields(argument))
        return fields
    return set()


def _resolve_candidate(
    candidate: RuleCandidate,
    index: int,
    excluded_statuses: frozenset[SigmaStatus],
    field_costs: Mapping[str, float],
    unknown_field_cost: float | None,
    missing_collection_conditions: frozenset[str],
    available_collection_conditions: frozenset[str] | None,
    required_logsource_fields: frozenset[str],
) -> _ResolvedCandidate:
    invalid_reasons = list(candidate.invalid_reasons)
    collection_missing = set(candidate.missing_collection_conditions)

    if not candidate.collection_available:
        collection_missing.add("<collection unavailable>")

    if candidate.rule is not None:
        rule_reasons, rule_fields = _validate_rule(candidate.rule, excluded_statuses)
        invalid_reasons.extend(rule_reasons)
        fields = candidate.fields if candidate.fields is not None else frozenset(rule_fields)
        risks = (
            candidate.risks
            if candidate.risks is not None
            else frozenset(str(tag).strip() for tag in candidate.rule.tags)
        )
        for field_name in required_logsource_fields:
            logsource = candidate.rule.logsource
            value = getattr(logsource, field_name, None)
            if value is None and logsource.custom_attributes:
                value = logsource.custom_attributes.get(field_name)
            if value is None:
                collection_missing.add(f"logsource.{field_name}")
    else:
        fields = candidate.fields or frozenset()
        risks = candidate.risks or frozenset()

    collection_missing.update(candidate.collection_conditions & missing_collection_conditions)
    if available_collection_conditions is not None:
        collection_missing.update(candidate.collection_conditions - available_collection_conditions)

    if unknown_field_cost is None:
        unpriced_fields = fields - field_costs.keys()
        if unpriced_fields:
            invalid_reasons.append(
                "no field cost declared for: " + ", ".join(sorted(unpriced_fields))
            )

    key = (
        candidate.reference
        or (str(candidate.rule.id) if candidate.rule is not None and candidate.rule.id else None)
        or (candidate.rule.name if candidate.rule is not None and candidate.rule.name else None)
        or (candidate.rule.title if candidate.rule is not None and candidate.rule.title else None)
        or f"rule-{index + 1}"
    )

    return _ResolvedCandidate(
        key=key,
        candidate=candidate,
        risks=frozenset(risk for risk in risks if risk),
        fields=frozenset(field for field in fields if field),
        invalid_reasons=tuple(dict.fromkeys(invalid_reasons)),
        collection_missing=frozenset(collection_missing),
        order=index,
    )


def _field_cost(
    fields: Iterable[str],
    field_costs: Mapping[str, float],
    unknown_field_cost: float | None,
) -> float:
    if unknown_field_cost is None:
        missing = set(fields) - field_costs.keys()
        if missing:
            return math.inf
    return sum(
        field_costs.get(field_name, unknown_field_cost if unknown_field_cost is not None else 0.0)
        for field_name in fields
    )


def _prepare_candidates(
    rules: Iterable[Any],
    excluded_statuses: frozenset[SigmaStatus],
    field_costs: Mapping[str, float],
    unknown_field_cost: float | None,
    missing_collection_conditions: frozenset[str],
    available_collection_conditions: frozenset[str] | None,
    required_logsource_fields: frozenset[str],
) -> tuple[list[_ResolvedCandidate], dict[str, list[str]], dict[str, _ResolvedCandidate]]:
    candidates = [_coerce_candidate(item, index) for index, item in enumerate(rules)]
    resolved: list[_ResolvedCandidate] = []
    aliases: dict[str, list[str]] = {}
    used_keys: set[str] = set()

    for index, candidate in enumerate(candidates):
        item = _resolve_candidate(
            candidate,
            index,
            excluded_statuses,
            field_costs,
            unknown_field_cost,
            missing_collection_conditions,
            available_collection_conditions,
            required_logsource_fields,
        )
        base_key = item.key
        key = base_key
        suffix = 2
        while key in used_keys:
            key = f"{base_key}#{suffix}"
            suffix += 1
        item.key = key
        used_keys.add(key)
        resolved.append(item)

        for alias in (
            key,
            base_key,
            candidate.reference,
            str(candidate.rule.id) if candidate.rule is not None and candidate.rule.id else None,
            candidate.rule.name if candidate.rule is not None else None,
            candidate.rule.title if candidate.rule is not None else None,
        ):
            if alias:
                aliases.setdefault(str(alias), []).append(key)

    by_key = {item.key: item for item in resolved}
    return resolved, aliases, by_key


def _resolve_rule_reference(
    reference: str | UUID,
    aliases: Mapping[str, list[str]],
) -> str:
    text = str(reference)
    if text in aliases:
        keys = list(dict.fromkeys(aliases[text]))
        if len(keys) == 1:
            return keys[0]
        raise sigma_exceptions.SigmaSelectionError(
            f"rule reference '{text}' is ambiguous: {', '.join(keys)}"
        )
    raise sigma_exceptions.SigmaSelectionError(f"unknown rule reference '{text}' in group")


def _normalize_groups(
    groups: Iterable[Iterable[str | UUID]] | Mapping[Any, Iterable[str | UUID]] | None,
    aliases: Mapping[str, list[str]],
) -> list[tuple[str, ...]]:
    if groups is None:
        return []
    group_values: Iterable[Any]
    if isinstance(groups, Mapping):
        group_values = groups.values()
    else:
        group_values = groups

    normalized: list[tuple[str, ...]] = []
    for group in group_values:
        if isinstance(group, (str, UUID)):
            refs: Iterable[str | UUID] = [group]
        else:
            refs = group
        keys = tuple(_resolve_rule_reference(reference, aliases) for reference in refs)
        normalized.append(tuple(dict.fromkeys(keys)))
    return normalized


def _build_units(
    resolved: Sequence[_ResolvedCandidate],
    groups: Sequence[Sequence[str]],
    field_costs: Mapping[str, float],
    unknown_field_cost: float | None,
) -> list[_DeliveryUnit]:
    parent = {item.key: item.key for item in resolved}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    by_group: dict[str, list[str]] = {}
    for item in resolved:
        if item.candidate.group:
            by_group.setdefault(item.candidate.group, []).append(item.key)
    for keys in by_group.values():
        for key in keys[1:]:
            union(keys[0], key)
    for group in groups:
        if group:
            for key in group[1:]:
                union(group[0], key)

    components: dict[str, list[_ResolvedCandidate]] = {}
    for item in resolved:
        components.setdefault(find(item.key), []).append(item)

    units: list[_DeliveryUnit] = []
    for members in components.values():
        member_reasons: list[str] = []
        for member in members:
            if member.invalid_reasons:
                member_reasons.append(f"{member.key}: " + "; ".join(member.invalid_reasons))
            if member.collection_missing:
                member_reasons.append(
                    f"{member.key}: missing collection condition(s): "
                    + ", ".join(sorted(member.collection_missing))
                )
        keys = tuple(sorted(member.key for member in members))
        risks = frozenset(risk for member in members for risk in member.risks)
        fields = frozenset(field for member in members for field in member.fields)
        units.append(
            _DeliveryUnit(
                keys=keys,
                candidates=tuple(sorted(members, key=lambda member: member.order)),
                risks=risks,
                fields=fields,
                cost=_field_cost(fields, field_costs, unknown_field_cost),
                blocked_reasons=tuple(member_reasons),
                is_group=len(members) > 1,
            )
        )

    return sorted(units, key=lambda unit: unit.keys)


def _solution_better(
    coverage: int,
    cost: float,
    rule_count: int,
    keys: tuple[str, ...],
    best_coverage: int,
    best_cost: float,
    best_rule_count: int,
    best_keys: tuple[str, ...],
) -> bool:
    if coverage != best_coverage:
        return coverage > best_coverage
    if abs(cost - best_cost) > _EPSILON:
        return cost < best_cost
    if rule_count != best_rule_count:
        return rule_count < best_rule_count
    return keys < best_keys


def _select_exact(
    units: Sequence[_DeliveryUnit],
    required: frozenset[str],
    field_costs: Mapping[str, float],
    unknown_field_cost: float | None,
    budget: float,
) -> tuple[int, ...]:
    ordered_pairs = sorted(
        enumerate(units),
        key=lambda pair: (-len(pair[1].risks & required), pair[1].cost, pair[1].keys),
    )
    ordered = [unit for _, unit in ordered_pairs]
    original_indices = [index for index, _ in ordered_pairs]
    count = len(ordered)
    suffix_union: list[frozenset[str]] = [frozenset() for _ in range(count + 1)]
    for index in range(count - 1, -1, -1):
        suffix_union[index] = suffix_union[index + 1] | (ordered[index].risks & required)

    best_coverage = 0
    best_cost = 0.0
    best_rule_count = 0
    best_keys: tuple[str, ...] = ()
    best_selected: tuple[int, ...] = ()

    def update(covered: frozenset[str], cost: float, selected: tuple[int, ...]) -> None:
        nonlocal best_coverage, best_cost, best_rule_count, best_keys, best_selected
        rule_count = sum(len(ordered[index].keys) for index in selected)
        keys = tuple(sorted(key for index in selected for key in ordered[index].keys))
        if _solution_better(
            len(covered),
            cost,
            rule_count,
            keys,
            best_coverage,
            best_cost,
            best_rule_count,
            best_keys,
        ):
            best_coverage = len(covered)
            best_cost = cost
            best_rule_count = rule_count
            best_keys = keys
            best_selected = selected

    def search(
        position: int,
        fields: frozenset[str],
        covered: frozenset[str],
        cost: float,
        selected: tuple[int, ...],
    ) -> None:
        nonlocal best_coverage, best_cost
        if len(covered) == len(required):
            update(covered, cost, selected)
            return
        if position == count:
            update(covered, cost, selected)
            return

        upper_bound = len(covered | suffix_union[position])
        if upper_bound < best_coverage:
            return
        if upper_bound == best_coverage and cost > best_cost + _EPSILON:
            return

        unit = ordered[position]
        new_risks = (unit.risks & required) - covered
        if new_risks:
            new_fields = fields | unit.fields
            new_cost = _field_cost(new_fields, field_costs, unknown_field_cost)
            if new_cost <= budget + _EPSILON:
                search(
                    position + 1,
                    new_fields,
                    covered | new_risks,
                    new_cost,
                    selected + (position,),
                )

        search(position + 1, fields, covered, cost, selected)

    search(0, frozenset(), frozenset(), 0.0, ())
    return tuple(sorted(original_indices[index] for index in best_selected))


def _select_exhaustive(
    units: Sequence[_DeliveryUnit],
    required: frozenset[str],
    field_costs: Mapping[str, float],
    unknown_field_cost: float | None,
    budget: float,
    max_units: int,
) -> tuple[int, ...]:
    if len(units) > max_units:
        raise sigma_exceptions.SigmaSelectionError(
            f"exhaustive comparison is limited to {max_units} delivery units; got {len(units)}"
        )

    best_coverage = 0
    best_cost = 0.0
    best_rule_count = 0
    best_keys: tuple[str, ...] = ()
    best_selected: tuple[int, ...] = ()

    for mask in range(1 << len(units)):
        selected = tuple(index for index in range(len(units)) if mask & (1 << index))
        fields = frozenset(field for index in selected for field in units[index].fields)
        cost = _field_cost(fields, field_costs, unknown_field_cost)
        if cost > budget + _EPSILON:
            continue
        covered = frozenset(risk for index in selected for risk in (units[index].risks & required))
        rule_count = sum(len(units[index].keys) for index in selected)
        keys = tuple(sorted(key for index in selected for key in units[index].keys))
        if _solution_better(
            len(covered),
            cost,
            rule_count,
            keys,
            best_coverage,
            best_cost,
            best_rule_count,
            best_keys,
        ):
            best_coverage = len(covered)
            best_cost = cost
            best_rule_count = rule_count
            best_keys = keys
            best_selected = selected

    return best_selected


def _select_greedy(
    units: Sequence[_DeliveryUnit],
    required: frozenset[str],
    field_costs: Mapping[str, float],
    unknown_field_cost: float | None,
    budget: float,
) -> tuple[int, ...]:
    selected: list[int] = []
    selected_set: set[int] = set()
    fields: frozenset[str] = frozenset()
    covered: frozenset[str] = frozenset()
    cost = 0.0

    while True:
        best: tuple[tuple[float, int, float, tuple[str, ...], int], int] | None = None
        for index, unit in enumerate(units):
            if index in selected_set:
                continue
            new_risks = (unit.risks & required) - covered
            if not new_risks:
                continue
            new_fields = fields | unit.fields
            new_cost = _field_cost(new_fields, field_costs, unknown_field_cost)
            if new_cost > budget + _EPSILON:
                continue
            incremental = new_cost - cost
            score = len(new_risks) / incremental if incremental > _EPSILON else math.inf
            rank = (
                -score,
                -len(new_risks),
                new_cost,
                unit.keys,
                index,
            )
            if best is None or rank < best[0]:
                best = (rank, index)

        if best is None:
            break
        chosen = best[1]
        unit = units[chosen]
        selected.append(chosen)
        selected_set.add(chosen)
        fields |= unit.fields
        covered |= unit.risks & required
        cost = _field_cost(fields, field_costs, unknown_field_cost)

    return tuple(selected)


def _diagnose_uncovered(
    risk: str,
    resolved: Sequence[_ResolvedCandidate],
    units: Sequence[_DeliveryUnit],
    selected_fields: frozenset[str],
    selected_cost: float,
    budget: float,
    field_costs: Mapping[str, float],
    unknown_field_cost: float | None,
    group_reasons: Mapping[str, str],
) -> UncoveredRisk:
    declared = [item for item in resolved if risk in item.risks]
    candidate_keys = tuple(item.key for item in declared)

    if not declared:
        return UncoveredRisk(
            risk=risk,
            reason="no_candidate",
            message="no candidate rule declares this risk",
        )

    deliverable = [item for item in declared if item.deliverable]
    if not deliverable:
        invalid = [item for item in declared if item.invalid_reasons]
        collection = [
            item for item in declared if item.collection_missing and not item.invalid_reasons
        ]
        blocked = [item for item in declared if item.key in group_reasons]
        parts: list[str] = []
        if invalid:
            parts.append(
                "invalid rule(s): "
                + "; ".join(f"{item.key} ({'; '.join(item.invalid_reasons)})" for item in invalid)
            )
        if collection:
            parts.append(
                "missing collection condition(s): "
                + "; ".join(
                    f"{item.key} requires {', '.join(sorted(item.collection_missing))}"
                    for item in collection
                )
            )
        if blocked:
            parts.append(
                "related delivery group cannot be selected: "
                + "; ".join(f"{item.key}: {group_reasons[item.key]}" for item in blocked)
            )
        if invalid:
            reason = "invalid_candidate"
        elif collection:
            reason = "collection_conditions"
        else:
            reason = "related_group"
        return UncoveredRisk(
            risk=risk,
            reason=reason,
            message="; ".join(parts),
            candidate_keys=candidate_keys,
        )

    if deliverable and all(item.key in group_reasons for item in deliverable):
        return UncoveredRisk(
            risk=risk,
            reason="related_group",
            message="related delivery group cannot be selected: "
            + "; ".join(f"{item.key}: {group_reasons[item.key]}" for item in deliverable),
            candidate_keys=candidate_keys,
        )

    feasible_units = [unit for unit in units if unit.deliverable and risk in unit.risks]
    if feasible_units:
        cheapest = min(unit.cost for unit in feasible_units)
        if cheapest > budget + _EPSILON:
            message = f"cheapest delivery unit costs {cheapest:g}, above budget {budget:g}"
        else:
            incremental_costs = [
                _field_cost(selected_fields | unit.fields, field_costs, unknown_field_cost)
                - selected_cost
                for unit in feasible_units
            ]
            minimum_incremental = min(incremental_costs)
            message = (
                "budget is insufficient for a joint selection covering this risk; "
                f"adding a delivery unit costs at least {minimum_incremental:g} and "
                f"only {max(budget - selected_cost, 0.0):g} budget remains"
            )
    else:
        message = "no deliverable candidate can be selected within the budget"

    return UncoveredRisk(
        risk=risk,
        reason="budget",
        message=message,
        candidate_keys=candidate_keys,
    )


def select_rules(
    rules: Iterable[Any],
    required_risks: Iterable[str | SigmaRuleTag],
    field_costs: Mapping[str, float],
    budget: float,
    *,
    groups: Iterable[Iterable[str | UUID]] | Mapping[Any, Iterable[str | UUID]] | None = None,
    available_collection_conditions: Iterable[str] | None = None,
    missing_collection_conditions: Iterable[str] = (),
    required_logsource_fields: Iterable[str] = (),
    excluded_statuses: Iterable[SigmaStatus | str] = (
        SigmaStatus.DEPRECATED,
        SigmaStatus.UNSUPPORTED,
    ),
    unknown_field_cost: float | None = None,
    algorithm: RuleSelectionAlgorithm = "exact",
    max_exhaustive_units: int = 20,
) -> RuleSelection:
    """
    Select a set of Sigma rules that covers reviewed risk labels within a field budget.

    Parameters
    ----------
    rules:
        Parsed rules, :class:`RuleCandidate` objects, or mappings. A mapping can either be a
        normal Sigma rule or a candidate wrapper with a ``rule`` entry and selection metadata.
    required_risks:
        Already reviewed risk labels that must be observed. Coverage only comes from rules that
        have runnable detection logic.
    field_costs:
        Cost of onboarding each field. Costs are counted once for the union of fields required by
        the selected rules.
    budget:
        Maximum total field cost.
    groups:
        Groups of rule references that must be selected or rejected atomically. Members can be
        referenced by candidate key, id, name or title. A ``group`` on a candidate is equivalent
        to adding a group containing that candidate.
    available_collection_conditions:
        Collection capabilities that are available. If supplied, a candidate is only deliverable
        when all of its ``collection_conditions`` are present.
    missing_collection_conditions:
        Collection capabilities known to be missing. This is useful when there is no complete
        allowlist of available conditions.
    required_logsource_fields:
        Logsource attributes (``category``, ``product``, ``service`` or a custom attribute) that
        are required for a rule to be collectable.
    excluded_statuses:
        Rule statuses that must not be delivered. Deprecated and unsupported rules are excluded by
        default.
    unknown_field_cost:
        Cost used for fields without an explicit price. ``None`` (the default) rejects candidates
        with unpriced fields, because their budget compliance cannot be proven.
    algorithm:
        ``exact`` uses branch-and-bound, ``exhaustive`` enumerates all subsets for small inputs and
        is useful as a reference, and ``greedy`` ranks candidates by newly covered risks divided by
        incremental field cost.
    max_exhaustive_units:
        Safety limit for the exhaustive reference implementation.

    Returns
    -------
    RuleSelection
        The selected candidates, total shared-field cost, covered risks, and a reason for every
        required risk that could not be covered.
    """
    if algorithm not in ("exact", "exhaustive", "greedy"):
        raise sigma_exceptions.SigmaSelectionError(f"unknown selection algorithm '{algorithm}'")

    if hasattr(rules, "rules") and not isinstance(rules, Mapping):
        collection_rules = getattr(rules, "rules")
        if isinstance(collection_rules, Iterable):
            rules = collection_rules

    if isinstance(required_risks, (str, SigmaRuleTag)):
        risk_values: Iterable[str | SigmaRuleTag] = [required_risks]
    elif isinstance(required_risks, (set, frozenset)):
        risk_values = sorted(str(risk) for risk in required_risks)
    else:
        risk_values = required_risks
    required_order = _ordered_unique(_as_strings(risk_values))
    required = frozenset(required_order)

    normalized_costs = {
        str(field_name): _validate_number(cost, f"cost of field '{field_name}'")
        for field_name, cost in field_costs.items()
    }
    budget_value = _validate_number(budget, "budget")
    unknown_cost = (
        None
        if unknown_field_cost is None
        else _validate_number(unknown_field_cost, "unknown_field_cost")
    )
    excluded_status_values = _normalize_excluded_statuses(excluded_statuses)
    missing_conditions = _as_str_set(missing_collection_conditions) or frozenset()
    available_conditions = _as_str_set(available_collection_conditions)
    logsource_fields = _as_str_set(required_logsource_fields) or frozenset()

    resolved, aliases, by_key = _prepare_candidates(
        rules,
        excluded_status_values,
        normalized_costs,
        unknown_cost,
        missing_conditions,
        available_conditions,
        logsource_fields,
    )
    normalized_groups = _normalize_groups(groups, aliases)
    units = _build_units(resolved, normalized_groups, normalized_costs, unknown_cost)

    group_reasons: dict[str, str] = {}
    for unit in units:
        if unit.is_group and unit.blocked_reasons:
            reason = "related group cannot be delivered: " + "; ".join(unit.blocked_reasons)
            for key in unit.keys:
                group_reasons[key] = reason

    relevant_units = [unit for unit in units if unit.deliverable and unit.risks & required]
    if algorithm == "greedy":
        selected_indices = _select_greedy(
            relevant_units, required, normalized_costs, unknown_cost, budget_value
        )
    elif algorithm == "exhaustive":
        selected_indices = _select_exhaustive(
            relevant_units,
            required,
            normalized_costs,
            unknown_cost,
            budget_value,
            max_exhaustive_units,
        )
    else:
        selected_indices = _select_exact(
            relevant_units, required, normalized_costs, unknown_cost, budget_value
        )

    selected_units = [relevant_units[index] for index in selected_indices]
    selected_keys = {key for unit in selected_units for key in unit.keys}
    selected_candidates = sorted(
        (by_key[key] for key in selected_keys if key in by_key),
        key=lambda item: item.order,
    )
    used_fields = frozenset(field for unit in selected_units for field in unit.fields)
    all_covered = frozenset(risk for unit in selected_units for risk in unit.risks)
    covered_required = all_covered & required
    total_cost = _field_cost(used_fields, normalized_costs, unknown_cost)

    diagnostics = [
        _diagnose_uncovered(
            risk,
            resolved,
            relevant_units,
            used_fields,
            total_cost,
            budget_value,
            normalized_costs,
            unknown_cost,
            group_reasons,
        )
        for risk in required_order
        if risk not in covered_required
    ]
    uncovered_risks = {diagnostic.risk: diagnostic.message for diagnostic in diagnostics}

    excluded: dict[str, tuple[str, ...]] = {}
    for item in resolved:
        reasons = list(item.invalid_reasons)
        if item.collection_missing:
            reasons.append(
                "missing collection condition(s): " + ", ".join(sorted(item.collection_missing))
            )
        if item.key in group_reasons:
            reasons.append(group_reasons[item.key])
        if reasons:
            excluded[item.key] = tuple(dict.fromkeys(_one_line(reason) for reason in reasons))

    result_candidates = [item.candidate for item in selected_candidates]

    return RuleSelection(
        selected=result_candidates,
        selected_keys=tuple(item.key for item in selected_candidates),
        required_risks=required_order,
        covered_risks=covered_required,
        all_covered_risks=all_covered,
        uncovered_risks=uncovered_risks,
        diagnostics=diagnostics,
        total_cost=total_cost,
        budget=budget_value,
        used_fields=used_fields,
        field_costs_used={
            field: normalized_costs.get(field, unknown_cost if unknown_cost is not None else 0.0)
            for field in sorted(used_fields)
        },
        excluded_candidates=excluded,
        algorithm=algorithm,
    )


def select_rules_exact(
    rules: Iterable[Any],
    required_risks: Iterable[str | SigmaRuleTag],
    field_costs: Mapping[str, float],
    budget: float,
    **kwargs: Any,
) -> RuleSelection:
    """Optimal branch-and-bound selection. Alias for ``select_rules(..., algorithm="exact")``."""
    return select_rules(rules, required_risks, field_costs, budget, algorithm="exact", **kwargs)


def select_rules_exhaustive(
    rules: Iterable[Any],
    required_risks: Iterable[str | SigmaRuleTag],
    field_costs: Mapping[str, float],
    budget: float,
    **kwargs: Any,
) -> RuleSelection:
    """Enumerate all subsets. Intended for small inputs and reference comparisons."""
    return select_rules(
        rules, required_risks, field_costs, budget, algorithm="exhaustive", **kwargs
    )


def brute_force_select(
    rules: Iterable[Any],
    required_risks: Iterable[str | SigmaRuleTag],
    field_costs: Mapping[str, float],
    budget: float,
    **kwargs: Any,
) -> RuleSelection:
    """Alias for :func:`select_rules_exhaustive`."""
    return select_rules_exhaustive(rules, required_risks, field_costs, budget, **kwargs)


def select_rules_greedy(
    rules: Iterable[Any],
    required_risks: Iterable[str | SigmaRuleTag],
    field_costs: Mapping[str, float],
    budget: float,
    **kwargs: Any,
) -> RuleSelection:
    """Score-ranked selection by newly covered risks and incremental field cost."""
    return select_rules(rules, required_risks, field_costs, budget, algorithm="greedy", **kwargs)


def select_rules_by_score(
    rules: Iterable[Any],
    required_risks: Iterable[str | SigmaRuleTag],
    field_costs: Mapping[str, float],
    budget: float,
    **kwargs: Any,
) -> RuleSelection:
    """Alias for :func:`select_rules_greedy`."""
    return select_rules_greedy(rules, required_risks, field_costs, budget, **kwargs)


@dataclass(frozen=True)
class SigmaRuleSelector:
    """
    Reusable selector object for a fixed budget and field catalog.

    The function API is usually more convenient; this class is useful when a backend receives
    many rule batches with the same reviewed risks and costs.
    """

    required_risks: tuple[str, ...]
    field_costs: Mapping[str, float]
    budget: float
    groups: Iterable[Iterable[str | UUID]] | Mapping[Any, Iterable[str | UUID]] | None = None
    available_collection_conditions: frozenset[str] | None = None
    missing_collection_conditions: frozenset[str] = frozenset()
    required_logsource_fields: frozenset[str] = frozenset()
    excluded_statuses: tuple[SigmaStatus, ...] = (
        SigmaStatus.DEPRECATED,
        SigmaStatus.UNSUPPORTED,
    )
    unknown_field_cost: float | None = None
    algorithm: RuleSelectionAlgorithm = "exact"

    def select(self, rules: Iterable[Any]) -> RuleSelection:
        return select_rules(
            rules,
            self.required_risks,
            self.field_costs,
            self.budget,
            groups=self.groups,
            available_collection_conditions=self.available_collection_conditions,
            missing_collection_conditions=self.missing_collection_conditions,
            required_logsource_fields=self.required_logsource_fields,
            excluded_statuses=self.excluded_statuses,
            unknown_field_cost=self.unknown_field_cost,
            algorithm=self.algorithm,
        )


RuleSelector = SigmaRuleSelector
SelectionResult = RuleSelection
select_sigma_rules = select_rules

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
