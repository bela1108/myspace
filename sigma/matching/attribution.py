from __future__ import annotations

# Offline change attribution for pre-conversion notification review.

import copy
import itertools
import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence, cast
from uuid import UUID

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaAttributionError
from sigma.matching.event import Event, EventLogSource
from sigma.matching.matcher import SigmaMatcher
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule.attributes import SigmaLevel, SigmaStatus
from sigma.rule.base import SigmaRuleBase


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class ChangeKind(_StringEnum):
    """Kinds of rule changes understood by the offline attributor."""

    ARCHIVED = "archived"
    ARCHIVE = "archived"
    CONVERSION_UNSUPPORTED = "conversion_unsupported"
    CONVERSION_GAP = "conversion_unsupported"
    COVERAGE_GAP = "conversion_unsupported"
    UNSUPPORTED = "conversion_unsupported"
    LEVEL_CHANGED = "level_changed"
    LEVEL = "level_changed"
    LEVEL_CHANGE = "level_changed"
    STATUS_CHANGED = "status_changed"
    STATUS_CHANGE = "status_changed"


class QueueKind(_StringEnum):
    """Delivery semantics of a notification queue."""

    NOTIFICATION = "notification"
    PHONE = "notification"
    PAGER = "notification"
    TICKET = "ticket"
    BACKEND = "ticket"
    WORK_ITEM = "ticket"


class ReplayStatus(_StringEnum):
    """Per-event result of comparing baseline and candidate notification."""

    UNCHANGED = "unchanged"
    ADDED = "added"
    PARTIAL_LOSS = "partial_loss"
    NOTIFICATION_LOST = "notification_lost"
    TICKET_LOST = "ticket_lost"
    ALERT_LOST = "alert_lost"
    NO_BASELINE = "no_baseline"


class LossScope(_StringEnum):
    """Whether a loss removes one queue or the complete alert."""

    QUEUE = "queue"
    ALERT = "alert"


_CHANGE_KIND_ALIASES = {
    "archive": ChangeKind.ARCHIVED,
    "archived": ChangeKind.ARCHIVED,
    "decommissioned": ChangeKind.ARCHIVED,
    "remove": ChangeKind.ARCHIVED,
    "removed": ChangeKind.ARCHIVED,
    "retire": ChangeKind.ARCHIVED,
    "retired": ChangeKind.ARCHIVED,
    "withdraw": ChangeKind.ARCHIVED,
    "withdrawn": ChangeKind.ARCHIVED,
    "conversion_failed": ChangeKind.CONVERSION_UNSUPPORTED,
    "conversion_coverage_gap": ChangeKind.CONVERSION_UNSUPPORTED,
    "conversion_gap": ChangeKind.CONVERSION_UNSUPPORTED,
    "coverage_gap": ChangeKind.CONVERSION_UNSUPPORTED,
    "not_supported": ChangeKind.CONVERSION_UNSUPPORTED,
    "uncovered": ChangeKind.CONVERSION_UNSUPPORTED,
    "unsupported": ChangeKind.CONVERSION_UNSUPPORTED,
    "conversion_uncovered": ChangeKind.CONVERSION_UNSUPPORTED,
    "conversion_unsupported": ChangeKind.CONVERSION_UNSUPPORTED,
    "not_converted": ChangeKind.CONVERSION_UNSUPPORTED,
    "unconvertible": ChangeKind.CONVERSION_UNSUPPORTED,
    "downgrade": ChangeKind.LEVEL_CHANGED,
    "downgraded": ChangeKind.LEVEL_CHANGED,
    "level": ChangeKind.LEVEL_CHANGED,
    "level_change": ChangeKind.LEVEL_CHANGED,
    "level_changed": ChangeKind.LEVEL_CHANGED,
    "notification_level": ChangeKind.LEVEL_CHANGED,
    "notification_level_change": ChangeKind.LEVEL_CHANGED,
    "notification_level_changed": ChangeKind.LEVEL_CHANGED,
    "severity_change": ChangeKind.LEVEL_CHANGED,
    "severity_changed": ChangeKind.LEVEL_CHANGED,
    "status": ChangeKind.STATUS_CHANGED,
    "status_change": ChangeKind.STATUS_CHANGED,
    "status_changed": ChangeKind.STATUS_CHANGED,
}

_QUEUE_KIND_ALIASES = {
    "alert": QueueKind.NOTIFICATION,
    "notification": QueueKind.NOTIFICATION,
    "pager": QueueKind.NOTIFICATION,
    "phone": QueueKind.NOTIFICATION,
    "sms": QueueKind.NOTIFICATION,
    "backend": QueueKind.TICKET,
    "case": QueueKind.TICKET,
    "itsm": QueueKind.TICKET,
    "ticket": QueueKind.TICKET,
    "work_item": QueueKind.TICKET,
}


def _normalized_token(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _change_kind(value: ChangeKind | str) -> ChangeKind:
    if isinstance(value, ChangeKind):
        return value
    try:
        return ChangeKind(_normalized_token(value))
    except ValueError:
        try:
            return _CHANGE_KIND_ALIASES[_normalized_token(value)]
        except KeyError:
            raise SigmaAttributionError(f"Unknown rule change kind {value!r}")


def _queue_kind(value: QueueKind | str) -> QueueKind:
    if isinstance(value, QueueKind):
        return value
    token = _normalized_token(value)
    try:
        return QueueKind(token)
    except ValueError:
        try:
            return _QUEUE_KIND_ALIASES[token]
        except KeyError:
            raise SigmaAttributionError(f"Unknown queue kind {value!r}")


def _sigma_level(value: SigmaLevel | str | None) -> SigmaLevel | None:
    if value is None or isinstance(value, SigmaLevel):
        return value
    try:
        return SigmaLevel[_normalized_token(value).upper()]
    except KeyError:
        raise SigmaAttributionError(f"Unknown Sigma level {value!r}")


def _sigma_status(value: SigmaStatus | str | None) -> SigmaStatus | None:
    if value is None or isinstance(value, SigmaStatus):
        return value
    try:
        return SigmaStatus[_normalized_token(value).upper()]
    except KeyError:
        raise SigmaAttributionError(f"Unknown Sigma status {value!r}")


def _infer_queue_kind(queue: str) -> QueueKind:
    token = _normalized_token(queue)
    if token in {"backend", "case", "itsm", "ticket", "work_item"}:
        return QueueKind.TICKET
    return QueueKind.NOTIFICATION


def _is_level_token(value: Any) -> bool:
    try:
        _sigma_level(str(value))
        return True
    except SigmaAttributionError:
        return False


def _level_set(
    values: Iterable[SigmaLevel | str] | SigmaLevel | str | None,
) -> frozenset[SigmaLevel] | None:
    if values is None:
        return None
    items: Iterable[SigmaLevel | str]
    if isinstance(values, (SigmaLevel, str)):
        items = [values]
    else:
        items = values
    return frozenset(level for value in items if (level := _sigma_level(value)) is not None)


def _status_set(
    values: Iterable[SigmaStatus | str] | SigmaStatus | str | None,
) -> frozenset[SigmaStatus] | None:
    if values is None:
        return None
    items: Iterable[SigmaStatus | str]
    if isinstance(values, (SigmaStatus, str)):
        items = [values]
    else:
        items = values
    return frozenset(status for value in items if (status := _sigma_status(value)) is not None)


def _str_set(values: Iterable[str] | str | None) -> frozenset[str] | None:
    if values is None:
        return None
    items: Iterable[str]
    if isinstance(values, str):
        items = [values]
    else:
        items = values
    return frozenset(str(value) for value in items)


def _uuid_set(values: Iterable[UUID | str] | UUID | str | None) -> frozenset[UUID] | None:
    if values is None:
        return None
    if isinstance(values, (UUID, str)):
        values = [values]
    result: set[UUID] = set()
    for value in values:
        try:
            result.add(value if isinstance(value, UUID) else UUID(str(value)))
        except ValueError:
            raise SigmaAttributionError(f"Invalid rule UUID {value!r}")
    return frozenset(result)


def _rule_label(rule: SigmaRuleBase) -> str:
    for attribute in ("name", "title"):
        value = getattr(rule, attribute, None)
        if value:
            return str(value)
    rule_id = getattr(rule, "id", None)
    if rule_id is not None:
        return str(rule_id)
    return type(rule).__name__


def _rule_level(rule: SigmaRuleBase) -> SigmaLevel | None:
    level = getattr(rule, "level", None)
    return level if isinstance(level, SigmaLevel) else None


def _rule_status(rule: SigmaRuleBase) -> SigmaStatus | None:
    status = getattr(rule, "status", None)
    return status if isinstance(status, SigmaStatus) else None


def _rule_tags(rule: SigmaRuleBase) -> frozenset[str]:
    return frozenset(str(tag) for tag in (getattr(rule, "tags", None) or ()))


@dataclass(frozen=True)
class RoutingDecision:
    """Maintainer-provided decision that routes matching alerts to one queue.

    Decisions are additive: every decision whose constraints match a rule contributes
    its queue. A decision without constraints matches every rule.
    """

    queue: str | None = None
    name: str | None = None
    min_level: SigmaLevel | str | None = None
    max_level: SigmaLevel | str | None = None
    levels: Iterable[SigmaLevel | str] | SigmaLevel | str | None = None
    level: SigmaLevel | str | None = None
    statuses: Iterable[SigmaStatus | str] | SigmaStatus | str | None = None
    rule_names: Iterable[str] | str | None = None
    rule_ids: Iterable[UUID | str] | UUID | str | None = None
    tags: Iterable[str] | str | None = None
    kind: QueueKind | str | None = None
    channel: QueueKind | str | None = None
    queue_kind: QueueKind | str | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        queue = self.queue if self.queue is not None else self.name
        if not queue:
            raise SigmaAttributionError("Routing decision queue must not be empty")
        object.__setattr__(self, "queue", str(queue))
        object.__setattr__(self, "min_level", _sigma_level(self.min_level))
        object.__setattr__(self, "max_level", _sigma_level(self.max_level))
        levels = _level_set(self.levels)
        if levels is None and self.level is not None:
            levels = _level_set(self.level)
        object.__setattr__(self, "levels", levels)
        object.__setattr__(self, "level", _sigma_level(self.level))
        object.__setattr__(self, "statuses", _status_set(self.statuses))
        object.__setattr__(self, "rule_names", _str_set(self.rule_names))
        object.__setattr__(self, "rule_ids", _uuid_set(self.rule_ids))
        object.__setattr__(self, "tags", _str_set(self.tags))
        object.__setattr__(self, "channel", _queue_kind(self.channel) if self.channel else None)
        object.__setattr__(
            self,
            "queue_kind",
            _queue_kind(self.queue_kind) if self.queue_kind is not None else None,
        )
        if self.channel is not None:
            kind = _queue_kind(self.channel)
        elif self.queue_kind is not None:
            kind = _queue_kind(self.queue_kind)
        elif self.kind is None:
            kind = _infer_queue_kind(queue)
        else:
            kind = _queue_kind(self.kind)
        object.__setattr__(self, "kind", kind)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RoutingDecision:
        return cls(**dict(value))

    @property
    def is_ticket(self) -> bool:
        return self.kind == QueueKind.TICKET

    @property
    def is_notification(self) -> bool:
        return self.kind == QueueKind.NOTIFICATION

    @classmethod
    def for_levels(
        cls,
        queue: str,
        levels: Iterable[SigmaLevel | str] | SigmaLevel | str,
        *,
        kind: QueueKind | str | None = None,
    ) -> RoutingDecision:
        return cls(queue=queue, levels=levels, kind=kind)

    @classmethod
    def ticket(cls, queue: str = "ticket", **kwargs: Any) -> RoutingDecision:
        return cls(queue=queue, kind=QueueKind.TICKET, **kwargs)

    def matches(self, rule: SigmaRuleBase) -> bool:
        if not self.enabled:
            return False
        level = _rule_level(rule)
        status = _rule_status(rule)
        rule_id = getattr(rule, "id", None)
        rule_name = getattr(rule, "name", None)
        tags = _rule_tags(rule)
        min_level = cast(SigmaLevel | None, self.min_level)
        max_level = cast(SigmaLevel | None, self.max_level)
        allowed_levels = cast(frozenset[SigmaLevel] | None, self.levels)
        allowed_statuses = cast(frozenset[SigmaStatus] | None, self.statuses)
        allowed_names = cast(frozenset[str] | None, self.rule_names)
        allowed_ids = cast(frozenset[UUID] | None, self.rule_ids)
        allowed_tags = cast(frozenset[str] | None, self.tags)

        if allowed_levels is not None and level not in allowed_levels:
            return False
        if min_level is not None and (level is None or level < min_level):
            return False
        if max_level is not None and (level is None or level > max_level):
            return False
        if allowed_statuses is not None and status not in allowed_statuses:
            return False
        if allowed_names is not None and rule_name not in allowed_names:
            return False
        if allowed_ids is not None and (rule_id is None or rule_id not in allowed_ids):
            return False
        if allowed_tags is not None and not (tags & allowed_tags):
            return False
        return True


@dataclass
class RoutingPolicy:
    """Ordered collection of routing decisions."""

    decisions: Sequence[RoutingDecision | Mapping[str, Any] | str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if isinstance(self.decisions, Mapping):
            self.decisions = self._from_mapping(self.decisions)
        elif isinstance(self.decisions, (RoutingDecision, str)):
            self.decisions = [_coerce_routing_decision(self.decisions)]
        else:
            self.decisions = [_coerce_routing_decision(decision) for decision in self.decisions]

    @classmethod
    def _from_mapping(cls, mapping: Mapping[str, Any]) -> list[RoutingDecision]:
        if mapping and all(_is_level_token(key) for key in mapping):
            decisions: list[RoutingDecision] = []
            for level, queues in mapping.items():
                if isinstance(queues, str):
                    specifications: Iterable[Any] = [queues]
                elif isinstance(queues, Mapping):
                    values = dict(queues)
                    nested = values.pop("queues", None)
                    if nested is None:
                        nested = values.pop("queue", None)
                    if nested is None:
                        specifications = [values]
                    elif isinstance(nested, str):
                        specifications = [nested]
                    else:
                        specifications = nested
                elif isinstance(queues, Iterable):
                    specifications = queues
                else:
                    specifications = [queues]
                for specification in specifications:
                    if isinstance(specification, str):
                        decisions.append(
                            RoutingDecision(
                                queue=specification,
                                levels=[level],
                                kind=_infer_queue_kind(specification),
                            )
                        )
                    elif isinstance(specification, Mapping):
                        values = dict(specification)
                        values.setdefault("levels", [level])
                        if "queue" in values:
                            values.setdefault("kind", _infer_queue_kind(str(values["queue"])))
                            decisions.append(RoutingDecision(**values))
                    elif isinstance(specification, RoutingDecision):
                        normalized_level = _sigma_level(level)
                        if (
                            specification.levels is None
                            and specification.level is None
                            and normalized_level is not None
                        ):
                            specification = replace(
                                specification, levels=frozenset({normalized_level})
                            )
                        decisions.append(specification)
            return decisions

        decisions = []
        for queue, specification in mapping.items():
            if isinstance(specification, RoutingDecision):
                decisions.append(replace(specification, queue=str(queue)))
            elif isinstance(specification, Mapping):
                values = dict(specification)
                values.setdefault("queue", queue)
                values.setdefault("kind", _infer_queue_kind(str(queue)))
                decisions.append(RoutingDecision(**values))
            else:
                decisions.append(
                    RoutingDecision(
                        queue=str(queue),
                        levels=specification,
                        kind=_infer_queue_kind(str(queue)),
                    )
                )
        return decisions

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> RoutingPolicy:
        """Build a policy from a queue-to-levels or level-to-queues mapping."""
        return cls(mapping)

    @classmethod
    def coerce(
        cls,
        value: (
            RoutingPolicy
            | Iterable[RoutingDecision | Mapping[str, Any] | str]
            | Mapping[str, Any]
            | None
        ),
    ) -> RoutingPolicy:
        if value is None:
            return cls(())
        if isinstance(value, RoutingPolicy):
            return value
        return cls(value)  # type: ignore[arg-type]

    @property
    def queue_kinds(self) -> dict[str, QueueKind]:
        return {
            cast(str, decision.queue): cast(QueueKind, decision.kind)
            for decision in self.decisions
            if isinstance(decision, RoutingDecision)
        }

    def route(self, rule: SigmaRuleBase) -> dict[str, RoutingDecision]:
        result: dict[str, RoutingDecision] = {}
        for decision in self.decisions:
            if isinstance(decision, RoutingDecision) and decision.matches(rule):
                result[cast(str, decision.queue)] = decision
        return result

    def queues_for(self, rule: SigmaRuleBase) -> frozenset[str]:
        return frozenset(self.route(rule))


def _coerce_routing_decision(
    decision: RoutingDecision | Mapping[str, Any] | str | tuple[str, Any],
) -> RoutingDecision:
    if isinstance(decision, RoutingDecision):
        return decision
    if isinstance(decision, Mapping):
        return RoutingDecision(**dict(decision))
    if isinstance(decision, tuple) and len(decision) == 2:
        queue, levels = decision
        return RoutingDecision(
            queue=str(queue),
            levels=levels,
            kind=_infer_queue_kind(str(queue)),
        )
    return RoutingDecision(queue=str(decision), kind=_infer_queue_kind(str(decision)))


def _rule_identity(rule: SigmaRuleBase) -> tuple[str | None, str | None, str | None]:
    rule_id = getattr(rule, "id", None)
    return (
        str(rule_id) if rule_id is not None else None,
        cast(str | None, getattr(rule, "name", None)),
        cast(str | None, getattr(rule, "title", None)),
    )


@dataclass(frozen=True)
class RuleChange:
    """A single explicit modification applied to a baseline rule collection.

    A change can target a rule by object, name, or UUID. Archive and conversion
    coverage changes remove the rule from the reviewed candidate; level and status
    changes keep the rule but alter how it is routed.
    """

    kind: ChangeKind | str
    rule: str | UUID | SigmaRuleBase | None = None
    new_level: SigmaLevel | str | None = None
    label: str | None = None
    rule_name: str | None = None
    rule_title: str | None = None
    rule_id: UUID | str | None = None
    level: SigmaLevel | str | None = None
    new_status: SigmaStatus | str | None = None
    status: SigmaStatus | str | None = None

    def __post_init__(self) -> None:
        kind = _change_kind(self.kind)
        object.__setattr__(self, "kind", kind)
        if (
            self.rule is None
            and self.rule_name is None
            and self.rule_title is None
            and self.rule_id is None
        ):
            raise SigmaAttributionError(
                "Rule change must specify a rule, rule_name, rule_title, or rule_id"
            )

        new_level = self.new_level if self.new_level is not None else self.level
        new_status = self.new_status if self.new_status is not None else self.status
        if kind == ChangeKind.LEVEL_CHANGED:
            if new_level is None:
                raise SigmaAttributionError("Level change requires new_level or level")
            object.__setattr__(self, "new_level", _sigma_level(new_level))
        if kind == ChangeKind.STATUS_CHANGED:
            if new_status is None:
                raise SigmaAttributionError("Status change requires new_status or status")
            object.__setattr__(self, "new_status", _sigma_status(new_status))
        if self.rule_id is not None:
            _uuid_set(self.rule_id)

    @classmethod
    def archived(cls, rule: Any = None, label: str | None = None, **kwargs: Any) -> RuleChange:
        return cls(ChangeKind.ARCHIVED, rule=rule, label=label, **kwargs)

    @classmethod
    def conversion_unsupported(
        cls, rule: Any = None, label: str | None = None, **kwargs: Any
    ) -> RuleChange:
        return cls(ChangeKind.CONVERSION_UNSUPPORTED, rule=rule, label=label, **kwargs)

    @classmethod
    def level_changed(
        cls,
        rule: Any = None,
        new_level: SigmaLevel | str | None = None,
        label: str | None = None,
        **kwargs: Any,
    ) -> RuleChange:
        return cls(
            ChangeKind.LEVEL_CHANGED,
            rule=rule,
            new_level=new_level,
            label=label,
            **kwargs,
        )

    @classmethod
    def status_changed(
        cls,
        rule: Any = None,
        new_status: SigmaStatus | str | None = None,
        label: str | None = None,
        **kwargs: Any,
    ) -> RuleChange:
        return cls(
            ChangeKind.STATUS_CHANGED,
            rule=rule,
            new_status=new_status,
            label=label,
            **kwargs,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RuleChange:
        specification = dict(value)
        kind = (
            specification.pop("kind", None)
            or specification.pop("type", None)
            or specification.pop("change", None)
        )
        if kind is None:
            raise SigmaAttributionError("Rule change mapping requires a kind or type")
        if "title" in specification and "rule_title" not in specification:
            specification["rule_title"] = specification.pop("title")
        return cls(kind=kind, **specification)

    @property
    def selector(self) -> str:
        if self.rule is not None:
            if isinstance(self.rule, SigmaRuleBase):
                return _rule_label(self.rule)
            return str(self.rule)
        if self.rule_id is not None:
            return str(self.rule_id)
        if self.rule_title is not None:
            return self.rule_title
        return str(self.rule_name)

    @property
    def change_id(self) -> str:
        return self.label or f"{ChangeKind(self.kind).value}:{self.selector}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.change_id,
            "kind": ChangeKind(self.kind).value,
            "rule": self.selector,
            "new_level": (
                str(self.new_level) if isinstance(self.new_level, SigmaLevel) else self.new_level
            ),
            "new_status": (
                str(self.new_status)
                if isinstance(self.new_status, SigmaStatus)
                else self.new_status
            ),
            "label": self.label,
        }

    def matches_rule(self, rule: SigmaRuleBase) -> bool:
        if self.rule is not None:
            if isinstance(self.rule, SigmaRuleBase):
                return _rule_identity(rule) == _rule_identity(self.rule)
            selector = str(self.rule)
            if selector in (str(getattr(rule, "id", "")), str(getattr(rule, "name", ""))):
                return True
            return selector == str(getattr(rule, "title", ""))
        if self.rule_id is not None:
            return str(getattr(rule, "id", "")) == str(self.rule_id)
        if self.rule_name is not None:
            return self.rule_name in (
                str(getattr(rule, "name", "")),
                str(getattr(rule, "title", "")),
            )
        if self.rule_title is not None:
            return self.rule_title == str(getattr(rule, "title", ""))
        return False


@dataclass(frozen=True)
class MatchSummary:
    """Compact description of one rule match and the queues it routes to."""

    rule: str
    level: SigmaLevel | None
    status: SigmaStatus | None
    queues: frozenset[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "level": str(self.level) if self.level is not None else None,
            "status": str(self.status) if self.status is not None else None,
            "queues": sorted(self.queues),
        }


@dataclass
class EventReplay:
    """Baseline-versus-candidate notification result for one event."""

    index: int
    event: Event
    baseline_matches: tuple[MatchSummary, ...]
    candidate_matches: tuple[MatchSummary, ...]
    baseline_queues: frozenset[str]
    candidate_queues: frozenset[str]
    baseline_queue_sources: dict[str, tuple[str, ...]]
    candidate_queue_sources: dict[str, tuple[str, ...]]
    queue_kinds: dict[str, QueueKind] = field(default_factory=dict)

    @property
    def notified_queues(self) -> frozenset[str]:
        """Queues that would actually be notified in the candidate."""
        return self.candidate_queues

    @property
    def lost_queues(self) -> frozenset[str]:
        return self.baseline_queues - self.candidate_queues

    @property
    def added_queues(self) -> frozenset[str]:
        return self.candidate_queues - self.baseline_queues

    @property
    def retained_queues(self) -> frozenset[str]:
        return self.baseline_queues & self.candidate_queues

    @property
    def lost_notification_queues(self) -> frozenset[str]:
        return frozenset(
            queue for queue in self.lost_queues if self.queue_kind(queue) == QueueKind.NOTIFICATION
        )

    @property
    def lost_ticket_queues(self) -> frozenset[str]:
        return frozenset(
            queue for queue in self.lost_queues if self.queue_kind(queue) == QueueKind.TICKET
        )

    @property
    def alert_lost(self) -> bool:
        """True only when every pre-existing queue for the alert disappeared."""
        return bool(self.baseline_queues) and not self.candidate_queues

    @property
    def status(self) -> ReplayStatus:
        if not self.baseline_queues:
            return ReplayStatus.ADDED if self.candidate_queues else ReplayStatus.NO_BASELINE
        if not self.candidate_queues:
            return ReplayStatus.ALERT_LOST
        if self.lost_queues:
            if self.lost_notification_queues and not self.lost_ticket_queues:
                return ReplayStatus.NOTIFICATION_LOST
            if self.lost_ticket_queues and not self.lost_notification_queues:
                return ReplayStatus.TICKET_LOST
            return ReplayStatus.PARTIAL_LOSS
        if self.added_queues:
            return ReplayStatus.ADDED
        return ReplayStatus.UNCHANGED

    def queue_kind(self, queue: str) -> QueueKind:
        return self.queue_kinds.get(queue, QueueKind.NOTIFICATION)

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_index": self.index,
            "timestamp": self.event.timestamp.isoformat(),
            "logsource": {
                "category": self.event.logsource.category,
                "product": self.event.logsource.product,
                "service": self.event.logsource.service,
            },
            "data": self.event.data,
            "raw": self.event.raw,
            "status": self.status.value,
            "alert_lost": self.alert_lost,
            "baseline_matches": [match.as_dict() for match in self.baseline_matches],
            "candidate_matches": [match.as_dict() for match in self.candidate_matches],
            "baseline_queues": sorted(self.baseline_queues),
            "candidate_queues": sorted(self.candidate_queues),
            "notified_queues": sorted(self.candidate_queues),
            "lost_queues": sorted(self.lost_queues),
            "added_queues": sorted(self.added_queues),
            "retained_queues": sorted(self.retained_queues),
            "queue_kinds": {queue: kind.value for queue, kind in self.queue_kinds.items()},
            "baseline_queue_sources": {
                queue: list(sources) for queue, sources in self.baseline_queue_sources.items()
            },
            "candidate_queue_sources": {
                queue: list(sources) for queue, sources in self.candidate_queue_sources.items()
            },
        }


@dataclass
class ReplayComparison:
    """A replay of one or more events against a baseline and a candidate."""

    events: tuple[Event, ...]
    results: tuple[EventReplay, ...]
    changes: tuple[str, ...] = ()

    @property
    def alert_losses(self) -> tuple[EventReplay, ...]:
        return tuple(result for result in self.results if result.alert_lost)

    @property
    def notification_losses(self) -> tuple[EventReplay, ...]:
        return tuple(
            result for result in self.results if result.status == ReplayStatus.NOTIFICATION_LOST
        )

    @property
    def partial_losses(self) -> tuple[EventReplay, ...]:
        return tuple(
            result for result in self.results if result.lost_queues and not result.alert_lost
        )

    def lost_queues(self) -> dict[str, tuple[int, ...]]:
        lost: dict[str, list[int]] = defaultdict(list)
        for result in self.results:
            for queue in result.lost_queues:
                lost[queue].append(result.index)
        return {queue: tuple(indexes) for queue, indexes in lost.items()}

    @property
    def queues_lost(self) -> dict[str, tuple[int, ...]]:
        """Queue-name-to-event-indexes view of :meth:`lost_queues`."""
        return self.lost_queues()

    def as_dict(self) -> dict[str, Any]:
        return {
            "changes": list(self.changes),
            "events": [result.as_dict() for result in self.results],
            "lost_queues": {queue: list(indexes) for queue, indexes in self.lost_queues().items()},
            "alert_loss_count": len(self.alert_losses),
        }

    def rows(self) -> list[dict[str, Any]]:
        return [result.as_dict() for result in self.results]

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()

    def to_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("default", str)
        return json.dumps(self.as_dict(), **kwargs)


@dataclass(frozen=True)
class LossAttribution:
    """A queue loss observed with all changes applied, including minimal causes."""

    event_index: int
    event_timestamp: datetime
    queue: str
    queue_kind: QueueKind
    baseline_queues: frozenset[str]
    candidate_queues: frozenset[str]
    minimal_causes: tuple[tuple[str, ...], ...]

    @property
    def alert_lost(self) -> bool:
        return bool(self.baseline_queues) and not self.candidate_queues

    @property
    def scope(self) -> LossScope:
        return LossScope.ALERT if self.alert_lost else LossScope.QUEUE

    @property
    def minimal_combinations(self) -> tuple[tuple[str, ...], ...]:
        """Alias of :attr:`minimal_causes` for report terminology."""
        return self.minimal_causes

    @property
    def single_causes(self) -> tuple[tuple[str, ...], ...]:
        return tuple(cause for cause in self.minimal_causes if len(cause) == 1)

    @property
    def requires_combination(self) -> bool:
        return bool(self.minimal_causes) and all(len(cause) > 1 for cause in self.minimal_causes)

    @property
    def unexplained(self) -> bool:
        return not self.minimal_causes

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "timestamp": self.event_timestamp.isoformat(),
            "queue": self.queue,
            "queue_kind": self.queue_kind.value,
            "scope": self.scope.value,
            "alert_lost": self.alert_lost,
            "baseline_queues": sorted(self.baseline_queues),
            "candidate_queues": sorted(self.candidate_queues),
            "minimal_causes": [list(cause) for cause in self.minimal_causes],
            "requires_combination": self.requires_combination,
            "unexplained": self.unexplained,
        }


@dataclass(frozen=True)
class MinimalCombination:
    """Smallest set of changes that reproduces one loss."""

    event_index: int
    queue: str | None
    queue_kind: QueueKind | None
    change_ids: tuple[str, ...]
    baseline_queues: frozenset[str]
    candidate_queues: frozenset[str]

    @property
    def changes(self) -> tuple[str, ...]:
        """Alias of :attr:`change_ids`."""
        return self.change_ids

    @property
    def size(self) -> int:
        return len(self.change_ids)

    @property
    def requires_combination(self) -> bool:
        return self.size > 1

    @property
    def alert_lost(self) -> bool:
        return self.queue is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "queue": self.queue,
            "queue_kind": self.queue_kind.value if self.queue_kind is not None else None,
            "change_ids": list(self.change_ids),
            "size": self.size,
            "requires_combination": self.requires_combination,
            "alert_lost": self.alert_lost,
            "baseline_queues": sorted(self.baseline_queues),
            "candidate_queues": sorted(self.candidate_queues),
        }


@dataclass
class AttributionReport:
    """Result of an offline change-attribution review."""

    baseline: ReplayComparison
    candidate: ReplayComparison
    single_changes: dict[str, ReplayComparison]
    losses: tuple[LossAttribution, ...]
    minimal_combinations: tuple[MinimalCombination, ...]
    combination_replays: dict[tuple[str, ...], ReplayComparison] = field(default_factory=dict)
    max_combination_size: int = 2
    change_details: tuple[dict[str, Any], ...] = ()

    @property
    def alert_losses(self) -> tuple[EventReplay, ...]:
        """Events whose complete alert disappeared, one entry per event."""
        return self.candidate.alert_losses

    @property
    def alert_loss_events(self) -> tuple[EventReplay, ...]:
        """Alias of :attr:`alert_losses`."""
        return self.alert_losses

    @property
    def queue_alert_losses(self) -> tuple[LossAttribution, ...]:
        """Per-queue loss entries belonging to a complete alert loss."""
        return tuple(loss for loss in self.losses if loss.alert_lost)

    @property
    def queue_losses(self) -> tuple[LossAttribution, ...]:
        """Queue-level losses, including queues lost from otherwise live alerts."""
        return self.losses

    @property
    def partial_losses(self) -> tuple[LossAttribution, ...]:
        return tuple(loss for loss in self.losses if not loss.alert_lost)

    @property
    def combination_losses(self) -> tuple[LossAttribution, ...]:
        return tuple(loss for loss in self.losses if loss.requires_combination)

    @property
    def unexplained_losses(self) -> tuple[LossAttribution, ...]:
        return tuple(loss for loss in self.losses if loss.unexplained)

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_combination_size": self.max_combination_size,
            "change_ids": list(self.candidate.changes),
            "changes": list(self.change_details),
            "baseline": self.baseline.as_dict(),
            "candidate": self.candidate.as_dict(),
            "single_changes": {
                change: replay.as_dict() for change, replay in self.single_changes.items()
            },
            "losses": [loss.as_dict() for loss in self.losses],
            "minimal_combinations": [
                combination.as_dict() for combination in self.minimal_combinations
            ],
            "combination_replays": {
                "|".join(change_ids): replay.as_dict()
                for change_ids, replay in self.combination_replays.items()
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()

    def to_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("default", str)
        return json.dumps(self.as_dict(), **kwargs)

    def summary(self) -> str:
        lines = [
            f"Offline change attribution: {len(self.candidate.changes)} change(s), "
            f"{len(self.candidate.results)} event(s)"
        ]
        if not self.losses:
            lines.append("  no queue losses")
        for loss in self.losses:
            if loss.unexplained:
                cause = "cause not found within combination limit"
            else:
                cause = "; ".join(" + ".join(cause) for cause in loss.minimal_causes)
            retained = sorted(loss.candidate_queues)
            scope = "alert lost" if loss.alert_lost else f"retained: {', '.join(retained)}"
            lines.append(
                f"  event[{loss.event_index}] {loss.queue}: LOST "
                f"({loss.queue_kind.value}, {scope}); cause: {cause}"
            )
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.summary()


@dataclass
class _EventState:
    matches: tuple[MatchSummary, ...]
    queues: frozenset[str]
    sources: dict[str, tuple[str, ...]]


@dataclass
class _ReplaySide:
    states: tuple[_EventState, ...]
    queue_kinds: dict[str, QueueKind]


def _snapshot_rules(
    collection: SigmaCollection | Iterable[SigmaRuleBase],
) -> list[SigmaRuleBase]:
    if isinstance(collection, SigmaCollection):
        rules: Iterable[SigmaRuleBase] = collection.rules
    else:
        rules = collection
    return cast(list[SigmaRuleBase], copy.deepcopy(list(rules)))


def _is_event_like(value: Any) -> bool:
    return isinstance(value, Event) or (
        isinstance(value, Mapping)
        and "timestamp" in value
        and ("logsource" in value or "data" in value)
    )


def _coerce_event(value: Event | Mapping[str, Any]) -> Event:
    if isinstance(value, Event):
        return value
    if not isinstance(value, Mapping):
        raise SigmaAttributionError(f"Unsupported event value {value!r}")
    timestamp = value.get("timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            raise SigmaAttributionError(f"Invalid event timestamp {timestamp!r}")
    if not isinstance(timestamp, datetime):
        raise SigmaAttributionError("Event mapping requires a datetime timestamp")
    logsource_value = value.get("logsource", {}) or {}
    if isinstance(logsource_value, EventLogSource):
        logsource = logsource_value
    elif isinstance(logsource_value, Mapping):
        logsource = EventLogSource(
            category=logsource_value.get("category"),
            product=logsource_value.get("product"),
            service=logsource_value.get("service"),
        )
    else:
        raise SigmaAttributionError("Event logsource must be a mapping")
    data = value.get("data", {}) or {}
    if not isinstance(data, Mapping):
        raise SigmaAttributionError("Event data must be a mapping")
    raw = value.get("raw")
    return Event(
        timestamp=timestamp,
        logsource=logsource,
        data=dict(data),
        raw=raw if isinstance(raw, str) else None,
    )


def _coerce_events(events: Iterable[Event | Mapping[str, Any]]) -> tuple[Event, ...]:
    return tuple(_coerce_event(event) for event in events)


def _run_rules(
    events: Sequence[Event],
    rules: Sequence[SigmaRuleBase],
    routing: RoutingPolicy,
    pipeline: ProcessingPipeline | None = None,
) -> _ReplaySide:
    collection = SigmaCollection(list(rules), resolve_references=False)  # type: ignore[arg-type]
    states: list[_EventState] = []
    queue_kinds = routing.queue_kinds
    with SigmaMatcher(collection, pipeline=pipeline) as matcher:
        for event in events:
            matches = matcher.match(event)
            summaries: list[MatchSummary] = []
            sources: dict[str, set[str]] = defaultdict(set)
            queues: set[str] = set()
            for match in matches:
                rule = match.rule
                routed = routing.route(rule)
                rule_queues = frozenset(routed)
                label = _rule_label(rule)
                summaries.append(
                    MatchSummary(
                        rule=label,
                        level=_rule_level(rule),
                        status=_rule_status(rule),
                        queues=rule_queues,
                    )
                )
                for queue, decision in routed.items():
                    queues.add(queue)
                    sources[queue].add(label)
                    queue_kinds.setdefault(queue, cast(QueueKind, decision.kind))
            states.append(
                _EventState(
                    matches=tuple(summaries),
                    queues=frozenset(queues),
                    sources={
                        queue: tuple(sorted(queue_sources))
                        for queue, queue_sources in sources.items()
                    },
                )
            )
    return _ReplaySide(states=tuple(states), queue_kinds=queue_kinds)


def _build_comparison(
    events: Sequence[Event],
    baseline: _ReplaySide,
    candidate: _ReplaySide,
    changes: Sequence[str] = (),
) -> ReplayComparison:
    results: list[EventReplay] = []
    queue_kinds = dict(baseline.queue_kinds)
    queue_kinds.update(candidate.queue_kinds)
    for index, (event, baseline_state, candidate_state) in enumerate(
        zip(events, baseline.states, candidate.states)
    ):
        results.append(
            EventReplay(
                index=index,
                event=event,
                baseline_matches=baseline_state.matches,
                candidate_matches=candidate_state.matches,
                baseline_queues=baseline_state.queues,
                candidate_queues=candidate_state.queues,
                baseline_queue_sources=baseline_state.sources,
                candidate_queue_sources=candidate_state.sources,
                queue_kinds=queue_kinds,
            )
        )
    return ReplayComparison(
        events=tuple(events),
        results=tuple(results),
        changes=tuple(changes),
    )


def _unique_change_ids(changes: Sequence[RuleChange]) -> tuple[str, ...]:
    seen: dict[str, int] = defaultdict(int)
    result: list[str] = []
    for change in changes:
        base = change.change_id
        seen[base] += 1
        result.append(base if seen[base] == 1 else f"{base}#{seen[base]}")
    return tuple(result)


def _coerce_change(change: RuleChange | Mapping[str, Any]) -> RuleChange:
    if isinstance(change, RuleChange):
        return change
    if isinstance(change, Mapping):
        return RuleChange.from_mapping(change)
    raise SigmaAttributionError(f"Unsupported rule change {change!r}")


class ChangeAttributor:
    """Offline attribution of rule changes to notification-queue losses.

    The attributor applies explicit changes to a baseline collection, replays a small
    event set through the matching engine, and compares which queues would actually
    be notified. It evaluates single changes and minimal combinations, so a loss that
    needs two changes together is reported as that pair rather than as either change.
    """

    def __init__(
        self,
        collection: SigmaCollection | Iterable[SigmaRuleBase],
        changes: Iterable[RuleChange | Mapping[str, Any]] = (),
        routing: (
            RoutingPolicy
            | Iterable[RoutingDecision | Mapping[str, Any] | str]
            | Mapping[str, Any]
            | None
        ) = None,
        pipeline: ProcessingPipeline | None = None,
        max_combination_size: int | None = 2,
        max_combination_replays: int = 20000,
    ) -> None:
        if isinstance(collection, SigmaCollection):
            self.collection = collection
        else:
            self.collection = SigmaCollection(  # type: ignore[arg-type]
                list(collection), resolve_references=False
            )
        self.changes = tuple(_coerce_change(change) for change in changes)
        self.change_ids = _unique_change_ids(self.changes)
        self.routing = RoutingPolicy.coerce(routing)
        self.pipeline = pipeline
        if max_combination_size is not None and max_combination_size < 0:
            raise SigmaAttributionError("max_combination_size must be non-negative or None")
        self.max_combination_size = max_combination_size
        self.max_combination_replays = max_combination_replays

    def _rules_for(self, change_indexes: Iterable[int]) -> list[SigmaRuleBase]:
        rules = _snapshot_rules(self.collection)
        remove_ids: set[int] = set()
        selected = [self.changes[index] for index in change_indexes]

        for change in selected:
            matched = [rule for rule in rules if change.matches_rule(rule)]
            if not matched:
                raise SigmaAttributionError(f"Change {change.change_id!r} does not match any rule")
            for rule in matched:
                if change.kind in (
                    ChangeKind.ARCHIVED,
                    ChangeKind.CONVERSION_UNSUPPORTED,
                ):
                    remove_ids.add(id(rule))
                elif change.kind == ChangeKind.LEVEL_CHANGED:
                    rule.level = cast(SigmaLevel | None, change.new_level)
                elif change.kind == ChangeKind.STATUS_CHANGED:
                    rule.status = cast(SigmaStatus | None, change.new_status)
        return [rule for rule in rules if id(rule) not in remove_ids]

    def _run_side(
        self,
        events: Sequence[Event],
        change_indexes: Iterable[int],
    ) -> _ReplaySide:
        return _run_rules(
            events,
            self._rules_for(change_indexes),
            self.routing,
            self.pipeline,
        )

    def replay(
        self,
        events: Iterable[Event | Mapping[str, Any]],
        changes: Iterable[int | str | RuleChange | Mapping[str, Any]] | None = None,
    ) -> ReplayComparison:
        """Replay events with an explicit subset of changes."""
        event_list = _coerce_events(events)
        baseline = self._run_side(event_list, ())
        if changes is None:
            candidate = baseline
            change_indexes: tuple[int, ...] = ()
        else:
            change_indexes = self._resolve_change_indexes(changes)
            candidate = self._run_side(event_list, change_indexes)
        labels = tuple(self.change_ids[index] for index in change_indexes)
        return _build_comparison(event_list, baseline, candidate, labels)

    def _resolve_change_indexes(
        self,
        changes: Iterable[int | str | RuleChange | Mapping[str, Any]],
    ) -> tuple[int, ...]:
        indexes: list[int] = []
        for change in changes:
            if isinstance(change, Mapping):
                change = _coerce_change(change)
            if isinstance(change, int):
                index = change
            elif isinstance(change, RuleChange):
                try:
                    index = self.changes.index(change)
                except ValueError:
                    raise SigmaAttributionError(f"Unknown rule change {change.change_id!r}")
            else:
                try:
                    index = self.change_ids.index(str(change))
                except ValueError:
                    raise SigmaAttributionError(f"Unknown rule change {change!r}")
            if index < 0 or index >= len(self.changes):
                raise SigmaAttributionError(f"Rule change index {index} out of range")
            if index not in indexes:
                indexes.append(index)
        return tuple(indexes)

    def attribute(self, events: Iterable[Event | Mapping[str, Any]]) -> AttributionReport:
        """Alias of :meth:`analyze` for attribution terminology."""
        return self.analyze(events)

    def analyze(self, events: Iterable[Event | Mapping[str, Any]]) -> AttributionReport:
        """Compare baseline and candidate alerts, then attribute each loss."""
        event_list = _coerce_events(events)
        baseline = self._run_side(event_list, ())
        baseline_comparison = _build_comparison(event_list, baseline, baseline)

        all_indexes = tuple(range(len(self.changes)))
        candidate = self._run_side(event_list, all_indexes)
        candidate_changes = tuple(self.change_ids)
        candidate_comparison = _build_comparison(event_list, baseline, candidate, candidate_changes)

        max_size = len(self.changes)
        if self.max_combination_size is not None:
            max_size = min(max_size, self.max_combination_size)

        subset_count = sum(math.comb(len(all_indexes), size) for size in range(1, max_size + 1))
        if subset_count > self.max_combination_replays:
            raise SigmaAttributionError(
                f"Combination analysis would evaluate {subset_count} replays, "
                f"more than max_combination_replays={self.max_combination_replays}"
            )

        combination_replays: dict[tuple[str, ...], ReplayComparison] = {}
        single_changes: dict[str, ReplayComparison] = {}
        queue_causes: dict[tuple[int, str], list[tuple[str, ...]]] = defaultdict(list)
        alert_causes: dict[int, list[tuple[str, ...]]] = defaultdict(list)

        for size in range(1, max_size + 1):
            for indexes in itertools.combinations(all_indexes, size):
                labels = tuple(self.change_ids[index] for index in indexes)
                replay = _build_comparison(
                    event_list,
                    baseline,
                    self._run_side(event_list, indexes),
                    labels,
                )
                combination_replays[labels] = replay
                if len(labels) == 1:
                    single_changes[labels[0]] = replay
                for result in replay.results:
                    for queue in result.lost_queues:
                        key = (result.index, queue)
                        if not any(set(existing) < set(labels) for existing in queue_causes[key]):
                            queue_causes[key].append(labels)
                    if result.alert_lost and not any(
                        set(existing) < set(labels) for existing in alert_causes[result.index]
                    ):
                        alert_causes[result.index].append(labels)

        losses: list[LossAttribution] = []
        minimal: list[MinimalCombination] = []
        for result in candidate_comparison.results:
            for queue in sorted(result.lost_queues):
                causes = tuple(queue_causes.get((result.index, queue), ()))
                loss = LossAttribution(
                    event_index=result.index,
                    event_timestamp=result.event.timestamp,
                    queue=queue,
                    queue_kind=result.queue_kind(queue),
                    baseline_queues=result.baseline_queues,
                    candidate_queues=result.candidate_queues,
                    minimal_causes=causes,
                )
                losses.append(loss)

            if result.alert_lost:
                for cause in alert_causes.get(result.index, ()):
                    minimal.append(
                        MinimalCombination(
                            event_index=result.index,
                            queue=None,
                            queue_kind=None,
                            change_ids=cause,
                            baseline_queues=result.baseline_queues,
                            candidate_queues=result.candidate_queues,
                        )
                    )
            else:
                for queue in sorted(result.lost_queues):
                    for cause in queue_causes.get((result.index, queue), ()):
                        minimal.append(
                            MinimalCombination(
                                event_index=result.index,
                                queue=queue,
                                queue_kind=result.queue_kind(queue),
                                change_ids=cause,
                                baseline_queues=result.baseline_queues,
                                candidate_queues=result.candidate_queues,
                            )
                        )

        return AttributionReport(
            baseline=baseline_comparison,
            candidate=candidate_comparison,
            single_changes=single_changes,
            losses=tuple(losses),
            minimal_combinations=tuple(minimal),
            combination_replays=combination_replays,
            max_combination_size=max_size,
            change_details=tuple(change.as_dict() for change in self.changes),
        )


def attribute_changes(
    collection: SigmaCollection | Iterable[SigmaRuleBase],
    events: (
        Iterable[Event | Mapping[str, Any]] | Iterable[RuleChange | Mapping[str, Any]] | None
    ) = None,
    changes: Iterable[RuleChange | Mapping[str, Any]] | Iterable[Event] | None = None,
    routing: (
        RoutingPolicy
        | Iterable[RoutingDecision | Mapping[str, Any] | str]
        | Mapping[str, Any]
        | None
    ) = None,
    *,
    pipeline: ProcessingPipeline | None = None,
    max_combination_size: int | None = 2,
    max_combination_replays: int = 20000,
) -> AttributionReport:
    """Run an offline change-attribution review.

    ``events`` and ``changes`` may be supplied in either positional order: the event
    iterable is recognized by its ``Event`` elements, so both ``(events, changes)``
    and ``(changes, events)`` are accepted. Keyword use is unambiguous.
    """
    event_items = tuple(events) if events is not None else ()
    change_items = tuple(changes) if changes is not None else ()

    def is_event_sequence(items: tuple[Any, ...]) -> bool:
        return all(_is_event_like(item) for item in items)

    if event_items and is_event_sequence(event_items):
        event_sequence: tuple[Event, ...] = event_items  # type: ignore[assignment]
        change_sequence = change_items
    elif change_items and is_event_sequence(change_items):
        event_sequence = change_items  # type: ignore[assignment]
        change_sequence = event_items
    elif event_items and not change_items and not is_event_sequence(event_items):
        event_sequence = ()
        change_sequence = event_items
    else:
        event_sequence = event_items  # type: ignore[assignment]
        change_sequence = change_items
    return ChangeAttributor(
        collection,
        change_sequence,  # type: ignore[arg-type]
        routing,
        pipeline=pipeline,
        max_combination_size=max_combination_size,
        max_combination_replays=max_combination_replays,
    ).analyze(event_sequence)


def analyze_changes(
    collection: SigmaCollection | Iterable[SigmaRuleBase],
    events: Iterable[Event | Mapping[str, Any]],
    changes: Iterable[RuleChange | Mapping[str, Any]],
    routing: (
        RoutingPolicy
        | Iterable[RoutingDecision | Mapping[str, Any] | str]
        | Mapping[str, Any]
        | None
    ) = None,
    *,
    pipeline: ProcessingPipeline | None = None,
    max_combination_size: int | None = 2,
    max_combination_replays: int = 20000,
) -> AttributionReport:
    """Explicit-order wrapper around :func:`attribute_changes`."""
    return attribute_changes(
        collection,
        events,
        changes,
        routing,
        pipeline=pipeline,
        max_combination_size=max_combination_size,
        max_combination_replays=max_combination_replays,
    )


def compare_replay(
    baseline: SigmaCollection | Iterable[SigmaRuleBase],
    candidate: SigmaCollection | Iterable[SigmaRuleBase],
    events: Iterable[Event | Mapping[str, Any]],
    routing: (
        RoutingPolicy
        | Iterable[RoutingDecision | Mapping[str, Any] | str]
        | Mapping[str, Any]
        | None
    ) = None,
    *,
    pipeline: ProcessingPipeline | None = None,
    changes: Iterable[str] = (),
) -> ReplayComparison:
    """Replay events against two explicit collections and compare their queues."""
    event_list = _coerce_events(events)
    routing_policy = RoutingPolicy.coerce(routing)
    baseline_side = _run_rules(
        event_list,
        _snapshot_rules(baseline),
        routing_policy,
        pipeline,
    )
    candidate_side = _run_rules(
        event_list,
        _snapshot_rules(candidate),
        routing_policy,
        pipeline,
    )
    return _build_comparison(event_list, baseline_side, candidate_side, tuple(changes))


def replay_comparison(
    baseline: SigmaCollection | Iterable[SigmaRuleBase],
    candidate: SigmaCollection | Iterable[SigmaRuleBase],
    events: Iterable[Event | Mapping[str, Any]],
    routing: (
        RoutingPolicy
        | Iterable[RoutingDecision | Mapping[str, Any] | str]
        | Mapping[str, Any]
        | None
    ) = None,
    *,
    pipeline: ProcessingPipeline | None = None,
    changes: Iterable[str] = (),
) -> ReplayComparison:
    """Alias of :func:`compare_replay` for replay-review terminology."""
    return compare_replay(
        baseline,
        candidate,
        events,
        routing,
        pipeline=pipeline,
        changes=changes,
    )


def replay_changes(
    collection: SigmaCollection | Iterable[SigmaRuleBase],
    events: Iterable[Event | Mapping[str, Any]],
    changes: Iterable[RuleChange | Mapping[str, Any]],
    routing: (
        RoutingPolicy
        | Iterable[RoutingDecision | Mapping[str, Any] | str]
        | Mapping[str, Any]
        | None
    ) = None,
    *,
    pipeline: ProcessingPipeline | None = None,
) -> ReplayComparison:
    """Replay one collection with all supplied changes applied."""
    attributor = ChangeAttributor(collection, changes, routing, pipeline=pipeline)
    return attributor.replay(events, range(len(attributor.changes)))


def notified_queues(
    collection: SigmaCollection | Iterable[SigmaRuleBase],
    events: Iterable[Event | Mapping[str, Any]],
    routing: (
        RoutingPolicy
        | Iterable[RoutingDecision | Mapping[str, Any] | str]
        | Mapping[str, Any]
        | None
    ) = None,
    *,
    pipeline: ProcessingPipeline | None = None,
) -> tuple[frozenset[str], ...]:
    """Return the queues actually notified for each event, in event order."""
    event_list = _coerce_events(events)
    side = _run_rules(
        event_list,
        _snapshot_rules(collection),
        RoutingPolicy.coerce(routing),
        pipeline,
    )
    return tuple(state.queues for state in side.states)


ChangeType = ChangeKind
LossKind = ReplayStatus
RuleChangeKind = ChangeKind
ChangeSet = tuple[RuleChange, ...]
Route = RoutingDecision
NotificationRoute = RoutingDecision
NotificationQueue = RoutingDecision
Queue = RoutingDecision
RoutingTable = RoutingPolicy
NotificationRouter = RoutingPolicy
Attribution = ChangeAttributor
ChangeAttribution = ChangeAttributor
OfflineAttribution = ChangeAttributor
PreConversionReview = ChangeAttributor
ChangeAttributionReport = AttributionReport
ChangeReport = AttributionReport
EventReplayResult = EventReplay
QueueLoss = LossAttribution
QueueLossAttribution = LossAttribution


__all__ = [
    "Attribution",
    "AttributionReport",
    "ChangeAttribution",
    "ChangeAttributionReport",
    "ChangeAttributor",
    "ChangeKind",
    "ChangeReport",
    "ChangeSet",
    "ChangeType",
    "EventReplay",
    "EventReplayResult",
    "LossAttribution",
    "LossKind",
    "LossScope",
    "MatchSummary",
    "MinimalCombination",
    "NotificationQueue",
    "NotificationRoute",
    "NotificationRouter",
    "OfflineAttribution",
    "PreConversionReview",
    "Queue",
    "QueueKind",
    "QueueLoss",
    "QueueLossAttribution",
    "ReplayComparison",
    "ReplayStatus",
    "Route",
    "RoutingDecision",
    "RoutingPolicy",
    "RoutingTable",
    "RuleChange",
    "RuleChangeKind",
    "analyze_changes",
    "attribute_changes",
    "compare_replay",
    "notified_queues",
    "replay_changes",
    "replay_comparison",
]
