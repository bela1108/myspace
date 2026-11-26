"""Post-match notification selection for offline pySigma matches.

The selector is intentionally downstream of :class:`sigma.matching.SigmaMatcher`.
It groups :class:`~sigma.matching.match.SigmaMatch` objects that refer to the same
event, validates rule-declared compression relationships, and returns an auditable
result instead of mutating or discarding matches.

Supported rule metadata (all keys are optional unless a strict policy is used)::

    name: credential_access_cover
    level: critical
    responsibility:
      item: ACCOUNTABILITY-CRED-01
      group: identity-defense
      owner: identity-oncall
    supersedes:
      - old_rule_name
    superseded_by:
      - new_rule_name
    covers:
      - old_rule_name
    covers_basis:
      - lsass_handle

Flat aliases such as ``responsible_group``, ``owner_group``, ``replaces`` and
``replaced_by`` are also accepted. Native Sigma ``related`` entries with type
``obsolete`` or ``renamed`` are treated as a ``superseded_by`` declaration.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Iterable, Literal
from uuid import UUID

from sigma.matching.event import Event
from sigma.matching.match import SigmaMatch
from sigma.rule.attributes import SigmaLevel
from sigma.rule.base import SigmaRuleBase

MutualClaimPolicy = Literal["retain_all", "severity_or_retain"]
GroupKeyFn = Callable[[SigmaMatch], str]


def _jsonable(value: Any) -> Any:
    """Convert common metadata values into JSON-compatible values."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):  # pragma: no cover - defensive, strings are normalised
        return value.name.lower()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def _pick(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value is not None and value != "":
            return value
    return None


def _as_text_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, (list, tuple, set, frozenset)):
        result: list[str] = []
        for item in value:
            text = str(item).strip()
            if text and text not in result:
                result.append(text)
        return tuple(result)
    text = str(value).strip()
    return (text,) if text else ()


def _rule_identity_keys(rule: SigmaRuleBase) -> set[str]:
    keys: set[str] = set()
    if getattr(rule, "id", None) is not None:
        keys.add(str(rule.id).strip().lower())
    if getattr(rule, "name", None):
        keys.add(str(rule.name).strip().lower())
    if getattr(rule, "title", None):
        keys.add(str(rule.title).strip().lower())
    return keys


def _ref_key(value: Any) -> str:
    """Normalize a rule reference to the form used for matching declarations."""
    if isinstance(value, SigmaRuleBase):
        keys = _rule_identity_keys(value)
        if keys:
            return next(iter(keys))
        return f"sigma-rule:{id(value)}"
    if isinstance(value, UUID):
        return str(value).lower()
    if isinstance(value, dict):
        for key in ("id", "rule_id", "uuid", "ref", "name", "rule"):
            if key in value:
                return _ref_key(value[key])
    text = str(value).strip().lower()
    if text.startswith("urn:uuid:"):
        text = text.removeprefix("urn:uuid:")
    return text


def _as_ref_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, dict):
        for key in ("rules", "rule_ids", "ids", "names", "refs"):
            if key in value:
                return _as_ref_tuple(value[key])
        return (_ref_key(value),)
    if isinstance(value, (list, tuple, set, frozenset)):
        result: list[str] = []
        for item in value:
            if item is None:
                continue
            key = _ref_key(item)
            if key and key not in result:
                result.append(key)
        return tuple(result)
    key = _ref_key(value)
    return (key,) if key else ()


def event_fingerprint(event: Event) -> str:
    """Return a stable SHA-256 fingerprint for an event's observable content."""
    payload = {
        "timestamp": event.timestamp.isoformat(),
        "logsource": asdict(event.logsource),
        "data": event.data,
        "raw": event.raw,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceRecord:
    """Deep-copied event evidence attached to a notification decision."""

    fingerprint: str
    timestamp: datetime
    logsource: dict[str, str | None]
    data: dict[str, Any]
    raw: str | None

    @classmethod
    def from_event(cls, event: Event) -> "EvidenceRecord":
        return cls(
            fingerprint=event_fingerprint(event),
            timestamp=event.timestamp,
            logsource=asdict(event.logsource),
            data=copy.deepcopy(event.data),
            raw=copy.deepcopy(event.raw),
        )

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class Responsibility:
    """Accountability declaration used to explain why a notification is owned."""

    group: str | None = None
    owner: str | None = None
    item: str | None = None
    source: str | None = None
    assumes_groups: tuple[str, ...] = ()
    cross_group_allowed: bool = False

    @property
    def accountable(self) -> bool:
        return bool(self.group or self.owner or self.item)

    @property
    def label(self) -> str:
        return self.group or self.item or self.owner or "undeclared responsibility"

    @property
    def responsible_group(self) -> str | None:
        return self.group

    @property
    def owner_group(self) -> str | None:
        return self.group

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class RuleClaims:
    supersedes: tuple[str, ...] = ()
    superseded_by: tuple[str, ...] = ()
    covers: tuple[str, ...] = ()
    covers_basis: tuple[str, ...] = ()
    basis: tuple[str, ...] = ()


def _extract_responsibility(rule: SigmaRuleBase) -> Responsibility:
    custom = getattr(rule, "custom_attributes", None) or {}
    group: str | None = None
    owner: str | None = None
    item: str | None = None
    source: str | None = None
    assumes: tuple[str, ...] = ()
    cross_group = False

    mappings: list[tuple[str, dict[str, Any]]] = [("custom_attributes", custom)]
    for nested_name in ("responsibility_policy", "notification", "alert"):
        nested = custom.get(nested_name)
        if isinstance(nested, dict):
            mappings.append((f"custom_attributes.{nested_name}", nested))

    for prefix, mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        for field_name in ("responsibility", "accountability", "ownership"):
            block = mapping.get(field_name)
            block_prefix = f"{prefix}.{field_name}"
            if isinstance(block, str) and block.strip():
                if group is None:
                    group = block.strip()
                    source = block_prefix
            elif isinstance(block, dict):
                group = group or _pick(
                    block, "group", "responsible_group", "response_group", "owner_group", "team"
                )
                owner = owner or _pick(block, "owner", "oncall", "assignee", "lead")
                item = item or _pick(
                    block, "item", "responsibility_item", "accountability_item", "ticket", "queue"
                )
                assumes = assumes or _as_text_tuple(
                    block.get("assumes_groups") or block.get("assumes")
                )
                cross_group = cross_group or bool(
                    block.get("cross_group")
                    or block.get("cross_group_allowed")
                    or block.get("assume_all_groups")
                )
                if source is None and (group or owner or item):
                    source = block_prefix

        if group is None:
            value = _pick(
                mapping,
                "responsible_group",
                "responsibility_group",
                "owner_group",
                "response_group",
                "service_owner_group",
                "team",
            )
            if value is not None:
                group = str(value)
                source = f"{prefix}.responsible_group"
        if owner is None:
            value = _pick(mapping, "owner", "oncall", "assignee", "responsible_owner")
            if value is not None:
                owner = str(value)
                source = source or f"{prefix}.owner"
        if item is None:
            value = _pick(
                mapping,
                "responsibility_item",
                "accountability_item",
                "owner_item",
                "responsibility_id",
            )
            if value is not None:
                item = str(value)
                source = source or f"{prefix}.responsibility_item"

    if source is None and (group or owner or item):
        source = "custom_attributes"
    return Responsibility(
        group=group,
        owner=owner,
        item=item,
        source=source,
        assumes_groups=tuple(a.lower() for a in assumes),
        cross_group_allowed=cross_group,
    )


def _extract_claims(rule: SigmaRuleBase) -> RuleClaims:
    custom = getattr(rule, "custom_attributes", None) or {}
    notification = custom.get("notification")
    mappings = [custom]
    if isinstance(notification, dict):
        mappings.append(notification)

    def refs(*keys: str) -> tuple[str, ...]:
        values: list[str] = []
        for mapping in mappings:
            for key in keys:
                if key in mapping:
                    for ref in _as_ref_tuple(mapping[key]):
                        if ref not in values:
                            values.append(ref)
        return tuple(values)

    supersedes = refs(
        "supersedes",
        "replaces",
        "succeeds",
        "successor_of",
        "compresses",
        "suppresses_rules",
    )
    superseded_by = refs(
        "superseded_by",
        "replaced_by",
        "successor",
        "successors",
        "predecessor_is_superseded_by",
    )
    covers = refs("covers", "covers_rules", "coverage", "deduplicates", "absorbs")
    covers_basis = tuple(
        basis.lower() for basis in refs("covers_basis", "coverage_basis", "covered_basis")
    )
    basis = tuple(basis.lower() for basis in refs("basis", "evidence_basis", "detection_basis"))

    related = getattr(rule, "related", None)
    related_items = getattr(related, "related", None) or ()
    for related_item in related_items:
        related_type = str(getattr(related_item, "type", "")).lower()
        if related_type in ("obsolete", "renamed"):
            ref = _ref_key(getattr(related_item, "id", related_item))
            if ref and ref not in superseded_by:
                superseded_by = (*superseded_by, ref)

    return RuleClaims(
        supersedes=supersedes,
        superseded_by=superseded_by,
        covers=covers,
        covers_basis=covers_basis,
        basis=basis,
    )


def _extract_severity(rule: SigmaRuleBase) -> tuple[str | None, int]:
    level = getattr(rule, "level", None)
    if isinstance(level, SigmaLevel):
        return level.name.lower(), int(level.value)
    custom = getattr(rule, "custom_attributes", None) or {}
    value = level if level is not None else custom.get("severity")
    if value is None:
        notification = custom.get("notification")
        if isinstance(notification, dict):
            value = notification.get("severity")
    if value is None:
        return None, 0
    text = str(value).lower()
    try:
        return text, int(SigmaLevel[text.upper()].value)
    except KeyError:
        return text, 0


@dataclass
class _Candidate:
    index: int
    match: SigmaMatch
    rule: SigmaRuleBase
    rule_ref: str
    identity_keys: set[str]
    severity: str | None
    severity_rank: int
    responsibility: Responsibility
    claims: RuleClaims
    evidence: list[EvidenceRecord]
    active: bool = True
    state_notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CompressionCheck:
    """Validation result for one declared winner/loser compression edge."""

    winner_ref: str
    loser_ref: str
    allowed: bool
    reasons: tuple[str, ...]
    blockers: tuple[str, ...]
    mutual_claim: bool = False
    resolution: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class ConflictRecord:
    """A contradictory or unsafe suppression relationship."""

    rule_refs: tuple[str, str]
    kind: str
    resolution: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class CompressedAlert:
    """An alert that can be represented by the selected notification."""

    rule_ref: str
    rule_id: str | None
    rule_name: str | None
    title: str
    severity: str | None
    responsibility: Responsibility
    reasons: tuple[str, ...]
    evidence: tuple[EvidenceRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))

    @property
    def reason(self) -> str | None:
        return self.reasons[0] if self.reasons else None


@dataclass
class Notification:
    """A notification that should still be sent."""

    notification_id: str
    group_key: str
    rule_ref: str
    rule_id: str | None
    rule_name: str | None
    title: str
    severity: str | None
    severity_rank: int
    responsibility: Responsibility
    active: bool
    reasons: tuple[str, ...]
    blockers: tuple[str, ...]
    explanation: str
    evidence: tuple[EvidenceRecord, ...]
    compressed: tuple[CompressedAlert, ...] = ()

    @property
    def compressed_refs(self) -> list[str]:
        return [item.rule_ref for item in self.compressed]

    @property
    def responsible_group(self) -> str | None:
        return self.responsibility.group

    @property
    def owner_group(self) -> str | None:
        return self.responsibility.group

    @property
    def owner(self) -> str | None:
        return self.responsibility.owner

    @property
    def responsibility_item(self) -> str | None:
        return self.responsibility.item

    @property
    def accountability(self) -> Responsibility:
        return self.responsibility

    @property
    def reason(self) -> str | None:
        return self.reasons[0] if self.reasons else None

    def explain(self, language: str = "zh") -> str:
        if language.lower().startswith("en"):
            return self._explanation_en()
        return self.explanation

    def _explanation_en(self) -> str:
        resp = self.responsibility
        lines = [
            f"Send {self.title!r} ({self.rule_ref}); severity={self.severity or 'undeclared'}.",
            "Accountability basis: "
            f"item={resp.item or 'undeclared'}, group={resp.group or 'undeclared'}, "
            f"owner={resp.owner or 'undeclared'}, source={resp.source or 'none'}.",
        ]
        if self.compressed:
            lines.append("Compressed: " + ", ".join(self.compressed_refs) + ".")
        if self.blockers:
            lines.append("Blockers: " + "; ".join(self.blockers) + ".")
        lines.append(f"Preserved evidence records: {len(self.evidence)}.")
        return " ".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass
class CandidateDecision:
    """Per-rule audit decision."""

    rule_ref: str
    title: str
    disposition: Literal["notify", "compressed"]
    selected: bool
    active: bool
    severity: str | None
    responsibility: Responsibility
    reasons: tuple[str, ...]
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass
class NotificationGroupResult:
    group_key: str
    notifications: list[Notification] = field(default_factory=list)
    checks: list[CompressionCheck] = field(default_factory=list)
    conflicts: list[ConflictRecord] = field(default_factory=list)
    decisions: list[CandidateDecision] = field(default_factory=list)

    @property
    def compressed(self) -> list[CompressedAlert]:
        return [
            compressed
            for notification in self.notifications
            for compressed in notification.compressed
        ]

    @property
    def winner(self) -> Notification | None:
        """Return the single winning notification for a fully compressed group."""
        return self.notifications[0] if len(self.notifications) == 1 else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_key": self.group_key,
            "notifications": [item.to_dict() for item in self.notifications],
            "compressed": [item.to_dict() for item in self.compressed],
            "checks": [item.to_dict() for item in self.checks],
            "conflicts": [item.to_dict() for item in self.conflicts],
            "decisions": [item.to_dict() for item in self.decisions],
        }


@dataclass
class NotificationSelection:
    """Complete selector output for one offline matching batch."""

    groups: list[NotificationGroupResult] = field(default_factory=list)

    @property
    def notifications(self) -> list[Notification]:
        return [item for group in self.groups for item in group.notifications]

    @property
    def selected(self) -> list[Notification]:
        return self.notifications

    @property
    def alerts(self) -> list[Notification]:
        return self.notifications

    @property
    def send(self) -> list[Notification]:
        return self.notifications

    @property
    def compressed(self) -> list[CompressedAlert]:
        return [item for group in self.groups for item in group.compressed]

    @property
    def suppressed(self) -> list[CompressedAlert]:
        return self.compressed

    @property
    def winner(self) -> Notification | None:
        """Convenience accessor for the common one-group/one-winner result."""
        return self.notifications[0] if len(self.notifications) == 1 else None

    @property
    def checks(self) -> list[CompressionCheck]:
        return [item for group in self.groups for item in group.checks]

    @property
    def conflicts(self) -> list[ConflictRecord]:
        return [item for group in self.groups for item in group.conflicts]

    @property
    def decisions(self) -> list[CandidateDecision]:
        return [item for group in self.groups for item in group.decisions]

    def explain(self, language: str = "zh") -> str:
        if not self.notifications:
            return "没有可发送通知。"
        return "\n\n".join(item.explain(language) for item in self.notifications)

    def to_dict(self) -> dict[str, Any]:
        return {
            "notification_count": len(self.notifications),
            "compressed_count": len(self.compressed),
            "conflict_count": len(self.conflicts),
            "notifications": [item.to_dict() for item in self.notifications],
            "groups": [group.to_dict() for group in self.groups],
        }


@dataclass
class SelectionTransition:
    """Difference between two selection runs across a rule availability change."""

    before: NotificationSelection
    after: NotificationSelection
    revived: list[Notification] = field(default_factory=list)

    @property
    def revived_refs(self) -> list[str]:
        return [item.rule_ref for item in self.revived]

    def explain(self, language: str = "zh") -> str:
        if not self.revived:
            return "没有告警因规则停用而恢复为通知。"
        refs = ", ".join(self.revived_refs)
        return f"接替规则状态变化后，以下过去被压缩的告警恢复发送：{refs}。"

    def to_dict(self) -> dict[str, Any]:
        return {
            "revived_refs": self.revived_refs,
            "revived": [item.to_dict() for item in self.revived],
        }


def compare_selections(
    before: NotificationSelection, after: NotificationSelection
) -> SelectionTransition:
    """Identify alerts compressed before but notified after a handoff change."""
    before_compressed = {item.rule_ref for item in before.compressed}
    revived = [
        notification
        for notification in after.notifications
        if notification.rule_ref in before_compressed
    ]
    return SelectionTransition(before=before, after=after, revived=revived)


def default_group_key(match: SigmaMatch) -> str:
    """Group single-event matches by stable event fingerprint."""
    fingerprints = sorted(event_fingerprint(event) for event in match.events)
    if not fingerprints:
        return f"match-without-events:{id(match)}"
    if len(fingerprints) == 1:
        return fingerprints[0]
    digest = hashlib.sha256("|".join(fingerprints).encode("utf-8")).hexdigest()
    return f"event-bundle:{digest}"


class NotificationSelector:
    """Choose notifications after offline Sigma matching.

    Parameters
    ----------
    offline_rules:
        Rule references or :class:`~sigma.rule.base.SigmaRuleBase` objects that are
        currently offline/disabled. This lets a rule declare ``superseded_by`` a
        successor that is absent from the current matcher output and still explain
        why the older alert was revived.
    mutual_claim_policy:
        ``severity_or_retain`` resolves a mutual suppression claim only when one side
        has strictly higher severity; equal-severity cycles are retained. Use
        ``retain_all`` to reject every direction in a mutual claim.
    require_responsibility / require_severity:
        When true, missing winner accountability or severity blocks compression.
    """

    def __init__(
        self,
        offline_rules: Iterable[Any] | Mapping[Any, Any] | None = None,
        *,
        disabled_rules: Iterable[Any] | None = None,
        inactive_rules: Iterable[Any] | None = None,
        deactivated_rules: Iterable[Any] | None = None,
        rule_states: Mapping[Any, Any] | None = None,
        mutual_claim_policy: MutualClaimPolicy = "severity_or_retain",
        require_responsibility: bool = True,
        require_severity: bool = True,
        block_cross_group: bool = True,
        group_key: GroupKeyFn | None = None,
    ) -> None:
        if mutual_claim_policy not in ("retain_all", "severity_or_retain"):
            raise ValueError(f"Unsupported mutual_claim_policy: {mutual_claim_policy}")
        if offline_rules is None:
            self.offline_rules = []
        elif isinstance(offline_rules, Mapping):
            self.offline_rules = []
        else:
            self.offline_rules = list(offline_rules)
        self.disabled_rules = list(disabled_rules or ())
        self.inactive_rules = list(inactive_rules or ())
        self.deactivated_rules = list(deactivated_rules or ())
        self.rule_states = dict(rule_states or {})
        self.mutual_claim_policy = mutual_claim_policy
        self.require_responsibility = require_responsibility
        self.require_severity = require_severity
        self.block_cross_group = block_cross_group
        self.group_key = group_key or default_group_key

    def select(
        self,
        matches: Iterable[SigmaMatch],
        *,
        offline_rules: Iterable[Any] | Mapping[Any, Any] | None = None,
        disabled_rules: Iterable[Any] | None = None,
        inactive_rules: Iterable[Any] | None = None,
        deactivated_rules: Iterable[Any] | None = None,
        rule_states: Mapping[Any, Any] | None = None,
    ) -> NotificationSelection:
        offline_keys = self._offline_keys(
            [
                *self.offline_rules,
                *self.disabled_rules,
                *self.inactive_rules,
                *self.deactivated_rules,
                *(
                    offline_rules
                    if offline_rules is not None and not isinstance(offline_rules, Mapping)
                    else ()
                ),
                *(disabled_rules or ()),
                *(inactive_rules or ()),
                *(deactivated_rules or ()),
            ]
        )
        offline_keys.update(self._offline_state_keys(self.rule_states))
        offline_keys.update(self._offline_state_keys(rule_states or {}))
        if isinstance(offline_rules, Mapping):
            offline_keys.update(self._offline_state_keys(offline_rules))
        grouped: dict[str, list[SigmaMatch]] = defaultdict(list)
        for match in matches:
            grouped[self.group_key(match)].append(match)

        result = NotificationSelection()
        for group_key, group_matches in grouped.items():
            result.groups.append(self._select_group(group_key, group_matches, offline_keys))
        return result

    @staticmethod
    def _offline_state_keys(states: Mapping[Any, Any]) -> set[str]:
        inactive_states = {
            "offline",
            "disabled",
            "inactive",
            "deactivated",
            "stopped",
            "retired",
        }
        keys: set[str] = set()
        for rule, state in states.items():
            if isinstance(rule, SigmaRuleBase):
                rule_keys = _rule_identity_keys(rule)
            else:
                rule_keys = {_ref_key(rule)}
            if state is False:
                keys.update(rule_keys)
            elif isinstance(state, str) and state.strip().lower() in inactive_states:
                keys.update(rule_keys)
        return keys

    @classmethod
    def _offline_keys(cls, rules: Iterable[Any]) -> set[str]:
        keys: set[str] = set()
        for rule in rules:
            if isinstance(rule, SigmaRuleBase):
                keys.update(_rule_identity_keys(rule))
            elif isinstance(rule, Mapping):
                keys.update(cls._offline_state_keys(rule))
            else:
                keys.add(_ref_key(rule))
        return keys

    def _candidate_from_match(
        self, index: int, match: SigmaMatch, offline_keys: set[str]
    ) -> _Candidate:
        rule = match.rule
        identity_keys = _rule_identity_keys(rule)
        primary_ref = (
            getattr(rule, "name", None)
            or (str(rule.id) if getattr(rule, "id", None) else None)
            or getattr(rule, "title", None)
            or f"rule-{index}"
        )
        severity, rank = _extract_severity(rule)
        candidate = _Candidate(
            index=index,
            match=match,
            rule=rule,
            rule_ref=str(primary_ref),
            identity_keys=identity_keys or {_ref_key(primary_ref)},
            severity=severity,
            severity_rank=rank,
            responsibility=_extract_responsibility(rule),
            claims=_extract_claims(rule),
            evidence=[EvidenceRecord.from_event(event) for event in match.events],
        )
        if identity_keys & offline_keys:
            candidate.active = False
            candidate.state_notes.append("rule_listed_offline_or_disabled")
        custom = getattr(rule, "custom_attributes", {}) or {}
        if custom.get("enabled") is False or custom.get("active") is False:
            candidate.active = False
            candidate.state_notes.append("rule_declared_inactive")
        return candidate

    def _select_group(
        self, group_key: str, matches: list[SigmaMatch], offline_keys: set[str]
    ) -> NotificationGroupResult:
        group_result = NotificationGroupResult(group_key=group_key)
        candidates = [
            self._candidate_from_match(index, match, offline_keys)
            for index, match in enumerate(matches)
        ]
        by_index = {candidate.index: candidate for candidate in candidates}
        alias_to_index: dict[str, int] = {}
        for candidate in candidates:
            for key in candidate.identity_keys:
                alias_to_index.setdefault(key, candidate.index)

        claimed_pairs: dict[tuple[int, int], list[str]] = defaultdict(list)
        for winner in candidates:
            for ref in winner.claims.supersedes:
                loser_index = alias_to_index.get(ref)
                if loser_index is not None:
                    claimed_pairs[(winner.index, loser_index)].append(
                        f"winner_declares_supersedes:{ref}"
                    )
        for loser in candidates:
            for ref in loser.claims.superseded_by:
                winner_index = alias_to_index.get(ref)
                if winner_index is not None:
                    claimed_pairs[(winner_index, loser.index)].append(
                        f"loser_declares_superseded_by:{ref}"
                    )

        checks: dict[tuple[int, int], CompressionCheck] = {}
        for (winner_index, loser_index), claim_reasons in claimed_pairs.items():
            winner = by_index[winner_index]
            loser = by_index[loser_index]
            check = self._build_check(winner, loser, claim_reasons, claimed_pairs)
            checks[(winner_index, loser_index)] = check
            group_result.checks.append(check)

        seen_conflict_pairs: set[tuple[int, int]] = set()
        for (winner_index, loser_index), check in checks.items():
            reverse_check = checks.get((loser_index, winner_index))
            pair = tuple(sorted((winner_index, loser_index)))
            if reverse_check is None or pair in seen_conflict_pairs:
                continue
            seen_conflict_pairs.add(pair)
            first_check = check
            second_check = reverse_check
            allowed_check = (
                first_check
                if first_check.allowed
                else second_check if second_check.allowed else None
            )
            resolution = (
                allowed_check.resolution
                if allowed_check is not None and allowed_check.resolution
                else first_check.resolution or second_check.resolution or "unresolved"
            )
            detail = " | ".join(
                "; ".join(item.reasons + item.blockers) for item in (first_check, second_check)
            )
            group_result.conflicts.append(
                ConflictRecord(
                    rule_refs=(
                        by_index[winner_index].rule_ref,
                        by_index[loser_index].rule_ref,
                    ),
                    kind="mutual_suppression_claim",
                    resolution=resolution,
                    detail=detail,
                )
            )

        eligible_winners = [
            candidate
            for candidate in candidates
            if candidate.active
            and all(
                checks.get((candidate.index, other.index)) is not None
                and checks[(candidate.index, other.index)].allowed
                for other in candidates
                if other.index != candidate.index
            )
        ]

        winner: _Candidate | None = None
        if eligible_winners:
            winner = sorted(
                eligible_winners,
                key=lambda candidate: (
                    -candidate.severity_rank,
                    -self._accountability_score(candidate.responsibility),
                    candidate.rule_ref.lower(),
                    candidate.index,
                ),
            )[0]
            if len(eligible_winners) > 1:
                winner.state_notes.append(
                    f"deterministic_winner_selected_from:{len(eligible_winners)}"
                )

        decisions: list[CandidateDecision] = []
        notifications: list[Notification] = []
        for candidate in candidates:
            is_winner = winner is not None and candidate.index == winner.index
            is_compressed = winner is not None and not is_winner
            outgoing = [
                check
                for (check_winner, _loser), check in checks.items()
                if check_winner == candidate.index
            ]
            blockers = [note for note in candidate.state_notes]
            blockers.extend(blocker for check in outgoing for blocker in check.blockers)
            blockers.extend(self._missing_winner_blockers(candidate, candidates, checks))
            reasons = [reason for check in outgoing for reason in check.reasons]
            successor_notes = self._declared_successor_notes(
                candidate, alias_to_index, offline_keys
            )
            blockers.extend(successor_notes)

            if is_winner:
                decisions.append(
                    CandidateDecision(
                        rule_ref=candidate.rule_ref,
                        title=getattr(candidate.rule, "title", candidate.rule_ref),
                        disposition="notify",
                        selected=True,
                        active=candidate.active,
                        severity=candidate.severity,
                        responsibility=candidate.responsibility,
                        reasons=tuple(dict.fromkeys(reasons + candidate.state_notes)),
                        blockers=(),
                    )
                )
                compressed_alerts: list[CompressedAlert] = []
                evidence = list(candidate.evidence)
                for loser in candidates:
                    if loser.index == candidate.index:
                        continue
                    check = checks[(candidate.index, loser.index)]
                    evidence.extend(loser.evidence)
                    compressed_alerts.append(
                        CompressedAlert(
                            rule_ref=loser.rule_ref,
                            rule_id=str(loser.rule.id) if loser.rule.id else None,
                            rule_name=loser.rule.name,
                            title=getattr(loser.rule, "title", loser.rule_ref),
                            severity=loser.severity,
                            responsibility=loser.responsibility,
                            reasons=check.reasons,
                            evidence=tuple(loser.evidence),
                        )
                    )
                unique_evidence: dict[str, EvidenceRecord] = {}
                for record in evidence:
                    unique_evidence.setdefault(record.fingerprint, record)
                notification = self._build_notification(
                    group_key,
                    candidate,
                    reasons=tuple(dict.fromkeys(reasons + candidate.state_notes)),
                    blockers=(),
                    evidence=tuple(unique_evidence.values()),
                    compressed=tuple(compressed_alerts),
                )
                notifications.append(notification)
            else:
                disposition: Literal["notify", "compressed"] = (
                    "compressed" if is_compressed else "notify"
                )
                decisions.append(
                    CandidateDecision(
                        rule_ref=candidate.rule_ref,
                        title=getattr(candidate.rule, "title", candidate.rule_ref),
                        disposition=disposition,
                        selected=False,
                        active=candidate.active,
                        severity=candidate.severity,
                        responsibility=candidate.responsibility,
                        reasons=tuple(dict.fromkeys(reasons)),
                        blockers=tuple(dict.fromkeys(blockers)),
                    )
                )
                if not is_compressed:
                    notifications.append(
                        self._build_notification(
                            group_key,
                            candidate,
                            reasons=tuple(dict.fromkeys(reasons)),
                            blockers=tuple(dict.fromkeys(blockers)),
                            evidence=tuple(candidate.evidence),
                            compressed=(),
                        )
                    )

        group_result.notifications = notifications
        group_result.decisions = decisions
        return group_result

    def _build_check(
        self,
        winner: _Candidate,
        loser: _Candidate,
        claim_reasons: list[str],
        claimed_pairs: dict[tuple[int, int], list[str]],
    ) -> CompressionCheck:
        reasons: list[str] = list(claim_reasons)
        blockers: list[str] = []
        mutual = (loser.index, winner.index) in claimed_pairs
        resolution: str | None = None

        if not winner.active:
            blockers.append("winner_rule_offline_or_disabled")

        coverage_blocker = self._coverage_blocker(winner, loser)
        if coverage_blocker:
            blockers.append(coverage_blocker)
        else:
            reasons.append("coverage_validated")

        resp_blocker = self._responsibility_blocker(winner, loser)
        if resp_blocker:
            blockers.append(resp_blocker)
        else:
            reasons.append(f"accountability_basis:{winner.responsibility.label}")

        severity_blocker = self._severity_blocker(winner, loser)
        if severity_blocker:
            blockers.append(severity_blocker)
        elif winner.severity and loser.severity:
            reasons.append(f"severity_order:{winner.severity}>={loser.severity}")
        else:
            reasons.append("severity_not_declared")

        if mutual:
            reasons.append("mutual_suppression_claim")
            if self.mutual_claim_policy == "retain_all":
                blockers.append("mutual_suppression_claim_retained")
                resolution = "retained_both"
            elif winner.severity_rank and loser.severity_rank:
                if winner.severity_rank > loser.severity_rank:
                    resolution = "higher_severity_selected"
                elif winner.severity_rank < loser.severity_rank:
                    blockers.append("mutual_claim_lower_severity")
                    resolution = "lower_severity_rejected"
                else:
                    blockers.append("mutual_claim_equal_severity_ambiguous")
                    resolution = "equal_severity_retained"
            else:
                blockers.append("mutual_claim_severity_unknown")
                resolution = "unknown_severity_retained"

        allowed = not blockers
        return CompressionCheck(
            winner_ref=winner.rule_ref,
            loser_ref=loser.rule_ref,
            allowed=allowed,
            reasons=tuple(dict.fromkeys(reasons)),
            blockers=tuple(dict.fromkeys(blockers)),
            mutual_claim=mutual,
            resolution=resolution,
        )

    def _coverage_blocker(self, winner: _Candidate, loser: _Candidate) -> str | None:
        wildcard = any(ref in ("*", "all", "all_rules") for ref in winner.claims.covers)
        rule_covered = wildcard or bool(loser.identity_keys & set(winner.claims.covers))
        if winner.claims.covers and not rule_covered:
            return f"coverage_declaration_does_not_cover:{loser.rule_ref}"

        basis_wildcard = "*" in winner.claims.covers_basis or "all" in winner.claims.covers_basis
        if loser.claims.basis and winner.claims.covers_basis:
            basis_covered = basis_wildcard or set(loser.claims.basis).issubset(
                winner.claims.covers_basis
            )
            if not basis_covered and not rule_covered:
                missing = sorted(set(loser.claims.basis) - set(winner.claims.covers_basis))
                return "coverage_basis_gap:" + ",".join(missing)
        if not winner.claims.covers and not winner.claims.covers_basis:
            return None
        return None

    def _responsibility_blocker(self, winner: _Candidate, loser: _Candidate) -> str | None:
        responsibility = winner.responsibility
        if not responsibility.accountable:
            if self.require_responsibility:
                return "winner_missing_responsibility_item_or_group"
            return None
        if not self.block_cross_group:
            return None
        winner_group = (responsibility.group or "").lower()
        loser_group = (loser.responsibility.group or "").lower()
        if not loser_group or not winner_group or winner_group == loser_group:
            return None
        if responsibility.cross_group_allowed or "*" in responsibility.assumes_groups:
            return None
        if loser_group in responsibility.assumes_groups:
            return None
        return f"responsibility_group_mismatch:{winner_group}!={loser_group}"

    def _severity_blocker(self, winner: _Candidate, loser: _Candidate) -> str | None:
        if winner.severity_rank and loser.severity_rank:
            if winner.severity_rank < loser.severity_rank:
                return (
                    "severity_downgrade_blocked:"
                    f"{winner.severity or winner.severity_rank}<{loser.severity or loser.severity_rank}"
                )
            return None
        if self.require_severity and (not winner.severity_rank or not loser.severity_rank):
            return "severity_missing_or_unranked"
        return None

    @staticmethod
    def _accountability_score(responsibility: Responsibility) -> int:
        return sum(
            bool(value)
            for value in (
                responsibility.group,
                responsibility.owner,
                responsibility.item,
                responsibility.source,
            )
        )

    def _missing_winner_blockers(
        self,
        candidate: _Candidate,
        candidates: list[_Candidate],
        checks: dict[tuple[int, int], CompressionCheck],
    ) -> list[str]:
        if candidate.active and all(
            (candidate.index == other.index)
            or (
                checks.get((candidate.index, other.index)) is not None
                and checks[(candidate.index, other.index)].allowed
            )
            for other in candidates
        ):
            return []
        blockers: list[str] = []
        for other in candidates:
            if other.index == candidate.index:
                continue
            check = checks.get((candidate.index, other.index))
            if check is None:
                blockers.append(f"no_valid_supersession_claim_to:{other.rule_ref}")
            elif not check.allowed:
                blockers.extend(check.blockers)
        return list(dict.fromkeys(blockers))

    @staticmethod
    def _declared_successor_notes(
        candidate: _Candidate,
        alias_to_index: dict[str, int],
        offline_keys: set[str],
    ) -> list[str]:
        notes: list[str] = []
        for ref in candidate.claims.superseded_by:
            if ref in alias_to_index:
                continue
            if ref in offline_keys:
                notes.append(f"declared_successor_offline:{ref}")
            else:
                notes.append(f"declared_successor_not_matched:{ref}")
        return list(dict.fromkeys(notes))

    def _build_notification(
        self,
        group_key: str,
        candidate: _Candidate,
        *,
        reasons: tuple[str, ...],
        blockers: tuple[str, ...],
        evidence: tuple[EvidenceRecord, ...],
        compressed: tuple[CompressedAlert, ...],
    ) -> Notification:
        rule = candidate.rule
        rule_id = str(rule.id) if getattr(rule, "id", None) else None
        notification_id = f"{group_key[:16]}:{candidate.rule_ref}"
        notification = Notification(
            notification_id=notification_id,
            group_key=group_key,
            rule_ref=candidate.rule_ref,
            rule_id=rule_id,
            rule_name=getattr(rule, "name", None),
            title=getattr(rule, "title", candidate.rule_ref),
            severity=candidate.severity,
            severity_rank=candidate.severity_rank,
            responsibility=candidate.responsibility,
            active=candidate.active,
            reasons=reasons,
            blockers=blockers,
            explanation="",
            evidence=evidence,
            compressed=compressed,
        )
        notification.explanation = self._chinese_explanation(notification)
        return notification

    @staticmethod
    def _chinese_explanation(notification: Notification) -> str:
        resp = notification.responsibility
        responsibility_text = (
            f"责任项 {resp.item or '未声明'}，责任组 {resp.group or '未声明'}，"
            f"责任人 {resp.owner or '未声明'}，声明来源 {resp.source or '未找到'}"
        )
        if notification.compressed:
            action = (
                f"发送规则「{notification.title}」({notification.rule_ref})，"
                f"并压缩 {len(notification.compressed)} 条同源告警："
                f"{', '.join(notification.compressed_refs)}。"
            )
        else:
            action = f"保留并发送规则「{notification.title}」({notification.rule_ref})。"
        severity_text = f"严重等级为 {notification.severity or '未声明'}。"
        basis_text = f"通知所依据的{responsibility_text}。"
        evidence_text = f"已保全 {len(notification.evidence)} 份原始事件证物快照。"
        blocker_text = ""
        if notification.blockers:
            blocker_text = " 未压缩原因：" + "；".join(notification.blockers) + "。"
        inactive_text = (
            " 注意：该规则在选择时已被标记为停用/下线。" if not notification.active else ""
        )
        return action + severity_text + basis_text + evidence_text + blocker_text + inactive_text


def select_notifications(
    matches: Iterable[SigmaMatch],
    *,
    offline_rules: Iterable[Any] | None = None,
    disabled_rules: Iterable[Any] | None = None,
    inactive_rules: Iterable[Any] | None = None,
    deactivated_rules: Iterable[Any] | None = None,
    rule_states: Mapping[Any, Any] | None = None,
    mutual_claim_policy: MutualClaimPolicy = "severity_or_retain",
    require_responsibility: bool = True,
    require_severity: bool = True,
    block_cross_group: bool = True,
    group_key: GroupKeyFn | None = None,
) -> NotificationSelection:
    """Functional wrapper around :class:`NotificationSelector`."""
    selector = NotificationSelector(
        offline_rules=offline_rules,
        disabled_rules=disabled_rules,
        inactive_rules=inactive_rules,
        deactivated_rules=deactivated_rules,
        rule_states=rule_states,
        mutual_claim_policy=mutual_claim_policy,
        require_responsibility=require_responsibility,
        require_severity=require_severity,
        block_cross_group=block_cross_group,
        group_key=group_key,
    )
    return selector.select(matches)


def select_notification(
    matches: Iterable[SigmaMatch],
    *,
    offline_rules: Iterable[Any] | None = None,
    disabled_rules: Iterable[Any] | None = None,
    inactive_rules: Iterable[Any] | None = None,
    deactivated_rules: Iterable[Any] | None = None,
    rule_states: Mapping[Any, Any] | None = None,
    mutual_claim_policy: MutualClaimPolicy = "severity_or_retain",
    require_responsibility: bool = True,
    require_severity: bool = True,
    block_cross_group: bool = True,
    group_key: GroupKeyFn | None = None,
) -> NotificationSelection:
    """Singular alias for :func:`select_notifications`."""
    return select_notifications(
        matches,
        offline_rules=offline_rules,
        disabled_rules=disabled_rules,
        inactive_rules=inactive_rules,
        deactivated_rules=deactivated_rules,
        rule_states=rule_states,
        mutual_claim_policy=mutual_claim_policy,
        require_responsibility=require_responsibility,
        require_severity=require_severity,
        block_cross_group=block_cross_group,
        group_key=group_key,
    )


# Common descriptive aliases for integrations and discovery.
NotificationDeduplicator = NotificationSelector
DeduplicationSelector = NotificationSelector
NotificationPolicy = NotificationSelector
select_deduplicated_notifications = select_notifications
choose_notifications = select_notifications
deduplicate_matches = select_notifications
compress_matches = select_notifications
