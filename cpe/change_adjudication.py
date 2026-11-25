# -*- coding: utf-8 -*-
"""
Change-window adjudication for CPE-based security announcements.

This module adds a small policy layer on top of the CPE name matcher in this
package.  It answers a narrower question than a scanner:

* which announcements currently match an asset's observed CPE state?
* which of those matches are temporarily covered by a change ticket?
* which decisions must be left to a human because the inventory or the
  evidence connecting two changes is incomplete?

The adjudicator is deliberately time-aware.  Observations are sorted by their
observation time, aliases only become usable at their effective/record time,
and a ticket can defer a match only for the components and interval recorded
on that ticket.
"""

from __future__ import absolute_import, unicode_literals

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import unquote

from .cpe import CPE
from .cpe2_3_wfn import CPE2_3_WFN
from .cpeset2_3 import CPESet2_3


STATUS_DEFERRED = "deferred"
STATUS_REMEDIATION = "remediation"
STATUS_MANUAL_REVIEW = "manual_review"
STATUS_CLEAR = "clear"

CHAIN_VERIFIED = "verified"
CHAIN_MANUAL_REVIEW = "manual_review"

_MIN_TIME = datetime.min.replace(tzinfo=timezone.utc)
_ATTR_ORDER = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


def _as_datetime(value: Any, default: Optional[datetime] = None) -> Optional[datetime]:
    """Return a timezone-aware datetime from a datetime or ISO-8601 string."""
    if value is None:
        return default
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            raise ValueError("invalid ISO-8601 timestamp: {0!r}".format(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    raise TypeError("timestamp must be a datetime or ISO-8601 string")


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


def _first(item: Mapping[str, Any], *keys: str, **kwargs: Any) -> Any:
    default = kwargs.get("default")
    for key in keys:
        if key in item and item[key] is not None:
            return item[key]
    return default


def _as_tuple(value: Any) -> Tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, Mapping)):
        return (value,)
    return tuple(value)


def _stable_auto_id(prefix: str, *parts: Any) -> str:
    payload = "|".join(_text(part) for part in parts)
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]
    return "{0}-{1}".format(prefix, digest)


@dataclass(frozen=True)
class Asset:
    """An asset inventory entry.

    ``components`` maps a stable component id (for example ``"openssl"``) to
    the CPE observed at inventory time.  A one-component asset can instead use
    the shorthand ``cpe`` field.
    """

    asset_id: str
    cpe: Optional[str] = None
    components: Mapping[str, str] = field(default_factory=dict)
    inventory_at: Optional[datetime] = None
    inventory_valid_until: Optional[datetime] = None
    inventory_gaps: Tuple[Tuple[datetime, datetime], ...] = ()
    aliases: Tuple[Any, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChangeTicket:
    """A maintenance authorization for one asset."""

    ticket_id: str
    asset_id: str
    starts_at: datetime
    ends_at: datetime
    planned_components: Tuple[str, ...] = ()
    component_ids: Tuple[str, ...] = ()
    aliases: Tuple[Any, ...] = ()
    previous_ticket_id: Optional[str] = None
    chain_id: Optional[str] = None
    source_cpes: Mapping[str, str] = field(default_factory=dict)
    target_cpes: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def start(self) -> datetime:
        return self.starts_at

    @property
    def end(self) -> datetime:
        return self.ends_at

    def contains(self, when: datetime) -> bool:
        return self.starts_at <= when <= self.ends_at


@dataclass(frozen=True)
class Observation:
    """A time-stamped CPE observation.

    ``kind`` is normally ``upgrade``, ``rollback``, or ``inventory``.  A
    ``missing``/``inventory_gap`` observation records an interval for which no
    trustworthy inventory exists and is intentionally not used to infer state.
    ``recorded_at`` is kept for audit; ordering always uses ``observed_at``.
    """

    observation_id: str
    asset_id: str
    observed_at: datetime
    cpe: Optional[str]
    kind: str = "inventory"
    component_id: Optional[str] = None
    ticket_id: Optional[str] = None
    ticket_ids: Tuple[str, ...] = ()
    recorded_at: Optional[datetime] = None
    previous_observation_id: Optional[str] = None
    chain_id: Optional[str] = None
    evidence_id: Optional[str] = None
    gap_ends_at: Optional[datetime] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Alias:
    """A time-scoped CPE alias.

    ``alias_cpe`` is the name seen in an observation and ``canonical_cpe`` is
    the name used for matching.  An alias is not usable before
    ``effective_at`` or before ``recorded_at``.  This prevents a late backfill
    from changing the result of an earlier maintenance window.
    """

    alias_cpe: str
    canonical_cpe: str
    effective_at: Optional[datetime] = None
    recorded_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    ticket_id: Optional[str] = None
    asset_id: Optional[str] = None
    component_id: Optional[str] = None
    alias_id: Optional[str] = None

    def usable_at(self, when: datetime) -> bool:
        usable_from = max(
            self.effective_at or _MIN_TIME,
            self.recorded_at or _MIN_TIME,
        )
        if usable_from > when:
            return False
        if self.expires_at is not None and self.expires_at < when:
            return False
        return True


@dataclass(frozen=True)
class Announcement:
    """A security announcement expressed as one or more CPE names."""

    announcement_id: str
    expression: str
    published_at: Optional[datetime] = None
    title: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def expressions(self) -> Tuple[str, ...]:
        return (self.expression,)


@dataclass(frozen=True)
class MatchEvidence:
    """Why a particular announcement matched a particular observation."""

    announcement_id: str
    expression: str
    observed_cpe: str
    resolved_cpe: str
    matched_fields: Tuple[Mapping[str, Any], ...] = ()
    alias_ids: Tuple[str, ...] = ()
    observation_ids: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "type": "cpe_name",
            "announcement_id": self.announcement_id,
            "expression": self.expression,
            "matched_expression": self.expression,
            "observed_cpe": self.observed_cpe,
            "resolved_cpe": self.resolved_cpe,
            "fields": [dict(field) for field in self.matched_fields],
            "alias_ids": list(self.alias_ids),
            "observation_ids": list(self.observation_ids),
        }


@dataclass(frozen=True)
class AdjudicationDecision:
    """The result for one asset/component/announcement tuple."""

    asset_id: str
    announcement_id: str
    component_id: Optional[str]
    status: str
    announcement_expression: Optional[str] = None
    observed_cpe: Optional[str] = None
    resolved_cpe: Optional[str] = None
    ticket_id: Optional[str] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    deferral_ticket_ids: Tuple[str, ...] = ()
    returned_after_deferral: bool = False
    matched_fields: Tuple[Mapping[str, Any], ...] = ()
    alias_ids: Tuple[str, ...] = ()
    observation_ids: Tuple[str, ...] = ()
    reason: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def deferred(self) -> bool:
        return self.status == STATUS_DEFERRED

    @property
    def requires_remediation(self) -> bool:
        return self.status == STATUS_REMEDIATION

    @property
    def manual_review(self) -> bool:
        return self.status == STATUS_MANUAL_REVIEW

    @property
    def matched_expression(self) -> Optional[str]:
        return self.announcement_expression

    def as_dict(self) -> Dict[str, Any]:
        action = {
            STATUS_DEFERRED: "defer",
            STATUS_REMEDIATION: "remediate",
            STATUS_MANUAL_REVIEW: "manual_review",
            STATUS_CLEAR: "none",
        }.get(self.status, self.status)
        match = {
            "type": "cpe_name",
            "expression": self.announcement_expression,
            "matched_expression": self.announcement_expression,
            "observed_cpe": self.observed_cpe,
            "resolved_cpe": self.resolved_cpe,
            "fields": [dict(item) for item in self.matched_fields],
            "alias_ids": list(self.alias_ids),
        }
        return {
            "asset_id": self.asset_id,
            "announcement_id": self.announcement_id,
            "component_id": self.component_id,
            "status": self.status,
            "action": action,
            "deferred": self.deferred,
            "requires_remediation": self.requires_remediation,
            "manual_review": self.manual_review,
            "announcement_expression": self.announcement_expression,
            "matched_expression": self.announcement_expression,
            "observed_cpe": self.observed_cpe,
            "resolved_cpe": self.resolved_cpe,
            "ticket_id": self.ticket_id,
            "window_start": _iso(self.window_start),
            "window_end": _iso(self.window_end),
            "deferral_ticket_ids": list(self.deferral_ticket_ids),
            "returned_after_deferral": self.returned_after_deferral,
            "matched_fields": [dict(item) for item in self.matched_fields],
            "alias_ids": list(self.alias_ids),
            "observation_ids": list(self.observation_ids),
            "match": match,
            "evidence": {
                "ticket_id": self.ticket_id,
                "window_start": _iso(self.window_start),
                "window_end": _iso(self.window_end),
                "deferral_ticket_ids": list(self.deferral_ticket_ids),
                "observation_ids": list(self.observation_ids),
            },
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DeferralEvent:
    """A historically valid deferral, used to explain a returning advisory."""

    asset_id: str
    announcement_id: str
    component_id: Optional[str]
    ticket_id: str
    decided_at: datetime
    observed_cpe: str
    expression: str


@dataclass(frozen=True)
class EvidenceChain:
    """Evidence connecting two consecutive changes on a device."""

    asset_id: str
    ticket_ids: Tuple[str, str]
    status: str
    observation_ids: Tuple[str, ...] = ()
    reason: str = ""

    @property
    def chained(self) -> bool:
        return self.status == CHAIN_VERIFIED

    def as_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ticket_ids": list(self.ticket_ids),
            "status": self.status,
            "chained": self.chained,
            "observation_ids": list(self.observation_ids),
            "reason": self.reason,
        }


class _RemediationList(list):
    """A list that also supports call-style access for compatibility."""

    def __call__(self) -> List[Dict[str, Any]]:
        return list(self)


@dataclass(frozen=True)
class AdjudicationResult:
    """Deterministic result of one adjudication run."""

    as_of: datetime
    decisions: Tuple[AdjudicationDecision, ...]
    deferral_events: Tuple[DeferralEvent, ...] = ()
    evidence_chains: Tuple[EvidenceChain, ...] = ()

    @property
    def deferred(self) -> Tuple[AdjudicationDecision, ...]:
        return tuple(
            decision for decision in self.decisions
            if decision.status == STATUS_DEFERRED
        )

    @property
    def remediation(self) -> Tuple[AdjudicationDecision, ...]:
        return tuple(
            decision for decision in self.decisions
            if decision.status == STATUS_REMEDIATION
        )

    @property
    def manual_reviews(self) -> Tuple[AdjudicationDecision, ...]:
        return tuple(
            decision for decision in self.decisions
            if decision.status == STATUS_MANUAL_REVIEW
        )

    @property
    def remediation_list(self) -> "_RemediationList":
        """Export a stable, order-independent remediation work list.

        The returned value is both a list and callable, so result.remediation_list
        and result.remediation_list() are equivalent.
        """

        entries = [decision.as_dict() for decision in self.remediation]
        entries.sort(key=_remediation_sort_key)
        return _RemediationList(entries)

    def export_remediation_list(self) -> List[Dict[str, Any]]:
        return self.remediation_list()

    @property
    def remediation_ids(self) -> Tuple[str, ...]:
        return tuple(
            _stable_auto_id(
                "finding",
                item["asset_id"],
                item["announcement_id"],
                item["component_id"],
                item["announcement_expression"],
            )
            for item in self.remediation_list()
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "as_of": _iso(self.as_of),
            "remediation": self.remediation_list(),
            "deferred": [decision.as_dict() for decision in self.deferred],
            "manual_review": [
                decision.as_dict() for decision in self.manual_reviews
            ],
            "deferral_events": [
                {
                    "asset_id": event.asset_id,
                    "announcement_id": event.announcement_id,
                    "component_id": event.component_id,
                    "ticket_id": event.ticket_id,
                    "decided_at": _iso(event.decided_at),
                    "observed_cpe": event.observed_cpe,
                    "expression": event.expression,
                }
                for event in self.deferral_events
            ],
            "evidence_chains": [chain.as_dict() for chain in self.evidence_chains],
        }


@dataclass
class _Component:
    component_id: str
    baseline_cpe: Optional[str]
    baseline_at: Optional[datetime]
    events: List[Observation] = field(default_factory=list)


@dataclass(frozen=True)
class _State:
    known: bool
    cpe: Optional[str] = None
    observation_ids: Tuple[str, ...] = ()
    reason: str = ""


@dataclass
class _Match:
    matched: bool
    fields: Tuple[Mapping[str, Any], ...] = ()
    reason: str = ""


def _remediation_sort_key(item: Mapping[str, Any]) -> Tuple[Any, ...]:
    return (
        _text(item.get("asset_id") or ""),
        _text(item.get("announcement_id") or ""),
        _text(item.get("component_id") or ""),
        _text(item.get("announcement_expression") or ""),
        _text(item.get("observed_cpe") or ""),
        _text(item.get("resolved_cpe") or ""),
    )


def _component_from_mapping(value: Any) -> Tuple[str, Optional[str]]:
    if isinstance(value, str):
        return value, None
    if not isinstance(value, Mapping):
        raise TypeError("component must be a CPE string or object")
    cpe = _first(value, "cpe", "cpe_name", "expression")
    component_id = _first(value, "component_id", "id", "name", "component")
    if component_id is None and cpe:
        component_id = _cpe_identity_key(cpe) or _stable_auto_id("component", cpe)
    return _text(component_id), cpe


def _normalise_components(raw: Mapping[str, Any]) -> Dict[str, str]:
    components: Dict[str, str] = {}
    raw_components = _first(raw, "components", "component_inventory")
    if isinstance(raw_components, Mapping):
        for component_id, component in raw_components.items():
            if isinstance(component, Mapping):
                cpe = _first(component, "cpe", "cpe_name", "expression")
            else:
                cpe = component
            if cpe:
                components[_text(component_id)] = _text(cpe)
    elif raw_components is not None:
        for item in _as_tuple(raw_components):
            component_id, cpe = _component_from_mapping(item)
            if cpe:
                components[component_id] = cpe

    if not components:
        raw_cpe = _first(raw, "cpe", "cpe_name", "original_cpe")
        raw_cpes = _first(raw, "cpes", "original_cpes")
        if raw_cpe:
            components["default"] = _text(raw_cpe)
        elif raw_cpes:
            for index, cpe in enumerate(_as_tuple(raw_cpes)):
                cpe_text = _text(cpe)
                components[
                    _cpe_identity_key(cpe_text) or "component-{0}".format(index)
                ] = cpe_text
    return components


def _normalise_asset(raw: Any) -> Asset:
    if isinstance(raw, Asset):
        gaps = []
        for start, end in raw.inventory_gaps:
            start = _as_datetime(start)
            end = _as_datetime(end)
            if start is not None and end is not None:
                gaps.append((start, end))
        components = {
            _text(component_id): _text(cpe)
            for component_id, cpe in raw.components.items()
        }
        if not components and raw.cpe is not None:
            components["default"] = _text(raw.cpe)
        return Asset(
            asset_id=_text(raw.asset_id),
            cpe=_text(raw.cpe) if raw.cpe is not None else None,
            components=components,
            inventory_at=_as_datetime(raw.inventory_at),
            inventory_valid_until=_as_datetime(raw.inventory_valid_until),
            inventory_gaps=tuple(gaps),
            aliases=tuple(raw.aliases),
            metadata=raw.metadata,
        )
    if not isinstance(raw, Mapping):
        raise TypeError("asset must be an Asset or mapping")
    asset_id = _first(raw, "asset_id", "device_id", "id")
    if asset_id is None:
        raise ValueError("asset_id is required")

    gaps: List[Tuple[datetime, datetime]] = []
    for gap in _as_tuple(_first(raw, "inventory_gaps", "gaps")):
        if isinstance(gap, Mapping):
            start = _as_datetime(_first(gap, "starts_at", "start", "from"))
            end = _as_datetime(_first(gap, "ends_at", "end", "to"))
        else:
            start = _as_datetime(gap[0])
            end = _as_datetime(gap[1])
        if start is not None and end is not None:
            gaps.append((start, end))

    aliases = _as_tuple(_first(raw, "aliases", "cpe_aliases"))
    return Asset(
        asset_id=_text(asset_id),
        cpe=_first(raw, "cpe", "cpe_name"),
        components=_normalise_components(raw),
        inventory_at=_as_datetime(
            _first(raw, "inventory_at", "baseline_at", "observed_at")
        ),
        inventory_valid_until=_as_datetime(
            _first(raw, "inventory_valid_until", "valid_until")
        ),
        inventory_gaps=tuple(gaps),
        aliases=aliases,
        metadata=_first(raw, "metadata", default={}) or {},
    )


def _normalise_planned(ticket: Mapping[str, Any]) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    planned_cpes: List[str] = []
    component_ids: List[str] = []

    raw_planned = _first(
        ticket,
        "planned_components",
        "planned_cpes",
        "planned",
        "components",
        "planned_component_cpes",
        "authorized_components",
    )
    if isinstance(raw_planned, Mapping):
        for component_id, value in raw_planned.items():
            component_ids.append(_text(component_id))
            if isinstance(value, Mapping):
                value = _first(value, "cpe", "cpe_name", "expression", default=value)
            if isinstance(value, str) and _looks_like_cpe(value):
                planned_cpes.append(value)
            elif value is not None and not isinstance(value, Mapping):
                planned_cpes.append(_text(value))
    elif raw_planned is not None:
        for item in _as_tuple(raw_planned):
            if isinstance(item, Mapping):
                component_id = _first(item, "component_id", "id", "name")
                cpe = _first(item, "cpe", "cpe_name", "expression")
                if component_id is not None:
                    component_ids.append(_text(component_id))
                if cpe:
                    planned_cpes.append(_text(cpe))
            elif _looks_like_cpe(_text(item)):
                planned_cpes.append(_text(item))
            else:
                component_ids.append(_text(item))

    explicit_ids = _first(
        ticket,
        "component_ids",
        "planned_component_ids",
        "component_id",
    )
    for component_id in _as_tuple(explicit_ids):
        if isinstance(component_id, Mapping):
            component_id = _first(component_id, "component_id", "id", "name")
        if component_id is not None:
            component_ids.append(_text(component_id))

    return tuple(_dedupe(planned_cpes)), tuple(_dedupe(component_ids))


def _normalise_alias(raw: Any, ticket: Optional[Mapping[str, Any]] = None) -> Alias:
    if isinstance(raw, Alias):
        effective_at = _as_datetime(raw.effective_at)
        if ticket and effective_at is None:
            effective_at = _as_datetime(
                _first(
                ticket,
                "starts_at",
                "start",
                "window_start",
                "from",
                "start_time",
                "maintenance_start",
            )
            )
        if ticket and raw.ticket_id is None:
            return Alias(
                alias_cpe=raw.alias_cpe,
                canonical_cpe=raw.canonical_cpe,
                effective_at=effective_at,
                recorded_at=_as_datetime(raw.recorded_at),
                expires_at=_as_datetime(raw.expires_at),
                ticket_id=_first(ticket, "ticket_id", "change_id", "id"),
                asset_id=raw.asset_id or _first(ticket, "asset_id", "device_id"),
                component_id=raw.component_id,
                alias_id=raw.alias_id,
            )
        return Alias(
            alias_cpe=raw.alias_cpe,
            canonical_cpe=raw.canonical_cpe,
            effective_at=effective_at,
            recorded_at=_as_datetime(raw.recorded_at),
            expires_at=_as_datetime(raw.expires_at),
            ticket_id=raw.ticket_id,
            asset_id=raw.asset_id,
            component_id=raw.component_id,
            alias_id=raw.alias_id,
        )
    if not isinstance(raw, Mapping):
        raise TypeError("alias must be an Alias or mapping")
    alias_cpe = _first(
        raw,
        "alias_cpe",
        "alias",
        "from_cpe",
        "source_cpe",
        "from",
    )
    canonical_cpe = _first(
        raw,
        "canonical_cpe",
        "cpe",
        "to_cpe",
        "target_cpe",
        "canonical",
        "to",
    )
    if alias_cpe is None or canonical_cpe is None:
        raise ValueError("alias requires both alias_cpe and canonical_cpe")
    ticket_id = _first(raw, "ticket_id", "change_id")
    asset_id = _first(raw, "asset_id", "device_id")
    if ticket:
        ticket_id = ticket_id or _first(ticket, "ticket_id", "change_id", "id")
        asset_id = asset_id or _first(ticket, "asset_id", "device_id")
    effective_at = _as_datetime(
        _first(raw, "effective_at", "valid_from", "known_at")
    )
    if ticket and effective_at is None:
        effective_at = _as_datetime(
            _first(
                ticket,
                "starts_at",
                "start",
                "window_start",
                "from",
                "start_time",
                "maintenance_start",
            )
        )
    return Alias(
        alias_cpe=_text(alias_cpe),
        canonical_cpe=_text(canonical_cpe),
        effective_at=effective_at,
        recorded_at=_as_datetime(
            _first(raw, "recorded_at", "created_at", "recorded")
        ),
        expires_at=_as_datetime(_first(raw, "expires_at", "valid_to")),
        ticket_id=_text(ticket_id) if ticket_id is not None else None,
        asset_id=_text(asset_id) if asset_id is not None else None,
        component_id=(
            _text(_first(raw, "component_id", "component"))
            if _first(raw, "component_id", "component") is not None
            else None
        ),
        alias_id=(
            _text(_first(raw, "alias_id", "id"))
            if _first(raw, "alias_id", "id") is not None
            else None
        ),
    )


def _normalise_alias_values(
    values: Any,
    ticket: Optional[Mapping[str, Any]] = None,
) -> List[Alias]:
    if values is None:
        return []
    if isinstance(values, Mapping):
        alias_keys = {
            "alias_cpe",
            "alias",
            "from_cpe",
            "source_cpe",
            "canonical_cpe",
            "to_cpe",
            "target_cpe",
        }
        if alias_keys.intersection(values):
            return [_normalise_alias(values, ticket)]
        expanded = []
        for alias_cpe, canonical_cpe in values.items():
            if isinstance(canonical_cpe, Mapping):
                item = dict(canonical_cpe)
                item.setdefault("alias_cpe", alias_cpe)
            else:
                item = {
                    "alias_cpe": alias_cpe,
                    "canonical_cpe": canonical_cpe,
                }
            expanded.append(item)
        return [_normalise_alias(item, ticket) for item in expanded]
    return [
        _normalise_alias(item, ticket) for item in _as_tuple(values)
    ]


def _normalise_ticket(raw: Any) -> ChangeTicket:
    if isinstance(raw, ChangeTicket):
        return ChangeTicket(
            ticket_id=_text(raw.ticket_id),
            asset_id=_text(raw.asset_id),
            starts_at=_as_datetime(raw.starts_at),
            ends_at=_as_datetime(raw.ends_at),
            planned_components=tuple(_text(item) for item in raw.planned_components),
            component_ids=tuple(_text(item) for item in raw.component_ids),
            aliases=tuple(raw.aliases),
            previous_ticket_id=raw.previous_ticket_id,
            chain_id=raw.chain_id,
            source_cpes=dict(raw.source_cpes),
            target_cpes=dict(raw.target_cpes),
            metadata=raw.metadata,
        )
    if not isinstance(raw, Mapping):
        raise TypeError("change ticket must be a ChangeTicket or mapping")
    ticket_id = _first(raw, "ticket_id", "change_id", "id")
    asset_id = _first(raw, "asset_id", "device_id")
    if ticket_id is None or asset_id is None:
        raise ValueError("ticket_id and asset_id are required")
    starts_at = _as_datetime(
        _first(
            raw,
            "starts_at",
            "start",
            "window_start",
            "from",
            "start_time",
            "maintenance_start",
        )
    )
    ends_at = _as_datetime(
        _first(
            raw,
            "ends_at",
            "end",
            "window_end",
            "to",
            "end_time",
            "maintenance_end",
        )
    )
    if starts_at is None or ends_at is None:
        raise ValueError("ticket {0} requires a start and end".format(ticket_id))
    if ends_at < starts_at:
        raise ValueError("ticket {0} ends before it starts".format(ticket_id))
    planned_components, component_ids = _normalise_planned(raw)
    aliases = tuple(
        _normalise_alias_values(
            _first(raw, "aliases", "cpe_aliases"),
            raw,
        )
    )
    return ChangeTicket(
        ticket_id=_text(ticket_id),
        asset_id=_text(asset_id),
        starts_at=starts_at,
        ends_at=ends_at,
        planned_components=planned_components,
        component_ids=component_ids,
        aliases=aliases,
        previous_ticket_id=(
            _text(
                _first(
                    raw,
                    "previous_ticket_id",
                    "predecessor_ticket_id",
                    "predecessor",
                )
            )
            if _first(
                raw,
                "previous_ticket_id",
                "predecessor_ticket_id",
                "predecessor",
            ) is not None
            else None
        ),
        chain_id=(
            _text(_first(raw, "chain_id"))
            if _first(raw, "chain_id") is not None
            else None
        ),
        source_cpes=dict(_first(raw, "source_cpes", "from_cpes", default={}) or {}),
        target_cpes=dict(_first(raw, "target_cpes", "to_cpes", default={}) or {}),
        metadata=_first(raw, "metadata", default={}) or {},
    )


def _normalise_ticket_values(values: Any) -> List[ChangeTicket]:
    if values is None:
        return []
    if isinstance(values, Mapping):
        if {
            "ticket_id",
            "change_id",
            "asset_id",
            "device_id",
            "starts_at",
            "start",
        }.intersection(values):
            return [_normalise_ticket(values)]
        expanded = []
        for ticket_id, value in values.items():
            if isinstance(value, Mapping):
                item = dict(value)
                item.setdefault("ticket_id", ticket_id)
            else:
                item = {"ticket_id": ticket_id, "asset_id": value}
            expanded.append(item)
        return [_normalise_ticket(item) for item in expanded]
    return [_normalise_ticket(item) for item in _as_tuple(values)]


def _normalise_observation(raw: Any) -> Observation:
    if isinstance(raw, Observation):
        return Observation(
            observation_id=_text(raw.observation_id),
            asset_id=_text(raw.asset_id),
            observed_at=_as_datetime(raw.observed_at),
            cpe=_text(raw.cpe) if raw.cpe is not None else None,
            kind=_text(raw.kind).lower(),
            component_id=(
                _text(raw.component_id) if raw.component_id is not None else None
            ),
            ticket_id=(
                _text(raw.ticket_id) if raw.ticket_id is not None else None
            ),
            ticket_ids=tuple(_text(item) for item in raw.ticket_ids),
            recorded_at=_as_datetime(raw.recorded_at),
            previous_observation_id=raw.previous_observation_id,
            chain_id=raw.chain_id,
            evidence_id=raw.evidence_id,
            gap_ends_at=_as_datetime(raw.gap_ends_at),
            metadata=raw.metadata,
        )
    if not isinstance(raw, Mapping):
        raise TypeError("observation must be an Observation or mapping")
    asset_id = _first(raw, "asset_id", "device_id")
    observed_at = _as_datetime(
        _first(raw, "observed_at", "at", "timestamp", "seen_at", "time")
    )
    if asset_id is None or observed_at is None:
        raise ValueError("observation asset_id and observed_at are required")
    cpe = _first(
        raw,
        "cpe",
        "cpe_name",
        "observed_cpe",
        "actual_cpe",
        "resulting_cpe",
        "cpe23Uri",
    )
    kind = _text(_first(raw, "kind", "type", "action", default="inventory")).lower()
    component_id = _first(raw, "component_id", "component")
    ticket_ids = tuple(
        _text(item)
        for item in _as_tuple(_first(raw, "ticket_ids", "change_ids"))
    )
    observation_id = _first(raw, "observation_id", "id")
    if observation_id is None:
        observation_id = _stable_auto_id(
            "obs",
            asset_id,
            _iso(observed_at),
            kind,
            component_id,
            cpe,
            _first(raw, "ticket_id", "change_id"),
            _first(raw, "evidence_id"),
        )
    ticket_id = _first(raw, "ticket_id", "change_id")
    return Observation(
        observation_id=_text(observation_id),
        asset_id=_text(asset_id),
        observed_at=observed_at,
        cpe=_text(cpe) if cpe is not None else None,
        kind=kind,
        component_id=_text(component_id) if component_id is not None else None,
        ticket_id=_text(ticket_id) if ticket_id is not None else None,
        ticket_ids=ticket_ids,
        recorded_at=_as_datetime(
            _first(raw, "recorded_at", "created_at", "recorded")
        ),
        previous_observation_id=(
            _text(
                _first(
                    raw,
                    "previous_observation_id",
                    "predecessor_id",
                    "parent_observation_id",
                )
            )
            if _first(
                raw,
                "previous_observation_id",
                "predecessor_id",
                "parent_observation_id",
            ) is not None
            else None
        ),
        chain_id=(
            _text(_first(raw, "chain_id"))
            if _first(raw, "chain_id") is not None
            else None
        ),
        evidence_id=(
            _text(_first(raw, "evidence_id"))
            if _first(raw, "evidence_id") is not None
            else None
        ),
        gap_ends_at=_as_datetime(_first(raw, "gap_ends_at", "ends_at")),
        metadata=_first(raw, "metadata", default={}) or {},
    )


def _normalise_observation_values(values: Any) -> List[Observation]:
    if values is None:
        return []
    if isinstance(values, Mapping):
        if {
            "asset_id",
            "device_id",
            "observed_at",
            "timestamp",
            "time",
        }.intersection(values):
            return [_normalise_observation(values)]
        expanded = []
        for observation_id, value in values.items():
            if isinstance(value, Mapping):
                item = dict(value)
                item.setdefault("observation_id", observation_id)
            else:
                item = {
                    "observation_id": observation_id,
                    "asset_id": value,
                }
            expanded.append(item)
        return [_normalise_observation(item) for item in expanded]
    return [_normalise_observation(item) for item in _as_tuple(values)]


def _normalise_announcement(raw: Any) -> Announcement:
    if isinstance(raw, Announcement):
        return Announcement(
            announcement_id=_text(raw.announcement_id),
            expression=_text(raw.expression),
            published_at=_as_datetime(raw.published_at),
            title=raw.title,
            metadata=raw.metadata,
        )
    if not isinstance(raw, Mapping):
        raise TypeError("announcement must be an Announcement or mapping")
    announcement_id = _first(
        raw,
        "announcement_id",
        "advisory_id",
        "id",
        "cve_id",
        "cve",
    )
    expression = _first(
        raw,
        "expression",
        "cpe",
        "cpe_name",
        "match",
        "match_expression",
        "cpe_expression",
        "cpe23Uri",
        "cpe23_uri",
        "cpe_uri",
    )
    if announcement_id is None or expression is None:
        raise ValueError("announcement_id and expression are required")
    return Announcement(
        announcement_id=_text(announcement_id),
        expression=_text(expression),
        published_at=_as_datetime(_first(raw, "published_at", "published")),
        title=_first(raw, "title"),
        metadata=_first(raw, "metadata", default={}) or {},
    )


def _normalise_announcement_values(values: Any) -> List[Announcement]:
    if values is None:
        return []
    if isinstance(values, Mapping):
        if any(
            key in values
            for key in (
                "announcement_id",
                "advisory_id",
                "id",
                "expression",
                "cpe",
                "cpe_name",
            )
        ):
            return [_normalise_announcement(values)]
        expanded = []
        for announcement_id, expression in values.items():
            if isinstance(expression, Mapping):
                item = dict(expression)
                item.setdefault("announcement_id", announcement_id)
            else:
                item = {
                    "announcement_id": announcement_id,
                    "expression": expression,
                }
            expanded.append(item)
        return [_normalise_announcement(item) for item in expanded]
    result = []
    for item in _as_tuple(values):
        if isinstance(item, str):
            result.append(
                Announcement(
                    announcement_id=_stable_auto_id(
                        "announcement", item
                    ),
                    expression=item,
                )
            )
        else:
            result.append(_normalise_announcement(item))
    return result


def _payload_observations(payload: Mapping[str, Any]) -> List[Any]:
    values = list(
        _as_tuple(
            _first(
                payload,
                "observations",
                "actual_observations",
                "change_observations",
                default=[],
            )
        )
    )
    for key, kind in (
        ("upgrade_observations", "upgrade"),
        ("upgrades", "upgrade"),
        ("rollback_observations", "rollback"),
        ("rollbacks", "rollback"),
    ):
        for item in _as_tuple(_first(payload, key, default=[])):
            if isinstance(item, Mapping):
                item = dict(item)
                item.setdefault("kind", kind)
            values.append(item)
    return values


def _dedupe(values: Iterable[Any]) -> List[Any]:
    result: List[Any] = []
    seen = set()
    for value in values:
        marker = _text(value)
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def _dedupe_observations(values: Iterable[Observation]) -> List[Observation]:
    """Deduplicate observations without hashing their metadata mappings."""
    result: List[Observation] = []
    seen = set()
    for value in values:
        if value.observation_id in seen:
            continue
        seen.add(value.observation_id)
        result.append(value)
    result.sort(key=lambda item: (item.observed_at, item.observation_id))
    return result


def _looks_like_cpe(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith("cpe:") or lowered.startswith("wfn:")


def _split_escaped(value: str, separator: str = ":") -> List[str]:
    fields: List[str] = []
    current: List[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == separator:
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def _quoted_wfn_value(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


def _wfn_from_fs(cpe_name: str) -> Optional[CPE2_3_WFN]:
    prefix = "cpe:2.3:"
    if not cpe_name.lower().startswith(prefix):
        return None
    fields = _split_escaped(cpe_name[len(prefix):])
    if not 3 <= len(fields) <= len(_ATTR_ORDER):
        return None
    fields.extend(["*"] * (len(_ATTR_ORDER) - len(fields)))
    pairs = []
    for attribute, value in zip(_ATTR_ORDER, fields):
        if value == "*":
            pairs.append("{0}=ANY".format(attribute))
        elif value == "-":
            pairs.append("{0}=NA".format(attribute))
        else:
            pairs.append("{0}={1}".format(attribute, _quoted_wfn_value(value)))
    return CPE2_3_WFN("wfn:[{0}]".format(", ".join(pairs)))


def _wfn_from_uri(cpe_name: str) -> Optional[CPE2_3_WFN]:
    lowered = cpe_name.lower()
    if not lowered.startswith("cpe:/"):
        return None
    attributes = (
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "language",
    )
    fields = _split_escaped(cpe_name[5:])
    if not fields or len(fields) > len(attributes):
        return None
    pairs = []
    for attribute, value in zip(attributes, fields):
        if value in ("", "*"):
            pairs.append("{0}=ANY".format(attribute))
        elif value == "-":
            pairs.append("{0}=NA".format(attribute))
        else:
            pairs.append(
                "{0}={1}".format(
                    attribute,
                    _quoted_wfn_value(unquote(value)),
                )
            )
    return CPE2_3_WFN("wfn:[{0}]".format(", ".join(pairs)))


def _wfn(cpe_name: str) -> CPE2_3_WFN:
    try:
        parsed = CPE(cpe_name)
        return CPE2_3_WFN(parsed.as_wfn())
    except (ValueError, NotImplementedError):
        fallback = _wfn_from_fs(cpe_name) or _wfn_from_uri(cpe_name)
        if fallback is None:
            raise
        return fallback


def _cpe_identity_key(cpe_name: str) -> Optional[str]:
    try:
        parsed = CPE(cpe_name)
    except Exception:
        return None
    values = []
    for attribute in ("part", "vendor", "product", "target_sw", "target_hw"):
        try:
            value = parsed.get_attribute_values(attribute)
        except Exception:
            value = []
        if value:
            values.append(_text(value[0]).strip('"').lower())
    if not values:
        return None
    return "|".join(values)


def _attribute_value(wfn: CPE2_3_WFN, attribute: str) -> str:
    value = wfn.get_attribute_values(attribute)[0]
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _match_cpe(expression: str, observed_cpe: str) -> _Match:
    """Return whether the CPE expression contains the observed CPE name."""
    try:
        expression_wfn = _wfn(expression)
        observed_wfn = _wfn(observed_cpe)
    except Exception as exc:
        return _Match(False, reason="invalid CPE: {0}".format(exc))
    if not CPESet2_3.cpe_superset(expression_wfn, observed_wfn):
        return _Match(False)

    fields: List[Mapping[str, Any]] = []
    relations = dict(CPESet2_3.compare_wfns(expression_wfn, observed_wfn))
    for attribute in _ATTR_ORDER:
        expression_value = _attribute_value(expression_wfn, attribute)
        observed_value = _attribute_value(observed_wfn, attribute)
        if expression_value in ("ANY", "NA"):
            continue
        relation = relations.get(attribute)
        if relation in (
            CPESet2_3.LOGICAL_VALUE_EQUAL,
            CPESet2_3.LOGICAL_VALUE_SUPERSET,
        ):
            fields.append(
                {
                    "attribute": attribute,
                    "expression_value": expression_value,
                    "observed_value": observed_value,
                }
            )
    return _Match(True, fields=tuple(fields))


def _resolve_cpe(
    cpe_name: str,
    when: datetime,
    aliases: Sequence[Alias],
    asset_id: str,
    component_id: Optional[str],
) -> Tuple[str, Tuple[str, ...], bool]:
    current = cpe_name
    used: List[str] = []
    invalid = False
    eligible = [
        alias for alias in aliases
        if alias.usable_at(when)
        and (alias.asset_id is None or alias.asset_id == asset_id)
        and (
            alias.component_id is None
            or component_id is None
            or alias.component_id == component_id
        )
    ]
    eligible.sort(
        key=lambda alias: (
            alias.effective_at or _MIN_TIME,
            alias.recorded_at or _MIN_TIME,
            alias.alias_id or "",
            alias.alias_cpe,
            alias.canonical_cpe,
        )
    )
    for _ in range(len(eligible) + 1):
        changed = False
        for alias in eligible:
            match = _match_cpe(alias.alias_cpe, current)
            if not match.matched:
                continue
            if match.reason:
                invalid = True
                continue
            if alias.canonical_cpe != current:
                current = alias.canonical_cpe
                alias_id = alias.alias_id or _stable_auto_id(
                    "alias",
                    alias.alias_cpe,
                    alias.canonical_cpe,
                    _iso(alias.effective_at),
                )
                if alias_id not in used:
                    used.append(alias_id)
                changed = True
                break
        if not changed:
            break
    return current, tuple(used), invalid


def _ticket_covers(
    ticket: ChangeTicket,
    component: _Component,
    actual_cpe: str,
) -> bool:
    if ticket.component_ids and component.component_id not in ticket.component_ids:
        return False
    if ticket.planned_components:
        if not any(
            _match_cpe(expression, actual_cpe).matched
            for expression in ticket.planned_components
        ):
            return False
    if not ticket.component_ids and not ticket.planned_components:
        return False
    return True


def _state_at(
    asset: Asset,
    component: _Component,
    when: datetime,
) -> _State:
    visible = [
        event for event in component.events
        if event.observed_at <= when and event.cpe
    ]
    last_event = visible[-1] if visible else None

    for starts_at, ends_at in asset.inventory_gaps:
        if starts_at <= when <= ends_at:
            if last_event is None or last_event.observed_at < starts_at:
                return _State(
                    False,
                    observation_ids=tuple(
                        event.observation_id for event in visible[-3:]
                    ),
                    reason="inventory gap at {0}".format(_iso(when)),
                )

    if last_event is not None:
        return _State(
            True,
            cpe=last_event.cpe,
            observation_ids=tuple(
                event.observation_id for event in visible[-3:]
            ),
        )
    if component.baseline_cpe is None:
        return _State(False, reason="no inventory or observation for component")
    if (
        asset.inventory_valid_until is not None
        and when > asset.inventory_valid_until
    ):
        return _State(
            False,
            reason="inventory expired at {0}".format(
                _iso(asset.inventory_valid_until)
            ),
        )
    if component.baseline_at is not None and when < component.baseline_at:
        return _State(False, reason="inventory is not yet valid")
    return _State(True, cpe=component.baseline_cpe)


def _component_for_observation(
    asset: Asset,
    components: Mapping[str, _Component],
    observation: Observation,
    tickets_by_id: Mapping[str, ChangeTicket],
    aliases: Sequence[Alias],
) -> Optional[str]:
    if observation.component_id:
        if observation.component_id not in components:
            components[observation.component_id] = _Component(
                observation.component_id,
                baseline_cpe=None,
                baseline_at=None,
            )
        return observation.component_id

    if len(components) == 1:
        return next(iter(components))
    if observation.cpe is None:
        return None

    resolved, _, _ = _resolve_cpe(
        observation.cpe,
        observation.observed_at,
        aliases,
        asset.asset_id,
        None,
    )
    identity = _cpe_identity_key(resolved)
    candidates = [
        component_id
        for component_id, component in components.items()
        if component.baseline_cpe
        and _cpe_identity_key(component.baseline_cpe) == identity
    ]
    if len(candidates) == 1:
        return candidates[0]

    ticket_ids = []
    if observation.ticket_id:
        ticket_ids.append(observation.ticket_id)
    ticket_ids.extend(observation.ticket_ids)
    plan_candidates = []
    for ticket_id in _dedupe(ticket_ids):
        ticket = tickets_by_id.get(ticket_id)
        if ticket is None:
            continue
        if ticket.component_ids:
            plan_candidates.extend(ticket.component_ids)
        elif ticket.planned_components:
            if any(
                _match_cpe(expression, resolved).matched
                for expression in ticket.planned_components
            ):
                plan_candidates.extend(components.keys())
    plan_candidates = _dedupe(plan_candidates)
    if len(plan_candidates) == 1 and plan_candidates[0] in components:
        return plan_candidates[0]

    dynamic_id = identity or _stable_auto_id("component", resolved)
    components[dynamic_id] = _Component(
        dynamic_id,
        baseline_cpe=None,
        baseline_at=None,
    )
    return dynamic_id


def _normalise_inputs(
    original_assets: Any,
    change_tickets: Any,
    observations: Any,
    announcements: Any,
    aliases: Any,
) -> Tuple[
    List[Asset],
    List[ChangeTicket],
    List[Observation],
    List[Announcement],
    List[Alias],
]:
    payload_keys = {
        "assets",
        "original_assets",
        "tickets",
        "change_tickets",
        "observations",
        "upgrade_observations",
        "rollback_observations",
        "announcements",
        "announcement_expressions",
    }
    if (
        change_tickets is None
        and isinstance(original_assets, Mapping)
        and payload_keys.intersection(original_assets)
    ):
        payload = original_assets
        original_assets = _first(payload, "assets", "original_assets", default=[])
        change_tickets = _first(
            payload, "tickets", "change_tickets", default=[]
        )
        observations = _payload_observations(payload)
        announcements = _first(
            payload,
            "announcements",
            "announcement_expressions",
            "advisories",
            default=[],
        )
        aliases = _first(payload, "aliases", "cpe_aliases", default=aliases)

    if isinstance(original_assets, Mapping):
        asset_values = []
        for asset_id, value in original_assets.items():
            if isinstance(value, Mapping):
                item = dict(value)
                item.setdefault("asset_id", asset_id)
            else:
                item = {"asset_id": asset_id, "cpe": value}
            asset_values.append(item)
        original_assets = asset_values

    assets = [_normalise_asset(raw) for raw in _as_tuple(original_assets)]
    tickets = _normalise_ticket_values(change_tickets)
    observation_list = _normalise_observation_values(observations)
    announcement_list = _normalise_announcement_values(announcements)
    alias_list = _normalise_alias_values(aliases)
    for ticket in tickets:
        alias_list.extend(ticket.aliases)
    for asset in assets:
        alias_list.extend(_normalise_alias_values(asset.aliases))

    assets.sort(key=lambda item: item.asset_id)
    tickets.sort(
        key=lambda item: (
            item.asset_id,
            item.starts_at,
            item.ends_at,
            item.ticket_id,
        )
    )
    observation_list.sort(
        key=lambda item: (
            item.asset_id,
            item.observed_at,
            item.observation_id,
        )
    )
    announcement_list.sort(key=lambda item: item.announcement_id)

    alias_list = sorted(
        alias_list,
        key=lambda alias: (
            alias.effective_at or _MIN_TIME,
            alias.recorded_at or _MIN_TIME,
            alias.alias_id or "",
            alias.alias_cpe,
            alias.canonical_cpe,
        ),
    )
    return assets, tickets, observation_list, announcement_list, alias_list


def _build_components(
    asset: Asset,
    tickets: Sequence[ChangeTicket],
    observations: Sequence[Observation],
    aliases: Sequence[Alias],
) -> Tuple[Dict[str, _Component], List[Tuple[Observation, str]]]:
    components: Dict[str, _Component] = {
        component_id: _Component(
            component_id,
            baseline_cpe=cpe,
            baseline_at=asset.inventory_at,
        )
        for component_id, cpe in asset.components.items()
    }
    tickets_by_id = {ticket.ticket_id: ticket for ticket in tickets}
    ambiguous: List[Tuple[Observation, str]] = []
    for observation in observations:
        if observation.kind in ("missing", "inventory_gap", "gap"):
            continue
        if not observation.cpe:
            ambiguous.append((observation, "observation has no CPE"))
            continue
        component_id = _component_for_observation(
            asset, components, observation, tickets_by_id, aliases
        )
        if component_id is None:
            ambiguous.append((observation, "observation cannot be mapped"))
            continue
        components[component_id].events.append(observation)

    for component in components.values():
        component.events.sort(
            key=lambda event: (
                event.observed_at,
                event.observation_id,
                event.kind,
                event.cpe or "",
                event.ticket_id or "",
            )
        )
    return components, ambiguous


def _ticket_observations(
    ticket: ChangeTicket,
    component: _Component,
    observations: Sequence[Observation],
    asset: Asset,
    aliases: Sequence[Alias],
) -> List[Observation]:
    result = []
    for observation in observations:
        if observation.cpe is None:
            continue
        if observation.observed_at < ticket.starts_at:
            continue
        if observation.observed_at > ticket.ends_at:
            continue
        ticket_ids = set(observation.ticket_ids)
        if observation.ticket_id:
            ticket_ids.add(observation.ticket_id)
        if ticket_ids and ticket.ticket_id not in ticket_ids:
            continue
        resolved, _, _ = _resolve_cpe(
            observation.cpe,
            observation.observed_at,
            aliases,
            asset.asset_id,
            component.component_id,
        )
        if ticket.component_ids:
            if component.component_id not in ticket.component_ids:
                continue
        elif not ticket.planned_components:
            continue
        if ticket.planned_components and not any(
            _match_cpe(expression, resolved).matched
            for expression in ticket.planned_components
        ):
            continue
        result.append(observation)
    return result


def _build_evidence_chains(
    assets: Sequence[Asset],
    tickets: Sequence[ChangeTicket],
    observations: Sequence[Observation],
    aliases: Sequence[Alias],
    as_of: Optional[datetime] = None,
) -> List[EvidenceChain]:
    if as_of is not None:
        observations = [
            observation for observation in observations
            if observation.observed_at <= as_of
        ]
    chains: List[EvidenceChain] = []
    tickets_by_asset: Dict[str, List[ChangeTicket]] = defaultdict(list)
    for ticket in tickets:
        tickets_by_asset[ticket.asset_id].append(ticket)

    for asset in assets:
        asset_tickets = sorted(
            tickets_by_asset.get(asset.asset_id, []),
            key=lambda ticket: (
                ticket.starts_at,
                ticket.ends_at,
                ticket.ticket_id,
            ),
        )
        components, _ = _build_components(
            asset, asset_tickets, observations, aliases
        )
        for previous, current in zip(asset_tickets, asset_tickets[1:]):
            explicit_link = current.previous_ticket_id == previous.ticket_id
            shared_chain = bool(
                previous.chain_id
                and current.chain_id
                and previous.chain_id == current.chain_id
            )
            evidence_ids: List[str] = []
            reason = ""

            previous_observations = []
            current_observations = []
            for component in components.values():
                previous_observations.extend(
                    _ticket_observations(
                        previous, component, observations, asset, aliases
                    )
                )
                current_observations.extend(
                    _ticket_observations(
                        current, component, observations, asset, aliases
                    )
                )
            previous_observations = _dedupe_observations(previous_observations)
            current_observations = _dedupe_observations(current_observations)

            if previous_observations and current_observations:
                previous_ids = {
                    marker
                    for item in previous_observations
                    for marker in (item.observation_id, item.evidence_id)
                    if marker
                }
                linked = [
                    item for item in current_observations
                    if item.previous_observation_id in previous_ids
                ]
                if linked:
                    for item in linked:
                        evidence_ids.extend(
                            [item.previous_observation_id, item.observation_id]
                        )
                    reason = "rollback/upgrade observation links to the earlier change"
                else:
                    previous_markers = {
                        marker
                        for item in previous_observations
                        for marker in (item.chain_id, item.evidence_id)
                        if marker
                    }
                    current_markers = {
                        marker
                        for item in current_observations
                        for marker in (item.chain_id, item.evidence_id)
                        if marker
                    }
                    shared_markers = previous_markers.intersection(current_markers)
                    if shared_markers:
                        for item in previous_observations[-1:]:
                            evidence_ids.append(item.observation_id)
                        for item in current_observations[:1]:
                            evidence_ids.append(item.observation_id)
                        reason = "observations share a change evidence marker"
                    for component_id in components:
                        previous_state = _state_at(
                            asset, components[component_id], previous.ends_at
                        )
                        current_state = _state_at(
                            asset, components[component_id], current.starts_at
                        )
                        if previous_state.known and current_state.known:
                            previous_resolved, _, _ = _resolve_cpe(
                                previous_state.cpe,
                                previous.ends_at,
                                aliases,
                                asset.asset_id,
                                component_id,
                            )
                            current_resolved, _, _ = _resolve_cpe(
                                current_state.cpe,
                                current.starts_at,
                                aliases,
                                asset.asset_id,
                                component_id,
                            )
                            if previous_resolved == current_resolved:
                                evidence_ids.extend(
                                    previous_state.observation_ids
                                )
                                evidence_ids.extend(current_state.observation_ids)
                                reason = (
                                    "the observed state is continuous at the "
                                    "ticket boundary"
                                )
                                break

            if explicit_link and previous_observations and current_observations:
                for item in previous_observations[-1:]:
                    evidence_ids.append(item.observation_id)
                for item in current_observations[:1]:
                    evidence_ids.append(item.observation_id)
                reason = reason or "ticket explicitly references its predecessor"

            if shared_chain and previous_observations and current_observations:
                for item in previous_observations[-1:]:
                    evidence_ids.append(item.observation_id)
                for item in current_observations[:1]:
                    evidence_ids.append(item.observation_id)
                reason = reason or "tickets share a change evidence chain"

            if not evidence_ids and previous.target_cpes and current.source_cpes:
                for component_id, target in previous.target_cpes.items():
                    source = current.source_cpes.get(component_id)
                    if source and target == source:
                        for item in previous_observations[-1:]:
                            evidence_ids.append(item.observation_id)
                        for item in current_observations[:1]:
                            evidence_ids.append(item.observation_id)
                        reason = "the later ticket starts from the earlier ticket target"
                        break

            evidence_ids = _dedupe(evidence_ids)
            verified = bool(evidence_ids)
            if verified:
                chains.append(
                    EvidenceChain(
                        asset_id=asset.asset_id,
                        ticket_ids=(previous.ticket_id, current.ticket_id),
                        status=CHAIN_VERIFIED,
                        observation_ids=tuple(evidence_ids),
                        reason=reason,
                    )
                )
            else:
                missing = "inventory gap between changes"
                if not previous_observations or not current_observations:
                    missing = "missing observation interval for one of the changes"
                chains.append(
                    EvidenceChain(
                        asset_id=asset.asset_id,
                        ticket_ids=(previous.ticket_id, current.ticket_id),
                        status=CHAIN_MANUAL_REVIEW,
                        reason=missing,
                    )
                )
    return chains


def _manual_covering_tickets(chains: Sequence[EvidenceChain]) -> set:
    manual = set()
    for chain in chains:
        if not chain.chained:
            manual.add(chain.ticket_ids[1])
    return manual


def _deferral_ticket(
    asset: Asset,
    component: _Component,
    announcement: Announcement,
    when: datetime,
    ticket: ChangeTicket,
    aliases: Sequence[Alias],
) -> Optional[Tuple[str, str, Tuple[str, ...]]]:
    if not ticket.contains(when):
        return None
    state = _state_at(asset, component, when)
    if not state.known or not state.cpe:
        return None
    resolved, alias_ids, invalid = _resolve_cpe(
        state.cpe,
        when,
        aliases,
        asset.asset_id,
        component.component_id,
    )
    if invalid:
        return None
    announcement_match = _match_cpe(announcement.expression, resolved)
    if not announcement_match.matched:
        return None
    if not _ticket_covers(ticket, component, resolved):
        return None
    return state.cpe, resolved, alias_ids


def _historical_deferrals(
    assets: Sequence[Asset],
    tickets: Sequence[ChangeTicket],
    components_by_asset: Mapping[str, Mapping[str, _Component]],
    observations: Sequence[Observation],
    announcements: Sequence[Announcement],
    aliases: Sequence[Alias],
    as_of: datetime,
    manual_ticket_ids: set,
) -> List[DeferralEvent]:
    events: Dict[Tuple[str, str, Optional[str], str], DeferralEvent] = {}
    observation_times = sorted(
        {observation.observed_at for observation in observations}
    )
    for asset in assets:
        components = components_by_asset.get(asset.asset_id, {})
        asset_tickets = [ticket for ticket in tickets if ticket.asset_id == asset.asset_id]
        for ticket in asset_tickets:
            if ticket.ticket_id in manual_ticket_ids:
                continue
            times = {ticket.starts_at, ticket.ends_at, min(as_of, ticket.ends_at)}
            times.update(
                when for when in observation_times
                if ticket.starts_at <= when <= min(as_of, ticket.ends_at)
            )
            for component in components.values():
                for announcement in announcements:
                    for when in sorted(times):
                        covered = _deferral_ticket(
                            asset,
                            component,
                            announcement,
                            when,
                            ticket,
                            aliases,
                        )
                        if covered is None:
                            continue
                        observed_cpe, _, _ = covered
                        key = (
                            asset.asset_id,
                            announcement.announcement_id,
                            component.component_id,
                            ticket.ticket_id,
                        )
                        existing = events.get(key)
                        if existing is None:
                            events[key] = DeferralEvent(
                                asset_id=asset.asset_id,
                                announcement_id=announcement.announcement_id,
                                component_id=component.component_id,
                                ticket_id=ticket.ticket_id,
                                decided_at=when,
                                observed_cpe=observed_cpe,
                                expression=announcement.expression,
                            )
    return sorted(
        events.values(),
        key=lambda event: (
            event.asset_id,
            event.announcement_id,
            event.component_id or "",
            event.ticket_id,
        ),
    )


def _make_decision(
    asset: Asset,
    component: _Component,
    announcement: Announcement,
    when: datetime,
    tickets: Sequence[ChangeTicket],
    aliases: Sequence[Alias],
    manual_ticket_ids: set,
    deferral_events: Sequence[DeferralEvent],
) -> AdjudicationDecision:
    if announcement.published_at is not None and announcement.published_at > when:
        return AdjudicationDecision(
            asset_id=asset.asset_id,
            announcement_id=announcement.announcement_id,
            component_id=component.component_id,
            status=STATUS_CLEAR,
            announcement_expression=announcement.expression,
            reason="announcement is not published at the evaluation time",
        )

    state = _state_at(asset, component, when)
    if not state.known or not state.cpe:
        return AdjudicationDecision(
            asset_id=asset.asset_id,
            announcement_id=announcement.announcement_id,
            component_id=component.component_id,
            status=STATUS_MANUAL_REVIEW,
            announcement_expression=announcement.expression,
            observation_ids=state.observation_ids,
            reason=state.reason or "asset state is unknown",
            metadata={"manual_reason": "inventory_gap"},
        )

    resolved, alias_ids, alias_invalid = _resolve_cpe(
        state.cpe,
        when,
        aliases,
        asset.asset_id,
        component.component_id,
    )
    if alias_invalid:
        return AdjudicationDecision(
            asset_id=asset.asset_id,
            announcement_id=announcement.announcement_id,
            component_id=component.component_id,
            status=STATUS_MANUAL_REVIEW,
            announcement_expression=announcement.expression,
            observed_cpe=state.cpe,
            resolved_cpe=resolved,
            observation_ids=state.observation_ids,
            reason="one or more CPE aliases are invalid",
            metadata={"manual_reason": "invalid_alias"},
        )

    match = _match_cpe(announcement.expression, resolved)
    if match.reason:
        return AdjudicationDecision(
            asset_id=asset.asset_id,
            announcement_id=announcement.announcement_id,
            component_id=component.component_id,
            status=STATUS_MANUAL_REVIEW,
            announcement_expression=announcement.expression,
            observed_cpe=state.cpe,
            resolved_cpe=resolved,
            observation_ids=state.observation_ids,
            reason=match.reason,
            metadata={"manual_reason": "invalid_cpe"},
        )
    if not match.matched:
        return AdjudicationDecision(
            asset_id=asset.asset_id,
            announcement_id=announcement.announcement_id,
            component_id=component.component_id,
            status=STATUS_CLEAR,
            announcement_expression=announcement.expression,
            observed_cpe=state.cpe,
            resolved_cpe=resolved,
            alias_ids=alias_ids,
            observation_ids=state.observation_ids,
            reason="announcement does not match the current CPE",
        )

    covering = []
    for ticket in tickets:
        if ticket.asset_id != asset.asset_id or not ticket.contains(when):
            continue
        if _ticket_covers(ticket, component, resolved):
            covering.append(ticket)
    covering.sort(key=lambda ticket: (ticket.starts_at, ticket.ends_at, ticket.ticket_id))
    verified = [
        ticket for ticket in covering
        if ticket.ticket_id not in manual_ticket_ids
    ]

    prior_events = [
        event for event in deferral_events
        if event.asset_id == asset.asset_id
        and event.announcement_id == announcement.announcement_id
        and event.component_id == component.component_id
    ]
    prior_ticket_ids = tuple(
        sorted({event.ticket_id for event in prior_events})
    )
    returned = bool(prior_events)

    if covering and any(
        ticket.ticket_id in manual_ticket_ids for ticket in covering
    ):
        primary = covering[-1]
        return AdjudicationDecision(
            asset_id=asset.asset_id,
            announcement_id=announcement.announcement_id,
            component_id=component.component_id,
            status=STATUS_MANUAL_REVIEW,
            announcement_expression=announcement.expression,
            observed_cpe=state.cpe,
            resolved_cpe=resolved,
            ticket_id=primary.ticket_id,
            window_start=primary.starts_at,
            window_end=primary.ends_at,
            deferral_ticket_ids=prior_ticket_ids,
            returned_after_deferral=False,
            matched_fields=match.fields,
            alias_ids=alias_ids,
            observation_ids=state.observation_ids,
            reason=(
                "overlapping change {0} covers the component and window, but "
                "the consecutive changes lack chainable evidence"
            ).format(primary.ticket_id),
            metadata={"manual_reason": "missing_chain_evidence"},
        )

    if verified:
        primary = verified[-1]
        return AdjudicationDecision(
            asset_id=asset.asset_id,
            announcement_id=announcement.announcement_id,
            component_id=component.component_id,
            status=STATUS_DEFERRED,
            announcement_expression=announcement.expression,
            observed_cpe=state.cpe,
            resolved_cpe=resolved,
            ticket_id=primary.ticket_id,
            window_start=primary.starts_at,
            window_end=primary.ends_at,
            deferral_ticket_ids=tuple(
                ticket.ticket_id for ticket in verified
            ),
            returned_after_deferral=False,
            matched_fields=match.fields,
            alias_ids=alias_ids,
            observation_ids=state.observation_ids,
            reason=(
                "matched {0} and deferred by ticket {1} for planned component "
                "{2} inside {3}..{4}"
            ).format(
                announcement.expression,
                primary.ticket_id,
                component.component_id,
                _iso(primary.starts_at),
                _iso(primary.ends_at),
            ),
            metadata={"covering_ticket_ids": [t.ticket_id for t in covering]},
        )

    if covering:
        primary = covering[-1]
        return AdjudicationDecision(
            asset_id=asset.asset_id,
            announcement_id=announcement.announcement_id,
            component_id=component.component_id,
            status=STATUS_MANUAL_REVIEW,
            announcement_expression=announcement.expression,
            observed_cpe=state.cpe,
            resolved_cpe=resolved,
            ticket_id=primary.ticket_id,
            window_start=primary.starts_at,
            window_end=primary.ends_at,
            deferral_ticket_ids=prior_ticket_ids,
            returned_after_deferral=False,
            matched_fields=match.fields,
            alias_ids=alias_ids,
            observation_ids=state.observation_ids,
            reason=(
                "ticket {0} covers the component and window, but consecutive "
                "changes lack chainable evidence"
            ).format(primary.ticket_id),
            metadata={"manual_reason": "missing_chain_evidence"},
        )

    if returned:
        ticket = sorted(
            prior_events, key=lambda event: (event.decided_at, event.ticket_id)
        )[-1]
        reason = (
            "matched {0}; advisory returned after deferral in ticket {1} "
            "when component {2} ended at {3}"
        ).format(
            announcement.expression,
            ticket.ticket_id,
            component.component_id,
            resolved,
        )
    else:
        reason = "matched {0}; no active planned change covers component {1}".format(
            announcement.expression,
            component.component_id,
        )

    return AdjudicationDecision(
        asset_id=asset.asset_id,
        announcement_id=announcement.announcement_id,
        component_id=component.component_id,
        status=STATUS_REMEDIATION,
        announcement_expression=announcement.expression,
        observed_cpe=state.cpe,
        resolved_cpe=resolved,
        deferral_ticket_ids=prior_ticket_ids,
        returned_after_deferral=returned,
        matched_fields=match.fields,
        alias_ids=alias_ids,
        observation_ids=state.observation_ids,
        reason=reason,
    )


def adjudicate_announcements(
    original_assets: Any,
    change_tickets: Any = None,
    observations: Any = None,
    announcements: Any = None,
    aliases: Any = None,
    as_of: Any = None,
) -> AdjudicationResult:
    """Adjudicate announcements against assets, tickets, and observations.

    The function accepts either a payload mapping with the keys ``assets``,
    ``tickets``, ``observations``, ``announcements``, and optional ``aliases``,
    or four positional sequences.  Input order is irrelevant.  CPE matching is
    performed with the package's CPE 2.3 name matcher.
    """

    if (
        as_of is None
        and aliases is not None
        and isinstance(aliases, (datetime, str))
    ):
        as_of = aliases
        aliases = None
    if as_of is None and isinstance(original_assets, Mapping):
        as_of = _first(original_assets, "as_of", "evaluated_at")

    (
        asset_list,
        ticket_list,
        observation_list,
        announcement_list,
        alias_list,
    ) = _normalise_inputs(
        original_assets,
        change_tickets,
        observations,
        announcements,
        aliases,
    )

    event_times = [observation.observed_at for observation in observation_list]
    event_times.extend(
        asset.inventory_at for asset in asset_list if asset.inventory_at is not None
    )
    event_times.extend(
        asset.inventory_valid_until
        for asset in asset_list
        if asset.inventory_valid_until is not None
    )
    event_times.extend(ticket.ends_at for ticket in ticket_list)
    event_times.extend(ticket.starts_at for ticket in ticket_list)
    event_times.extend(
        announcement.published_at
        for announcement in announcement_list
        if announcement.published_at is not None
    )
    if as_of is None:
        when = max(event_times) if event_times else _MIN_TIME
    else:
        when = _as_datetime(as_of)

    evidence_chains = _build_evidence_chains(
        asset_list,
        ticket_list,
        observation_list,
        alias_list,
        as_of=when,
    )
    manual_ticket_ids = _manual_covering_tickets(evidence_chains)

    components_by_asset: Dict[str, Dict[str, _Component]] = {}
    ambiguous_by_asset: Dict[str, List[Tuple[Observation, str]]] = {}
    for asset in asset_list:
        asset_tickets = [
            ticket for ticket in ticket_list
            if ticket.asset_id == asset.asset_id
        ]
        components, ambiguous = _build_components(
            asset, asset_tickets, observation_list, alias_list
        )
        components_by_asset[asset.asset_id] = components
        ambiguous_by_asset[asset.asset_id] = ambiguous

    deferral_events = _historical_deferrals(
        asset_list,
        ticket_list,
        components_by_asset,
        observation_list,
        announcement_list,
        alias_list,
        when,
        manual_ticket_ids,
    )

    decisions: List[AdjudicationDecision] = []
    for asset in asset_list:
        components = components_by_asset.get(asset.asset_id, {})
        for component in components.values():
            for announcement in announcement_list:
                decisions.append(
                    _make_decision(
                        asset,
                        component,
                        announcement,
                        when,
                        ticket_list,
                        alias_list,
                        manual_ticket_ids,
                        deferral_events,
                    )
                )

        for observation, reason in ambiguous_by_asset.get(asset.asset_id, []):
            for announcement in announcement_list:
                decisions.append(
                    AdjudicationDecision(
                        asset_id=asset.asset_id,
                        announcement_id=announcement.announcement_id,
                        component_id=observation.component_id,
                        status=STATUS_MANUAL_REVIEW,
                        announcement_expression=announcement.expression,
                        observed_cpe=observation.cpe,
                        observation_ids=(observation.observation_id,),
                        reason="{0}: {1}".format(reason, observation.observation_id),
                        metadata={"manual_reason": "ambiguous_observation"},
                    )
                )

    decisions.sort(
        key=lambda decision: (
            decision.asset_id,
            decision.announcement_id,
            decision.component_id or "",
            decision.status,
            decision.announcement_expression or "",
        )
    )
    return AdjudicationResult(
        as_of=when,
        decisions=tuple(decisions),
        deferral_events=tuple(deferral_events),
        evidence_chains=tuple(evidence_chains),
    )


def export_remediation_list(
    original_assets: Any,
    change_tickets: Any = None,
    observations: Any = None,
    announcements: Any = None,
    aliases: Any = None,
    as_of: Any = None,
) -> List[Dict[str, Any]]:
    """Run the adjudicator and return only the stable remediation list."""

    return adjudicate_announcements(
        original_assets,
        change_tickets,
        observations,
        announcements,
        aliases,
        as_of,
    ).remediation_list()


class ChangeAwareAnnouncementEvaluator:
    """Reusable object form of :func:`adjudicate_announcements`."""

    def __init__(
        self,
        original_assets: Any,
        change_tickets: Any = None,
        announcements: Any = None,
        aliases: Any = None,
    ):
        self.original_assets = original_assets
        self.change_tickets = change_tickets
        self.announcements = announcements
        self.aliases = aliases

    def evaluate(self, observations: Any, as_of: Any = None) -> AdjudicationResult:
        return adjudicate_announcements(
            self.original_assets,
            self.change_tickets,
            observations,
            self.announcements,
            self.aliases,
            as_of,
        )


def dumps(result: AdjudicationResult) -> str:
    """Serialize a result deterministically as JSON."""

    return json.dumps(
        result.to_dict(),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """JSON command-line entry point.

    ``python -m cpe.change_adjudication`` reads one payload from a file (or
    stdin), runs the adjudicator, and writes deterministic JSON to stdout.
    ``--remediation-only`` emits the exported remediation work list by itself.
    """

    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Adjudicate CPE announcements during change windows"
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="JSON payload path, or '-' for stdin (default)",
    )
    parser.add_argument(
        "--as-of",
        dest="as_of",
        help="evaluation time in ISO-8601; defaults to the latest input event",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="output path, or '-' for stdout (default)",
    )
    parser.add_argument(
        "--remediation-only",
        action="store_true",
        help="write only the stable remediation list",
    )
    args = parser.parse_args(argv)

    if args.input == "-":
        payload = json.load(sys.stdin)
    else:
        with open(args.input, encoding="utf-8") as handle:
            payload = json.load(handle)

    result = adjudicate_announcements(payload, as_of=args.as_of)
    output = result.remediation_list() if args.remediation_only else result.to_dict()
    rendered = json.dumps(
        output,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    if args.output == "-":
        sys.stdout.write(rendered + "\n")
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    return 0


# Readable aliases for callers that use the domain terms directly.
ChangeAdjudicator = ChangeAwareAnnouncementEvaluator
AnnouncementDeferralAdjudicator = ChangeAwareAnnouncementEvaluator
adjudicate_changes = adjudicate_announcements
evaluate_announcements = adjudicate_announcements
adjudicate_change_announcements = adjudicate_announcements
evaluate_change_announcements = adjudicate_announcements
build_remediation_list = export_remediation_list
export_work_list = export_remediation_list


__all__ = [
    "Alias",
    "Announcement",
    "AnnouncementDeferralAdjudicator",
    "Asset",
    "ChangeAdjudicator",
    "ChangeAwareAnnouncementEvaluator",
    "ChangeTicket",
    "DeferralEvent",
    "EvidenceChain",
    "MatchEvidence",
    "Observation",
    "AdjudicationDecision",
    "AdjudicationResult",
    "STATUS_CLEAR",
    "STATUS_DEFERRED",
    "STATUS_MANUAL_REVIEW",
    "STATUS_REMEDIATION",
    "adjudicate_announcements",
    "adjudicate_change_announcements",
    "adjudicate_changes",
    "build_remediation_list",
    "dumps",
    "evaluate_announcements",
    "evaluate_change_announcements",
    "export_remediation_list",
    "export_work_list",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
