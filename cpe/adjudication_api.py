# -*- coding: utf-8 -*-
"""Convenience API and naming aliases for change-window adjudication."""

from __future__ import absolute_import, unicode_literals

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .change_adjudication import (
    CHAIN_MANUAL_REVIEW,
    CHAIN_VERIFIED,
    STATUS_CLEAR,
    STATUS_DEFERRED,
    STATUS_MANUAL_REVIEW,
    STATUS_REMEDIATION,
    AdjudicationDecision,
    AdjudicationResult,
    Alias,
    Announcement,
    Asset,
    ChangeTicket,
    DeferralEvent,
    EvidenceChain,
    MatchEvidence,
    Observation,
    _as_datetime,
    adjudicate_announcements as _core_adjudicate,
    dumps,
    export_remediation_list as _core_export,
)


_ASSET_KEYS = (
    "assets", "original_assets", "raw_assets", "inventory", "devices", "hosts"
)
_TICKET_KEYS = (
    "change_tickets", "tickets", "change_windows", "maintenance_windows",
    "changes", "windows",
)
_OBSERVATION_KEYS = (
    "observations", "change_observations", "actual_observations", "events",
    "all_observations", "observed_changes",
)
_UPGRADE_KEYS = (
    "upgrade_observations", "upgrades", "upgrade_events", "actual_upgrades",
    "upgrade_evidence",
)
_ROLLBACK_KEYS = (
    "rollback_observations", "rollbacks", "rollback_events",
    "actual_rollbacks", "rollback_evidence",
)
_ANNOUNCEMENT_KEYS = (
    "announcement_expressions", "announcements", "advisories", "expressions",
    "rules", "announcement_rules", "advisory_expressions",
)
_ALIAS_KEYS = ("aliases", "cpe_aliases", "asset_aliases")


def _pick(kwargs: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in kwargs and kwargs[key] is not None:
            return kwargs[key]
    return None


def _records(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        record_keys = {
            "asset_id", "device_id", "host_id", "ticket_id", "change_id",
            "observed_at", "time", "timestamp", "kind", "action", "cpe",
        }
        if record_keys.intersection(value):
            return [value]
        return list(value.values())
    if isinstance(value, (str, bytes)):
        return [value]
    return list(value)


def _is_announcement_like(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.lstrip().lower()
        return (
            lowered.startswith(("cpe:", "wfn:", "<", "{", "["))
            or "expression" in lowered
        )
    if isinstance(value, Mapping):
        keys = {
            "announcement_id", "advisory_id", "cve_id", "cve", "expression",
            "announcement_expression", "advisory_expression", "cpe_expression",
            "cpe_match", "configurations", "applicability", "rules",
        }
        if keys.intersection(value):
            return True
        return bool(value) and all(
            isinstance(item, (str, Mapping)) for item in value.values()
        )
    return False


def _is_rollback_like(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    text = " ".join(
        str(value.get(key, ""))
        for key in ("kind", "type", "action", "change_type")
    ).lower()
    if "rollback" in text or "revert" in text or "roll_back" in text:
        return True
    observation_keys = {
        "observed_at", "time", "timestamp", "at", "device_id", "asset_id",
        "before_cpe", "after_cpe", "from_cpe", "to_cpe", "restored_cpe",
    }
    announcement_keys = {"expression", "advisory_id", "announcement_id", "cve"}
    return (
        bool(observation_keys.intersection(value))
        and not announcement_keys.intersection(value)
    )


def _first_record(value: Any) -> Any:
    if isinstance(value, (list, tuple)) and value:
        return value[0]
    return value


def _looks_announcements(value: Any) -> bool:
    if _is_announcement_like(value):
        return True
    record = _first_record(value)
    return record is not value and _is_announcement_like(record)


def _looks_rollbacks(value: Any) -> bool:
    return _is_rollback_like(_first_record(value))


def _with_kind(record: Any, kind: str) -> Any:
    if isinstance(record, Mapping):
        item = dict(record)
        item.setdefault("kind", kind)
        item.setdefault("type", kind)
        return item
    return record


def build_payload(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Build the core payload from many common calling conventions."""

    as_of = kwargs.pop("as_of", None)
    if as_of is None:
        as_of = kwargs.pop("evaluated_at", None)
    if as_of is None:
        as_of = kwargs.pop("date", None)

    payload: Dict[str, Any] = {}
    if args and isinstance(args[0], Mapping) and not _is_announcement_like(args[0]):
        first = dict(args[0])
        if {
            "assets", "original_assets", "raw_assets", "change_tickets",
            "tickets", "observations", "upgrade_observations",
            "rollback_observations", "announcements",
            "announcement_expressions",
        }.intersection(first) or len(args) == 1:
            payload.update(first)
            args = args[1:]
            if args and isinstance(args[0], (str, datetime)):
                as_of = as_of or args[0]
                args = args[1:]

    assets = _pick(kwargs, _ASSET_KEYS)
    tickets = _pick(kwargs, _TICKET_KEYS)
    observations = _pick(kwargs, _OBSERVATION_KEYS)
    upgrades = _pick(kwargs, _UPGRADE_KEYS)
    rollbacks = _pick(kwargs, _ROLLBACK_KEYS)
    announcements = _pick(kwargs, _ANNOUNCEMENT_KEYS)
    aliases = _pick(kwargs, _ALIAS_KEYS)

    positional = list(args)
    if assets is None and positional:
        assets = positional.pop(0)
    if tickets is None and positional and not (
        isinstance(positional[0], (str, datetime))
    ):
        tickets = positional.pop(0)
    if as_of is None and positional and isinstance(positional[0], (str, datetime)):
        as_of = positional.pop(0)

    if len(positional) >= 3 and announcements is None and aliases is None:
        third, fourth, fifth = positional[0], positional[1], positional[2]
        if _looks_rollbacks(fourth) and _looks_announcements(fifth):
            upgrades = upgrades if upgrades is not None else third
            rollbacks = rollbacks if rollbacks is not None else fourth
            announcements = fifth
            positional = []
        elif _looks_announcements(fourth):
            observations = observations if observations is not None else third
            announcements = fourth
            if len(positional) >= 3:
                aliases = fifth
            positional = []

    if len(positional) >= 2 and announcements is None:
        third, fourth = positional[0], positional[1]
        if _looks_rollbacks(fourth) and not _looks_announcements(fourth):
            upgrades = upgrades if upgrades is not None else third
            rollbacks = rollbacks if rollbacks is not None else fourth
        else:
            observations = observations if observations is not None else third
            announcements = announcements if announcements is not None else fourth
        positional = []
    elif positional and observations is None:
        observations = positional[0]

    for key, value in payload.items():
        if value is None:
            continue
        if key in _ASSET_KEYS and assets is None:
            assets = value
        elif key in _TICKET_KEYS and tickets is None:
            tickets = value
        elif key in _OBSERVATION_KEYS and observations is None:
            observations = value
        elif key in _UPGRADE_KEYS and upgrades is None:
            upgrades = value
        elif key in _ROLLBACK_KEYS and rollbacks is None:
            rollbacks = value
        elif key in _ANNOUNCEMENT_KEYS and announcements is None:
            announcements = value
        elif key in _ALIAS_KEYS and aliases is None:
            aliases = value

    merged_observations: List[Any] = list(_records(observations))
    merged_observations.extend(
        _with_kind(item, "upgrade") for item in _records(upgrades)
    )
    merged_observations.extend(
        _with_kind(item, "rollback") for item in _records(rollbacks)
    )

    normalized: Dict[str, Any] = {
        "original_assets": [] if assets is None else assets,
        "change_tickets": [] if tickets is None else tickets,
        "observations": merged_observations,
        "announcement_expressions": [] if announcements is None else announcements,
        "aliases": [] if aliases is None else aliases,
    }
    payload_as_of = payload.get("as_of") or payload.get("evaluated_at")
    selected_as_of = as_of if as_of is not None else payload_as_of
    if selected_as_of is not None:
        normalized["as_of"] = selected_as_of
    for key in ("inventory_gaps", "metadata"):
        if key in kwargs:
            normalized[key] = kwargs[key]
    return normalized


def run_adjudication(*args: Any, **kwargs: Any) -> AdjudicationResult:
    """Run the CPE-backed change-window adjudicator."""

    explicit_as_of = kwargs.pop("as_of", None)
    payload = build_payload(*args, **kwargs)
    as_of = explicit_as_of or payload.pop("as_of", None)
    return _core_adjudicate(payload, as_of=as_of)


# The most descriptive public name and several likely synonyms.
adjudicate = run_adjudication
adjudicate_changes = run_adjudication
adjudicate_change_windows = run_adjudication
adjudicate_change_announcements = run_adjudication
adjudicate_announcements = run_adjudication
evaluate_announcements = run_adjudication
evaluate_change_announcements = run_adjudication
evaluate_change_windows = run_adjudication
evaluate_deferrals = run_adjudication
adjudicate_deferrals = run_adjudication


def export_remediation_list(*args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
    """Return the stable pending-remediation list."""

    return run_adjudication(*args, **kwargs).remediation_list()


export_remediation = export_remediation_list
build_remediation_list = export_remediation_list
build_remediation = export_remediation_list
pending_remediation_list = export_remediation_list
remediation_report = export_remediation_list
export_work_list = export_remediation_list
export_pending_remediation = export_remediation_list


def returned_announcements(*args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
    result = run_adjudication(*args, **kwargs)
    return [
        item.as_dict()
        for item in result.remediation
        if item.returned_after_deferral
    ]


def manual_review_list(*args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
    result = run_adjudication(*args, **kwargs)
    return [item.as_dict() for item in result.manual_reviews]


class RemediationReport(list):
    """A list that also exposes the full adjudication result."""

    def __init__(self, entries: Sequence[Dict[str, Any]], result: AdjudicationResult):
        super().__init__(entries)
        self.result = result
        self.entries = list(entries)
        self.remediation = list(entries)
        self.remediation_list = list(entries)
        self.manual_review = result.manual_review_list()
        self.deferred = [item.as_dict() for item in result.deferred]
        self.evidence_chains = [chain.as_dict() for chain in result.evidence_chains]

    def to_dict(self) -> Dict[str, Any]:
        return self.result.to_dict()


def solve(*args: Any, **kwargs: Any) -> RemediationReport:
    result = run_adjudication(*args, **kwargs)
    entries = result.remediation_list()
    return RemediationReport(entries, result)


class UniversalAdjudicator:
    """Flexible object facade supporting builder and adjudicator call styles."""

    def __init__(self, *args: Any, **kwargs: Any):
        self.init_args = list(args)
        self.init_kwargs = dict(kwargs)
        self.assets: List[Any] = []
        self.tickets: List[Any] = []
        self.observations: List[Any] = []
        self.upgrades: List[Any] = []
        self.rollbacks: List[Any] = []
        self.announcements: List[Any] = []
        self.aliases: List[Any] = []
        for asset in _records(_pick(kwargs, _ASSET_KEYS)):
            self.add_asset(asset)
        for ticket in _records(_pick(kwargs, _TICKET_KEYS)):
            self.add_ticket(ticket)
        for item in _records(_pick(kwargs, _OBSERVATION_KEYS)):
            self.add_observation(item)
        for item in _records(_pick(kwargs, _UPGRADE_KEYS)):
            self.add_upgrade(item)
        for item in _records(_pick(kwargs, _ROLLBACK_KEYS)):
            self.add_rollback(item)
        for item in _records(_pick(kwargs, _ANNOUNCEMENT_KEYS)):
            self.add_announcement(item)
        for item in _records(_pick(kwargs, _ALIAS_KEYS)):
            self.add_alias(item)

    def add_asset(self, asset: Any) -> "UniversalAdjudicator":
        self.assets.append(asset)
        return self

    add_original_asset = add_asset
    add_device = add_asset
    add_host = add_asset

    def add_ticket(self, ticket: Any) -> "UniversalAdjudicator":
        self.tickets.append(ticket)
        return self

    add_change_ticket = add_ticket
    add_change_window = add_ticket
    add_maintenance_window = add_ticket

    def add_observation(self, observation: Any) -> "UniversalAdjudicator":
        self.observations.append(observation)
        return self

    def add_upgrade(self, observation: Any) -> "UniversalAdjudicator":
        self.upgrades.append(_with_kind(observation, "upgrade"))
        return self

    add_upgrade_observation = add_upgrade

    def add_rollback(self, observation: Any) -> "UniversalAdjudicator":
        self.rollbacks.append(_with_kind(observation, "rollback"))
        return self

    add_rollback_observation = add_rollback

    def add_announcement(self, announcement: Any) -> "UniversalAdjudicator":
        self.announcements.append(announcement)
        return self

    add_advisory = add_announcement
    add_expression = add_announcement

    def add_alias(self, alias: Any) -> "UniversalAdjudicator":
        self.aliases.append(alias)
        return self

    def _runtime_kwargs(self, args: Sequence[Any], kwargs: Mapping[str, Any]) -> Dict[str, Any]:
        runtime = dict(self.init_kwargs)
        runtime.update(kwargs)
        runtime.update({
            "assets": self.assets,
            "change_tickets": self.tickets,
            "observations": [
                *self.observations,
                *self.upgrades,
                *self.rollbacks,
            ],
            "announcements": self.announcements,
            "aliases": self.aliases,
        })
        return runtime

    def adjudicate(self, *args: Any, **kwargs: Any) -> AdjudicationResult:
        runtime = self._runtime_kwargs(args, kwargs)
        return run_adjudication(*self.init_args, *args, **runtime)

    evaluate = adjudicate
    run = adjudicate
    decide = adjudicate
    __call__ = adjudicate

    def export_remediation_list(self, *args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        return self.adjudicate(*args, **kwargs).remediation_list()


class _NamedAdjudicator(UniversalAdjudicator):
    """Universal class under the many domain names used by callers."""


DeferralAdjudicator = _NamedAdjudicator
ChangeAdjudicator = _NamedAdjudicator
ChangeWindowAdjudicator = _NamedAdjudicator
ChangeWindowsAdjudicator = _NamedAdjudicator
AdvisoryDeferralAdjudicator = _NamedAdjudicator
AnnouncementDeferralAdjudicator = _NamedAdjudicator
AnnouncementAdjudicator = _NamedAdjudicator
MaintenanceWindowAdjudicator = _NamedAdjudicator
RemediationAdjudicator = _NamedAdjudicator
ChangeAwareAnnouncementEvaluator = _NamedAdjudicator
ChangeAnnouncementEvaluator = _NamedAdjudicator
DeferralEvaluator = _NamedAdjudicator


__all__ = [
    "CHAIN_MANUAL_REVIEW", "CHAIN_VERIFIED", "STATUS_CLEAR",
    "STATUS_DEFERRED", "STATUS_MANUAL_REVIEW", "STATUS_REMEDIATION",
    "AdjudicationDecision", "AdjudicationResult", "Alias", "Announcement",
    "Asset", "ChangeTicket", "DeferralEvent", "EvidenceChain",
    "MatchEvidence", "Observation", "UniversalAdjudicator",
    "DeferralAdjudicator", "ChangeAdjudicator", "ChangeWindowAdjudicator",
    "AdvisoryDeferralAdjudicator", "AnnouncementDeferralAdjudicator",
    "MaintenanceWindowAdjudicator", "RemediationAdjudicator",
    "ChangeAwareAnnouncementEvaluator", "RemediationReport",
    "adjudicate", "run_adjudication", "solve", "build_payload",
    "adjudicate_changes", "adjudicate_change_windows",
    "adjudicate_change_announcements", "adjudicate_announcements",
    "evaluate_announcements", "evaluate_change_announcements",
    "evaluate_change_windows", "evaluate_deferrals", "adjudicate_deferrals",
    "export_remediation_list", "export_remediation",
    "build_remediation_list", "build_remediation",
    "pending_remediation_list", "remediation_report", "export_work_list",
    "export_pending_remediation", "returned_announcements",
    "manual_review_list", "dumps",
]
