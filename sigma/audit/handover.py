"""Offline shift handover auditing built on pySigma rule identity and pipelines.

The audit deliberately separates three questions for every rule:

* may this shift be notified about the rule (``can_notify``),
* may this shift act on the rule (``can_handle``), and
* is a required notify or handle role missing without an approved substitute
  (``no_substitute``).

Permissions are keyed by a content-backed rule identity that includes the Sigma
UUID.  Rule names and titles are reporting attributes only.  This is important:
pySigma correlation rules use ``name`` as a reference label and a collection can
contain two different rules that share a name.  Merging them would grant one
rule the other rule permissions.

A processing pipeline is applied to a private copy of each rule.  The audit
records the ordered processing items that actually fired, the field mappings
they produced, and any configured branch that is temporarily disabled.  Rules
that traversed a disabled branch stay notifiable for reference, but they are not
a release basis until the configured historical role countersigns them.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

import yaml

from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import (
    SigmaHandoverConfigurationError,
    SigmaHandoverIdentityError,
)
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations.base import (
    DetectionItemTransformation,
    FieldMappingTransformationBase,
)
from sigma.rule import SigmaDetection, SigmaRule

SigmaRuleLike = SigmaRule | SigmaCorrelationRule

__all__ = [
    "BranchState",
    "HandoverConfig",
    "HandoverReport",
    "HandoverState",
    "NotificationChain",
    "ProcessingBranch",
    "ProcessingTrace",
    "Recipient",
    "RuleAudit",
    "RuleIdentity",
    "RuleSelector",
    "Shift",
    "ShiftDuty",
    "SubstituteApproval",
    "SubstituteStatus",
    "UncoveredDuty",
    "audit_from_config",
    "audit_handover",
    "audit_shift_handover",
    "rule_identity",
]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_rule_text(rule: SigmaRuleLike) -> str:
    """Return a stable representation of the rule content used for identity."""
    return json.dumps(rule.to_dict(), sort_keys=True, default=str, ensure_ascii=False)


def _source_text(rule: SigmaRuleLike) -> str | None:
    source = rule.source
    if source is None:
        return None
    text = str(source.path)
    if source.line is not None:
        text += ":" + str(source.line)
    return text


def _check_keys(value: Mapping[str, Any], allowed: set[str], what: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SigmaHandoverConfigurationError(
            what + " contains unknown keys: " + ", ".join(unknown)
        )


def _as_mapping(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SigmaHandoverConfigurationError(what + " must be a mapping")
    return value


def _as_tuple_of_strings(value: Any, what: str, allow_empty: bool = True) -> tuple[str, ...]:
    if value is None:
        result: tuple[str, ...] = ()
    elif isinstance(value, str):
        result = (value,)
    elif isinstance(value, (list, tuple, set, frozenset)):
        if not all(isinstance(item, (str, int)) for item in value):
            raise SigmaHandoverConfigurationError(what + " must contain only strings")
        result = tuple(str(item) for item in value)
    else:
        raise SigmaHandoverConfigurationError(what + " must be a string or a list of strings")
    if not allow_empty and len(result) == 0:
        raise SigmaHandoverConfigurationError(what + " must not be empty")
    if any(item.strip() == "" for item in result):
        raise SigmaHandoverConfigurationError(what + " must not contain empty strings")
    return result


def _as_bool(value: Any, what: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise SigmaHandoverConfigurationError(what + " must be a boolean")
    return value


def _as_datetime(value: Any, what: str) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SigmaHandoverConfigurationError(what + " must be an ISO 8601 timestamp") from exc
    else:
        raise SigmaHandoverConfigurationError(what + " must be an ISO 8601 timestamp")
    if result.tzinfo is None or result.utcoffset() is None:
        raise SigmaHandoverConfigurationError(what + " must include an explicit timezone offset")
    return result


class HandoverState(str, Enum):
    """Effective state of one rule for one explicit shift."""

    NOTIFIABLE = "notifiable"
    ACTIONABLE = "actionable"
    NO_SUBSTITUTE = "no_substitute"

    @property
    def label(self) -> str:
        return {
            HandoverState.NOTIFIABLE: "可通知 (notifiable)",
            HandoverState.ACTIONABLE: "可处置 (actionable)",
            HandoverState.NO_SUBSTITUTE: "无替代 (no_substitute)",
        }[self]


class BranchState(str, Enum):
    """State of a configured processing branch."""

    ACTIVE = "active"
    DISABLED = "disabled"


@dataclass(frozen=True)
class RuleIdentity:
    """A permission-safe rule identity.

    ``key`` is derived from the Sigma UUID and the canonical rule content.  Two
    rules that merely share a ``name`` or ``title`` therefore never share a key.
    """

    key: str
    rule_id: str | None
    name: str | None
    title: str
    content_digest: str
    source: str | None = None

    @classmethod
    def from_rule(cls, rule: SigmaRuleLike) -> RuleIdentity:
        digest = _sha256(_canonical_rule_text(rule))
        rule_id = str(rule.id) if rule.id is not None else None
        if rule_id is not None:
            key = "uuid:" + rule_id + ":" + digest[:16]
        else:
            key = "content:" + digest[:16]
        return cls(
            key=key,
            rule_id=rule_id,
            name=rule.name,
            title=rule.title,
            content_digest=digest,
            source=_source_text(rule),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "rule_id": self.rule_id,
            "name": self.name,
            "title": self.title,
            "content_digest": self.content_digest,
            "source": self.source,
        }


def rule_identity(rule: SigmaRuleLike) -> RuleIdentity:
    """Return a permission-safe identity for a Sigma rule."""
    return RuleIdentity.from_rule(rule)


@dataclass(frozen=True)
class RuleSelector:
    """Explicit rule selector used by shift duties and substitute approvals.

    Selection by name or title is intentionally unsupported.  Use ``rule_ids``
    or ``rule_keys`` for identity-level grants, or tags/logsource fields for
    broader operational scopes.  Broad selectors are reported as warnings so an
    auditor can see when a duty is not tied to a single rule identity.
    """

    rule_ids: tuple[str, ...] = ()
    rule_keys: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    levels: tuple[str, ...] = ()
    statuses: tuple[str, ...] = ()
    logsource_categories: tuple[str, ...] = ()
    logsource_products: tuple[str, ...] = ()
    logsource_services: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: Any) -> RuleSelector:
        data = _as_mapping(value, "selector")
        unsafe = {"name", "names", "title", "titles"} & set(data)
        if unsafe:
            raise SigmaHandoverConfigurationError(
                "selector must not use name or title for permission grants: "
                + ", ".join(sorted(unsafe))
            )
        allowed = {
            "rule_ids",
            "rule_keys",
            "tags",
            "levels",
            "statuses",
            "logsource_categories",
            "logsource_products",
            "logsource_services",
        }
        _check_keys(data, allowed, "selector")
        return cls(
            rule_ids=_as_tuple_of_strings(data.get("rule_ids"), "selector.rule_ids"),
            rule_keys=_as_tuple_of_strings(data.get("rule_keys"), "selector.rule_keys"),
            tags=_as_tuple_of_strings(data.get("tags"), "selector.tags"),
            levels=_as_tuple_of_strings(data.get("levels"), "selector.levels"),
            statuses=_as_tuple_of_strings(data.get("statuses"), "selector.statuses"),
            logsource_categories=_as_tuple_of_strings(
                data.get("logsource_categories"), "selector.logsource_categories"
            ),
            logsource_products=_as_tuple_of_strings(
                data.get("logsource_products"), "selector.logsource_products"
            ),
            logsource_services=_as_tuple_of_strings(
                data.get("logsource_services"), "selector.logsource_services"
            ),
        )

    @property
    def restricted_to_identity(self) -> bool:
        return bool(self.rule_ids or self.rule_keys)

    def matches(self, identity: RuleIdentity, rule: SigmaRuleLike) -> bool:
        if self.rule_ids and identity.rule_id not in self.rule_ids:
            return False
        if self.rule_keys and identity.key not in self.rule_keys:
            return False
        if self.tags:
            tag_values = {str(tag).lower() for tag in rule.tags}
            if not any(_tag_pattern_matches(pattern.lower(), tag_values) for pattern in self.tags):
                return False
        if self.levels and str(rule.level).lower() not in {level.lower() for level in self.levels}:
            return False
        if self.statuses and str(rule.status).lower() not in {
            status.lower() for status in self.statuses
        }:
            return False
        logsource = getattr(rule, "logsource", None)
        if self.logsource_categories and (
            logsource is None or logsource.category not in self.logsource_categories
        ):
            return False
        if self.logsource_products and (
            logsource is None or logsource.product not in self.logsource_products
        ):
            return False
        if self.logsource_services and (
            logsource is None or logsource.service not in self.logsource_services
        ):
            return False
        return True


def _tag_pattern_matches(pattern: str, tag_values: set[str]) -> bool:
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return any(tag.startswith(prefix) for tag in tag_values)
    return pattern in tag_values


@dataclass(frozen=True)
class ShiftDuty:
    """An explicit responsibility line for a shift."""

    duty_id: str
    role: str
    selector: RuleSelector
    notify: bool = True
    handle: bool = False
    release_basis: bool = True
    note: str | None = None

    def __post_init__(self) -> None:
        if not self.duty_id.strip():
            raise SigmaHandoverConfigurationError("shift duty id must be a non-empty string")
        if not self.role.strip():
            raise SigmaHandoverConfigurationError("shift duty role must be a non-empty string")

    @classmethod
    def from_dict(cls, value: Any) -> ShiftDuty:
        data = _as_mapping(value, "shift duty")
        selector_keys = {
            "rule_ids",
            "rule_keys",
            "tags",
            "levels",
            "statuses",
            "logsource_categories",
            "logsource_products",
            "logsource_services",
        }
        allowed = {
            "id",
            "duty_id",
            "role",
            "selector",
            "notify",
            "handle",
            "release_basis",
            "note",
        } | selector_keys
        _check_keys(data, allowed, "shift duty")
        if "selector" in data and any(key in data for key in selector_keys):
            raise SigmaHandoverConfigurationError(
                "shift duty must use either selector or direct selector keys, not both"
            )
        if "selector" in data:
            selector = RuleSelector.from_dict(data["selector"])
        else:
            selector = RuleSelector.from_dict(
                {key: data[key] for key in selector_keys if key in data}
            )
        duty_id = data.get("duty_id", data.get("id"))
        if duty_id is None:
            raise SigmaHandoverConfigurationError("shift duty requires id or duty_id")
        if not isinstance(duty_id, str) or duty_id.strip() == "":
            raise SigmaHandoverConfigurationError("shift duty id must be a non-empty string")
        role = data.get("role")
        if not isinstance(role, str) or role.strip() == "":
            raise SigmaHandoverConfigurationError("shift duty role must be a non-empty string")
        note = data.get("note")
        if note is not None and not isinstance(note, str):
            raise SigmaHandoverConfigurationError("shift duty note must be a string")
        return cls(
            duty_id=duty_id,
            role=role,
            selector=selector,
            notify=_as_bool(data.get("notify"), "shift duty notify", True),
            handle=_as_bool(data.get("handle"), "shift duty handle", False),
            release_basis=_as_bool(data.get("release_basis"), "shift duty release_basis", True),
            note=note,
        )


@dataclass(frozen=True)
class SubstituteApproval:
    """An explicitly approved substitute for one role and rule scope."""

    approval_id: str
    for_role: str
    substitute: str
    selector: RuleSelector
    approved_by: str
    valid_from: datetime
    valid_until: datetime
    notify: bool = True
    handle: bool = True
    release_basis: bool = True
    note: str | None = None

    def __post_init__(self) -> None:
        for name in ("approval_id", "for_role", "substitute", "approved_by"):
            if not getattr(self, name).strip():
                raise SigmaHandoverConfigurationError(
                    "substitute approval " + name + " must be a non-empty string"
                )
        if self.valid_from.tzinfo is None or self.valid_from.utcoffset() is None:
            raise SigmaHandoverConfigurationError(
                "substitute approval valid_from must include a timezone offset"
            )
        if self.valid_until.tzinfo is None or self.valid_until.utcoffset() is None:
            raise SigmaHandoverConfigurationError(
                "substitute approval valid_until must include a timezone offset"
            )
        if self.valid_until <= self.valid_from:
            raise SigmaHandoverConfigurationError(
                "substitute approval valid_until must be after valid_from"
            )

    @classmethod
    def from_dict(cls, value: Any) -> SubstituteApproval:
        data = _as_mapping(value, "substitute approval")
        selector_keys = {
            "rule_ids",
            "rule_keys",
            "tags",
            "levels",
            "statuses",
            "logsource_categories",
            "logsource_products",
            "logsource_services",
        }
        allowed = {
            "id",
            "approval_id",
            "for_role",
            "role",
            "substitute",
            "selector",
            "approved_by",
            "valid_from",
            "valid_until",
            "notify",
            "handle",
            "release_basis",
            "note",
        } | selector_keys
        _check_keys(data, allowed, "substitute approval")
        if "selector" in data and any(key in data for key in selector_keys):
            raise SigmaHandoverConfigurationError(
                "substitute approval must use either selector or direct selector keys, not both"
            )
        if "selector" in data:
            selector = RuleSelector.from_dict(data["selector"])
        else:
            selector = RuleSelector.from_dict(
                {key: data[key] for key in selector_keys if key in data}
            )
        approval_id = data.get("approval_id", data.get("id"))
        if approval_id is None:
            raise SigmaHandoverConfigurationError("substitute approval requires id or approval_id")
        if not isinstance(approval_id, str) or approval_id.strip() == "":
            raise SigmaHandoverConfigurationError(
                "substitute approval id must be a non-empty string"
            )
        for_role = data.get("for_role", data.get("role"))
        if not isinstance(for_role, str) or for_role.strip() == "":
            raise SigmaHandoverConfigurationError(
                "substitute approval for_role must be a non-empty string"
            )
        substitute = data.get("substitute")
        if not isinstance(substitute, str) or substitute.strip() == "":
            raise SigmaHandoverConfigurationError(
                "substitute approval substitute must be a non-empty string"
            )
        approved_by = data.get("approved_by")
        if not isinstance(approved_by, str) or approved_by.strip() == "":
            raise SigmaHandoverConfigurationError(
                "substitute approval approved_by must be a non-empty string"
            )
        note = data.get("note")
        if note is not None and not isinstance(note, str):
            raise SigmaHandoverConfigurationError("substitute approval note must be a string")
        valid_from = _as_datetime(data.get("valid_from"), "substitute approval valid_from")
        valid_until = _as_datetime(data.get("valid_until"), "substitute approval valid_until")
        if valid_until <= valid_from:
            raise SigmaHandoverConfigurationError(
                "substitute approval valid_until must be after valid_from"
            )
        return cls(
            approval_id=approval_id,
            for_role=for_role,
            substitute=substitute,
            selector=selector,
            approved_by=approved_by,
            valid_from=valid_from,
            valid_until=valid_until,
            notify=_as_bool(data.get("notify"), "substitute approval notify", True),
            handle=_as_bool(data.get("handle"), "substitute approval handle", True),
            release_basis=_as_bool(
                data.get("release_basis"), "substitute approval release_basis", True
            ),
            note=note,
        )

    def status_for(self, shift: Shift) -> SubstituteStatus:
        if shift.starts_at < self.valid_from or shift.ends_at > self.valid_until:
            return SubstituteStatus(
                self.approval_id,
                self.for_role,
                self.substitute,
                False,
                "approval_does_not_cover_full_shift",
            )
        if self.substitute not in shift.on_duty:
            return SubstituteStatus(
                self.approval_id,
                self.for_role,
                self.substitute,
                False,
                "substitute_not_on_duty",
            )
        return SubstituteStatus(
            self.approval_id,
            self.for_role,
            self.substitute,
            True,
            "approved_and_on_duty",
        )


@dataclass(frozen=True)
class SubstituteStatus:
    approval_id: str
    for_role: str
    substitute: str
    effective: bool
    reason: str


@dataclass(frozen=True)
class Shift:
    """Explicit shift responsibilities and approved substitutes."""

    shift_id: str
    starts_at: datetime
    ends_at: datetime
    on_duty: tuple[str, ...]
    duties: tuple[ShiftDuty, ...]
    substitutes: tuple[SubstituteApproval, ...] = ()

    def __post_init__(self) -> None:
        if not self.shift_id.strip():
            raise SigmaHandoverConfigurationError("shift id must be a non-empty string")
        for name, value in (("starts_at", self.starts_at), ("ends_at", self.ends_at)):
            if value.tzinfo is None or value.utcoffset() is None:
                raise SigmaHandoverConfigurationError(
                    "shift " + name + " must include a timezone offset"
                )
        if self.ends_at <= self.starts_at:
            raise SigmaHandoverConfigurationError("shift ends_at must be after starts_at")
        if not self.on_duty:
            raise SigmaHandoverConfigurationError("shift on_duty must not be empty")
        if any(not role.strip() for role in self.on_duty):
            raise SigmaHandoverConfigurationError("shift on_duty must not contain empty strings")
        if len(set(self.on_duty)) != len(self.on_duty):
            raise SigmaHandoverConfigurationError("shift on_duty must not contain duplicates")
        if len({duty.duty_id for duty in self.duties}) != len(self.duties):
            raise SigmaHandoverConfigurationError("shift duty ids must be unique")
        if len({approval.approval_id for approval in self.substitutes}) != len(self.substitutes):
            raise SigmaHandoverConfigurationError("substitute approval ids must be unique")

    @classmethod
    def from_dict(cls, value: Any) -> Shift:
        data = _as_mapping(value, "shift")
        allowed = {
            "id",
            "shift_id",
            "starts_at",
            "ends_at",
            "on_duty",
            "duties",
            "substitutes",
            "approved_substitutes",
        }
        _check_keys(data, allowed, "shift")
        shift_id = data.get("shift_id", data.get("id"))
        if not isinstance(shift_id, str) or shift_id.strip() == "":
            raise SigmaHandoverConfigurationError("shift requires id or shift_id")
        starts_at = _as_datetime(data.get("starts_at"), "shift starts_at")
        ends_at = _as_datetime(data.get("ends_at"), "shift ends_at")
        if ends_at <= starts_at:
            raise SigmaHandoverConfigurationError("shift ends_at must be after starts_at")
        on_duty = _as_tuple_of_strings(data.get("on_duty"), "shift on_duty", allow_empty=False)
        if len(set(on_duty)) != len(on_duty):
            raise SigmaHandoverConfigurationError("shift on_duty must not contain duplicates")
        raw_duties = data.get("duties")
        if not isinstance(raw_duties, list):
            raise SigmaHandoverConfigurationError("shift duties must be a list")
        duties = tuple(ShiftDuty.from_dict(item) for item in raw_duties)
        duty_ids = [duty.duty_id for duty in duties]
        if len(set(duty_ids)) != len(duty_ids):
            raise SigmaHandoverConfigurationError("shift duty ids must be unique")
        raw_substitutes = data.get("substitutes", data.get("approved_substitutes", []))
        if raw_substitutes is None:
            raw_substitutes = []
        if not isinstance(raw_substitutes, list):
            raise SigmaHandoverConfigurationError("shift substitutes must be a list")
        substitutes = tuple(SubstituteApproval.from_dict(item) for item in raw_substitutes)
        approval_ids = [approval.approval_id for approval in substitutes]
        if len(set(approval_ids)) != len(approval_ids):
            raise SigmaHandoverConfigurationError("substitute approval ids must be unique")
        return cls(
            shift_id=shift_id,
            starts_at=starts_at,
            ends_at=ends_at,
            on_duty=on_duty,
            duties=duties,
            substitutes=substitutes,
        )

    @classmethod
    def from_yaml(cls, value: str) -> Shift:
        try:
            parsed = yaml.safe_load(value)
        except yaml.YAMLError as exc:
            raise SigmaHandoverConfigurationError("invalid shift YAML") from exc
        return cls.from_dict(parsed)


@dataclass(frozen=True)
class ProcessingBranch:
    """A named group of processing items that can be temporarily closed."""

    branch_id: str
    processing_item_ids: tuple[str, ...]
    state: BranchState = BranchState.ACTIVE
    historical_role: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self.branch_id.strip():
            raise SigmaHandoverConfigurationError("processing branch id must be a non-empty string")
        if not self.processing_item_ids:
            raise SigmaHandoverConfigurationError(
                "processing branch must name at least one processing item"
            )
        if any(not item_id.strip() for item_id in self.processing_item_ids):
            raise SigmaHandoverConfigurationError("processing branch item ids must not be empty")
        if self.state is BranchState.DISABLED and (
            self.historical_role is None or not self.historical_role.strip()
        ):
            raise SigmaHandoverConfigurationError(
                "disabled processing branch "
                + self.branch_id
                + " must declare the historical_role that countersigns it"
            )

    @classmethod
    def from_dict(cls, value: Any) -> ProcessingBranch:
        data = _as_mapping(value, "processing branch")
        allowed = {
            "id",
            "branch_id",
            "processing_items",
            "processing_item_ids",
            "state",
            "historical_role",
            "reason",
        }
        _check_keys(data, allowed, "processing branch")
        branch_id = data.get("branch_id", data.get("id"))
        if not isinstance(branch_id, str) or branch_id.strip() == "":
            raise SigmaHandoverConfigurationError("processing branch requires id or branch_id")
        item_ids = _as_tuple_of_strings(
            data.get("processing_items", data.get("processing_item_ids")),
            "processing branch processing_items",
            allow_empty=False,
        )
        state_value = data.get("state", "active")
        try:
            state = BranchState(str(state_value).lower())
        except ValueError as exc:
            raise SigmaHandoverConfigurationError(
                "processing branch state must be active or disabled"
            ) from exc
        historical_role = data.get("historical_role")
        if historical_role is not None and (
            not isinstance(historical_role, str) or historical_role.strip() == ""
        ):
            raise SigmaHandoverConfigurationError(
                "processing branch historical_role must be a non-empty string"
            )
        reason = data.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise SigmaHandoverConfigurationError("processing branch reason must be a string")
        if state is BranchState.DISABLED and historical_role is None:
            raise SigmaHandoverConfigurationError(
                "disabled processing branch "
                + branch_id
                + " must declare the historical_role that countersigns it"
            )
        return cls(
            branch_id=branch_id,
            processing_item_ids=item_ids,
            state=state,
            historical_role=historical_role,
            reason=reason,
        )

    def matches(self, applied_item_ids: Sequence[str]) -> bool:
        return bool(set(self.processing_item_ids) & set(applied_item_ids))


@dataclass(frozen=True)
class ProcessingTrace:
    """What the configured processing chain actually did to one rule."""

    pipeline_name: str | None
    applied_item_ids: tuple[str, ...]
    applied_branches: tuple[str, ...]
    disabled_branches: tuple[str, ...]
    countersign_roles: tuple[str, ...]
    field_mappings: Mapping[str | None, tuple[str, ...]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pipeline_name": self.pipeline_name,
            "applied_item_ids": list(self.applied_item_ids),
            "applied_branches": list(self.applied_branches),
            "disabled_branches": list(self.disabled_branches),
            "countersign_roles": list(self.countersign_roles),
            "field_mappings": {
                ("<keyword>" if source is None else source): list(targets)
                for source, targets in self.field_mappings.items()
            },
        }


@dataclass(frozen=True)
class Recipient:
    """One role that is notified and/or authorized for a rule."""

    role: str
    via: tuple[str, ...]
    source_roles: tuple[str, ...]
    duty_ids: tuple[str, ...]
    approval_ids: tuple[str, ...]
    notify: bool
    handle: bool
    release_basis: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "via": list(self.via),
            "source_roles": list(self.source_roles),
            "duty_ids": list(self.duty_ids),
            "approval_ids": list(self.approval_ids),
            "notify": self.notify,
            "handle": self.handle,
            "release_basis": self.release_basis,
        }


@dataclass(frozen=True)
class UncoveredDuty:
    duty_id: str
    role: str
    notify_required: bool
    handle_required: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "duty_id": self.duty_id,
            "role": self.role,
            "notify_required": self.notify_required,
            "handle_required": self.handle_required,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class NotificationChain:
    """The notification fan-out produced for one rule under one shift."""

    chain_id: str
    identity: RuleIdentity
    shift_id: str
    state: HandoverState
    recipients: tuple[Recipient, ...]
    handlers: tuple[Recipient, ...]
    release_basis: bool
    reference_only: bool
    release_blockers: tuple[str, ...]
    countersign_roles: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "identity": self.identity.to_dict(),
            "shift_id": self.shift_id,
            "state": self.state.value,
            "recipients": [recipient.to_dict() for recipient in self.recipients],
            "handlers": [handler.to_dict() for handler in self.handlers],
            "release_basis": self.release_basis,
            "reference_only": self.reference_only,
            "release_blockers": list(self.release_blockers),
            "countersign_roles": list(self.countersign_roles),
        }


@dataclass(frozen=True)
class RuleAudit:
    identity: RuleIdentity
    title: str
    name: str | None
    duplicate_name: bool
    state: HandoverState
    can_notify: bool
    can_handle: bool
    no_substitute: bool
    recipients: tuple[Recipient, ...]
    handlers: tuple[Recipient, ...]
    uncovered_duties: tuple[UncoveredDuty, ...]
    processing: ProcessingTrace
    countersign_roles: tuple[str, ...]
    chain: NotificationChain
    warnings: tuple[str, ...]

    @property
    def chain_id(self) -> str:
        return self.chain.chain_id

    @property
    def release_basis(self) -> bool:
        return self.chain.release_basis

    @property
    def reference_only(self) -> bool:
        return self.chain.reference_only

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "title": self.title,
            "name": self.name,
            "duplicate_name": self.duplicate_name,
            "state": self.state.value,
            "state_label": self.state.label,
            "can_notify": self.can_notify,
            "can_handle": self.can_handle,
            "no_substitute": self.no_substitute,
            "recipients": [recipient.to_dict() for recipient in self.recipients],
            "handlers": [handler.to_dict() for handler in self.handlers],
            "uncovered_duties": [duty.to_dict() for duty in self.uncovered_duties],
            "processing": self.processing.to_dict(),
            "countersign_roles": list(self.countersign_roles),
            "chain": self.chain.to_dict(),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class HandoverReport:
    shift: Shift
    generated_at: datetime
    audits: tuple[RuleAudit, ...]
    substitute_statuses: tuple[SubstituteStatus, ...]
    branches: tuple[ProcessingBranch, ...]
    duplicate_names: tuple[str, ...]
    duplicate_titles: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def chains(self) -> tuple[NotificationChain, ...]:
        return tuple(audit.chain for audit in self.audits)

    @property
    def reference_only_chains(self) -> tuple[NotificationChain, ...]:
        return tuple(
            audit.chain
            for audit in self.audits
            if audit.chain.reference_only and audit.chain.recipients
        )

    def filter_chains(
        self,
        reference_only: bool | None = None,
        state: HandoverState | str | None = None,
        role: str | None = None,
        identity_key: str | None = None,
    ) -> tuple[NotificationChain, ...]:
        state_value: str | None = None
        if isinstance(state, HandoverState):
            state_value = state.value
        elif state is not None:
            state_value = str(state)
        result: list[NotificationChain] = []
        for audit in self.audits:
            chain = audit.chain
            if reference_only is not None and chain.reference_only is not reference_only:
                continue
            if state_value is not None and chain.state.value != state_value:
                continue
            if role is not None and not any(
                recipient.role == role for recipient in chain.recipients
            ):
                continue
            if identity_key is not None and chain.identity.key != identity_key:
                continue
            result.append(chain)
        return tuple(result)

    def chain(self, identity_key: str) -> NotificationChain:
        for audit in self.audits:
            if audit.identity.key == identity_key:
                return audit.chain
        raise KeyError(identity_key)

    def state_counts(self) -> dict[str, int]:
        counts = Counter(audit.state.value for audit in self.audits)
        return {
            HandoverState.NOTIFIABLE.value: counts.get(HandoverState.NOTIFIABLE.value, 0),
            HandoverState.ACTIONABLE.value: counts.get(HandoverState.ACTIONABLE.value, 0),
            HandoverState.NO_SUBSTITUTE.value: counts.get(HandoverState.NO_SUBSTITUTE.value, 0),
        }

    def summary(self) -> dict[str, Any]:
        return {
            "shift_id": self.shift.shift_id,
            "rule_count": len(self.audits),
            "state_counts": self.state_counts(),
            "reference_only_chain_ids": [chain.chain_id for chain in self.reference_only_chains],
            "duplicate_names": list(self.duplicate_names),
            "duplicate_titles": list(self.duplicate_titles),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "shift": {
                "shift_id": self.shift.shift_id,
                "starts_at": self.shift.starts_at.isoformat(),
                "ends_at": self.shift.ends_at.isoformat(),
                "on_duty": list(self.shift.on_duty),
                "duties": [
                    {
                        "duty_id": duty.duty_id,
                        "role": duty.role,
                        "selector": {
                            "rule_ids": list(duty.selector.rule_ids),
                            "rule_keys": list(duty.selector.rule_keys),
                            "tags": list(duty.selector.tags),
                            "levels": list(duty.selector.levels),
                            "statuses": list(duty.selector.statuses),
                            "logsource_categories": list(duty.selector.logsource_categories),
                            "logsource_products": list(duty.selector.logsource_products),
                            "logsource_services": list(duty.selector.logsource_services),
                        },
                        "notify": duty.notify,
                        "handle": duty.handle,
                        "release_basis": duty.release_basis,
                        "note": duty.note,
                    }
                    for duty in self.shift.duties
                ],
                "substitutes": [
                    {
                        "approval_id": approval.approval_id,
                        "for_role": approval.for_role,
                        "substitute": approval.substitute,
                        "approved_by": approval.approved_by,
                        "valid_from": approval.valid_from.isoformat(),
                        "valid_until": approval.valid_until.isoformat(),
                        "notify": approval.notify,
                        "handle": approval.handle,
                        "release_basis": approval.release_basis,
                        "note": approval.note,
                    }
                    for approval in self.shift.substitutes
                ],
            },
            "generated_at": self.generated_at.isoformat(),
            "summary": self.summary(),
            "audits": [audit.to_dict() for audit in self.audits],
            "chains": [audit.chain.to_dict() for audit in self.audits],
            "reference_only_chains": [chain.to_dict() for chain in self.reference_only_chains],
            "substitute_statuses": [
                {
                    "approval_id": status.approval_id,
                    "for_role": status.for_role,
                    "substitute": status.substitute,
                    "effective": status.effective,
                    "reason": status.reason,
                }
                for status in self.substitute_statuses
            ],
            "branches": [
                {
                    "branch_id": branch.branch_id,
                    "processing_item_ids": list(branch.processing_item_ids),
                    "state": branch.state.value,
                    "historical_role": branch.historical_role,
                    "reason": branch.reason,
                }
                for branch in self.branches
            ],
            "duplicate_names": list(self.duplicate_names),
            "duplicate_titles": list(self.duplicate_titles),
            "warnings": list(self.warnings),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self, reference_only_only: bool = False) -> str:
        chains = (
            self.reference_only_chains
            if reference_only_only
            else tuple(audit.chain for audit in self.audits)
        )
        return _render_markdown(self, chains, reference_only_only)


def _merge_recipient(
    store: dict[str, dict[str, Any]],
    role: str,
    via: str,
    duty: ShiftDuty,
    approval: SubstituteApproval | None,
    release_basis: bool,
) -> None:
    item = store.setdefault(
        role,
        {
            "via": [],
            "source_roles": [],
            "duty_ids": [],
            "approval_ids": [],
            "notify": False,
            "handle": False,
            "release_basis": False,
        },
    )
    if via not in item["via"]:
        item["via"].append(via)
    if duty.duty_id not in item["duty_ids"]:
        item["duty_ids"].append(duty.duty_id)
    if approval is not None:
        if approval.approval_id not in item["approval_ids"]:
            item["approval_ids"].append(approval.approval_id)
        if approval.for_role not in item["source_roles"]:
            item["source_roles"].append(approval.for_role)
    item["notify"] = item["notify"] or duty.notify
    item["handle"] = item["handle"] or duty.handle
    item["release_basis"] = item["release_basis"] or release_basis


def _freeze_recipients(store: dict[str, dict[str, Any]]) -> tuple[Recipient, ...]:
    return tuple(
        Recipient(
            role=role,
            via=tuple(item["via"]),
            source_roles=tuple(item["source_roles"]),
            duty_ids=tuple(item["duty_ids"]),
            approval_ids=tuple(item["approval_ids"]),
            notify=item["notify"],
            handle=item["handle"],
            release_basis=item["release_basis"],
        )
        for role, item in store.items()
    )


def _collect_detection_applied_ids(detection: SigmaDetection, ids: set[str]) -> None:
    for detection_item in detection.detection_items:
        if isinstance(detection_item, SigmaDetection):
            _collect_detection_applied_ids(detection_item, ids)
        else:
            ids.update(detection_item.applied_processing_items)


def _effective_applied_item_ids(
    pipeline: ProcessingPipeline, rule: SigmaRuleLike
) -> tuple[str, ...]:
    """Return processing items that changed this rule rather than merely matching it.

    pySigma marks a detection-item transformation as applied on the rule even when
    no field or value matched. For an audit, a branch should only count when it
    actually affected the rule. Field mappings therefore count only when the
    pipeline recorded a real source-to-target mapping. Other detection-item
    transformations count when at least one detection item recorded the item id.
    Preprocessing transformations count whenever their condition matched.
    """
    field_effective: set[str] = set()
    for item_ids in pipeline.field_name_applied_ids.values():
        field_effective.update(item_ids)
    detection_effective: set[str] = set()
    if isinstance(rule, SigmaRule):
        for detection in rule.detection.detections.values():
            _collect_detection_applied_ids(detection, detection_effective)
    result: list[str] = []
    for item, applied in zip(pipeline.items, pipeline.applied):
        if not applied or item.identifier is None:
            continue
        transformation = item.transformation
        if isinstance(
            transformation, (FieldMappingTransformationBase, DetectionItemTransformation)
        ):
            effective = item.identifier in detection_effective or item.identifier in field_effective
        else:
            effective = True
        if effective:
            result.append(item.identifier)
    return tuple(result)


def _apply_processing_chain(
    rule: SigmaRuleLike,
    pipeline: ProcessingPipeline | None,
    branches: Sequence[ProcessingBranch],
) -> ProcessingTrace:
    if pipeline is None:
        return ProcessingTrace(
            pipeline_name=None,
            applied_item_ids=(),
            applied_branches=(),
            disabled_branches=(),
            countersign_roles=(),
            field_mappings={},
        )
    working = copy.deepcopy(rule)
    pipeline.apply(working)
    applied_item_ids = _effective_applied_item_ids(pipeline, working)
    matched_branches = tuple(branch for branch in branches if branch.matches(applied_item_ids))
    disabled_branches = tuple(
        branch for branch in matched_branches if branch.state is BranchState.DISABLED
    )
    countersign_roles = tuple(
        dict.fromkeys(
            branch.historical_role
            for branch in disabled_branches
            if branch.historical_role is not None
        )
    )
    field_mappings: dict[str | None, tuple[str, ...]] = {
        source: tuple(sorted(targets)) for source, targets in pipeline.field_mappings.items()
    }
    return ProcessingTrace(
        pipeline_name=pipeline.name,
        applied_item_ids=applied_item_ids,
        applied_branches=tuple(branch.branch_id for branch in matched_branches),
        disabled_branches=tuple(branch.branch_id for branch in disabled_branches),
        countersign_roles=countersign_roles,
        field_mappings=field_mappings,
    )


def _select_substitute(
    duty: ShiftDuty,
    identity: RuleIdentity,
    rule: SigmaRuleLike,
    shift: Shift,
) -> tuple[SubstituteApproval | None, tuple[SubstituteApproval, ...]]:
    candidates = tuple(
        approval
        for approval in shift.substitutes
        if approval.for_role == duty.role
        and approval.selector.matches(identity, rule)
        and approval.status_for(shift).effective
        and (not duty.notify or approval.notify)
        and (not duty.handle or approval.handle)
    )
    if not candidates:
        return None, ()
    return candidates[0], candidates


def _substitute_gap_reason(
    duty: ShiftDuty,
    identity: RuleIdentity,
    rule: SigmaRuleLike,
    shift: Shift,
) -> str:
    role_approvals = tuple(
        approval for approval in shift.substitutes if approval.for_role == duty.role
    )
    if not role_approvals:
        return "role_off_duty_no_approved_substitute"
    matching = tuple(
        approval for approval in role_approvals if approval.selector.matches(identity, rule)
    )
    if not matching:
        return "no_approved_substitute_for_rule"
    statuses = tuple((approval, approval.status_for(shift)) for approval in matching)
    effective = tuple((approval, status) for approval, status in statuses if status.effective)
    if not effective:
        return "approved_substitute_not_effective:" + ";".join(
            status.reason for _approval, status in statuses
        )
    if not any(
        (not duty.notify or approval.notify) and (not duty.handle or approval.handle)
        for approval, _status in effective
    ):
        return "approved_substitute_lacks_required_authority"
    return "no_approved_substitute_for_rule"


def _audit_one_rule(
    rule: SigmaRuleLike,
    identity: RuleIdentity,
    shift: Shift,
    pipeline: ProcessingPipeline | None,
    branches: Sequence[ProcessingBranch],
    duplicate_name: bool,
) -> RuleAudit:
    processing = _apply_processing_chain(rule, pipeline, branches)
    warnings: list[str] = []
    if identity.rule_id is None:
        warnings.append("rule has no Sigma UUID; identity was derived from a content digest")
    if duplicate_name:
        warnings.append(
            "rule name or title is shared with another distinct rule identity; "
            "permissions were not merged"
        )
    if rule.errors:
        warnings.append("rule carries parse errors: " + "; ".join(str(e) for e in rule.errors))
    for branch in processing.disabled_branches:
        warnings.append(
            "processing branch "
            + branch
            + " is temporarily disabled; handling is suspended until countersign"
        )

    store: dict[str, dict[str, Any]] = {}
    uncovered: list[UncoveredDuty] = []
    matching_duties = tuple(duty for duty in shift.duties if duty.selector.matches(identity, rule))
    for duty in matching_duties:
        if not duty.selector.restricted_to_identity:
            warnings.append(
                "duty "
                + duty.duty_id
                + " matched through a broad selector; confirm the operational scope"
            )
        if duty.role in shift.on_duty:
            _merge_recipient(
                store,
                role=duty.role,
                via="duty",
                duty=duty,
                approval=None,
                release_basis=duty.release_basis,
            )
            continue
        substitute, alternatives = _select_substitute(duty, identity, rule, shift)
        if substitute is None:
            uncovered.append(
                UncoveredDuty(
                    duty_id=duty.duty_id,
                    role=duty.role,
                    notify_required=duty.notify,
                    handle_required=duty.handle,
                    reason=_substitute_gap_reason(duty, identity, rule, shift),
                )
            )
            continue
        if len(alternatives) > 1:
            warnings.append(
                "multiple approved substitutes cover duty "
                + duty.duty_id
                + "; selected "
                + substitute.approval_id
                + " in configuration order"
            )
        _merge_recipient(
            store,
            role=substitute.substitute,
            via="substitute",
            duty=duty,
            approval=substitute,
            release_basis=duty.release_basis and substitute.release_basis,
        )

    all_roles = _freeze_recipients(store)
    recipients = tuple(recipient for recipient in all_roles if recipient.notify)
    handlers = tuple(recipient for recipient in all_roles if recipient.handle)
    can_notify = bool(recipients)
    can_handle_authorized = bool(handlers)
    can_handle = can_handle_authorized and not processing.disabled_branches
    uncovered_handle = any(duty.handle_required for duty in uncovered)
    no_substitute = uncovered_handle or not matching_duties or (not can_notify and not can_handle)

    if can_handle:
        state = HandoverState.ACTIONABLE
    elif uncovered_handle:
        state = HandoverState.NO_SUBSTITUTE
    elif can_notify:
        state = HandoverState.NOTIFIABLE
    else:
        state = HandoverState.NO_SUBSTITUTE

    release_blockers: list[str] = []
    if not recipients:
        release_blockers.append("no_notification_recipients")
    if not handlers:
        release_blockers.append("no_authorized_handler")
    elif not any(handler.release_basis for handler in handlers):
        release_blockers.append("handler_not_authorized_for_release")
    if uncovered_handle:
        release_blockers.append("required_handler_has_no_substitute")
    if processing.disabled_branches:
        release_blockers.append(
            "disabled_branch_requires_countersign:"
            + ",".join(processing.disabled_branches)
            + ":"
            + ",".join(processing.countersign_roles)
        )
    release_basis = (
        bool(recipients)
        and can_handle
        and any(handler.release_basis for handler in handlers)
        and not uncovered_handle
    )
    reference_only = bool(recipients) and not release_basis
    chain_id = "chain:" + _sha256(shift.shift_id + "|" + identity.key)[:16]
    chain = NotificationChain(
        chain_id=chain_id,
        identity=identity,
        shift_id=shift.shift_id,
        state=state,
        recipients=recipients,
        handlers=handlers,
        release_basis=release_basis,
        reference_only=reference_only,
        release_blockers=tuple(release_blockers),
        countersign_roles=processing.countersign_roles,
    )
    return RuleAudit(
        identity=identity,
        title=identity.title,
        name=identity.name,
        duplicate_name=duplicate_name,
        state=state,
        can_notify=can_notify,
        can_handle=can_handle,
        no_substitute=no_substitute,
        recipients=recipients,
        handlers=handlers,
        uncovered_duties=tuple(uncovered),
        processing=processing,
        countersign_roles=processing.countersign_roles,
        chain=chain,
        warnings=tuple(dict.fromkeys(warnings)),
    )


def audit_handover(
    rules: Iterable[SigmaRuleLike],
    shift: Shift,
    pipeline: ProcessingPipeline | None = None,
    branches: Iterable[ProcessingBranch] = (),
    generated_at: datetime | None = None,
) -> HandoverReport:
    """Audit an explicit shift against a set of Sigma rules.

    The audit is offline and deterministic.  It applies ``pipeline`` to a private
    copy of each rule, records the branch trace, resolves explicit duties and
    approved substitutes, and returns one notification chain per distinct rule
    identity.
    """
    branch_tuple = tuple(branches)
    rule_list = list(rules)
    identities = tuple(RuleIdentity.from_rule(rule) for rule in rule_list)
    name_counts = Counter(identity.name for identity in identities if identity.name)
    title_counts = Counter(identity.title for identity in identities if identity.title)
    duplicate_names = tuple(sorted(name for name, count in name_counts.items() if count > 1))
    duplicate_titles = tuple(sorted(title for title, count in title_counts.items() if count > 1))

    uuid_to_keys: dict[str, set[str]] = {}
    for identity in identities:
        if identity.rule_id is not None:
            uuid_to_keys.setdefault(identity.rule_id, set()).add(identity.key)
    ambiguous_uuids = {rule_id for rule_id, keys in uuid_to_keys.items() if len(keys) > 1}
    for duty in shift.duties:
        overlap = ambiguous_uuids & set(duty.selector.rule_ids)
        if overlap:
            raise SigmaHandoverIdentityError(
                "duty "
                + duty.duty_id
                + " selects an ambiguous Sigma UUID with multiple distinct contents: "
                + ", ".join(sorted(overlap))
            )
    for approval in shift.substitutes:
        overlap = ambiguous_uuids & set(approval.selector.rule_ids)
        if overlap:
            raise SigmaHandoverIdentityError(
                "substitute approval "
                + approval.approval_id
                + " selects an ambiguous Sigma UUID with multiple distinct contents: "
                + ", ".join(sorted(overlap))
            )

    unique: dict[str, tuple[RuleIdentity, SigmaRuleLike]] = {}
    for identity, rule in zip(identities, rule_list):
        unique.setdefault(identity.key, (identity, rule))

    report_warnings: list[str] = []
    for name in duplicate_names:
        report_warnings.append(
            "rule name "
            + name
            + " is shared by multiple distinct identities; permissions remain separate"
        )
    for title in duplicate_titles:
        report_warnings.append(
            "rule title "
            + title
            + " is shared by multiple distinct identities; permissions remain separate"
        )
    for rule_id, keys in uuid_to_keys.items():
        if len(keys) > 1:
            report_warnings.append(
                "Sigma UUID "
                + rule_id
                + " appears with "
                + str(len(keys))
                + " distinct rule contents; use identity keys for unambiguous grants"
            )

    audits = tuple(
        _audit_one_rule(
            rule=rule,
            identity=identity,
            shift=shift,
            pipeline=pipeline,
            branches=branch_tuple,
            duplicate_name=(
                (identity.name is not None and identity.name in duplicate_names)
                or identity.title in duplicate_titles
            ),
        )
        for identity, rule in unique.values()
    )
    if generated_at is None:
        generated_at = shift.starts_at
    else:
        if generated_at.tzinfo is None or generated_at.utcoffset() is None:
            raise SigmaHandoverConfigurationError(
                "generated_at must include an explicit timezone offset"
            )
    substitute_statuses = tuple(approval.status_for(shift) for approval in shift.substitutes)
    return HandoverReport(
        shift=shift,
        generated_at=generated_at,
        audits=audits,
        substitute_statuses=substitute_statuses,
        branches=branch_tuple,
        duplicate_names=duplicate_names,
        duplicate_titles=duplicate_titles,
        warnings=tuple(report_warnings),
    )


audit_shift_handover = audit_handover


def _md(value: Any) -> str:
    if value is None:
        return "-"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _recipient_text(recipients: Sequence[Recipient]) -> str:
    if not recipients:
        return "-"
    parts: list[str] = []
    for recipient in recipients:
        capabilities: list[str] = []
        if recipient.notify:
            capabilities.append("notify")
        if recipient.handle:
            capabilities.append("handle")
        if not recipient.release_basis:
            capabilities.append("reference-only")
        parts.append(
            recipient.role + " (" + "+".join(recipient.via) + "; " + "/".join(capabilities) + ")"
        )
    return ", ".join(parts)


def _render_markdown(
    report: HandoverReport,
    chains: Sequence[NotificationChain],
    reference_only_only: bool,
) -> str:
    shift = report.shift
    if reference_only_only:
        scope_keys = {chain.identity.key for chain in chains}
        audits = tuple(audit for audit in report.audits if audit.identity.key in scope_keys)
    else:
        audits = report.audits
    lines: list[str] = []
    if reference_only_only:
        lines.append("# Offline Shift Handover Audit - Reference-Only Chains")
    else:
        lines.append("# Offline Shift Handover Audit")
    lines.append("")
    lines.append("## Shift")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append("| Shift | " + _md(shift.shift_id) + " |")
    lines.append(
        "| Window | "
        + _md(shift.starts_at.isoformat())
        + " to "
        + _md(shift.ends_at.isoformat())
        + " |"
    )
    lines.append("| On duty | " + _md(", ".join(shift.on_duty)) + " |")
    lines.append("| Generated at | " + _md(report.generated_at.isoformat()) + " |")
    counts = report.state_counts()
    lines.append(
        "| Rule states | "
        + str(counts[HandoverState.ACTIONABLE.value])
        + " actionable, "
        + str(counts[HandoverState.NOTIFIABLE.value])
        + " notifiable, "
        + str(counts[HandoverState.NO_SUBSTITUTE.value])
        + " no substitute |"
    )
    lines.append("| Reference-only chains | " + str(len(report.reference_only_chains)) + " |")
    lines.append("")
    lines.append(
        "Permissions are keyed by rule identity (Sigma UUID plus content digest). "
        "Name and title are never used as permission keys."
    )
    if reference_only_only:
        lines.append("")
        lines.append(
            "Filter: reference-only notification chains only. Summary counts still "
            "describe the full shift."
        )
    lines.append("")

    if report.duplicate_names or report.duplicate_titles:
        lines.append("## Duplicate names that were not merged")
        lines.append("")
        for name in report.duplicate_names:
            lines.append("- name: " + _md(name))
        for title in report.duplicate_titles:
            lines.append("- title: " + _md(title))
        lines.append("")
        lines.append(
            "Each duplicate is audited as a separate identity. A permission granted "
            "to one identity does not apply to the other."
        )
        lines.append("")

    lines.append("## Processing branches")
    lines.append("")
    if report.branches:
        lines.append("| Branch | Items | State | Countersign role | Reason |")
        lines.append("| --- | --- | --- | --- | --- |")
        for branch in report.branches:
            lines.append(
                "| "
                + _md(branch.branch_id)
                + " | "
                + _md(", ".join(branch.processing_item_ids))
                + " | "
                + _md(branch.state.value)
                + " | "
                + _md(branch.historical_role)
                + " | "
                + _md(branch.reason)
                + " |"
            )
    else:
        lines.append("No processing branches configured.")
    lines.append("")

    lines.append("## Approved substitutes")
    lines.append("")
    if report.substitute_statuses:
        lines.append("| Approval | For role | Substitute | Effective | Reason |")
        lines.append("| --- | --- | --- | --- | --- |")
        for status in report.substitute_statuses:
            lines.append(
                "| "
                + _md(status.approval_id)
                + " | "
                + _md(status.for_role)
                + " | "
                + _md(status.substitute)
                + " | "
                + _yes_no(status.effective)
                + " | "
                + _md(status.reason)
                + " |"
            )
    else:
        lines.append("No substitutes were submitted.")
    lines.append("")

    lines.append("## Rule audit")
    lines.append("")
    lines.append(
        "| Identity | Title / name | State | Notify | Handle | No substitute | "
        "Countersign | Chain | Reference only |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for audit in audits:
        title = audit.title
        if audit.name is not None and audit.name != audit.title:
            title += " / " + audit.name
        lines.append(
            "| "
            + _md(audit.identity.key)
            + " | "
            + _md(title)
            + " | "
            + _md(audit.state.label)
            + " | "
            + _yes_no(audit.can_notify)
            + " | "
            + _yes_no(audit.can_handle)
            + " | "
            + _yes_no(audit.no_substitute)
            + " | "
            + _md(", ".join(audit.countersign_roles))
            + " | "
            + _md(audit.chain.chain_id)
            + " | "
            + _yes_no(audit.chain.reference_only)
            + " |"
        )
    lines.append("")

    lines.append("## Rules in detail")
    lines.append("")
    for audit in audits:
        lines.append("### " + _md(audit.title) + " (`" + audit.identity.key + "`)")
        lines.append("")
        lines.append("- Identity: `" + audit.identity.key + "`")
        lines.append("- Sigma UUID: " + _md(audit.identity.rule_id))
        lines.append("- Name: " + _md(audit.name))
        if audit.identity.source is not None:
            lines.append("- Source: " + _md(audit.identity.source))
        lines.append("- State: " + audit.state.label)
        lines.append("- Can notify: " + _yes_no(audit.can_notify))
        lines.append("- Can handle: " + _yes_no(audit.can_handle))
        lines.append("- No substitute: " + _yes_no(audit.no_substitute))
        lines.append(
            "- Processing chain: "
            + _md(audit.processing.pipeline_name)
            + " -> "
            + _md(", ".join(audit.processing.applied_item_ids) or "-")
        )
        lines.append("- Branches: " + _md(", ".join(audit.processing.applied_branches) or "-"))
        lines.append(
            "- Disabled branches: " + _md(", ".join(audit.processing.disabled_branches) or "-")
        )
        if audit.processing.field_mappings:
            mappings = ", ".join(
                ("<keyword>" if source is None else source) + " -> " + "/".join(targets)
                for source, targets in audit.processing.field_mappings.items()
            )
            lines.append("- Field mappings: " + _md(mappings))
        lines.append("- Recipients: " + _md(_recipient_text(audit.recipients)))
        if audit.uncovered_duties:
            lines.append(
                "- Uncovered duties: "
                + _md(
                    "; ".join(
                        duty.duty_id + " (role " + duty.role + ": " + duty.reason + ")"
                        for duty in audit.uncovered_duties
                    )
                )
            )
        lines.append("- Countersign roles: " + _md(", ".join(audit.countersign_roles) or "-"))
        lines.append(
            "- Notification chain: `"
            + audit.chain.chain_id
            + "` (release basis: "
            + _yes_no(audit.chain.release_basis)
            + "; reference only: "
            + _yes_no(audit.chain.reference_only)
            + ")"
        )
        if audit.chain.release_blockers:
            lines.append("- Release blockers: " + _md(", ".join(audit.chain.release_blockers)))
        if audit.warnings:
            lines.append("- Warnings: " + _md("; ".join(audit.warnings)))
        lines.append("")

    if reference_only_only:
        lines.append("## Reference-only notification chains")
        lines.append("")
        lines.append(
            "> These chains are reference material only. They MUST NOT be used as "
            "a shift release basis."
        )
        lines.append("")
    else:
        lines.append("## Notification chains")
        lines.append("")
    if not chains:
        lines.append("No matching notification chains.")
        lines.append("")
    for chain in chains:
        lines.append("### " + chain.chain_id)
        lines.append("")
        lines.append("- Rule: " + chain.identity.title + " (`" + chain.identity.key + "`)")
        lines.append("- State: " + chain.state.label)
        lines.append("- Reference only: " + _yes_no(chain.reference_only))
        lines.append("- Release basis: " + _yes_no(chain.release_basis))
        lines.append("- Recipients: " + _md(_recipient_text(chain.recipients)))
        lines.append("- Handler grants: " + _md(_recipient_text(chain.handlers)))
        lines.append("- Countersign roles: " + _md(", ".join(chain.countersign_roles) or "-"))
        if chain.release_blockers:
            lines.append("- Blockers: " + _md(", ".join(chain.release_blockers)))
        lines.append("")

    if report.warnings:
        lines.append("## Audit warnings")
        lines.append("")
        for warning in report.warnings:
            lines.append("- " + _md(warning))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


@dataclass(frozen=True)
class HandoverConfig:
    """A complete offline audit input: shift duties plus branch state."""

    shift: Shift
    branches: tuple[ProcessingBranch, ...] = ()

    @classmethod
    def from_dict(cls, value: Any) -> HandoverConfig:
        data = _as_mapping(value, "handover config")
        _check_keys(data, {"shift", "branches"}, "handover config")
        if "shift" not in data:
            raise SigmaHandoverConfigurationError("handover config requires shift")
        raw_branches = data.get("branches", [])
        if raw_branches is None:
            raw_branches = []
        if not isinstance(raw_branches, list):
            raise SigmaHandoverConfigurationError("handover config branches must be a list")
        return cls(
            shift=Shift.from_dict(data["shift"]),
            branches=tuple(ProcessingBranch.from_dict(branch) for branch in raw_branches),
        )

    @classmethod
    def from_yaml(cls, value: str) -> HandoverConfig:
        try:
            parsed = yaml.safe_load(value)
        except yaml.YAMLError as exc:
            raise SigmaHandoverConfigurationError("invalid handover config YAML") from exc
        return cls.from_dict(parsed)


def audit_from_config(
    rules: Iterable[SigmaRuleLike],
    config: HandoverConfig,
    pipeline: ProcessingPipeline | None = None,
    generated_at: datetime | None = None,
) -> HandoverReport:
    """Audit rules against a parsed handover configuration."""
    return audit_handover(
        rules=rules,
        shift=config.shift,
        pipeline=pipeline,
        branches=config.branches,
        generated_at=generated_at,
    )
