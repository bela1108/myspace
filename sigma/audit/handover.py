from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, TYPE_CHECKING
from uuid import UUID

import yaml

from sigma.exceptions import SigmaAuditError
from sigma.rule import SigmaRule

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline


class Responsibility(str, Enum):
    """Explicit responsibility attached to a shift duty."""

    NOTIFY = "notify"
    HANDLE = "handle"

    @classmethod
    def parse(cls, value: "Responsibility | str") -> "Responsibility":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as e:
            raise SigmaAuditError(
                f"Unknown shift responsibility '{value}'; expected 'notify' or 'handle'"
            ) from e


class AuditStatus(str, Enum):
    """Result of evaluating one rule against one shift roster."""

    NOTIFIABLE = "notifiable"
    ACTIONABLE = "actionable"
    NO_SUBSTITUTE = "no_substitute"

    @classmethod
    def parse(cls, value: "AuditStatus | str") -> "AuditStatus":
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower().replace("-", "_")
        if normalized in ("nosubstitute", "no_substitution"):
            normalized = "no_substitute"
        try:
            return cls(normalized)
        except ValueError as e:
            raise SigmaAuditError(
                f"Unknown audit status '{value}'; expected 'notifiable', 'actionable' or "
                "'no_substitute'"
            ) from e


def _parse_datetime(value: datetime | str, field_name: str) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as e:
            raise SigmaAuditError(
                f"{field_name} must be an ISO-8601 datetime with a timezone offset"
            ) from e
    else:
        raise SigmaAuditError(f"{field_name} must be a datetime or ISO-8601 string")

    if result.tzinfo is None or result.utcoffset() is None:
        raise SigmaAuditError(
            f"{field_name} must include an explicit timezone offset, "
            "e.g. '2026-11-23T02:10:00+08:00'"
        )
    return result


def _parse_uuid(value: UUID | str, field_name: str) -> UUID:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (ValueError, AttributeError, TypeError) as e:
        raise SigmaAuditError(f"{field_name} must be a UUID, got '{value}'") from e


def _uuid_set(value: Iterable[UUID | str] | None, field_name: str) -> frozenset[UUID] | None:
    if value is None:
        return None
    if isinstance(value, (str, UUID)):
        raise SigmaAuditError(f"{field_name} must be a list of UUIDs")
    return frozenset(_parse_uuid(item, field_name) for item in value)


def _string_set(value: Iterable[str] | None, field_name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    return frozenset(str(item) for item in value)


def _require_nonempty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SigmaAuditError(f"{field_name} must be a non-empty string")
    return value


def _parse_bool(value: bool | str, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "yes", "1"):
            return True
        if normalized in ("false", "no", "0"):
            return False
    raise SigmaAuditError(f"{field_name} must be a boolean")


def _isoformat(value: datetime) -> str:
    return value.isoformat()


def _md_cell(value: object) -> str:
    """Escape a value for a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ")


@dataclass(frozen=True)
class BranchSteward:
    """A role that owned a processing branch for a bounded period."""

    role: str
    effective_from: datetime
    effective_to: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.role, "BranchSteward.role")
        start = _parse_datetime(self.effective_from, "BranchSteward.effective_from")
        end = (
            _parse_datetime(self.effective_to, "BranchSteward.effective_to")
            if self.effective_to is not None
            else None
        )
        if end is not None and end <= start:
            raise SigmaAuditError("BranchSteward.effective_to must be after effective_from")
        object.__setattr__(self, "effective_from", start)
        object.__setattr__(self, "effective_to", end)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BranchSteward":
        return cls(
            role=data["role"],
            effective_from=data["effective_from"],
            effective_to=data.get("effective_to"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "effective_from": _isoformat(self.effective_from),
            "effective_to": _isoformat(self.effective_to) if self.effective_to else None,
        }


@dataclass(frozen=True)
class ReleaseBranch:
    """
    A release-relevant branch in a processing chain.

    ``processing_item_id`` is matched against pySigma's applied processing item identifiers.
    ``rule_ids`` scopes a branch to specific Sigma rule UUIDs. A disabled branch is reported as
    temporarily closed even when its processing item was applied.
    """

    branch_id: str
    processing_item_id: str
    owner_role: str
    required: bool = True
    enabled: bool = True
    countersign_role: str | None = None
    rule_ids: frozenset[UUID] | None = None
    history: tuple[BranchSteward, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty(self.branch_id, "ReleaseBranch.branch_id")
        _require_nonempty(self.processing_item_id, "ReleaseBranch.processing_item_id")
        _require_nonempty(self.owner_role, "ReleaseBranch.owner_role")
        if self.countersign_role is not None:
            _require_nonempty(self.countersign_role, "ReleaseBranch.countersign_role")
        object.__setattr__(self, "rule_ids", _uuid_set(self.rule_ids, "ReleaseBranch.rule_ids"))
        object.__setattr__(
            self,
            "history",
            tuple(item if isinstance(item, BranchSteward) else BranchSteward.from_dict(item)
                  for item in self.history),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReleaseBranch":
        return cls(
            branch_id=data.get("id", data.get("branch_id")),
            processing_item_id=data["processing_item_id"],
            owner_role=data["owner_role"],
            required=_parse_bool(data.get("required", True), "ReleaseBranch.required"),
            enabled=_parse_bool(data.get("enabled", True), "ReleaseBranch.enabled"),
            countersign_role=data.get("countersign_role"),
            rule_ids=data.get("rule_ids"),
            history=tuple(data.get("history", ())),
        )

    def applies_to(self, rule_id: UUID) -> bool:
        return self.rule_ids is None or rule_id in self.rule_ids

    def historical_countersign_role(self, at: datetime) -> str | None:
        """
        Return the most recent stewardship role that had already ended at ``at``.

        If no tenure has ended yet, return the latest known stewardship role. An explicit
        ``countersign_role`` on the branch always takes precedence over this fallback.
        """
        ended = [
            steward
            for steward in self.history
            if steward.effective_to is not None and steward.effective_to <= at
        ]
        if ended:
            return max(
                ended,
                key=lambda item: (item.effective_to, item.effective_from),
            ).role
        if self.history:
            return max(
                self.history,
                key=lambda item: (
                    item.effective_to or datetime.max.replace(tzinfo=at.tzinfo),
                    item.effective_from,
                ),
            ).role
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.branch_id,
            "processing_item_id": self.processing_item_id,
            "owner_role": self.owner_role,
            "required": self.required,
            "enabled": self.enabled,
            "countersign_role": self.countersign_role,
            "rule_ids": [str(item) for item in self.rule_ids] if self.rule_ids else None,
            "history": [steward.to_dict() for steward in self.history],
        }


@dataclass(frozen=True)
class ShiftDuty:
    """
    Explicit shift responsibility.

    A duty never implies another responsibility. In particular, a notify duty does not grant
    handling authority. ``rule_ids`` and ``branch_ids`` are UUID/branch scoped, not title scoped.
    """

    role: str
    responsibility: Responsibility
    person: str
    available: bool = True
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    rule_ids: frozenset[UUID] | None = None
    branch_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _require_nonempty(self.role, "ShiftDuty.role")
        _require_nonempty(self.person, "ShiftDuty.person")
        object.__setattr__(self, "responsibility", Responsibility.parse(self.responsibility))
        start = (
            _parse_datetime(self.valid_from, "ShiftDuty.valid_from")
            if self.valid_from is not None
            else None
        )
        end = (
            _parse_datetime(self.valid_to, "ShiftDuty.valid_to")
            if self.valid_to is not None
            else None
        )
        if start is not None and end is not None and end <= start:
            raise SigmaAuditError("ShiftDuty.valid_to must be after valid_from")
        object.__setattr__(self, "valid_from", start)
        object.__setattr__(self, "valid_to", end)
        object.__setattr__(self, "rule_ids", _uuid_set(self.rule_ids, "ShiftDuty.rule_ids"))
        object.__setattr__(
            self, "branch_ids", _string_set(self.branch_ids, "ShiftDuty.branch_ids")
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ShiftDuty":
        return cls(
            role=data["role"],
            responsibility=data["responsibility"],
            person=data["person"],
            available=_parse_bool(data.get("available", True), "ShiftDuty.available"),
            valid_from=data.get("valid_from"),
            valid_to=data.get("valid_to"),
            rule_ids=data.get("rule_ids"),
            branch_ids=data.get("branch_ids", ()),
        )

    def is_available_at(self, at: datetime) -> bool:
        if not self.available:
            return False
        if self.valid_from is not None and at < self.valid_from:
            return False
        if self.valid_to is not None and at >= self.valid_to:
            return False
        return True

    def applies_to(self, rule_id: UUID, branch_ids: frozenset[str]) -> bool:
        if self.rule_ids is not None and rule_id not in self.rule_ids:
            return False
        if self.branch_ids and not (self.branch_ids & branch_ids):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "responsibility": self.responsibility.value,
            "person": self.person,
            "available": self.available,
            "valid_from": _isoformat(self.valid_from) if self.valid_from else None,
            "valid_to": _isoformat(self.valid_to) if self.valid_to else None,
            "rule_ids": [str(item) for item in self.rule_ids] if self.rule_ids else None,
            "branch_ids": sorted(self.branch_ids),
        }


@dataclass(frozen=True)
class ApprovedSubstitution:
    """
    An explicitly approved substitute for a duty role.

    Approval metadata is mandatory. A substitution without an approver and approval reference is
    a configuration error rather than an implicitly trusted override.
    """

    role: str
    substitute_person: str
    approved_by: str
    approval_ref: str
    approved_at: datetime
    valid_from: datetime
    valid_to: datetime | None = None
    substitute_role: str | None = None
    rule_ids: frozenset[UUID] | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.role, "ApprovedSubstitution.role")
        _require_nonempty(self.substitute_person, "ApprovedSubstitution.substitute_person")
        _require_nonempty(self.approved_by, "ApprovedSubstitution.approved_by")
        _require_nonempty(self.approval_ref, "ApprovedSubstitution.approval_ref")
        if self.substitute_role is not None:
            _require_nonempty(self.substitute_role, "ApprovedSubstitution.substitute_role")
        approved_at = _parse_datetime(self.approved_at, "ApprovedSubstitution.approved_at")
        start = _parse_datetime(self.valid_from, "ApprovedSubstitution.valid_from")
        end = (
            _parse_datetime(self.valid_to, "ApprovedSubstitution.valid_to")
            if self.valid_to is not None
            else None
        )
        if end is not None and end <= start:
            raise SigmaAuditError("ApprovedSubstitution.valid_to must be after valid_from")
        if approved_at > start:
            raise SigmaAuditError(
                "ApprovedSubstitution.approved_at must not be later than valid_from"
            )
        object.__setattr__(self, "approved_at", approved_at)
        object.__setattr__(self, "valid_from", start)
        object.__setattr__(self, "valid_to", end)
        object.__setattr__(
            self, "rule_ids", _uuid_set(self.rule_ids, "ApprovedSubstitution.rule_ids")
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ApprovedSubstitution":
        return cls(
            role=data["role"],
            substitute_person=data["substitute_person"],
            approved_by=data["approved_by"],
            approval_ref=data["approval_ref"],
            approved_at=data.get("approved_at", data["valid_from"]),
            valid_from=data["valid_from"],
            valid_to=data.get("valid_to"),
            substitute_role=data.get("substitute_role"),
            rule_ids=data.get("rule_ids"),
        )

    def is_valid_at(self, at: datetime) -> bool:
        if at < self.valid_from:
            return False
        if self.valid_to is not None and at >= self.valid_to:
            return False
        return True

    def applies_to(self, rule_id: UUID) -> bool:
        return self.rule_ids is None or rule_id in self.rule_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "substitute_person": self.substitute_person,
            "substitute_role": self.substitute_role,
            "approved_by": self.approved_by,
            "approval_ref": self.approval_ref,
            "approved_at": _isoformat(self.approved_at),
            "valid_from": _isoformat(self.valid_from),
            "valid_to": _isoformat(self.valid_to) if self.valid_to else None,
            "rule_ids": [str(item) for item in self.rule_ids] if self.rule_ids else None,
        }


@dataclass(frozen=True)
class ResolvedAssignment:
    """An effective person/role assignment for one responsibility."""

    role: str
    person: str
    responsibility: Responsibility
    source: str
    substitute_role: str | None = None
    approval_ref: str | None = None
    approved_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "person": self.person,
            "responsibility": self.responsibility.value,
            "source": self.source,
            "substitute_role": self.substitute_role,
            "approval_ref": self.approval_ref,
            "approved_by": self.approved_by,
        }


@dataclass(frozen=True)
class OpenBranch:
    branch_id: str
    processing_item_id: str
    owner_role: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.branch_id,
            "processing_item_id": self.processing_item_id,
            "owner_role": self.owner_role,
        }


@dataclass(frozen=True)
class ClosedBranch:
    branch_id: str
    processing_item_id: str
    owner_role: str
    reason: str
    required: bool
    countersign_role: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.branch_id,
            "processing_item_id": self.processing_item_id,
            "owner_role": self.owner_role,
            "reason": self.reason,
            "required": self.required,
            "countersign_role": self.countersign_role,
        }


@dataclass(frozen=True)
class NotificationChain:
    """One rule's audited notification/handling chain."""

    chain_id: str
    rule_id: UUID
    rule_title: str
    rule_name: str | None
    status: AuditStatus
    can_notify: bool
    can_handle: bool
    has_substitute: bool
    release_basis: bool
    reference_only: bool
    escalation_required: bool
    notify_assignments: tuple[ResolvedAssignment, ...]
    handle_assignments: tuple[ResolvedAssignment, ...]
    open_branches: tuple[OpenBranch, ...]
    closed_branches: tuple[ClosedBranch, ...]
    uncovered_handle_roles: tuple[str, ...]
    same_title_ids: tuple[UUID, ...]
    reason_codes: tuple[str, ...]
    reasons: tuple[str, ...]
    pipeline_name: str | None
    audit_time: datetime

    @property
    def countersign_roles(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    branch.countersign_role
                    for branch in self.closed_branches
                    if branch.countersign_role is not None
                }
            )
        )

    @property
    def requires_countersign(self) -> bool:
        return bool(self.closed_branches)

    @property
    def notifiable(self) -> bool:
        """True when the chain is notify-only and therefore reference-only."""
        return self.status == AuditStatus.NOTIFIABLE

    @property
    def actionable(self) -> bool:
        """True when handling coverage and branch evidence are sufficient for this shift."""
        return self.status == AuditStatus.ACTIONABLE

    @property
    def no_substitute(self) -> bool:
        """True when handling coverage is blocked for lack of an approved substitute."""
        return self.status == AuditStatus.NO_SUBSTITUTE

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "rule": {
                "id": str(self.rule_id),
                "title": self.rule_title,
                "name": self.rule_name,
            },
            "status": self.status.value,
            "notifiable": self.notifiable,
            "actionable": self.actionable,
            "no_substitute": self.no_substitute,
            "can_notify": self.can_notify,
            "can_handle": self.can_handle,
            "has_substitute": self.has_substitute,
            "release_basis": self.release_basis,
            "reference_only": self.reference_only,
            "escalation_required": self.escalation_required,
            "notify": [item.to_dict() for item in self.notify_assignments],
            "handle": [item.to_dict() for item in self.handle_assignments],
            "open_branches": [item.to_dict() for item in self.open_branches],
            "closed_branches": [item.to_dict() for item in self.closed_branches],
            "countersign_roles": list(self.countersign_roles),
            "uncovered_handle_roles": list(self.uncovered_handle_roles),
            "same_title_ids": [str(item) for item in self.same_title_ids],
            "reason_codes": list(self.reason_codes),
            "reasons": list(self.reasons),
            "pipeline": self.pipeline_name,
            "audit_time": _isoformat(self.audit_time),
        }


@dataclass(frozen=True)
class HandoverAuditConfig:
    """Explicit offline handover input: shift, duties, approvals and processing branches."""

    shift_id: str
    audit_time: datetime
    duties: tuple[ShiftDuty, ...]
    substitutions: tuple[ApprovedSubstitution, ...] = ()
    branches: tuple[ReleaseBranch, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty(self.shift_id, "HandoverAuditConfig.shift_id")
        object.__setattr__(
            self, "audit_time", _parse_datetime(self.audit_time, "HandoverAuditConfig.audit_time")
        )
        object.__setattr__(
            self,
            "duties",
            tuple(item if isinstance(item, ShiftDuty) else ShiftDuty.from_dict(item)
                  for item in self.duties),
        )
        object.__setattr__(
            self,
            "substitutions",
            tuple(
                item if isinstance(item, ApprovedSubstitution)
                else ApprovedSubstitution.from_dict(item)
                for item in self.substitutions
            ),
        )
        object.__setattr__(
            self,
            "branches",
            tuple(item if isinstance(item, ReleaseBranch) else ReleaseBranch.from_dict(item)
                  for item in self.branches),
        )
        branch_ids = [branch.branch_id for branch in self.branches]
        if len(branch_ids) != len(set(branch_ids)):
            raise SigmaAuditError("HandoverAuditConfig contains duplicate branch ids")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HandoverAuditConfig":
        known_keys = {"shift", "duties", "approved_substitutions", "branches"}
        unknown_keys = sorted(set(data) - known_keys)
        if unknown_keys:
            raise SigmaAuditError(
                "Unknown handover audit configuration keys: " + ", ".join(unknown_keys)
            )
        try:
            shift = data["shift"]
            if not isinstance(shift, Mapping):
                raise SigmaAuditError("Handover audit 'shift' must be a mapping")
            return cls(
                shift_id=shift["id"],
                audit_time=shift["audit_time"],
                duties=tuple(data.get("duties", ())),
                substitutions=tuple(data.get("approved_substitutions", ())),
                branches=tuple(data.get("branches", ())),
            )
        except KeyError as e:
            raise SigmaAuditError(f"Missing handover audit configuration key: {e}") from e

    @classmethod
    def from_yaml(cls, yaml_str: str | bytes) -> "HandoverAuditConfig":
        try:
            data = yaml.safe_load(yaml_str)
        except yaml.YAMLError as e:
            raise SigmaAuditError("Invalid handover audit YAML") from e
        if not isinstance(data, Mapping):
            raise SigmaAuditError("Handover audit YAML must contain a mapping at the document root")
        return cls.from_dict(data)

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> "HandoverAuditConfig":
        return cls.from_yaml(Path(path).read_bytes())

    def to_dict(self) -> dict[str, Any]:
        return {
            "shift": {
                "id": self.shift_id,
                "audit_time": _isoformat(self.audit_time),
            },
            "duties": [duty.to_dict() for duty in self.duties],
            "approved_substitutions": [
                substitution.to_dict() for substitution in self.substitutions
            ],
            "branches": [branch.to_dict() for branch in self.branches],
        }


@dataclass(frozen=True)
class HandoverAuditReport:
    """Filterable offline audit report."""

    shift_id: str
    audit_time: datetime
    chains: tuple[NotificationChain, ...]
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty(self.shift_id, "HandoverAuditReport.shift_id")
        object.__setattr__(
            self, "audit_time", _parse_datetime(self.audit_time, "HandoverAuditReport.audit_time")
        )
        object.__setattr__(self, "chains", tuple(self.chains))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        groups: defaultdict[str, list[UUID]] = defaultdict(list)
        name_groups: defaultdict[str, list[UUID]] = defaultdict(list)
        for chain in self.chains:
            groups[chain.rule_title].append(chain.rule_id)
            if chain.rule_name:
                name_groups[chain.rule_name].append(chain.rule_id)
        object.__setattr__(
            self,
            "same_title_groups",
            {
                title: tuple(sorted(ids, key=str))
                for title, ids in groups.items()
                if len(ids) > 1
            },
        )
        object.__setattr__(
            self,
            "same_name_groups",
            {
                name: tuple(sorted(ids, key=str))
                for name, ids in name_groups.items()
                if len(ids) > 1
            },
        )

    same_title_groups: dict[str, tuple[UUID, ...]] = field(
        init=False, compare=False, default_factory=dict
    )
    same_name_groups: dict[str, tuple[UUID, ...]] = field(
        init=False, compare=False, default_factory=dict
    )

    def filter(
        self,
        *,
        status: AuditStatus | str | None = None,
        release_basis: bool | None = None,
        reference_only: bool | None = None,
        escalation_required: bool | None = None,
        rule_id: UUID | str | None = None,
        title: str | None = None,
        countersign_role: str | None = None,
        closed_branch: str | None = None,
    ) -> list[NotificationChain]:
        """Return chains matching all supplied predicates."""
        parsed_status = AuditStatus.parse(status) if status is not None else None
        parsed_rule_id = _parse_uuid(rule_id, "rule_id") if rule_id is not None else None
        result: list[NotificationChain] = []
        for chain in self.chains:
            if parsed_status is not None and chain.status != parsed_status:
                continue
            if release_basis is not None and chain.release_basis != release_basis:
                continue
            if reference_only is not None and chain.reference_only != reference_only:
                continue
            if (
                escalation_required is not None
                and chain.escalation_required != escalation_required
            ):
                continue
            if parsed_rule_id is not None and chain.rule_id != parsed_rule_id:
                continue
            if title is not None and chain.rule_title != title:
                continue
            if countersign_role is not None and countersign_role not in chain.countersign_roles:
                continue
            if closed_branch is not None and not any(
                branch.branch_id == closed_branch for branch in chain.closed_branches
            ):
                continue
            result.append(chain)
        return result

    def reference_only_chains(self) -> list[NotificationChain]:
        """Chains that may be used for awareness only and never as a release basis."""
        return self.filter(reference_only=True, release_basis=False)

    def summary(self) -> dict[str, Any]:
        counts = {status.value: 0 for status in AuditStatus}
        for chain in self.chains:
            counts[chain.status.value] += 1
        return {
            "shift_id": self.shift_id,
            "audit_time": _isoformat(self.audit_time),
            "rule_count": len(self.chains),
            "status_counts": counts,
            "release_basis_count": sum(1 for chain in self.chains if chain.release_basis),
            "reference_only_count": sum(1 for chain in self.chains if chain.reference_only),
            "escalation_required_count": sum(
                1 for chain in self.chains if chain.escalation_required
            ),
            "countersign_required_count": sum(
                1 for chain in self.chains if chain.requires_countersign
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "shift_id": self.shift_id,
            "audit_time": _isoformat(self.audit_time),
            "summary": self.summary(),
            "warnings": list(self.warnings),
            "same_title_groups": {
                title: [str(rule_id) for rule_id in ids]
                for title, ids in self.same_title_groups.items()
            },
            "same_name_groups": {
                name: [str(rule_id) for rule_id in ids]
                for name, ids in self.same_name_groups.items()
            },
            "chains": [chain.to_dict() for chain in self.chains],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_markdown(self) -> str:
        lines = [
            f"# Offline handover audit: {self.shift_id}",
            "",
            f"- Audit time: `{_isoformat(self.audit_time)}`",
            f"- Rules audited: {len(self.chains)}",
            f"- Release-basis chains: {self.summary()['release_basis_count']}",
            f"- Reference-only chains: {self.summary()['reference_only_count']}",
            "",
            "## Status summary",
            "",
            "| Status | Count |",
            "| --- | ---: |",
        ]
        for status, count in self.summary()["status_counts"].items():
            lines.append(f"| `{status}` | {count} |")

        lines.extend(
            [
                "",
                "## Notification chains",
                "",
                "| Chain | Rule | Rule ID | Status | Notify | Handle | Release basis | "
                "Countersign |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for chain in self.chains:
            notify_people = (
                ", ".join(
                    _md_cell(f"{item.person} ({item.role})")
                    for item in chain.notify_assignments
                )
                or "-"
            )
            handle_people = (
                ", ".join(
                    _md_cell(
                        f"{item.person} ({item.role}"
                        f"{', substitute' if item.source != 'primary' else ''})"
                    )
                    for item in chain.handle_assignments
                )
                or "-"
            )
            countersign = _md_cell(", ".join(chain.countersign_roles) or "-")
            lines.append(
                "| {chain} | {title} | `{rule_id}` | `{status}` | {notify} | {handle} | "
                "{release} | {countersign} |".format(
                    chain=_md_cell(chain.chain_id),
                    title=_md_cell(chain.rule_title),
                    rule_id=chain.rule_id,
                    status=chain.status.value,
                    notify=notify_people,
                    handle=handle_people,
                    release="yes" if chain.release_basis else "no",
                    countersign=countersign,
                )
            )

        lines.extend(["", "## Reference-only chains", ""])
        reference_only = self.reference_only_chains()
        if not reference_only:
            lines.append("None.")
        else:
            for chain in reference_only:
                lines.append(
                    f"- `{_md_cell(chain.chain_id)}` ({_md_cell(chain.rule_title)}, "
                    f"`{chain.rule_id}`): "
                    "reference only; do **not** use this chain as an on-call release basis."
                )

        lines.extend(["", "## Closed branches and countersigns", ""])
        closed_entries = [
            (chain, branch)
            for chain in self.chains
            for branch in chain.closed_branches
        ]
        if not closed_entries:
            lines.append("None.")
        else:
            for chain, branch in closed_entries:
                role = branch.countersign_role or "UNASSIGNED"
                lines.append(
                    f"- `{_md_cell(chain.chain_id)}` / `{_md_cell(branch.branch_id)}`: "
                    f"{_md_cell(branch.reason)}; countersign role: `{_md_cell(role)}`."
                )

        if self.warnings:
            lines.extend(["", "## Warnings", ""])
            lines.extend(f"- {warning}" for warning in self.warnings)

        return "\n".join(lines) + "\n"


class HandoverAuditor:
    """Evaluate rules against an explicit shift roster and a pySigma processing chain."""

    def __init__(self, config: HandoverAuditConfig):
        self.config = config

    @staticmethod
    def _rule_id(rule: SigmaRule) -> UUID:
        if rule.id is None:
            raise SigmaAuditError(
                f"Rule '{rule.title}' has no UUID; rule identity is required for handover audit"
            )
        return _parse_uuid(rule.id, f"rule '{rule.title}' id")

    @staticmethod
    def _rule_title(rule: SigmaRule) -> str:
        return rule.title or rule.name or "<untitled>"

    def _find_substitution(
        self,
        role: str,
        rule_id: UUID,
        at: datetime,
    ) -> ApprovedSubstitution | None:
        candidates = [
            substitution
            for substitution in self.config.substitutions
            if substitution.role == role
            and substitution.applies_to(rule_id)
            and substitution.is_valid_at(at)
        ]
        if len(candidates) > 1:
            refs = ", ".join(sorted(item.approval_ref for item in candidates))
            raise SigmaAuditError(
                f"Ambiguous approved substitutions for role '{role}' at {_isoformat(at)}: {refs}"
            )
        return candidates[0] if candidates else None

    def _resolve(
        self,
        duties: Iterable[ShiftDuty],
        responsibility: Responsibility,
        rule_id: UUID,
        at: datetime,
    ) -> tuple[list[ResolvedAssignment], list[str]]:
        assignments: list[ResolvedAssignment] = []
        uncovered_roles: list[str] = []
        for duty in duties:
            if duty.responsibility != responsibility:
                continue
            if duty.is_available_at(at):
                assignments.append(
                    ResolvedAssignment(
                        role=duty.role,
                        person=duty.person,
                        responsibility=responsibility,
                        source="primary",
                    )
                )
                continue
            substitution = self._find_substitution(duty.role, rule_id, at)
            if substitution is None:
                uncovered_roles.append(duty.role)
                continue
            assignments.append(
                ResolvedAssignment(
                    role=duty.role,
                    person=substitution.substitute_person,
                    responsibility=responsibility,
                    source="approved_substitute",
                    substitute_role=substitution.substitute_role,
                    approval_ref=substitution.approval_ref,
                    approved_by=substitution.approved_by,
                )
            )
        return assignments, uncovered_roles

    def _branch_state(
        self,
        branch: ReleaseBranch,
        applied_ids: set[str],
        pipeline_item_ids: set[str],
        at: datetime,
    ) -> OpenBranch | ClosedBranch:
        reason: str | None = None
        if not branch.enabled:
            reason = "temporarily_disabled"
        elif branch.processing_item_id not in pipeline_item_ids:
            reason = "missing_from_pipeline"
        elif branch.processing_item_id not in applied_ids:
            reason = "condition_not_matched"

        if reason is None:
            return OpenBranch(
                branch_id=branch.branch_id,
                processing_item_id=branch.processing_item_id,
                owner_role=branch.owner_role,
            )

        countersign_role = (
            branch.countersign_role or branch.historical_countersign_role(at)
        )
        return ClosedBranch(
            branch_id=branch.branch_id,
            processing_item_id=branch.processing_item_id,
            owner_role=branch.owner_role,
            reason=reason,
            required=branch.required,
            countersign_role=countersign_role,
        )

    def audit_rule(
        self,
        rule: SigmaRule,
        pipeline: "ProcessingPipeline",
        *,
        at: datetime | None = None,
        same_title_ids: tuple[UUID, ...] = (),
    ) -> NotificationChain:
        audit_time = at or self.config.audit_time
        audit_time = _parse_datetime(audit_time, "audit_time")
        rule_id = self._rule_id(rule)
        rule_title = self._rule_title(rule)

        pipeline.apply(rule)
        applied_ids = set(pipeline.applied_ids)
        pipeline_item_ids = {
            item.identifier for item in pipeline.items if item.identifier is not None
        }

        branches = [
            branch for branch in self.config.branches if branch.applies_to(rule_id)
        ]
        applicable_branch_ids = frozenset(branch.branch_id for branch in branches)
        branch_states = [
            self._branch_state(branch, applied_ids, pipeline_item_ids, audit_time)
            for branch in branches
        ]
        open_branches = tuple(
            state for state in branch_states if isinstance(state, OpenBranch)
        )
        closed_branches = tuple(
            state for state in branch_states if isinstance(state, ClosedBranch)
        )
        required_branches = [branch for branch in branches if branch.required]
        required_closed = [
            branch for branch in closed_branches if branch.required
        ]

        duties = [
            duty
            for duty in self.config.duties
            if duty.applies_to(rule_id, applicable_branch_ids)
        ]
        notify_assignments, uncovered_notify_roles = self._resolve(
            duties, Responsibility.NOTIFY, rule_id, audit_time
        )
        handle_assignments, uncovered_handle_roles = self._resolve(
            duties, Responsibility.HANDLE, rule_id, audit_time
        )
        handle_duties = [
            duty for duty in duties if duty.responsibility == Responsibility.HANDLE
        ]

        can_notify = bool(notify_assignments)
        can_handle = (
            bool(handle_assignments) and bool(required_branches) and not required_closed
        )
        release_basis = can_notify and can_handle
        has_substitute = any(
            assignment.source == "approved_substitute"
            for assignment in (*notify_assignments, *handle_assignments)
        )

        if not handle_assignments and handle_duties:
            status = AuditStatus.NO_SUBSTITUTE
        elif can_handle:
            status = AuditStatus.ACTIONABLE
        elif notify_assignments:
            status = AuditStatus.NOTIFIABLE
        elif handle_duties:
            status = AuditStatus.NO_SUBSTITUTE
        elif notify_assignments:
            status = AuditStatus.NOTIFIABLE
        else:
            status = AuditStatus.NO_SUBSTITUTE

        reference_only = status == AuditStatus.NOTIFIABLE
        escalation_required = status == AuditStatus.NO_SUBSTITUTE or not can_notify

        reason_codes: list[str] = []
        reasons: list[str] = []
        for assignment in (*notify_assignments, *handle_assignments):
            if assignment.source == "approved_substitute":
                reason_codes.append("approved_substitute")
                reasons.append(
                    f"Approved substitute {assignment.person} covers role '{assignment.role}' "
                    f"under {assignment.approval_ref}."
                )
        for branch in closed_branches:
            reason_codes.append("branch_closed")
            counter = branch.countersign_role or "UNASSIGNED"
            reasons.append(
                f"Branch '{branch.branch_id}' is closed ({branch.reason}); "
                f"countersign role: {counter}."
            )
            if branch.countersign_role is None:
                reason_codes.append("countersign_unassigned")
        if uncovered_notify_roles:
            reason_codes.append("notify_uncovered")
            reasons.append(
                "Notify duty has no available assignee or approved substitute for role(s): "
                + ", ".join(sorted(uncovered_notify_roles))
                + "."
            )
        if uncovered_handle_roles and not handle_assignments:
            reason_codes.append("no_approved_substitute")
            reasons.append(
                "Handling duty is unavailable and no active approved substitute exists for "
                "role(s): "
                + ", ".join(sorted(uncovered_handle_roles))
                + "."
            )
        if not required_branches:
            reason_codes.append("missing_release_branch")
            reasons.append(
                "No required processing branch is declared for this rule UUID; release evidence "
                "is incomplete."
            )
        if status == AuditStatus.ACTIONABLE and release_basis:
            reason_codes.append("release_ready")
            reasons.append(
                "Notification and handling paths are covered and all required branches are open."
            )
        elif status == AuditStatus.ACTIONABLE:
            reason_codes.append("release_blocked")
            reasons.append(
                "Handling coverage exists, but the notification path is uncovered; release is "
                "blocked."
            )
        elif reference_only:
            reason_codes.append("reference_only")
            reasons.append(
                "Notify-only chain; it must not be used as an on-call release basis."
            )
        if escalation_required:
            reason_codes.append("escalation_required")
            reasons.append(
                "Release is blocked by incomplete duty coverage; escalate before release."
            )
        if len(same_title_ids) > 1:
            reason_codes.append("same_title_identity")
            reasons.append(
                "Other rule identities share this title; permissions were evaluated separately "
                "by UUID."
            )

        return NotificationChain(
            chain_id=f"chain-{rule_id}",
            rule_id=rule_id,
            rule_title=rule_title,
            rule_name=rule.name,
            status=status,
            can_notify=can_notify,
            can_handle=can_handle,
            has_substitute=has_substitute,
            release_basis=release_basis,
            reference_only=reference_only,
            escalation_required=escalation_required,
            notify_assignments=tuple(notify_assignments),
            handle_assignments=tuple(handle_assignments),
            open_branches=open_branches,
            closed_branches=closed_branches,
            uncovered_handle_roles=tuple(sorted(uncovered_handle_roles)),
            same_title_ids=same_title_ids,
            reason_codes=tuple(dict.fromkeys(reason_codes)),
            reasons=tuple(reasons),
            pipeline_name=pipeline.name,
            audit_time=audit_time,
        )

    def audit(
        self,
        rules: Iterable[SigmaRule],
        pipeline: "ProcessingPipeline",
        *,
        at: datetime | None = None,
    ) -> HandoverAuditReport:
        audit_time = _parse_datetime(at or self.config.audit_time, "audit_time")
        rule_list = list(rules)
        ids = [self._rule_id(rule) for rule in rule_list]
        duplicates = sorted({str(item) for item in ids if ids.count(item) > 1})
        if duplicates:
            raise SigmaAuditError(
                "Duplicate rule UUID(s) in audit input: " + ", ".join(duplicates)
            )

        title_groups: defaultdict[str, list[UUID]] = defaultdict(list)
        name_groups: defaultdict[str, list[UUID]] = defaultdict(list)
        for rule, rule_id in zip(rule_list, ids):
            title_groups[self._rule_title(rule)].append(rule_id)
            if rule.name is not None:
                name_groups[rule.name].append(rule_id)
        same_title_ids = {
            rule_id: tuple(sorted(title_groups[self._rule_title(rule)], key=str))
            for rule, rule_id in zip(rule_list, ids)
        }

        chains = tuple(
            sorted(
                (
                    self.audit_rule(
                        rule,
                        pipeline,
                        at=audit_time,
                        same_title_ids=same_title_ids[rule_id],
                    )
                    for rule, rule_id in zip(rule_list, ids)
                ),
                key=lambda chain: str(chain.rule_id),
            )
        )

        warnings: list[str] = []
        for title, title_ids in sorted(
            ((title, tuple(sorted(group, key=str))) for title, group in title_groups.items()),
            key=lambda item: item[0],
        ):
            if len(title_ids) > 1:
                warnings.append(
                    f"Title '{title}' is shared by {len(title_ids)} rule UUIDs; "
                    "permissions and chains remain separate."
                )
        for name, name_ids in sorted(
            ((name, tuple(sorted(group, key=str))) for name, group in name_groups.items()),
            key=lambda item: item[0],
        ):
            if len(name_ids) > 1:
                warnings.append(
                    f"Name '{name}' is shared by {len(name_ids)} rule UUIDs; "
                    "permissions and chains remain separate."
                )
        for chain in chains:
            for branch in chain.closed_branches:
                if branch.countersign_role is None:
                    warnings.append(
                        f"Closed branch '{branch.branch_id}' in {chain.chain_id} has no "
                        "historical countersign role."
                    )
        for substitution in self.config.substitutions:
            if not substitution.is_valid_at(audit_time):
                warnings.append(
                    f"Approved substitution {substitution.approval_ref} for role "
                    f"'{substitution.role}' is outside its validity window at audit time."
                )

        return HandoverAuditReport(
            shift_id=self.config.shift_id,
            audit_time=audit_time,
            chains=chains,
            warnings=tuple(warnings),
        )


def audit_handover(
    rules: Iterable[SigmaRule],
    pipeline: "ProcessingPipeline",
    config: HandoverAuditConfig,
    *,
    at: datetime | None = None,
) -> HandoverAuditReport:
    """Convenience wrapper around :class:`HandoverAuditor`."""
    return HandoverAuditor(config).audit(rules, pipeline, at=at)
