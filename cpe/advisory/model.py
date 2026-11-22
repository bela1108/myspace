# -*- coding: utf-8 -*-

"""
Data model for slot-scoped advisory adjudication.

The model deliberately keeps the host identity and the application slot
identity as separate fields.  A single control cabinet (one host number) can
carry several application slots, and each slot can own a different component
version.  A closure record therefore has to name both the slot and the
component witness it was derived from.

This module has no dependency on the matching engine; it only defines the
shape of the evidence that is passed to it.
"""

from __future__ import unicode_literals

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, Optional, Tuple


# Condition scopes.
HOST_SCOPE = "host"
SLOT_SCOPE = "slot"
SCOPE_VALUES = (HOST_SCOPE, SLOT_SCOPE)

# Slot applicability.
STATUS_APPLICABLE = "applicable"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_INDETERMINATE = "indeterminate"

# Individual condition evaluation.
CONDITION_MATCHED = "matched"
CONDITION_ABSENT = "absent"
CONDITION_SHADOWED = "shadowed"
CONDITION_UNKNOWN = "unknown"

# Closure evaluation.
CLOSURE_CLOSED = "closed"
CLOSURE_PARTIALLY_CLOSED = "partially_closed"
CLOSURE_OPEN = "open"
CLOSURE_NOT_REQUIRED = "not_required"
CLOSURE_INDETERMINATE = "indeterminate"


def _sorted_tuple(values):
    return tuple(sorted(values))


@dataclass(frozen=True)
class Slot:
    """An application slot inside a control cabinet."""

    slot_id: str
    application: str = ""
    note: str = ""

    def to_dict(self):
        return {
            "slot_id": self.slot_id,
            "application": self.application,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            slot_id=data["slot_id"],
            application=data.get("application", ""),
            note=data.get("note", ""),
        )


@dataclass(frozen=True)
class Cabinet:
    """
    A control cabinet with exactly one host number and one or more slots.

    ``cabinet_id`` is the inventory identity.  ``host_id`` is the single host
    number that appears in the disposition report.  Keeping both explicit
    makes the point that a host roll-up is not a slot roll-up.
    """

    cabinet_id: str
    host_id: str
    name: str = ""
    slots: Tuple[Slot, ...] = ()

    def __post_init__(self):
        if not self.cabinet_id:
            raise ValueError("cabinet_id is required")
        if not self.host_id:
            raise ValueError("host_id is required")
        object.__setattr__(self, "slots", tuple(self.slots))
        slot_ids = [slot.slot_id for slot in self.slots]
        if len(slot_ids) != len(set(slot_ids)):
            raise ValueError("duplicate slot_id in cabinet")

    @property
    def slot_ids(self):
        return tuple(slot.slot_id for slot in self.slots)

    def get_slot(self, slot_id):
        for slot in self.slots:
            if slot.slot_id == slot_id:
                return slot
        raise KeyError("unknown slot_id {0!r}".format(slot_id))

    def to_dict(self):
        return {
            "cabinet_id": self.cabinet_id,
            "host_id": self.host_id,
            "name": self.name,
            "slots": [slot.to_dict() for slot in self.slots],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            cabinet_id=data["cabinet_id"],
            host_id=data["host_id"],
            name=data.get("name", ""),
            slots=tuple(Slot.from_dict(item) for item in data.get("slots", ())),
        )


@dataclass(frozen=True)
class Component:
    """
    A component observed in one snapshot.

    ``slots`` is empty for a host-common component.  A component that is
    genuinely shared by two applications lists both slot ids; it is still one
    component, but it has two slot responsibilities.
    """

    component_id: str
    cpe: str
    slots: FrozenSet[str] = frozenset()
    label: str = ""

    def __post_init__(self):
        if not self.component_id:
            raise ValueError("component_id is required")
        if not self.cpe:
            raise ValueError("component cpe is required")
        object.__setattr__(self, "slots", frozenset(self.slots))

    @property
    def is_host_common(self):
        return not self.slots

    @property
    def is_shared(self):
        return len(self.slots) > 1

    def belongs_to(self, slot_id):
        return slot_id in self.slots

    def to_dict(self):
        return {
            "component_id": self.component_id,
            "cpe": self.cpe,
            "slots": list(_sorted_tuple(self.slots)),
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            component_id=data["component_id"],
            cpe=data["cpe"],
            slots=frozenset(data.get("slots", ())),
            label=data.get("label", ""),
        )


@dataclass(frozen=True)
class Snapshot:
    """
    One inventory snapshot for a cabinet.

    ``evidence_slots`` records which application slots were actually
    re-evidenced in this snapshot.  ``None`` means "all slots in the cabinet".
    A single-slot supplement is a snapshot whose ``evidence_slots`` contains
    one slot; the other slots continue to use their previous evidence.
    """

    snapshot_id: str
    cabinet_id: str
    captured_at: str = ""
    components: Tuple[Component, ...] = ()
    evidence_slots: Optional[FrozenSet[str]] = None
    host_evidence: bool = True
    complete: bool = True
    note: str = ""

    def __post_init__(self):
        if not self.snapshot_id:
            raise ValueError("snapshot_id is required")
        if not self.cabinet_id:
            raise ValueError("snapshot cabinet_id is required")
        object.__setattr__(self, "components", tuple(self.components))
        if self.evidence_slots is not None:
            object.__setattr__(
                self, "evidence_slots", frozenset(self.evidence_slots))
        component_ids = [item.component_id for item in self.components]
        if len(component_ids) != len(set(component_ids)):
            raise ValueError(
                "duplicate component_id in snapshot {0!r}".format(
                    self.snapshot_id))

    def has_evidence_for(self, slot_id):
        if self.evidence_slots is None:
            return True
        return slot_id in self.evidence_slots

    def components_for_slot(self, slot_id):
        return tuple(
            item for item in self.components if item.belongs_to(slot_id))

    @property
    def host_components(self):
        return tuple(item for item in self.components if item.is_host_common)

    def find_component(self, component_id):
        for item in self.components:
            if item.component_id == component_id:
                return item
        return None

    def to_dict(self):
        return {
            "snapshot_id": self.snapshot_id,
            "cabinet_id": self.cabinet_id,
            "captured_at": self.captured_at,
            "components": [item.to_dict() for item in self.components],
            "evidence_slots": (
                None if self.evidence_slots is None
                else list(_sorted_tuple(self.evidence_slots))),
            "host_evidence": self.host_evidence,
            "complete": self.complete,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data):
        evidence_slots = data.get("evidence_slots")
        return cls(
            snapshot_id=data["snapshot_id"],
            cabinet_id=data["cabinet_id"],
            captured_at=data.get("captured_at", ""),
            components=tuple(
                Component.from_dict(item)
                for item in data.get("components", ())),
            evidence_slots=(
                None if evidence_slots is None
                else frozenset(evidence_slots)),
            host_evidence=bool(data.get("host_evidence", True)),
            complete=bool(data.get("complete", True)),
            note=data.get("note", ""),
        )


@dataclass(frozen=True)
class Condition:
    """
    One fact condition in an advisory.

    ``scope="host"`` can only be witnessed by a host-common component.
    ``scope="slot"`` is evaluated against the slot currently being adjudicated
    and can only be witnessed by a component that belongs to that slot.

    ``slot_id`` is optional.  When set, the condition is only required for
    that slot.  When omitted, a slot-scoped condition is required for every
    slot but is always evaluated against that slot's own components.
    """

    condition_id: str
    cpe: str
    scope: str
    slot_id: Optional[str] = None
    description: str = ""

    def __post_init__(self):
        if not self.condition_id:
            raise ValueError("condition_id is required")
        if not self.cpe:
            raise ValueError("condition cpe is required")
        if self.scope not in SCOPE_VALUES:
            raise ValueError(
                "condition scope must be one of {0}".format(SCOPE_VALUES))
        if self.scope == HOST_SCOPE and self.slot_id is not None:
            raise ValueError("host-scoped condition cannot target a slot")

    def applies_to_slot(self, slot_id):
        return self.slot_id is None or self.slot_id == slot_id

    def to_dict(self):
        return {
            "condition_id": self.condition_id,
            "cpe": self.cpe,
            "scope": self.scope,
            "slot_id": self.slot_id,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            condition_id=data["condition_id"],
            cpe=data["cpe"],
            scope=data["scope"],
            slot_id=data.get("slot_id"),
            description=data.get("description", ""),
        )


@dataclass(frozen=True)
class Advisory:
    """A bulletin whose conditions are adjudicated per application slot."""

    advisory_id: str
    title: str = ""
    conditions: Tuple[Condition, ...] = ()
    operator: str = "AND"
    description: str = ""

    def __post_init__(self):
        if not self.advisory_id:
            raise ValueError("advisory_id is required")
        object.__setattr__(self, "conditions", tuple(self.conditions))
        operator = self.operator.upper()
        if operator not in ("AND", "OR"):
            raise ValueError("advisory operator must be AND or OR")
        object.__setattr__(self, "operator", operator)
        ids = [item.condition_id for item in self.conditions]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate condition_id in advisory")

    def conditions_for_slot(self, slot_id):
        return tuple(
            item for item in self.conditions if item.applies_to_slot(slot_id))

    def get_condition(self, condition_id):
        for item in self.conditions:
            if item.condition_id == condition_id:
                return item
        return None

    def to_dict(self):
        return {
            "advisory_id": self.advisory_id,
            "title": self.title,
            "operator": self.operator,
            "description": self.description,
            "conditions": [item.to_dict() for item in self.conditions],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            advisory_id=data["advisory_id"],
            title=data.get("title", ""),
            conditions=tuple(
                Condition.from_dict(item)
                for item in data.get("conditions", ())),
            operator=data.get("operator", "AND"),
            description=data.get("description", ""),
        )


@dataclass(frozen=True)
class Witness:
    """
    The exact component identity that made a condition true.

    A witness is copied into a closure record.  It includes the source
    snapshot and the component's slot ownership so that a later adjudication
    can reject a stale or cross-slot closure without re-deriving the match.
    """

    component_id: str
    cpe: str
    source_snapshot_id: str
    condition_id: str
    condition_scope: str
    component_slots: FrozenSet[str] = frozenset()
    label: str = ""

    def __post_init__(self):
        object.__setattr__(self, "component_slots", frozenset(self.component_slots))

    @property
    def is_host_common(self):
        return not self.component_slots

    def to_dict(self):
        return {
            "component_id": self.component_id,
            "cpe": self.cpe,
            "source_snapshot_id": self.source_snapshot_id,
            "condition_id": self.condition_id,
            "condition_scope": self.condition_scope,
            "component_slots": list(_sorted_tuple(self.component_slots)),
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            component_id=data["component_id"],
            cpe=data["cpe"],
            source_snapshot_id=data.get("source_snapshot_id", ""),
            condition_id=data["condition_id"],
            condition_scope=data["condition_scope"],
            component_slots=frozenset(data.get("component_slots", ())),
            label=data.get("label", ""),
        )


@dataclass(frozen=True)
class ClosureRecord:
    """
    A disposition/closure record.

    ``slot_ids`` is empty only for a legacy host-aggregated closure.  Such a
    record can prove host-scoped conditions, but it cannot prove a
    slot-scoped condition because it has no application-slot identity.

    A joint closure for a shared component must explicitly list every slot it
    covers.  That makes the shared responsibility visible in the audit trail.
    """

    closure_id: str
    cabinet_id: str
    advisory_id: str
    slot_ids: FrozenSet[str] = frozenset()
    witnesses: Tuple[Witness, ...] = ()
    recorded_at: str = ""
    note: str = ""
    source: str = ""

    def __post_init__(self):
        if not self.closure_id:
            raise ValueError("closure_id is required")
        object.__setattr__(self, "slot_ids", frozenset(self.slot_ids))
        object.__setattr__(self, "witnesses", tuple(self.witnesses))

    @property
    def is_host_aggregated(self):
        return not self.slot_ids

    @property
    def condition_ids(self):
        return frozenset(item.condition_id for item in self.witnesses)

    def covers_slot(self, slot_id):
        return slot_id in self.slot_ids

    def witnesses_for_condition(self, condition_id):
        return tuple(
            item for item in self.witnesses
            if item.condition_id == condition_id)

    def to_dict(self):
        return {
            "closure_id": self.closure_id,
            "cabinet_id": self.cabinet_id,
            "advisory_id": self.advisory_id,
            "slot_ids": list(_sorted_tuple(self.slot_ids)),
            "witnesses": [item.to_dict() for item in self.witnesses],
            "recorded_at": self.recorded_at,
            "note": self.note,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            closure_id=data["closure_id"],
            cabinet_id=data["cabinet_id"],
            advisory_id=data["advisory_id"],
            slot_ids=frozenset(data.get("slot_ids", ())),
            witnesses=tuple(
                Witness.from_dict(item)
                for item in data.get("witnesses", ())),
            recorded_at=data.get("recorded_at", ""),
            note=data.get("note", ""),
            source=data.get("source", ""),
        )


@dataclass(frozen=True)
class ResolvedComponent:
    """A component plus the snapshot it was carried over from."""

    component: Component
    source_snapshot_id: str


@dataclass(frozen=True)
class ResolvedEvidence:
    """
    Evidence assembled for one slot at one point in the snapshot timeline.

    Slot-bound components come from the newest snapshot that actually
    re-evidenced this slot.  Host-common components come from the newest
    snapshot with host evidence.  Nothing is borrowed from a different slot.
    """

    slot_id: str
    as_of_snapshot_id: str
    components: Tuple[ResolvedComponent, ...] = ()
    host_source_snapshot_id: Optional[str] = None
    slot_source_snapshot_id: Optional[str] = None
    complete: bool = True
    context_components: Tuple[ResolvedComponent, ...] = ()

    @property
    def host_components(self):
        return tuple(
            item for item in self.components
            if item.component.is_host_common)

    @property
    def slot_components(self):
        return tuple(
            item for item in self.components
            if not item.component.is_host_common)

    def find(self, component_id):
        for item in self.components:
            if item.component.component_id == component_id:
                return item
        return None

    @property
    def all_components(self):
        return tuple(self.components) + tuple(self.context_components)

    def find_any(self, component_id):
        for item in self.all_components:
            if item.component.component_id == component_id:
                return item
        return None

    def source_map(self):
        return {
            item.component.component_id: item.source_snapshot_id
            for item in self.components
        }


@dataclass(frozen=True)
class ConditionMatch:
    """The evaluation of one condition against one slot's evidence."""

    condition: Condition
    status: str
    witness: Optional[Witness] = None
    eligible_witnesses: Tuple[Witness, ...] = ()
    shadow_witnesses: Tuple[Witness, ...] = ()
    reason_code: str = ""
    explanation: str = ""

    @property
    def matched(self):
        return self.status == CONDITION_MATCHED


@dataclass(frozen=True)
class SlotResult:
    """Applicability of an advisory to one application slot."""

    cabinet_id: str
    advisory_id: str
    slot_id: str
    application: str
    status: str
    applicable: Optional[bool]
    conditions: Tuple[ConditionMatch, ...] = ()
    evidence: Optional[ResolvedEvidence] = None
    reasons: Tuple[str, ...] = ()

    @property
    def matched_witnesses(self):
        return tuple(
            item.witness for item in self.conditions
            if item.matched and item.witness is not None)

    @property
    def shadow_witnesses(self):
        result = []
        for item in self.conditions:
            result.extend(item.shadow_witnesses)
        return tuple(result)

    def condition(self, condition_id):
        for item in self.conditions:
            if item.condition.condition_id == condition_id:
                return item
        return None

    @property
    def required_condition_ids(self):
        return frozenset(
            item.condition.condition_id for item in self.conditions)


@dataclass(frozen=True)
class AcceptedClosure:
    record: ClosureRecord
    condition: Condition
    witness: Witness
    reused_from_other_slot: bool = False


@dataclass(frozen=True)
class RejectedClosure:
    record: ClosureRecord
    condition: Optional[Condition]
    witness: Optional[Witness]
    reason_code: str
    explanation: str


@dataclass(frozen=True)
class ClosureEvaluation:
    """What a set of closure records proves for one slot."""

    slot_id: str
    status: str
    required_condition_ids: FrozenSet[str] = frozenset()
    covered_condition_ids: FrozenSet[str] = frozenset()
    missing_condition_ids: FrozenSet[str] = frozenset()
    accepted: Tuple[AcceptedClosure, ...] = ()
    rejected: Tuple[RejectedClosure, ...] = ()

    @property
    def closed(self):
        return self.status == CLOSURE_CLOSED


@dataclass(frozen=True)
class SubstitutionCheck:
    """
    Why a closure owned by another slot cannot stand in for this slot.

    ``reusable_conditions`` is usually limited to host-scoped conditions: the
    host component is common, so its evidence can be shared.  The
    slot-scoped conditions remain blocked and need a witness owned by the
    target slot.
    """

    source_closure_id: str
    source_slot_ids: FrozenSet[str]
    target_slot_id: str
    can_substitute: bool
    reusable_conditions: Tuple[str, ...] = ()
    blocked_conditions: Tuple[str, ...] = ()
    reason_code: str = ""
    explanation: str = ""


@dataclass(frozen=True)
class ResponsibilityNote:
    """An explanation of how responsibility changes in a given scenario."""

    scenario: str
    summary: str
    detail: str
    slots: Tuple[str, ...] = ()
    components: Tuple[str, ...] = ()


@dataclass(frozen=True)
class SlotSnapshotReport:
    snapshot_id: str
    slot_id: str
    application: str
    evidence_sources: Dict[str, str]
    applicability: SlotResult
    closure: ClosureEvaluation
    substitution_checks: Tuple[SubstitutionCheck, ...] = ()
    responsibility_notes: Tuple[ResponsibilityNote, ...] = ()


@dataclass(frozen=True)
class HostRollup:
    """
    A deliberately lossy host-level view, included to show why it must not be
    used as a disposition report.
    """

    cabinet_id: str
    host_id: str
    applicable_slots: Tuple[str, ...] = ()
    closed_slots: Tuple[str, ...] = ()
    host_aggregated_closures: Tuple[str, ...] = ()
    valid: bool = False
    warning: str = ""


@dataclass(frozen=True)
class SnapshotReport:
    snapshot_id: str
    captured_at: str
    evidence_slots: Optional[Tuple[str, ...]]
    slots: Dict[str, SlotSnapshotReport]
    responsibility_notes: Tuple[ResponsibilityNote, ...] = ()
    host_rollup: Optional[HostRollup] = None


@dataclass(frozen=True)
class QueryReport:
    cabinet: Cabinet
    advisory: Advisory
    snapshots: Tuple[SnapshotReport, ...]
    responsibility_notes: Tuple[ResponsibilityNote, ...] = ()
    policy_notes: Tuple[ResponsibilityNote, ...] = field(default_factory=tuple)

    def snapshot(self, snapshot_id):
        for item in self.snapshots:
            if item.snapshot_id == snapshot_id:
                return item
        return None

    def latest(self):
        if not self.snapshots:
            return None
        return self.snapshots[-1]
