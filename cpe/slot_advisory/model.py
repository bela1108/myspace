"""Data objects for application-slot advisory adjudication."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .matching import cpe_fields, normalize_component

HOST_COMMON = "host_common"
SLOT_STRICT = "slot_strict"
SCOPES = (HOST_COMMON, SLOT_STRICT)

VERDICT_APPLICABLE = "applicable"
VERDICT_NOT_APPLICABLE = "not_applicable"
VERDICT_UNKNOWN = "unknown"

CLOSURE_SCOPE_HOST = "host"
CLOSURE_SCOPE_SLOT = "slot"


def as_mapping(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    raise TypeError("Expected mapping or slot advisory model object")


@dataclass
class Component:
    cpe: str
    component_id: Optional[str] = None
    version: Optional[str] = None
    digest: Optional[str] = None
    path: Optional[str] = None
    owner: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return normalize_component(asdict(self))


@dataclass
class Condition:
    id: str
    scope: str
    cpe: str
    version_constraint: Optional[str] = None
    affected_versions: Optional[List[str]] = None
    role: Optional[str] = None
    description_zh: Optional[str] = None
    strict_identity: bool = True

    def __post_init__(self) -> None:
        scope_aliases = {
            "host": HOST_COMMON,
            "common": HOST_COMMON,
            "host-common": HOST_COMMON,
            "slot": SLOT_STRICT,
            "strict": SLOT_STRICT,
            "slot-local": SLOT_STRICT,
        }
        self.scope = scope_aliases.get(self.scope, self.scope)
        if self.scope not in SCOPES:
            raise ValueError("condition scope must be host_common or slot_strict")
        cpe_fields(self.cpe)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Advisory:
    advisory_id: str
    conditions: List[Condition]
    operator: str = "all"
    title: Optional[str] = None
    severity: Optional[str] = None

    def __post_init__(self) -> None:
        if self.operator not in ("all", "any"):
            raise ValueError("operator must be all or any")
        self.conditions = [
            item if isinstance(item, Condition) else Condition(**item)
            for item in self.conditions
        ]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["conditions"] = [condition.to_dict() for condition in self.conditions]
        return data


@dataclass
class Cabinet:
    cabinet_id: str
    host_id: str
    common_components: List[Any] = field(default_factory=list)
    host_owner: Optional[str] = None
    common_snapshot_id: Optional[str] = None

    def __post_init__(self) -> None:
        self.common_components = [
            normalize_component(as_mapping(item), HOST_COMMON)
            for item in self.common_components
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cabinet_id": self.cabinet_id,
            "host_id": self.host_id,
            "host_owner": self.host_owner,
            "common_snapshot_id": self.common_snapshot_id,
            "common_components": self.common_components,
        }


@dataclass
class SlotSnapshot:
    snapshot_id: str
    slot_id: str
    components: List[Any] = field(default_factory=list)
    slot_owner: Optional[str] = None
    host_id: Optional[str] = None
    captured_at: Optional[str] = None
    application: Optional[str] = None
    generation: Optional[str] = None

    def __post_init__(self) -> None:
        self.components = [
            normalize_component(as_mapping(item), SLOT_STRICT)
            for item in self.components
        ]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def advisory_from(raw: Any) -> Advisory:
    data = as_mapping(raw)
    if "advisory_id" not in data and "id" in data:
        data["advisory_id"] = data.pop("id")
    return Advisory(**data)


def cabinet_from(raw: Any) -> Cabinet:
    return Cabinet(**as_mapping(raw))


def snapshot_from(raw: Any) -> SlotSnapshot:
    return SlotSnapshot(**as_mapping(raw))
