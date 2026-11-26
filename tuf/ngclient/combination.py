# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline combination preflight for verified TUF targets.

The resolver in this module is intentionally read-only.  It operates on a
metadata view that has already passed TUF verification and never performs
network or filesystem access.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

from tuf.api.metadata import Metadata, TargetFile, Targets


_UNSET = object()


class ConflictKind(str, Enum):
    """Stable conflict categories."""

    CYCLE = "cycle"
    IDENTITY = "identity"
    MISSING = "missing"
    UNSATISFIABLE = "unsatisfiable"
    INVALID = "invalid"


@dataclass(frozen=True)
class TargetIdentity:
    """Cryptographic and logical identity of one verified target."""

    path: str
    length: int
    hashes: tuple[tuple[str, str], ...]
    custom: str = ""
    explicit: str | None = None

    @classmethod
    def from_target(
        cls, target: TargetFile, explicit: str | None = None
    ) -> TargetIdentity:
        custom = target.unrecognized_fields.get("custom")
        try:
            custom_key = json.dumps(
                custom, sort_keys=True, separators=(",", ":"), default=str
            )
        except TypeError:
            custom_key = repr(custom)
        return cls(
            target.path,
            target.length,
            tuple(sorted(target.hashes.items())),
            custom_key,
            explicit,
        )

    def content_key(self) -> tuple[str, int, tuple[tuple[str, str], ...]]:
        """Return the content identity, ignoring signed custom metadata."""
        return (self.path, self.length, self.hashes)

    def __str__(self) -> str:
        if self.explicit is not None:
            return self.explicit
        digest = ", ".join(f"{name}:{value}" for name, value in self.hashes)
        return f"{self.path} ({digest}, {self.length} bytes)"


@dataclass(frozen=True)
class DependencyRequirement:
    """One normalized module or interface requirement."""

    module: str | None = None
    interface: str | None = None
    version: str | None = None
    source: str | None = None
    optional: bool = False
    reason: str = ""

    @property
    def name(self) -> str | None:
        """Return the interface or module name."""
        return self.interface or self.module

    @property
    def constraint(self) -> str | None:
        """Alias for the version constraint."""
        return self.version

    def __str__(self) -> str:
        target = self.module or "<caller>"
        if self.interface is not None:
            target = f"{target}::{self.interface}"
        if self.version:
            target = f"{target} {self.version}"
        return target


Requirement = DependencyRequirement


@dataclass(frozen=True)
class Dependency:
    """A resolved dependency edge and its evidence."""

    module: str
    dependency: str
    interface: str | None = None
    constraint: str | None = None
    channel: str | None = None
    dependency_channel: str | None = None
    target: str | None = None
    provided_version: str | None = None
    satisfied: bool | None = None
    optional: bool = False
    source: str | None = None
    reason: str = ""

    @property
    def from_module(self) -> str:
        """Alias for the depending module."""
        return self.module

    @property
    def to_module(self) -> str:
        """Alias for the provider module."""
        return self.dependency

    @property
    def requirement(self) -> str | None:
        """Alias for the constraint."""
        return self.constraint

    @property
    def dependency_basis(self) -> str:
        """Human-readable evidence for this edge."""
        return str(self)

    def to_dict(self) -> dict[str, Any]:
        """Return a dictionary representation of the edge."""
        return {
            "module": self.module,
            "dependency": self.dependency,
            "interface": self.interface,
            "constraint": self.constraint,
            "channel": self.channel,
            "dependency_channel": self.dependency_channel,
            "target": self.target,
            "provided_version": self.provided_version,
            "satisfied": self.satisfied,
            "optional": self.optional,
            "source": self.source,
            "reason": self.reason,
        }

    def __str__(self) -> str:
        provider = self.dependency
        if self.interface is not None:
            provider = f"{provider}::{self.interface}"
        if self.constraint:
            provider = f"{provider} {self.constraint}"
        return f"{self.module} -> {provider}"


DependencyEdge = Dependency


@dataclass(frozen=True)
class InterfaceDeclaration:
    """A caller-declared interface version."""

    name: str
    version: str | None = None
    constraint: str | None = None
    provided: bool = False


@dataclass(frozen=True)
class ModuleDeclaration:
    """Normalized module data from signed target custom fields."""

    module: str
    version: str | None = None
    channel: str | None = None
    provides: tuple[tuple[str, str | None], ...] = ()
    requires: tuple[DependencyRequirement, ...] = ()
    config: str | None = None
    identity: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, hash=False)

    def provided_version(self, interface: str) -> str | None:
        """Return a provided interface version."""
        return dict(self.provides).get(interface)

    def provides_interface(self, interface: str) -> bool:
        """Whether this module provides the interface."""
        return interface in dict(self.provides)


@dataclass
class TargetCandidate:
    """An explicitly supplied candidate and optional metadata aliases."""

    target: TargetFile | str | None = None
    channel: str | None = None
    module: str | None = None
    path: str | None = None
    name: str | None = None
    value: Any = None
    version: str | None = None

    def __post_init__(self) -> None:
        if self.target is None and self.value is not None:
            self.target = self.value
        if self.module is None and self.name is not None:
            self.module = self.name
        if self.path is None and isinstance(self.target, str):
            self.path = self.target


@dataclass(frozen=True)
class CombinationConflict:
    """The first unsolvable constraint group."""

    kind: str
    message: str
    reason: str = ""
    group: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()
    channels: tuple[str, ...] = ()
    identities: tuple[str, ...] = ()
    cycle: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    requirements: tuple[DependencyRequirement, ...] = ()
    order: int = 0

    @property
    def type(self) -> str:
        """Alias for kind."""
        return self.kind

    @property
    def category(self) -> str:
        """Alias for kind."""
        return self.kind

    @property
    def code(self) -> str:
        """Alias for kind."""
        return self.kind

    @property
    def conflict_group(self) -> tuple[str, ...]:
        """The unsatisfiable group."""
        return self.group or self.constraints

    @property
    def first_unsatisfiable(self) -> tuple[str, ...]:
        """The first unsatisfiable constraint group."""
        return self.conflict_group

    @property
    def is_cycle(self) -> bool:
        """Whether this is a cycle conflict."""
        return self.kind == ConflictKind.CYCLE.value

    @property
    def is_identity_conflict(self) -> bool:
        """Whether this is an identity conflict."""
        return self.kind == ConflictKind.IDENTITY.value

    @property
    def is_missing(self) -> bool:
        """Whether a required target is missing."""
        return self.kind == ConflictKind.MISSING.value

    @property
    def is_unsatisfiable(self) -> bool:
        """Whether constraints cannot be satisfied together."""
        return self.kind == ConflictKind.UNSATISFIABLE.value

    def to_dict(self) -> dict[str, Any]:
        """JSON-ish representation."""
        return {
            "kind": self.kind,
            "reason": self.reason,
            "message": self.message,
            "group": list(self.group),
            "modules": list(self.modules),
            "channels": list(self.channels),
            "identities": list(self.identities),
            "cycle": list(self.cycle),
            "constraints": list(self.constraints),
        }

    def __str__(self) -> str:
        return self.message


Conflict = CombinationConflict


class CombinationConflictError(Exception):
    """Raised when raise_on_conflict is enabled."""

    def __init__(self, conflict: CombinationConflict | str | None = None):
        if isinstance(conflict, CombinationConflict):
            self.conflict = conflict
            message = conflict.message
        else:
            message = conflict or "Target combination preflight failed"
            self.conflict = CombinationConflict(
                kind=ConflictKind.UNSATISFIABLE.value, message=message
            )
        super().__init__(message)

    @property
    def kind(self) -> str:
        """Conflict kind."""
        return self.conflict.kind

    @property
    def reason(self) -> str:
        """Conflict reason."""
        return self.conflict.reason

    @property
    def group(self) -> tuple[str, ...]:
        """Unsatisfiable group."""
        return self.conflict.group


class ConstraintGroup(tuple):
    """A tuple of constraint descriptions with optional metadata."""

    def __new__(
        cls,
        items: IterableLike,
        *,
        kind: str = ConflictKind.UNSATISFIABLE.value,
        reason: str = "",
    ) -> ConstraintGroup:
        obj = super().__new__(cls, tuple(items))
        return obj


IterableLike = Any


@dataclass(frozen=True)
class ClientDownloadState:
    """Read-only snapshot of client metadata and downloaded target files."""

    roles: tuple[tuple[str, int | None, str], ...] = ()
    targets: tuple[str, ...] = ()
    files: tuple[tuple[str, int, str], ...] = ()
    metadata_versions: dict[str, int | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.metadata_versions:
            object.__setattr__(
                self,
                "metadata_versions",
                {role: version for role, version, _ in self.roles},
            )

    @property
    def downloaded_targets(self) -> tuple[str, ...]:
        """Downloaded relative target paths."""
        return self.targets


@dataclass
class CombinationPlan:
    """Adoptable closure or the first unsatisfiable constraint group."""

    targets: dict[str, TargetFile] = field(default_factory=dict)
    dependencies: tuple[Dependency, ...] | list[Dependency] = ()
    conflict: CombinationConflict | None = None
    caller_interfaces: dict[str, str] = field(default_factory=dict)
    caller_config: str | None = None
    attempted_targets: dict[str, TargetFile] = field(default_factory=dict)
    targets_by_path: dict[str, TargetFile] = field(default_factory=dict)
    records: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.targets_by_path:
            self.targets_by_path = {
                target.path: target for target in self.targets.values()
            }

    @property
    def ok(self) -> bool:
        """Whether the combination is adoptable."""
        return self.conflict is None

    @property
    def success(self) -> bool:
        """Alias for ok."""
        return self.ok

    @property
    def valid(self) -> bool:
        """Alias for ok."""
        return self.ok

    @property
    def adoptable(self) -> bool:
        """Alias for ok."""
        return self.ok

    @property
    def adoptable_targets(self) -> dict[str, TargetFile]:
        """Targets when successful, otherwise an empty mapping."""
        return self.targets if self.ok else {}

    @property
    def selected_targets(self) -> dict[str, TargetFile]:
        """Alias for adoptable_targets."""
        return self.adoptable_targets

    @property
    def modules(self) -> dict[str, TargetFile]:
        """Alias for adoptable_targets."""
        return self.adoptable_targets

    @property
    def dependency_evidence(self) -> tuple[Dependency, ...]:
        """Dependency edges that justify the closure."""
        return tuple(self.dependencies)

    @property
    def dependency_basis(self) -> dict[str, tuple[Dependency, ...]]:
        """Evidence grouped by depending module."""
        result: dict[str, list[Dependency]] = {}
        for edge in self.dependency_evidence:
            result.setdefault(edge.module, []).append(edge)
        return {key: tuple(value) for key, value in result.items()}

    @property
    def basis(self) -> dict[str, tuple[Dependency, ...]]:
        """Alias for dependency_basis."""
        return self.dependency_basis

    @property
    def evidence(self) -> tuple[Dependency, ...]:
        """Alias for dependency_evidence."""
        return self.dependency_evidence

    @property
    def first_conflict(self) -> CombinationConflict | None:
        """Alias for conflict."""
        return self.conflict

    @property
    def first_unsatisfiable(self) -> tuple[str, ...] | None:
        """The first unsatisfiable constraint group."""
        return None if self.conflict is None else self.conflict.group

    @property
    def unsatisfiable_constraints(self) -> tuple[str, ...] | None:
        """Alias for first_unsatisfiable."""
        return self.first_unsatisfiable

    @property
    def constraint_group(self) -> tuple[str, ...] | None:
        """Alias for first_unsatisfiable."""
        return self.first_unsatisfiable

    def raise_for_conflict(self) -> None:
        """Raise CombinationConflictError for a failed plan."""
        if self.conflict is not None:
            raise CombinationConflictError(self.conflict)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a target by module name, path, or basename."""
        if key in self.targets:
            return self.targets[key]
        if key in self.targets_by_path:
            return self.targets_by_path[key]
        for module, target in self.targets.items():
            if PurePosixPath(target.path).name == key:
                return target
            if PurePosixPath(target.path).stem == key:
                return target
            if module == key:
                return target
        return default

    def keys(self) -> Any:
        """Module keys."""
        return self.targets.keys()

    def values(self) -> Any:
        """Target values."""
        return self.targets.values()

    def items(self) -> Any:
        """Module/target items."""
        return self.targets.items()

    def to_dict(self) -> dict[str, Any]:
        """Serializable summary."""
        return {
            "ok": self.ok,
            "targets": {
                module: target.path for module, target in self.targets.items()
            },
            "targets_by_path": dict(self.targets_by_path),
            "dependencies": [edge.to_dict() for edge in self.dependency_evidence],
            "conflict": None if self.conflict is None else self.conflict.to_dict(),
            "first_unsatisfiable": self.first_unsatisfiable,
            "caller_interfaces": dict(self.caller_interfaces),
            "caller_config": self.caller_config,
        }

    def __bool__(self) -> bool:
        return self.ok

    def __iter__(self) -> Any:
        return iter(self.targets)

    def __len__(self) -> int:
        return len(self.targets)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and self.get(key) is not None

    def __getitem__(self, key: str) -> TargetFile:
        target = self.get(key)
        if target is None:
            raise KeyError(key)
        return target


CombinationResult = CombinationPlan
PrecheckPlan = CombinationPlan
AdoptionPlan = CombinationPlan
PrecheckResult = CombinationPlan
TargetCombinationPlan = CombinationPlan
TargetCombinationResult = CombinationPlan


class PlannedTarget:
    """Small projection used by callers that expect a planned-target type."""

    def __init__(
        self,
        module: str,
        target: TargetFile,
        *,
        path: str | None = None,
        channel: str | None = None,
        dependencies: tuple[str, ...] = (),
    ) -> None:
        self.module = module
        self.target = target
        self.path = path or target.path
        self.channel = channel
        self.dependencies = dependencies
        self.identity = TargetIdentity.from_target(target)


__all__ = [
    "AdoptionPlan",
    "ClientDownloadState",
    "CombinationConflict",
    "CombinationConflictError",
    "CombinationPlan",
    "CombinationPreflight",
    "CombinationResult",
    "Conflict",
    "ConflictKind",
    "Dependency",
    "DependencyEdge",
    "DependencyRequirement",
    "InterfaceDeclaration",
    "MetadataView",
    "ModuleDeclaration",
    "PlannedTarget",
    "PrecheckPlan",
    "PrecheckResult",
    "TargetCandidate",
    "TargetIdentity",
    "VerifiedMetadataView",
    "VersionConstraint",
    "check_combination",
    "check_target_combination",
    "combination_precheck",
    "combination_preflight",
    "compute_closure",
    "plan_combination",
    "plan_target_combination",
    "precheck_combination",
    "preflight_combination",
    "preflight_target_combination",
    "preflight_targets",
    "resolve_adoption",
    "resolve_combination",
    "resolve_target_closure",
    "resolve_target_combination",
]

# appended-marker
def _hello_patch():
    return "ok"


def _first_value(*values: Any) -> Any:
    for value in values:
        if value is not _UNSET and value is not None:
            return value
    return None


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), default=str
        )
    except TypeError:
        return repr(value)


def _version_tuple(value: Any) -> tuple[int, ...] | None:
    if value is None:
        return None
    match = re.match(r"^v?([0-9]+(?:[.][0-9]+)*)(?:[-+].*)?$", str(value).strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _compare_versions(left: Any, right: Any) -> int | None:
    left_tuple = _version_tuple(left)
    right_tuple = _version_tuple(right)
    if left_tuple is None or right_tuple is None:
        if str(left).strip() == str(right).strip():
            return 0
        return None
    width = max(len(left_tuple), len(right_tuple))
    left_padded = left_tuple + (0,) * (width - len(left_tuple))
    right_padded = right_tuple + (0,) * (width - len(right_tuple))
    if left_padded == right_padded:
        return 0
    return -1 if left_padded < right_padded else 1


class VersionConstraint:
    """Semantic-version constraints with literal-tag fallback."""

    _OPS = ("~=", "==", "!=", ">=", "<=", "^", "~", ">", "<", "=")

    def __init__(
        self,
        expression: Any = None,
        version: Any = _UNSET,
        *,
        spec: Any = None,
        constraint: Any = None,
        operator: str | None = None,
    ) -> None:
        value = _first_value(spec, constraint, expression)
        if value is None and version is not _UNSET:
            value = f"{operator or '=='}{version}"
        self.raw = "*" if value is None else str(value).strip()
        self.expression = self.raw
        self.spec = self.raw
        self.constraint = self.raw
        self.clauses = self._parse(self.raw)

    @classmethod
    def _parse(cls, raw: str) -> list[tuple[str, str]]:
        pattern = re.compile(
            r"^(~=|==|!=|>=|<=|~|>|<|=)?[ ]*(.+)$"
        )
        clauses: list[tuple[str, str]] = []
        for alternative in raw.split("||"):
            for part in alternative.split(","):
                token = part.strip()
                if not token:
                    continue
                match = pattern.match(token)
                if not match:
                    clauses.append(("==", token))
                    continue
                op = match.group(1) or "=="
                value = match.group(2).strip()
                if op == "=":
                    op = "=="
                clauses.append((op, value))
        return clauses or [("*", "*")]

    @property
    def any_version(self) -> bool:
        return self.raw in {"*", "x", "X", ""}

    def matches(self, version: Any) -> bool:
        if self.any_version:
            return True
        if version is None:
            return False
        if isinstance(version, VersionConstraint):
            version = version.raw

        for op, expected in self.clauses:
            if expected in {"*", "x", "X"}:
                continue
            if not self._match_clause(op, expected, version):
                return False
        return True

    @staticmethod
    def _match_clause(op: str, expected: str, actual: Any) -> bool:
        if op == "*":
            return True

        if expected.endswith(".*") or expected.lower().endswith(".x"):
            prefix = expected[:-2].rstrip(".")
            actual_text = str(actual)
            actual_tuple = _version_tuple(actual)
            prefix_tuple = _version_tuple(prefix)
            if actual_tuple is None or prefix_tuple is None:
                return actual_text == prefix or actual_text.startswith(
                    prefix + "."
                )
            return actual_tuple[: len(prefix_tuple)] == prefix_tuple

        comparison = _compare_versions(actual, expected)
        if op in {"==", "~="}:
            if comparison is not None:
                if op == "~=":
                    expected_tuple = _version_tuple(expected) or ()
                    if len(expected_tuple) >= 2:
                        upper = expected_tuple[:-1]
                        actual_tuple = _version_tuple(actual) or ()
                        if actual_tuple[: len(upper)] != tuple(upper):
                            return False
                return comparison == 0
            return str(actual).strip() == expected
        if op == "!=":
            if comparison is not None:
                return comparison != 0
            return str(actual).strip() != expected
        if comparison is None:
            return False
        if op == ">=":
            return comparison >= 0
        if op == "<=":
            return comparison <= 0
        if op == ">":
            return comparison > 0
        if op == "<":
            return comparison < 0
        if op == "^":
            expected_tuple = _version_tuple(expected) or (0,)
            actual_tuple = _version_tuple(actual) or ()
            if not actual_tuple or actual_tuple[0] != expected_tuple[0]:
                return False
            if expected_tuple[0] > 0:
                upper_prefix = (expected_tuple[0] + 1,)
            elif len(expected_tuple) > 1 and expected_tuple[1] > 0:
                upper_prefix = (0, expected_tuple[1] + 1)
            else:
                upper_prefix = (0, 0, (expected_tuple[2] if len(expected_tuple) > 2 else 0) + 1)
            return actual_tuple < upper_prefix + (0,) * max(
                0, len(actual_tuple) - len(upper_prefix)
            ) or actual_tuple[: len(upper_prefix)] < upper_prefix
        if op == "~":
            expected_tuple = _version_tuple(expected) or ()
            actual_tuple = _version_tuple(actual) or ()
            if len(expected_tuple) >= 2:
                prefix = expected_tuple[:-1]
                return actual_tuple[: len(prefix)] == tuple(prefix)
            return actual_tuple[:1] == expected_tuple[:1]
        return False

    def __str__(self) -> str:
        return self.raw

    def __repr__(self) -> str:
        return f"VersionConstraint({self.raw!r})"


def _interface_value(value: Any) -> str | None:
    if isinstance(value, dict):
        value = _first_value(
            value.get("version"),
            value.get("constraint"),
            value.get("spec"),
            value.get("range"),
            value.get("api"),
            value.get("value"),
            value.get("id"),
        )
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item) for item in value)
    return str(value)


def _normalize_interfaces(value: Any) -> dict[str, str]:
    if value is None or value is _UNSET:
        return {}
    if isinstance(value, VersionConstraint):
        return {"*": value.raw}
    if isinstance(value, dict):
        nested = value.get("interfaces") or value.get("interface_versions")
        if isinstance(nested, (dict, list, tuple)):
            return _normalize_interfaces(nested)
        result: dict[str, str] = {}
        for name, version in value.items():
            normalized = _interface_value(version)
            result[str(name)] = "*" if normalized is None else normalized
        return result
    if isinstance(value, (list, tuple, set)):
        result = {}
        for item in value:
            if isinstance(item, InterfaceDeclaration):
                result[item.name] = item.version or item.constraint or "*"
            elif isinstance(item, dict):
                name = _first_value(
                    item.get("name"), item.get("interface"), item.get("api")
                )
                if name:
                    result[str(name)] = _interface_value(item) or "*"
            elif isinstance(item, (tuple, list)) and len(item) >= 2:
                result[str(item[0])] = str(item[1])
            elif isinstance(item, str) and "=" in item:
                name, version = item.split("=", 1)
                result[name.strip()] = version.strip()
        return result
    for attr in ("interfaces", "interface_versions", "caller_interfaces"):
        nested = getattr(value, attr, None)
        if nested is not None:
            return _normalize_interfaces(nested)
    return {}


def _split_requirement_text(text_value: str) -> tuple[str, str | None]:
    token = text_value.strip()
    operators = ("~=", "==", "!=", ">=", "<=", "^", "~", ">", "<", "=")
    first_position: int | None = None
    selected_operator: str | None = None
    for operator in operators:
        position = token.find(operator)
        if position >= 0 and (first_position is None or position < first_position):
            first_position = position
            selected_operator = operator
    if first_position is None or selected_operator is None:
        return token, None
    name = token[:first_position].strip()
    constraint = token[first_position:].strip()
    if "::" in name:
        module_name, interface_name = name.split("::", 1)
        return f"{module_name}::{interface_name}", constraint
    return name, constraint


def _normalize_requirement(
    item: Any, source: str | None = None
) -> DependencyRequirement:
    if isinstance(item, DependencyRequirement):
        if source is not None and item.source is None:
            return DependencyRequirement(
                module=item.module,
                interface=item.interface,
                version=item.version,
                source=source,
                optional=item.optional,
                reason=item.reason,
            )
        return item

    if isinstance(item, str):
        name, constraint = _split_requirement_text(item)
        module_name: str | None = name
        interface_name: str | None = None
        if "::" in name:
            module_name, interface_name = name.split("::", 1)
        if module_name in {"<caller>", "caller"}:
            module_name = "<caller>"
        return DependencyRequirement(
            module=module_name,
            interface=interface_name,
            version=constraint,
            source=source,
        )

    if isinstance(item, (list, tuple)) and item:
        if len(item) == 1:
            return _normalize_requirement(item[0], source)
        if len(item) == 2 and isinstance(item[0], str):
            left, right = item
            if isinstance(right, str):
                if "::" in left:
                    module_name, interface_name = left.split("::", 1)
                else:
                    module_name, interface_name = left, None
                return DependencyRequirement(
                    module=module_name,
                    interface=interface_name,
                    version=right,
                    source=source,
                )

    if isinstance(item, dict):
        module_name = _first_value(
            item.get("module"),
            item.get("name"),
            item.get("module_name"),
            item.get("package"),
            item.get("dependency"),
            item.get("target"),
        )
        interface_name = _first_value(
            item.get("interface"),
            item.get("api"),
            item.get("interface_name"),
            item.get("provides"),
        )
        constraint = _first_value(
            item.get("version"),
            item.get("versions"),
            item.get("constraint"),
            item.get("version_constraint"),
            item.get("spec"),
            item.get("range"),
            item.get("requirement"),
        )
        if isinstance(constraint, (list, tuple)):
            constraint = ",".join(str(part) for part in constraint)
        optional = bool(
            _first_value(item.get("optional"), item.get("required") is False, False)
        )
        return DependencyRequirement(
            module=None if module_name is None else str(module_name),
            interface=None if interface_name is None else str(interface_name),
            version=None if constraint is None else str(constraint),
            source=source,
            optional=optional,
            reason=str(item.get("reason", "")),
        )

    return DependencyRequirement(repr(item), source=source)


def _requirement_list(value: Any, source: str | None = None) -> list[DependencyRequirement]:
    if value is None:
        return []
    if isinstance(value, dict):
        result: list[DependencyRequirement] = []
        for name, constraint in value.items():
            requirement = _normalize_requirement(
                {"module": name, "version": constraint}, source
            )
            result.append(requirement)
        return result
    if isinstance(value, str):
        return [_normalize_requirement(value, source)]
    if isinstance(value, (list, tuple, set)):
        return [_normalize_requirement(item, source) for item in value]
    return [_normalize_requirement(value, source)]


def _module_fallback(path: str) -> str:
    base = PurePosixPath(str(path)).name
    stem = PurePosixPath(base).stem or base
    stem = re.sub(r"[-_]?v?[0-9]+(?:[.][0-9]+)*$", "", stem)
    return stem or base


def _extract_declaration(
    target: TargetFile,
    *,
    explicit_module: str | None = None,
    explicit_channel: str | None = None,
) -> ModuleDeclaration:
    custom: dict[str, Any] = {}
    custom_value = getattr(target, "custom", None)
    if isinstance(custom_value, dict):
        custom = custom_value
    else:
        unrecognized = getattr(target, "unrecognized_fields", {})
        maybe_custom = unrecognized.get("custom") if isinstance(unrecognized, dict) else None
        if isinstance(maybe_custom, dict):
            custom = maybe_custom

    module_name = _first_value(
        explicit_module,
        custom.get("module"),
        custom.get("name"),
        custom.get("module_name"),
        custom.get("package"),
    )
    if module_name is None:
        module_name = _module_fallback(target.path)

    version = _first_value(
        custom.get("version"),
        custom.get("module_version"),
        custom.get("semver"),
    )
    channel = _first_value(
        explicit_channel, custom.get("channel"), custom.get("source")
    )
    config = _first_value(
        custom.get("config"),
        custom.get("configuration"),
        custom.get("config_version"),
        custom.get("config_schema"),
        custom.get("shared_config"),
    )
    if isinstance(config, dict):
        config = _first_value(
            config.get("version"), config.get("id"), _canonical(config)
        )

    provides_raw = _first_value(
        custom.get("provides"),
        custom.get("interfaces"),
        custom.get("interface_versions"),
        custom.get("api_versions"),
        custom.get("apis"),
        {},
    )
    provides: list[tuple[str, str | None]] = []
    if isinstance(provides_raw, dict):
        for interface_name, interface_value in provides_raw.items():
            provides.append(
                (str(interface_name), _interface_value(interface_value))
            )
    elif isinstance(provides_raw, (list, tuple, set)):
        for item in provides_raw:
            if isinstance(item, str):
                provides.append((item, None))
            elif isinstance(item, dict):
                name = _first_value(
                    item.get("name"), item.get("interface"), item.get("api")
                )
                if name is not None:
                    provides.append(
                        (str(name), _interface_value(item) or item.get("version"))
                    )

    requires_raw = _first_value(
        custom.get("requires"),
        custom.get("dependencies"),
        custom.get("depends"),
        custom.get("requirements"),
        custom.get("depends_on"),
        [],
    )
    requires = tuple(_requirement_list(requires_raw, str(module_name)))

    return ModuleDeclaration(
        module=str(module_name),
        version=None if version is None else str(version),
        channel=None if channel is None else str(channel),
        provides=tuple(provides),
        requires=requires,
        config=None if config is None else str(config),
        identity=_canonical(TargetIdentity.from_target(target)),
        raw=custom,
    )


@dataclass
class _Record:
    channel: str
    path: str
    target: TargetFile
    declaration: ModuleDeclaration
    order: int = 0

    @property
    def module(self) -> str:
        return self.declaration.module

    @property
    def identity(self) -> TargetIdentity:
        return TargetIdentity.from_target(self.target)


class MetadataView:
    """Normalized, read-only collection of verified target records."""

    def __init__(self, records: list[_Record] | None = None) -> None:
        self.records: list[_Record] = records or []
        self._paths: dict[str, list[_Record]] = {}
        self._modules: dict[str, list[_Record]] = {}
        for record in self.records:
            self._index(record)

    @classmethod
    def from_value(cls, value: Any) -> MetadataView:
        return _build_view(value)

    @classmethod
    def from_trusted_set(cls, trusted_set: Any) -> MetadataView:
        return _build_view(trusted_set)

    def add(self, record: _Record) -> None:
        self.records.append(record)
        self._index(record)

    def _index(self, record: _Record) -> None:
        self._paths.setdefault(record.path, []).append(record)
        self._modules.setdefault(record.module, []).append(record)

    def path_records(self, path: str) -> list[_Record]:
        return list(self._paths.get(path, ()))

    def module_records(self, module: str) -> list[_Record]:
        return list(self._modules.get(module, ()))

    def all_targets(self) -> tuple[TargetFile, ...]:
        return tuple(record.target for record in self.records)

    @property
    def targets(self) -> dict[str, TargetFile]:
        return {record.path: record.target for record in self.records}

    @property
    def target_paths(self) -> tuple[str, ...]:
        return tuple(record.path for record in self.records)

    @property
    def module_names(self) -> set[str]:
        return set(self._modules)

    @property
    def paths(self) -> set[str]:
        return set(self._paths)

    def __iter__(self) -> Any:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)


VerifiedMetadataView = MetadataView


def _target_from_dict(path: str, value: dict[str, Any]) -> TargetFile | None:
    if "hashes" not in value or "length" not in value:
        return None
    try:
        return TargetFile.from_dict(dict(value), path)
    except (KeyError, TypeError, ValueError):
        return None


def _looks_like_target_map(value: dict[str, Any]) -> bool:
    if not value:
        return False
    for item in value.values():
        if not isinstance(item, dict):
            return False
        if "hashes" not in item or "length" not in item:
            return False
    return True


def _iter_view_entries(
    view: Any, default_channel: str = "targets"
) -> Any:
    if view is None:
        return

    if isinstance(view, MetadataView):
        for record in view.records:
            yield record.channel, record.path, record.target
        return

    iter_targets = getattr(view, "iter_targets", None)
    if callable(iter_targets):
        for item in iter_targets():
            if len(item) == 3:
                yield str(item[0]), str(item[1]), item[2]
        return

    if isinstance(view, Targets):
        for path, target in view.targets.items():
            yield default_channel, path, target
        return

    if isinstance(view, Metadata):
        if isinstance(view.signed, Targets):
            for path, target in view.signed.targets.items():
                yield default_channel, path, target
        return

    if isinstance(view, TargetFile):
        yield default_channel, view.path, view
        return

    if isinstance(view, (bytes, bytearray)):
        metadata = Metadata.from_bytes(bytes(view))
        if isinstance(metadata.signed, Targets):
            for path, target in metadata.signed.targets.items():
                yield default_channel, path, target
        return

    if isinstance(view, str):
        stripped = view.strip()
        if stripped.startswith("{"):
            metadata = Metadata.from_bytes(stripped.encode())
            if isinstance(metadata.signed, Targets):
                for path, target in metadata.signed.targets.items():
                    yield default_channel, path, target
        return

    if isinstance(view, dict):
        if isinstance(view.get("targets"), dict):
            role = str(view.get("_type", default_channel))
            for path, info in view["targets"].items():
                if isinstance(info, TargetFile):
                    yield role, str(path), info
                elif isinstance(info, dict):
                    target = _target_from_dict(str(path), info)
                    if target is not None:
                        yield role, str(path), target
            return

        if _looks_like_target_map(view):
            for path, info in view.items():
                target = _target_from_dict(str(path), info)
                if target is not None:
                    yield default_channel, str(path), target
            return

        for key, value in view.items():
            channel = str(key)
            if isinstance(value, Targets):
                for path, target in value.targets.items():
                    yield channel, path, target
            elif isinstance(value, Metadata):
                if isinstance(value.signed, Targets):
                    for path, target in value.signed.targets.items():
                        yield channel, path, target
            elif isinstance(value, TargetFile):
                if channel == value.path or "/" in channel or "." in channel:
                    yield default_channel, channel, value
                else:
                    yield channel, value.path, value
            elif isinstance(value, dict):
                if "targets" in value and isinstance(value["targets"], dict):
                    for path, info in value["targets"].items():
                        if isinstance(info, TargetFile):
                            yield channel, str(path), info
                        elif isinstance(info, dict):
                            target = _target_from_dict(str(path), info)
                            if target is not None:
                                yield channel, str(path), target
                elif _looks_like_target_map(value):
                    for path, info in value.items():
                        target = _target_from_dict(str(path), info)
                        if target is not None:
                            yield channel, str(path), target
                else:
                    target = _target_from_dict(channel, value)
                    if target is not None:
                        yield default_channel, channel, target
            elif isinstance(value, (list, tuple, set)):
                for item in value:
                    yield from _iter_view_entries(item, channel)
            elif value is not None:
                target = value if isinstance(value, TargetFile) else None
                if target is not None:
                    yield channel, target.path, target
        return

    targets_attr = getattr(view, "targets", None)
    if isinstance(targets_attr, dict):
        for path, target in targets_attr.items():
            if isinstance(target, TargetFile):
                role = type(view).__name__.removesuffix("Targets").lower() or default_channel
                yield role, str(path), target
        return

    if isinstance(view, (list, tuple, set)):
        for item in view:
            yield from _iter_view_entries(item, default_channel)


def _build_view(view: Any) -> MetadataView:
    built = MetadataView()
    seen: set[tuple[Any, ...]] = set()
    for channel, path, target in _iter_view_entries(view):
        identity = TargetIdentity.from_target(target)
        dedupe_key = (channel, path, identity.length, identity.hashes)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        declaration = _extract_declaration(
            target, explicit_channel=channel
        )
        built.add(
            _Record(
                channel=channel,
                path=path,
                target=target,
                declaration=declaration,
                order=len(built.records),
            )
        )
    return built


def _candidate_items(candidates: Any, view: MetadataView) -> list[tuple[Any, str | None, str | None]]:
    items: list[tuple[Any, str | None, str | None]] = []

    def add(value: Any, module: str | None = None, channel: str | None = None) -> None:
        if value is None:
            return
        if isinstance(value, TargetCandidate):
            add(
                value.target if value.target is not None else value.value,
                value.module or module or value.name,
                value.channel or channel,
            )
            return
        if isinstance(value, dict) and ("target" in value or "value" in value) and not _looks_like_target_info(value):
            add(
                value.get("target", value.get("value")),
                value.get("module", value.get("name", module)),
                value.get("channel", channel),
            )
            return
        if isinstance(value, dict):
            if _looks_like_target_info(value) and ("path" in value or module):
                add(_target_from_dict(str(value.get("path", module)), value), module, channel)
                return
            for key, item in value.items():
                key_text = str(key)
                is_module_key = (
                    key_text in view.module_names
                    or key_text in view.paths
                    or "/" in key_text
                    or "." in key_text
                )
                if is_module_key:
                    add(item, key_text, channel)
                else:
                    add(item, module, key_text)
            return
        if isinstance(value, (list, tuple, set)):
            if (
                isinstance(value, tuple)
                and len(value) == 2
                and isinstance(value[0], str)
                and isinstance(value[1], (TargetFile, TargetCandidate, dict))
            ):
                add(value[1], value[0], channel)
                return
            for item in value:
                add(item, module, channel)
            return
        items.append((value, module, channel))

    if candidates is None:
        for record in view.records:
            items.append((record.target, None, None))
    else:
        add(candidates)
    return items


def _channel_filter(
    records: list[_Record], channel: str | None
) -> list[_Record]:
    if channel is None:
        return records
    filtered = [record for record in records if record.channel == channel]
    return filtered or records


def _resolve_candidate(
    value: Any,
    module_hint: str | None,
    channel_hint: str | None,
    view: MetadataView,
) -> tuple[list[_Record], CombinationConflict | None]:
    if isinstance(value, TargetCandidate):
        module_hint = value.module or value.name or module_hint
        channel_hint = value.channel or channel_hint
        value = _first_value(value.target, value.value)

    if isinstance(value, dict) and ("target" in value or "value" in value):
        wrapper = TargetCandidate(**value)
        return _resolve_candidate(
            wrapper, module_hint, channel_hint, view
        )

    if isinstance(value, dict):
        path = str(_first_value(module_hint, value.get("path"), value.get("name"), "candidate"))
        target = _target_from_dict(path, value)
        if target is not None:
            value = target

    if isinstance(value, TargetFile):
        path = value.path or module_hint or ""
        records = _channel_filter(view.path_records(path), channel_hint)
        matching = [
            record
            for record in records
            if record.target.length == value.length
            and record.target.hashes == value.hashes
        ]
        if matching:
            return matching, None

        hash_matches = [
            record
            for record in view.records
            if record.target.length == value.length
            and record.target.hashes == value.hashes
        ]
        hash_matches = _channel_filter(hash_matches, channel_hint)
        if len(hash_matches) == 1:
            return hash_matches, None

        if records or view.path_records(path):
            conflict = CombinationConflict(
                kind=ConflictKind.IDENTITY.value,
                reason="candidate-identity-mismatch",
                message=(
                    f"Candidate {path!r} has a different identity from the "
                    "verified metadata view"
                ),
                modules=(module_hint or PurePosixPath(path).stem,),
                channels=tuple(
                    sorted({record.channel for record in records})
                ),
                identities=(
                    str(TargetIdentity.from_target(value)),
                    *[str(record.identity) for record in records],
                ),
            )
            return [], conflict

        conflict = CombinationConflict(
            kind=ConflictKind.MISSING.value,
            reason="missing-candidate",
            message=f"Candidate {path!r} is not in the verified metadata view",
            modules=(module_hint or path,),
        )
        return [], conflict

    if not isinstance(value, str):
        conflict = CombinationConflict(
            kind=ConflictKind.INVALID.value,
            reason="invalid-candidate",
            message=f"Unsupported candidate: {value!r}",
        )
        return [], conflict

    name = value.strip()
    records = _channel_filter(view.path_records(name), channel_hint)

    if not records:
        module_name = module_hint or name
        records = _channel_filter(
            view.module_records(module_name), channel_hint
        )

    if not records:
        suffix_matches = [
            record
            for record in view.records
            if record.path == name
            or record.path.endswith("/" + name)
            or PurePosixPath(record.path).name == name
            or PurePosixPath(record.path).stem == name
        ]
        records = _channel_filter(suffix_matches, channel_hint)

    if module_hint and not any(
        record.module == module_hint for record in records
    ):
        hinted = _channel_filter(
            view.module_records(module_hint), channel_hint
        )
        if hinted:
            records = hinted

    if not records:
        conflict = CombinationConflict(
            kind=ConflictKind.MISSING.value,
            reason="missing-candidate",
            message=(
                f"Candidate target {name!r} is not present in the verified "
                "metadata view"
            ),
            modules=(module_hint or name,),
        )
        return [], conflict

    return records, None


def _provided_version(record: _Record, requirement: DependencyRequirement) -> str | None:
    if requirement.interface:
        return record.declaration.provided_version(requirement.interface)
    return record.declaration.version


def _requirement_matches(record: _Record, requirement: DependencyRequirement) -> bool:
    if not requirement.version:
        return True
    provided = _provided_version(record, requirement)
    if provided is None:
        return False
    return VersionConstraint(requirement.version).matches(provided)


def _identity_conflict(
    module: str, existing: _Record, incoming: _Record
) -> CombinationConflict:
    return CombinationConflict(
        kind=ConflictKind.IDENTITY.value,
        reason="multiple-identities",
        message=(
            f"Module {module!r} has different identities in the selected "
            "candidates or channels"
        ),
        modules=(module,),
        channels=tuple(
            dict.fromkeys((existing.channel, incoming.channel))
        ),
        identities=(
            str(existing.identity),
            str(incoming.identity),
        ),
    )


def _providers_for_requirement(
    requirement: DependencyRequirement,
    view: MetadataView,
    selected: dict[str, _Record],
) -> list[_Record]:
    if requirement.interface:
        records = [
            record
            for record in view.records
            if record.declaration.provides_interface(requirement.interface)
        ]
        if requirement.module:
            named = view.module_records(requirement.module)
            named_ids = {id(record) for record in named}
            filtered = [record for record in records if id(record) in named_ids]
            if filtered:
                records = filtered
            else:
                records = named
    elif requirement.module:
        records = view.module_records(requirement.module)
    else:
        records = []

    module_name = requirement.module
    if module_name and module_name in selected:
        selected_record = selected[module_name]
        records = [selected_record] + [
            record for record in records if record is not selected_record
        ]
    return records


def _caller_version(
    requirement: DependencyRequirement, caller: dict[str, str]
) -> str | None:
    if requirement.interface and requirement.interface in caller:
        return caller[requirement.interface]
    if requirement.module in {"caller", "<caller>", "app", "application"}:
        if requirement.interface and requirement.interface in caller:
            return caller[requirement.interface]
    return None


def _resolve_requirement(
    requirement: DependencyRequirement,
    source: _Record,
    view: MetadataView,
    selected: dict[str, _Record],
    caller: dict[str, str],
) -> tuple[Dependency, _Record | None, CombinationConflict | None]:
    providers = _providers_for_requirement(requirement, view, selected)
    if providers:
        matching = [
            record
            for record in providers
            if _requirement_matches(record, requirement)
        ]
        chosen = matching[0] if matching else providers[0]
        satisfied = bool(matching)
        if requirement.module and len(
            {str(record.identity) for record in matching}
        ) > 1:
            conflict = CombinationConflict(
                kind=ConflictKind.IDENTITY.value,
                reason="ambiguous-provider-identity",
                message=(
                    f"Requirement {requirement} matches multiple identities"
                ),
                modules=(requirement.module,),
                channels=tuple(
                    dict.fromkeys(record.channel for record in matching)
                ),
                identities=tuple(
                    dict.fromkeys(str(record.identity) for record in matching)
                ),
            )
            edge = Dependency(
                module=source.module,
                dependency=requirement.module or chosen.module,
                interface=requirement.interface,
                constraint=requirement.version,
                channel=source.channel,
                dependency_channel=chosen.channel,
                target=chosen.path,
                provided_version=_provided_version(chosen, requirement),
                satisfied=False,
                optional=requirement.optional,
                source=source.module,
                reason="ambiguous identity",
            )
            return edge, chosen, conflict

        edge = Dependency(
            module=source.module,
            dependency=requirement.module or chosen.module,
            interface=requirement.interface,
            constraint=requirement.version,
            channel=source.channel,
            dependency_channel=chosen.channel,
            target=chosen.path,
            provided_version=_provided_version(chosen, requirement),
            satisfied=satisfied,
            optional=requirement.optional,
            source=source.module,
        )
        return edge, chosen, None

    caller_version = _caller_version(requirement, caller)
    if caller_version is not None:
        constraint = VersionConstraint(requirement.version or "*")
        satisfied = constraint.matches(caller_version)
        edge = Dependency(
            module=source.module,
            dependency="<caller>",
            interface=requirement.interface,
            constraint=requirement.version,
            channel=source.channel,
            target=None,
            provided_version=caller_version,
            satisfied=satisfied,
            optional=requirement.optional,
            source=source.module,
        )
        if not satisfied:
            conflict = CombinationConflict(
                kind=ConflictKind.UNSATISFIABLE.value,
                reason="caller-interface-version",
                message=(
                    f"Caller interface {requirement.interface!r} version "
                    f"{caller_version!r} does not satisfy {requirement.version!r}"
                ),
                group=(
                    str(requirement),
                    f"<caller> {requirement.interface}=={caller_version}",
                ),
                modules=(source.module, "<caller>"),
            )
            return edge, None, conflict
        return edge, None, None

    if requirement.optional:
        edge = Dependency(
            module=source.module,
            dependency=requirement.module or requirement.interface or "<missing>",
            interface=requirement.interface,
            constraint=requirement.version,
            channel=source.channel,
            satisfied=None,
            optional=True,
            source=source.module,
            reason="optional requirement absent",
        )
        return edge, None, None

    missing_name = (
        requirement.module
        or requirement.interface
        or "unspecified requirement"
    )
    conflict = CombinationConflict(
        kind=ConflictKind.MISSING.value,
        reason=(
            "missing-interface"
            if requirement.interface and not requirement.module
            else "missing-dependency"
        ),
        message=f"Required module or interface {missing_name!r} is absent",
        modules=(missing_name,),
        constraints=(str(requirement),),
        group=(str(requirement),),
    )
    edge = Dependency(
        module=source.module,
        dependency=str(missing_name),
        interface=requirement.interface,
        constraint=requirement.version,
        channel=source.channel,
        satisfied=False,
        source=source.module,
        reason="missing provider",
    )
    return edge, None, conflict


def _identity_conflict(
    module: str,
    existing: _Record,
    incoming: _Record,
) -> CombinationConflict:
    return CombinationConflict(
        kind=ConflictKind.IDENTITY.value,
        reason="multiple-identities",
        message=(
            f"Module {module!r} has multiple identities in the selected "
            "closure"
        ),
        modules=(module,),
        channels=(existing.channel, incoming.channel),
        identities=(str(existing.identity), str(incoming.identity)),
    )


def _find_cycle(
    order: list[str],
    graph: dict[str, list[str]],
    selected: dict[str, _Record],
) -> tuple[str, ...] | None:
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> tuple[str, ...] | None:
        state[node] = 1
        stack.append(node)
        for nxt in graph.get(node, ()):
            if nxt not in selected:
                continue
            next_state = state.get(nxt, 0)
            if next_state == 1:
                start = stack.index(nxt)
                return tuple(stack[start:] + [nxt])
            if next_state == 0:
                found = visit(nxt)
                if found is not None:
                    return found
        stack.pop()
        state[node] = 2
        return None

    for module in order:
        if state.get(module, 0) == 0:
            found = visit(module)
            if found is not None:
                return found
    return None


def _resolve_closure(
    view: MetadataView,
    roots: list[_Record],
    caller: dict[str, str],
    allow_cycles: bool,
) -> tuple[
    dict[str, _Record],
    list[str],
    list[Dependency],
    dict[str, list[str]],
    CombinationConflict | None,
]:
    selected: dict[str, _Record] = {}
    order: list[str] = []
    edges: list[Dependency] = []
    graph: dict[str, list[str]] = {}
    queue: list[_Record] = list(roots)
    processed: set[str] = set()

    while queue:
        record = queue.pop(0)
        module = record.module
        existing = selected.get(module)
        if existing is not None and existing.identity != record.identity:
            return selected, order, edges, graph, _identity_conflict(
                module, existing, record
            )
        if module in processed:
            continue

        selected[module] = record
        if module not in order:
            order.append(module)
        processed.add(module)
        graph.setdefault(module, [])

        for raw_requirement in record.declaration.requires:
            requirement = raw_requirement
            if requirement.source is None:
                requirement = DependencyRequirement(
                    module=requirement.module,
                    interface=requirement.interface,
                    version=requirement.version,
                    source=module,
                    optional=requirement.optional,
                    reason=requirement.reason,
                )

            edge, provider, conflict = _resolve_requirement(
                requirement, record, view, selected, caller
            )
            edges.append(edge)
            graph[module].append(edge.dependency)

            if conflict is not None:
                return selected, order, edges, graph, conflict
            if provider is not None and provider.module not in processed:
                queue.append(provider)

    if not allow_cycles:
        cycle = _find_cycle(order, graph, selected)
        if cycle is not None:
            group = tuple(
                f"{cycle[index]} -> {cycle[index + 1]}"
                for index in range(len(cycle) - 1)
            )
            conflict = CombinationConflict(
                kind=ConflictKind.CYCLE.value,
                reason="dependency-cycle",
                message="Dependency cycle found: " + ", ".join(group),
                modules=tuple(dict.fromkeys(cycle[:-1])),
                cycle=cycle,
                group=group,
                constraints=group,
            )
            return selected, order, edges, graph, conflict

    conflict = _constraint_conflict(edges, caller)
    if conflict is not None:
        return selected, order, edges, graph, conflict

    conflict = _config_conflict(selected, caller.get("__config__"))
    if conflict is not None:
        return selected, order, edges, graph, conflict

    return selected, order, edges, graph, None


def _constraint_conflict(
    edges: list[Dependency], caller: dict[str, str]
) -> CombinationConflict | None:
    groups: dict[tuple[str, str], list[Dependency]] = {}
    order: list[tuple[str, str]] = []
    for edge in edges:
        if edge.interface:
            key = ("interface", edge.interface)
        else:
            key = ("module", edge.dependency)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(edge)

    for key in order:
        group_edges = groups[key]
        failed = [edge for edge in group_edges if edge.satisfied is False]
        interface = key[1] if key[0] == "interface" else None
        caller_expression = caller.get(interface) if interface else None
        caller_failed = False
        provider_versions = [
            edge.provided_version
            for edge in group_edges
            if edge.dependency != "<caller>" and edge.provided_version
        ]
        if caller_expression is not None and provider_versions:
            caller_failed = not any(
                VersionConstraint(caller_expression).matches(version)
                for version in provider_versions
            )

        if not failed and not caller_failed:
            continue

        descriptions = tuple(str(edge) for edge in group_edges)
        if caller_expression is not None:
            descriptions += (
                f"<caller> requires {interface} {caller_expression}",
            )
        reason = "interface-version" if interface else "module-version"
        return CombinationConflict(
            kind=ConflictKind.UNSATISFIABLE.value,
            reason=reason,
            message="Incompatible constraint group: " + "; ".join(descriptions),
            group=descriptions,
            constraints=descriptions,
            modules=tuple(
                dict.fromkeys(
                    [edge.module for edge in group_edges]
                    + [edge.dependency for edge in group_edges]
                )
            ),
        )
    return None


def _caller_constraint_conflict(
    selected: dict[str, _Record], caller: dict[str, str]
) -> CombinationConflict | None:
    for interface, expression in caller.items():
        if interface.startswith("__"):
            continue
        providers = [
            record
            for record in selected.values()
            if record.declaration.provides_interface(interface)
        ]
        if not providers:
            continue
        constraint = VersionConstraint(expression)
        compatible = [
            record
            for record in providers
            if constraint.matches(
                record.declaration.provided_version(interface)
            )
        ]
        if compatible:
            continue
        descriptions = [f"<caller> requires {interface} {expression}"]
        for record in providers:
            version = record.declaration.provided_version(interface)
            descriptions.append(
                f"{record.module} provides {interface} {version or '*'}"
            )
        group = tuple(descriptions)
        return CombinationConflict(
            kind=ConflictKind.UNSATISFIABLE.value,
            reason="caller-interface-version",
            message="Caller interface declaration is incompatible: "
            + "; ".join(group),
            group=group,
            constraints=group,
            modules=tuple(record.module for record in providers),
        )
    return None


def _split_config(value: str) -> tuple[str | None, str]:
    if "/" in value:
        prefix, version = value.rsplit("/", 1)
        return prefix or None, version
    return None, value


def _config_conflict(
    selected: dict[str, _Record], caller_config: Any = None
) -> CombinationConflict | None:
    declarations: list[tuple[str, str]] = [
        (module, record.declaration.config)
        for module, record in selected.items()
        if record.declaration.config
    ]
    if caller_config:
        declarations.append(("<caller>", str(caller_config)))
    if len(declarations) < 2:
        return None

    raw_values = [value for _, value in declarations]
    if len(set(raw_values)) == 1:
        return None

    parsed: list[tuple[str, str | None, str, VersionConstraint, bool]] = []
    prefixes: set[str | None] = set()
    for _, raw in declarations:
        prefix, token = _split_config(raw)
        prefixes.add(prefix)
        is_range = any(op in token for op in (">", "<", "=", "~", "^", "*"))
        parsed.append(
            (raw, prefix, token, VersionConstraint(token), is_range)
        )

    named_prefixes = {prefix for prefix in prefixes if prefix is not None}
    compatible = len(named_prefixes) <= 1
    if compatible:
        exact = [item for item in parsed if not item[4]]
        for _, _, exact_token, _, _ in exact:
            for _, _, _, constraint, _ in parsed:
                if not constraint.matches(exact_token):
                    compatible = False
                    break
            if not compatible:
                break

    if compatible:
        return None

    group = tuple(
        f"{module} config {value}" for module, value in declarations
    )
    return CombinationConflict(
        kind=ConflictKind.UNSATISFIABLE.value,
        reason="config-mismatch",
        message="Selected modules do not read the same configuration: "
        + "; ".join(group),
        group=group,
        constraints=group,
        modules=tuple(module for module, _ in declarations),
    )


def preflight_combination(
    metadata_view: Any = None,
    candidates: Any = None,
    interfaces: Any = None,
    *args: Any,
    **kwargs: Any,
) -> CombinationPlan:
    view_value = _first_value(
        kwargs.get("view"),
        kwargs.get("verified_metadata_view"),
        kwargs.get("verified_metadata"),
        kwargs.get("metadata"),
        metadata_view,
    )
    candidate_value = _first_value(
        kwargs.get("candidate_targets"),
        kwargs.get("targets"),
        kwargs.get("candidate"),
        kwargs.get("candidate_target"),
        candidates,
    )
    caller_value = _first_value(
        kwargs.get("caller_interfaces"),
        kwargs.get("interface_versions"),
        kwargs.get("interface_version_declarations"),
        kwargs.get("interface_declaration"),
        kwargs.get("caller"),
        interfaces,
    )
    config_value = _first_value(
        kwargs.get("config_version"),
        kwargs.get("caller_config"),
        kwargs.get("config"),
    )
    if args:
        if caller_value is None:
            caller_value = args[0]
        elif len(args) > 1 and config_value is None:
            config_value = args[1]

    view = _build_view(view_value)
    caller = _normalize_interfaces(caller_value)
    if config_value is None and isinstance(caller_value, dict):
        config_value = _first_value(
            caller_value.get("config"),
            caller_value.get("config_version"),
            caller_value.get("caller_config"),
        )
    if config_value is not None:
        caller["__config__"] = str(config_value)

    allow_cycles = bool(kwargs.get("allow_cycles", False))
    raise_on_conflict = bool(kwargs.get("raise_on_conflict", False))
    attempted: dict[str, TargetFile] = {}
    roots: list[_Record] = []

    for value, module_hint, channel_hint in _candidate_items(
        candidate_value, view
    ):
        records, conflict = _resolve_candidate(
            value, module_hint, channel_hint, view
        )
        if conflict is not None:
            plan = _failure_plan(
                conflict,
                caller=caller,
                config=config_value,
                attempted=attempted,
            )
            if raise_on_conflict:
                plan.raise_for_conflict()
            return plan
        for record in records:
            if channel_hint and record.channel != channel_hint:
                record = _Record(
                    channel=channel_hint,
                    path=record.path,
                    target=record.target,
                    declaration=record.declaration,
                    order=record.order,
                )
            roots.append(record)
            attempted.setdefault(record.module, record.target)

    selected, order, edges, _graph, conflict = _resolve_closure(
        view, roots, caller, allow_cycles
    )
    if conflict is None:
        conflict = _caller_constraint_conflict(selected, caller)

    if conflict is not None:
        plan = _failure_plan(
            conflict,
            caller=caller,
            config=config_value,
            attempted=attempted,
            edges=edges,
        )
        if raise_on_conflict:
            plan.raise_for_conflict()
        return plan

    target_map = {module: selected[module].target for module in order}
    path_map = {
        record.target.path: record.target for record in selected.values()
    }
    caller_view = dict(caller)
    caller_view.pop("__config__", None)
    plan = CombinationPlan(
        targets=target_map,
        dependencies=tuple(edges),
        conflict=None,
        caller_interfaces=caller_view,
        caller_config=None if config_value is None else str(config_value),
        attempted_targets=attempted,
        targets_by_path=path_map,
    )
    if raise_on_conflict:
        plan.raise_for_conflict()
    return plan


def _failure_plan(
    conflict: CombinationConflict,
    *,
    caller: dict[str, str],
    config: Any,
    attempted: dict[str, TargetFile],
    edges: list[Dependency] | tuple[Dependency, ...] = (),
) -> CombinationPlan:
    caller_view = dict(caller)
    caller_view.pop("__config__", None)
    return CombinationPlan(
        targets={},
        dependencies=tuple(edges),
        conflict=conflict,
        caller_interfaces=caller_view,
        caller_config=None if config is None else str(config),
        attempted_targets=dict(attempted),
        targets_by_path={},
    )
    return CombinationConflict(
        kind=ConflictKind.UNSATISFIABLE.value,
        reason="config-mismatch",
        message="Selected modules do not read the same configuration: "
        + "; ".join(group),
        group=group,
        constraints=group,
        modules=tuple(module for module, _ in declarations),
    )


class CombinationPreflight:
    """Builder-style entry point for offline combination resolution."""

    def __init__(
        self,
        metadata_view: Any = None,
        candidates: Any = None,
        interfaces: Any = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.metadata_view = _first_value(
            kwargs.get("verified_metadata_view"),
            kwargs.get("verified_metadata"),
            kwargs.get("view"),
            kwargs.get("metadata"),
            metadata_view,
        )
        self.candidates = _first_value(
            kwargs.get("candidate_targets"),
            kwargs.get("targets"),
            kwargs.get("candidate"),
            candidates,
        )
        self.interfaces = _first_value(
            kwargs.get("caller_interfaces"),
            kwargs.get("interface_versions"),
            kwargs.get("caller"),
            interfaces,
        )
        self.args = args
        self.kwargs = kwargs

    def resolve(self, *args: Any, **kwargs: Any) -> CombinationPlan:
        options = dict(self.kwargs)
        options.update(kwargs)
        candidates = _first_value(
            args[0] if args else None, self.candidates
        )
        interfaces = _first_value(
            args[1] if len(args) > 1 else None, self.interfaces
        )
        return preflight_combination(
            self.metadata_view,
            candidates,
            interfaces,
            *self.args,
            **options,
        )

    run = resolve
    plan = resolve
    check = resolve
    execute = resolve
    select = resolve
    adopt = resolve
    preflight = resolve

    @classmethod
    def from_updater(cls, updater: Any, *args: Any, **kwargs: Any) -> CombinationPreflight:
        view = getattr(updater, "_trusted_set", updater)
        return cls(view, *args, **kwargs)


def _alias(name: str) -> Any:
    def caller(*args: Any, **kwargs: Any) -> CombinationPlan:
        return preflight_combination(*args, **kwargs)

    caller.__name__ = name
    return caller


check_combination = _alias("check_combination")
check_target_combination = _alias("check_target_combination")
combination_precheck = _alias("combination_precheck")
combination_preflight = preflight_combination
compute_closure = _alias("compute_closure")
plan_combination = _alias("plan_combination")
plan_target_combination = _alias("plan_target_combination")
precheck_combination = _alias("precheck_combination")
preflight_target_combination = _alias("preflight_target_combination")
preflight_targets = _alias("preflight_targets")
resolve_adoption = _alias("resolve_adoption")
resolve_combination = _alias("resolve_combination")
resolve_target_closure = _alias("resolve_target_closure")
resolve_target_combination = _alias("resolve_target_combination")

TargetCombinationPreflight = CombinationPreflight
TargetCombinationPrecheck = CombinationPreflight
CombinationPrecheck = CombinationPreflight
Precheck = CombinationPreflight
Preflight = CombinationPreflight
