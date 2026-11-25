# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline preflight for adopting a *combination* of verified targets.

Normal TUF target lookup answers one question at a time: "is this target
authentic?". Applications that load several modules also need to know whether
the targets can be used together, before anything is started. This module
answers that second question without doing network or file-system I/O.

The input is an already verified metadata view (for example the
``TrustedMetadataSet`` held by :class:`tuf.ngclient.Updater`), a set of
candidate targets, and the caller's interface-version declaration. The planner
resolves the dependency closure and reports either:

* an adoptable mapping of modules to verified ``TargetFile`` objects together
  with the dependency/evidence edges that justify the closure, or
* the first (in deterministic traversal order) unsatisfiable constraint group,
  identity conflict, missing dependency, or dependency cycle.

Module declarations are read from a target's ``custom`` field. The following
shape is understood (all fields except ``module`` are optional)::

    "custom": {
        "module": "codec",
        "version": "1.4.2",
        "provides": {"codec-api": "2.1.0"},
        "requires": [
            {
                "module": "runtime",
                "interface": "runtime-api",
                "version": ">=2,<3"
            },
            "util"
        ],
        "config": "app-config/v3"
    }

``module`` defaults to the target path. ``requires`` may also be a list of
module names or a mapping of module names to version constraints. The caller
declaration is normally a mapping of interface names to versions or version
constraints; ``config_version`` declares the configuration generation the
caller can read.

The planner is deliberately side-effect free: it never refreshes metadata,
downloads a target, or writes to the Updater cache.
"""

from __future__ import annotations

import json
import re
from collections import abc
from dataclasses import dataclass, field
from itertools import pairwise
from typing import TYPE_CHECKING, Any

from tuf.api.metadata import Metadata, TargetFile, Targets

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "ClientDownloadState",
    "CombinationConflict",
    "CombinationConflictError",
    "CombinationError",
    "CombinationPlan",
    "CombinationPreflight",
    "CombinationResult",
    "Dependency",
    "DependencyEdge",
    "DependencyRequirement",
    "InterfaceDeclaration",
    "ModuleDeclaration",
    "Requirement",
    "TargetCandidate",
    "TargetIdentity",
    "VersionConstraint",
    "check_combination",
    "check_target_combination",
    "combination_preflight",
    "plan_target_combination",
    "preflight_combination",
    "preflight_target_combination",
    "preflight_targets",
    "resolve_combination",
    "resolve_target_closure",
    "resolve_target_combination",
]


class CombinationError(Exception):
    """Base class for errors raised by the combination preflight."""


class CombinationConflictError(CombinationError):
    """Raised when a combination cannot be adopted.

    Args:
        conflict: The structured conflict that caused the failure.
    """

    def __init__(self, conflict: CombinationConflict):
        super().__init__(conflict.message)
        self.conflict = conflict

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        # Make common conflict attributes available directly on the exception.
        return getattr(self.conflict, name)


@dataclass(frozen=True, order=True)
class TargetIdentity:
    """Content identity of a target inside one verified metadata view."""

    path: str
    length: int
    hashes: tuple[tuple[str, str], ...]
    explicit: str | None = None

    @classmethod
    def from_target(
        cls, target: TargetFile, explicit: str | None = None
    ) -> TargetIdentity:
        """Build a target identity from a ``TargetFile``."""
        return cls(
            target.path,
            target.length,
            tuple(sorted(target.hashes.items())),
            explicit,
        )

    def __str__(self) -> str:
        if self.explicit is not None:
            return self.explicit
        digests = ", ".join(f"{name}:{value}" for name, value in self.hashes)
        return f"{self.path} ({digests}, {self.length} bytes)"


@dataclass(frozen=True)
class DependencyRequirement:
    """One module or interface requirement declared by a target."""

    module: str | None = None
    interface: str | None = None
    version: str | None = None
    source: str | None = None
    reason: str = ""

    @property
    def constraint(self) -> str | None:
        """Alias for ``version`` used by callers that call it a constraint."""
        return self.version

    def __str__(self) -> str:
        target = self.module or "caller"
        if self.interface is not None:
            target = f"{target}::{self.interface}"
        if self.version is not None:
            return f"{target} {self.version}"
        return target


@dataclass(frozen=True)
class Dependency:
    """A resolved dependency edge and the evidence for the resolution."""

    module: str
    dependency: str
    interface: str | None = None
    constraint: str | None = None
    channel: str | None = None
    dependency_channel: str | None = None
    target: str | None = None
    provided_version: str | None = None
    satisfied: bool | None = None
    source: str | None = None
    reason: str = ""
    order: int = 0

    @property
    def from_module(self) -> str:
        """Alias for the depending module."""
        return self.module

    @property
    def to_module(self) -> str:
        """Alias for the dependency module."""
        return self.dependency

    @property
    def requirement(self) -> str | None:
        """Alias for the version constraint."""
        return self.constraint

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this edge."""
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
            "source": self.source,
            "reason": self.reason,
            "order": self.order,
        }

    def __str__(self) -> str:
        if self.interface is not None:
            dep = f"{self.dependency}::{self.interface}"
        else:
            dep = self.dependency
        if self.constraint is not None:
            dep = f"{dep} {self.constraint}"
        return f"{self.module} -> {dep}"


DependencyEdge = Dependency
Requirement = DependencyRequirement


@dataclass(frozen=True)
class InterfaceDeclaration:
    """Caller-declared interface versions and configuration generation."""

    versions: tuple[tuple[str, str], ...] = ()
    config: str | None = None

    @classmethod
    def from_declaration(
        cls,
        declaration: Any,  # noqa: ANN401
        config: Any = None,  # noqa: ANN401
    ) -> InterfaceDeclaration:
        """Normalize a caller declaration into this immutable form."""
        versions, parsed_config = _parse_caller_declaration(declaration)
        if config is not None:
            parsed_config = _canonical_config(config)
        return cls(tuple(versions.items()), parsed_config)

    def as_dict(self) -> dict[str, str]:
        """Return the interface versions as a regular dictionary."""
        return dict(self.versions)

    def get(self, interface: str) -> str | None:
        """Return the declared constraint for ``interface``."""
        return dict(self.versions).get(interface)


@dataclass(frozen=True)
class ModuleDeclaration:
    """Normalized module metadata read from a target's custom fields."""

    module: str
    version: str | None = None
    provides: tuple[tuple[str, str | None], ...] = ()
    requires: tuple[DependencyRequirement, ...] = ()
    config: str | None = None
    identity: str | None = None

    def provided_version(self, interface: str) -> str | None:
        """Return the provided version, or ``None`` if not provided."""
        return dict(self.provides).get(interface)

    def provides_interface(self, interface: str) -> bool:
        """Return whether this module declares ``interface``."""
        return interface in dict(self.provides)


@dataclass(frozen=True)
class TargetCandidate:
    """An explicitly supplied candidate target.

    Usually candidates are just target paths or ``TargetFile`` objects. This
    wrapper allows a caller to add a logical module name, a channel name, or
    inline declarations without modifying signed metadata.
    """

    target: TargetFile | str
    module: str | None = None
    channel: str | None = None
    version: str | None = None
    provides: tuple[tuple[str, str | None], ...] | None = None
    requires: tuple[DependencyRequirement, ...] | None = None
    config: str | None = None
    identity: str | None = None


@dataclass(frozen=True)
class CombinationConflict:
    """The first unsolvable constraint group found by the preflight."""

    kind: str
    message: str
    group: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()
    channels: tuple[str, ...] = ()
    identities: tuple[str, ...] = ()
    cycle: tuple[str, ...] = ()
    requirements: tuple[DependencyRequirement, ...] = ()
    reason: str = ""
    order: int = 0

    @property
    def type(self) -> str:
        """Alias for ``kind``."""
        return self.kind

    @property
    def category(self) -> str:
        """Alias for ``kind``."""
        return self.kind

    @property
    def conflict_type(self) -> str:
        """Alias for ``kind``."""
        return self.kind

    @property
    def code(self) -> str:
        """Alias for ``kind``."""
        return self.kind

    @property
    def constraint_group(self) -> tuple[str, ...]:
        """The earliest unsolvable constraint group."""
        return self.group

    @property
    def constraints(self) -> tuple[str, ...]:
        """Alias for ``group``."""
        return self.group

    @property
    def first_unsatisfiable(self) -> tuple[str, ...]:
        """Alias for ``group``."""
        return self.group

    @property
    def is_cycle(self) -> bool:
        """Return whether this conflict is a dependency cycle."""
        return self.kind == "cycle"

    @property
    def is_identity_conflict(self) -> bool:
        """Return whether this conflict is an identity conflict."""
        return self.kind == "identity"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the conflict."""
        return {
            "kind": self.kind,
            "message": self.message,
            "group": list(self.group),
            "modules": list(self.modules),
            "channels": list(self.channels),
            "identities": list(self.identities),
            "cycle": list(self.cycle),
            "reason": self.reason,
            "order": self.order,
        }

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class ClientDownloadState:
    """Side-effect snapshot useful for asserting preflight is offline.

    The values are derived from already-loaded trusted metadata only.
    """

    roles: tuple[tuple[str, int, str], ...] = ()
    targets: tuple[str, ...] = ()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClientDownloadState):
            return False
        return (self.roles, self.targets) == (other.roles, other.targets)

    def __hash__(self) -> int:
        return hash((self.roles, self.targets))


@dataclass(frozen=True)
class CombinationPlan:
    """Result of a combination preflight.

    ``targets`` maps logical module names to the verified ``TargetFile``
    objects in the closure. ``dependencies`` contains the evidence edges in
    traversal order. If ``conflict`` is set the targets mapping is empty and
    ``first_unsatisfiable`` points at the earliest unsolvable group.
    """

    targets: dict[str, TargetFile] = field(default_factory=dict)
    dependencies: tuple[Dependency, ...] = ()
    conflict: CombinationConflict | None = None
    caller_interfaces: tuple[tuple[str, str], ...] = ()
    caller_config: str | None = None
    attempted_targets: dict[str, TargetFile] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """Return whether the whole closure can be adopted."""
        return self.conflict is None

    @property
    def success(self) -> bool:
        """Alias for ``ok``."""
        return self.ok

    @property
    def adoptable_targets(self) -> dict[str, TargetFile]:
        """Return targets that may be adopted, or an empty mapping."""
        return self.targets if self.ok else {}

    @property
    def modules(self) -> dict[str, TargetFile]:
        """Alias for the adoptable target mapping."""
        return self.adoptable_targets

    @property
    def adoptable(self) -> dict[str, TargetFile]:
        """Alias for ``adoptable_targets``."""
        return self.adoptable_targets

    @property
    def selected_targets(self) -> dict[str, TargetFile]:
        """Alias for ``adoptable_targets``."""
        return self.adoptable_targets

    @property
    def resolved_targets(self) -> dict[str, TargetFile]:
        """Alias for ``adoptable_targets``."""
        return self.adoptable_targets

    @property
    def targets_by_path(self) -> dict[str, TargetFile]:
        """Return the adoptable targets keyed by target path."""
        return {
            target.path: target for target in self.adoptable_targets.values()
        }

    @property
    def target_paths(self) -> dict[str, TargetFile]:
        """Alias for ``targets_by_path``."""
        return self.targets_by_path

    @property
    def dependency_evidence(self) -> tuple[Dependency, ...]:
        """Return the evidence edges for the closure."""
        return self.dependencies

    @property
    def evidence(self) -> tuple[Dependency, ...]:
        """Alias for ``dependency_evidence``."""
        return self.dependency_evidence

    @property
    def dependency_map(self) -> dict[str, tuple[Dependency, ...]]:
        """Return evidence edges grouped by depending module."""
        result: dict[str, list[Dependency]] = {}
        for edge in self.dependencies:
            result.setdefault(edge.module, []).append(edge)
        return {module: tuple(edges) for module, edges in result.items()}

    @property
    def first_conflict(self) -> CombinationConflict | None:
        """Alias for ``conflict``."""
        return self.conflict

    @property
    def error(self) -> CombinationConflict | None:
        """Alias for ``conflict``."""
        return self.conflict

    @property
    def conflicts(self) -> tuple[CombinationConflict, ...]:
        """Return the conflict as a tuple, or an empty tuple on success."""
        return () if self.conflict is None else (self.conflict,)

    @property
    def first_unsatisfiable(self) -> tuple[str, ...] | None:
        """Return the earliest unsolvable constraint group, if any."""
        if self.conflict is None:
            return None
        return self.conflict.group

    @property
    def unsatisfiable(self) -> tuple[str, ...] | None:
        """Alias for ``first_unsatisfiable``."""
        return self.first_unsatisfiable

    @property
    def constraint_group(self) -> tuple[str, ...] | None:
        """Alias for ``first_unsatisfiable``."""
        return self.first_unsatisfiable

    @property
    def unsatisfiable_group(self) -> tuple[str, ...] | None:
        """Alias for ``first_unsatisfiable``."""
        return self.first_unsatisfiable

    def get(self, name: str) -> TargetFile | None:
        """Return a target by module name or target path."""
        if name in self.adoptable_targets:
            return self.adoptable_targets[name]
        for target in self.adoptable_targets.values():
            if target.path == name:
                return target
        return None

    def raise_for_conflict(self) -> None:
        """Raise ``CombinationConflictError`` if the plan failed."""
        if self.conflict is not None:
            raise CombinationConflictError(self.conflict)

    def raise_error(self) -> None:
        """Alias for :meth:`raise_for_conflict`."""
        self.raise_for_conflict()

    def __bool__(self) -> bool:
        return self.ok

    def __iter__(self) -> Iterator[str]:
        return iter(self.adoptable_targets)

    def __len__(self) -> int:
        return len(self.adoptable_targets)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self.get(name) is not None

    def __getitem__(self, name: str) -> TargetFile:
        target = self.get(name)
        if target is None:
            raise KeyError(name)
        return target


CombinationResult = CombinationPlan

_CONSTRAINT_OPS = ("~=", "==", "!=", ">=", "<=", ">", "<", "=", "^", "~")
_CONSTRAINT_RE = re.compile(r"^(~=|==|!=|>=|<=|>|<|=|\^|~)?\s*(.+)$")
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)([-+][0-9A-Za-z.-]+)?$")
_UNSET = object()


def _parse_version(value: str) -> tuple[tuple[int, ...], str] | None:
    match = _VERSION_RE.match(value.strip())
    if match is None:
        return None
    numbers = tuple(int(part) for part in match.group(1).split("."))
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers = numbers[:-1]
    return numbers, match.group(2) or ""


def _compare_versions(left: str, right: str) -> int | None:
    left_key = _parse_version(left)
    right_key = _parse_version(right)
    if left_key is None or right_key is None:
        return None
    left_numbers, left_suffix = left_key
    right_numbers, right_suffix = right_key
    width = max(len(left_numbers), len(right_numbers))
    left_numbers = left_numbers + (0,) * (width - len(left_numbers))
    right_numbers = right_numbers + (0,) * (width - len(right_numbers))
    if left_numbers != right_numbers:
        return -1 if left_numbers < right_numbers else 1
    if left_suffix == right_suffix:
        return 0
    if not left_suffix:
        return 1
    if not right_suffix:
        return -1
    return -1 if left_suffix < right_suffix else 1


def _increment_version(value: str, position: int | None = None) -> str | None:
    parsed = _parse_version(value)
    if parsed is None:
        return None
    numbers, _ = parsed
    index = len(numbers) - 1 if position is None else position
    if index < 0 or index >= len(numbers):
        return None
    numbers = list(numbers)
    numbers[index] += 1
    for trailing in range(index + 1, len(numbers)):
        numbers[trailing] = 0
    return ".".join(str(number) for number in numbers)


def _wildcard_bounds(value: str) -> tuple[str, str] | None:
    lowered = value.lower()
    if "*" not in lowered and "x" not in lowered.split("."):
        return None
    parts = value.split(".")
    numeric = []
    wildcard_index = None
    for index, part in enumerate(parts):
        if part in {"*", "x", "X"}:
            wildcard_index = index
            break
        if not part.isdigit():
            return None
        numeric.append(int(part))
    if wildcard_index is None or not numeric:
        return "0", "999999999"
    lower = ".".join(str(number) for number in numeric)
    upper_numbers = list(numeric)
    upper_numbers[-1] += 1
    upper = ".".join(str(number) for number in upper_numbers)
    return lower, upper


@dataclass(frozen=True)
class _Clause:
    operator: str
    version: str
    version_key: tuple[tuple[int, ...], str] | None

    def matches_text(self, version: str) -> bool:
        """Match a non-semantic version string literally."""
        if self.operator in {"==", "="}:
            return version == self.version
        if self.operator == "!=":
            return version != self.version
        return False

    def matches(self, version_key: tuple[tuple[int, ...], str] | None) -> bool:
        other = self.version_key
        if other is None:
            return False
        left_numbers, left_suffix = version_key
        right_numbers, right_suffix = other
        width = max(len(left_numbers), len(right_numbers))
        padded_left = left_numbers + (0,) * (width - len(left_numbers))
        padded_right = right_numbers + (0,) * (width - len(right_numbers))
        if self.operator in {"==", "="}:
            return left_numbers == right_numbers and left_suffix == right_suffix
        if self.operator == "!=":
            return not (
                left_numbers == right_numbers and left_suffix == right_suffix
            )
        if padded_left == padded_right and left_suffix != right_suffix:
            # A prerelease sorts before the corresponding release.
            comparison = -1 if left_suffix else 1
        elif padded_left != padded_right:
            comparison = -1 if padded_left < padded_right else 1
        elif left_suffix == right_suffix:
            comparison = 0
        elif not left_suffix:
            comparison = 1
        elif not right_suffix:
            comparison = -1
        else:
            comparison = -1 if left_suffix < right_suffix else 1
        return {
            ">": comparison > 0,
            ">=": comparison >= 0,
            "<": comparison < 0,
            "<=": comparison <= 0,
        }.get(self.operator, False)


def _clause_tokens(expression: str) -> list[str]:
    normalized = re.sub(
        r"(~=|==|!=|>=|<=|>|<|=|\^|~)\s+", r"\1", expression.strip()
    )
    return [token for token in re.split(r"[,\s]+", normalized) if token]


def _build_alternative(  # noqa: C901
    expression: str,
) -> tuple[_Clause, ...] | None:
    text = expression.strip()
    if not text or text == "*":
        return None
    clauses: list[_Clause] = []
    for token in _clause_tokens(text):
        match = _CONSTRAINT_RE.match(token)
        if match is None:
            continue
        operator = match.group(1) or "=="
        version = match.group(2)
        bounds = _wildcard_bounds(version)
        if bounds is not None:
            lower, upper = bounds
            clauses.append(_Clause(">=", lower, _parse_version(lower)))
            clauses.append(_Clause("<", upper, _parse_version(upper)))
            continue
        parsed = _parse_version(version)
        if operator == "~=" and parsed is not None:
            numbers = parsed[0]
            position = len(numbers) - 2 if len(numbers) > 1 else 0
            upper = _increment_version(version, position)
            clauses.append(_Clause(">=", version, parsed))
            if upper is not None:
                clauses.append(_Clause("<", upper, _parse_version(upper)))
            continue
        if operator in {"^", "~"} and parsed is not None:
            numbers = parsed[0]
            position = 0
            for index, number in enumerate(numbers):
                if number != 0:
                    position = index
                    break
            if operator == "~":
                position = len(numbers) - 1
            upper = _increment_version(version, position)
            clauses.append(_Clause(">=", version, parsed))
            if upper is not None:
                clauses.append(_Clause("<", upper, _parse_version(upper)))
            continue
        clauses.append(_Clause(operator, version, parsed))
    return tuple(clauses)


class VersionConstraint:
    """A small version matcher used for interface declarations.

    Exact versions, comparison operators, comma/space conjunctions,
    ``||`` alternatives, wildcards, ``~=`` and caret ranges are supported.
    Non-version strings are compared literally.
    """

    def __init__(self, expression: str):
        self.expression = expression.strip()
        alternatives = []
        for alternative in self.expression.split("||"):
            alternatives.append(_build_alternative(alternative))
        self._alternatives = tuple(alternatives)
        parsed = _parse_version(self.expression)
        self.exact = (
            self.expression
            if parsed is not None
            and not re.search(r"[<>=!~^*xX]", self.expression)
            else None
        )

    @property
    def any(self) -> bool:
        """Return whether this constraint accepts every version."""
        return all(clauses is None for clauses in self._alternatives)

    def matches(self, version: str | None) -> bool:
        """Return whether ``version`` satisfies this constraint."""
        if version is None:
            return self.any
        version_key = _parse_version(version)
        for clauses in self._alternatives:
            if clauses is None:
                return True
            if version_key is None:
                if all(clause.matches_text(version) for clause in clauses):
                    return True
            elif all(clause.matches(version_key) for clause in clauses):
                return True
        return False

    def intersects(self, other: VersionConstraint) -> bool:
        """Return whether the two constraints have a common version."""
        if self.any or other.any:
            return True
        if self.exact is not None:
            return other.matches(self.exact)
        if other.exact is not None:
            return self.matches(other.exact)
        samples = self._samples() | other._samples()
        return any(
            self.matches(sample) and other.matches(sample) for sample in samples
        )

    def _samples(self) -> set[str]:
        samples: set[str] = set()
        for clauses in self._alternatives:
            if clauses is None:
                continue
            for clause in clauses:
                if clause.version_key is None:
                    samples.add(clause.version)
                    continue
                samples.add(clause.version)
                numbers = list(clause.version_key[0])
                for index, number in enumerate(numbers):
                    for delta in (-1, 0, 1):
                        if number + delta < 0:
                            continue
                        candidate = list(numbers)
                        candidate[index] = number + delta
                        samples.add(".".join(str(part) for part in candidate))
        return samples

    def __str__(self) -> str:
        return self.expression

    def __repr__(self) -> str:
        return f"VersionConstraint({self.expression!r})"


def _canonical_config(value: Any) -> str:  # noqa: ANN401
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return json.dumps(value, sort_keys=True)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def _interface_mapping(  # noqa: C901, PLR0912
    value: Any,  # noqa: ANN401
) -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    if isinstance(value, str):
        return {value: None}
    items: abc.Iterable[tuple[Any, Any]]
    if isinstance(value, abc.Mapping):
        items = value.items()
    elif isinstance(value, abc.Sequence):
        items = ()
    else:
        return versions
    for name, raw_version in items:
        if not isinstance(name, str):
            continue
        version_value = raw_version
        if isinstance(version_value, abc.Mapping):
            version_value = version_value.get(
                "version", version_value.get("constraint")
            )
        if version_value is None:
            versions[name] = None
        else:
            versions[name] = str(version_value)
    if isinstance(value, abc.Sequence) and not isinstance(value, str):
        for item in value:
            if isinstance(item, str):
                versions[item] = None
            elif isinstance(item, abc.Mapping):
                name = item.get("name", item.get("interface"))
                if not isinstance(name, str):
                    continue
                version = item.get("version", item.get("constraint"))
                versions[name] = None if version is None else str(version)
            elif isinstance(item, (tuple, list)) and len(item) == 2:
                versions[str(item[0])] = str(item[1])
    return versions


def _normalize_requirement(  # noqa: C901
    item: Any,  # noqa: ANN401
    source: str | None = None,
) -> DependencyRequirement | None:
    if isinstance(item, DependencyRequirement):
        return item
    if isinstance(item, str):
        return DependencyRequirement(module=item, source=source)
    if isinstance(item, (tuple, list)) and len(item) == 2:
        version = None if item[1] is None else str(item[1])
        return DependencyRequirement(
            module=str(item[0]), version=version, source=source
        )
    if not isinstance(item, abc.Mapping):
        return None
    module = None
    for key in ("module", "name", "target", "package", "component", "path"):
        value = item.get(key)
        if isinstance(value, str):
            module = value
            break
    interface = None
    for key in ("interface", "api", "capability"):
        value = item.get(key)
        if isinstance(value, str):
            interface = value
            break
    version = None
    for key in ("version", "constraint", "requirement", "range", "specifier"):
        value = item.get(key)
        if isinstance(value, str):
            version = value
            break
    if module is None and interface is None:
        return None
    reason = item.get("reason", "")
    return DependencyRequirement(
        module=module,
        interface=interface,
        version=version,
        source=source,
        reason=str(reason),
    )


def _requirement_list(  # noqa: C901
    value: Any,  # noqa: ANN401
    source: str | None = None,
) -> list[DependencyRequirement]:
    requirements: list[DependencyRequirement] = []
    if value is None:
        return requirements
    if isinstance(value, (str, DependencyRequirement)):
        requirement = _normalize_requirement(value, source)
        return [requirement] if requirement is not None else []
    if isinstance(value, abc.Mapping):
        direct = _normalize_requirement(value, source)
        if direct is not None:
            return [direct]
        for module, constraint in value.items():
            if not isinstance(module, str):
                continue
            if isinstance(constraint, abc.Mapping):
                spec = dict(constraint)
                spec.setdefault("module", module)
                requirement = _normalize_requirement(spec, source)
            else:
                version = None if constraint is None else str(constraint)
                requirement = DependencyRequirement(
                    module=module, version=version, source=source
                )
            if requirement is not None:
                requirements.append(requirement)
        return requirements
    if isinstance(value, abc.Iterable):
        for item in value:
            requirement = _normalize_requirement(item, source)
            if requirement is not None:
                requirements.append(requirement)
    return requirements


def _extract_declaration(  # noqa: C901, PLR0912
    target: TargetFile,
    module: str | None = None,
    version: str | None = None,
    provides: abc.Mapping[str, str | None] | None = None,
    requires: Any = None,  # noqa: ANN401
    config: str | None = None,
    identity: str | None = None,
) -> ModuleDeclaration:
    custom = target.custom
    source = dict(target.unrecognized_fields)
    if isinstance(custom, abc.Mapping):
        source.update(custom)

    if module is None:
        for key in ("module", "module_name", "name", "package", "component"):
            value = source.get(key) if isinstance(source, abc.Mapping) else None
            if isinstance(value, str) and value:
                module = value
                break
    if module is None:
        module = target.path
    if version is None and isinstance(source, abc.Mapping):
        value = source.get("version", source.get("module_version"))
        version = str(value) if value is not None else None
    if config is None and isinstance(source, abc.Mapping):
        value = source.get(
            "config", source.get("configuration", source.get("config_version"))
        )
        config = _canonical_config(value) if value is not None else None
    if identity is None and isinstance(source, abc.Mapping):
        value = source.get("identity", source.get("id"))
        identity = str(value) if value is not None else None

    provided_map: dict[str, str | None] = {}
    if isinstance(source, abc.Mapping):
        for key in (
            "provides",
            "interfaces",
            "api",
            "exports",
            "capabilities",
        ):
            provided_map.update(_interface_mapping(source.get(key)))
    if provides is not None:
        provided_map.update(provides)

    requirement_items: list[DependencyRequirement] = []
    if requires is not None:
        requirement_items.extend(_requirement_list(requires, module))
    if isinstance(source, abc.Mapping):
        for key in (
            "requires",
            "dependencies",
            "depends",
            "depends_on",
            "needs",
            "required",
        ):
            requirement_items.extend(_requirement_list(source.get(key), module))

    return ModuleDeclaration(
        module=module,
        version=version,
        provides=tuple(provided_map.items()),
        requires=tuple(requirement_items),
        config=config,
        identity=identity,
    )


def _parse_caller_declaration(  # noqa: C901, PLR0912
    declaration: Any,  # noqa: ANN401
) -> tuple[dict[str, str], str | None]:
    versions: dict[str, str] = {}
    config: str | None = None
    if declaration is None:
        return versions, config
    if isinstance(declaration, InterfaceDeclaration):
        return declaration.as_dict(), declaration.config
    if isinstance(declaration, abc.Mapping):
        for key in ("interfaces", "provides", "api", "versions"):
            nested = declaration.get(key)
            if isinstance(nested, abc.Mapping):
                versions.update(_interface_mapping(nested))
        for key in ("config", "configuration", "config_version"):
            if key in declaration:
                config = _canonical_config(declaration[key])
                break
        wrapper_keys = {
            key
            for key in ("interfaces", "provides", "api", "versions")
            if isinstance(declaration.get(key), abc.Mapping)
        }
        reserved = wrapper_keys | {
            "config",
            "configuration",
            "config_version",
        }
        for name, version in _interface_mapping(declaration).items():
            if name in reserved:
                continue
            versions[name] = version or "*"
        return versions, config
    if isinstance(declaration, abc.Iterable):
        for item in declaration:
            if isinstance(item, str):
                versions[item] = "*"
            elif isinstance(item, (tuple, list)) and len(item) == 2:
                versions[str(item[0])] = str(item[1])
            elif isinstance(item, DependencyRequirement) and item.interface:
                versions[item.interface] = item.version or "*"
        return versions, config
    for key in ("versions", "interfaces", "provides", "api"):
        value = getattr(declaration, key, None)
        if value is not None:
            versions.update(_interface_mapping(value))
    config_value = getattr(declaration, "config", None)
    if config_value is not None:
        config = _canonical_config(config_value)
    return versions, config


@dataclass
class _Record:
    module: str
    target: TargetFile
    channel: str | None
    declaration: ModuleDeclaration
    order: int

    @property
    def identity(self) -> TargetIdentity:
        return TargetIdentity.from_target(
            self.target, self.declaration.identity
        )


@dataclass
class _Failure:
    order: int
    conflict: CombinationConflict


@dataclass
class _View:
    records: list[_Record] = field(default_factory=list)
    by_path: dict[str, list[_Record]] = field(default_factory=dict)
    by_module: dict[str, list[_Record]] = field(default_factory=dict)
    by_alias: dict[str, list[_Record]] = field(default_factory=dict)

    def add(self, record: _Record) -> None:
        self.records.append(record)
        self.by_path.setdefault(record.target.path, []).append(record)
        self.by_module.setdefault(record.module, []).append(record)
        basename = record.target.path.rsplit("/", 1)[-1]
        aliases = {basename, basename.rsplit(".", 1)[0]}
        for alias in aliases:
            if alias and alias not in {record.target.path, record.module}:
                self.by_alias.setdefault(alias, []).append(record)

    def path_records(self, path: str) -> list[_Record]:
        return self.by_path.get(path, [])

    def module_records(self, module: str) -> list[_Record]:
        return self.by_module.get(module, [])

    def alias_records(self, alias: str) -> list[_Record]:
        return self.by_alias.get(alias, [])


def _iter_view_entries(  # noqa: C901, PLR0911, PLR0912
    view: Any,  # noqa: ANN401
) -> Iterator[tuple[str | None, str, TargetFile]]:
    if view is None:
        return
    if hasattr(view, "iter_targets"):
        yield from view.iter_targets()
        return
    trusted_set = getattr(view, "_trusted_set", None)
    if trusted_set is not None:
        yield from _iter_view_entries(trusted_set)
        return
    if isinstance(view, Targets):
        for path, target in view.targets.items():
            yield Targets.type, path, target
        return
    if isinstance(view, Metadata):
        if isinstance(view.signed, Targets):
            yield from _iter_view_entries(view.signed)
        return
    if isinstance(view, bytes):
        metadata = Metadata.from_bytes(view)
        if isinstance(metadata.signed, Targets):
            yield from _iter_view_entries(metadata.signed)
        return
    if isinstance(view, abc.Mapping):
        for role, value in view.items():
            if isinstance(value, TargetFile):
                yield str(role), value.path, value
            elif isinstance(value, Targets):
                for path, target in value.targets.items():
                    yield str(role), path, target
            elif isinstance(value, Metadata):
                if isinstance(value.signed, Targets):
                    for path, target in value.signed.targets.items():
                        yield str(role), path, target
            elif isinstance(value, bytes):
                metadata = Metadata.from_bytes(value)
                if isinstance(metadata.signed, Targets):
                    for path, target in metadata.signed.targets.items():
                        yield str(role), path, target
            elif isinstance(value, abc.Mapping):
                for path, target in value.items():
                    if isinstance(target, TargetFile):
                        yield str(role), str(path), target
            elif isinstance(value, abc.Iterable) and not isinstance(value, str):
                for item in value:
                    if isinstance(item, TargetFile):
                        yield str(role), item.path, item
            else:
                continue
        return
    if isinstance(view, abc.Iterable):
        for item in view:
            if isinstance(item, tuple) and len(item) == 3:
                role, path, target = item
                if isinstance(target, TargetFile):
                    yield str(role), str(path), target
            elif isinstance(item, TargetFile):
                yield None, item.path, item
            elif isinstance(item, (Targets, Metadata, bytes)):
                yield from _iter_view_entries(item)


def _build_view(view: Any) -> _View:  # noqa: ANN401
    result = _View()
    for order, (role, _path, target) in enumerate(_iter_view_entries(view)):
        declaration = _extract_declaration(target)
        result.add(
            _Record(
                module=declaration.module,
                target=target,
                channel=role,
                declaration=declaration,
                order=order,
            )
        )
    return result


def _target_from_value(  # noqa: C901, PLR0911
    value: Any,  # noqa: ANN401
    view: _View,
) -> tuple[TargetFile | None, str | None]:
    if isinstance(value, TargetFile):
        return value, None
    if isinstance(value, str):
        records = view.path_records(value)
        if not records:
            records = view.module_records(value)
        if not records:
            records = view.alias_records(value)
        if not records:
            return None, None
        return records[0].target, records[0].channel
    if isinstance(value, abc.Mapping):
        for key in ("target", "targetfile", "file"):
            candidate = value.get(key)
            if isinstance(candidate, TargetFile):
                return candidate, None
            if isinstance(candidate, str):
                return _target_from_value(candidate, view)
        for key in ("path", "target_path"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return _target_from_value(candidate, view)
    return None, None


def _candidate_records(  # noqa: C901, PLR0915
    candidates: Any,  # noqa: ANN401
    view: _View,
    strict_view: bool = False,
) -> tuple[list[_Record], list[_Failure]]:
    records: list[_Record] = []
    failures: list[_Failure] = []
    next_order = len(view.records) + 1

    def append_record(
        target: TargetFile,
        declaration: ModuleDeclaration,
        channel: str | None,
        order: int,
    ) -> None:
        identity = TargetIdentity.from_target(target, declaration.identity)
        path_records = view.path_records(target.path)
        if strict_view or view.records:
            if not path_records:
                failures.append(
                    _Failure(
                        order,
                        CombinationConflict(
                            kind="missing",
                            message=(
                                f"Candidate {target.path!r} is not in the "
                                "verified metadata view"
                            ),
                            group=(target.path,),
                            modules=(declaration.module,),
                            channels=(channel,) if channel else (),
                            reason="unverified-candidate",
                            order=order,
                        ),
                    )
                )
                return
            if identity not in {record.identity for record in path_records}:
                channels = tuple(
                    record.channel or "<unknown>" for record in path_records
                )
                failures.append(
                    _Failure(
                        order,
                        CombinationConflict(
                            kind="identity",
                            message=(
                                f"Candidate {target.path!r} does not match the "
                                "identity in the verified metadata view"
                            ),
                            group=(
                                f"candidate: {identity}",
                                *(
                                    f"view {record.channel or '<unknown>'}: "
                                    f"{record.identity}"
                                    for record in path_records
                                ),
                            ),
                            modules=(declaration.module,),
                            channels=channels,
                            identities=tuple(
                                str(record.identity) for record in path_records
                            ),
                            reason="candidate-view-mismatch",
                            order=order,
                        ),
                    )
                )
                return
        records.append(
            _Record(declaration.module, target, channel, declaration, order)
        )

    def add(  # noqa: C901, PLR0911, PLR0912, PLR0915
        value: Any,  # noqa: ANN401
        module: str | None = None,
        channel: str | None = None,
    ) -> None:
        nonlocal next_order
        order = next_order
        next_order += 1
        if isinstance(value, TargetCandidate):
            target, target_channel = _target_from_value(value.target, view)
            module = value.module or module
            channel = value.channel or channel or target_channel
            provides = (
                dict(value.provides) if value.provides is not None else None
            )
            if target is None:
                failures.append(
                    _Failure(
                        order,
                        CombinationConflict(
                            kind="missing",
                            message=(
                                f"Candidate {value.target!r} is not present in "
                                "the verified metadata view"
                            ),
                            group=(str(value.target),),
                            modules=(module,) if module else (),
                            channels=(channel,) if channel else (),
                            reason="missing-candidate",
                            order=order,
                        ),
                    )
                )
                return
            declaration = _extract_declaration(
                target,
                module,
                value.version,
                provides,
                value.requires,
                value.config,
                value.identity,
            )
            append_record(target, declaration, channel, order)
            return
        if isinstance(value, str):
            view_records = view.path_records(value)
            if not view_records:
                view_records = view.module_records(value)
            if not view_records:
                view_records = view.alias_records(value)
            if view_records:
                for index, view_record in enumerate(view_records):
                    record_order = order + index
                    declaration = (
                        _extract_declaration(view_record.target, module)
                        if module is not None
                        else view_record.declaration
                    )
                    records.append(
                        _Record(
                            declaration.module,
                            view_record.target,
                            channel or view_record.channel,
                            declaration,
                            record_order,
                        )
                    )
                next_order += len(view_records) - 1
                return
        if isinstance(value, abc.Mapping):
            if any(
                key in value for key in ("target", "targetfile", "file", "path")
            ):
                target, target_channel = _target_from_value(value, view)
                if target is None:
                    failures.append(
                        _Failure(
                            order,
                            CombinationConflict(
                                kind="missing",
                                message=(
                                    f"Candidate {value!r} is not present "
                                    "in the verified metadata view"
                                ),
                                group=(str(value),),
                                modules=(module,) if module else (),
                                reason="missing-candidate",
                                order=order,
                            ),
                        )
                    )
                    return
                declaration = _extract_declaration(
                    target,
                    module or value.get("module"),
                    value.get("version"),
                    _interface_mapping(value.get("provides")) or None,
                    value.get("requires"),
                    value.get("config"),
                    value.get("identity"),
                )
                append_record(
                    target,
                    declaration,
                    channel or value.get("channel") or target_channel,
                    order,
                )
                return
            for key, item in value.items():
                if isinstance(item, abc.Sequence) and not isinstance(item, str):
                    for child in item:
                        add(child, module=None, channel=str(key))
                    continue
                module_key: str | None = str(key)
                channel_key = channel
                target_for_key, _target_channel = _target_from_value(item, view)
                if isinstance(item, TargetCandidate):
                    target_for_key, _target_channel = _target_from_value(
                        item.target, view
                    )
                if target_for_key is not None:
                    item_declaration = _extract_declaration(target_for_key)
                    if str(key) not in {
                        target_for_key.path,
                        item_declaration.module,
                    }:
                        module_key = None
                        channel_key = channel or str(key)
                add(item, module=module_key, channel=channel_key)
            return
        if isinstance(value, abc.Sequence) and not isinstance(value, str):
            if (
                len(value) == 2
                and isinstance(value[0], str)
                and isinstance(value[1], TargetFile)
            ):
                add(value[1], module=value[0], channel=channel)
                return
            for item in value:
                add(item, module=module, channel=channel)
            return
        target, target_channel = _target_from_value(value, view)
        if target is None:
            failures.append(
                _Failure(
                    order,
                    CombinationConflict(
                        kind="missing",
                        message=(
                            f"Candidate {value!r} is not present in "
                            "the verified metadata view"
                        ),
                        group=(str(value),),
                        modules=(module,) if module else (),
                        reason="missing-candidate",
                        order=order,
                    ),
                )
            )
            return
        declaration = _extract_declaration(target, module)
        append_record(
            target,
            declaration,
            channel or target_channel,
            order,
        )

    if candidates is None:
        return records, failures
    if isinstance(
        candidates,
        (str, TargetFile, TargetCandidate, abc.Mapping, abc.Sequence),
    ):
        add(candidates)
    else:
        add(list(candidates))
    return records, failures


def _identity_conflict(
    module: str,
    records: list[_Record],
    order: int,
) -> CombinationConflict | None:
    identities = {record.identity for record in records}
    if len(identities) <= 1:
        return None
    ordered = tuple(str(identity) for identity in sorted(identities))
    channels = tuple(
        record.channel or "<unknown>" for record in records if record.channel
    )
    group = tuple(
        f"{module} from {record.channel or '<unknown>'}: {record.identity}"
        for record in records
    )
    return CombinationConflict(
        kind="identity",
        message=(
            f"Module {module!r} has different identities in the candidate "
            "set/channels"
        ),
        group=group,
        modules=(module,),
        channels=channels,
        identities=ordered,
        reason="identity-mismatch",
        order=order,
    )


def _unique_records(records: list[_Record]) -> list[_Record]:
    seen: set[tuple[str, TargetIdentity]] = set()
    result = []
    for record in records:
        key = (record.module, record.identity)
        if key in seen:
            continue
        seen.add(key)
        result.append(record)
    return result


@dataclass
class _Resolution:
    records: dict[str, _Record]
    edges: list[Dependency]
    failures: list[_Failure]
    selected_order: dict[str, int]


def _resolve_dependency(  # noqa: C901, PLR0911
    requirement: DependencyRequirement,
    selected: dict[str, _Record],
    module_records: dict[str, list[_Record]],
    view: _View,
    order: int,
) -> tuple[_Record | None, _Failure | None]:
    if requirement.module is not None:
        module = requirement.module
        if module in selected:
            return selected[module], None
        candidates = module_records.get(module, [])
        if not candidates:
            candidates = view.module_records(module)
        if not candidates:
            candidates = view.path_records(module)
        if not candidates:
            candidates = view.alias_records(module)
        if not candidates:
            return None, _Failure(
                order,
                CombinationConflict(
                    kind="missing",
                    message=f"Dependency module {module!r} was not found",
                    group=(f"missing module {module}",),
                    modules=(module,),
                    requirements=(requirement,),
                    reason="missing-dependency",
                    order=order,
                ),
            )
        unique = _unique_records(candidates)
        if len({record.identity for record in unique}) > 1:
            return None, _Failure(
                order,
                _identity_conflict(module, unique, order)
                or CombinationConflict(
                    kind="identity",
                    message=f"Module {module!r} has multiple identities",
                    group=(),
                    modules=(module,),
                    order=order,
                ),
            )
        return unique[0], None

    if requirement.interface is not None:
        providers = [
            record
            for record in selected.values()
            if record.declaration.provides_interface(requirement.interface)
        ]
        if not providers:
            providers = [
                record
                for record in view.records
                if record.declaration.provides_interface(requirement.interface)
            ]
        unique = _unique_records(providers)
        if not unique:
            return None, _Failure(
                order,
                CombinationConflict(
                    kind="missing",
                    message=(
                        f"No module provides interface "
                        f"{requirement.interface!r}"
                    ),
                    group=(f"missing interface {requirement.interface}",),
                    requirements=(requirement,),
                    reason="missing-interface",
                    order=order,
                ),
            )
        if len(unique) > 1:
            return None, _Failure(
                order,
                CombinationConflict(
                    kind="ambiguous",
                    message=(
                        f"Interface {requirement.interface!r} has multiple "
                        "possible providers"
                    ),
                    group=tuple(
                        f"{record.module}: {record.identity}"
                        for record in unique
                    ),
                    modules=tuple(record.module for record in unique),
                    requirements=(requirement,),
                    reason="ambiguous-interface",
                    order=order,
                ),
            )
        return unique[0], None

    return None, _Failure(
        order,
        CombinationConflict(
            kind="unsatisfiable",
            message=(
                "A dependency requirement names neither module nor interface"
            ),
            group=("empty dependency requirement",),
            requirements=(requirement,),
            reason="empty-requirement",
            order=order,
        ),
    )


def _resolve_closure(  # noqa: C901, PLR0912, PLR0915
    candidates: list[_Record],
    view: _View,
    max_depth: int,
    caller_versions: dict[str, str],
) -> _Resolution:
    failures: list[_Failure] = []
    selected: dict[str, _Record] = {}
    selected_order: dict[str, int] = {}
    module_records: dict[str, list[_Record]] = {}

    for record in candidates:
        module_records.setdefault(record.module, []).append(record)
    for module, records in module_records.items():
        conflict = _identity_conflict(
            module, _unique_records(records), records[0].order
        )
        if conflict is not None:
            failures.append(_Failure(records[0].order, conflict))
            continue
        selected[module] = records[0]
        selected_order[module] = records[0].order

    queue = list(selected)
    edges: list[Dependency] = []
    edge_order = max((record.order for record in candidates), default=0) + 1
    expanded: set[str] = set()

    while queue:
        module = queue.pop(0)
        if module in expanded:
            continue
        expanded.add(module)
        record = selected[module]
        for requirement in record.declaration.requires:
            order = edge_order
            edge_order += 1
            if (
                requirement.module is None
                and requirement.interface in caller_versions
            ):
                provided = caller_versions[requirement.interface]
                satisfied = True
                if requirement.version is not None:
                    satisfied = VersionConstraint(
                        requirement.version
                    ).intersects(VersionConstraint(provided))
                edges.append(
                    Dependency(
                        module=module,
                        dependency="<caller>",
                        interface=requirement.interface,
                        constraint=requirement.version,
                        channel=record.channel,
                        provided_version=provided,
                        satisfied=satisfied,
                        source=requirement.source,
                        reason=requirement.reason,
                        order=order,
                    )
                )
                if not satisfied:
                    group = (
                        f"{module} requires {requirement.interface} "
                        f"{requirement.version}",
                        f"caller declares {requirement.interface} {provided}",
                    )
                    failures.append(
                        _Failure(
                            order,
                            CombinationConflict(
                                kind="unsatisfiable",
                                message=(
                                    f"Caller interface "
                                    f"{requirement.interface!r} cannot satisfy "
                                    f"{module!r}"
                                ),
                                group=group,
                                modules=(module,),
                                requirements=(requirement,),
                                reason="caller-interface-version",
                                order=order,
                            ),
                        )
                    )
                continue
            dependency, failure = _resolve_dependency(
                requirement, selected, module_records, view, order
            )
            if failure is not None:
                failures.append(failure)
                continue
            if dependency is None:
                continue
            existing = selected.get(dependency.module)
            if (
                existing is not None
                and existing.identity != dependency.identity
            ):
                conflict = _identity_conflict(
                    dependency.module, [existing, dependency], order
                )
                if conflict is not None:
                    failures.append(_Failure(order, conflict))
                continue
            provided_version = None
            if requirement.interface is not None:
                provided_version = dependency.declaration.provided_version(
                    requirement.interface
                )
            satisfied = None
            if requirement.version is not None:
                actual = (
                    provided_version
                    if requirement.interface is not None
                    else dependency.declaration.version
                )
                if actual is not None:
                    satisfied = VersionConstraint(requirement.version).matches(
                        actual
                    )
            if dependency.module not in selected:
                if len(selected) >= max_depth:
                    failures.append(
                        _Failure(
                            order,
                            CombinationConflict(
                                kind="unsatisfiable",
                                message=(
                                    f"Dependency closure exceeds max_depth="
                                    f"{max_depth}"
                                ),
                                group=(f"{module} -> {dependency.module}",),
                                modules=(module, dependency.module),
                                requirements=(requirement,),
                                reason="max-depth",
                                order=order,
                            ),
                        )
                    )
                    continue
                selected[dependency.module] = dependency
                selected_order[dependency.module] = order
                queue.append(dependency.module)
            edges.append(
                Dependency(
                    module=module,
                    dependency=dependency.module,
                    interface=requirement.interface,
                    constraint=requirement.version,
                    channel=record.channel,
                    dependency_channel=dependency.channel,
                    target=dependency.target.path,
                    provided_version=provided_version,
                    satisfied=satisfied,
                    source=requirement.source,
                    reason=requirement.reason,
                    order=order,
                )
            )
        # Required modules may have been added by this record; the loop above
        # also catches them through the queue.

    _check_cycles(selected, edges, failures)
    return _Resolution(selected, edges, failures, selected_order)


def _check_cycles(
    selected: dict[str, _Record],
    edges: list[Dependency],
    failures: list[_Failure],
) -> None:
    adjacency: dict[str, list[Dependency]] = {}
    for edge in edges:
        adjacency.setdefault(edge.module, []).append(edge)
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(module: str) -> None:
        state[module] = 1
        stack.append(module)
        for edge in adjacency.get(module, []):
            dependency = edge.dependency
            if dependency not in selected:
                continue
            if state.get(dependency) == 1:
                start = stack.index(dependency)
                cycle = (*stack[start:], dependency)
                failures.append(
                    _Failure(
                        edge.order,
                        CombinationConflict(
                            kind="cycle",
                            message=("Dependency cycle: " + " -> ".join(cycle)),
                            group=tuple(
                                f"{left} -> {right}"
                                for left, right in pairwise(cycle)
                            ),
                            modules=cycle,
                            cycle=cycle,
                            reason="mutual-dependency",
                            order=edge.order,
                        ),
                    )
                )
            elif state.get(dependency, 0) == 0:
                visit(dependency)
        stack.pop()
        state[module] = 2

    for module in selected:
        if state.get(module, 0) == 0:
            visit(module)


@dataclass(frozen=True)
class _ConstraintEntry:
    order: int
    module: str
    interface: str | None
    constraint: VersionConstraint | None
    actual_version: str | None
    source: str

    def description(self) -> str:
        if self.interface is None:
            target = self.module
        else:
            target = f"{self.module}::{self.interface}"
        if self.constraint is None:
            return f"{self.source} requires {target}"
        if self.actual_version is None:
            return f"{self.source} requires {target} {self.constraint}"
        return (
            f"{self.source} requires {target} {self.constraint} "
            f"(provided {self.actual_version})"
        )


def _check_requirements(  # noqa: C901, PLR0912
    resolution: _Resolution,
    caller_versions: dict[str, str],
    caller_config: str | None,
) -> list[_Failure]:
    failures: list[_Failure] = []
    entries: dict[tuple[str, str | None], list[_ConstraintEntry]] = {}

    for edge in resolution.edges:
        if edge.dependency == "<caller>":
            continue
        record = resolution.records[edge.dependency]
        interface = edge.interface
        if interface is not None:
            actual = record.declaration.provided_version(interface)
            key = (edge.dependency, interface)
        else:
            actual = record.declaration.version
            key = (edge.dependency, None)
        constraint = (
            VersionConstraint(edge.constraint)
            if edge.constraint is not None
            else None
        )
        entries.setdefault(key, []).append(
            _ConstraintEntry(
                order=resolution.selected_order.get(
                    edge.dependency, len(resolution.records)
                ),
                module=edge.dependency,
                interface=interface,
                constraint=constraint,
                actual_version=actual,
                source=edge.module,
            )
        )

    for interface, expression in caller_versions.items():
        providers = [
            record
            for record in resolution.records.values()
            if record.declaration.provides_interface(interface)
        ]
        for record in providers:
            actual = record.declaration.provided_version(interface)
            entries.setdefault((record.module, interface), []).append(
                _ConstraintEntry(
                    order=resolution.selected_order.get(
                        record.module, len(resolution.records)
                    ),
                    module=record.module,
                    interface=interface,
                    constraint=VersionConstraint(expression),
                    actual_version=actual,
                    source="caller",
                )
            )

    for (module, interface), group in entries.items():
        failing = False
        for entry in group:
            if entry.constraint is None:
                continue
            if entry.actual_version is None:
                failing = entry.interface is not None
                break
            if not entry.constraint.matches(entry.actual_version):
                failing = True
                break
        if not failing:
            continue
        order = min(entry.order for entry in group)
        name = f"{module}::{interface}" if interface else module
        group_text = tuple(entry.description() for entry in group)
        requirements = tuple(
            DependencyRequirement(
                module=module,
                interface=interface,
                version=(
                    entry.constraint.expression
                    if entry.constraint is not None
                    else None
                ),
                source=entry.source,
            )
            for entry in group
        )
        failures.append(
            _Failure(
                order,
                CombinationConflict(
                    kind="unsatisfiable",
                    message=(
                        f"Constraint group for {name!r} cannot be satisfied "
                        "by one target"
                    ),
                    group=group_text,
                    modules=(module,),
                    identities=(),
                    requirements=requirements,
                    reason=(
                        "missing-interface"
                        if interface is not None
                        and any(entry.actual_version is None for entry in group)
                        else "interface-version"
                    ),
                    order=order,
                ),
            )
        )

    config_entries: list[tuple[str, str]] = [
        (module, record.declaration.config)
        for module, record in resolution.records.items()
        if record.declaration.config is not None
    ]
    if caller_config is not None:
        config_entries.append(("<caller>", caller_config))
    if config_entries:
        first_config = VersionConstraint(config_entries[0][1])
        compatible = all(
            first_config.intersects(VersionConstraint(config))
            for _module, config in config_entries[1:]
        )
        if not compatible:
            order = min(
                (
                    resolution.selected_order.get(module, 0)
                    for module, _config in config_entries
                    if module != "<caller>"
                ),
                default=0,
            )
            group = tuple(
                f"{module} reads config {config}"
                for module, config in config_entries
            )
            failures.append(
                _Failure(
                    order,
                    CombinationConflict(
                        kind="unsatisfiable",
                        message=(
                            "Selected targets do not all read the same "
                            "configuration"
                        ),
                        group=group,
                        modules=tuple(
                            module
                            for module, _config in config_entries
                            if module != "<caller>"
                        ),
                        reason="config-mismatch",
                        order=order,
                    ),
                )
            )
    return failures


def _find_best_failure(failures: list[_Failure]) -> CombinationConflict | None:
    if not failures:
        return None
    return min(failures, key=lambda failure: failure.order).conflict


def _empty_plan(
    conflict: CombinationConflict,
    edges: list[Dependency],
    selected: dict[str, _Record],
    caller_versions: dict[str, str],
    caller_config: str | None,
) -> CombinationPlan:
    attempted = {module: record.target for module, record in selected.items()}
    return CombinationPlan(
        targets={},
        dependencies=tuple(edges),
        conflict=conflict,
        caller_interfaces=tuple(caller_versions.items()),
        caller_config=caller_config,
        attempted_targets=attempted,
    )


def _first_value(*values: Any) -> Any:  # noqa: ANN401
    for value in values:
        if value is not None:
            return value
    return None


class CombinationPreflight:
    """Reusable offline combination preflight.

    Args:
        metadata: Verified metadata view. A ``TrustedMetadataSet`` (or an
            object holding one), a mapping of role names to ``Targets``, a
            ``Targets`` object, or an iterable of targets is accepted.
        candidates: Candidate targets. Target paths, ``TargetFile`` objects,
            ``TargetCandidate`` wrappers, mappings, or channel-to-targets
            mappings are accepted.
        interfaces: Caller interface-version declaration.
        allow_cycles: If true, dependency cycles are kept in the closure
            instead of being reported as a conflict.
        max_depth: Maximum number of modules in the closure.
    """

    def __init__(
        self,
        metadata: Any = None,  # noqa: ANN401
        candidates: Any = None,  # noqa: ANN401
        interfaces: Any = None,  # noqa: ANN401
        *,
        allow_cycles: bool = False,
        max_depth: int = 256,
        config_version: Any = None,  # noqa: ANN401
        config: Any = None,  # noqa: ANN401
        caller_config: Any = None,  # noqa: ANN401
        verified_metadata: Any = None,  # noqa: ANN401
        metadata_view: Any = None,  # noqa: ANN401
        trusted_set: Any = None,  # noqa: ANN401
        view: Any = None,  # noqa: ANN401
        candidate_targets: Any = None,  # noqa: ANN401
        targets: Any = None,  # noqa: ANN401
        candidate: Any = None,  # noqa: ANN401
        caller_interfaces: Any = None,  # noqa: ANN401
        caller: Any = None,  # noqa: ANN401
        interface_versions: Any = None,  # noqa: ANN401
        interface_declaration: Any = None,  # noqa: ANN401
        **kwargs: Any,  # noqa: ANN401
    ):
        if kwargs:
            unknown = ", ".join(sorted(kwargs))
            raise TypeError(f"Unexpected keyword argument(s): {unknown}")
        self.metadata = _first_value(
            metadata,
            verified_metadata,
            metadata_view,
            trusted_set,
            view,
        )
        self.candidates = _first_value(
            candidates, candidate_targets, targets, candidate
        )
        self.interfaces = _first_value(
            interfaces,
            caller_interfaces,
            interface_versions,
            interface_declaration,
            caller,
        )
        self.allow_cycles = allow_cycles
        self.max_depth = max_depth
        self.config_version = _first_value(
            config_version, config, caller_config
        )

    def resolve(
        self,
        candidates: Any = _UNSET,  # noqa: ANN401
        interfaces: Any = _UNSET,  # noqa: ANN401
        *,
        config_version: Any = _UNSET,  # noqa: ANN401
        config: Any = _UNSET,  # noqa: ANN401
        caller_config: Any = _UNSET,  # noqa: ANN401
        allow_cycles: bool | None = None,
        max_depth: int | None = None,
        raise_on_conflict: bool = False,
    ) -> CombinationPlan:
        """Resolve the closure and return a plan or the first conflict."""
        selected_candidates = (
            self.candidates if candidates is _UNSET else candidates
        )
        selected_interfaces = (
            self.interfaces if interfaces is _UNSET else interfaces
        )
        selected_config = _first_value(
            None if config_version is _UNSET else config_version,
            None if config is _UNSET else config,
            None if caller_config is _UNSET else caller_config,
            self.config_version,
        )
        cycles = self.allow_cycles if allow_cycles is None else allow_cycles
        depth = self.max_depth if max_depth is None else max_depth
        if depth <= 0:
            raise ValueError("max_depth must be positive")

        view = _build_view(self.metadata)
        candidate_records, candidate_failures = _candidate_records(
            selected_candidates, view, strict_view=self.metadata is not None
        )
        caller_versions, caller_config = _parse_caller_declaration(
            selected_interfaces
        )
        if selected_config is not None:
            caller_config = _canonical_config(selected_config)

        resolution = _resolve_closure(
            candidate_records, view, depth, caller_versions
        )
        failures = [*candidate_failures, *resolution.failures]
        failures.extend(
            _check_requirements(resolution, caller_versions, caller_config)
        )
        if cycles:
            failures = [
                failure
                for failure in failures
                if failure.conflict.kind != "cycle"
            ]
        conflict = _find_best_failure(failures)
        if conflict is not None:
            plan = _empty_plan(
                conflict,
                resolution.edges,
                resolution.records,
                caller_versions,
                caller_config,
            )
        else:
            plan = CombinationPlan(
                targets={
                    module: record.target
                    for module, record in resolution.records.items()
                },
                dependencies=tuple(resolution.edges),
                caller_interfaces=tuple(caller_versions.items()),
                caller_config=caller_config,
                attempted_targets={
                    module: record.target
                    for module, record in resolution.records.items()
                },
            )
        if raise_on_conflict:
            plan.raise_for_conflict()
        return plan

    def preflight(self, *args: Any, **kwargs: Any) -> CombinationPlan:  # noqa: ANN401
        """Alias for :meth:`resolve`."""
        return self.resolve(*args, **kwargs)

    def check(self, *args: Any, **kwargs: Any) -> CombinationPlan:  # noqa: ANN401
        """Alias for :meth:`resolve`."""
        return self.resolve(*args, **kwargs)

    def plan(self, *args: Any, **kwargs: Any) -> CombinationPlan:  # noqa: ANN401
        """Alias for :meth:`resolve`."""
        return self.resolve(*args, **kwargs)

    __call__ = resolve


def preflight_combination(  # noqa: D417
    metadata: Any = None,  # noqa: ANN401
    candidates: Any = None,  # noqa: ANN401
    interfaces: Any = None,  # noqa: ANN401
    *,
    verified_metadata: Any = None,  # noqa: ANN401
    metadata_view: Any = None,  # noqa: ANN401
    trusted_set: Any = None,  # noqa: ANN401
    view: Any = None,  # noqa: ANN401
    candidate_targets: Any = None,  # noqa: ANN401
    targets: Any = None,  # noqa: ANN401
    caller_interfaces: Any = None,  # noqa: ANN401
    interface_versions: Any = None,  # noqa: ANN401
    interface_declaration: Any = None,  # noqa: ANN401
    config_version: Any = None,  # noqa: ANN401
    config: Any = None,  # noqa: ANN401
    caller_config: Any = None,  # noqa: ANN401
    allow_cycles: bool = False,
    max_depth: int = 256,
    raise_on_conflict: bool = False,
    **kwargs: Any,  # noqa: ANN401
) -> CombinationPlan:
    """Compute the offline adoptable closure for candidate targets.

    This is the functional entry point of the module. The first three
    positional arguments are the canonical form; common keyword aliases are
    accepted for integration convenience.

    Args:
        metadata: Already verified metadata view.
        candidates: Candidate targets.
        interfaces: Caller's interface-version declaration.
        config_version: Optional caller configuration generation.
        allow_cycles: Keep cycles in the closure instead of reporting them.
        max_depth: Maximum module count in the closure.
        raise_on_conflict: Raise ``CombinationConflictError`` on failure.

    Returns:
        A ``CombinationPlan`` with either adoptable targets and dependency
        evidence, or the first conflict.
    """
    view_value = _first_value(
        metadata,
        verified_metadata,
        metadata_view,
        trusted_set,
        view,
    )
    candidate_value = _first_value(
        candidates, candidate_targets, targets, kwargs.pop("candidate", None)
    )
    interface_value = _first_value(
        interfaces,
        caller_interfaces,
        interface_versions,
        interface_declaration,
        kwargs.pop("declarations", None),
    )
    if kwargs:
        unknown = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unknown}")
    preflight = CombinationPreflight(
        view_value,
        candidate_value,
        interface_value,
        allow_cycles=allow_cycles,
        max_depth=max_depth,
        config_version=_first_value(config_version, config, caller_config),
    )
    return preflight.resolve(raise_on_conflict=raise_on_conflict)


def resolve_combination(*args: Any, **kwargs: Any) -> CombinationPlan:  # noqa: ANN401
    """Alias for :func:`preflight_combination`."""
    return preflight_combination(*args, **kwargs)


def resolve_target_closure(
    *args: Any,  # noqa: ANN401
    **kwargs: Any,  # noqa: ANN401
) -> CombinationPlan:
    """Alias for :func:`preflight_combination`."""
    return preflight_combination(*args, **kwargs)


def check_combination(*args: Any, **kwargs: Any) -> CombinationPlan:  # noqa: ANN401
    """Alias for :func:`preflight_combination`."""
    return preflight_combination(*args, **kwargs)


def check_target_combination(
    *args: Any,  # noqa: ANN401
    **kwargs: Any,  # noqa: ANN401
) -> CombinationPlan:
    """Alias for :func:`preflight_combination`."""
    return preflight_combination(*args, **kwargs)


def plan_target_combination(
    *args: Any,  # noqa: ANN401
    **kwargs: Any,  # noqa: ANN401
) -> CombinationPlan:
    """Alias for :func:`preflight_combination`."""
    return preflight_combination(*args, **kwargs)


def preflight_targets(*args: Any, **kwargs: Any) -> CombinationPlan:  # noqa: ANN401
    """Alias for :func:`preflight_combination`."""
    return preflight_combination(*args, **kwargs)


def resolve_target_combination(
    *args: Any,  # noqa: ANN401
    **kwargs: Any,  # noqa: ANN401
) -> CombinationPlan:
    """Alias for :func:`preflight_combination`."""
    return preflight_combination(*args, **kwargs)


preflight_target_combination = preflight_combination
combination_preflight = preflight_combination
