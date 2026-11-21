"""
Offline target environments for lockfile auditing.

Lockfiles describe more than one installation target at a time.  Auditing the
flattened package list as if it were a single environment loses the marker and
artifact evidence that tells us which packages actually belong to each target.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from pathlib import Path
from types import MappingProxyType
from typing import Any

import tomli
from packaging.markers import InvalidMarker, Marker, UndefinedEnvironmentName, Variable
from packaging.tags import Tag, compatible_tags, cpython_tags, generic_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename


class TargetEnvironmentError(ValueError):
    """Raised when a target environment or its matrix is invalid."""

    pass


class EvidenceStatus(str, Enum):
    """
    The audit evidence available for a package in one target environment.
    """

    CHECKED = "checked"
    """The lock entry applies, a compatible distribution was locked, and it was queried."""

    EXCLUDED = "excluded"
    """A marker, ``requires-python``, or artifact selection says this entry does not apply."""

    MISSING_MARKER_VARIABLE = "missing-marker-variable"
    """A marker could not be evaluated because the target environment lacks a variable."""

    MISSING_ARTIFACT = "missing-artifact"
    """The entry applies, but no wheel or sdist in the lock can be installed here."""

    INVALID_ARTIFACT = "invalid-artifact"
    """The lock contains an artifact whose filename cannot be interpreted."""

    INVALID_MARKER = "invalid-marker"
    """The lock contains a marker expression that cannot be evaluated."""

    INVALID_REQUIRES_PYTHON = "invalid-requires-python"
    """The lock contains an invalid ``requires-python`` constraint."""

    MISSING_VERSION = "missing-version"
    """The lock entry has no version and therefore cannot be audited."""

    ADVISORY_SKIPPED = "advisory-skipped"
    """The advisory service did not provide a result for the distribution."""

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class LockedDependency:
    """
    One package entry from a lockfile, interpreted for one target environment.
    """

    name: str
    version: str | None
    status: EvidenceStatus
    artifact: str | None = None
    reason: str | None = None
    missing: tuple[str, ...] = ()

    @property
    def is_checked(self) -> bool:
        """Whether this entry has complete evidence and should be queried."""
        return self.status is EvidenceStatus.CHECKED

    @property
    def identity(self) -> tuple[str, str] | None:
        """The distribution identity used for advisory queries."""
        if self.version is None:
            return None
        return self.name, self.version


@dataclass(frozen=True)
class MarkerEvaluation:
    """The result of evaluating one marker against one target environment."""

    applies: bool
    missing: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def complete(self) -> bool:
        """Whether the marker could be evaluated without missing evidence."""
        return not self.missing and self.reason is None


def marker_variables(marker: Marker) -> set[str]:
    """
    Return every marker variable referenced by ``marker``.

    ``packaging`` fills unspecified variables from the host environment when
    evaluating a marker.  That behavior is wrong for an offline target matrix:
    a Windows target must not silently inherit the host's ``sys_platform``.
    Extracting the referenced names lets us reject those incomplete targets
    before evaluation.
    """

    names: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, Variable):
            names.add(node.value)
        elif isinstance(node, (list, tuple)):
            for item in node:
                visit(item)

    visit(marker._markers)
    return names


def evaluate_marker(marker_text: str, environment: TargetEnvironment) -> MarkerEvaluation:
    """
    Evaluate a marker string without consulting the host environment.
    """

    try:
        marker = Marker(marker_text)
    except InvalidMarker:
        return MarkerEvaluation(False, reason=f"invalid marker: {marker_text!r}")

    missing = tuple(sorted(marker_variables(marker) - environment.markers.keys()))
    if missing:
        return MarkerEvaluation(False, missing=missing)

    try:
        return MarkerEvaluation(bool(marker.evaluate(dict(environment.markers))))
    except UndefinedEnvironmentName as exc:
        return MarkerEvaluation(False, missing=(str(exc),))
    except Exception as exc:  # pragma: no cover - defensive against packaging changes
        return MarkerEvaluation(False, reason=str(exc))


def _python_version(markers: Mapping[str, str]) -> tuple[int, int] | None:
    raw = markers.get("python_version") or markers.get("python_full_version")
    if raw is None:
        return None

    parts = raw.split(".")
    if len(parts) < 2:
        return None
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return None


def _default_platform_tags(markers: Mapping[str, str]) -> tuple[str, ...]:
    sys_platform = markers.get("sys_platform")
    machine = markers.get("platform_machine", "")

    if sys_platform == "win32":
        if machine.lower() in {"amd64", "x86_64"}:
            return ("win_amd64",)
        if machine.lower() in {"arm64", "aarch64"}:
            return ("win_arm64",)
        return ("win32",)

    if sys_platform == "darwin":
        arch = "arm64" if machine.lower() in {"arm64", "aarch64"} else "x86_64"
        return (f"macosx_11_0_{arch}",)

    if sys_platform == "linux":
        if machine.lower() in {"x86_64", "amd64"}:
            return (
                "manylinux_2_17_x86_64",
                "manylinux2014_x86_64",
                "manylinux_2_5_x86_64",
                "manylinux1_x86_64",
                "linux_x86_64",
            )
        if machine in {"aarch64", "arm64"}:
            return (
                "manylinux_2_17_aarch64",
                "manylinux2014_aarch64",
                "linux_aarch64",
            )
        return (f"linux_{machine}",) if machine else ()

    return ()


@dataclass(frozen=True)
class TargetEnvironment:
    """
    One fully specified, offline installation target.

    ``markers`` contains PEP 508 marker variables.  It should be complete for
    every marker used by the lockfile; omitted variables are reported as
    missing evidence rather than inherited from the machine running the audit.

    ``platform_tags`` contains wheel platform tags such as ``manylinux_2_17_x86_64``
    or ``win_amd64``.  If omitted, a conservative set is derived from
    ``sys_platform`` and ``platform_machine``.
    """

    name: str
    markers: Mapping[str, str] = field(default_factory=dict)
    platform_tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name:
            raise TargetEnvironmentError("target environment name must not be empty")

        normalized = {str(key): str(value) for key, value in self.markers.items()}
        object.__setattr__(self, "markers", MappingProxyType(normalized))
        object.__setattr__(self, "platform_tags", tuple(self.platform_tags))

    @property
    def marker_environment(self) -> Mapping[str, str]:
        """Alias for ``markers``."""
        return self.markers

    @classmethod
    def from_markers(
        cls,
        name: str,
        markers: Mapping[str, str],
        platform_tags: Sequence[str] = (),
    ) -> TargetEnvironment:
        """Construct a target from a marker environment and platform tags."""
        return cls(name=name, markers=markers, platform_tags=tuple(platform_tags))

    @property
    def python_version(self) -> tuple[int, int] | None:
        """The target Python version as ``(major, minor)``, if specified."""
        return _python_version(self.markers)

    @cached_property
    def supported_tags(self) -> frozenset[Tag]:
        """
        Return the wheel tags installable in this target.

        Raises ``TargetEnvironmentError`` if enough information is not present
        to derive tags.
        """

        python_version = self.python_version
        if python_version is None:
            raise TargetEnvironmentError(f"target environment {self.name!r} has no python_version")

        platforms = self.platform_tags or _default_platform_tags(self.markers)
        if not platforms:
            raise TargetEnvironmentError(f"target environment {self.name!r} has no platform tags")

        implementation = self.markers.get("implementation_name", "cpython").lower()
        major, minor = python_version
        tags: set[Tag] = set()

        if implementation == "cpython":
            abi = f"cp{major}{minor}"
            tags.update(
                cpython_tags(python_version, abis=(abi, "abi3", "none"), platforms=platforms)
            )
            interpreter = abi
        elif implementation == "pypy":
            abi = f"pp{major}{minor}"
            pypy_version = self.markers.get("implementation_version", "")
            pypy_parts = pypy_version.split(".")
            if len(pypy_parts) >= 2:
                pypy_abi = f"pypy{major}{minor}_pp{pypy_parts[0]}{pypy_parts[1]}"
            else:
                pypy_abi = f"pypy{major}{minor}"
            tags.update(generic_tags(abi, abis=(pypy_abi, "none"), platforms=platforms))
            interpreter = abi
        else:
            interpreter = f"py{major}{minor}"
            tags.update(generic_tags(interpreter, abis=("none",), platforms=platforms))

        tags.update(compatible_tags(python_version, interpreter, platforms=platforms))
        return frozenset(tags)

    def supports_wheel(self, filename: str) -> tuple[bool, str | None]:
        """
        Check whether a wheel filename is installable in this target.

        Returns ``(supported, error)``.  ``error`` is non-``None`` when the
        filename itself is invalid.
        """

        try:
            _, _, _, wheel_tags = parse_wheel_filename(filename)
        except (InvalidWheelFilename, ValueError) as exc:
            return False, str(exc)

        return not wheel_tags.isdisjoint(self.supported_tags), None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the environment to a JSON-compatible mapping."""
        return {
            "name": self.name,
            "markers": dict(self.markers),
            "platform_tags": list(self.platform_tags),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TargetEnvironment:
        """
        Construct a target environment from a matrix-file entry.

        Both nested (``markers = {...}``) and flat marker-variable forms are
        accepted.  ``platform-tags`` is accepted as an alias for ``platform_tags``.
        """

        name = data.get("name", data.get("label"))
        if not isinstance(name, str) or not name:
            raise TargetEnvironmentError("target environment entry is missing a name")

        raw_markers = data.get("markers", {})
        if raw_markers is None:
            raw_markers = {}
        if not isinstance(raw_markers, Mapping):
            raise TargetEnvironmentError(f"target environment {name!r} has invalid markers")

        reserved = {"name", "label", "markers", "platform_tags", "platform-tags", "platforms"}
        markers = {str(key): str(value) for key, value in raw_markers.items()}
        for key, value in data.items():
            if key not in reserved:
                markers[str(key)] = str(value)

        raw_tags = data.get("platform_tags", data.get("platform-tags", data.get("platforms", ())))
        if raw_tags is None:
            raw_tags = ()
        if isinstance(raw_tags, str) or not isinstance(raw_tags, Sequence):
            raise TargetEnvironmentError(f"target environment {name!r} has invalid platform_tags")

        return cls(name=name, markers=markers, platform_tags=tuple(str(tag) for tag in raw_tags))


@dataclass(frozen=True)
class TargetEnvironmentMatrix:
    """
    An ordered set of offline target environments.
    """

    environments: tuple[TargetEnvironment, ...]

    def __post_init__(self) -> None:
        environments = tuple(self.environments)
        names = [environment.name for environment in environments]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise TargetEnvironmentError(
                f"duplicate target environment name(s): {', '.join(duplicates)}"
            )
        object.__setattr__(self, "environments", environments)

    def __iter__(self) -> Iterator[TargetEnvironment]:
        return iter(self.environments)

    @property
    def names(self) -> tuple[str, ...]:
        """The ordered target environment names."""
        return tuple(environment.name for environment in self.environments)

    def __len__(self) -> int:
        return len(self.environments)

    def __getitem__(self, index: int) -> TargetEnvironment:
        return self.environments[index]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the matrix to a JSON-compatible mapping."""
        return {"environments": [environment.to_dict() for environment in self.environments]}

    @classmethod
    def from_iterable(cls, environments: Iterable[TargetEnvironment]) -> TargetEnvironmentMatrix:
        """Construct a matrix from an iterable of environments."""
        return cls(tuple(environments))


EnvironmentMatrix = TargetEnvironmentMatrix
"""Backwards-friendly alias for `TargetEnvironmentMatrix`."""


def load_target_environment_matrix(path: Path) -> TargetEnvironmentMatrix:
    """
    Load a target-environment matrix from a TOML or JSON file.

    The file must contain a list under ``environments`` (or ``environment``/``targets``).
    Each entry is either a nested mapping with a ``markers`` table or a flat
    mapping of marker variables.
    """

    try:
        if path.suffix.lower() == ".json":
            with path.open(encoding="utf-8") as io:
                document = json.load(io)
        else:
            with path.open("rb") as io:
                document = tomli.load(io)
    except (OSError, ValueError, tomli.TOMLDecodeError) as exc:
        raise TargetEnvironmentError(f"{path}: could not load target matrix: {exc}") from exc

    if isinstance(document, list):
        entries = document
    elif isinstance(document, Mapping):
        entries = document.get("environments", document.get("environment", document.get("targets")))
    else:
        entries = None

    if not isinstance(entries, list) or not entries:
        raise TargetEnvironmentError(f"{path}: missing non-empty environments list")

    environments = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise TargetEnvironmentError(f"{path}: invalid target environment entry")
        environments.append(TargetEnvironment.from_dict(entry))

    return TargetEnvironmentMatrix(tuple(environments))
