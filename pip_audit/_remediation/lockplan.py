"""
Offline parsing of resolved PEP 751 (`pylock.*.toml`) lock plans.

A lock plan is treated purely as data: this module never installs, downloads,
or resolves anything. It reads the environment markers, optional groups, and
dependency edges that the packaging tool already resolved so that the
remediation checker can reason about where a package comes from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import tomli
from packaging.markers import Marker
from packaging.utils import canonicalize_name


@dataclass(frozen=True)
class LockDependency:
    """
    A single dependency edge declared by a package in a lock plan.

    `name` is the (uncanonicalized) package name. `marker` is the raw marker
    string attached to the edge, or `None` when the edge is unconditional.
    """

    name: str
    marker: str | None

    @property
    def canonical_name(self) -> str:
        """
        The PEP 503 canonicalized name of the dependency target.
        """

        return canonicalize_name(self.name)

    @property
    def marker_active(self) -> bool | None:
        """
        Decide the edge's marker without a live environment.

        Returns `True` for an unconditional edge, `False` when the marker can
        be proven false with no variables (only tautology/contradiction cases),
        and `None` when the marker references variables that the offline check
        must not invent values for.
        """

        return evaluate_marker(self.marker)


@dataclass(frozen=True)
class LockPackage:
    """
    A single package entry within a lock plan.
    """

    name: str
    version: str | None
    dependencies: tuple[LockDependency, ...]
    marker: str | None

    @property
    def canonical_name(self) -> str:
        """
        The PEP 503 canonicalized package name.
        """

        return canonicalize_name(self.name)

    @property
    def resolved(self) -> bool:
        """
        Whether the package entry carries a resolved version.
        """

        return self.version is not None


@dataclass(frozen=True)
class LockPlan:
    """
    A fully parsed, resolved lock plan.

    `environments` holds the top-level environment markers recorded by the
    packaging tool. `groups` maps each optional group to the package names
    declared as its members. `packages` is keyed by canonical package name.
    """

    source: Path
    lock_version: str
    environments: tuple[str, ...]
    requires_python: str | None
    groups: dict[str, tuple[str, ...]]
    packages: dict[str, LockPackage]
    root_names: tuple[str, ...] = field(default_factory=tuple)

    def package(self, canonical: str) -> LockPackage | None:
        """
        Return the package with the given canonical name, if present.
        """

        return self.packages.get(canonicalize_name(canonical))

    def group_members(self, group: str) -> tuple[str, ...]:
        """
        Return the canonical member names declared for an optional group.
        """

        members = self.groups.get(group)
        if members is None:
            raise KeyError(group)
        return tuple(canonicalize_name(name) for name in members)


class LockPlanError(Exception):
    """
    Raised when a lock plan cannot be parsed into a `LockPlan`.
    """


def load_lock_plan(path: Path) -> LockPlan:
    """
    Load a single PEP 751 lock plan from `path`.

    Only structural validation is performed; no network or resolver access
    occurs. Raises `LockPlanError` on malformed or unsupported input.
    """

    try:
        with path.open(mode="rb") as io:
            raw = tomli.load(io)
    except FileNotFoundError as e:
        raise LockPlanError(f"{path}: lock plan not found") from e
    except OSError as e:
        raise LockPlanError(f"{path}: unable to read lock plan") from e
    except tomli.TOMLDecodeError as e:
        raise LockPlanError(f"{path}: invalid TOML in lock plan") from e

    lock_version = raw.get("lock-version")
    if not lock_version:
        raise LockPlanError(f"{path}: missing lock-version in lock plan")
    if not str(lock_version).startswith("1."):
        raise LockPlanError(f"{path}: lock plan version {lock_version} is not supported")

    packages_raw = raw.get("packages")
    if not packages_raw:
        raise LockPlanError(f"{path}: missing packages in lock plan")

    packages: dict[str, LockPackage] = {}
    for idx, entry in enumerate(packages_raw):
        name = entry.get("name")
        if not name:
            raise LockPlanError(f"{path}: invalid package #{idx}: no name")
        dependencies = tuple(
            LockDependency(name=dep["name"], marker=dep.get("marker"))
            for dep in entry.get("dependencies", [])
            if dep.get("name")
        )
        package = LockPackage(
            name=name,
            version=entry.get("version"),
            dependencies=dependencies,
            marker=entry.get("marker"),
        )
        packages[package.canonical_name] = package

    groups: dict[str, tuple[str, ...]] = {}
    for group_name, group_table in raw.get("groups", {}).items():
        members = group_table.get("members", []) if isinstance(group_table, dict) else []
        groups[group_name] = tuple(
            member["name"] for member in members if isinstance(member, dict) and member.get("name")
        )

    referenced = {
        dep.canonical_name for package in packages.values() for dep in package.dependencies
    }
    group_members = {canonicalize_name(member) for members in groups.values() for member in members}
    # Lock-level roots are unreferenced packages that are not claimed by an
    # optional group; group members are roots of their own groups instead.
    root_names = tuple(
        sorted(name for name in packages if name not in referenced and name not in group_members)
    )

    return LockPlan(
        source=path,
        lock_version=str(lock_version),
        environments=tuple(raw.get("environments", [])),
        requires_python=raw.get("requires-python"),
        groups=groups,
        packages=packages,
        root_names=root_names,
    )


def evaluate_marker(marker: str | None) -> bool | None:
    """
    Evaluate a dependency marker without a live target environment.

    The remediation check is offline and must not fabricate the user's target
    environment. An unconditional edge (`None`) always applies. A marker that
    references variables that cannot be supplied returns `None`, so the caller
    can flag the affected chain as incomplete evidence.
    """

    if marker is None:
        return True

    # Any non-empty marker references target-environment variables. The
    # remediation check runs offline and must not invent values for them, so
    # the edge is reported as undecidable rather than evaluated against
    # packaging's process-derived default environment. We still parse the
    # marker so that syntactically invalid markers are treated the same way.
    try:
        Marker(marker)
    except Exception:
        return None
    return None
