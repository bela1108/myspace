"""Data model, fixture loading, and compatibility-constraint evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import Version


class FixtureError(Exception):
    """Raised when the fixture is missing a required field or reference."""


@dataclass(frozen=True)
class Package:
    """A fictional distribution package and the maintenance line it belongs to."""

    name: str
    line: str
    role: str
    candidate_versions: tuple[str, ...]


@dataclass(frozen=True)
class Advisory:
    """A synthetic vulnerability advisory with an affected range and fix versions."""

    id: str
    package: str
    affected: str
    fixed: tuple[str, ...]
    severity: str
    summary: str


@dataclass(frozen=True)
class Disposition:
    """A signed, already-closed risk disposition that must not be reopened."""

    id: str
    package: str
    signed_by: str
    signed_on: str
    reopenable: bool
    note: str


@dataclass(frozen=True)
class RemediationTarget:
    """A finding that must be closed in every terminal candidate lock."""

    id: str
    package: str
    required_at: str
    note: str


@dataclass(frozen=True)
class TransientAcceptance:
    """A time- and duration-bounded acceptance for a transient finding."""

    id: str
    package: str
    severity: str
    max_consecutive_states: int
    mitigation: str
    owner: str
    expires: str
    note: str


@dataclass(frozen=True)
class ResidualAcceptance:
    """A signed acceptance for a finding that remains in the terminal lock."""

    id: str
    package: str
    severity: str
    mitigation: str
    owner: str
    expires: str
    review_cadence: str
    note: str


@dataclass(frozen=True)
class LockConstraint:
    """A compatibility rule evaluated against a complete candidate lock."""

    id: str
    when: dict[str, str]
    require: dict[str, str]
    reason: str


@dataclass(frozen=True)
class PatchUnit:
    """An atomic, ordered patch step, possibly spanning both maintenance lines."""

    id: str
    lines: tuple[str, ...]
    title: str
    requires: dict[str, str]
    change: dict[str, str]
    note: str


@dataclass(frozen=True)
class Route:
    """A candidate ordering of patch units."""

    id: str
    label: str
    lanes: tuple[str, ...]
    intent: str
    units: tuple[str, ...]


@dataclass(frozen=True)
class UnitIssue:
    """A failed precondition for a patch unit."""

    unit_id: str
    package: str
    required: str
    actual: str


@dataclass(frozen=True)
class ConstraintViolation:
    """A compatibility constraint that does not hold for a lock."""

    constraint_id: str
    package: str
    required: str
    actual: str
    reason: str


@dataclass(frozen=True)
class RouteState:
    """One lock state in a route, after zero or more patch units."""

    index: int
    unit_id: str | None
    lock: dict[str, str]
    unit_issues: tuple[UnitIssue, ...]
    constraint_violations: tuple[ConstraintViolation, ...]


@dataclass(frozen=True)
class Fixture:
    """The complete patch-order-review fixture."""

    root: Path
    packages: tuple[Package, ...]
    advisories: tuple[Advisory, ...]
    baseline: dict[str, str]
    locked_closed: tuple[Disposition, ...]
    remediation_targets: tuple[RemediationTarget, ...]
    accepted_transient: tuple[TransientAcceptance, ...]
    accepted_residual: tuple[ResidualAcceptance, ...]
    policy: dict[str, bool]
    review_as_of: str
    terminal_requirements: dict[str, str]
    constraints: tuple[LockConstraint, ...]
    units: tuple[PatchUnit, ...]
    routes: tuple[Route, ...]

    def unit(self, unit_id: str) -> PatchUnit:
        """Return a patch unit by identifier."""

        for unit in self.units:
            if unit.id == unit_id:
                return unit
        raise FixtureError(f"unknown patch unit: {unit_id}")

    def advisory(self, advisory_id: str) -> Advisory:
        """Return an advisory by identifier."""

        for advisory in self.advisories:
            if advisory.id == advisory_id:
                return advisory
        raise FixtureError(f"unknown advisory: {advisory_id}")

    def transient_acceptance(self, advisory_id: str) -> TransientAcceptance | None:
        """Return the transient acceptance for an advisory, if one exists."""

        return next((item for item in self.accepted_transient if item.id == advisory_id), None)

    def residual_acceptance(self, advisory_id: str) -> ResidualAcceptance | None:
        """Return the residual acceptance for an advisory, if one exists."""

        return next((item for item in self.accepted_residual if item.id == advisory_id), None)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FixtureError(f"missing fixture file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FixtureError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FixtureError(f"expected a JSON object in {path}")
    return data


def _require(data: dict[str, Any], key: str, where: str) -> Any:
    try:
        return data[key]
    except KeyError as exc:
        raise FixtureError(f"missing key {key!r} in {where}") from exc


def load_fixture(root: Path | None = None) -> Fixture:
    """Load and validate the fixture rooted at `root` (defaults to this package)."""

    fixture_root = (root or Path(__file__).resolve().parent / "fixture").resolve()
    packages_raw = _require(
        _load_json(fixture_root / "packages.json"), "packages", "packages.json"
    )
    advisories_raw = _require(
        _load_json(fixture_root / "advisories.json"), "advisories", "advisories.json"
    )
    baseline = _load_json(fixture_root / "baseline_lock.json")
    dispositions = _load_json(fixture_root / "dispositions.json")
    constraints_raw = _load_json(fixture_root / "constraints.json")
    units_raw = _require(
        _load_json(fixture_root / "patch_units.json"), "units", "patch_units.json"
    )

    packages = tuple(
        Package(
            name=_require(item, "name", "packages.json"),
            line=_require(item, "line", "packages.json"),
            role=_require(item, "role", "packages.json"),
            candidate_versions=tuple(_require(item, "candidate_versions", "packages.json")),
        )
        for item in packages_raw
    )
    advisories = tuple(
        Advisory(
            id=_require(item, "id", "advisories.json"),
            package=_require(item, "package", "advisories.json"),
            affected=_require(item, "affected", "advisories.json"),
            fixed=tuple(_require(item, "fixed", "advisories.json")),
            severity=_require(item, "severity", "advisories.json"),
            summary=_require(item, "summary", "advisories.json"),
        )
        for item in advisories_raw
    )
    locked_closed = tuple(
        Disposition(
            id=_require(item, "id", "dispositions.json"),
            package=_require(item, "package", "dispositions.json"),
            signed_by=_require(item, "signed_by", "dispositions.json"),
            signed_on=_require(item, "signed_on", "dispositions.json"),
            reopenable=bool(_require(item, "reopenable", "dispositions.json")),
            note=_require(item, "note", "dispositions.json"),
        )
        for item in dispositions["locked_closed"]
    )
    remediation_targets = tuple(
        RemediationTarget(
            id=_require(item, "id", "dispositions.json"),
            package=_require(item, "package", "dispositions.json"),
            required_at=_require(item, "required_at", "dispositions.json"),
            note=_require(item, "note", "dispositions.json"),
        )
        for item in dispositions["remediation_targets"]
    )
    accepted_transient = tuple(
        TransientAcceptance(
            id=_require(item, "id", "dispositions.json"),
            package=_require(item, "package", "dispositions.json"),
            severity=_require(item, "severity", "dispositions.json"),
            max_consecutive_states=int(
                _require(item, "max_consecutive_states", "dispositions.json")
            ),
            mitigation=_require(item, "mitigation", "dispositions.json"),
            owner=_require(item, "owner", "dispositions.json"),
            expires=_require(item, "expires", "dispositions.json"),
            note=_require(item, "note", "dispositions.json"),
        )
        for item in dispositions["accepted_transient"]
    )
    accepted_residual = tuple(
        ResidualAcceptance(
            id=_require(item, "id", "dispositions.json"),
            package=_require(item, "package", "dispositions.json"),
            severity=_require(item, "severity", "dispositions.json"),
            mitigation=_require(item, "mitigation", "dispositions.json"),
            owner=_require(item, "owner", "dispositions.json"),
            expires=_require(item, "expires", "dispositions.json"),
            review_cadence=_require(item, "review_cadence", "dispositions.json"),
            note=_require(item, "note", "dispositions.json"),
        )
        for item in dispositions["accepted_residual"]
    )
    constraints = tuple(
        LockConstraint(
            id=_require(item, "id", "constraints.json"),
            when=dict(_require(item, "when", "constraints.json")),
            require=dict(_require(item, "require", "constraints.json")),
            reason=_require(item, "reason", "constraints.json"),
        )
        for item in constraints_raw["lock_constraints"]
    )
    terminal_requirements = dict(
        _require(constraints_raw, "terminal_requirements", "constraints.json")
    )
    units = tuple(
        PatchUnit(
            id=_require(item, "id", "patch_units.json"),
            lines=tuple(_require(item, "lines", "patch_units.json")),
            title=_require(item, "title", "patch_units.json"),
            requires=dict(_require(item, "requires", "patch_units.json")),
            change=dict(_require(item, "change", "patch_units.json")),
            note=_require(item, "note", "patch_units.json"),
        )
        for item in units_raw
    )
    routes = tuple(
        Route(
            id=_require(route_raw, "id", "routes"),
            label=_require(route_raw, "label", "routes"),
            lanes=tuple(_require(route_raw, "lanes", "routes")),
            intent=_require(route_raw, "intent", "routes"),
            units=tuple(_require(route_raw, "units", "routes")),
        )
        for route_raw in (
            _load_json(fixture_root / "routes" / "min_delta.json"),
            _load_json(fixture_root / "routes" / "bridge_release.json"),
        )
    )

    package_names = {package.name for package in packages}
    if package_names != set(baseline):
        raise FixtureError("baseline lock must pin exactly the four fixture packages")
    for unit in units:
        for package in set(unit.requires) | set(unit.change):
            if package not in package_names:
                raise FixtureError(f"patch unit {unit.id} references unknown package {package}")
    for route in routes:
        for unit_id in route.units:
            if all(unit.id != unit_id for unit in units):
                raise FixtureError(f"route {route.id} references unknown unit {unit_id}")

    return Fixture(
        root=fixture_root,
        packages=packages,
        advisories=advisories,
        baseline=dict(baseline),
        locked_closed=locked_closed,
        remediation_targets=remediation_targets,
        accepted_transient=accepted_transient,
        accepted_residual=accepted_residual,
        policy={key: bool(value) for key, value in dispositions["policy"].items()},
        review_as_of=_require(dispositions, "review_as_of", "dispositions.json"),
        terminal_requirements=terminal_requirements,
        constraints=constraints,
        units=units,
        routes=routes,
    )


def version_matches(version: str, specifier: str) -> bool:
    """Return whether `version` satisfies the PEP 440 `specifier`."""

    return Version(version) in SpecifierSet(specifier)


def version_delta(left: str, right: str) -> int:
    """Return the sum of absolute release-component deltas between two versions."""

    left_release = Version(left).release
    right_release = Version(right).release
    return sum(
        abs((a or 0) - (b or 0)) for a, b in zip_longest(left_release, right_release, fillvalue=0)
    )


def lock_gap(baseline: dict[str, str], lock: dict[str, str]) -> int:
    """Return the version-gap metric for a terminal lock against the baseline."""

    return sum(version_delta(baseline[name], lock[name]) for name in baseline)


def advisory_matches(advisory: Advisory, version: str) -> bool:
    """Return whether an advisory affects the given version of its package."""

    return version_matches(version, advisory.affected)


def open_advisories(fixture: Fixture, lock: dict[str, str]) -> tuple[Advisory, ...]:
    """Return the advisories that are open for a complete lock."""

    return tuple(
        advisory
        for advisory in fixture.advisories
        if advisory_matches(advisory, lock[advisory.package])
    )


def check_lock(fixture: Fixture, lock: dict[str, str]) -> tuple[ConstraintViolation, ...]:
    """Evaluate every compatibility constraint against a complete lock."""

    violations: list[ConstraintViolation] = []
    for constraint in fixture.constraints:
        if not all(version_matches(lock[name], spec) for name, spec in constraint.when.items()):
            continue
        for name, spec in constraint.require.items():
            if not version_matches(lock[name], spec):
                violations.append(
                    ConstraintViolation(
                        constraint_id=constraint.id,
                        package=name,
                        required=spec,
                        actual=lock[name],
                        reason=constraint.reason,
                    )
                )
    return tuple(violations)


def check_unit(unit: PatchUnit, lock: dict[str, str]) -> tuple[UnitIssue, ...]:
    """Evaluate a patch unit's preconditions against a lock."""

    issues: list[UnitIssue] = []
    for name, spec in unit.requires.items():
        if name not in lock or not version_matches(lock[name], spec):
            issues.append(
                UnitIssue(
                    unit_id=unit.id,
                    package=name,
                    required=spec,
                    actual=lock.get(name, "<missing>"),
                )
            )
    return tuple(issues)


def apply_unit(unit: PatchUnit, lock: dict[str, str]) -> dict[str, str]:
    """Return a new lock with the patch unit's changes applied."""

    updated = dict(lock)
    updated.update(unit.change)
    return updated


def build_route_states(fixture: Fixture, route: Route) -> tuple[RouteState, ...]:
    """Build every lock state for a route, recording precondition and compatibility failures."""

    states: list[RouteState] = [
        RouteState(
            index=0,
            unit_id=None,
            lock=dict(fixture.baseline),
            unit_issues=(),
            constraint_violations=check_lock(fixture, fixture.baseline),
        )
    ]
    lock = dict(fixture.baseline)
    for index, unit_id in enumerate(route.units, start=1):
        unit = fixture.unit(unit_id)
        issues = check_unit(unit, lock)
        lock = apply_unit(unit, lock)
        states.append(
            RouteState(
                index=index,
                unit_id=unit_id,
                lock=lock,
                unit_issues=issues,
                constraint_violations=check_lock(fixture, lock),
            )
        )
    return tuple(states)


def iter_units_by_id(fixture: Fixture) -> dict[str, PatchUnit]:
    """Return the fixture's patch units keyed by identifier."""

    return {unit.id: unit for unit in fixture.units}
