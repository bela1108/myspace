"""Generate offline pip-audit-format results for every fixture lock state."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from pip_audit._audit import Auditor
from pip_audit._dependency_source.interface import DependencySource
from pip_audit._format.json import JsonFormat
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._service.interface import VulnerabilityID
from packaging.version import Version

from .model import Fixture, RouteState, advisory_matches, build_route_states


class FixtureLockSource(DependencySource):
    """A local dependency source that yields the packages of one fixture lock."""

    def __init__(self, fixture: Fixture, lock: dict[str, str]):
        self._fixture = fixture
        self._lock = lock

    def collect(self) -> Iterator[Dependency]:
        """Yield each fixture package at its locked version."""

        for package in self._fixture.packages:
            yield ResolvedDependency(package.name, Version(self._lock[package.name]))

    def fix(self, fix_version: ResolvedFixVersion) -> None:
        """Reject fix operations; the fixture review never mutates a lock in place."""

        raise NotImplementedError("fixture locks are immutable")


class FixtureVulnerabilityService(VulnerabilityService):
    """A local vulnerability service backed by the fixture advisory ranges."""

    def __init__(self, fixture: Fixture):
        self._fixture = fixture

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """Return fixture advisories that affect the given resolved dependency."""

        if spec.is_skipped():
            return spec, []
        dependency = cast(ResolvedDependency, spec)
        results = [
            VulnerabilityResult.create(
                [VulnerabilityID(advisory.id)],
                f"[severity={advisory.severity}] {advisory.summary}",
                [Version(version) for version in advisory.fixed],
                None,
            )
            for advisory in self._fixture.advisories
            if advisory.package == dependency.canonical_name
            and advisory_matches(advisory, str(dependency.version))
        ]
        return dependency, results


def render_pip_audit_result(fixture: Fixture, lock: dict[str, str]) -> str:
    """Run pip-audit's local auditor over a lock and render its JSON manifest."""

    service = FixtureVulnerabilityService(fixture)
    source = FixtureLockSource(fixture, lock)
    results = dict(Auditor(service).audit(source))
    return JsonFormat(output_desc=True, output_aliases=True).format(results, [])


def _state_record(state: RouteState) -> dict[str, Any]:
    return {
        "index": state.index,
        "unit": state.unit_id,
        "lock": dict(state.lock),
        "unit_issues": [issue.__dict__ for issue in state.unit_issues],
        "constraint_violations": [violation.__dict__ for violation in state.constraint_violations],
    }


def write_audits(fixture: Fixture, out_root: Path) -> dict[str, Any]:
    """Write one pip-audit JSON document per route state and return an index."""

    out_root.mkdir(parents=True, exist_ok=True)
    index: dict[str, Any] = {
        "schema": "patch-order-review/audit-index/v1",
        "generator": "pip_audit._format.json.JsonFormat",
        "routes": {},
    }
    for route in fixture.routes:
        route_dir = out_root / route.id
        route_dir.mkdir(parents=True, exist_ok=True)
        steps: list[dict[str, Any]] = []
        for state in build_route_states(fixture, route):
            payload = render_pip_audit_result(fixture, state.lock)
            filename = f"step_{state.index:02d}.json"
            path = route_dir / filename
            path.write_text(payload + "\n", encoding="utf-8")
            record = _state_record(state)
            record.update(
                {
                    "file": f"{route.id}/{filename}",
                    "sha256": hashlib.sha256((payload + "\n").encode("utf-8")).hexdigest(),
                }
            )
            steps.append(record)
        index["routes"][route.id] = {
            "label": route.label,
            "lanes": list(route.lanes),
            "intent": route.intent,
            "units": list(route.units),
            "steps": steps,
        }
    (out_root / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return index
