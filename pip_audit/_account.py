"""
Offline two-layer accounting of audit findings.

This module implements the `--account` offline entrypoint, which projects
an existing `pip-audit` JSON report onto two accounting layers, using a
declared ledger of composition relationships and provenance:

* the **deliverable layer**, used by supply-chain teams to account for
  remediation quota per deliverable artifact, and
* the **service layer**, used by business teams to report per service.

A release package embedded as-is ("shared" provenance) into any number of
services is a single deliverable unit, so its findings are charged to the
remediation quota exactly once. A release package that is repackaged for a
service ("repackaged" provenance) genuinely adds one unit of responsibility
and is accounted as its own deliverable unit.

The version-level facts of the underlying `pip-audit` JSON report (package
names, versions, vulnerability IDs, fix versions, and any other fields) are
carried through verbatim in each layer's findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

SHARED = "shared"
"""
Provenance marker for a release package embedded as-is into a service.
"""

REPACKAGED = "repackaged"
"""
Provenance marker for a release package repackaged into a service.
"""

_PROVENANCES = {SHARED, REPACKAGED}


class LedgerError(Exception):
    """
    Raised when an accounting ledger declaration is invalid.
    """


def _normalize_version(version: str) -> str:
    """
    Normalize a version string for comparison, falling back to the raw
    string when it is not a valid PEP 440 version.
    """
    try:
        return str(Version(version))
    except InvalidVersion:
        return version


@dataclass(frozen=True)
class PinnedDependency:
    """
    A single dependency pinned by a release package.
    """

    name: str
    """
    The dependency's name.
    """

    version: str
    """
    The dependency's pinned version.
    """


@dataclass(frozen=True)
class ReleasePackage:
    """
    A release package: a named artifact pinning a set of dependencies.
    """

    id: str
    """
    The release package's declared identifier.
    """

    dependencies: tuple[PinnedDependency, ...]
    """
    The dependencies pinned by this release package.
    """


@dataclass(frozen=True)
class PackageUse:
    """
    A composition edge: a service embedding a release package, with provenance.
    """

    package: str
    """
    The identifier of the release package being embedded.
    """

    provenance: str
    """
    How the package is embedded: `shared` (as-is) or `repackaged`.
    """


@dataclass(frozen=True)
class Service:
    """
    A service composed of one or more release packages.
    """

    id: str
    """
    The service's declared identifier.
    """

    uses: tuple[PackageUse, ...]
    """
    The release packages embedded by this service.
    """


@dataclass(frozen=True)
class Ledger:
    """
    A parsed accounting ledger: release packages, services, and the audit
    report whose findings are projected onto both layers.
    """

    release_packages: tuple[ReleasePackage, ...]
    """
    The declared release packages.
    """

    services: tuple[Service, ...]
    """
    The declared services and their composition relationships.
    """

    audit_report: dict[str, Any]
    """
    The `pip-audit` JSON report supplying version-level vulnerability facts.
    """

    @classmethod
    def load(cls, path: Path) -> Ledger:
        """
        Load a ledger declaration from a JSON file.

        Raises `LedgerError` if the file cannot be read or is invalid.
        """
        try:
            obj = json.loads(path.read_text())
        except OSError as e:
            raise LedgerError(f"cannot read ledger {path}: {e}") from e
        except json.JSONDecodeError as e:
            raise LedgerError(f"ledger {path} is not valid JSON: {e}") from e
        return cls.from_dict(obj, base=path.parent)

    @classmethod
    def from_dict(cls, obj: Any, *, base: Path | None = None) -> Ledger:
        """
        Build a ledger from an already-parsed JSON object.

        `base` is the directory used to resolve a relative `audit_report`
        path. Raises `LedgerError` if the declaration is invalid.
        """
        if not isinstance(obj, dict):
            raise LedgerError("ledger must be a JSON object")

        packages = _parse_release_packages(obj.get("release_packages"))
        services = _parse_services(obj.get("services"), {pkg.id for pkg in packages})
        audit_report = _parse_audit_report(obj, base=base)

        return cls(
            release_packages=tuple(packages),
            services=tuple(services),
            audit_report=audit_report,
        )


def _expect_str(obj: Any, what: str) -> str:
    if not isinstance(obj, str) or not obj:
        raise LedgerError(f"{what} must be a non-empty string")
    return obj


def _parse_release_packages(obj: Any) -> list[ReleasePackage]:
    if not isinstance(obj, list) or not obj:
        raise LedgerError("ledger must declare a non-empty 'release_packages' list")

    packages = []
    seen: set[str] = set()
    for entry in obj:
        if not isinstance(entry, dict):
            raise LedgerError("each release package must be an object")
        package_id = _expect_str(entry.get("id"), "release package 'id'")
        if package_id in seen:
            raise LedgerError(f"duplicate release package: {package_id}")
        seen.add(package_id)

        deps_obj = entry.get("dependencies")
        if not isinstance(deps_obj, list):
            raise LedgerError(f"release package {package_id}: 'dependencies' must be a list")
        dependencies = []
        for dep in deps_obj:
            if not isinstance(dep, dict):
                raise LedgerError(
                    f"release package {package_id}: each dependency must be an object"
                )
            dependencies.append(
                PinnedDependency(
                    name=_expect_str(dep.get("name"), f"{package_id}: dependency 'name'"),
                    version=_expect_str(dep.get("version"), f"{package_id}: dependency 'version'"),
                )
            )
        packages.append(ReleasePackage(id=package_id, dependencies=tuple(dependencies)))
    return packages


def _parse_services(obj: Any, package_ids: set[str]) -> list[Service]:
    if not isinstance(obj, list) or not obj:
        raise LedgerError("ledger must declare a non-empty 'services' list")

    services = []
    seen: set[str] = set()
    for entry in obj:
        if not isinstance(entry, dict):
            raise LedgerError("each service must be an object")
        service_id = _expect_str(entry.get("id"), "service 'id'")
        if service_id in seen:
            raise LedgerError(f"duplicate service: {service_id}")
        seen.add(service_id)

        uses_obj = entry.get("uses")
        if not isinstance(uses_obj, list) or not uses_obj:
            raise LedgerError(f"service {service_id}: 'uses' must be a non-empty list")
        uses = []
        for use in uses_obj:
            if not isinstance(use, dict):
                raise LedgerError(f"service {service_id}: each use must be an object")
            package = _expect_str(use.get("package"), f"service {service_id}: use 'package'")
            if package not in package_ids:
                raise LedgerError(f"service {service_id}: unknown release package {package!r}")
            provenance = use.get("provenance", SHARED)
            if provenance not in _PROVENANCES:
                raise LedgerError(
                    f"service {service_id}: provenance must be one of "
                    f"{sorted(_PROVENANCES)}, got {provenance!r}"
                )
            uses.append(PackageUse(package=package, provenance=provenance))
        services.append(Service(id=service_id, uses=tuple(uses)))
    return services


def _parse_audit_report(obj: dict[str, Any], *, base: Path | None) -> dict[str, Any]:
    report = obj.get("audit")
    if report is None:
        report_ref = obj.get("audit_report")
        if report_ref is None:
            raise LedgerError("ledger must declare an 'audit' report or an 'audit_report' path")
        report_ref = _expect_str(report_ref, "'audit_report'")
        report_path = Path(report_ref)
        if not report_path.is_absolute() and base is not None:
            report_path = base / report_path
        try:
            report = json.loads(report_path.read_text())
        except OSError as e:
            raise LedgerError(f"cannot read audit report {report_path}: {e}") from e
        except json.JSONDecodeError as e:
            raise LedgerError(f"audit report {report_path} is not valid JSON: {e}") from e

    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise LedgerError("audit report must be a pip-audit JSON object with a 'dependencies' list")
    return report


@dataclass(frozen=True)
class _DeliverableUnit:
    """
    An internal accounting unit at the deliverable layer.
    """

    key: str
    package: str
    provenance: str
    services: tuple[str, ...]


def _unit_key(package: str, provenance: str, service: str) -> str:
    if provenance == SHARED:
        return f"{package}#{SHARED}"
    # Each repackaging genuinely adds one unit of responsibility.
    return f"{package}#{REPACKAGED}:{service}"


def _deliverable_units(ledger: Ledger) -> list[_DeliverableUnit]:
    units: dict[str, _DeliverableUnit] = {}
    order: list[str] = []
    for service in ledger.services:
        for use in service.uses:
            key = _unit_key(use.package, use.provenance, service.id)
            unit = units.get(key)
            if unit is None:
                unit = _DeliverableUnit(
                    key=key,
                    package=use.package,
                    provenance=use.provenance,
                    services=(),
                )
                order.append(key)
            if service.id not in unit.services:
                unit = _DeliverableUnit(
                    key=key,
                    package=unit.package,
                    provenance=unit.provenance,
                    services=(*unit.services, service.id),
                )
            units[key] = unit
    return [units[key] for key in order]


def _index_audit_report(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for dep in report["dependencies"]:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name")
        version = dep.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            # Skipped dependencies carry no version-level facts to project.
            continue
        index[(canonicalize_name(name), _normalize_version(version))] = dep
    return index


def _unit_findings(
    package: ReleasePackage,
    index: dict[tuple[str, str], dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    findings = []
    unaudited = []
    for dep in package.dependencies:
        fact = index.get((canonicalize_name(dep.name), _normalize_version(dep.version)))
        if fact is None:
            unaudited.append(f"{dep.name}=={dep.version}")
        elif fact.get("vulns"):
            # Carry the report's version-level facts through verbatim.
            findings.append(fact)
    return findings, unaudited


def project(ledger: Ledger) -> dict[str, Any]:
    """
    Project a ledger's audit findings onto the deliverable and service layers.

    Returns a JSON-serializable object with `deliverables`, `services`, and
    a `summary` reconciling the two layers' pending remediation counts.
    """
    packages_by_id = {pkg.id: pkg for pkg in ledger.release_packages}
    index = _index_audit_report(ledger.audit_report)
    units = _deliverable_units(ledger)

    findings_by_unit: dict[str, list[dict[str, Any]]] = {}
    unaudited_by_unit: dict[str, list[str]] = {}
    for unit in units:
        findings, unaudited = _unit_findings(packages_by_id[unit.package], index)
        findings_by_unit[unit.key] = findings
        unaudited_by_unit[unit.key] = unaudited

    deliverables = [
        {
            "id": unit.key,
            "package": unit.package,
            "provenance": unit.provenance,
            "services": list(unit.services),
            "findings": findings_by_unit[unit.key],
            "unaudited": unaudited_by_unit[unit.key],
        }
        for unit in units
    ]

    unit_by_key = {unit.key: unit for unit in units}
    services = []
    for service in ledger.services:
        items = []
        for use in service.uses:
            key = _unit_key(use.package, use.provenance, service.id)
            unit = unit_by_key[key]
            items.append(
                {
                    "deliverable": key,
                    "package": use.package,
                    "provenance": use.provenance,
                    "shared_with": [s for s in unit.services if s != service.id],
                    "findings": findings_by_unit[key],
                }
            )
        services.append({"id": service.id, "items": items})

    deliverable_pending = sum(len(findings_by_unit[unit.key]) for unit in units)
    service_pending = sum(
        len(findings_by_unit[item["deliverable"]])
        for service in services
        for item in service["items"]
    )
    # The deliverable layer is the remediation quota: shared embeddings of
    # the same release package collapse into one unit, so the quota is not
    # multiplied by the number of services. Each repackaged copy belongs to
    # exactly one service and is accounted once more, because repackaging
    # genuinely adds one unit of responsibility.
    summary = {
        "release_packages": len(ledger.release_packages),
        "services": len(ledger.services),
        "deliverable_units": len(units),
        "repackaged_units": sum(1 for unit in units if unit.provenance == REPACKAGED),
        "deliverable_layer_pending": deliverable_pending,
        "service_layer_pending": service_pending,
        "shared_findings": service_pending - deliverable_pending,
    }

    return {
        "deliverables": deliverables,
        "services": services,
        "summary": summary,
    }
