"""
Offline release landing verification for pip-audit results.

A release pipeline can audit one lock file and then deploy the result to
several installation targets. This module reconciles the existing audit output
with the packages that were actually installed on each target and with a simple
mapping of build cache entries. It never contacts the network.

The input model is deliberately small:

* an audit report in the pip-audit JSON shape, optionally enriched with marker,
  extra and artifact fields per dependency;
* one installed-package manifest per release target;
* one build-cache mapping per release target.

Markers and optional dependencies are expanded against the declared release
scope, not against the host that runs the reconciliation. A missing cache
mapping is reported separately from a missing install manifest. Dependency
identity includes the artifact where it is known, so two entries with the same
package name are never collapsed into one result merely because the name
matches.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

import tomli
from packaging.markers import InvalidMarker, Marker, UndefinedEnvironmentName, Variable
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


class ReconciliationError(ValueError):
    """Raised when release reconciliation input is malformed."""


class FindingKind(str, Enum):
    """The kind of discrepancy found during landing verification."""

    STALE_CACHE = "stale-cache"
    STALE_CACHE_ARTIFACT = "stale-cache-artifact"
    CACHE_VERSION_MISMATCH = "cache-version-mismatch"
    MISSING_MANIFEST = "missing-manifest"
    MISSING_CACHE_MAPPING = "missing-cache-mapping"
    MISSING_PACKAGE_CACHE_MAPPING = "missing-package-cache-mapping"
    MISSING_INSTALL = "missing-install"
    INSTALLED_VERSION_MISMATCH = "installed-version-mismatch"
    INSTALLED_ARTIFACT_MISMATCH = "installed-artifact-mismatch"
    UNEXPECTED_INSTALL = "unexpected-install"
    UNRESOLVED_MARKER = "unresolved-marker"
    AMBIGUOUS_MATCH = "ambiguous-match"
    UNVERIFIED_ARTIFACT = "unverified-artifact"

    def __str__(self) -> str:
        return self.value


CACHE_FINDINGS = frozenset(
    {
        FindingKind.STALE_CACHE,
        FindingKind.STALE_CACHE_ARTIFACT,
        FindingKind.CACHE_VERSION_MISMATCH,
    }
)

MAPPING_FINDINGS = frozenset(
    {
        FindingKind.MISSING_CACHE_MAPPING,
        FindingKind.MISSING_PACKAGE_CACHE_MAPPING,
    }
)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _basename(value: str | None) -> str | None:
    if value is None:
        return None
    return value.rstrip("/").rsplit("/", 1)[-1] or None


def _normalize_digest(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        for algorithm in ("sha256", "sha512", "sha1", "md5"):
            if algorithm in value:
                digest = _normalize_digest(value[algorithm])
                if digest is not None:
                    return digest if ":" in digest else f"{algorithm}:{digest}"
        return None
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            digest = _normalize_digest(item)
            if digest is not None:
                return digest
        return None
    text = str(value).strip()
    if not text:
        return None
    lowered = text.lower()
    for prefix in ("sha256:", "sha256=", "sha512:", "sha512="):
        if lowered.startswith(prefix):
            algorithm, payload = prefix[:-1], text[len(prefix) :].strip()
            return f"{algorithm}:{payload.lower()}"
    if len(text) in (32, 40, 64, 128) and all(char in "0123456789abcdefABCDEF" for char in text):
        algorithm = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}[len(text)]
        return f"{algorithm}:{text.lower()}"
    return None


@dataclass(frozen=True)
class ArtifactIdentity:
    """The identity of one distribution artifact, when one is known."""

    filename: str | None = None
    digest: str | None = None
    url: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "filename", _basename(_text(self.filename)))
        object.__setattr__(self, "digest", _normalize_digest(self.digest))
        object.__setattr__(self, "url", _text(self.url))

    @classmethod
    def from_value(cls, value: Any) -> ArtifactIdentity | None:
        """Build an artifact identity from a filename, digest or mapping."""

        if value is None:
            return None
        if isinstance(value, ArtifactIdentity):
            return value
        if isinstance(value, Mapping):
            filename = value.get("filename") or value.get("file") or value.get("name")
            digest = (
                value.get("digest")
                or value.get("hash")
                or value.get("sha256")
                or value.get("sha512")
                or value.get("hashes")
            )
            url = value.get("url") or value.get("download_url")
            artifact = cls(
                filename=_text(filename),
                digest=_normalize_digest(digest),
                url=_text(url),
            )
            return artifact if artifact.known else None
        text = _text(value)
        if text is None:
            return None
        digest = _normalize_digest(text)
        if digest is not None:
            return cls(digest=digest)
        if "://" in text:
            return cls(filename=_basename(text), url=text)
        return cls(filename=text)

    @property
    def known(self) -> bool:
        """Whether this identity contains any usable artifact evidence."""

        return bool(self.filename or self.digest or self.url)

    def same_as(self, other: ArtifactIdentity | None) -> bool | None:
        """Compare identities, returning None when the evidence is insufficient."""

        if other is None or not self.known or not other.known:
            return None
        if self.digest and other.digest:
            return self.digest.lower() == other.digest.lower()
        if self.filename and other.filename:
            return self.filename.lower() == other.filename.lower()
        if self.url and other.url:
            return self.url == other.url
        return None

    def describe(self) -> str | None:
        """Return a compact human-readable identity."""

        parts: list[str] = []
        if self.filename:
            parts.append(self.filename)
        if self.digest:
            parts.append(self.digest)
        if not parts and self.url:
            parts.append(self.url)
        return ", ".join(parts) if parts else None


def _version(value: Any) -> Version | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _string_set(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Mapping):
        return frozenset(str(key) for key in value)
    if isinstance(value, Iterable):
        return frozenset(str(item) for item in value)
    return frozenset({str(value)})


def _vulnerability_ids(value: Any) -> tuple[str, ...]:
    ids: set[str] = set()
    if value is None:
        return ()
    if isinstance(value, Mapping):
        value = [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            if isinstance(item, Mapping):
                identifier = item.get("id")
                if identifier:
                    ids.add(str(identifier))
                for alias in item.get("aliases", ()) or ():
                    ids.add(str(alias))
            elif item:
                ids.add(str(item))
    elif value:
        ids.add(str(value))
    return tuple(sorted(ids))


@dataclass(frozen=True)
class AuditedDependency:
    """One dependency from an existing audit report."""

    name: str
    version: Version | None = None
    marker: str | None = None
    extras: frozenset[str] = field(default_factory=frozenset)
    artifact: ArtifactIdentity | None = None
    vulnerabilities: tuple[str, ...] = ()
    skip_reason: str | None = None
    target: str | None = None

    def __post_init__(self) -> None:
        if not _text(self.name):
            raise ReconciliationError("audit dependency has no name")
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "marker", _text(self.marker))
        object.__setattr__(self, "skip_reason", _text(self.skip_reason))
        object.__setattr__(self, "target", _text(self.target))
        object.__setattr__(self, "extras", _string_set(self.extras))
        object.__setattr__(self, "vulnerabilities", tuple(self.vulnerabilities))

    @property
    def canonical_name(self) -> str:
        """The PEP 503 canonical package name."""

        return canonicalize_name(self.name)

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any], default_target: str | None = None
    ) -> AuditedDependency:
        """Build one audited dependency from pip-audit JSON or an enriched entry."""

        if not isinstance(value, Mapping):
            raise ReconciliationError(
                f"audit dependency must be a mapping, got {type(value).__name__}"
            )
        name = value.get("name")
        if not name:
            raise ReconciliationError("audit dependency has no name")
        version = value.get("version") or value.get("installed_version")
        return cls(
            name=str(name),
            version=_version(version),
            marker=_text(value.get("marker")),
            extras=_string_set(value.get("extras") or value.get("required_extras")),
            artifact=ArtifactIdentity.from_value(
                value.get("artifact") or value.get("distribution")
            ),
            vulnerabilities=_vulnerability_ids(value.get("vulns") or value.get("vulnerabilities")),
            skip_reason=_text(value.get("skip_reason")),
            target=_text(value.get("target")) or default_target,
        )


@dataclass(frozen=True)
class ReleaseTarget:
    """One installation target in the declared release scope."""

    name: str
    kind: str = "desktop"
    markers: Mapping[str, str] = field(default_factory=dict)
    extras: frozenset[str] = field(default_factory=frozenset)
    architecture: str | None = None
    platform: str | None = None
    desktop: bool | None = None

    def __post_init__(self) -> None:
        if not _text(self.name):
            raise ReconciliationError("release target has no name")
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "kind", str(self.kind or "desktop"))
        object.__setattr__(
            self,
            "markers",
            MappingProxyType({str(key): str(value) for key, value in self.markers.items()}),
        )
        object.__setattr__(self, "extras", _string_set(self.extras))
        object.__setattr__(self, "architecture", _text(self.architecture))
        object.__setattr__(self, "platform", _text(self.platform))

    @property
    def is_desktop(self) -> bool:
        """Whether the target belongs to the desktop release family."""

        if self.desktop is not None:
            return self.desktop
        return (
            self.kind.lower() in {"desktop", "workstation", "client"}
            or "desktop" in self.name.lower()
        )

    @property
    def marker_environment(self) -> dict[str, str]:
        """A complete marker environment supplied by the release scope."""

        environment = dict(self.markers)
        environment.setdefault("extra", "")
        return environment

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReleaseTarget:
        """Build one release target from a scope file entry."""

        if not isinstance(value, Mapping):
            raise ReconciliationError(
                f"release target must be a mapping, got {type(value).__name__}"
            )
        name = value.get("name")
        if not name:
            raise ReconciliationError("release target has no name")
        markers = value.get("markers") or value.get("environment") or {}
        if not isinstance(markers, Mapping):
            raise ReconciliationError(f"target {name}: markers must be a mapping")
        desktop = value.get("desktop")
        return cls(
            name=str(name),
            kind=str(value.get("kind") or "desktop"),
            markers=markers,
            extras=_string_set(value.get("extras")),
            architecture=_text(
                value.get("architecture") or value.get("arch") or value.get("platform_machine")
            ),
            platform=_text(value.get("platform") or value.get("sys_platform")),
            desktop=bool(desktop) if desktop is not None else None,
        )


@dataclass(frozen=True)
class InstalledDistribution:
    """One package entry from an install manifest or build cache mapping."""

    name: str
    version: Version | None = None
    artifact: ArtifactIdentity | None = None
    origin: str | None = None

    def __post_init__(self) -> None:
        if not _text(self.name):
            raise ReconciliationError("distribution has no name")
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "origin", _text(self.origin))

    @property
    def canonical_name(self) -> str:
        return canonicalize_name(self.name)

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any], default_name: str | None = None
    ) -> InstalledDistribution:
        if not isinstance(value, Mapping):
            raise ReconciliationError(f"distribution must be a mapping, got {type(value).__name__}")
        name = value.get("name") or value.get("package") or default_name
        if not name:
            raise ReconciliationError("distribution has no name")
        artifact_value = value.get("artifact") or value.get("distribution")
        artifact = ArtifactIdentity.from_value(artifact_value)
        if artifact is None:
            artifact = ArtifactIdentity.from_value(
                {
                    "filename": value.get("filename") or value.get("file") or value.get("wheel"),
                    "digest": value.get("digest")
                    or value.get("hash")
                    or value.get("sha256")
                    or value.get("hashes"),
                    "url": value.get("url"),
                }
            )
        return cls(
            name=str(name),
            version=_version(value.get("version")),
            artifact=artifact,
            origin=_text(value.get("origin") or value.get("source")),
        )


def _load_json_source(source: Any) -> Any:
    """Load JSON from a path, a JSON string or an already decoded value."""

    if isinstance(source, (Mapping, list)):
        return source
    if isinstance(source, Path):
        return json.loads(source.read_text())
    if not isinstance(source, str):
        raise ReconciliationError(f"unsupported JSON source: {type(source).__name__}")
    text = source.strip()
    if text.startswith("{") or text.startswith("["):
        return json.loads(text)
    path = Path(source)
    if not path.is_file():
        raise ReconciliationError(f"file not found: {source}")
    text = path.read_text()
    if path.suffix == ".toml":
        return tomli.loads(text)
    return json.loads(text)


@dataclass(frozen=True)
class AuditReport:
    """An existing audit result plus any target information it carries."""

    dependencies: tuple[AuditedDependency, ...]
    targets: tuple[ReleaseTarget, ...] = ()

    @classmethod
    def from_mapping(cls, value: Any) -> AuditReport:
        """Build an audit report from pip-audit JSON or an enriched report."""

        if isinstance(value, list):
            dependencies = tuple(AuditedDependency.from_mapping(item) for item in value)
            return cls(dependencies=dependencies)

        if not isinstance(value, Mapping):
            raise ReconciliationError("audit report must be a mapping or a list of dependencies")

        raw_dependencies = value.get("dependencies")
        if raw_dependencies is None:
            raw_dependencies = value.get("packages")
        if not isinstance(raw_dependencies, list):
            raise ReconciliationError("audit report has no dependencies list")

        targets_value = value.get("targets") or value.get("scope") or ()
        if not isinstance(targets_value, (list, tuple)):
            raise ReconciliationError("audit report targets must be a list")

        dependencies: list[AuditedDependency] = []
        default_target = _text(value.get("target"))
        for item in raw_dependencies:
            dependencies.append(AuditedDependency.from_mapping(item, default_target=default_target))
        targets = tuple(ReleaseTarget.from_mapping(item) for item in targets_value)
        return cls(dependencies=tuple(dependencies), targets=targets)

    @classmethod
    def load(cls, source: Any) -> AuditReport:
        """Load an audit report from a path, JSON string, mapping or list."""

        return cls.from_mapping(_load_json_source(source))


@dataclass(frozen=True)
class MarkerDecision:
    """The result of evaluating a dependency marker for one target."""

    applies: bool
    matched_extra: str | None = None
    missing: tuple[str, ...] = ()
    reason: str | None = None


def marker_variables(marker: Marker) -> set[str]:
    """Return every marker variable referenced by a parsed marker."""

    names: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, Variable):
            names.add(node.value)
        elif isinstance(node, (list, tuple)):
            for item in node:
                visit(item)

    visit(marker._markers)
    return names


def evaluate_marker(marker_text: str, target: ReleaseTarget) -> MarkerDecision:
    """Evaluate a marker without inheriting variables from the host machine."""

    try:
        marker = Marker(marker_text)
    except InvalidMarker as exc:
        return MarkerDecision(False, reason=f"invalid marker: {exc}")

    referenced = marker_variables(marker)
    required = referenced - {"extra"}
    missing = tuple(sorted(required - target.markers.keys()))
    if missing:
        return MarkerDecision(False, missing=missing)

    extras: list[str] = [""]
    if "extra" in referenced:
        extras.extend(sorted(target.extras))

    for extra in extras:
        environment = dict(target.markers)
        environment["extra"] = extra
        try:
            applies = bool(marker.evaluate(environment))
        except UndefinedEnvironmentName as exc:
            return MarkerDecision(False, missing=(str(exc),))
        except Exception as exc:
            return MarkerDecision(False, reason=str(exc))
        if applies:
            return MarkerDecision(True, matched_extra=extra or None)

    return MarkerDecision(False)


@dataclass(frozen=True)
class DependencyBasis:
    """The audit evidence that puts one dependency in a target scope."""

    package: str
    version: str | None
    marker: str | None = None
    matched_extra: str | None = None
    artifact: ArtifactIdentity | None = None
    vulnerabilities: tuple[str, ...] = ()
    note: str | None = None

    @property
    def canonical_name(self) -> str:
        return canonicalize_name(self.package)

    def describe(self) -> str:
        """Render the audit basis for a reviewer."""

        text = self.package
        if self.version:
            text += f"=={self.version}"
        details: list[str] = []
        if self.marker:
            details.append(f"marker: {self.marker}")
        if self.matched_extra:
            details.append(f"extra: {self.matched_extra}")
        artifact = self.artifact.describe() if self.artifact else None
        if artifact:
            details.append(f"artifact: {artifact}")
        if self.vulnerabilities:
            details.append("advisories: " + ", ".join(self.vulnerabilities))
        if self.note:
            details.append(self.note)
        return text + (" (" + "; ".join(details) + ")" if details else "")

    def as_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "marker": self.marker,
            "matched_extra": self.matched_extra,
            "artifact": self.artifact.describe() if self.artifact else None,
            "vulnerabilities": list(self.vulnerabilities),
            "note": self.note,
        }


@dataclass(frozen=True)
class ScopeEntry:
    """One applicable dependency together with its audit record."""

    dependency: AuditedDependency
    basis: DependencyBasis


@dataclass(frozen=True)
class Finding:
    """One discrepancy or missing piece of landing evidence."""

    kind: FindingKind
    target: str
    package: str
    detail: str
    expected_version: str | None = None
    actual_version: str | None = None
    expected_artifact: ArtifactIdentity | None = None
    actual_artifact: ArtifactIdentity | None = None
    basis: DependencyBasis | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": str(self.kind),
            "target": self.target,
            "package": self.package,
            "detail": self.detail,
            "expected_version": self.expected_version,
            "actual_version": self.actual_version,
            "expected_artifact": self.expected_artifact.describe()
            if self.expected_artifact
            else None,
            "actual_artifact": self.actual_artifact.describe() if self.actual_artifact else None,
            "basis": self.basis.as_dict() if self.basis else None,
        }


def expand_scope(
    audit: AuditReport, target: ReleaseTarget
) -> tuple[tuple[ScopeEntry, ...], tuple[Finding, ...]]:
    """Expand markers and extras for one target and return applicable entries."""

    applicable: list[ScopeEntry] = []
    unresolved: list[Finding] = []

    for dependency in audit.dependencies:
        if dependency.target is not None and dependency.target != target.name:
            continue

        if dependency.extras and not (dependency.extras & target.extras):
            continue

        matched_extra: str | None = None
        if dependency.extras:
            enabled = sorted(dependency.extras & target.extras)
            if not enabled:
                continue
            matched_extra = enabled[0]

        if dependency.marker:
            decision = evaluate_marker(dependency.marker, target)
            if decision.missing or decision.reason:
                detail = decision.reason or (
                    "missing marker variables: " + ", ".join(decision.missing)
                )
                basis = DependencyBasis(
                    package=dependency.name,
                    version=str(dependency.version) if dependency.version else None,
                    marker=dependency.marker,
                    artifact=dependency.artifact,
                    vulnerabilities=dependency.vulnerabilities,
                    note=detail,
                )
                unresolved.append(
                    Finding(
                        kind=FindingKind.UNRESOLVED_MARKER,
                        target=target.name,
                        package=dependency.name,
                        detail="marker cannot be evaluated offline: " + detail,
                        expected_version=basis.version,
                        basis=basis,
                    )
                )
                continue
            if not decision.applies:
                continue
            matched_extra = decision.matched_extra or matched_extra

        note = None
        if dependency.skip_reason:
            note = "audit entry skipped: " + dependency.skip_reason
        basis = DependencyBasis(
            package=dependency.name,
            version=str(dependency.version) if dependency.version else None,
            marker=dependency.marker,
            matched_extra=matched_extra,
            artifact=dependency.artifact,
            vulnerabilities=dependency.vulnerabilities,
            note=note,
        )
        applicable.append(ScopeEntry(dependency=dependency, basis=basis))

    applicable.sort(
        key=lambda item: (
            item.basis.canonical_name,
            item.basis.version or "",
            item.basis.describe(),
        )
    )
    unresolved.sort(key=lambda item: (item.package.lower(), item.detail))
    return tuple(applicable), tuple(unresolved)


def _parse_entries(raw: Any, target: str) -> tuple[InstalledDistribution, ...] | None:
    """Normalize one target value from a manifest or cache mapping."""

    if raw is None:
        return None
    if isinstance(raw, (str, Path)) and Path(raw).is_file():
        loaded = load_manifests(Path(raw))
        return loaded.get("default", next(iter(loaded.values())) if loaded else None)
    if isinstance(raw, Mapping):
        for key in ("packages", "installed", "dependencies", "entries"):
            if key in raw:
                return _parse_entries(raw[key], target)
    if isinstance(raw, (list, tuple)):
        return tuple(
            item
            if isinstance(item, InstalledDistribution)
            else InstalledDistribution.from_mapping(item)
            for item in raw
        )
    if isinstance(raw, Mapping):
        if "name" in raw or "package" in raw:
            return (InstalledDistribution.from_mapping(raw),)
        entries: list[InstalledDistribution] = []
        for package, value in raw.items():
            if isinstance(value, Mapping):
                entries.append(InstalledDistribution.from_mapping(value, default_name=str(package)))
            elif value is None:
                entries.append(InstalledDistribution(name=str(package)))
            else:
                version = _version(value)
                if version is not None:
                    entries.append(InstalledDistribution(name=str(package), version=version))
                else:
                    entries.append(
                        InstalledDistribution(
                            name=str(package),
                            artifact=ArtifactIdentity.from_value(value),
                        )
                    )
        return tuple(entries)
    raise ReconciliationError(f"target {target}: unsupported manifest or cache value")


def load_targets(source: Any) -> tuple[ReleaseTarget, ...]:
    """Load the declared release scope from JSON, TOML-like mapping or a path."""

    value = _load_json_source(source)
    if isinstance(value, Mapping):
        if "targets" in value:
            value = value["targets"]
        elif "scope" in value:
            value = value["scope"]
        elif "name" in value:
            value = [value]
    if not isinstance(value, (list, tuple)):
        raise ReconciliationError("release scope must contain a targets list")
    return tuple(ReleaseTarget.from_mapping(item) for item in value)


def load_manifests(source: Any) -> dict[str, tuple[InstalledDistribution, ...] | None]:
    """Load one installed-package manifest per target."""

    if isinstance(source, (str, Path)) and Path(source).is_dir():
        return {
            path.stem: load_manifests(path)["default"]
            for path in sorted(Path(source).glob("*.json"))
        }

    value = _load_json_source(source)
    result: dict[str, tuple[InstalledDistribution, ...] | None] = {}

    if isinstance(value, Mapping):
        if any(
            key in value for key in ("packages", "installed", "dependencies", "entries", "name")
        ):
            return {"default": _parse_entries(value, "default")}
        for target, raw in value.items():
            if target in {"scope", "targets"}:
                continue
            result[str(target)] = _parse_entries(raw, str(target))
    elif isinstance(value, list):
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for item in value:
            if not isinstance(item, Mapping):
                raise ReconciliationError("manifest list entries must be mappings")
            target = _text(item.get("target")) or "default"
            grouped.setdefault(target, []).append(item)
        for target, entries in grouped.items():
            result[target] = tuple(InstalledDistribution.from_mapping(item) for item in entries)
    else:
        raise ReconciliationError("manifests must be a mapping or a list")

    return result


def load_cache_map(source: Any) -> dict[str, tuple[InstalledDistribution, ...] | None]:
    """Load a simple build-cache mapping per target."""

    return load_manifests(source)


def _versions_in(values: Sequence[InstalledDistribution]) -> str:
    versions = sorted({str(item.version) if item.version else "unknown" for item in values})
    return ", ".join(versions)


def _same_artifact(
    expected: ArtifactIdentity | None, actual: ArtifactIdentity | None
) -> bool | None:
    if expected is None:
        return None
    return expected.same_as(actual)


def _compare_manifest(
    target: ReleaseTarget,
    expected: Sequence[ScopeEntry],
    installed: Sequence[InstalledDistribution],
) -> list[Finding]:
    findings: list[Finding] = []
    matched: set[int] = set()
    expected_names = {entry.basis.canonical_name for entry in expected}

    for entry in expected:
        basis = entry.basis
        artifact = entry.dependency.artifact
        if entry.dependency.skip_reason or basis.version is None:
            continue
        candidates = [item for item in installed if item.canonical_name == basis.canonical_name]
        if not candidates:
            findings.append(
                Finding(
                    kind=FindingKind.MISSING_INSTALL,
                    target=target.name,
                    package=basis.package,
                    detail="package is in the audited release scope but absent from the install manifest",
                    expected_version=basis.version,
                    expected_artifact=artifact,
                    basis=basis,
                )
            )
            continue

        if len(candidates) > 1:
            findings.append(
                Finding(
                    kind=FindingKind.AMBIGUOUS_MATCH,
                    target=target.name,
                    package=basis.package,
                    detail="manifest has several entries with this name; artifact identity was kept separate",
                    expected_version=basis.version,
                    actual_version=_versions_in(candidates),
                    expected_artifact=artifact,
                    basis=basis,
                )
            )

        same_version = [
            item
            for item in candidates
            if basis.version and item.version and str(item.version) == basis.version
        ]
        if artifact is None and same_version:
            for item in same_version:
                matched.add(id(item))
            continue
        exact = [item for item in same_version if _same_artifact(artifact, item.artifact) is True]
        if exact:
            for item in exact:
                matched.add(id(item))
            if len(exact) < len(candidates):
                findings.append(
                    Finding(
                        kind=FindingKind.AMBIGUOUS_MATCH,
                        target=target.name,
                        package=basis.package,
                        detail="only some same-name manifest entries carry the audited artifact",
                        expected_version=basis.version,
                        actual_version=_versions_in(candidates),
                        expected_artifact=artifact,
                        basis=basis,
                    )
                )
            continue

        if same_version:
            item = same_version[0]
            matched.add(id(item))
            comparison = _same_artifact(artifact, item.artifact)
            if comparison is False:
                findings.append(
                    Finding(
                        kind=FindingKind.INSTALLED_ARTIFACT_MISMATCH,
                        target=target.name,
                        package=basis.package,
                        detail="version matches but the installed artifact is not the audited artifact",
                        expected_version=basis.version,
                        actual_version=str(item.version) if item.version else None,
                        expected_artifact=artifact,
                        actual_artifact=item.artifact,
                        basis=basis,
                    )
                )
            else:
                findings.append(
                    Finding(
                        kind=FindingKind.UNVERIFIED_ARTIFACT,
                        target=target.name,
                        package=basis.package,
                        detail="version matches but artifact identity is missing on one side",
                        expected_version=basis.version,
                        actual_version=str(item.version) if item.version else None,
                        expected_artifact=artifact,
                        actual_artifact=item.artifact,
                        basis=basis,
                    )
                )
            continue

        for item in candidates:
            matched.add(id(item))
        findings.append(
            Finding(
                kind=FindingKind.INSTALLED_VERSION_MISMATCH,
                target=target.name,
                package=basis.package,
                detail="installed version does not match the audited release scope",
                expected_version=basis.version,
                actual_version=_versions_in(candidates),
                expected_artifact=artifact,
                basis=basis,
            )
        )

    for item in installed:
        if id(item) in matched:
            continue
        if item.canonical_name not in expected_names:
            findings.append(
                Finding(
                    kind=FindingKind.UNEXPECTED_INSTALL,
                    target=target.name,
                    package=item.name,
                    detail="installed package is not in the audited release scope for this target",
                    actual_version=str(item.version) if item.version else None,
                    actual_artifact=item.artifact,
                )
            )

    return findings


def _compare_cache(
    target: ReleaseTarget,
    expected: Sequence[ScopeEntry],
    cached: Sequence[InstalledDistribution],
) -> list[Finding]:
    findings: list[Finding] = []

    for entry in expected:
        basis = entry.basis
        artifact = entry.dependency.artifact
        if entry.dependency.skip_reason or basis.version is None:
            continue
        expected_version = _version(basis.version)
        candidates = [item for item in cached if item.canonical_name == basis.canonical_name]
        if not candidates:
            findings.append(
                Finding(
                    kind=FindingKind.MISSING_PACKAGE_CACHE_MAPPING,
                    target=target.name,
                    package=basis.package,
                    detail="no build-cache mapping for this audited package",
                    expected_version=basis.version,
                    expected_artifact=artifact,
                    basis=basis,
                )
            )
            continue

        if artifact is None and expected_version is not None:
            same = [item for item in candidates if item.version == expected_version]
            if same:
                continue

        exact = [
            item
            for item in candidates
            if expected_version is not None
            and item.version == expected_version
            and _same_artifact(artifact, item.artifact) is True
        ]
        if len(exact) == 1:
            continue
        if len(exact) > 1:
            findings.append(
                Finding(
                    kind=FindingKind.AMBIGUOUS_MATCH,
                    target=target.name,
                    package=basis.package,
                    detail="build cache has several entries matching this artifact",
                    expected_version=basis.version,
                    actual_version=_versions_in(candidates),
                    expected_artifact=artifact,
                    basis=basis,
                )
            )
            continue

        same_version = [
            item
            for item in candidates
            if expected_version is not None and item.version == expected_version
        ]
        if same_version:
            item = same_version[0]
            comparison = _same_artifact(artifact, item.artifact)
            if comparison is False:
                findings.append(
                    Finding(
                        kind=FindingKind.STALE_CACHE_ARTIFACT,
                        target=target.name,
                        package=basis.package,
                        detail="build cache has the audited version but a different artifact",
                        expected_version=basis.version,
                        actual_version=str(item.version) if item.version else None,
                        expected_artifact=artifact,
                        actual_artifact=item.artifact,
                        basis=basis,
                    )
                )
            else:
                findings.append(
                    Finding(
                        kind=FindingKind.UNVERIFIED_ARTIFACT,
                        target=target.name,
                        package=basis.package,
                        detail="build cache version matches but artifact identity is not fully known",
                        expected_version=basis.version,
                        actual_version=str(item.version) if item.version else None,
                        expected_artifact=artifact,
                        actual_artifact=item.artifact,
                        basis=basis,
                    )
                )
            continue

        item = candidates[0]
        kind = FindingKind.CACHE_VERSION_MISMATCH
        if (
            expected_version is not None
            and item.version is not None
            and item.version < expected_version
        ):
            kind = FindingKind.STALE_CACHE
        findings.append(
            Finding(
                kind=kind,
                target=target.name,
                package=basis.package,
                detail="build cache does not hold the audited artifact",
                expected_version=basis.version,
                actual_version=str(item.version) if item.version else None,
                expected_artifact=artifact,
                actual_artifact=item.artifact,
                basis=basis,
            )
        )

    return findings


@dataclass(frozen=True)
class TargetReconciliation:
    """All landing evidence for one release target."""

    target: ReleaseTarget
    expected: tuple[DependencyBasis, ...]
    findings: tuple[Finding, ...]
    unresolved: tuple[Finding, ...] = ()
    manifest_present: bool = True
    cache_mapping_present: bool = True

    @property
    def stale_cache_findings(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.kind in CACHE_FINDINGS)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.name,
            "kind": self.target.kind,
            "desktop": self.target.is_desktop,
            "architecture": self.target.architecture,
            "platform": self.target.platform,
            "extras": sorted(self.target.extras),
            "manifest_present": self.manifest_present,
            "cache_mapping_present": self.cache_mapping_present,
            "dependencies": [basis.as_dict() for basis in self.expected],
            "findings": [finding.as_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class ReconciliationReport:
    """The complete offline landing-verification report."""

    targets: tuple[TargetReconciliation, ...]

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(finding for target in self.targets for finding in target.findings)

    @property
    def unresolved(self) -> tuple[Finding, ...]:
        return tuple(finding for target in self.targets for finding in target.unresolved)

    def _record(self, name: str) -> TargetReconciliation | None:
        return next((target for target in self.targets if target.target.name == name), None)

    @property
    def stale_cache_findings(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.kind in CACHE_FINDINGS)

    @property
    def _desktop_names(self) -> set[str]:
        return {target.target.name for target in self.targets if target.target.is_desktop}

    @property
    def old_cache_findings(self) -> tuple[Finding, ...]:
        kinds = {FindingKind.STALE_CACHE, FindingKind.CACHE_VERSION_MISMATCH}
        return tuple(finding for finding in self.findings if finding.kind in kinds)

    @property
    def desktop_old_cache_findings(self) -> tuple[Finding, ...]:
        desktop = self._desktop_names
        return tuple(finding for finding in self.old_cache_findings if finding.target in desktop)

    @property
    def other_old_cache_findings(self) -> tuple[Finding, ...]:
        desktop = self._desktop_names
        return tuple(
            finding for finding in self.old_cache_findings if finding.target not in desktop
        )

    @property
    def desktop_artifact_cache_findings(self) -> tuple[Finding, ...]:
        desktop = self._desktop_names
        return tuple(
            finding
            for finding in self.findings
            if finding.kind is FindingKind.STALE_CACHE_ARTIFACT and finding.target in desktop
        )

    @property
    def desktop_stale_cache_findings(self) -> tuple[Finding, ...]:
        desktop = self._desktop_names
        return tuple(finding for finding in self.stale_cache_findings if finding.target in desktop)

    @property
    def missing_manifest_findings(self) -> tuple[Finding, ...]:
        return tuple(
            finding for finding in self.findings if finding.kind is FindingKind.MISSING_MANIFEST
        )

    @property
    def missing_cache_mapping_findings(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.kind in MAPPING_FINDINGS)

    @property
    def has_blocking_findings(self) -> bool:
        return bool(self.findings or self.unresolved)

    def as_dict(self) -> dict[str, Any]:
        desktop_stale: list[dict[str, Any]] = []
        for finding in self.desktop_old_cache_findings:
            record = self._record(finding.target)
            target = record.target if record else None
            desktop_stale.append(
                {
                    "target": finding.target,
                    "architecture": target.architecture if target else None,
                    "platform": target.platform if target else None,
                    "package": finding.package,
                    "expected_version": finding.expected_version,
                    "actual_version": finding.actual_version,
                    "expected_artifact": finding.expected_artifact.describe()
                    if finding.expected_artifact
                    else None,
                    "actual_artifact": finding.actual_artifact.describe()
                    if finding.actual_artifact
                    else None,
                    "basis": finding.basis.describe() if finding.basis else None,
                    "detail": finding.detail,
                }
            )

        missing_manifests: list[dict[str, Any]] = []
        for finding in self.missing_manifest_findings:
            record = self._record(finding.target)
            target = record.target if record else None
            missing_manifests.append(
                {
                    "target": finding.target,
                    "kind": target.kind if target else None,
                    "architecture": target.architecture if target else None,
                    "platform": target.platform if target else None,
                    "dependencies": [basis.as_dict() for basis in record.expected]
                    if record
                    else [],
                    "basis": [basis.describe() for basis in record.expected] if record else [],
                }
            )

        return {
            "summary": {
                "targets": len(self.targets),
                "desktop_stale_cache": len(desktop_stale),
                "missing_install_manifests": len(missing_manifests),
                "missing_cache_mappings": len(self.missing_cache_mapping_findings),
                "unresolved_markers": len(self.unresolved),
            },
            "desktop_stale_cache": desktop_stale,
            "desktop_cache_artifact_findings": [
                finding.as_dict() for finding in self.desktop_artifact_cache_findings
            ],
            "other_stale_cache_findings": [
                finding.as_dict() for finding in self.other_old_cache_findings
            ],
            "missing_install_manifests": missing_manifests,
            "missing_cache_mappings": [
                finding.as_dict() for finding in self.missing_cache_mapping_findings
            ],
            "artifact_findings": [
                finding.as_dict()
                for finding in self.findings
                if finding.kind
                in {
                    FindingKind.STALE_CACHE_ARTIFACT,
                    FindingKind.INSTALLED_ARTIFACT_MISMATCH,
                    FindingKind.UNVERIFIED_ARTIFACT,
                    FindingKind.AMBIGUOUS_MATCH,
                }
            ],
            "targets": [target.as_dict() for target in self.targets],
            "findings": [finding.as_dict() for finding in self.findings],
        }

    def _target_label(self, name: str) -> str:
        record = self._record(name)
        if record is None:
            return name
        target = record.target
        details: list[str] = []
        if target.architecture:
            details.append(target.architecture)
        if target.platform:
            details.append(target.platform)
        if target.kind:
            details.append(target.kind)
        return name + (" (" + ", ".join(details) + ")" if details else "")

    def render_text(self) -> str:
        """Render the reviewer-facing landing check."""

        lines: list[str] = [
            "Landing verification",
            "====================",
            f"Targets checked: {len(self.targets)}",
        ]
        if not self.findings and not self.unresolved:
            lines.append("All declared targets match the audited release scope and build cache.")
            return "\n".join(lines)

        lines.extend(["", "Desktop architectures on an old build cache:"])
        if not self.desktop_old_cache_findings:
            lines.append("- none")
        for finding in self.desktop_old_cache_findings:
            lines.append(
                f"- {self._target_label(finding.target)}: {finding.package} "
                "audit=%s cache=%s"
                % (finding.expected_version or "unknown", finding.actual_version or "unknown")
            )
            if finding.detail:
                lines.append(f"  detail: {finding.detail}")
            if finding.expected_artifact and finding.actual_artifact:
                lines.append(
                    "  artifact: audit="
                    + (finding.expected_artifact.describe() or "unknown")
                    + " cache="
                    + (finding.actual_artifact.describe() or "unknown")
                )
            if finding.basis:
                lines.append(f"  basis: {finding.basis.describe()}")

        lines.extend(["", "Desktop architectures with a non-audited cache artifact:"])
        if not self.desktop_artifact_cache_findings:
            lines.append("- none")
        for finding in self.desktop_artifact_cache_findings:
            lines.append(
                f"- {self._target_label(finding.target)}: {finding.package} "
                "audit=%s cache=%s"
                % (finding.expected_version or "unknown", finding.actual_version or "unknown")
            )
            if finding.expected_artifact and finding.actual_artifact:
                lines.append(
                    "  artifact: audit="
                    + (finding.expected_artifact.describe() or "unknown")
                    + " cache="
                    + (finding.actual_artifact.describe() or "unknown")
                )
            if finding.basis:
                lines.append(f"  basis: {finding.basis.describe()}")

        lines.extend(["", "Targets without an install manifest:"])
        if not self.missing_manifest_findings:
            lines.append("- none")
        for finding in self.missing_manifest_findings:
            record = self._record(finding.target)
            lines.append(f"- {self._target_label(finding.target)}")
            if record is None or not record.expected:
                lines.append("  recheck: no audited dependencies apply to this target")
            else:
                lines.extend(f"  recheck: {basis.describe()}" for basis in record.expected)

        lines.extend(["", "Missing cache mappings (listed separately):"])
        if not self.missing_cache_mapping_findings:
            lines.append("- none")
        for finding in self.missing_cache_mapping_findings:
            if finding.kind is FindingKind.MISSING_CACHE_MAPPING:
                lines.append(
                    f"- {self._target_label(finding.target)}: no build-cache entry for this target"
                )
            else:
                lines.append(
                    f"- {self._target_label(finding.target)}: {finding.package} "
                    "(audit %s) has no cache mapping" % (finding.expected_version or "unknown")
                )
            if finding.basis:
                lines.append(f"  basis: {finding.basis.describe()}")

        lines.extend(["", "Other targets on an old build cache:"])
        if not self.other_old_cache_findings:
            lines.append("- none")
        for finding in self.other_old_cache_findings:
            lines.append(
                f"- {self._target_label(finding.target)}: {finding.package} "
                "audit=%s cache=%s"
                % (finding.expected_version or "unknown", finding.actual_version or "unknown")
            )
            if finding.basis:
                lines.append(f"  basis: {finding.basis.describe()}")

        other = [
            finding
            for finding in self.findings
            if finding.kind not in CACHE_FINDINGS
            and finding.kind not in MAPPING_FINDINGS
            and finding.kind is not FindingKind.MISSING_MANIFEST
        ]
        if other or self.unresolved:
            lines.extend(["", "Other findings requiring review:"])
            lines.extend(
                f"- {self._target_label(finding.target)}: {finding.package}: {finding.detail}"
                for finding in other
            )
            lines.extend(
                f"- {self._target_label(finding.target)}: {finding.package}: {finding.detail}"
                for finding in self.unresolved
            )

        return "\n".join(lines)


def reconcile(
    audit: AuditReport | Any,
    manifests: Any,
    cache_map: Any,
    targets: Sequence[ReleaseTarget] | Any | None = None,
) -> ReconciliationReport:
    """Reconcile an existing audit report with install manifests and a cache map."""

    audit_report = audit if isinstance(audit, AuditReport) else AuditReport.load(audit)
    manifest_map = load_manifests(manifests)
    cache_entries = load_cache_map(cache_map)

    if targets is None:
        target_list = list(audit_report.targets)
        if not target_list:
            scope_value = None
            for source in (manifests, cache_map):
                try:
                    raw_source = _load_json_source(source)
                except ReconciliationError:
                    continue
                if isinstance(raw_source, Mapping):
                    scope_value = raw_source.get("scope") or raw_source.get("targets")
                    if scope_value:
                        break
            if scope_value:
                target_list = list(load_targets(scope_value))
        if not target_list:
            names = sorted(set(manifest_map) | set(cache_entries))
            target_list = [ReleaseTarget(name=name) for name in names]
    elif isinstance(targets, (str, Path, Mapping)):
        target_list = list(load_targets(targets))
    else:
        candidate_targets = list(targets)
        if candidate_targets and all(isinstance(item, ReleaseTarget) for item in candidate_targets):
            target_list = candidate_targets
        else:
            target_list = list(load_targets(candidate_targets))

    records: list[TargetReconciliation] = []
    for target in sorted(target_list, key=lambda item: item.name):
        expected_entries, unresolved = expand_scope(audit_report, target)
        expected = tuple(entry.basis for entry in expected_entries)
        findings: list[Finding] = list(unresolved)

        manifest_present = target.name in manifest_map and manifest_map[target.name] is not None
        if not manifest_present:
            findings.append(
                Finding(
                    kind=FindingKind.MISSING_MANIFEST,
                    target=target.name,
                    package="(install manifest)",
                    detail="no installed-package manifest was supplied for this target",
                )
            )
        else:
            findings.extend(
                _compare_manifest(target, expected_entries, manifest_map[target.name] or ())
            )

        cache_present = target.name in cache_entries and cache_entries[target.name] is not None
        if not cache_present:
            findings.append(
                Finding(
                    kind=FindingKind.MISSING_CACHE_MAPPING,
                    target=target.name,
                    package="(build cache)",
                    detail="no build-cache mapping was supplied for this target",
                )
            )
        else:
            findings.extend(
                _compare_cache(target, expected_entries, cache_entries[target.name] or ())
            )

        findings.sort(key=lambda item: (str(item.kind), item.package.lower(), item.detail))
        records.append(
            TargetReconciliation(
                target=target,
                expected=expected,
                findings=tuple(findings),
                unresolved=unresolved,
                manifest_present=manifest_present,
                cache_mapping_present=cache_present,
            )
        )

    return ReconciliationReport(targets=tuple(records))


def _manifest_argument(value: str) -> tuple[str, str | None]:
    target, separator, path = value.partition("=")
    if not separator or not target:
        raise argparse.ArgumentTypeError("manifest must be written as TARGET=PATH")
    return target, path or None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pip_audit._reconcile",
        description="reconcile an existing pip-audit report with release install manifests",
    )
    parser.add_argument("--audit", required=True, help="existing pip-audit JSON report")
    parser.add_argument("--scope", help="release scope with target markers and enabled extras")
    parser.add_argument(
        "--manifest",
        action="append",
        default=[],
        type=_manifest_argument,
        metavar="TARGET=PATH",
        help="installed-package manifest per target; repeat for each target",
    )
    parser.add_argument("--cache-map", help="simple build-cache mapping per target")
    parser.add_argument("--json", action="store_true", help="emit the structured JSON report")
    parser.add_argument("--output", type=Path, help="write the report to this path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline landing-verification step."""

    args = _parser().parse_args(argv)
    audit = AuditReport.load(args.audit)
    targets = load_targets(args.scope) if args.scope else (audit.targets or None)

    if targets is None:
        for _target, path in args.manifest:
            if path is None:
                continue
            raw_manifest = json.loads(Path(path).read_text())
            if isinstance(raw_manifest, Mapping):
                scope_value = raw_manifest.get("scope") or raw_manifest.get("targets")
                if scope_value:
                    targets = load_targets(scope_value)
                    break

    manifests: dict[str, tuple[InstalledDistribution, ...] | None] = {}
    for target, path in args.manifest:
        if path is None:
            manifests[target] = None
            continue
        loaded = load_manifests(path)
        manifests[target] = loaded.get(target, loaded.get("default"))

    cache_map: Any = args.cache_map if args.cache_map else {}

    report = reconcile(audit, manifests, cache_map, targets)
    output = (
        json.dumps(report.as_dict(), indent=2, sort_keys=True)
        if args.json
        else report.render_text()
    )

    if args.output:
        args.output.write_text(output + "\n")
    else:
        print(output)
    return 1 if report.has_blocking_findings else 0


if __name__ == "__main__":
    sys.exit(main())
