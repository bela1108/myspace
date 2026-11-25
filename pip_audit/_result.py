"""
Partial-audit result models and source snapshot persistence.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from packaging.version import Version

from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
)
from pip_audit._service.status import (
    CacheStatus,
    SourceSnapshot,
    _utc_now,
)


def fingerprint_dependencies(specs: Iterable[Dependency]) -> str:
    """
    Build a stable fingerprint for one audited dependency set.
    """
    material: list[dict[str, str]] = []
    for spec in specs:
        item = {
            "canonical_name": spec.canonical_name,
            "kind": spec.__class__.__name__,
        }
        if isinstance(spec, ResolvedDependency):
            item["version"] = str(spec.version)
        elif isinstance(spec, SkippedDependency):
            item["skip_reason"] = spec.skip_reason
        material.append(item)

    material.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    encoded = json.dumps(material, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def dependency_to_dict(dep: Dependency) -> dict[str, Any]:
    """
    Serialize a dependency to the stable JSON dependency shape.
    """
    if isinstance(dep, SkippedDependency):
        return {
            "name": dep.canonical_name,
            "skip_reason": dep.skip_reason,
        }
    if isinstance(dep, ResolvedDependency):
        return {
            "name": dep.canonical_name,
            "version": str(dep.version),
        }
    return {"name": dep.canonical_name}


@dataclass(frozen=True)
class UnqueriedDependency:
    """
    A dependency/source pair that was not successfully queried.
    """

    dependency: Dependency
    reason: str
    source: str | None = None
    checked_at: datetime = field(default_factory=_utc_now)

    @property
    def name(self) -> str:
        """
        Return the dependency's uncanonicalized name.
        """
        return self.dependency.name

    @property
    def canonical_name(self) -> str:
        """
        Return the dependency's canonicalized name.
        """
        return self.dependency.canonical_name

    @property
    def version(self) -> Version | None:
        """
        Return the resolved version, when the dependency has one.
        """
        if isinstance(self.dependency, ResolvedDependency):
            return self.dependency.version
        return None

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize this unqueried object to a JSON-compatible dictionary.
        """
        return {
            "dependency": dependency_to_dict(self.dependency),
            "name": self.dependency.canonical_name,
            "version": str(self.version) if self.version is not None else None,
            "source": self.source,
            "reason": self.reason,
            "checked_at": self.checked_at.isoformat(),
        }


class AuditResult:
    """
    Segmented audit outcome: sources, caches, vulnerabilities and unqueried objects.
    """

    def __init__(
        self,
        results: dict[Dependency, list[VulnerabilityResult]] | None = None,
        *,
        sources: dict[str, SourceSnapshot] | None = None,
        cache_statuses: dict[str, CacheStatus] | None = None,
        unqueried: list[UnqueriedDependency] | None = None,
        input_digest: str | None = None,
        vulnerabilities: dict[Dependency, list[VulnerabilityResult]] | None = None,
        confirmed_vulnerabilities: dict[Dependency, list[VulnerabilityResult]] | None = None,
        source_statuses: dict[str, SourceSnapshot] | None = None,
        source_availability: dict[str, SourceSnapshot] | None = None,
        cache_freshness: dict[str, CacheStatus] | None = None,
        unqueried_objects: list[UnqueriedDependency] | None = None,
    ) -> None:
        """
        Create a segmented audit result.

        Alias keyword arguments are accepted for the vocabulary used in the feature
        request, while `results`, `sources`, `cache_statuses`, and `unqueried` are the
        canonical fields.
        """
        chosen_results = results if results is not None else vulnerabilities
        if chosen_results is None and confirmed_vulnerabilities is not None:
            chosen_results = confirmed_vulnerabilities
        self.results: dict[Dependency, list[VulnerabilityResult]] = dict(chosen_results or {})

        chosen_sources = sources if sources is not None else source_statuses
        if chosen_sources is None:
            chosen_sources = source_availability
        self.sources: dict[str, SourceSnapshot] = dict(chosen_sources or {})

        chosen_caches = cache_statuses if cache_statuses is not None else cache_freshness
        if chosen_caches is None:
            chosen_caches = {
                name: snapshot.cache
                for name, snapshot in self.sources.items()
                if snapshot.cache is not None
            }
        self.cache_statuses: dict[str, CacheStatus] = dict(chosen_caches)

        chosen_unqueried = unqueried if unqueried is not None else unqueried_objects
        self.unqueried: list[UnqueriedDependency] = list(chosen_unqueried or [])
        self.input_digest = input_digest

    @property
    def dependencies(self) -> dict[Dependency, list[VulnerabilityResult]]:
        """
        Return successfully queried dependencies and their results.
        """
        return self.results

    @property
    def vulnerabilities(self) -> dict[Dependency, list[VulnerabilityResult]]:
        """
        Alias for `results`, preserving mapping-style result access.
        """
        return self.results

    @property
    def confirmed_vulnerabilities(self) -> dict[Dependency, list[VulnerabilityResult]]:
        """
        Return only dependencies with at least one confirmed vulnerability.
        """
        return {dep: vulns for dep, vulns in self.results.items() if vulns}

    @property
    def source_statuses(self) -> dict[str, SourceSnapshot]:
        """
        Alias for `sources`.
        """
        return self.sources

    @property
    def source_availability(self) -> dict[str, SourceSnapshot]:
        """
        Alias for `sources`.
        """
        return self.sources

    @property
    def cache_freshness(self) -> dict[str, CacheStatus]:
        """
        Alias for `cache_statuses`.
        """
        return self.cache_statuses

    @property
    def unqueried_objects(self) -> list[UnqueriedDependency]:
        """
        Alias for `unqueried`.
        """
        return self.unqueried

    @property
    def unqueried_dependencies(self) -> list[UnqueriedDependency]:
        """
        Alias for `unqueried`.
        """
        return self.unqueried

    @property
    def incomplete(self) -> bool:
        """
        Return whether any source/dependency pair was not fully queried.
        """
        return bool(self.unqueried) or any(not source.available for source in self.sources.values())

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize source, cache and unqueried segments. Vulnerability formatting is
        left to formatters because description and alias options are user-controlled.
        """
        return {
            "input_digest": self.input_digest,
            "sources": {name: source.to_dict() for name, source in self.sources.items()},
            "cache_freshness": {
                name: cache.to_dict() for name, cache in self.cache_statuses.items()
            },
            "unqueried": [item.to_dict() for item in self.unqueried],
            "unqueried_objects": [item.to_dict() for item in self.unqueried],
        }

    def __getitem__(self, key: str) -> Any:
        segments = {
            "results": self.results,
            "dependencies": self.results,
            "sources": self.sources,
            "source_availability": self.sources,
            "source_statuses": self.sources,
            "cache": self.cache_statuses,
            "cache_statuses": self.cache_statuses,
            "cache_freshness": self.cache_statuses,
            "vulnerabilities": self.confirmed_vulnerabilities,
            "confirmed_vulnerabilities": self.confirmed_vulnerabilities,
            "unqueried": self.unqueried,
            "unqueried_objects": self.unqueried,
            "unqueried_dependencies": self.unqueried,
            "input_digest": self.input_digest,
        }
        if key not in segments:
            raise KeyError(key)
        return segments[key]

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


class AuditReport(dict[Dependency, list[VulnerabilityResult]]):
    """
    A legacy result mapping carrying the new segmented `AuditResult`.
    """

    def __init__(
        self,
        audit_result: AuditResult | dict[Dependency, list[VulnerabilityResult]] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Create a mapping view over an `AuditResult`.
        """
        if isinstance(audit_result, AuditResult):
            result = audit_result
        else:
            result = AuditResult(audit_result, *args, **kwargs)
        super().__init__(result.results)
        self.audit_result = result

    def __setitem__(self, key: Dependency, value: list[VulnerabilityResult]) -> None:
        """
        Keep the segmented model synchronized with mapping-style updates.
        """
        super().__setitem__(key, value)
        self.audit_result.results[key] = value

    def __getitem__(self, key: Dependency | str) -> Any:
        if isinstance(key, str):
            return self.audit_result[key]
        return super().__getitem__(key)

    def get(self, key: Dependency | str, default: Any = None) -> Any:
        if isinstance(key, str):
            return self.audit_result.get(key, default)
        return super().get(key, default)

    @property
    def sources(self) -> dict[str, SourceSnapshot]:
        """
        Return source availability snapshots.
        """
        return self.audit_result.sources

    @property
    def cache_statuses(self) -> dict[str, CacheStatus]:
        """
        Return cache freshness statuses.
        """
        return self.audit_result.cache_statuses

    @property
    def unqueried(self) -> list[UnqueriedDependency]:
        """
        Return unqueried source/dependency pairs.
        """
        return self.audit_result.unqueried

    @property
    def input_digest(self) -> str | None:
        """
        Return the fingerprint of the audited input.
        """
        return self.audit_result.input_digest

    @property
    def incomplete(self) -> bool:
        """
        Return whether the report has unavailable sources or unqueried objects.
        """
        return self.audit_result.incomplete


# Descriptive aliases for callers naming the richer model directly.
ResultModel = AuditResult
AuditOutcome = AuditResult
SegmentedAuditResult = AuditResult
PartialAuditResult = AuditReport
PartialAuditReport = AuditReport


class SnapshotStore:
    """
    Persist and preserve source snapshots keyed by dependency-input fingerprint.
    """

    VERSION = 1

    def __init__(self, path: str | Path | None = None) -> None:
        """
        Create a store at `path`. When `path` is `None`, snapshots live only in memory.
        """
        self.path = Path(path) if path is not None else None
        self._data: dict[str, Any] = {"version": self.VERSION, "inputs": {}}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.path is None or not self.path.is_file():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(loaded, dict) and isinstance(loaded.get("inputs"), dict):
            self._data = loaded

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                json.dump(self._data, temporary, sort_keys=True, ensure_ascii=False)
            Path(temporary_name).replace(self.path)
        except OSError:
            if temporary_name is not None:
                try:
                    Path(temporary_name).unlink()
                except OSError:
                    pass

    def preserve(
        self,
        input_digest: str,
        snapshots: dict[str, SourceSnapshot],
    ) -> dict[str, SourceSnapshot]:
        """
        Merge current snapshots with any prior snapshot for the same input.
        """
        self._load()
        now = _utc_now()
        inputs = self._data.setdefault("inputs", {})
        input_entry = inputs.setdefault(
            input_digest,
            {"first_run_at": now.isoformat(), "sources": {}},
        )
        previous_sources = input_entry.setdefault("sources", {})
        preserved: dict[str, SourceSnapshot] = {}

        for name, snapshot in snapshots.items():
            snapshot = replace(snapshot, input_digest=input_digest)
            previous_data = previous_sources.get(name)
            if isinstance(previous_data, dict):
                previous = SourceSnapshot.from_dict(previous_data)
                snapshot_id = previous.snapshot_id or _stable_snapshot_id(input_digest, name)
                first_observed_at = previous.first_observed_at or previous.checked_at
                last_successful_at = snapshot.last_successful_at
                if last_successful_at is None and snapshot.available:
                    last_successful_at = snapshot.checked_at
                if last_successful_at is None:
                    last_successful_at = previous.last_successful_at
                if last_successful_at is None and previous.available:
                    last_successful_at = previous.checked_at

                last_known_good = snapshot.last_known_good
                if last_known_good is None and not snapshot.available:
                    last_known_good = previous if previous.available else previous.last_known_good

                snapshot = replace(
                    snapshot,
                    snapshot_id=snapshot_id,
                    first_observed_at=first_observed_at,
                    last_successful_at=last_successful_at,
                    last_known_good=last_known_good,
                )
            else:
                snapshot = replace(
                    snapshot,
                    snapshot_id=_stable_snapshot_id(input_digest, name),
                    first_observed_at=snapshot.checked_at,
                    last_successful_at=snapshot.checked_at if snapshot.available else None,
                )

            preserved[name] = snapshot
            previous_sources[name] = snapshot.to_dict()

        input_entry["last_run_at"] = now.isoformat()
        self._save()
        return preserved

    def load_snapshots(self, input_digest: str) -> dict[str, SourceSnapshot]:
        """
        Load stored source snapshots for one input fingerprint.
        """
        self._load()
        entry = self._data.get("inputs", {}).get(input_digest, {})
        sources = entry.get("sources", {}) if isinstance(entry, dict) else {}
        return {
            name: SourceSnapshot.from_dict(data)
            for name, data in sources.items()
            if isinstance(data, dict)
        }


def _stable_snapshot_id(input_digest: str, source_name: str) -> str:
    return hashlib.sha256(f"{input_digest}:{source_name}".encode()).hexdigest()[:16]


SourceSnapshotStore = SnapshotStore
UnqueriedObject = UnqueriedDependency
UnqueriedPackage = UnqueriedDependency
ConfirmedVulnerability = VulnerabilityResult
Snapshot = SourceSnapshot


__all__ = [
    "AuditReport",
    "AuditResult",
    "AuditOutcome",
    "ConfirmedVulnerability",
    "PartialAuditResult",
    "PartialAuditReport",
    "ResultModel",
    "SegmentedAuditResult",
    "SnapshotStore",
    "SourceSnapshotStore",
    "Snapshot",
    "UnqueriedDependency",
    "UnqueriedObject",
    "UnqueriedPackage",
    "dependency_to_dict",
    "fingerprint_dependencies",
]
