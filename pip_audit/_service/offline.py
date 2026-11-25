"""
Offline, versioned vulnerability advisory snapshots.

An `AdvisorySnapshot` is an immutable view of a vulnerability data source at a
single point in time, identified by a data-source `version`. Snapshots live on
disk instead of behind a network call, which makes advisory revisions (for
example, a previously merged CVE/GHSA pair being split into two records)
deterministic and auditable.

The `OfflineSnapshotService` wraps a snapshot and implements the normal
`VulnerabilityService` interface, while also exposing withdrawn advisories and
the snapshot's data-source version to the audit layer.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, cast

from packaging.utils import canonicalize_name
from packaging.version import Version
from packaging.version import parse as parse_version

from pip_audit._service.interface import (
    ConnectionError,
    Dependency,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)

PackageKey: TypeAlias = tuple[str, str]
"""
A canonical package name paired with a concrete version string.
"""


@dataclass(frozen=True)
class AdvisoryEntry:
    """
    A single advisory record within an `AdvisorySnapshot`.

    Unlike a `VulnerabilityResult`, an `AdvisoryEntry` retains its withdrawn
    state instead of filtering it out, so callers can distinguish a retracted
    advisory from a missing one.
    """

    id: str
    """
    The advisory's primary identifier.
    """

    aliases: frozenset[str]
    """
    Alternative identifiers associated with this advisory in this snapshot.
    """

    description: str
    """
    A human-readable description of the advisory.
    """

    fix_versions: tuple[Version, ...]
    """
    Versions that resolve the advisory.
    """

    withdrawn: bool = False
    """
    Whether the advisory has been withdrawn in this snapshot.
    """

    def to_result(self) -> VulnerabilityResult:
        """
        Convert this entry into a normal `VulnerabilityResult`.
        """

        return VulnerabilityResult.create(
            ids=[self.id, *sorted(self.aliases)],
            description=self.description,
            fix_versions=list(self.fix_versions),
            published=None,
        )


@dataclass(frozen=True)
class SnapshotFeedResult:
    """
    The structured answer of one snapshot for one package/version pair.

    `active` and `withdrawn` are kept separate so that the audit layer can
    emit distinct outcomes for a retracted advisory and an unreachable feed.
    """

    source: str
    """
    The name of the data source that produced the snapshot.
    """

    source_version: str
    """
    The data-source version embedded in the snapshot.
    """

    active: tuple[VulnerabilityResult, ...]
    """
    Advisories that currently apply to the queried package/version.
    """

    withdrawn: tuple[VulnerabilityResult, ...]
    """
    Advisories that exist but have been withdrawn.
    """

    unavailable: bool = False
    """
    Whether this feed was temporarily unreachable for the query.
    """

    @classmethod
    def make_unavailable(cls, source: str, source_version: str) -> SnapshotFeedResult:
        """
        Build a placeholder result representing an unreachable feed.
        """

        return cls(source, source_version, (), (), unavailable=True)


@dataclass(frozen=True)
class AdvisorySnapshot:
    """
    An immutable, versioned collection of offline advisory records.

    Records are keyed by canonical package name and exact version. A key that
    is marked unavailable models a service that cannot currently answer for
    that package/version, which is distinct from having no advisories.
    """

    source: str
    """
    The data source's name.
    """

    version: str
    """
    The data source's version (e.g. an export timestamp or revision tag).
    """

    entries: Mapping[PackageKey, tuple[AdvisoryEntry, ...]]
    """
    Advisory records keyed by `(canonical package name, version string)`.
    """

    unavailable: frozenset[PackageKey] = frozenset()
    """
    Package/version pairs for which the feed is temporarily unreachable.
    """

    @staticmethod
    def _key(dep: ResolvedDependency) -> PackageKey:
        """
        Build the canonical  lookup key for a dependency.
        """

        return dep.canonical_name, str(dep.version)

    @classmethod
    def from_json(cls, path: Path | str) -> AdvisorySnapshot:
        """
        Load a snapshot from a JSON file.

        The schema is::

            {
              "source": "osv-offline",
              "version": "2026-11-01",
              "packages": {
                "foo": {
                  "1.0.0": {
                    "unavailable": false,
                    "advisories": [
                      {
                        "id": "CVE-2026-0001",
                        "aliases": ["GHSA-aaaa-bbbb-cccc"],
                        "description": "...",
                        "fix_versions": ["1.1.0"],
                        "withdrawn": false
                      }
                    ]
                  }
                }
              }
            }
        """

        snapshot_path = Path(path)
        payload = json.loads(snapshot_path.read_text(encoding="utf-8"))

        entries: dict[PackageKey, tuple[AdvisoryEntry, ...]] = {}
        unavailable: set[PackageKey] = set()

        for raw_name, versions in payload["packages"].items():
            package = canonicalize_name(raw_name)
            for raw_version, body in versions.items():
                key = (package, raw_version)
                if body.get("unavailable", False):
                    unavailable.add(key)
                    continue

                records = tuple(
                    AdvisoryEntry(
                        id=advisory["id"],
                        aliases=frozenset(advisory.get("aliases", ())),
                        description=advisory.get("description", "N/A"),
                        fix_versions=tuple(
                            parse_version(version) for version in advisory.get("fix_versions", ())
                        ),
                        withdrawn=advisory.get("withdrawn", False),
                    )
                    for advisory in body.get("advisories", ())
                )
                entries[key] = records

        return cls(
            source=payload["source"],
            version=payload["version"],
            entries=entries,
            unavailable=frozenset(unavailable),
        )

    def lookup(self, dep: ResolvedDependency) -> SnapshotFeedResult:
        """
        Return the structured feed result for a resolved dependency.
        """

        key = self._key(dep)
        if key in self.unavailable:
            return SnapshotFeedResult.make_unavailable(self.source, self.version)

        records = self.entries.get(key, ())
        active = tuple(record.to_result() for record in records if not record.withdrawn)
        withdrawn = tuple(record.to_result() for record in records if record.withdrawn)
        return SnapshotFeedResult(self.source, self.version, active, withdrawn)


class OfflineSnapshotService(VulnerabilityService):
    """
    A `VulnerabilityService` backed by a local `AdvisorySnapshot`.

    The standard `query` method mirrors live services: it raises
    `ConnectionError` for an unreachable feed and filters out withdrawn
    advisories. Use `query_snapshot` to obtain the full, versioned feed result
    including withdrawn records.
    """

    def __init__(self, snapshot: AdvisorySnapshot):
        """
        Wrap the given snapshot as a vulnerability service.
        """

        self.snapshot = snapshot

    @property
    def source(self) -> str:
        """
        The wrapped snapshot's data-source name.
        """

        return self.snapshot.source

    @property
    def source_version(self) -> str:
        """
        The wrapped snapshot's data-source version.
        """

        return self.snapshot.version

    def query_snapshot(self, spec: Dependency) -> SnapshotFeedResult:
        """
        Return the full snapshot answer, including withdrawn advisories.

        Raises `ConnectionError` when the feed is unreachable for the
        requested package/version.
        """

        if spec.is_skipped():
            return SnapshotFeedResult(self.source, self.source_version, (), ())

        resolved = cast(ResolvedDependency, spec)
        feed = self.snapshot.lookup(resolved)
        if feed.unavailable:
            raise ConnectionError(
                f"{self.source} snapshot {self.source_version} is temporarily "
                f"unavailable for {resolved.name} ({resolved.version})"
            )
        return feed

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Query the snapshot, returning only active advisories.

        Withdrawn advisories are suppressed, matching the behavior of live
        services, and an unreachable feed raises `ConnectionError`.
        """

        if spec.is_skipped():
            return spec, []

        feed = self.query_snapshot(spec)
        return spec, list(feed.active)
