"""
Bitemporal reconciliation for `pip-audit` evidence.

`pip-audit` answers a single question: which vulnerabilities does a set of
dependencies have *right now*? Operational decisions need a second question:
which vulnerabilities were known to affect an environment when a previous
decision was made, and what changed since then?

This module keeps that distinction explicit:

* ``effective_at`` is the policy-approved time at which an advisory statement
  applies (valid time).
* ``retrieved_at`` is the time at which the statement was actually obtained
  (transaction time).

A query supplies an ``as_of`` date and a ``visible_at`` instant.  Only
snapshots that were both effective by ``as_of`` and retrieved by
``visible_at`` participate.  This makes it possible to replay a historical
closure without rewriting it, while also showing which closures need to be
reopened using information obtained later.
"""

from __future__ import annotations

import datetime as _dt
import enum
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import tomli
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

SCHEMA_VERSION = 1
_UTC = _dt.timezone.utc


class ReconciliationError(Exception):
    """Raised when reconciliation evidence cannot be read or interpreted."""


class TemporalError(ReconciliationError):
    """Raised when an evidence record has an ambiguous or missing timestamp."""


class EvidenceFormatError(ReconciliationError):
    """Raised when an evidence file does not match the expected schema."""


@enum.unique
class Audience(str, enum.Enum):
    """The intended reader of a reconciliation view."""

    INTERNAL = "internal"
    EXTERNAL = "external"


@enum.unique
class Status(str, enum.Enum):
    """The state of one artifact with respect to one advisory."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"
    WITHDRAWN = "withdrawn"


@enum.unique
class Visibility(str, enum.Enum):
    """Whether a reason may be redistributed outside the organization."""

    PUBLIC = "public"
    INTERNAL = "internal"


@enum.unique
class Action(str, enum.Enum):
    """The operational action implied by a reconciliation view."""

    NONE = "none"
    INVESTIGATE = "investigate"
    REOPEN = "reopen"


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_UTC)


def _parse_instant(value: Any, *, field_name: str, end_of_day: bool = False) -> _dt.datetime:
    """
    Parse an RFC3339 date or timestamp into an aware UTC datetime.

    Date-only values are interpreted as the start of the day, or the end of the
    day when ``end_of_day`` is true.  Naive timestamps are treated as UTC so
    that reports are reproducible across reviewer time zones.
    """

    if isinstance(value, _dt.datetime):
        parsed = value
    elif isinstance(value, _dt.date):
        parsed = _dt.datetime.combine(value, _dt.time.min)
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise TemporalError(f"{field_name}: timestamp must not be empty")
        try:
            if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
                day = _dt.date.fromisoformat(raw)
                parsed = _dt.datetime.combine(day, _dt.time.max if end_of_day else _dt.time.min)
            else:
                normalized = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
                parsed = _dt.datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise TemporalError(f"{field_name}: invalid ISO-8601 timestamp {value!r}") from exc
    else:
        raise TemporalError(
            f"{field_name}: expected a date or timestamp, got {type(value).__name__}"
        )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_UTC)
    return parsed.astimezone(_UTC)


def _parse_version(value: Any, *, field_name: str) -> Version:
    try:
        return Version(str(value))
    except InvalidVersion as exc:
        raise EvidenceFormatError(f"{field_name}: invalid PEP 440 version {value!r}") from exc


def _as_object(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceFormatError(f"{field_name}: expected a JSON object")
    return cast(Mapping[str, Any], value)


def _as_list(value: Any, *, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceFormatError(f"{field_name}: expected a JSON array")
    return value


def _first(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _isoformat(value: _dt.datetime | None) -> str | None:
    if value is None:
        return None
    value = value.astimezone(_UTC)
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_only(value: _dt.datetime) -> str:
    return value.astimezone(_UTC).date().isoformat()


@dataclass(frozen=True)
class Artifact:
    """A resolved package version from a lockfile or offline audit."""

    name: str
    version: Version

    @property
    def canonical_name(self) -> str:
        """Return the PEP 503 canonicalized package name."""

        return canonicalize_name(self.name)


@dataclass(frozen=True)
class VersionRange:
    """One OSV-style affected range."""

    introduced: Version | None = None
    fixed: Version | None = None
    last_affected: Version | None = None

    def contains(self, version: Version) -> bool:
        """Return whether ``version`` falls inside this range."""

        if self.introduced is not None and version < self.introduced:
            return False
        if self.fixed is not None and version >= self.fixed:
            return False
        if self.last_affected is not None and version > self.last_affected:
            return False
        return True


@dataclass(frozen=True)
class AffectedPackage:
    """An advisory's affected scope for one package."""

    name: str
    versions: frozenset[Version] = frozenset()
    ranges: tuple[VersionRange, ...] = ()
    ecosystem: str | None = "PyPI"

    def affects(self, artifact: Artifact) -> bool:
        """Return whether this scope covers ``artifact``."""

        if canonicalize_name(self.name) != artifact.canonical_name:
            return False
        if self.ecosystem is not None and self.ecosystem.lower() != "pypi":
            return False
        if not self.versions and not self.ranges:
            return True
        if artifact.version in self.versions:
            return True
        return any(version_range.contains(artifact.version) for version_range in self.ranges)


@dataclass(frozen=True)
class Reason:
    """A human-readable decision reason and its redistribution constraints."""

    text: str
    visibility: Visibility = Visibility.PUBLIC
    license: str | None = None


@dataclass(frozen=True)
class AdvisorySnapshot:
    """One dated version of an advisory record."""

    advisory_id: str
    effective_at: _dt.datetime
    retrieved_at: _dt.datetime
    affected: tuple[AffectedPackage, ...] = ()
    not_affected: frozenset[Artifact] = frozenset()
    declared_status: Status | None = None
    affects_all: bool = False
    reason: Reason | None = None
    description: str | None = None
    license: str | None = None
    visibility: Visibility = Visibility.PUBLIC
    withdrawn_at: _dt.datetime | None = None
    version: str | None = None
    source: str | None = None

    def status_for(self, artifact: Artifact) -> Status:
        """Evaluate the snapshot's affected scope for ``artifact``."""

        if artifact in self.not_affected:
            return Status.NOT_AFFECTED
        if self.affects_all:
            return Status.AFFECTED
        if any(scope.affects(artifact) for scope in self.affected):
            return Status.AFFECTED
        if self.affected:
            return Status.NOT_AFFECTED
        if self.declared_status is not None:
            return self.declared_status
        return Status.UNKNOWN


@dataclass(frozen=True)
class OfflineAudit:
    """A saved ``pip-audit --format=json`` result and its two times."""

    retrieved_at: _dt.datetime
    source: str
    effective_at: _dt.datetime | None = None
    dependencies: Mapping[str, Version] = field(default_factory=dict)
    reported: Mapping[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class Environment:
    """A deployment environment and the evidence that describes it."""

    name: str
    artifacts: Mapping[str, Artifact] = field(default_factory=dict)
    lockfile: str | None = None
    lockfile_retrieved_at: _dt.datetime | None = None
    offline_audits: tuple[OfflineAudit, ...] = ()


@dataclass(frozen=True)
class Closure:
    """
    An immutable historical closure decision.

    Closures are inputs, never outputs of reconciliation.  The class is frozen
    and the loader rejects duplicate IDs with different contents, so replaying
    a view cannot silently rewrite an on-call decision.
    """

    closure_id: str
    environment: str
    advisory_id: str
    closed_at: _dt.datetime
    as_of: _dt.datetime
    artifact: str | None = None
    reason: Reason | None = None
    evidence: str | None = None


@dataclass(frozen=True)
class LicensePolicy:
    """Rules for redistributing reasons outside the organization."""

    external_licenses: frozenset[str] | None = None
    internal_only_licenses: frozenset[str] = frozenset()
    license_visibility: Mapping[str, Visibility] = field(default_factory=dict)

    def permits_external(self, license_id: str | None) -> bool:
        """Return whether text under ``license_id`` may be shown externally."""

        if license_id is None:
            return self.external_licenses is None
        explicit = self.license_visibility.get(license_id)
        if explicit is not None:
            return explicit is Visibility.PUBLIC
        if license_id in self.internal_only_licenses:
            return False
        if self.external_licenses is None:
            return True
        return license_id in self.external_licenses

    def reason_visible(
        self, reason: Reason | None, default_license: str | None, audience: Audience
    ) -> bool:
        """Return whether ``reason`` may be included in a view for ``audience``."""

        if reason is None:
            return False
        if audience is Audience.INTERNAL:
            return True
        if reason.visibility is Visibility.INTERNAL:
            return False
        return self.permits_external(reason.license or default_license)


@dataclass(frozen=True)
class EvidenceBundle:
    """All local evidence used for temporal reconciliation."""

    environments: Mapping[str, Environment]
    snapshots: tuple[AdvisorySnapshot, ...]
    closures: tuple[Closure, ...] = ()
    license_policy: LicensePolicy = field(default_factory=LicensePolicy)


@dataclass(frozen=True)
class Finding:
    """A reconciled affected/unknown result for one artifact and advisory."""

    environment: str
    artifact: str
    version: str
    advisory_id: str
    status: Status
    reason: str | None
    reason_redacted: bool
    effective_at: _dt.datetime | None
    retrieved_at: _dt.datetime | None
    snapshot_version: str | None
    source: str | None
    evidence_conflict: bool = False


@dataclass(frozen=True)
class ClosureReview:
    """A preserved closure and its status under the current query."""

    closure_id: str
    environment: str
    advisory_id: str
    artifact: str | None
    closed_at: _dt.datetime
    as_of: _dt.datetime
    decision_status: Status
    decision_reason: str | None
    decision_reason_redacted: bool
    current_status: Status
    current_reason: str | None
    current_reason_redacted: bool
    reopen_required: bool
    evidence: str | None


@dataclass(frozen=True)
class WorkItem:
    """A concrete follow-up task produced by a view."""

    action: Action
    environment: str
    artifact: str | None
    advisory_id: str
    status: Status
    previous_closure: str | None
    reason: str | None
    reason_redacted: bool
    effective_at: _dt.datetime | None
    retrieved_at: _dt.datetime | None
    source: str | None


@dataclass(frozen=True)
class EnvironmentReview:
    """The reconciled state of one environment."""

    name: str
    artifacts: Mapping[str, str]
    findings: tuple[Finding, ...]
    closures: tuple[ClosureReview, ...]
    work: tuple[WorkItem, ...]
    drift: tuple[str, ...] = ()


@dataclass(frozen=True)
class View:
    """One comparable, point-in-time reconciliation view."""

    label: str
    as_of: _dt.datetime
    visible_at: _dt.datetime
    audience: Audience
    environments: Mapping[str, EnvironmentReview]
    reopen_environments: tuple[str, ...]
    redactions: int


@dataclass(frozen=True)
class Change:
    """A status change between two views that share the same ``as_of``."""

    environment: str
    artifact: str
    advisory_id: str
    before: Status
    after: Status
    action: Action


@dataclass(frozen=True)
class Comparison:
    """A machine-readable comparison of two views with the same ``as_of``."""

    as_of: _dt.datetime
    earlier: View
    later: View
    changes: tuple[Change, ...]
    reopen: tuple[WorkItem, ...]


def _parse_visibility(value: Any, *, field_name: str, default: Visibility) -> Visibility:
    if value is None:
        return default
    text = str(value).strip().lower().replace("-", "_")
    if text in {"public", "external", "redistributable", "shareable", "open"}:
        return Visibility.PUBLIC
    if text in {
        "internal",
        "private",
        "restricted",
        "internal_only",
        "confidential",
        "need_to_know",
        "secret",
    }:
        return Visibility.INTERNAL
    raise EvidenceFormatError(f"{field_name}: unknown visibility {value!r}")


def _parse_status(value: Any, *, field_name: str) -> Status:
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if text in {"affected", "vulnerable", "impacted"}:
        return Status.AFFECTED
    if text in {
        "not_affected",
        "unaffected",
        "clean",
        "not_vulnerable",
        "false_positive",
        "fixed",
        "resolved",
    }:
        return Status.NOT_AFFECTED
    if text in {"withdrawn", "revoked"}:
        return Status.WITHDRAWN
    if text in {"unknown", "undetermined", "pending", "under_investigation"}:
        return Status.UNKNOWN
    raise EvidenceFormatError(f"{field_name}: unknown status {value!r}")


def _parse_reason(
    value: Any,
    *,
    field_name: str,
    default_visibility: Visibility,
    default_license: str | None,
) -> Reason | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return Reason(text, default_visibility, default_license) if text else None
    if not isinstance(value, dict):
        raise EvidenceFormatError(f"{field_name}: expected a string or JSON object")
    obj = cast(Mapping[str, Any], value)
    raw_text = _first(obj, "text", "reason", "rationale", "note", "summary", "details")
    if raw_text is None:
        return None
    text = str(raw_text).strip()
    if not text:
        return None
    visibility = _parse_visibility(
        _first(obj, "visibility", "audience", "distribution", "redistribution"),
        field_name=f"{field_name}.visibility",
        default=default_visibility,
    )
    license_id = _first(obj, "license", "license_id", "spdx", "spdx_id")
    return Reason(
        text=text,
        visibility=visibility,
        license=str(license_id) if license_id is not None else default_license,
    )


def _ranges_from_events(events: Any, *, field_name: str) -> tuple[VersionRange, ...]:
    ranges: list[VersionRange] = []
    introduced: Version | None = None
    for raw_event in _as_list(events, field_name=field_name):
        event = _as_object(raw_event, field_name=f"{field_name}[]")
        if "introduced" in event:
            introduced = _parse_version(
                event["introduced"], field_name=f"{field_name}[].introduced"
            )
        if "fixed" in event:
            ranges.append(
                VersionRange(
                    introduced=introduced,
                    fixed=_parse_version(event["fixed"], field_name=f"{field_name}[].fixed"),
                )
            )
            introduced = None
        if "last_affected" in event:
            ranges.append(
                VersionRange(
                    introduced=introduced,
                    last_affected=_parse_version(
                        event["last_affected"], field_name=f"{field_name}[].last_affected"
                    ),
                )
            )
            introduced = None
    if introduced is not None:
        ranges.append(VersionRange(introduced=introduced))
    return tuple(ranges)


def _parse_affected_package(value: Any, *, field_name: str) -> AffectedPackage:
    obj = _as_object(value, field_name=field_name)
    package = obj.get("package")
    package_obj = (
        _as_object(package, field_name=f"{field_name}.package")
        if isinstance(package, dict)
        else cast(Mapping[str, Any], {})
    )
    raw_name = _first(obj, "name", default=package_obj.get("name"))
    if raw_name is None:
        raise EvidenceFormatError(f"{field_name}: affected entry is missing a package name")
    name = str(raw_name)
    ecosystem = _first(obj, "ecosystem", default=package_obj.get("ecosystem", "PyPI"))

    raw_versions = obj.get("versions", [])
    versions = frozenset(
        _parse_version(version, field_name=f"{field_name}.versions[]")
        for version in _as_list(raw_versions, field_name=f"{field_name}.versions")
    )

    ranges: list[VersionRange] = []
    raw_ranges = obj.get("ranges", [])
    for idx, raw_range in enumerate(_as_list(raw_ranges, field_name=f"{field_name}.ranges")):
        range_obj = _as_object(raw_range, field_name=f"{field_name}.ranges[{idx}]")
        range_type = range_obj.get("type")
        if range_type is not None and str(range_type).upper() not in {
            "ECOSYSTEM",
            "SEMVER",
        }:
            continue
        if "events" in range_obj:
            ranges.extend(
                _ranges_from_events(
                    range_obj["events"], field_name=f"{field_name}.ranges[{idx}].events"
                )
            )
        elif any(key in range_obj for key in ("introduced", "fixed", "last_affected")):
            ranges.append(
                VersionRange(
                    introduced=(
                        _parse_version(
                            range_obj["introduced"],
                            field_name=f"{field_name}.ranges[{idx}].introduced",
                        )
                        if "introduced" in range_obj
                        else None
                    ),
                    fixed=(
                        _parse_version(
                            range_obj["fixed"],
                            field_name=f"{field_name}.ranges[{idx}].fixed",
                        )
                        if "fixed" in range_obj
                        else None
                    ),
                    last_affected=(
                        _parse_version(
                            range_obj["last_affected"],
                            field_name=f"{field_name}.ranges[{idx}].last_affected",
                        )
                        if "last_affected" in range_obj
                        else None
                    ),
                )
            )
    return AffectedPackage(
        name=name,
        versions=versions,
        ranges=tuple(ranges),
        ecosystem=str(ecosystem) if ecosystem is not None else None,
    )


def _parse_artifact(value: Any, *, field_name: str) -> Artifact:
    if isinstance(value, str):
        match = _REQUIREMENT_PIN.match(value.strip())
        if match is None:
            raise EvidenceFormatError(
                f"{field_name}: expected an object with name and version or name==version"
            )
        return Artifact(
            name=match.group(1),
            version=_parse_version(match.group(2), field_name=f"{field_name}.version"),
        )
    obj = _as_object(value, field_name=field_name)
    package = obj.get("package")
    package_obj = (
        _as_object(package, field_name=f"{field_name}.package")
        if isinstance(package, dict)
        else cast(Mapping[str, Any], {})
    )
    raw_name = _first(obj, "name", default=package_obj.get("name"))
    raw_version = _first(obj, "version", default=package_obj.get("version"))
    if raw_name is None or raw_version is None:
        raise EvidenceFormatError(f"{field_name}: artifact requires name and version")
    return Artifact(
        name=str(raw_name),
        version=_parse_version(raw_version, field_name=f"{field_name}.version"),
    )


def _parse_times(
    obj: Mapping[str, Any],
    *,
    field_name: str,
    default_retrieved_at: Any = None,
    default_effective_at: Any = None,
) -> tuple[_dt.datetime, _dt.datetime]:
    raw_effective = _first(
        obj,
        "effective_at",
        "effective",
        "valid_from",
        "valid_from_at",
        "policy_effective_at",
        "published",
        "published_at",
        default=default_effective_at,
    )
    raw_retrieved = _first(
        obj,
        "retrieved_at",
        "retrieved",
        "observed_at",
        "recorded_at",
        "fetched_at",
        "modified",
        "modified_at",
        default=default_retrieved_at,
    )
    if raw_effective is None and raw_retrieved is None:
        raise TemporalError(
            f"{field_name}: record needs effective_at (valid time) and retrieved_at "
            "(transaction time)"
        )
    if raw_effective is None:
        raw_effective = raw_retrieved
    if raw_retrieved is None:
        raw_retrieved = raw_effective
    effective_at = _parse_instant(raw_effective, field_name=f"{field_name}.effective_at")
    retrieved_at = _parse_instant(raw_retrieved, field_name=f"{field_name}.retrieved_at")
    return effective_at, retrieved_at


def _snapshot_from_object(value: Any, *, source: str | None = None) -> AdvisorySnapshot:
    obj = _as_object(value, field_name="snapshot")
    record = _first(obj, "record", "advisory", "osv", "snapshot", "data", "vulnerability")
    record_obj = (
        _as_object(record, field_name="snapshot.record")
        if isinstance(record, dict)
        else cast(Mapping[str, Any], {})
    )
    merged: dict[str, Any] = dict(record_obj)
    merged.update(
        {key: val for key, val in obj.items() if key not in {"record", "advisory", "osv"}}
    )

    raw_id = _first(merged, "advisory_id", "vuln_id", "id", "osv_id")
    if raw_id is None:
        raise EvidenceFormatError("snapshot: missing advisory_id/id")
    advisory_id = str(raw_id)

    effective_at, retrieved_at = _parse_times(
        merged,
        field_name=f"snapshot {advisory_id}",
        default_effective_at=record_obj.get("effective_at"),
        default_retrieved_at=record_obj.get("retrieved_at"),
    )
    license_id = _first(merged, "license", "license_id", "spdx", "spdx_id")
    database_specific = merged.get("database_specific")
    if license_id is None and isinstance(database_specific, dict):
        license_id = _first(
            cast(Mapping[str, Any], database_specific), "license", "license_id", "spdx"
        )
    default_visibility = _parse_visibility(
        _first(merged, "visibility", "audience", "distribution", "redistribution"),
        field_name=f"snapshot {advisory_id}.visibility",
        default=Visibility.PUBLIC,
    )
    reason = _parse_reason(
        _first(merged, "reason", "not_affected_reason", "rationale", "closure_reason"),
        field_name=f"snapshot {advisory_id}.reason",
        default_visibility=default_visibility,
        default_license=str(license_id) if license_id is not None else None,
    )
    description = _first(merged, "description", "summary", "details")
    declared_status: Status | None = None
    raw_status = _first(merged, "status", "affected_status", "disposition", "state")
    if raw_status is not None:
        declared_status = _parse_status(raw_status, field_name=f"snapshot {advisory_id}.status")

    affected: list[AffectedPackage] = []
    raw_affected = merged.get("affected")
    if isinstance(raw_affected, dict):
        for name, details in cast(Mapping[str, Any], raw_affected).items():
            if isinstance(details, dict):
                scoped = dict(cast(Mapping[str, Any], details))
                scoped.setdefault("name", name)
                affected.append(
                    _parse_affected_package(
                        scoped, field_name=f"snapshot {advisory_id}.affected[{name}]"
                    )
                )
    elif raw_affected is not None:
        for idx, raw_scope in enumerate(
            _as_list(raw_affected, field_name=f"snapshot {advisory_id}.affected")
        ):
            affected.append(
                _parse_affected_package(
                    raw_scope, field_name=f"snapshot {advisory_id}.affected[{idx}]"
                )
            )

    not_affected: set[Artifact] = set()
    raw_not_affected = merged.get("not_affected")
    if raw_not_affected is not None:
        for idx, raw_artifact in enumerate(
            _as_list(raw_not_affected, field_name=f"snapshot {advisory_id}.not_affected")
        ):
            if isinstance(raw_artifact, str):
                raise EvidenceFormatError(
                    f"snapshot {advisory_id}.not_affected[{idx}]: "
                    "a version is required for an explicit negative"
                )
            not_affected.add(
                _parse_artifact(
                    raw_artifact, field_name=f"snapshot {advisory_id}.not_affected[{idx}]"
                )
            )

    withdrawn_at: _dt.datetime | None = None
    raw_withdrawn = _first(merged, "withdrawn", "withdrawn_at", "revoked_at")
    if raw_withdrawn is not None:
        withdrawn_at = _parse_instant(
            raw_withdrawn, field_name=f"snapshot {advisory_id}.withdrawn_at"
        )

    raw_version = _first(merged, "snapshot_version", "advisory_version", "version")
    snapshot_source = _first(merged, "source", default=source)
    return AdvisorySnapshot(
        advisory_id=advisory_id,
        effective_at=effective_at,
        retrieved_at=retrieved_at,
        affected=tuple(affected),
        not_affected=frozenset(not_affected),
        declared_status=declared_status,
        affects_all=bool(merged.get("affects_all", False)),
        reason=reason,
        description=str(description) if description is not None else None,
        license=str(license_id) if license_id is not None else None,
        visibility=default_visibility,
        withdrawn_at=withdrawn_at,
        version=str(raw_version) if raw_version is not None else None,
        source=str(snapshot_source) if snapshot_source is not None else None,
    )


def _snapshots_from_data(value: Any, *, source: str | None = None) -> list[AdvisorySnapshot]:
    if isinstance(value, list):
        return [
            _snapshot_from_object(item, source=source)
            for item in _as_list(value, field_name="snapshots")
        ]
    obj = _as_object(value, field_name="snapshots")
    for key in ("snapshots", "advisory_snapshots", "records"):
        if key in obj:
            return _snapshots_from_data(obj[key], source=source)
    if any(key in obj for key in ("advisory_id", "vuln_id", "id", "osv_id")):
        return [_snapshot_from_object(obj, source=source)]
    snapshots: list[AdvisorySnapshot] = []
    for advisory_id, raw_snapshot in obj.items():
        if isinstance(raw_snapshot, list):
            for raw_item in raw_snapshot:
                item = dict(_as_object(raw_item, field_name=f"snapshots[{advisory_id}]"))
                item.setdefault("advisory_id", advisory_id)
                snapshots.append(_snapshot_from_object(item, source=source))
        else:
            item = dict(_as_object(raw_snapshot, field_name=f"snapshots[{advisory_id}]"))
            item.setdefault("advisory_id", advisory_id)
            snapshots.append(_snapshot_from_object(item, source=source))
    return snapshots


def _closure_from_object(value: Any, *, default_id: str | None = None) -> Closure:
    obj = _as_object(value, field_name="closure")
    advisory = _first(obj, "advisory_id", "advisory", "vuln_id")
    if isinstance(advisory, dict):
        advisory = _first(cast(Mapping[str, Any], advisory), "id", "advisory_id")
    if advisory is None:
        raise EvidenceFormatError("closure: missing advisory_id")
    environment = _first(obj, "environment", "env", "environment_name")
    if environment is None:
        raise EvidenceFormatError("closure: missing environment")
    raw_closed = _first(obj, "closed_at", "closed", "decided_at", "closure_time")
    raw_as_of = _first(obj, "as_of", "valid_at", "decision_date", "decision_as_of")
    if raw_closed is None and raw_as_of is None:
        raise TemporalError("closure: missing closed_at/as_of")
    if raw_closed is None:
        raw_closed = raw_as_of
    if raw_as_of is None:
        raw_as_of = raw_closed
    closed_at = _parse_instant(raw_closed, field_name="closure.closed_at")
    as_of = _parse_instant(raw_as_of, field_name="closure.as_of", end_of_day=True)
    raw_artifact = _first(obj, "artifact", "package", "dependency")
    if isinstance(raw_artifact, dict):
        raw_artifact = _first(cast(Mapping[str, Any], raw_artifact), "name")
    license_id = _first(obj, "license", "license_id", "spdx", "spdx_id")
    visibility = _parse_visibility(
        _first(obj, "visibility", "audience", "distribution"),
        field_name="closure.visibility",
        default=Visibility.PUBLIC,
    )
    reason = _parse_reason(
        _first(obj, "reason", "rationale", "note", "closure_reason"),
        field_name="closure.reason",
        default_visibility=visibility,
        default_license=str(license_id) if license_id is not None else None,
    )
    closure_id = _first(obj, "closure_id", "id", default=default_id)
    if closure_id is None:
        raise EvidenceFormatError("closure: missing closure_id/id")
    evidence = _first(obj, "evidence", "basis", "snapshot", "evidence_snapshot")
    return Closure(
        closure_id=str(closure_id),
        environment=str(environment),
        advisory_id=str(advisory),
        closed_at=closed_at,
        as_of=as_of,
        artifact=str(raw_artifact) if raw_artifact is not None else None,
        reason=reason,
        evidence=str(evidence) if evidence is not None else None,
    )


def _offline_audit_from_data(
    value: Any, *, source: str, retrieved_at: _dt.datetime | None = None
) -> OfflineAudit:
    if isinstance(value, list):
        value = {"dependencies": value}
    obj = _as_object(value, field_name=f"offline result {source}")
    for wrapper_key in ("result", "report", "audit"):
        wrapped = obj.get(wrapper_key)
        if isinstance(wrapped, dict):
            merged = dict(cast(Mapping[str, Any], wrapped))
            for timing_key in (
                "retrieved_at",
                "observed_at",
                "recorded_at",
                "generated_at",
                "created_at",
                "effective_at",
                "valid_at",
                "valid_from",
            ):
                if timing_key in obj:
                    merged[timing_key] = obj[timing_key]
            obj = merged
            break
    if retrieved_at is None:
        raw_retrieved = _first(
            obj,
            "retrieved_at",
            "observed_at",
            "recorded_at",
            "generated_at",
            "created_at",
        )
        if raw_retrieved is None:
            raise TemporalError(f"offline result {source}: missing retrieved_at/generated_at")
        retrieved_at = _parse_instant(
            raw_retrieved, field_name=f"offline result {source}.retrieved_at"
        )

    dependencies: dict[str, Version] = {}
    reported: dict[str, set[str]] = {}
    raw_dependencies = obj.get("dependencies")
    if raw_dependencies is None and "vulns" in obj:
        raw_dependencies = [obj]
    if raw_dependencies is not None:
        for idx, raw_dep in enumerate(
            _as_list(raw_dependencies, field_name=f"offline result {source}.dependencies")
        ):
            dep = _as_object(raw_dep, field_name=f"offline result {source}.dependencies[{idx}]")
            name = dep.get("name")
            version = dep.get("version")
            if name is None or version is None:
                continue
            artifact_name = canonicalize_name(str(name))
            dependencies[artifact_name] = _parse_version(
                version, field_name=f"offline result {source}.dependencies[{idx}].version"
            )
            ids: set[str] = set()
            for vuln_idx, raw_vuln in enumerate(
                _as_list(
                    dep.get("vulns", []),
                    field_name=f"offline result {source}.dependencies[{idx}].vulns",
                )
            ):
                vuln = _as_object(
                    raw_vuln,
                    field_name=f"offline result {source}.dependencies[{idx}].vulns[{vuln_idx}]",
                )
                vuln_id = vuln.get("id")
                if vuln_id is not None:
                    ids.add(str(vuln_id))
                for alias in _as_list(
                    vuln.get("aliases", []),
                    field_name=(
                        f"offline result {source}.dependencies[{idx}].vulns[{vuln_idx}].aliases"
                    ),
                ):
                    ids.add(str(alias))
            if ids:
                reported[artifact_name] = frozenset(ids)
    raw_effective = _first(obj, "effective_at", "valid_at", "valid_from")
    effective_at = (
        _parse_instant(raw_effective, field_name=f"offline result {source}.effective_at")
        if raw_effective is not None
        else retrieved_at
    )
    return OfflineAudit(
        retrieved_at=retrieved_at,
        source=source,
        effective_at=effective_at,
        dependencies=dependencies,
        reported={name: frozenset(ids) for name, ids in reported.items()},
    )


_REQUIREMENT_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;]+)")


def _parse_lockfile(path: Path) -> dict[str, Artifact]:
    if path.suffix.lower() == ".toml":
        try:
            with path.open("rb") as io:
                data = tomli.load(io)
        except tomli.TOMLDecodeError as exc:
            raise EvidenceFormatError(f"{path}: invalid TOML lockfile") from exc
        packages: Any = data.get("packages")
        if packages is None:
            packages = data.get("package")
        if packages is None:
            raise EvidenceFormatError(f"{path}: no packages in lockfile")
        artifacts: dict[str, Artifact] = {}
        if isinstance(packages, dict):
            for name, raw_value in cast(Mapping[str, Any], packages).items():
                version = raw_value.get("version") if isinstance(raw_value, dict) else raw_value
                if version is None:
                    continue
                artifact = Artifact(
                    name=str(name),
                    version=_parse_version(version, field_name=f"{path}.packages[{name}]"),
                )
                artifacts[artifact.canonical_name] = artifact
            return artifacts
        for idx, raw_package in enumerate(_as_list(packages, field_name=f"{path}.packages")):
            package = _as_object(raw_package, field_name=f"{path}.packages[{idx}]")
            name = package.get("name")
            version = package.get("version")
            if name is None or version is None:
                continue
            artifact = Artifact(
                name=str(name),
                version=_parse_version(version, field_name=f"{path}.packages[{idx}].version"),
            )
            artifacts[artifact.canonical_name] = artifact
        return artifacts

    artifacts = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise EvidenceFormatError(f"{path}: cannot read lockfile") from exc
    for line in lines:
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        match = _REQUIREMENT_PIN.match(stripped)
        if match is None:
            continue
        artifact = Artifact(
            name=match.group(1),
            version=_parse_version(match.group(2), field_name=f"{path}:{stripped}"),
        )
        artifacts[artifact.canonical_name] = artifact
    if not artifacts:
        raise EvidenceFormatError(f"{path}: no exact name==version pins found")
    return artifacts


def _resolve_path(base: Path, raw: str | Path) -> Path:
    """Resolve a bundle-relative path without requiring it to exist yet."""

    path = Path(raw)
    return path if path.is_absolute() else (base / path)


def _merge_artifact(artifacts: dict[str, Artifact], artifact: Artifact, *, origin: str) -> None:
    """Insert an artifact, rejecting conflicting versions from one environment."""

    previous = artifacts.get(artifact.canonical_name)
    if previous is not None and previous.version != artifact.version:
        raise EvidenceFormatError(
            f"{origin}: conflicting versions for {artifact.canonical_name}: "
            f"{previous.version} and {artifact.version}"
        )
    artifacts[artifact.canonical_name] = artifact


def _load_json(path: Path) -> Any:
    """Load a JSON document, reporting the path on failure."""

    try:
        with path.open("r", encoding="utf-8") as io:
            return json.load(io)
    except OSError as exc:
        raise EvidenceFormatError(f"{path}: cannot read JSON file") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceFormatError(f"{path}: invalid JSON") from exc


def _reference_items(value: Any, *, field_name: str) -> list[Any]:
    """Normalize a single evidence reference or a list of references."""

    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


# probe


def _artifact_from_pair(name: Any, value: Any, *, field_name: str) -> Artifact:
    """Build an artifact from a name-to-version mapping entry."""

    if isinstance(value, dict):
        obj = _as_object(value, field_name=field_name)
        version = _first(obj, "version", "value")
    else:
        version = value
    if version is None:
        raise EvidenceFormatError(f"{field_name}: artifact requires a version")
    return Artifact(name=str(name), version=_parse_version(version, field_name=field_name))


def _artifacts_from_value(value: Any, *, field_name: str) -> dict[str, Artifact]:
    """Parse inline artifacts from a mapping or a list."""

    artifacts: dict[str, Artifact] = {}
    if value is None:
        return artifacts
    if isinstance(value, dict):
        for name, raw in cast(Mapping[str, Any], value).items():
            artifact = _artifact_from_pair(name, raw, field_name=f"{field_name}.{name}")
            _merge_artifact(artifacts, artifact, origin=field_name)
        return artifacts
    for idx, raw in enumerate(_as_list(value, field_name=field_name)):
        artifact = _parse_artifact(raw, field_name=f"{field_name}[{idx}]")
        _merge_artifact(artifacts, artifact, origin=field_name)
    return artifacts


def _environment_from_object(
    value: Any, *, base_dir: Path, default_name: str | None = None
) -> Environment:
    """Parse one environment entry from an evidence bundle."""

    obj = _as_object(value, field_name="environment")
    raw_name = _first(obj, "name", "environment", "env_name", default=default_name)
    if raw_name is None:
        raise EvidenceFormatError("environment: missing name")
    name = str(raw_name)
    artifacts = _artifacts_from_value(
        _first(obj, "artifacts", "packages"), field_name=f"environment {name}.artifacts"
    )

    lockfile_retrieved_at: _dt.datetime | None = None
    lockfile_label: str | None = None
    raw_lockfiles = _first(obj, "lockfile", "lockfiles", "lock", "pylock", "lock_file")
    for raw_lockfile in _reference_items(raw_lockfiles, field_name=f"environment {name}.lockfile"):
        retrieved_override: Any = None
        if isinstance(raw_lockfile, str):
            path = _resolve_path(base_dir, raw_lockfile)
        elif isinstance(raw_lockfile, dict):
            lock_obj = _as_object(raw_lockfile, field_name=f"environment {name}.lockfile")
            raw_path = _first(lock_obj, "path", "file", "filename")
            if raw_path is None:
                raise EvidenceFormatError(f"environment {name}.lockfile: missing path")
            path = _resolve_path(base_dir, str(raw_path))
            retrieved_override = _first(lock_obj, "retrieved_at", "observed_at", "recorded_at")
        else:
            raise EvidenceFormatError(f"environment {name}.lockfile: expected path or object")
        for artifact in _parse_lockfile(path).values():
            _merge_artifact(artifacts, artifact, origin=str(path))
        lockfile_label = str(path)
        if retrieved_override is not None:
            parsed_retrieved = _parse_instant(
                retrieved_override, field_name=f"environment {name}.lockfile.retrieved_at"
            )
            if lockfile_retrieved_at is None or parsed_retrieved > lockfile_retrieved_at:
                lockfile_retrieved_at = parsed_retrieved

    offline_audits: list[OfflineAudit] = []
    raw_audits = _first(
        obj,
        "offline_results",
        "offline_result",
        "offline_audit",
        "audits",
        "audit",
        "pip_audit",
        "pip_audit_results",
        "pip_audit_result",
    )
    for idx, raw_audit in enumerate(
        _reference_items(raw_audits, field_name=f"environment {name}.offline_result")
    ):
        if isinstance(raw_audit, str):
            path = _resolve_path(base_dir, raw_audit)
            audit = _offline_audit_from_data(_load_json(path), source=str(path))
        elif isinstance(raw_audit, dict):
            audit_obj = _as_object(
                raw_audit, field_name=f"environment {name}.offline_result[{idx}]"
            )
            raw_path = _first(audit_obj, "path", "file", "filename")
            if raw_path is not None:
                path = _resolve_path(base_dir, str(raw_path))
                retrieved_override = _first(audit_obj, "retrieved_at", "observed_at", "recorded_at")
                audit = _offline_audit_from_data(
                    _load_json(path),
                    source=str(path),
                    retrieved_at=(
                        _parse_instant(
                            retrieved_override,
                            field_name=f"environment {name}.offline_result.retrieved_at",
                        )
                        if retrieved_override is not None
                        else None
                    ),
                )
            else:
                audit = _offline_audit_from_data(
                    raw_audit, source=f"environment {name}.offline_result[{idx}]"
                )
        else:
            raise EvidenceFormatError(
                f"environment {name}.offline_result[{idx}]: expected path or object"
            )
        offline_audits.append(audit)
        for canonical, version in audit.dependencies.items():
            if canonical not in artifacts:
                artifacts[canonical] = Artifact(name=canonical, version=version)

    if not artifacts:
        raise EvidenceFormatError(f"environment {name}: no artifacts or lockfile")
    return Environment(
        name=name,
        artifacts=artifacts,
        lockfile=lockfile_label,
        lockfile_retrieved_at=lockfile_retrieved_at,
        offline_audits=tuple(sorted(offline_audits, key=lambda audit: audit.retrieved_at)),
    )


def _snapshots_from_bundle_value(value: Any, *, base_dir: Path) -> list[AdvisorySnapshot]:
    """Load inline snapshots or snapshot files referenced by a bundle."""

    snapshots: list[AdvisorySnapshot] = []
    for item in _reference_items(value, field_name="advisory_snapshots"):
        if isinstance(item, str):
            path = _resolve_path(base_dir, item)
            if path.is_dir():
                snapshots.extend(load_advisory_paths([path]))
            else:
                snapshots.extend(_snapshots_from_data(_load_json(path), source=str(path)))
        elif isinstance(item, dict):
            obj = _as_object(item, field_name="advisory_snapshots[]")
            raw_path = _first(obj, "path", "file", "filename")
            id_keys = ("id", "advisory_id", "vuln_id", "affected", "snapshots")
            if raw_path is not None and not any(key in obj for key in id_keys):
                path = _resolve_path(base_dir, str(raw_path))
                snapshots.extend(_snapshots_from_data(_load_json(path), source=str(path)))
            else:
                snapshots.extend(_snapshots_from_data(obj))
        else:
            raise EvidenceFormatError("advisory_snapshots[]: expected a path or object")
    return snapshots


def _closures_from_value(value: Any) -> list[Closure]:
    """Parse a closure ledger from a list or an ID-keyed mapping."""

    closures: list[Closure] = []
    if value is None:
        return closures
    if isinstance(value, str):
        return list(load_closure_paths([value]))
    if isinstance(value, list):
        for idx, item in enumerate(_as_list(value, field_name="closures")):
            closures.append(_closure_from_object(item, default_id=f"closure-{idx}"))
        return closures
    obj = _as_object(value, field_name="closures")
    if any(key in obj for key in ("closure_id", "id", "environment", "advisory_id")):
        closures.append(_closure_from_object(obj))
        return closures
    for key, item in obj.items():
        if isinstance(item, list):
            for idx, sub_item in enumerate(item):
                closures.append(_closure_from_object(sub_item, default_id=f"{key}-{idx}"))
        else:
            closures.append(_closure_from_object(item, default_id=str(key)))
    return closures


def _license_policy_from_data(value: Any) -> LicensePolicy:
    """Parse an optional license redistribution policy."""

    if value is None:
        return LicensePolicy()
    obj = _as_object(value, field_name="license_policy")
    raw_external = _first(obj, "external_licenses", "public_licenses", "redistributable_licenses")
    raw_internal = _first(obj, "internal_only_licenses", "restricted_licenses")
    raw_visibility = _first(obj, "licenses", "license_visibility", "redistribution")
    external = (
        frozenset(
            str(license_id)
            for license_id in _as_list(raw_external, field_name="license_policy.external_licenses")
        )
        if raw_external is not None
        else None
    )
    internal = (
        frozenset(
            str(license_id)
            for license_id in _as_list(
                raw_internal, field_name="license_policy.internal_only_licenses"
            )
        )
        if raw_internal is not None
        else frozenset()
    )
    visibility: dict[str, Visibility] = {}
    if isinstance(raw_visibility, dict):
        for license_id, raw_value in cast(Mapping[str, Any], raw_visibility).items():
            visibility[str(license_id)] = _parse_visibility(
                raw_value,
                field_name=f"license_policy.licenses[{license_id}]",
                default=Visibility.INTERNAL,
            )
    return LicensePolicy(
        external_licenses=external,
        internal_only_licenses=internal,
        license_visibility=visibility,
    )


def _dedupe_closures(closures: Iterable[Closure]) -> tuple[Closure, ...]:
    """Reject rewrites of a historical closure and return a stable ledger."""

    by_id: dict[str, Closure] = {}
    for closure in closures:
        previous = by_id.get(closure.closure_id)
        if previous is not None and previous != closure:
            raise EvidenceFormatError(
                f"closure {closure.closure_id}: conflicting duplicate records"
            )
        by_id[closure.closure_id] = closure
    return tuple(
        sorted(by_id.values(), key=lambda closure: (closure.closed_at, closure.closure_id))
    )


def load_advisory_paths(paths: Iterable[str | Path]) -> tuple[AdvisorySnapshot, ...]:
    """Load advisory snapshots from files or directories of JSON files."""

    snapshots: list[AdvisorySnapshot] = []
    seen: set[str] = set()
    for raw_path in paths:
        path = Path(raw_path)
        candidates = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        for candidate in candidates:
            key = str(candidate.resolve())
            if key in seen:
                continue
            seen.add(key)
            snapshots.extend(_snapshots_from_data(_load_json(candidate), source=str(candidate)))
    return tuple(snapshots)


def load_closure_paths(paths: Iterable[str | Path]) -> tuple[Closure, ...]:
    """Load closure records from JSON files or directories of JSON files."""

    closures: list[Closure] = []
    seen: set[str] = set()
    for raw_path in paths:
        path = Path(raw_path)
        candidates = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        for candidate in candidates:
            key = str(candidate.resolve())
            if key in seen:
                continue
            seen.add(key)
            closures.extend(_closures_from_value(_load_json(candidate)))
    return _dedupe_closures(closures)


def load_bundle(
    path: str | Path,
    *,
    extra_snapshots: Iterable[str | Path] = (),
    extra_closures: Iterable[str | Path] = (),
) -> EvidenceBundle:
    """Load an evidence bundle and optional additional snapshot or closure files."""

    bundle_path = Path(path)
    data = _as_object(_load_json(bundle_path), field_name=str(bundle_path))
    base_dir = bundle_path.parent

    raw_environments = data.get("environments")
    if raw_environments is None:
        raise EvidenceFormatError(f"{bundle_path}: missing environments")
    environments: dict[str, Environment] = {}
    if isinstance(raw_environments, dict):
        for key, raw_environment in cast(Mapping[str, Any], raw_environments).items():
            environment = _environment_from_object(
                raw_environment, base_dir=base_dir, default_name=str(key)
            )
            environments[environment.name] = environment
    else:
        for idx, raw_environment in enumerate(
            _as_list(raw_environments, field_name=f"{bundle_path}.environments")
        ):
            environment = _environment_from_object(raw_environment, base_dir=base_dir)
            if environment.name in environments:
                raise EvidenceFormatError(f"duplicate environment {environment.name}")
            environments[environment.name] = environment

    snapshots = _snapshots_from_bundle_value(
        _first(
            data,
            "advisory_snapshots",
            "advisory_snapshot",
            "snapshots",
            "advisories",
            "advisory_records",
        ),
        base_dir=base_dir,
    )
    snapshots.extend(load_advisory_paths(extra_snapshots))

    closures = _closures_from_value(
        _first(data, "closures", "closure_ledger", "closure_records", "decisions")
    )
    closures.extend(load_closure_paths(extra_closures))

    return EvidenceBundle(
        environments=environments,
        snapshots=tuple(snapshots),
        closures=_dedupe_closures(closures),
        license_policy=_license_policy_from_data(data.get("license_policy")),
    )


def _select_snapshot(
    snapshots: Iterable[AdvisorySnapshot],
    advisory_id: str,
    as_of: _dt.datetime,
    visible_at: _dt.datetime,
) -> AdvisorySnapshot | None:
    """Select the newest effective snapshot that was visible at the query instant."""

    eligible = [
        snapshot
        for snapshot in snapshots
        if snapshot.advisory_id == advisory_id
        and snapshot.retrieved_at <= visible_at
        and snapshot.effective_at <= as_of
    ]
    if not eligible:
        return None
    return max(
        eligible,
        key=lambda snapshot: (
            snapshot.effective_at,
            snapshot.retrieved_at,
            snapshot.version or "",
        ),
    )


def _artifact_by_name(environment: Environment, name: str) -> Artifact | None:
    """Look up an artifact by its canonical package name."""

    return environment.artifacts.get(canonicalize_name(name))


def _visible_audits(environment: Environment, visible_at: _dt.datetime) -> tuple[OfflineAudit, ...]:
    """Return offline audits that were obtained by the visibility instant."""

    return tuple(audit for audit in environment.offline_audits if audit.retrieved_at <= visible_at)


def _audit_evidence(
    environment: Environment,
    artifact: Artifact,
    advisory_id: str,
    visible_at: _dt.datetime,
    as_of: _dt.datetime,
) -> tuple[bool, bool, OfflineAudit | None]:
    """Return (observed, reported, audit) for the latest usable offline audit.

    An offline result is an observation, not a valid-time assertion.  We
    therefore use it only when it was both obtained by the visibility instant
    and captured on or before the query date.  A later capture can still be
    used when it is visible and the query date has caught up with it.
    """

    audits = tuple(
        audit
        for audit in _visible_audits(environment, visible_at)
        if (audit.effective_at or audit.retrieved_at) <= as_of
    )
    if not audits:
        return False, False, None
    latest = audits[-1]
    observed = latest.dependencies.get(artifact.canonical_name) == artifact.version
    reported = advisory_id in latest.reported.get(artifact.canonical_name, frozenset())
    return observed, reported, latest


def _status_for(
    environment: Environment,
    artifact: Artifact,
    advisory_id: str,
    snapshots: Iterable[AdvisorySnapshot],
    as_of: _dt.datetime,
    visible_at: _dt.datetime,
) -> tuple[Status, AdvisorySnapshot | None, OfflineAudit | None, bool]:
    """Evaluate one artifact, combining snapshots and offline audit evidence."""

    snapshot = _select_snapshot(snapshots, advisory_id, as_of, visible_at)
    observed, reported, audit = _audit_evidence(
        environment, artifact, advisory_id, visible_at, as_of
    )

    if snapshot is None:
        snapshot_status = Status.UNKNOWN
    elif snapshot.withdrawn_at is not None and snapshot.withdrawn_at <= visible_at:
        snapshot_status = Status.WITHDRAWN
    else:
        snapshot_status = snapshot.status_for(artifact)

    conflict = False
    if reported:
        if snapshot_status in (Status.NOT_AFFECTED, Status.WITHDRAWN):
            conflict = True
        status = Status.AFFECTED
    else:
        status = snapshot_status
        if observed and snapshot_status is Status.AFFECTED:
            conflict = True
    return status, snapshot, audit, conflict


def _snapshot_reason(
    snapshot: AdvisorySnapshot | None, audit: OfflineAudit | None, status: Status
) -> Reason | None:
    """Choose the most specific human-readable reason available."""

    if snapshot is not None and snapshot.reason is not None:
        return snapshot.reason
    if snapshot is not None and snapshot.description:
        return Reason(snapshot.description, snapshot.visibility, snapshot.license)
    if audit is not None and status is Status.AFFECTED:
        return Reason("reported by offline pip-audit result", Visibility.PUBLIC, None)
    return None


def _redacted_reason(
    reason: Reason | None,
    default_license: str | None,
    policy: LicensePolicy,
    audience: Audience,
) -> tuple[str | None, bool]:
    """Return (text, redacted) without leaking restricted reasons."""

    if reason is None:
        return None, False
    if policy.reason_visible(reason, default_license, audience):
        return reason.text, False
    return None, True


def _finding_for(
    environment: Environment,
    artifact: Artifact,
    advisory_id: str,
    snapshots: Iterable[AdvisorySnapshot],
    as_of: _dt.datetime,
    visible_at: _dt.datetime,
    policy: LicensePolicy,
    audience: Audience,
) -> Finding | None:
    """Build a finding for one artifact and advisory, or return None when clean."""

    status, snapshot, audit, conflict = _status_for(
        environment, artifact, advisory_id, snapshots, as_of, visible_at
    )
    if status in (Status.NOT_AFFECTED, Status.WITHDRAWN):
        return None

    reason = _snapshot_reason(snapshot, audit, status)
    reason_text, redacted = _redacted_reason(
        reason,
        snapshot.license if snapshot is not None else None,
        policy,
        audience,
    )
    effective_at = snapshot.effective_at if snapshot is not None else None
    retrieved_at = (
        snapshot.retrieved_at
        if snapshot is not None
        else (audit.retrieved_at if audit is not None else None)
    )
    source = snapshot.source if snapshot is not None else (audit.source if audit else None)
    return Finding(
        environment=environment.name,
        artifact=artifact.canonical_name,
        version=str(artifact.version),
        advisory_id=advisory_id,
        status=status,
        reason=reason_text,
        reason_redacted=redacted,
        effective_at=effective_at,
        retrieved_at=retrieved_at,
        snapshot_version=snapshot.version if snapshot is not None else None,
        source=source,
        evidence_conflict=conflict,
    )


def _closure_status(
    closure: Closure,
    environment: Environment,
    snapshots: Iterable[AdvisorySnapshot],
    as_of: _dt.datetime,
    visible_at: _dt.datetime,
) -> tuple[Status, AdvisorySnapshot | None, OfflineAudit | None]:
    """Evaluate the scope covered by a closure."""

    snapshot = _select_snapshot(snapshots, closure.advisory_id, as_of, visible_at)
    if closure.artifact is not None:
        artifact = _artifact_by_name(environment, closure.artifact)
        if artifact is None:
            return Status.UNKNOWN, snapshot, None
        status, snapshot, audit, _ = _status_for(
            environment, artifact, closure.advisory_id, snapshots, as_of, visible_at
        )
        return status, snapshot, audit

    if not environment.artifacts:
        return Status.UNKNOWN, snapshot, None
    statuses: list[Status] = []
    audits: list[OfflineAudit] = []
    for artifact in environment.artifacts.values():
        status, snapshot, audit, _ = _status_for(
            environment, artifact, closure.advisory_id, snapshots, as_of, visible_at
        )
        statuses.append(status)
        if audit is not None:
            audits.append(audit)
    if any(status is Status.AFFECTED for status in statuses):
        return Status.AFFECTED, snapshot, (audits[-1] if audits else None)
    if any(status is Status.UNKNOWN for status in statuses):
        return Status.UNKNOWN, snapshot, (audits[-1] if audits else None)
    if any(status is Status.WITHDRAWN for status in statuses):
        return Status.WITHDRAWN, snapshot, (audits[-1] if audits else None)
    return Status.NOT_AFFECTED, snapshot, (audits[-1] if audits else None)


def _closure_review(
    closure: Closure,
    environment: Environment,
    snapshots: Iterable[AdvisorySnapshot],
    as_of: _dt.datetime,
    visible_at: _dt.datetime,
    policy: LicensePolicy,
    audience: Audience,
) -> ClosureReview:
    """Preserve a closure while showing its decision basis and current status."""

    decision_status, decision_snapshot, decision_audit = _closure_status(
        closure, environment, snapshots, closure.as_of, closure.closed_at
    )
    current_status, current_snapshot, current_audit = _closure_status(
        closure, environment, snapshots, as_of, visible_at
    )
    decision_reason = closure.reason or _snapshot_reason(
        decision_snapshot, decision_audit, decision_status
    )
    current_reason = _snapshot_reason(current_snapshot, current_audit, current_status)
    decision_text, decision_redacted = _redacted_reason(
        decision_reason,
        (
            closure.reason.license
            if closure.reason is not None
            else (decision_snapshot.license if decision_snapshot is not None else None)
        ),
        policy,
        audience,
    )
    current_text, current_redacted = _redacted_reason(
        current_reason,
        current_snapshot.license if current_snapshot is not None else None,
        policy,
        audience,
    )
    evidence = closure.evidence
    if evidence is None and decision_snapshot is not None:
        evidence = decision_snapshot.version or decision_snapshot.source
    return ClosureReview(
        closure_id=closure.closure_id,
        environment=closure.environment,
        advisory_id=closure.advisory_id,
        artifact=closure.artifact,
        closed_at=closure.closed_at,
        as_of=closure.as_of,
        decision_status=decision_status,
        decision_reason=decision_text,
        decision_reason_redacted=decision_redacted,
        current_status=current_status,
        current_reason=current_text,
        current_reason_redacted=current_redacted,
        reopen_required=current_status is Status.AFFECTED,
        evidence=evidence,
    )


def _closure_covers(closure: ClosureReview, finding: Finding) -> bool:
    """Return whether a closure already covers a finding."""

    if closure.advisory_id != finding.advisory_id:
        return False
    if closure.artifact is None:
        return True
    return canonicalize_name(closure.artifact) == canonicalize_name(finding.artifact)


def _work_items(
    environment: Environment,
    findings: tuple[Finding, ...],
    closures: tuple[ClosureReview, ...],
) -> tuple[WorkItem, ...]:
    """Derive reopen and investigation work without rewriting past closures."""

    work: dict[tuple[str, str, str], WorkItem] = {}
    finding_by_key = {(finding.advisory_id, finding.artifact): finding for finding in findings}
    for closure in closures:
        artifact_key = closure.artifact or "*"
        key = (closure.advisory_id, artifact_key, closure.closure_id)
        action = (
            Action.REOPEN
            if closure.reopen_required
            else (Action.INVESTIGATE if closure.current_status is Status.UNKNOWN else Action.NONE)
        )
        if action is Action.NONE:
            continue
        finding = None
        if closure.artifact is None:
            finding = next(
                (
                    candidate
                    for candidate in findings
                    if candidate.advisory_id == closure.advisory_id
                    and candidate.status is Status.AFFECTED
                ),
                None,
            )
        else:
            finding = finding_by_key.get((closure.advisory_id, canonicalize_name(closure.artifact)))
        work[key] = WorkItem(
            action=action,
            environment=environment.name,
            artifact=closure.artifact,
            advisory_id=closure.advisory_id,
            status=closure.current_status,
            previous_closure=closure.closure_id,
            reason=closure.current_reason,
            reason_redacted=closure.current_reason_redacted,
            effective_at=finding.effective_at if finding is not None else None,
            retrieved_at=finding.retrieved_at if finding is not None else None,
            source=finding.source if finding is not None else None,
        )

    for finding in findings:
        if any(_closure_covers(closure, finding) for closure in closures):
            continue
        if finding.status not in (Status.AFFECTED, Status.UNKNOWN):
            continue
        key = (finding.advisory_id, finding.artifact, "")
        work[key] = WorkItem(
            action=Action.INVESTIGATE,
            environment=environment.name,
            artifact=finding.artifact,
            advisory_id=finding.advisory_id,
            status=finding.status,
            previous_closure=None,
            reason=finding.reason,
            reason_redacted=finding.reason_redacted,
            effective_at=finding.effective_at,
            retrieved_at=finding.retrieved_at,
            source=finding.source,
        )
    return tuple(
        sorted(
            work.values(),
            key=lambda item: (
                item.environment,
                item.artifact or "",
                item.advisory_id,
                item.action.value,
            ),
        )
    )


def _drift_for(environment: Environment, visible_at: _dt.datetime) -> tuple[str, ...]:
    """Report lockfile versus offline-audit version differences."""

    drift: list[str] = []
    for audit in _visible_audits(environment, visible_at):
        for name, version in audit.dependencies.items():
            artifact = environment.artifacts.get(name)
            if artifact is not None and artifact.version != version:
                drift.append(
                    f"{name}: lockfile {artifact.version}, audit {version} ({audit.source})"
                )
    return tuple(sorted(set(drift)))


def reconcile(
    bundle: EvidenceBundle,
    *,
    as_of: str | _dt.date | _dt.datetime,
    visible_at: str | _dt.date | _dt.datetime,
    audience: Audience = Audience.EXTERNAL,
    label: str = "view",
) -> View:
    """Reconcile all environments at one valid-time and visibility-time pair."""

    parsed_as_of = _parse_instant(as_of, field_name="as_of", end_of_day=True)
    parsed_visible_at = _parse_instant(visible_at, field_name="visible_at")
    snapshots = tuple(
        sorted(
            bundle.snapshots,
            key=lambda snapshot: (
                snapshot.advisory_id,
                snapshot.effective_at,
                snapshot.retrieved_at,
                snapshot.version or "",
            ),
        )
    )
    environments: dict[str, EnvironmentReview] = {}
    reopen_environments: set[str] = set()
    redactions = 0

    for environment in sorted(bundle.environments.values(), key=lambda env: env.name):
        advisory_ids = {snapshot.advisory_id for snapshot in snapshots}
        for audit in _visible_audits(environment, parsed_visible_at):
            for ids in audit.reported.values():
                advisory_ids.update(ids)

        findings: list[Finding] = []
        for artifact in sorted(
            environment.artifacts.values(), key=lambda artifact: artifact.canonical_name
        ):
            for advisory_id in sorted(advisory_ids):
                finding = _finding_for(
                    environment,
                    artifact,
                    advisory_id,
                    snapshots,
                    parsed_as_of,
                    parsed_visible_at,
                    bundle.license_policy,
                    audience,
                )
                if finding is not None:
                    findings.append(finding)

        closure_reviews = tuple(
            _closure_review(
                closure,
                environment,
                snapshots,
                parsed_as_of,
                parsed_visible_at,
                bundle.license_policy,
                audience,
            )
            for closure in bundle.closures
            if closure.environment == environment.name and closure.closed_at <= parsed_visible_at
        )
        work = _work_items(environment, tuple(findings), closure_reviews)
        redactions += sum(1 for finding in findings if finding.reason_redacted)
        redactions += sum(1 for closure in closure_reviews if closure.decision_reason_redacted)
        redactions += sum(1 for closure in closure_reviews if closure.current_reason_redacted)
        for item in work:
            if item.action is Action.REOPEN:
                reopen_environments.add(environment.name)

        environments[environment.name] = EnvironmentReview(
            name=environment.name,
            artifacts={
                canonical: str(artifact.version)
                for canonical, artifact in sorted(environment.artifacts.items())
            },
            findings=tuple(findings),
            closures=closure_reviews,
            work=work,
            drift=_drift_for(environment, parsed_visible_at),
        )

    return View(
        label=label,
        as_of=parsed_as_of,
        visible_at=parsed_visible_at,
        audience=audience,
        environments=environments,
        reopen_environments=tuple(sorted(reopen_environments)),
        redactions=redactions,
    )


def _status_map(view: View) -> dict[tuple[str, str, str], tuple[Status, Finding | None]]:
    """Build an environment/advisory/artifact status map for comparison."""

    statuses: dict[tuple[str, str, str], tuple[Status, Finding | None]] = {}
    for environment_name, environment in view.environments.items():
        for finding in environment.findings:
            statuses[(environment_name, finding.advisory_id, finding.artifact)] = (
                finding.status,
                finding,
            )
        for closure in environment.closures:
            if closure.artifact is not None:
                key = (
                    environment_name,
                    closure.advisory_id,
                    canonicalize_name(closure.artifact),
                )
                statuses.setdefault(key, (closure.current_status, None))
            else:
                for artifact in environment.artifacts:
                    key = (environment_name, closure.advisory_id, artifact)
                    statuses.setdefault(key, (closure.current_status, None))
    return statuses


def _closure_keys(view: View) -> set[tuple[str, str, str | None]]:
    """Return the closure scope keys present in a view."""

    keys: set[tuple[str, str, str | None]] = set()
    for environment_name, environment in view.environments.items():
        for closure in environment.closures:
            keys.add((environment_name, closure.advisory_id, closure.artifact))
    return keys


def compare_views(earlier: View, later: View) -> Comparison:
    """Compare two views that share one valid-time date."""

    if earlier.as_of != later.as_of:
        raise TemporalError("comparison requires both views to use the same as_of date")
    earlier_statuses = _status_map(earlier)
    later_statuses = _status_map(later)
    later_closures = _closure_keys(later)
    changes: list[Change] = []
    for key in sorted(set(earlier_statuses) | set(later_statuses)):
        environment, advisory_id, artifact = key
        before, _ = earlier_statuses.get(key, (Status.NOT_AFFECTED, None))
        after, _ = later_statuses.get(key, (Status.NOT_AFFECTED, None))
        closure_exists = any(
            env == environment
            and advisory == advisory_id
            and (scope is None or canonicalize_name(scope) == canonicalize_name(artifact))
            for env, advisory, scope in later_closures
        )
        if after is Status.AFFECTED:
            action = Action.REOPEN if closure_exists else Action.INVESTIGATE
        elif after is Status.UNKNOWN:
            action = Action.INVESTIGATE
        else:
            action = Action.NONE
        if before is not after or action is not Action.NONE:
            changes.append(
                Change(
                    environment=environment,
                    artifact=artifact,
                    advisory_id=advisory_id,
                    before=before,
                    after=after,
                    action=action,
                )
            )
    reopen: list[WorkItem] = []
    for environment in later.environments.values():
        reopen.extend(item for item in environment.work if item.action is Action.REOPEN)
    return Comparison(
        as_of=earlier.as_of,
        earlier=earlier,
        later=later,
        changes=tuple(
            sorted(
                changes,
                key=lambda change: (change.environment, change.artifact, change.advisory_id),
            )
        ),
        reopen=tuple(
            sorted(
                reopen,
                key=lambda item: (item.environment, item.artifact or "", item.advisory_id),
            )
        ),
    )


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "environment": finding.environment,
        "artifact": finding.artifact,
        "version": finding.version,
        "advisory_id": finding.advisory_id,
        "status": finding.status.value,
        "reason": finding.reason,
        "reason_redacted": finding.reason_redacted,
        "redaction": "license" if finding.reason_redacted else None,
        "effective_at": _isoformat(finding.effective_at),
        "retrieved_at": _isoformat(finding.retrieved_at),
        "snapshot_version": finding.snapshot_version,
        "source": finding.source,
        "evidence_conflict": finding.evidence_conflict,
    }


def _closure_dict(closure: ClosureReview) -> dict[str, Any]:
    return {
        "closure_id": closure.closure_id,
        "environment": closure.environment,
        "advisory_id": closure.advisory_id,
        "artifact": closure.artifact,
        "preserved": True,
        "closed_at": _isoformat(closure.closed_at),
        "as_of": _isoformat(closure.as_of),
        "decision_status": closure.decision_status.value,
        "decision_reason": closure.decision_reason,
        "decision_reason_redacted": closure.decision_reason_redacted,
        "decision_redaction": "license" if closure.decision_reason_redacted else None,
        "current_status": closure.current_status.value,
        "current_reason": closure.current_reason,
        "current_reason_redacted": closure.current_reason_redacted,
        "current_redaction": "license" if closure.current_reason_redacted else None,
        "reopen_required": closure.reopen_required,
        "evidence": closure.evidence,
    }


def _work_dict(item: WorkItem) -> dict[str, Any]:
    return {
        "action": item.action.value,
        "environment": item.environment,
        "artifact": item.artifact,
        "advisory_id": item.advisory_id,
        "status": item.status.value,
        "previous_closure": item.previous_closure,
        "reason": item.reason,
        "reason_redacted": item.reason_redacted,
        "redaction": "license" if item.reason_redacted else None,
        "effective_at": _isoformat(item.effective_at),
        "retrieved_at": _isoformat(item.retrieved_at),
        "source": item.source,
    }


def view_as_dict(view: View) -> dict[str, Any]:
    """Serialize a reconciliation view to a stable JSON-compatible mapping."""

    environments: dict[str, Any] = {}
    for name, environment in sorted(view.environments.items()):
        environments[name] = {
            "artifacts": dict(sorted(environment.artifacts.items())),
            "drift": list(environment.drift),
            "findings": [_finding_dict(finding) for finding in environment.findings],
            "closures": [_closure_dict(closure) for closure in environment.closures],
            "work": [_work_dict(item) for item in environment.work],
        }
    reopen_count = sum(
        1
        for environment in view.environments.values()
        for item in environment.work
        if item.action is Action.REOPEN
    )
    investigate_count = sum(
        1
        for environment in view.environments.values()
        for item in environment.work
        if item.action is Action.INVESTIGATE
    )
    finding_count = sum(len(environment.findings) for environment in view.environments.values())
    closure_count = sum(len(environment.closures) for environment in view.environments.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "pip-audit-temporal-reconciliation",
        "label": view.label,
        "as_of": _isoformat(view.as_of),
        "as_of_date": _date_only(view.as_of),
        "visible_at": _isoformat(view.visible_at),
        "audience": view.audience.value,
        "summary": {
            "reopen_environments": list(view.reopen_environments),
            "reopen_count": reopen_count,
            "investigate_count": investigate_count,
            "finding_count": finding_count,
            "closure_count": closure_count,
            "redactions": view.redactions,
        },
        "redactions": view.redactions,
        "reopen_environments": list(view.reopen_environments),
        "environments": environments,
    }


def comparison_as_dict(comparison: Comparison) -> dict[str, Any]:
    """Serialize a two-view comparison to a stable JSON-compatible mapping."""

    changes = [
        {
            "environment": change.environment,
            "artifact": change.artifact,
            "advisory_id": change.advisory_id,
            "before": change.before.value,
            "after": change.after.value,
            "action": change.action.value,
        }
        for change in comparison.changes
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "pip-audit-temporal-reconciliation-comparison",
        "same_as_of": comparison.earlier.as_of == comparison.later.as_of,
        "as_of": _isoformat(comparison.as_of),
        "as_of_date": _date_only(comparison.as_of),
        "views": [
            {
                "label": comparison.earlier.label,
                "visible_at": _isoformat(comparison.earlier.visible_at),
            },
            {
                "label": comparison.later.label,
                "visible_at": _isoformat(comparison.later.visible_at),
            },
        ],
        "changes": changes,
        "reopen": [_work_dict(item) for item in comparison.reopen],
    }


def views_document(views: Sequence[View], comparison: Comparison | None = None) -> dict[str, Any]:
    """Build the JSON document that keeps comparable views together."""

    if not views:
        raise ReconciliationError("at least one view is required")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "pip-audit-temporal-reconciliation-views",
        "as_of": _isoformat(views[0].as_of),
        "as_of_date": _date_only(views[0].as_of),
        "views": [view_as_dict(view) for view in views],
        "comparison": comparison_as_dict(comparison) if comparison is not None else None,
    }


def render_json(document: Mapping[str, Any], *, indent: int = 2) -> str:
    """Render a JSON-compatible mapping deterministically."""

    return json.dumps(document, indent=indent, sort_keys=True)


def _md_cell(value: Any) -> str:
    """Escape a value for a Markdown table cell."""

    if value is None:
        return "-"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _md_reason(reason: str | None, redacted: bool) -> str:
    """Render a reason without exposing a restricted value."""

    if redacted:
        return "(redacted: license restriction)"
    if reason:
        return _md_cell(reason)
    return "-"


def _md_row(cells: Sequence[str]) -> str:
    """Render one Markdown table row from already-escaped cells."""

    return "| " + " | ".join(cells) + " |"


def render_view_markdown(view: View) -> str:
    """Render one view as a human-readable Markdown section."""

    reopen_text = ", ".join(view.reopen_environments) or "none"
    lines = [
        f"### {view.label}",
        "",
        f"- As of: {_date_only(view.as_of)}",
        f"- Visible at: {_isoformat(view.visible_at)}",
        f"- Audience: {view.audience.value}",
        f"- Reopen environments: {_md_cell(reopen_text)}",
        f"- Redacted reasons: {view.redactions}",
        "",
    ]
    for name, environment in sorted(view.environments.items()):
        lines.extend([f"#### Environment {name}", ""])
        artifact_text = ", ".join(
            f"{artifact}=={version}" for artifact, version in sorted(environment.artifacts.items())
        )
        lines.append("Artifacts: " + _md_cell(artifact_text))
        if environment.drift:
            lines.append("Evidence drift: " + _md_cell("; ".join(environment.drift)))
        lines.append("")
        if environment.findings:
            lines.extend(
                [
                    "| Artifact | Version | Advisory | Status | Effective | Retrieved | Conflict | Reason |",
                    "| --- | --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
            lines.extend(
                _md_row(
                    [
                        _md_cell(finding.artifact),
                        _md_cell(finding.version),
                        _md_cell(finding.advisory_id),
                        _md_cell(finding.status.value),
                        _md_cell(_isoformat(finding.effective_at)),
                        _md_cell(_isoformat(finding.retrieved_at)),
                        _md_cell("yes" if finding.evidence_conflict else "no"),
                        _md_reason(finding.reason, finding.reason_redacted),
                    ]
                )
                for finding in environment.findings
            )
        else:
            lines.append("No affected artifacts in this view.")
        lines.append("")
        if environment.closures:
            lines.extend(
                [
                    "| Closure | Advisory | Decision status | Current status | Reopen | Decision reason |",
                    "| --- | --- | --- | --- | --- | --- |",
                ]
            )
            lines.extend(
                _md_row(
                    [
                        _md_cell(closure.closure_id),
                        _md_cell(closure.advisory_id),
                        _md_cell(closure.decision_status.value),
                        _md_cell(closure.current_status.value),
                        _md_cell("yes" if closure.reopen_required else "no"),
                        _md_reason(closure.decision_reason, closure.decision_reason_redacted),
                    ]
                )
                for closure in environment.closures
            )
            lines.append("")
        if environment.work:
            lines.extend(
                [
                    "| Action | Artifact | Advisory | Previous closure | Reason |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            lines.extend(
                _md_row(
                    [
                        _md_cell(item.action.value),
                        _md_cell(item.artifact or "(environment)"),
                        _md_cell(item.advisory_id),
                        _md_cell(item.previous_closure),
                        _md_reason(item.reason, item.reason_redacted),
                    ]
                )
                for item in environment.work
            )
            lines.append("")
    return "\n".join(lines)


def render_markdown(views: Sequence[View], comparison: Comparison | None = None) -> str:
    """Render two comparable views and their comparison as Markdown."""

    if not views:
        raise ReconciliationError("at least one view is required")
    lines = [
        "# pip-audit temporal reconciliation",
        "",
        f"As of: {_date_only(views[0].as_of)}",
        "",
        "| View | Visible at | Audience | Reopen environments |",
        "| --- | --- | --- | --- |",
    ]
    lines.extend(
        _md_row(
            [
                _md_cell(view.label),
                _md_cell(_isoformat(view.visible_at)),
                _md_cell(view.audience.value),
                _md_cell(", ".join(view.reopen_environments) or "none"),
            ]
        )
        for view in views
    )
    lines.append("")
    for view in views:
        lines.extend([render_view_markdown(view), ""])
    if comparison is not None:
        lines.extend(
            [
                "## Why the earlier closure was valid",
                "",
                "| Closure | Environment | Advisory | Decision status | Decision reason | Evidence |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for environment in comparison.earlier.environments.values():
            lines.extend(
                _md_row(
                    [
                        _md_cell(closure.closure_id),
                        _md_cell(closure.environment),
                        _md_cell(closure.advisory_id),
                        _md_cell(closure.decision_status.value),
                        _md_reason(closure.decision_reason, closure.decision_reason_redacted),
                        _md_cell(closure.evidence),
                    ]
                )
                for closure in environment.closures
            )
        lines.extend(["", "## Work to reopen now", ""])
        if comparison.reopen:
            lines.extend(
                [
                    "| Environment | Artifact | Advisory | Status | Previous closure | Reason |",
                    "| --- | --- | --- | --- | --- | --- |",
                ]
            )
            lines.extend(
                _md_row(
                    [
                        _md_cell(item.environment),
                        _md_cell(item.artifact or "(environment)"),
                        _md_cell(item.advisory_id),
                        _md_cell(item.status.value),
                        _md_cell(item.previous_closure),
                        _md_reason(item.reason, item.reason_redacted),
                    ]
                )
                for item in comparison.reopen
            )
        else:
            lines.append("No closure needs to be reopened in the later view.")
        lines.extend(["", "## Status changes", ""])
        if comparison.changes:
            lines.extend(
                [
                    "| Environment | Artifact | Advisory | Before | After | Action |",
                    "| --- | --- | --- | --- | --- | --- |",
                ]
            )
            lines.extend(
                _md_row(
                    [
                        _md_cell(change.environment),
                        _md_cell(change.artifact),
                        _md_cell(change.advisory_id),
                        _md_cell(change.before.value),
                        _md_cell(change.after.value),
                        _md_cell(change.action.value),
                    ]
                )
                for change in comparison.changes
            )
        else:
            lines.append("No status changes between the two views.")
    return "\n".join(lines)
