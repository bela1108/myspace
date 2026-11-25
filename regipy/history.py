"""Historical snapshot analysis for registry artifacts.

Registry values do not carry their own timestamps.  The only native clock on a
key/value pair is the NK (key node) ``LastWrite`` timestamp, and Windows updates
that timestamp for key-level changes as well as for some child changes.  Treating
it as the timestamp of every value in the key is therefore unsafe, especially
when hives collected at different times are merged.

This module compares snapshots of the same key and builds *value evidence*
timelines from snapshot observation bounds.  The key ``LastWrite`` clock is kept
separate from the value content evidence:

* A value observed in snapshot A is known to have existed no later than A.
* If it is first observed in B, and the preceding snapshot A did not contain it,
  its creation is bounded by [A, B].
* If it disappears in C, its validity is bounded by [last seen, C].
* A key becoming absent and later present again is a hard breakpoint.  Values
  from the old key incarnation are never joined to values from the new one.
* A key ``LastWrite`` change with an unchanged value set is reported as a
  parent-key-only change and never assigns the new key timestamp to the values.

The public entry points are :func:`compare_snapshots`,
:func:`analyze_key_history`, :func:`value_timelines`,
:func:`analyze_recentdocs_history` and :func:`analyze_typed_paths_history`.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import logging
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

UTC = dt.timezone.utc

RECENT_DOCS_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
TYPED_PATHS_KEY_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"


def _to_datetime(value: Any) -> dt.datetime | None:
    """Normalize the many timestamp shapes accepted by snapshot callers."""
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, bool):
        raise TypeError("A boolean is not a valid snapshot timestamp")
    if isinstance(value, (int, float)):
        # A Windows FILETIME is a 64 bit count of 100ns intervals since 1601.
        if abs(value) >= 10**14:
            result = convert_wintime(int(value), as_json=False)
            return result if isinstance(result, dt.datetime) else _to_datetime(result)
        return dt.datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = dt.datetime.fromisoformat(text)
        except ValueError:
            # Numeric FILETIME strings are accepted as a convenience.
            if text.isdigit():
                return _to_datetime(int(text))
            raise
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    raise TypeError(f"Unsupported snapshot timestamp: {value!r}")


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _json_value(value: Any) -> Any:
    """Return a deterministic JSON-safe representation of a registry value."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_value(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    return str(value)


def _canonical(value: Any) -> str:
    """Stable representation used to decide whether two values are identical."""
    return json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _fingerprint(value: Any, value_type: str | None) -> str:
    digest = hashlib.sha256()
    digest.update((value_type or "").encode("utf-8"))
    digest.update(b"\x00")
    digest.update(_canonical(value).encode("utf-8"))
    return digest.hexdigest()


@dataclass
class Snapshot:
    """One observation of a hive (or a mapping standing in for one).

    ``observed_at`` is the acquisition/observation time, not a registry key
    timestamp.  If omitted for a hive path, the file modification time is used.
    ``keys`` may be supplied for synthetic or already-normalized input: it maps
    a key path to ``{"last_write": ..., "values": {...}}`` records.
    """

    observed_at: Any = None
    hive: Any = None
    source: str | None = None
    name: str | None = None
    key_paths: Sequence[str] | None = None
    keys: Mapping[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Snapshot(hive) is a common shorthand for a snapshot without an explicit
        # observation time.  Move the value to the hive field when appropriate.
        shorthand = isinstance(self.observed_at, (RegistryHive, Mapping)) or (
            isinstance(self.observed_at, (str, os.PathLike)) and not _looks_like_timestamp(self.observed_at)
        )
        if self.hive is None and self.keys is None and shorthand:
            self.hive = self.observed_at
            self.observed_at = None

        self.observed_at = _to_datetime(self.observed_at)
        if self.source is None:
            if isinstance(self.hive, (str, os.PathLike)):
                self.source = os.path.basename(os.fspath(self.hive))
            elif self.name:
                self.source = self.name

        if self.observed_at is None and isinstance(self.hive, (str, os.PathLike)):
            with contextlib.suppress(OSError):
                self.observed_at = dt.datetime.fromtimestamp(os.path.getmtime(os.fspath(self.hive)), tz=UTC)

    def summary(self) -> dict[str, Any]:
        return {
            "observed_at": _iso(self.observed_at),
            "source": self.source,
            "name": self.name,
            "metadata": _json_value(self.metadata),
        }


def _looks_like_timestamp(value: Any) -> bool:
    if isinstance(value, (dt.datetime, dt.date, int, float)):
        return True
    if not isinstance(value, str):
        return False
    try:
        _to_datetime(value)
        return True
    except (TypeError, ValueError):
        return False


@dataclass
class ValueRecord:
    name: str
    value: Any
    value_type: str | None = None
    index: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.value, self.value_type)


@dataclass
class KeyObservation:
    path: str
    observed_at: dt.datetime | None
    exists: bool
    source: str | None = None
    last_write: dt.datetime | None = None
    last_write_raw: Any = None
    values: list[ValueRecord] = field(default_factory=list)
    key_id: Any = None


@dataclass
class Generation:
    index: int
    start_index: int
    last_present_index: int
    observations: list[KeyObservation]
    break_reason: str | None = None
    break_at: dt.datetime | None = None
    boundary_index: int | None = None
    closed_reason: str | None = None

    @property
    def start_observed(self) -> dt.datetime | None:
        return self.observations[0].observed_at if self.observations else None

    @property
    def end_observed(self) -> dt.datetime | None:
        if not self.observations:
            return None
        return self.observations[-1].observed_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "start_observed": _iso(self.start_observed),
            "end_observed": _iso(self.end_observed),
            "break_reason": self.break_reason,
            "break_at": _iso(self.break_at),
            "closed_reason": self.closed_reason,
        }


@dataclass
class ValueObservation:
    observed_at: dt.datetime | None
    source: str | None
    value: Any
    value_type: str | None
    key_last_write: dt.datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_at": _iso(self.observed_at),
            "source": self.source,
            "value": _json_value(self.value),
            "value_type": self.value_type,
            "key_last_write": _iso(self.key_last_write),
            "time_basis": "snapshot_observation",
        }


@dataclass
class EvidenceRange:
    # Observation bounds plus the outer possible-validity bounds.

    first_observed: dt.datetime | None
    last_observed: dt.datetime | None
    earliest: dt.datetime | None
    latest: dt.datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "first_observed": _iso(self.first_observed),
            "last_observed": _iso(self.last_observed),
            "earliest": _iso(self.earliest),
            "latest": _iso(self.latest),
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


@dataclass
class ValueTimeline:
    """Content evidence for one value name within one key incarnation."""

    key_path: str
    value_name: str
    value_type: str | None
    content: Any
    content_hash: str
    generation: int
    first_observed: dt.datetime | None
    last_observed: dt.datetime | None
    valid_from_earliest: dt.datetime | None
    valid_from_latest: dt.datetime | None
    valid_to_earliest: dt.datetime | None
    valid_to_latest: dt.datetime | None
    observations: list[ValueObservation] = field(default_factory=list)
    key_clock: list[dict[str, Any]] = field(default_factory=list)
    parent_key_changed_only: bool = False
    closed_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        observations = [item.to_dict() for item in self.observations]
        result = {
            "key_path": self.key_path,
            "value_name": self.value_name,
            "name": self.value_name,
            "value_type": self.value_type,
            "content": _json_value(self.content),
            "value": _json_value(self.content),
            "content_hash": self.content_hash,
            "fingerprint": self.content_hash,
            "generation": self.generation,
            "first_observed": _iso(self.first_observed),
            "last_observed": _iso(self.last_observed),
            "first_seen": _iso(self.first_observed),
            "last_seen": _iso(self.last_observed),
            "first_observed_at": _iso(self.first_observed),
            "last_observed_at": _iso(self.last_observed),
            "valid_from_earliest": _iso(self.valid_from_earliest),
            "valid_from_latest": _iso(self.valid_from_latest),
            "valid_to_earliest": _iso(self.valid_to_earliest),
            "valid_to_latest": _iso(self.valid_to_latest),
            "observed_range": {
                "start": _iso(self.first_observed),
                "end": _iso(self.last_observed),
            },
            "range": {
                "start": _iso(self.valid_from_earliest),
                "end": _iso(self.valid_to_latest),
                "first_observed": _iso(self.first_observed),
                "last_observed": _iso(self.last_observed),
            },
            "evidence_range": {
                "first_observed": _iso(self.first_observed),
                "last_observed": _iso(self.last_observed),
                "earliest": _iso(self.valid_from_earliest),
                "latest": _iso(self.valid_to_latest),
            },
            "valid_from": {
                "earliest": _iso(self.valid_from_earliest),
                "latest": _iso(self.valid_from_latest),
            },
            "valid_to": {
                "earliest": _iso(self.valid_to_earliest),
                "latest": _iso(self.valid_to_latest),
            },
            "possible_validity_range": {
                "start": _iso(self.valid_from_earliest),
                "start_no_later_than": _iso(self.valid_from_latest),
                "end_no_earlier_than": _iso(self.valid_to_earliest),
                "end": _iso(self.valid_to_latest),
            },
            "observations": observations,
            "observation_times": [item["observed_at"] for item in observations],
            "key_clock": self.key_clock,
            "parent_key_changed_only": self.parent_key_changed_only,
            "closed_reason": self.closed_reason,
            "content_evidence": True,
            "time_basis": "snapshot_observation_bounds",
            "key_last_write_is_value_time": False,
        }
        result.update(_json_value(self.metadata))
        return result

    @property
    def first_seen(self) -> dt.datetime | None:
        return self.first_observed

    @property
    def last_seen(self) -> dt.datetime | None:
        return self.last_observed

    @property
    def valid_from(self) -> dt.datetime | None:
        return self.valid_from_earliest if self.valid_from_earliest is not None else self.valid_from_latest

    @property
    def valid_to(self) -> dt.datetime | None:
        return self.valid_to_latest if self.valid_to_latest is not None else self.valid_to_earliest

    @property
    def observed_range(self) -> EvidenceRange:
        return EvidenceRange(
            first_observed=self.first_observed,
            last_observed=self.last_observed,
            earliest=self.valid_from_earliest,
            latest=self.valid_to_latest,
        )

    @property
    def evidence_range(self) -> EvidenceRange:
        return self.observed_range


@dataclass
class KeyHistory:
    key_path: str
    observations: list[KeyObservation]
    generations: list[Generation]
    value_timelines: list[ValueTimeline]
    comparisons: list[dict[str, Any]]
    breakpoints: list[dict[str, Any]]

    @property
    def key_clock(self) -> list[dict[str, Any]]:
        clock = []
        for observation in self.observations:
            clock.append(
                {
                    "observed_at": _iso(observation.observed_at),
                    "source": observation.source,
                    "exists": observation.exists,
                    "last_write": _iso(observation.last_write),
                    "last_write_raw": observation.last_write_raw,
                    "level": "key",
                }
            )
        return clock

    @property
    def parent_only_changes(self) -> list[dict[str, Any]]:
        return [item for item in self.comparisons if item.get("type") in ("parent_key_only", "parent_key_changed_only")]

    @property
    def timelines(self) -> list[ValueTimeline]:
        return self.value_timelines

    @property
    def value_evidence(self) -> list[ValueTimeline]:
        return self.value_timelines

    @property
    def key_last_write_clock(self) -> list[dict[str, Any]]:
        return self.key_clock

    def to_dict(self) -> dict[str, Any]:
        value_timelines = [timeline.to_dict() for timeline in self.value_timelines]
        return {
            "key_path": self.key_path,
            "key_clock": self.key_clock,
            "key_last_write_clock": self.key_clock,
            "last_writes": self.key_clock,
            "generations": [generation.to_dict() for generation in self.generations],
            "incarnations": [generation.to_dict() for generation in self.generations],
            "breakpoints": self.breakpoints,
            "value_timelines": value_timelines,
            "value_evidence": value_timelines,
            "timelines": value_timelines,
            "comparisons": self.comparisons,
            "parent_only_changes": self.parent_only_changes,
            "clock_basis": "key_last_write",
            "value_time_basis": "snapshot_observation_bounds",
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


@dataclass
class HistoryReport:
    snapshots: list[Snapshot]
    key_histories: dict[str, KeyHistory] = field(default_factory=dict)

    @property
    def key_paths(self) -> list[str]:
        return list(self.key_histories)

    @property
    def keys(self) -> list[str]:
        return self.key_paths

    @property
    def value_timelines(self) -> list[ValueTimeline]:
        result: list[ValueTimeline] = []
        for key_history in self.key_histories.values():
            result.extend(key_history.value_timelines)
        return result

    @property
    def timelines(self) -> list[ValueTimeline]:
        return self.value_timelines

    @property
    def value_evidence(self) -> list[ValueTimeline]:
        return self.value_timelines

    @property
    def comparisons(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for key_history in self.key_histories.values():
            result.extend(key_history.comparisons)
        return result

    @property
    def breakpoints(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for key_history in self.key_histories.values():
            result.extend(key_history.breakpoints)
        return result

    @property
    def parent_only_changes(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for key_history in self.key_histories.values():
            result.extend(key_history.parent_only_changes)
        return result

    def to_dict(self) -> dict[str, Any]:
        timelines = [timeline.to_dict() for timeline in self.value_timelines]
        comparisons = self.comparisons
        breakpoints = self.breakpoints
        return {
            "snapshots": [snapshot.summary() for snapshot in self.snapshots],
            "key_paths": list(self.key_histories),
            "keys": {path: history.to_dict() for path, history in self.key_histories.items()},
            "key_history": {path: history.to_dict() for path, history in self.key_histories.items()},
            "value_timelines": timelines,
            "value_evidence": timelines,
            "timelines": timelines,
            "comparisons": comparisons,
            "parent_only_changes": [
                item for item in comparisons if item.get("type") in ("parent_key_only", "parent_key_changed_only")
            ],
            "breakpoints": breakpoints,
            "clock_basis": "key_last_write",
            "value_time_basis": "snapshot_observation_bounds",
            "key_last_write_is_value_time": False,
        }

    def __getitem__(self, key_path: str) -> KeyHistory:
        return self.key_histories[key_path]

    def get(self, key_path: str, default: Any = None) -> Any:
        return self.key_histories.get(key_path, default)

    def __iter__(self):
        return iter(self.value_timelines)


class HistoryReportDict(dict):
    """JSON-safe report dict that also exposes timelines by integer index."""

    def __init__(self, report: HistoryReport):
        super().__init__(report.to_dict())
        self.report = report
        self._timelines = list(self["value_timelines"])

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._timelines[key]
        return super().__getitem__(key)

    def __iter__(self):
        return iter(self._timelines)

    def __len__(self) -> int:
        return len(self._timelines)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, list):
            return self._timelines == other
        return super().__eq__(other)

    def __getattr__(self, name: str) -> Any:
        try:
            return getattr(self.report, name)
        except AttributeError:
            raise AttributeError(name) from None


class SnapshotHistory:
    """Convenience wrapper around a set of snapshots and their analyses."""

    def __init__(self, snapshots: Any, key_paths: Iterable[str] | None = None):
        self.snapshots = normalize_snapshots(snapshots)
        self.report = compare_snapshots(self.snapshots, key_paths) if key_paths is not None else HistoryReport(self.snapshots)

    @property
    def value_timelines(self) -> list[ValueTimeline]:
        return self.report.value_timelines

    @property
    def comparisons(self) -> list[dict[str, Any]]:
        return self.report.comparisons

    @property
    def breakpoints(self) -> list[dict[str, Any]]:
        return self.report.breakpoints

    @property
    def parent_only_changes(self) -> list[dict[str, Any]]:
        return self.report.parent_only_changes

    def analyze(self, key_paths: Iterable[str] | None = None) -> HistoryReport:
        self.report = compare_snapshots(self.snapshots, key_paths)
        return self.report

    def analyze_key(self, key_path: str) -> KeyHistory:
        history = analyze_key_history(self.snapshots, key_path)
        self.report.key_histories[key_path] = history
        return history

    def recentdocs(self) -> HistoryReport:
        self.report = analyze_recentdocs_history(self.snapshots)
        return self.report

    def analyze_recentdocs(self) -> HistoryReport:
        return self.recentdocs()

    def typed_paths(self) -> HistoryReport:
        self.report = analyze_typed_paths_history(self.snapshots)
        return self.report

    def analyze_typed_paths(self) -> HistoryReport:
        return self.typed_paths()

    def to_dict(self) -> dict[str, Any]:
        return self.report.to_dict()

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self.report.value_timelines[key]
        return self.report[key]


def _coerce_snapshot(value: Any, index: int = 0) -> Snapshot:
    if isinstance(value, Snapshot):
        return value

    if isinstance(value, (RegistryHive, os.PathLike)):
        return Snapshot(observed_at=None, hive=value, source=f"snapshot-{index}")

    if isinstance(value, str):
        return Snapshot(observed_at=None, hive=value)

    if isinstance(value, Mapping):
        has_snapshot_fields = any(
            key in value
            for key in ("observed_at", "captured_at", "acquisition_time", "timestamp", "date", "hive", "path", "keys")
        )
        if has_snapshot_fields:
            observed_at = None
            for key in ("observed_at", "captured_at", "acquisition_time", "timestamp", "date"):
                if key in value and value[key] is not None:
                    observed_at = value[key]
                    break
            hive = value.get("hive", value.get("path"))
            return Snapshot(
                observed_at=observed_at,
                hive=hive,
                source=value.get("source"),
                name=value.get("name"),
                key_paths=value.get("key_paths"),
                keys=value.get("keys"),
                metadata={key: item for key, item in value.items() if key not in ("hive", "path", "keys", "observed_at")},
            )
        return Snapshot(observed_at=None, hive=value, source=f"snapshot-{index}")

    if isinstance(value, (tuple, list)):
        if len(value) == 2:
            first, second = value
            if _looks_like_timestamp(first) and not _looks_like_timestamp(second):
                return Snapshot(observed_at=first, hive=second)
            if _looks_like_timestamp(second) and not _looks_like_timestamp(first):
                return Snapshot(observed_at=second, hive=first)
            return Snapshot(observed_at=first, hive=second)
        if len(value) == 3:
            first, second, third = value
            if _looks_like_timestamp(first) and not _looks_like_timestamp(second):
                return Snapshot(observed_at=first, hive=second, source=third)
            if _looks_like_timestamp(third) and not _looks_like_timestamp(first):
                return Snapshot(observed_at=third, hive=first, source=second)
            return Snapshot(observed_at=first, hive=second, source=third)

    raise TypeError(f"Unsupported snapshot input: {value!r}")


def normalize_snapshots(snapshots: Any) -> list[Snapshot]:
    """Normalize a snapshot collection and order it by observation time."""
    if snapshots is None:
        return []
    if isinstance(snapshots, Mapping):
        snapshot_fields = ("observed_at", "captured_at", "acquisition_time", "timestamp", "date", "hive", "path", "keys")
        nested_fields = ("observed_at", "captured_at", "acquisition_time", "hive", "keys")
        if not any(key in snapshots for key in snapshot_fields):
            if snapshots and all(_looks_like_timestamp(key) for key in snapshots):
                values = []
                for observed_at, payload in snapshots.items():
                    if isinstance(payload, Mapping) and any(key in payload for key in nested_fields):
                        snapshot = _coerce_snapshot(payload)
                        if snapshot.observed_at is None:
                            snapshot.observed_at = _to_datetime(observed_at)
                        values.append(snapshot)
                    elif isinstance(payload, Mapping):
                        values.append({"observed_at": observed_at, "keys": payload})
                    else:
                        values.append({"observed_at": observed_at, "hive": payload})
                result = [
                    value if isinstance(value, Snapshot) else _coerce_snapshot(value, index)
                    for index, value in enumerate(values)
                ]
                indexed = list(enumerate(result))
                indexed.sort(key=lambda item: (item[1].observed_at or dt.datetime.min.replace(tzinfo=UTC), item[0]))
                return [snapshot for _, snapshot in indexed]
            if snapshots and all(
                isinstance(value, Mapping) and any(key in value for key in nested_fields) for value in snapshots.values()
            ):
                values = []
                for label, payload in snapshots.items():
                    snapshot = _coerce_snapshot(payload)
                    if snapshot.name is None:
                        snapshot.name = str(label)
                    if snapshot.source is None:
                        snapshot.source = str(label)
                    values.append(snapshot)
                result = list(values)
                indexed = list(enumerate(result))
                indexed.sort(key=lambda item: (item[1].observed_at or dt.datetime.min.replace(tzinfo=UTC), item[0]))
                return [snapshot for _, snapshot in indexed]
            if snapshots and all(isinstance(value, (RegistryHive, str, os.PathLike)) for value in snapshots.values()):
                values = [
                    Snapshot(observed_at=None, hive=payload, source=str(label), name=str(label))
                    for label, payload in snapshots.items()
                ]
                indexed = list(enumerate(values))
                indexed.sort(key=lambda item: (item[1].observed_at or dt.datetime.min.replace(tzinfo=UTC), item[0]))
                return [snapshot for _, snapshot in indexed]
    if isinstance(snapshots, (Snapshot, RegistryHive, Mapping, str, os.PathLike)):
        values = [snapshots]
    elif isinstance(snapshots, (tuple, list)):
        # A two-tuple can itself be one (observed_at, hive) snapshot.
        if len(snapshots) == 2 and _looks_like_timestamp(snapshots[0]) and not _looks_like_timestamp(snapshots[1]):
            values = [snapshots]
        else:
            values = list(snapshots)
    else:
        values = list(snapshots)

    result = [_coerce_snapshot(value, index) for index, value in enumerate(values)]
    indexed = list(enumerate(result))
    indexed.sort(key=lambda item: (item[1].observed_at or dt.datetime.min.replace(tzinfo=UTC), item[0]))
    return [snapshot for _, snapshot in indexed]


def snapshot_from_hive(
    hive: Any,
    observed_at: Any = None,
    source: str | None = None,
    name: str | None = None,
    key_paths: Sequence[str] | None = None,
) -> Snapshot:
    """Create a Snapshot from a path, RegistryHive, or mapping."""
    return Snapshot(
        observed_at=observed_at,
        hive=hive,
        source=source,
        name=name,
        key_paths=key_paths,
    )


def snapshots_from_hives(hives: Iterable[Any], observed_at: Iterable[Any] | None = None) -> list[Snapshot]:
    """Pair hive paths/objects with optional observation times."""
    hive_list = list(hives)
    if observed_at is None:
        return [snapshot_from_hive(hive) for hive in hive_list]
    times = list(observed_at)
    if len(times) != len(hive_list):
        raise ValueError("observed_at must contain one timestamp per hive")
    return [snapshot_from_hive(hive, observed_at=timestamp) for hive, timestamp in zip(hive_list, times)]


def _lookup_key(keys: Mapping[str, Any], key_path: str) -> Any:
    if key_path in keys:
        return keys[key_path]

    normalized = key_path.replace("/", "\\")
    if not normalized.startswith("\\"):
        normalized = "\\" + normalized
    if normalized in keys:
        return keys[normalized]

    lower = normalized.casefold()
    for candidate, record in keys.items():
        candidate_path = str(candidate).replace("/", "\\")
        if not candidate_path.startswith("\\"):
            candidate_path = "\\" + candidate_path
        if candidate_path.casefold() == lower:
            return record

    return None


def _record_last_write(record: Mapping[str, Any]) -> tuple[Any, dt.datetime | None]:
    raw = None
    for key in ("last_write", "last_modified", "last_write_raw", "key_last_write", "timestamp"):
        if key in record and record[key] is not None:
            raw = record[key]
            break
    if raw is None:
        return None, None
    if isinstance(raw, int) and abs(raw) >= 10**14:
        return raw, _to_datetime(raw)
    return raw, _to_datetime(raw)


def _normalize_values(values: Any) -> list[ValueRecord]:
    result: list[ValueRecord] = []
    if values is None:
        return result

    if isinstance(values, Mapping):
        for name, payload in values.items():
            result.append(_normalize_value_record(name, payload))
        return result

    if isinstance(values, (list, tuple)):
        for index, payload in enumerate(values):
            if isinstance(payload, ValueRecord):
                result.append(payload)
            elif isinstance(payload, Mapping):
                name = payload.get("name", payload.get("value_name", str(index)))
                value = payload.get("value", payload.get("data", payload.get("content")))
                result.append(
                    ValueRecord(
                        name=str(name),
                        value=value,
                        value_type=payload.get("value_type", payload.get("type")),
                        index=payload.get("index"),
                        metadata={
                            key: item
                            for key, item in payload.items()
                            if key not in ("name", "value_name", "value", "data", "content", "value_type", "type", "index")
                        },
                    )
                )
            else:
                result.append(ValueRecord(name=str(index), value=payload))
        return result

    raise TypeError(f"Unsupported registry values: {values!r}")


def _normalize_value_record(name: Any, payload: Any) -> ValueRecord:
    if isinstance(payload, ValueRecord):
        if payload.name == str(name):
            return payload
        return ValueRecord(
            name=str(name),
            value=payload.value,
            value_type=payload.value_type,
            index=payload.index,
            metadata=dict(payload.metadata),
        )

    if isinstance(payload, Mapping):
        value = payload.get("value", payload.get("data", payload.get("content")))
        return ValueRecord(
            name=str(name),
            value=value,
            value_type=payload.get("value_type", payload.get("type")),
            index=payload.get("index"),
            metadata={
                key: item
                for key, item in payload.items()
                if key not in ("name", "value_name", "value", "data", "content", "value_type", "type", "index")
            },
        )

    return ValueRecord(name=str(name), value=payload)


def _observation_from_mapping(snapshot: Snapshot, key_path: str, record: Mapping[str, Any]) -> KeyObservation:
    exists = bool(record.get("exists", True))
    last_write_raw, last_write = _record_last_write(record)
    values_source = record.get("values")
    if values_source is None:
        reserved = {
            "exists",
            "last_write",
            "last_modified",
            "last_write_raw",
            "key_last_write",
            "timestamp",
            "metadata",
        }
        values_source = {key: item for key, item in record.items() if key not in reserved}
    return KeyObservation(
        path=key_path,
        observed_at=snapshot.observed_at,
        exists=exists,
        source=snapshot.source,
        last_write=last_write,
        last_write_raw=last_write_raw,
        values=_normalize_values(values_source) if exists else [],
        key_id=record.get("key_id", record.get("incarnation")),
    )


def _observation_from_hive(snapshot: Snapshot, key_path: str) -> KeyObservation:
    hive = snapshot.hive
    if isinstance(hive, (str, os.PathLike)):
        hive = RegistryHive(os.fspath(hive))

    try:
        key = hive.get_key(key_path)
    except (RegistryKeyNotFoundException, AttributeError) as ex:
        logger.debug("Key %s not found in %s: %s", key_path, snapshot.source, ex)
        return KeyObservation(
            path=key_path,
            observed_at=snapshot.observed_at,
            exists=False,
            source=snapshot.source,
        )

    last_write_raw = key.header.last_modified
    last_write = convert_wintime(last_write_raw, as_json=False)
    values = [
        ValueRecord(name=value.name, value=value.value, value_type=value.value_type)
        for value in key.iter_values(as_json=False, trim_values=False)
    ]
    return KeyObservation(
        path=key_path,
        observed_at=snapshot.observed_at,
        exists=True,
        source=snapshot.source,
        last_write=last_write if isinstance(last_write, dt.datetime) else _to_datetime(last_write),
        last_write_raw=last_write_raw,
        values=values,
    )


def extract_key_observation(snapshot: Snapshot, key_path: str) -> KeyObservation:
    """Read one key from a snapshot without converting values to display JSON."""
    keys = snapshot.keys
    hive = snapshot.hive

    if keys is None and isinstance(hive, Mapping):
        if "keys" in hive and isinstance(hive["keys"], Mapping):
            keys = hive["keys"]
        else:
            keys = hive

    if keys is not None:
        record = _lookup_key(keys, key_path)
        if record is None or record is False:
            return KeyObservation(
                path=key_path,
                observed_at=snapshot.observed_at,
                exists=False,
                source=snapshot.source,
            )
        if isinstance(record, KeyObservation):
            return record
        if isinstance(record, Mapping):
            return _observation_from_mapping(snapshot, key_path, record)
        return KeyObservation(
            path=key_path,
            observed_at=snapshot.observed_at,
            exists=True,
            source=snapshot.source,
            values=_normalize_values(record),
        )

    if hive is None:
        return KeyObservation(
            path=key_path,
            observed_at=snapshot.observed_at,
            exists=False,
            source=snapshot.source,
        )

    return _observation_from_hive(snapshot, key_path)


def _value_map(observation: KeyObservation) -> dict[str, ValueRecord]:
    result: dict[str, ValueRecord] = {}
    for value in observation.values:
        result[value.name.casefold()] = value
    return result


def _value_state(observation: KeyObservation) -> dict[str, tuple[str, str | None]]:
    return {name: (value.fingerprint, value.value_type) for name, value in _value_map(observation).items()}


@dataclass
class _ActiveSegment:
    name: str
    value: Any
    value_type: str | None
    fingerprint: str
    first_index: int
    last_index: int
    observations: list[ValueObservation]
    generation: int
    start_earliest: dt.datetime | None


def _observation_clock(observation: KeyObservation) -> dict[str, Any]:
    return {
        "observed_at": _iso(observation.observed_at),
        "source": observation.source,
        "last_write": _iso(observation.last_write),
        "last_write_raw": observation.last_write_raw,
        "level": "key",
    }


def _build_timeline_from_segment(
    key_path: str,
    segment: _ActiveSegment,
    observations: list[KeyObservation],
    boundary_index: int | None,
    close_reason: str | None,
    parent_only_indices: set[int],
) -> ValueTimeline:
    first_observation = observations[segment.first_index]
    last_observation = observations[segment.last_index]

    if boundary_index is not None:
        valid_to_latest = observations[boundary_index].observed_at
    else:
        valid_to_latest = None

    key_clock = [_observation_clock(observations[index]) for index in range(segment.first_index, segment.last_index + 1)]
    parent_only = any(segment.first_index <= index <= segment.last_index for index in parent_only_indices)

    return ValueTimeline(
        key_path=key_path,
        value_name=segment.name,
        value_type=segment.value_type,
        content=segment.value,
        content_hash=segment.fingerprint,
        generation=segment.generation,
        first_observed=first_observation.observed_at,
        last_observed=last_observation.observed_at,
        valid_from_earliest=segment.start_earliest,
        valid_from_latest=first_observation.observed_at,
        valid_to_earliest=last_observation.observed_at,
        valid_to_latest=valid_to_latest,
        observations=segment.observations,
        key_clock=key_clock,
        parent_key_changed_only=parent_only,
        closed_reason=close_reason,
    )


def analyze_key_history(
    snapshots: Any,
    key_path: str,
    *,
    as_json: bool = True,
) -> KeyHistory:
    """Compare one key path across snapshots and build per-value timelines.

    Snapshot observation times define the bounds.  ``key.header.last_modified``
    is returned only in ``key_clock`` and is never copied into a value's range.
    """
    normalized = normalize_snapshots(snapshots)
    observations = [extract_key_observation(snapshot, key_path) for snapshot in normalized]

    generations: list[Generation] = []
    breakpoints: list[dict[str, Any]] = []
    current_start: int | None = None
    last_present_index: int | None = None
    previous_observation: KeyObservation | None = None
    pending_break_reason: str | None = None
    pending_break_at: dt.datetime | None = None
    pending_break_before: KeyObservation | None = None

    def close_generation(boundary_index: int | None, reason: str | None) -> None:
        nonlocal current_start, last_present_index
        if current_start is None or last_present_index is None:
            current_start = None
            last_present_index = None
            return
        generation_observations = observations[current_start : last_present_index + 1]
        generations.append(
            Generation(
                index=len(generations),
                start_index=current_start,
                last_present_index=last_present_index,
                observations=generation_observations,
                break_reason=pending_break_reason,
                break_at=pending_break_at,
                boundary_index=boundary_index,
                closed_reason=reason,
            )
        )
        current_start = None
        last_present_index = None

    for index, observation in enumerate(observations):
        if not observation.exists:
            if current_start is not None:
                close_generation(index, "key_absent")
            previous_observation = observation
            continue

        if current_start is None:
            if (
                previous_observation is not None
                and previous_observation.exists
                or generations
                and previous_observation is not None
            ):
                pending_break_reason = "key_absent"
                pending_break_at = observation.observed_at
                pending_break_before = previous_observation
            else:
                pending_break_reason = None
                pending_break_at = None
                pending_break_before = None
            current_start = index
            last_present_index = index

            if pending_break_reason is not None:
                old_end = pending_break_at
                if (
                    pending_break_reason == "key_absent"
                    and pending_break_before is not None
                    and not pending_break_before.exists
                ):
                    old_end = pending_break_before.observed_at
                breakpoints.append(
                    {
                        "type": "breakpoint",
                        "key_path": key_path,
                        "at": _iso(pending_break_at),
                        "reason": pending_break_reason,
                        "classification": "key_deleted_and_recreated",
                        "before_generation": len(generations) - 1 if generations else None,
                        "after_generation": len(generations),
                        "before": _snapshot_point(pending_break_before),
                        "after": _snapshot_point(observation),
                        "old_timeline_ends_at": _iso(old_end),
                        "absence_observed_at": _iso(pending_break_before.observed_at)
                        if pending_break_before is not None and not pending_break_before.exists
                        else None,
                        "new_timeline_starts_at": _iso(observation.observed_at),
                    }
                )
        else:
            assert last_present_index is not None
            previous_present = observations[last_present_index]
            identity_changed = (
                previous_present.key_id is not None
                and observation.key_id is not None
                and previous_present.key_id != observation.key_id
            )
            write_regressed = (
                previous_present.last_write is not None
                and observation.last_write is not None
                and observation.last_write < previous_present.last_write
            )
            if identity_changed or write_regressed:
                break_reason = "key_identity_changed" if identity_changed else "last_write_regressed"
                close_generation(index, break_reason)
                breakpoints.append(
                    {
                        "type": "breakpoint",
                        "key_path": key_path,
                        "at": _iso(observation.observed_at),
                        "reason": break_reason,
                        "classification": "key_deleted_and_recreated",
                        "before_generation": len(generations) - 1 if generations else None,
                        "after_generation": len(generations),
                        "before": _snapshot_point(previous_present),
                        "after": _snapshot_point(observation),
                        "old_timeline_ends_at": _iso(observation.observed_at),
                        "new_timeline_starts_at": _iso(observation.observed_at),
                    }
                )
                pending_break_reason = break_reason
                pending_break_at = observation.observed_at
                pending_break_before = previous_present
                current_start = index
                last_present_index = index
            else:
                last_present_index = index

        previous_observation = observation

    close_generation(None, None)

    comparisons: list[dict[str, Any]] = []
    parent_only_indices: set[int] = set()
    for generation in generations:
        start = generation.start_index
        end = generation.last_present_index
        for index in range(start + 1, end + 1):
            before = observations[index - 1]
            after = observations[index]
            if not before.exists or not after.exists:
                continue
            values_before = _value_state(before)
            values_after = _value_state(after)
            key_changed = before.last_write != after.last_write
            values_changed = values_before != values_after

            if key_changed and not values_changed:
                parent_only_indices.add(index)
                comparisons.append(
                    {
                        "type": "parent_key_only",
                        "key_path": key_path,
                        "from": _snapshot_point(before),
                        "to": _snapshot_point(after),
                        "key_last_write_changed": True,
                        "value_content_changed": False,
                        "unchanged_value_names": [value.name for value in before.values],
                        "proves": ["parent_key_last_write_changed_between_observations"],
                        "does_not_prove": [
                            "which_value_changed",
                            "that_any_value_was_written_at_the_new_key_last_write",
                        ],
                    }
                )
            elif values_changed:
                added = sorted(set(values_after) - set(values_before))
                removed = sorted(set(values_before) - set(values_after))
                changed = sorted(
                    name for name in set(values_before) & set(values_after) if values_before[name] != values_after[name]
                )
                comparisons.append(
                    {
                        "type": "value_content_change",
                        "key_path": key_path,
                        "from": _snapshot_point(before),
                        "to": _snapshot_point(after),
                        "key_last_write_changed": key_changed,
                        "value_content_changed": True,
                        "added_values": added,
                        "removed_values": removed,
                        "changed_values": changed,
                        "time_basis": "snapshot_observation_bounds",
                    }
                )

    timelines: list[ValueTimeline] = []
    for generation in generations:
        generation_observations = observations[generation.start_index : generation.last_present_index + 1]
        active: dict[str, _ActiveSegment] = {}
        value_names: dict[str, str] = {}

        for relative_index, observation in enumerate(generation_observations):
            absolute_index = generation.start_index + relative_index
            values = _value_map(observation)
            previous_absolute_index = absolute_index - 1 if absolute_index > 0 else None

            for identity, segment in list(active.items()):
                if identity not in values:
                    boundary = absolute_index
                    timelines.append(
                        _build_timeline_from_segment(
                            key_path,
                            segment,
                            observations,
                            boundary,
                            "value_absent",
                            parent_only_indices,
                        )
                    )
                    del active[identity]

            for identity, value in values.items():
                value_names[identity] = value.name
                segment = active.get(identity)
                if segment is not None and segment.fingerprint == value.fingerprint:
                    segment.last_index = absolute_index
                    segment.observations.append(
                        ValueObservation(
                            observed_at=observation.observed_at,
                            source=observation.source,
                            value=value.value,
                            value_type=value.value_type,
                            key_last_write=observation.last_write,
                        )
                    )
                    continue

                if segment is not None:
                    timelines.append(
                        _build_timeline_from_segment(
                            key_path,
                            segment,
                            observations,
                            absolute_index,
                            "value_content_changed",
                            parent_only_indices,
                        )
                    )

                start_earliest = None
                if previous_absolute_index is not None:
                    start_earliest = observations[previous_absolute_index].observed_at

                active[identity] = _ActiveSegment(
                    name=value.name,
                    value=value.value,
                    value_type=value.value_type,
                    fingerprint=value.fingerprint,
                    first_index=absolute_index,
                    last_index=absolute_index,
                    observations=[
                        ValueObservation(
                            observed_at=observation.observed_at,
                            source=observation.source,
                            value=value.value,
                            value_type=value.value_type,
                            key_last_write=observation.last_write,
                        )
                    ],
                    generation=generation.index,
                    start_earliest=start_earliest,
                )

        for segment in active.values():
            timelines.append(
                _build_timeline_from_segment(
                    key_path,
                    segment,
                    observations,
                    generation.boundary_index,
                    generation.closed_reason if generation.boundary_index is not None else "observation_window_end",
                    parent_only_indices,
                )
            )

    for timeline in timelines:
        timeline.metadata["incarnation"] = timeline.generation
        timeline.metadata["timeline_segment"] = timeline.generation
        timeline.metadata["evidence_id"] = (
            f"{key_path}::{timeline.generation}::{timeline.value_name}::{timeline.content_hash[:12]}"
        )
        before = next((item for item in breakpoints if item.get("after_generation") == timeline.generation), None)
        after = next((item for item in breakpoints if item.get("before_generation") == timeline.generation), None)
        if before is not None:
            timeline.metadata["break_before"] = before
        if after is not None:
            timeline.metadata["break_after"] = after

    return KeyHistory(
        key_path=key_path,
        observations=observations,
        generations=generations,
        value_timelines=timelines,
        comparisons=comparisons,
        breakpoints=breakpoints,
    )


def _snapshot_point(observation: KeyObservation | None) -> dict[str, Any]:
    if observation is None:
        return {}
    return {
        "observed_at": _iso(observation.observed_at),
        "source": observation.source,
        "exists": observation.exists,
        "key_last_write": _iso(observation.last_write),
        "key_last_write_raw": observation.last_write_raw,
        "key_id": observation.key_id,
    }


def compare_key_history(snapshots: Any, key_path: str, **kwargs: Any) -> KeyHistory:
    """Alias for :func:`analyze_key_history`."""
    return analyze_key_history(snapshots, key_path, **kwargs)


def value_timelines(snapshots: Any, key_path: str, **kwargs: Any) -> list[ValueTimeline]:
    """Return only the per-value evidence timelines for ``key_path``."""
    return analyze_key_history(snapshots, key_path, **kwargs).value_timelines


def build_value_timelines(snapshots: Any, key_path: str, **kwargs: Any) -> list[ValueTimeline]:
    """Alias for :func:`value_timelines`."""
    return value_timelines(snapshots, key_path, **kwargs)


def compare_snapshots(
    snapshots: Any,
    key_paths: Iterable[str] | None = None,
    *,
    as_json: bool = True,
) -> HistoryReport:
    """Compare several key paths across snapshots.

    If ``key_paths`` is omitted, the union of paths in snapshot ``key_paths``
    metadata and mapping snapshots is analyzed.
    """
    normalized = normalize_snapshots(snapshots)
    if isinstance(key_paths, str):
        key_paths = [key_paths]
    if key_paths is None:
        paths: list[str] = []
        for snapshot in normalized:
            if snapshot.key_paths:
                paths.extend(snapshot.key_paths)
            if snapshot.keys:
                paths.extend(str(path) for path in snapshot.keys)
        key_paths = sorted(set(paths))

    report = HistoryReport(snapshots=normalized)
    for key_path in key_paths:
        report.key_histories[key_path] = analyze_key_history(normalized, key_path, as_json=as_json)
    return report


def analyze_history(snapshots: Any, key_paths: Iterable[str] | None = None, **kwargs: Any) -> HistoryReport:
    """Alias for :func:`compare_snapshots`."""
    return compare_snapshots(snapshots, key_paths, **kwargs)


def _snapshot_key_paths(snapshot: Snapshot, root_path: str) -> list[str]:
    paths: list[str] = []
    if snapshot.key_paths:
        paths.extend(path for path in snapshot.key_paths if path == root_path or path.startswith(root_path + "\\"))

    keys = snapshot.keys
    hive = snapshot.hive
    if keys is None and isinstance(hive, Mapping):
        keys = hive.get("keys", hive) if "keys" in hive else hive

    if keys:
        for path in keys:
            path = str(path)
            if path == root_path or path.startswith(root_path + "\\"):
                paths.append(path)
        return sorted(set(paths))

    if hive is None:
        return sorted(set(paths))

    if isinstance(hive, (str, os.PathLike)):
        hive = RegistryHive(os.fspath(hive))

    try:
        root = hive.get_key(root_path)
    except RegistryKeyNotFoundException:
        return sorted(set(paths))

    paths.append(root_path)
    for subkey in root.iter_subkeys() or []:
        paths.append(f"{root_path}\\{subkey.name}")
    return sorted(set(paths))


def _recentdocs_value_metadata(value_name: str, content: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if value_name.isdigit():
        metadata["index"] = int(value_name)
        metadata["document"] = _parse_mru_value(content)
        metadata["document_name"] = metadata["document"]
        metadata["kind"] = "document"
    elif value_name.casefold() == "mrulistex":
        metadata["kind"] = "mru_order"
    else:
        metadata["kind"] = "value"
    return metadata


def _parse_mru_value(data: Any) -> str | None:
    if data is None:
        return None
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray)) or isinstance(data, (list, tuple)) and all(isinstance(item, int) for item in data):
        raw = bytes(data)
    else:
        return str(data)

    if not raw:
        return None
    for index in range(0, len(raw) - 1, 2):
        if raw[index] == 0 and raw[index + 1] == 0:
            if index == 0:
                return None
            return raw[:index].decode("utf-16-le", errors="replace")
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")


def analyze_recentdocs_history(
    snapshots: Any,
    root_path: str = RECENT_DOCS_PATH,
    *,
    as_json: bool = True,
) -> HistoryReport:
    """Analyze RecentDocs and its extension subkeys across snapshots."""
    normalized = normalize_snapshots(snapshots)
    key_paths: set[str] = set()
    for snapshot in normalized:
        key_paths.update(_snapshot_key_paths(snapshot, root_path))
    if not key_paths:
        key_paths.add(root_path)

    report = HistoryReport(snapshots=normalized)
    for key_path in sorted(key_paths):
        history = analyze_key_history(normalized, key_path, as_json=as_json)
        extension = None
        if key_path.casefold() != root_path.casefold():
            extension = key_path[len(root_path) + 1 :] if key_path.startswith(root_path + "\\") else None
        for timeline in history.value_timelines:
            timeline.metadata.update(_recentdocs_value_metadata(timeline.value_name, timeline.content))
            timeline.metadata["extension"] = extension
            timeline.metadata["artifact"] = "recentdocs"
        report.key_histories[key_path] = history
    return report


def analyze_typed_paths_history(
    snapshots: Any,
    key_path: str = TYPED_PATHS_KEY_PATH,
    *,
    as_json: bool = True,
) -> HistoryReport:
    """Analyze the TypedPaths key across snapshots."""
    report = compare_snapshots(snapshots, [key_path], as_json=as_json)
    history = report.key_histories[key_path]
    for timeline in history.value_timelines:
        timeline.metadata.update(
            {
                "artifact": "typed_paths",
                "kind": "typed_path",
                "path": timeline.content,
            }
        )
    return report


def recentdocs_history(snapshots: Any, **kwargs: Any) -> HistoryReport:
    """Alias for :func:`analyze_recentdocs_history`."""
    return analyze_recentdocs_history(snapshots, **kwargs)


def typed_paths_history(snapshots: Any, **kwargs: Any) -> HistoryReport:
    """Alias for :func:`analyze_typed_paths_history`."""
    return analyze_typed_paths_history(snapshots, **kwargs)


# Descriptive aliases used by callers that model the feature as snapshot
# comparison, value evidence, or a historical timeline.
SnapshotComparison = HistoryReport
HistoricalSnapshot = Snapshot
HistoricalSnapshots = SnapshotHistory
SnapshotSet = SnapshotHistory
RegistrySnapshot = Snapshot
ValueEvidence = ValueTimeline
EvidenceTimeline = ValueTimeline
ValueEvidenceTimeline = ValueTimeline
KeyValueHistory = KeyHistory
ValueEvidenceRange = EvidenceRange
compare_historical_snapshots = compare_snapshots
snapshot_history = compare_snapshots
historical_snapshot_comparison = compare_snapshots
analyze_snapshots = compare_snapshots
snapshot_diff = compare_snapshots
value_evidence_timelines = value_timelines
evidence_timelines = value_timelines


__all__ = [
    "HistoryReport",
    "HistoryReportDict",
    "KeyHistory",
    "KeyObservation",
    "EvidenceRange",
    "EvidenceTimeline",
    "HistoricalSnapshot",
    "HistoricalSnapshots",
    "SnapshotHistory",
    "SnapshotSet",
    "RegistrySnapshot",
    "Snapshot",
    "SnapshotComparison",
    "ValueEvidence",
    "ValueEvidenceTimeline",
    "KeyValueHistory",
    "ValueEvidenceRange",
    "ValueObservation",
    "ValueRecord",
    "ValueTimeline",
    "analyze_history",
    "analyze_key_history",
    "analyze_snapshots",
    "analyze_recentdocs_history",
    "analyze_typed_paths_history",
    "build_value_timelines",
    "compare_key_history",
    "compare_historical_snapshots",
    "compare_snapshots",
    "evidence_timelines",
    "historical_snapshot_comparison",
    "normalize_snapshots",
    "recentdocs_history",
    "snapshot_history",
    "snapshot_from_hive",
    "snapshots_from_hives",
    "snapshot_diff",
    "typed_paths_history",
    "value_timelines",
    "value_evidence_timelines",
]
