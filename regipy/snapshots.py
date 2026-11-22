"""Historical snapshot comparison for registry artifacts.

Registry *values* do not have their own timestamps.  A key's ``LastWrite``
clock describes the key (NK) record, not the individual values inside it.
That distinction matters as soon as more than one acquisition of the same
hive is available: a key may be rewritten for one value while every other
value is unchanged, and a key may be deleted and later recreated under the
same name with a completely unrelated value history.

This module builds per-value evidence timelines from an ordered set of hive
snapshots.  The rules are deliberately conservative:

* Snapshot observation times come from the caller.  They are never taken from
  a key's ``LastWrite`` clock.
* A value change is bounded by the two snapshots that surround it, expressed
  as an interval such as ``(2022-01-01T00:00:00+00:00, 2022-02-01T00:00:00+00:00]``.
  The engine never claims an exact value modification time.
* Key ``LastWrite`` changes are reported separately as key-clock evidence.
  If only the key clock changes while all tracked values are byte-identical,
  the change is reported as a ``key_only_change``: it proves that the parent
  key changed, and it explicitly does *not* prove a value change.
* If a key is absent in at least one snapshot between two present snapshots,
  the key is treated as having been deleted and recreated.  Values from the
  old instance and the new instance are never stitched together across that
  breakpoint.

The public entry points are :class:`Snapshot`, :func:`compare_snapshots` and
:func:`build_value_timelines`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
from collections import OrderedDict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from regipy.exceptions import NoRegistrySubkeysException, RegistryKeyNotFoundException
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

VALUE_TIMESTAMP_NOTE = (
    "Registry values have no timestamp. This interval is bounded only by the "
    "surrounding snapshot observation times; the key LastWrite clock is kept "
    "separate and is not used as a value timestamp."
)

KEY_CLOCK_NOTE = "Key LastWrite is key-level (NK record) evidence and is not a per-value timestamp."

__all__ = [
    "KEY_CLOCK_NOTE",
    "SCHEMA_VERSION",
    "VALUE_TIMESTAMP_NOTE",
    "Snapshot",
    "build_value_timelines",
    "compare_snapshots",
]


def _normalise_timestamp(value: dt.datetime | str | int | float | None) -> dt.datetime:
    """Return a timezone-aware UTC datetime for a caller supplied timestamp."""
    if value is None:
        raise ValueError("A snapshot timestamp is required (datetime, ISO-8601 string or FILETIME integer)")
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value
    if isinstance(value, bool):
        raise TypeError("A boolean is not a valid snapshot timestamp")
    if isinstance(value, (int, float)):
        # Convenience for callers that already have a raw FILETIME value.
        return _normalise_timestamp(convert_wintime(int(value)))
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    raise TypeError(f"Unsupported snapshot timestamp type: {type(value)!r}")


def _iso(timestamp: dt.datetime | None) -> str | None:
    return timestamp.isoformat() if timestamp is not None else None


@dataclass
class Snapshot:
    """A single hive acquisition.

    ``timestamp`` is the time at which this snapshot is considered to have been
    observed.  For merged images this should be the acquisition time supplied
    by the investigator, not a registry key ``LastWrite`` value.  When omitted
    in :meth:`from_hive`/:meth:`from_path`, the hive header's last modification
    time is used and marked as ``timestamp_source="hive_header"``.
    """

    registry_hive: Any
    timestamp: dt.datetime | str | int | float | None = None
    name: str | None = None
    timestamp_source: str = "provided"
    source_path: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.registry_hive, (str, Path)):
            from regipy.registry import RegistryHive

            source_path = str(self.registry_hive)
            self.registry_hive = RegistryHive(source_path)
            if self.source_path is None:
                self.source_path = source_path
            if self.name is None:
                self.name = Path(source_path).name
        if self.timestamp is None:
            header = getattr(self.registry_hive, "header", None)
            header_timestamp = getattr(header, "last_modification_time", None)
            if header_timestamp is None:
                raise ValueError("A snapshot timestamp is required when the hive has no header timestamp")
            self.timestamp = header_timestamp
            self.timestamp_source = "hive_header"
        self.timestamp = _normalise_timestamp(self.timestamp)  # type: ignore[arg-type]
        if self.name is None:
            self.name = getattr(self.registry_hive, "name", None)

    @classmethod
    def from_hive(
        cls,
        registry_hive: Any,
        timestamp: dt.datetime | str | int | float | None = None,
        name: str | None = None,
        source_path: str | None = None,
    ) -> Snapshot:
        return cls(
            registry_hive=registry_hive,
            timestamp=timestamp,
            name=name,
            timestamp_source="provided" if timestamp is not None else "hive_header",
            source_path=source_path,
        )

    @classmethod
    def from_path(
        cls,
        hive_path: str | Path,
        timestamp: dt.datetime | str | int | float | None = None,
        hive_type: str | None = None,
        partial_hive_path: str | None = None,
        name: str | None = None,
    ) -> Snapshot:
        from regipy.registry import RegistryHive

        resolved_path = str(hive_path)
        registry_hive = RegistryHive(resolved_path, hive_type=hive_type, partial_hive_path=partial_hive_path)
        return cls.from_hive(
            registry_hive,
            timestamp=timestamp,
            name=name or Path(resolved_path).name,
            source_path=resolved_path,
        )


@dataclass
class _ObservedValue:
    name: str
    value_type: str
    content_hash: str
    raw_value: Any
    decoded_value: Any = None
    is_corrupted: bool = False


@dataclass
class _ObservedKey:
    present: bool
    last_write_raw: int | None = None
    last_write: dt.datetime | None = None
    values: dict[str, _ObservedValue] = field(default_factory=dict)
    parse_error: str | None = None


@dataclass
class _Target:
    key_path: str
    plugin: str | None = None
    decode_value: Callable[[str, str, Any], Any] | None = None


def _value_sort_key(name: str) -> tuple[int, int, str]:
    if name.isdigit():
        return (0, int(name), name)
    return (1, 0, name.casefold())


def _value_identity(name: str) -> str:
    # Registry value names are case-insensitive.
    return name.casefold()


def _content_hash(value: Any, value_type: str, is_corrupted: bool) -> str:
    hasher = hashlib.sha256()
    hasher.update((value_type or "").encode("utf-8", errors="replace"))
    hasher.update(b"\x00")
    if is_corrupted:
        hasher.update(b"corrupted\x00")
    if value is None:
        hasher.update(b"null")
    elif isinstance(value, bytes):
        hasher.update(b"bytes\x00")
        hasher.update(value)
    elif isinstance(value, str):
        hasher.update(b"str\x00")
        hasher.update(value.encode("utf-8", errors="replace"))
    elif isinstance(value, bool):
        hasher.update(b"bool\x00")
        hasher.update(b"1" if value else b"0")
    elif isinstance(value, int):
        hasher.update(b"int\x00")
        hasher.update(str(value).encode("ascii"))
    elif isinstance(value, dt.datetime):
        hasher.update(b"datetime\x00")
        hasher.update(value.isoformat().encode("ascii"))
    else:
        hasher.update(b"repr\x00")
        hasher.update(repr(value).encode("utf-8", errors="replace"))
    return hasher.hexdigest()


def _json_safe_content(raw_value: Any, decoded_value: Any) -> Any:
    if decoded_value is not None:
        return decoded_value
    if isinstance(raw_value, bytes):
        return None
    if isinstance(raw_value, dt.datetime):
        return raw_value.isoformat()
    if isinstance(raw_value, (str, int, float, bool)) or raw_value is None:
        return raw_value
    return repr(raw_value)


def _value_size(raw_value: Any) -> int | None:
    if isinstance(raw_value, (bytes, str)):
        return len(raw_value)
    return None


def _interval(
    previous_timestamp: dt.datetime | None,
    current_timestamp: dt.datetime,
    lower_inclusive: bool = False,
) -> dict[str, Any]:
    """Describe the interval in which a change must have happened."""
    current = _iso(current_timestamp)
    if previous_timestamp is None:
        return {
            "not_before": None,
            "not_after": current,
            "lower_inclusive": False,
            "upper_inclusive": True,
            "iso8601": f"(-inf, {current}]",
            "resolution": "already_present_at_first_observation",
        }

    previous = _iso(previous_timestamp)
    lower_bracket = "[" if lower_inclusive else "("
    result: dict[str, Any] = {
        "not_before": previous,
        "not_after": current,
        "lower_inclusive": lower_inclusive,
        "upper_inclusive": True,
        "iso8601": f"{lower_bracket}{previous}, {current}]",
        "resolution": "between_observations",
    }
    if previous_timestamp == current_timestamp:
        result["resolution"] = "indeterminate_zero_width"
    return result


def _snapshot_descriptor(index: int, snapshot: Snapshot) -> dict[str, Any]:
    return {
        "index": index,
        "name": snapshot.name,
        "observed_at": _iso(snapshot.timestamp),  # type: ignore[arg-type]
        "timestamp_source": snapshot.timestamp_source,
        "source_path": snapshot.source_path,
    }


def _looks_like_hive(value: Any) -> bool:
    return hasattr(value, "get_key")


def _coerce_snapshot(value: Any) -> Snapshot:
    if isinstance(value, Snapshot):
        return value
    if isinstance(value, dict):
        hive = value.get("registry_hive") or value.get("hive")
        timestamp = value.get("timestamp", value.get("observed_at"))
        return Snapshot.from_hive(
            hive,
            timestamp=timestamp,
            name=value.get("name"),
            source_path=value.get("source_path") or value.get("path"),
        )
    if isinstance(value, (tuple, list)) and len(value) == 2:
        first, second = value
        if _looks_like_hive(first):
            hive, timestamp = first, second
        elif _looks_like_hive(second):
            timestamp, hive = first, second
        else:
            raise TypeError("Snapshot tuples must contain a hive object and a timestamp")
        return Snapshot.from_hive(hive, timestamp=timestamp)
    raise TypeError(
        "Snapshots must be Snapshot instances, {'hive': ..., 'timestamp': ...} mappings, or (hive, timestamp) pairs"
    )


def _normalise_snapshots(snapshots: Iterable[Any], sort: bool = True) -> list[Snapshot]:
    normalised = [_coerce_snapshot(snapshot) for snapshot in snapshots]
    if not normalised:
        raise ValueError("At least one snapshot is required")
    if sort:
        indexed = list(enumerate(normalised))
        indexed.sort(key=lambda item: (item[1].timestamp, item[0]))  # type: ignore[arg-type,operator]
        normalised = [snapshot for _, snapshot in indexed]
    return normalised


def _capture_key(snapshot: Snapshot, target: _Target) -> _ObservedKey:
    try:
        key = snapshot.registry_hive.get_key(target.key_path)
    except (RegistryKeyNotFoundException, NoRegistrySubkeysException, KeyError):
        return _ObservedKey(present=False)
    except Exception:
        logger.debug("Failed to look up key %s in snapshot %s", target.key_path, snapshot.name, exc_info=True)
        return _ObservedKey(present=False)

    last_write_raw = getattr(getattr(key, "header", None), "last_modified", None)
    last_write = convert_wintime(last_write_raw) if last_write_raw is not None else None
    observed = _ObservedKey(present=True, last_write_raw=last_write_raw, last_write=last_write)

    try:
        # Evidence must hash the complete value, not the MAX_LEN-trimmed
        # representation that iter_values() returns by default.
        values = list(key.iter_values(as_json=False, trim_values=False))
    except TypeError:
        # Lightweight test doubles and third-party hive wrappers may not
        # accept trim_values.
        try:
            values = list(key.iter_values(as_json=False))
        except Exception as ex:  # pragma: no cover - defensive against malformed hives
            observed.parse_error = str(ex)
            logger.debug("Failed to iterate values at %s", target.key_path, exc_info=True)
            return observed
    except Exception as ex:  # pragma: no cover - defensive against malformed hives
        observed.parse_error = str(ex)
        logger.debug("Failed to iterate values at %s", target.key_path, exc_info=True)
        return observed

    for value in values:
        name = str(getattr(value, "name", ""))
        raw_value = getattr(value, "value", None)
        value_type = str(getattr(value, "value_type", "") or "")
        is_corrupted = bool(getattr(value, "is_corrupted", False))
        decoded_value = None
        if target.decode_value is not None:
            try:
                decoded_value = target.decode_value(target.key_path, name, value)
            except Exception:
                logger.debug("Value decoder failed for %s\\%s", target.key_path, name, exc_info=True)
        observed.values[_value_identity(name)] = _ObservedValue(
            name=name,
            value_type=value_type,
            content_hash=_content_hash(raw_value, value_type, is_corrupted),
            raw_value=raw_value,
            decoded_value=decoded_value,
            is_corrupted=is_corrupted,
        )
    return observed


def _split_instances(presence: Sequence[bool]) -> list[tuple[int, int]]:
    """Return inclusive (start, end) runs of present snapshots."""
    runs: list[tuple[int, int]] = []
    index = 0
    while index < len(presence):
        if not presence[index]:
            index += 1
            continue
        start = index
        while index + 1 < len(presence) and presence[index + 1]:
            index += 1
        runs.append((start, index))
        index += 1
    return runs


def _breakpoint(
    snapshots: Sequence[Snapshot],
    previous_instance: int,
    next_instance: int,
    previous_end: int,
    next_start: int,
) -> dict[str, Any]:
    missing = list(range(previous_end + 1, next_start))
    return {
        "kind": "key_deleted_and_recreated",
        "previous_instance": previous_instance,
        "next_instance": next_instance,
        "previous_observed_at": _iso(snapshots[previous_end].timestamp),  # type: ignore[arg-type]
        "next_observed_at": _iso(snapshots[next_start].timestamp),  # type: ignore[arg-type]
        "missing_snapshots": [_snapshot_descriptor(index, snapshots[index]) for index in missing],
        "interval": _interval(snapshots[previous_end].timestamp, snapshots[next_start].timestamp),  # type: ignore[arg-type]
        "proves": ["the_key_name_was_absent_in_at_least_one_snapshot", "the_key_instance_changed"],
        "does_not_prove": [
            "the_exact_deletion_time",
            "the_exact_recreation_time",
            "that_any_value_has_the_same_identity_across_the_breakpoint",
        ],
        "rule": "Values are never merged across this breakpoint.",
    }


def _observed_value_summary(value: _ObservedValue) -> dict[str, Any]:
    return {
        "content_hash": value.content_hash,
        "value_type": value.value_type,
        "content": _json_safe_content(value.raw_value, value.decoded_value),
        "value_hex": value.raw_value.hex() if isinstance(value.raw_value, bytes) else None,
        "value_size": _value_size(value.raw_value),
        "is_corrupted": value.is_corrupted,
    }


def _value_segments_and_transitions(
    snapshots: Sequence[Snapshot],
    observations: Sequence[_ObservedKey],
    instance_start: int,
    instance_end: int,
    value_identity: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    snapshots_span = list(range(instance_start, instance_end + 1))
    segments: list[dict[str, Any]] = []
    transitions: list[dict[str, Any]] = []

    current_segment: dict[str, Any] | None = None
    previous_value: _ObservedValue | None = None
    previous_index: int | None = None

    for index in snapshots_span:
        value = observations[index].values.get(value_identity)
        if value is None:
            if current_segment is not None:
                _close_segment(current_segment, snapshots, index)
                segments.append(current_segment)
                current_segment = None
            if previous_value is not None and previous_index is not None:
                transitions.append(_transition("removed", snapshots, observations, previous_index, index, previous_value, None))
            previous_value = None
            previous_index = index
            continue

        if current_segment is None:
            current_segment = _new_segment(value, snapshots, index, observations)
        elif current_segment["content_hash"] != value.content_hash:
            _close_segment(current_segment, snapshots, index)
            segments.append(current_segment)
            transitions.append(_transition("modified", snapshots, observations, previous_index, index, previous_value, value))
            current_segment = _new_segment(value, snapshots, index, observations)
        else:
            current_segment["last_snapshot"] = _snapshot_descriptor(index, snapshots[index])
            current_segment["last_seen"] = _iso(snapshots[index].timestamp)
            current_segment["observation_count"] += 1
            current_segment["observed_snapshots"].append(_snapshot_descriptor(index, snapshots[index]))

        if previous_value is None and previous_index is not None and previous_index != index:
            transitions.append(_transition("added", snapshots, observations, previous_index, index, None, value))

        previous_value = value
        previous_index = index

    if current_segment is not None:
        # If the key instance ends because the key is absent at the next
        # snapshot, the segment's exit is bounded by that key-absence
        # breakpoint.  Otherwise it remains open at the end of the evidence.
        if instance_end + 1 < len(snapshots) and not observations[instance_end + 1].present:
            current_segment["ended_by"] = "key_absence_breakpoint"
            current_segment["exit_interval"] = _interval(
                snapshots[instance_end].timestamp,  # type: ignore[arg-type]
                snapshots[instance_end + 1].timestamp,  # type: ignore[arg-type]
                lower_inclusive=True,
            )
        else:
            current_segment["ended_by"] = None
            current_segment["exit_interval"] = None
        segments.append(current_segment)

    return segments, transitions


def _new_segment(
    value: _ObservedValue,
    snapshots: Sequence[Snapshot],
    index: int,
    observations: Sequence[_ObservedKey],
) -> dict[str, Any]:
    descriptor = _snapshot_descriptor(index, snapshots[index])
    segment: dict[str, Any] = {
        **_observed_value_summary(value),
        "first_snapshot": descriptor,
        "last_snapshot": descriptor,
        "first_seen": _iso(snapshots[index].timestamp),
        "last_seen": _iso(snapshots[index].timestamp),
        "observation_count": 1,
        "observed_snapshots": [descriptor],
        "evidence": "value_content_observed_identical",
        "entry_interval": None,
        "exit_interval": None,
        "ended_by": None,
    }
    if index > 0:
        segment["entry_interval"] = _interval(snapshots[index - 1].timestamp, snapshots[index].timestamp)  # type: ignore[arg-type]
    else:
        segment["entry_interval"] = _interval(None, snapshots[index].timestamp)  # type: ignore[arg-type]
    return segment


def _close_segment(segment: dict[str, Any], snapshots: Sequence[Snapshot], next_index: int) -> None:
    last_index = segment["last_snapshot"]["index"]
    if next_index > last_index:
        segment["exit_interval"] = _interval(
            snapshots[last_index].timestamp,  # type: ignore[arg-type]
            snapshots[next_index].timestamp,  # type: ignore[arg-type]
            lower_inclusive=True,
        )
        segment["ended_by"] = "value_changed_or_absent"


def _transition(
    kind: str,
    snapshots: Sequence[Snapshot],
    observations: Sequence[_ObservedKey],
    previous_index: int | None,
    current_index: int,
    previous_value: _ObservedValue | None,
    current_value: _ObservedValue | None,
) -> dict[str, Any]:
    previous_timestamp = snapshots[previous_index].timestamp if previous_index is not None else None
    current_timestamp = snapshots[current_index].timestamp
    previous_key = observations[previous_index] if previous_index is not None else None
    current_key = observations[current_index]
    return {
        "kind": kind,
        "from_hash": previous_value.content_hash if previous_value is not None else None,
        "to_hash": current_value.content_hash if current_value is not None else None,
        "from_content": _json_safe_content(previous_value.raw_value, previous_value.decoded_value)
        if previous_value is not None
        else None,
        "to_content": _json_safe_content(current_value.raw_value, current_value.decoded_value)
        if current_value is not None
        else None,
        "previous_snapshot_index": previous_index,
        "snapshot_index": current_index,
        "interval": _interval(previous_timestamp, current_timestamp),
        "evidence": "value_content_or_presence_changed_between_observations",
        "timestamp_note": VALUE_TIMESTAMP_NOTE,
        "key_clock_context": {
            "previous_last_write": _iso(previous_key.last_write) if previous_key is not None else None,
            "current_last_write": _iso(current_key.last_write),
            "used_as_value_timestamp": False,
        },
    }


def _key_clock_entries(
    snapshots: Sequence[Snapshot],
    observations: Sequence[_ObservedKey],
    instance_index: int,
    instance_start: int,
    instance_end: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    clock: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    previous: _ObservedKey | None = None
    previous_index: int | None = None
    for index in range(instance_start, instance_end + 1):
        observation = observations[index]
        if not observation.present:  # pragma: no cover - instances are present by construction
            continue
        clock.append(
            {
                "key_instance": instance_index,
                "snapshot_index": index,
                "snapshot": snapshots[index].name,
                "observed_at": _iso(snapshots[index].timestamp),
                "last_write": _iso(observation.last_write),
                "last_write_raw": observation.last_write_raw,
                "evidence": "key_nk_last_write",
                "note": KEY_CLOCK_NOTE,
            }
        )
        if previous is not None and previous.last_write_raw != observation.last_write_raw:
            changes.append(
                {
                    "key_instance": instance_index,
                    "snapshot_index": index,
                    "from_last_write": _iso(previous.last_write),
                    "to_last_write": _iso(observation.last_write),
                    "interval": _interval(snapshots[previous_index].timestamp, snapshots[index].timestamp),  # type: ignore[arg-type,index]
                    "evidence": "key_last_write_changed",
                    "note": KEY_CLOCK_NOTE,
                }
            )
        previous = observation
        previous_index = index
    return clock, changes


def _value_diff(
    previous: _ObservedKey,
    current: _ObservedKey,
) -> list[dict[str, Any]]:
    diff: list[dict[str, Any]] = []
    previous_keys = set(previous.values)
    current_keys = set(current.values)
    for identity in sorted(previous_keys - current_keys):
        value = previous.values[identity]
        diff.append({"kind": "removed", "value_name": value.name, "from_hash": value.content_hash, "to_hash": None})
    for identity in sorted(current_keys - previous_keys):
        value = current.values[identity]
        diff.append({"kind": "added", "value_name": value.name, "from_hash": None, "to_hash": value.content_hash})
    for identity in sorted(previous_keys & current_keys):
        before = previous.values[identity]
        after = current.values[identity]
        if before.content_hash != after.content_hash:
            diff.append(
                {
                    "kind": "modified",
                    "value_name": after.name,
                    "from_hash": before.content_hash,
                    "to_hash": after.content_hash,
                }
            )
    return diff


def _key_only_changes(
    snapshots: Sequence[Snapshot],
    observations: Sequence[_ObservedKey],
    instance_index: int,
    instance_start: int,
    instance_end: int,
    key_path: str,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index in range(instance_start + 1, instance_end + 1):
        previous = observations[index - 1]
        current = observations[index]
        if not previous.present or not current.present:  # pragma: no cover - instances are present by construction
            continue
        if previous.parse_error or current.parse_error:  # pragma: no cover - malformed hive defensive path
            continue
        value_changes = _value_diff(previous, current)
        if value_changes or previous.last_write_raw == current.last_write_raw:
            continue
        result.append(
            {
                "key_path": key_path,
                "key_instance": instance_index,
                "snapshot_index": index,
                "interval": _interval(snapshots[index - 1].timestamp, snapshots[index].timestamp),  # type: ignore[arg-type]
                "key_last_write": {
                    "before": _iso(previous.last_write),
                    "after": _iso(current.last_write),
                    "before_raw": previous.last_write_raw,
                    "after_raw": current.last_write_raw,
                },
                "value_changes": [],
                "proves": ["the_parent_key_last_write_changed"],
                "does_not_prove": ["that_any_tracked_value_changed", "an_exact_value_modification_time"],
                "control": True,
                "note": (
                    "All tracked values are byte-identical across this interval; only the key clock moved. "
                    "This entry must not be attached to a child value timeline."
                ),
            }
        )
    return result


def _build_target_timeline(
    snapshots: Sequence[Snapshot],
    target: _Target,
) -> dict[str, Any]:
    observations = [_capture_key(snapshot, target) for snapshot in snapshots]
    presence = [observation.present for observation in observations]
    instances = _split_instances(presence)

    breakpoints: list[dict[str, Any]] = []
    for instance_index in range(1, len(instances)):
        previous_start, previous_end = instances[instance_index - 1]
        next_start, next_end = instances[instance_index]
        breakpoints.append(
            _breakpoint(
                snapshots,
                previous_instance=instance_index - 1,
                next_instance=instance_index,
                previous_end=previous_end,
                next_start=next_start,
            )
        )

    key_evidence: dict[str, Any] = {
        "key_path": target.key_path,
        "key_identity": target.key_path.casefold(),
        "plugin": target.plugin,
        "snapshot_count": len(snapshots),
        "instances": [],
        "key_clock": [],
        "key_clock_changes": [],
        "key_only_changes": [],
        "breakpoints": [dict(breakpoint, key_path=target.key_path) for breakpoint in breakpoints],
    }
    value_timelines: list[dict[str, Any]] = []

    for instance_index, (instance_start, instance_end) in enumerate(instances):
        first_snapshot = _snapshot_descriptor(instance_start, snapshots[instance_start])
        last_snapshot = _snapshot_descriptor(instance_end, snapshots[instance_end])
        instance_break_before = breakpoints[instance_index - 1] if instance_index > 0 else None
        instance_break_after = breakpoints[instance_index] if instance_index < len(breakpoints) else None
        key_evidence["instances"].append(
            {
                "index": instance_index,
                "first_snapshot": first_snapshot,
                "last_snapshot": last_snapshot,
                "first_seen": first_snapshot["observed_at"],
                "last_seen": last_snapshot["observed_at"],
                "observed_snapshot_count": instance_end - instance_start + 1,
                "break_before": instance_break_before,
                "break_after": instance_break_after,
            }
        )

        clock, clock_changes = _key_clock_entries(snapshots, observations, instance_index, instance_start, instance_end)
        key_evidence["key_clock"].extend(clock)
        key_evidence["key_clock_changes"].extend(clock_changes)
        key_evidence["key_only_changes"].extend(
            _key_only_changes(
                snapshots,
                observations,
                instance_index,
                instance_start,
                instance_end,
                target.key_path,
            )
        )

        value_identities: OrderedDict[str, str] = OrderedDict()
        for index in range(instance_start, instance_end + 1):
            for identity, value in observations[index].values.items():
                value_identities.setdefault(identity, value.name)

        for identity, display_name in sorted(value_identities.items(), key=lambda item: _value_sort_key(item[1])):
            segments, transitions = _value_segments_and_transitions(
                snapshots, observations, instance_start, instance_end, identity
            )
            if not segments:  # pragma: no cover - identity came from an observation
                continue
            first_seen = segments[0]["first_seen"]
            last_seen = segments[-1]["last_seen"]
            instance_clock = [entry for entry in clock if entry["key_instance"] == instance_index]
            value_timeline: dict[str, Any] = {
                "key_path": target.key_path,
                "key_instance": instance_index,
                "plugin": target.plugin,
                "value_name": display_name,
                "value_identity": identity,
                "segments": segments,
                "transitions": transitions,
                "range": {
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "iso8601": f"[{first_seen}, {last_seen}]",
                    "first_snapshot": segments[0]["first_snapshot"],
                    "last_snapshot": segments[-1]["last_snapshot"],
                    "observed_snapshot_count": sum(segment["observation_count"] for segment in segments),
                    "content_change_count": len(transitions),
                    "unchanged": len(transitions) == 0,
                },
                "key_clock": {
                    "first_last_write": instance_clock[0]["last_write"] if instance_clock else None,
                    "last_last_write": instance_clock[-1]["last_write"] if instance_clock else None,
                    "changed": any(
                        instance_clock[index - 1]["last_write_raw"] != instance_clock[index]["last_write_raw"]
                        for index in range(1, len(instance_clock))
                    ),
                    "evidence": "key_nk_last_write",
                    "used_as_value_timestamp": False,
                    "note": KEY_CLOCK_NOTE,
                },
                "breaks": [],
                "timestamp_note": VALUE_TIMESTAMP_NOTE,
                "provenance": {
                    "value_content": "registry_value_bytes_observed_in_snapshots",
                    "key_clock": "nk_last_write_reported_separately",
                },
            }
            if instance_break_before is not None:
                value_timeline["breaks"].append(
                    {
                        "kind": "after_key_recreation",
                        "breakpoint": instance_break_before,
                        "rule": "This value timeline starts in a new key instance; prior-instance values are not merged.",
                    }
                )
            if instance_break_after is not None:
                value_timeline["breaks"].append(
                    {
                        "kind": "before_key_recreation",
                        "breakpoint": instance_break_after,
                        "rule": "This value timeline ends with the old key instance; later-instance values are not merged.",
                    }
                )
            value_timelines.append(value_timeline)

    return {"key_evidence": key_evidence, "value_timelines": value_timelines}


def _collect_targets(
    snapshots: Sequence[Snapshot],
    plugins: Sequence[Any] | None,
    key_paths: Sequence[str] | None,
    decode_value: Callable[[str, str, Any], Any] | None,
) -> tuple[list[_Target], list[str]]:
    targets: OrderedDict[str, _Target] = OrderedDict()
    plugin_names: list[str] = []

    for plugin_spec in plugins or []:
        if isinstance(plugin_spec, type):
            plugin_name = getattr(plugin_spec, "NAME", None)
            instances = [plugin_spec(snapshot.registry_hive, as_json=False) for snapshot in snapshots]
        else:
            plugin_name = getattr(plugin_spec, "NAME", None)
            instances = [plugin_spec]

        if plugin_name and plugin_name not in plugin_names:
            plugin_names.append(plugin_name)

        for instance in instances:
            get_paths = getattr(instance, "snapshot_key_paths", None)
            if get_paths is None:
                continue
            paths = get_paths()
            decoder = getattr(instance, "decode_snapshot_value", None)
            for path in paths:
                identity = path.casefold()
                if identity not in targets:
                    targets[identity] = _Target(
                        key_path=path,
                        plugin=plugin_name,
                        decode_value=decoder,
                    )

    for path in key_paths or []:
        identity = path.casefold()
        if identity not in targets:
            targets[identity] = _Target(key_path=path, plugin=None, decode_value=decode_value)

    return list(targets.values()), plugin_names


def _ensure_trailing_path(path: str) -> str:
    return path[:-1] if len(path) > 1 and path.endswith("\\") else path


def compare_snapshots(
    snapshots: Iterable[Any],
    plugins: Sequence[Any] | None = None,
    key_paths: Sequence[str] | None = None,
    as_json: bool = True,
    sort: bool = True,
    decode_value: Callable[[str, str, Any], Any] | None = None,
) -> dict[str, Any]:
    """Compare ordered hive snapshots and build per-value evidence timelines.

    :param snapshots: ``Snapshot`` objects, ``(hive, timestamp)`` pairs, or
                      ``{"hive": ..., "timestamp": ...}`` mappings.
    :param plugins: Plugin classes (or instances) that expose
                    ``snapshot_key_paths()`` and optionally
                    ``decode_snapshot_value(key_path, value_name, value)``.
                    When both ``plugins`` and ``key_paths`` are omitted, the
                    built-in ``recentdocs`` and ``typed_paths`` plugins are
                    used.
    :param key_paths: Additional registry key paths to compare.  Useful for
                      ad-hoc evidence without a plugin.
    :param as_json: Accepted for API symmetry.  The returned structure is
                    always JSON-serializable.
    :param sort: Sort snapshots by their observation timestamp.  Pass
                 ``False`` to keep the caller-provided order.
    :param decode_value: Optional decoder for ad-hoc ``key_paths``.
    :return: A JSON-serializable dictionary with ``snapshots``,
             ``key_evidence``, ``value_timelines``, ``breakpoints`` and
             ``key_only_changes``.
    """
    del as_json  # output is always JSON-safe

    if plugins is None and key_paths is None:
        from regipy.plugins.ntuser.recentdocs import RecentDocsPlugin
        from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin

        plugins = [RecentDocsPlugin, TypedPathsPlugin]

    normalised_snapshots = _normalise_snapshots(snapshots, sort=sort)
    targets, plugin_names = _collect_targets(normalised_snapshots, plugins, key_paths, decode_value)

    key_evidence: list[dict[str, Any]] = []
    value_timelines: list[dict[str, Any]] = []
    breakpoints: list[dict[str, Any]] = []
    key_only_changes: list[dict[str, Any]] = []

    for target in targets:
        target.key_path = _ensure_trailing_path(target.key_path)
        built = _build_target_timeline(normalised_snapshots, target)
        key_evidence.append(built["key_evidence"])
        value_timelines.extend(built["value_timelines"])
        breakpoints.extend(built["key_evidence"]["breakpoints"])
        key_only_changes.extend(built["key_evidence"]["key_only_changes"])

    return {
        "schema_version": SCHEMA_VERSION,
        "snapshots": [_snapshot_descriptor(index, snapshot) for index, snapshot in enumerate(normalised_snapshots)],
        "plugins": plugin_names,
        "key_evidence": key_evidence,
        "value_timelines": value_timelines,
        "breakpoints": breakpoints,
        "key_only_changes": key_only_changes,
    }


def build_value_timelines(
    snapshots: Iterable[Any],
    key_paths: Sequence[str],
    as_json: bool = True,
    sort: bool = True,
    decode_value: Callable[[str, str, Any], Any] | None = None,
) -> dict[str, Any]:
    """Build per-value timelines for arbitrary key paths (no plugin required)."""
    return compare_snapshots(
        snapshots,
        plugins=[],
        key_paths=key_paths,
        as_json=as_json,
        sort=sort,
        decode_value=decode_value,
    )
