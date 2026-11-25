"""Offline lineage reconstruction from DistributedLinkTracker identities.

The TrackerDataBlock (``DistributedLinkTracker``) stores two identity pairs:

* ``DroidVolumeId`` / ``DroidFileId`` - the current identity of the target.
* ``DroidBirthVolumeId`` / ``DroidBirthFileId`` - the identity the target had
  when the shortcut was created.

A shortcut saved before and after a move or copy therefore describes an edge:
the *current* identity in the older observation can become the *birth*
identity in a newer observation.  This module only uses local data.  It never
performs online lookups and it never fills in missing identifiers.

The caller supplies collection order and hardware generations because those
facts are not present in a LNK file.  They are used as ordering constraints,
not as independent proof of a relationship.  Likewise, LNK header timestamps
can only reject a candidate edge whose target predates its source; timestamps
alone never create an edge.

When several observations are equally supported as predecessors of the same
node, every edge is retained and the group is reported through ``ties``.
Identifier sharing is reported separately because two snapshots can share an
identity without one being the ancestor of the other.
"""

import argparse
import base64
import json
import re
from collections.abc import Iterable
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
from datetime import date
from datetime import datetime
from datetime import timezone
from itertools import pairwise
from pathlib import Path
from typing import Any
from typing import Optional

from LnkParse3.lnk_file import LnkFile
from LnkParse3.utils import parse_uuid


SCHEMA_VERSION = "1.0"

RELATION_MIGRATION = "migration"
RELATION_COPY = "copy"
RELATION_CONTINUATION = "continuation"
RELATION_SNAPSHOT_REUSE = "snapshot_reuse"

STATUS_ORIGINAL = "original"
STATUS_DERIVED = "derived"
STATUS_UNKNOWN_ORIGIN = "unknown_origin"

ZERO_GUID = "00000000-0000-0000-0000-000000000000"

_GUID_RE = re.compile(r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$")

_CURRENT_VOLUME_KEYS = (
    "droid_volume_identifier",
    "droid_volume_id",
    "current_droid_volume_identifier",
    "current_volume_identifier",
    "current_volume_id",
    "volume_identifier",
    "volume_id",
)
_CURRENT_FILE_KEYS = (
    "droid_file_identifier",
    "droid_file_id",
    "current_droid_file_identifier",
    "current_file_identifier",
    "current_file_id",
    "file_identifier",
    "file_id",
)
_BIRTH_VOLUME_KEYS = (
    "birth_droid_volume_identifier",
    "birth_droid_volume_id",
    "droid_birth_volume_identifier",
    "droid_birth_volume_id",
    "original_droid_volume_identifier",
    "original_volume_identifier",
    "original_volume_id",
    "birth_volume_identifier",
    "birth_volume_id",
)
_BIRTH_FILE_KEYS = (
    "birth_droid_file_identifier",
    "birth_droid_file_id",
    "droid_birth_file_identifier",
    "droid_birth_file_id",
    "original_droid_file_identifier",
    "original_file_identifier",
    "original_file_id",
    "birth_file_identifier",
    "birth_file_id",
)
_MACHINE_KEYS = (
    "machine_identifier",
    "machine_id",
    "machine_name",
    "machine",
    "netbios_name",
)

_TRACKER_KEYS = (
    "distributed_link_tracker_block",
    "distributed_link_tracker",
    "distributedlinktracker",
    "distributed_tracker",
    "dlt",
    "tracker_data",
    "tracker",
)

_ORDER_KEYS = (
    "collection_order",
    "collection_index",
    "collection_sequence",
    "collect_order",
    "sequence",
    "seq",
    "order",
)
_GENERATION_KEYS = (
    "hardware_generation",
    "hardware_gen",
    "machine_generation",
    "device_generation",
    "generation",
    "gen",
)
_BATCH_KEYS = (
    "collection_batch",
    "collection_batch_id",
    "backup",
    "backup_id",
    "batch",
    "batch_id",
)
_SOURCE_KEYS = (
    "source",
    "source_path",
    "path",
    "filename",
    "file_name",
)
_SAMPLE_ID_KEYS = (
    "sample_id",
    "sample",
    "sample_name",
    "id",
    "name",
)
_DATA_KEYS = (
    "data",
    "indata",
    "raw",
    "content",
    "lnk_data",
    "lnk",
    "file",
    "fhandle",
)


def _lower_keys(mapping: Mapping) -> dict[str, Any]:
    return {str(key).lower(): value for key, value in mapping.items()}


def _first(mapping: Mapping | None, keys: Iterable[str]) -> Any:
    if not isinstance(mapping, Mapping):
        return None
    for key in keys:
        if key in mapping:
            return mapping[key]
    lowered = _lower_keys(mapping)
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return None


def normalize_guid(value: Any) -> str | None:
    """Return an upper-case GUID string, or ``None`` for absent/zero values."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value)
        if len(value) != 16:
            return None
        value = parse_uuid(value)
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "n/a"}:
        return None
    text = text.strip("{}").upper()
    compact = text.replace("-", "")
    if len(compact) == 32 and re.fullmatch(r"[0-9A-F]{32}", compact):
        text = (
            compact[0:8]
            + "-"
            + compact[8:12]
            + "-"
            + compact[12:16]
            + "-"
            + compact[16:20]
            + "-"
            + compact[20:32]
        )
    if not _GUID_RE.fullmatch(text) or text == ZERO_GUID:
        return None
    return text


def _identity_from_value(value: Any) -> Optional["DroidIdentity"]:
    if value is None:
        return None
    if isinstance(value, DroidIdentity):
        return value
    if isinstance(value, Mapping):
        volume = _first(value, _CURRENT_VOLUME_KEYS + _BIRTH_VOLUME_KEYS)
        file_id = _first(value, _CURRENT_FILE_KEYS + _BIRTH_FILE_KEYS)
        if volume is None and file_id is None:
            volume = _first(value, ("volume",))
            file_id = _first(value, ("file", "object_id"))
        key_text = _first(value, ("key", "identity_key"))
        if volume is None and file_id is None and isinstance(key_text, str):
            return _identity_from_value(key_text)
        if volume is None and file_id is None:
            return None
        return DroidIdentity(volume, file_id)
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return DroidIdentity(value[0], value[1])
    if isinstance(value, str):
        # Accept the compact "VOLUME|FILE" notation emitted by this module.
        for separator in ("|", ":"):
            if separator in value:
                volume, file_id = value.split(separator, 1)
                return DroidIdentity(volume, file_id)
    return None


@dataclass(frozen=True)
class DroidIdentity:
    """A DistributedLinkTracker volume/file identity pair."""

    volume_id: str | None = None
    file_id: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "volume_id", normalize_guid(self.volume_id))
        object.__setattr__(self, "file_id", normalize_guid(self.file_id))

    @classmethod
    def from_mapping(cls, value: Mapping | None) -> "DroidIdentity":
        if not isinstance(value, Mapping):
            return cls()
        volume = _first(value, _CURRENT_VOLUME_KEYS + _BIRTH_VOLUME_KEYS)
        file_id = _first(value, _CURRENT_FILE_KEYS + _BIRTH_FILE_KEYS)
        if volume is None and file_id is None:
            key_text = _first(value, ("key", "identity_key"))
            if isinstance(key_text, str):
                parsed = _identity_from_value(key_text)
                if parsed is not None:
                    return parsed
        return cls(volume, file_id)

    @property
    def key(self) -> tuple[str, str] | None:
        if self.volume_id is None or self.file_id is None:
            return None
        return (self.volume_id, self.file_id)

    @property
    def is_complete(self) -> bool:
        return self.key is not None

    @property
    def volume_identifier(self) -> str | None:
        return self.volume_id

    @property
    def file_identifier(self) -> str | None:
        return self.file_id

    def as_dict(self) -> dict[str, Any]:
        return {
            "volume_id": self.volume_id,
            "file_id": self.file_id,
            "volume_identifier": self.volume_id,
            "file_identifier": self.file_id,
            "droid_volume_identifier": self.volume_id,
            "droid_file_identifier": self.file_id,
            "key": self.key_text,
            "complete": self.is_complete,
        }

    @property
    def key_text(self) -> str | None:
        if self.key is None:
            return None
        return f"{self.key[0]}|{self.key[1]}"

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_dict().get(key, default)


TrackerIdentity = DroidIdentity


def _optional_identity(value: DroidIdentity | None) -> DroidIdentity | None:
    if value is None or not value.is_complete:
        return None
    return value


@dataclass
class TrackerInfo:
    """Normalized TrackerDataBlock contents extracted from one source."""

    current: DroidIdentity = field(default_factory=DroidIdentity)
    birth: DroidIdentity | None = None
    machine_identifier: str | None = None
    header_times: dict[str, datetime | None] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    source_kind: str = "unknown"
    warnings: list[str] = field(default_factory=list)

    @property
    def original(self) -> DroidIdentity | None:
        return self.birth

    @property
    def original_identity(self) -> DroidIdentity | None:
        return self.birth

    @property
    def birth_identity(self) -> DroidIdentity | None:
        return self.birth

    @property
    def current_identity(self) -> DroidIdentity:
        return self.current

    @property
    def current_key(self) -> tuple[str, str] | None:
        return self.current.key

    @property
    def birth_key(self) -> tuple[str, str] | None:
        return self.birth.key if self.birth else None

    @property
    def is_original(self) -> bool:
        return bool(self.birth and self.current.key == self.birth.key)

    @property
    def identity_changed(self) -> bool:
        return bool(self.birth and self.current.key and self.current.key != self.birth.key)

    @property
    def status(self) -> str:
        if not self.birth or not self.current.is_complete:
            return STATUS_UNKNOWN_ORIGIN
        if self.current.key == self.birth.key:
            return STATUS_ORIGINAL
        return STATUS_DERIVED

    def as_dict(self) -> dict[str, Any]:
        return {
            "machine_identifier": self.machine_identifier,
            "current": self.current.as_dict(),
            "birth": self.birth.as_dict() if self.birth else None,
            "original": self.birth.as_dict() if self.birth else None,
            "current_key": self.current.key_text,
            "birth_key": self.birth.key_text if self.birth else None,
            "status": self.status,
            "is_original": self.is_original,
            "identity_changed": self.identity_changed,
            "header": _times_to_dict(self.header_times),
            "source": self.source,
            "source_kind": self.source_kind,
            "tracker": _json_safe(self.raw),
            "droid_volume_identifier": self.current.volume_id,
            "droid_file_identifier": self.current.file_id,
            "birth_droid_volume_identifier": (self.birth.volume_id if self.birth else None),
            "birth_droid_file_identifier": self.birth.file_id if self.birth else None,
            "warnings": list(self.warnings),
        }

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_dict().get(key, default)


def _times_to_dict(times: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _json_safe(value) for key, value in times.items()}


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.replace(microsecond=0).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return value


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        # Values above this threshold are FILETIME (100 ns intervals since 1601-01-01).
        seconds = (number - 116444736000000000) / 10000000 if number > 10**14 else number
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _header_times_from_mapping(mapping: Mapping) -> dict[str, datetime | None]:
    header = _first(mapping, ("header", "shell_link_header", "lnk_header"))
    if not isinstance(header, Mapping):
        header = {}
    combined = dict(mapping)
    combined.update(header)
    for key, value in mapping.items():
        if str(key).lower().startswith("header_"):
            combined.setdefault(str(key)[7:], value)

    def pick(*keys: str) -> Any:
        return _first(combined, keys)

    return {
        "creation_time": _parse_datetime(
            pick("creation_time", "created_time", "creation", "created")
        ),
        "access_time": _parse_datetime(
            pick("access_time", "accessed_time", "access", "last_access_time")
        ),
        "modified_time": _parse_datetime(
            pick(
                "modified_time",
                "write_time",
                "last_write_time",
                "modification_time",
                "modified",
            )
        ),
    }


def _header_times_from_lnk(lnk: LnkFile) -> dict[str, datetime | None]:
    header = getattr(lnk, "header", None)
    if header is None:
        return {}
    try:
        creation = header.creation_time()
    except (ValueError, Warning):
        creation = None
    try:
        access = header.access_time()
    except (ValueError, Warning):
        access = None
    try:
        modified = header.write_time()
    except (ValueError, Warning):
        modified = None
    return {
        "creation_time": creation,
        "access_time": access,
        "modified_time": modified,
    }


def _has_tracker_fields(mapping: Mapping) -> bool:
    lowered = _lower_keys(mapping)
    if _first(lowered, _CURRENT_VOLUME_KEYS) is not None:
        return True
    if _first(lowered, _BIRTH_VOLUME_KEYS) is not None:
        return True
    for key in ("current", "current_identity", "birth", "birth_identity", "original"):
        if key in lowered and isinstance(lowered[key], Mapping):
            return True
    return False


def _find_tracker_mapping(mapping: Mapping) -> tuple[Mapping | None, str | None]:
    lowered = _lower_keys(mapping)
    for key in _TRACKER_KEYS:
        value = lowered.get(key)
        if isinstance(value, Mapping):
            if _has_tracker_fields(value) or _find_tracker_mapping(value)[0] is not None:
                return value, key
            return value, key
    extra = lowered.get("extra")
    if isinstance(extra, Mapping):
        extra_lowered = _lower_keys(extra)
        for key in _TRACKER_KEYS:
            value = extra_lowered.get(key)
            if isinstance(value, Mapping):
                return value, f"extra.{key}"
        for key, value in extra.items():
            if isinstance(value, Mapping) and _has_tracker_fields(value):
                return value, f"extra.{key}"
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, Mapping) and _has_tracker_fields(item):
                        return item, f"extra.{key}"
    elif isinstance(extra, list):
        for item in extra:
            if isinstance(item, Mapping) and _has_tracker_fields(item):
                return item, "extra"
    if _has_tracker_fields(lowered):
        return mapping, "sample"
    return None, None


def _identity_from_flat(
    mapping: Mapping,
    volume_keys: Iterable[str],
    file_keys: Iterable[str],
) -> DroidIdentity | None:
    volume = _first(mapping, volume_keys)
    file_id = _first(mapping, file_keys)
    if volume is None and file_id is None:
        return None
    return DroidIdentity(volume, file_id)


def _identities_from_tracker(
    tracker: Mapping,
) -> tuple[DroidIdentity, DroidIdentity | None]:
    lowered = _lower_keys(tracker)

    current_value = _first(
        lowered,
        ("current", "current_identity", "droid", "current_droid", "now"),
    )
    current = _identity_from_value(current_value)
    if current is None:
        current = _identity_from_flat(lowered, _CURRENT_VOLUME_KEYS, _CURRENT_FILE_KEYS)

    birth_value = _first(
        lowered,
        (
            "birth",
            "birth_identity",
            "droid_birth",
            "original",
            "original_identity",
            "birth_droid",
        ),
    )
    birth = _identity_from_value(birth_value)
    if birth is None:
        birth = _identity_from_flat(lowered, _BIRTH_VOLUME_KEYS, _BIRTH_FILE_KEYS)

    return _optional_identity(current) or DroidIdentity(), _optional_identity(birth)


def _decode_local_sample(data: bytes) -> bytes:
    """Decode the base64 text used by this repository's local samples."""
    if data.startswith(b"L\x00\x00\x00"):
        return data
    compact = b"".join(data.split())
    if len(compact) < 8 or len(compact) % 4:
        return data
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, TypeError):
        return data
    if decoded.startswith(b"L\x00\x00\x00"):
        return decoded
    return data


def _read_lnk(source: Any) -> LnkFile | None:
    if isinstance(source, LnkFile):
        return source
    if isinstance(source, (bytes, bytearray, memoryview)):
        return LnkFile(indata=_decode_local_sample(bytes(source)))
    if isinstance(source, Path):
        if source.exists() and source.is_file():
            return LnkFile(indata=_decode_local_sample(source.read_bytes()))
        return None
    if isinstance(source, str):
        path = Path(source)
        if path.exists() and path.is_file():
            return LnkFile(indata=_decode_local_sample(path.read_bytes()))
        return None
    if hasattr(source, "read"):
        return LnkFile(indata=_decode_local_sample(source.read()))
    return None


def _tracker_from_lnk(lnk: LnkFile) -> tuple[Mapping | None, str | None]:
    extras = getattr(lnk, "extras", None)
    if extras is None:
        return None, None
    try:
        iterator = iter(extras)
    except TypeError:
        iterator = iter(())
    for extra in iterator:
        try:
            name = extra.name()
        except (AttributeError, ValueError):
            continue
        if name == "DISTRIBUTED_LINK_TRACKER_BLOCK":
            try:
                return extra.as_dict(), "lnk.extra"
            except (KeyError, ValueError, TypeError):
                return None, "lnk.extra"
    return None, None


def parse_tracker_identity(source: Any) -> TrackerInfo:
    """Extract and normalize the current/original tracker identities.

    ``source`` may be a :class:`LnkParse3.lnk_file.LnkFile`, raw LNK bytes, a
    local path, a parsed ``get_json()`` mapping, or a mapping that already
    contains tracker fields.
    """
    if isinstance(source, TrackerInfo):
        return source

    lnk = _read_lnk(source)
    if lnk is not None:
        tracker, source_kind = _tracker_from_lnk(lnk)
        tracker = tracker or {}
        current, birth = _identities_from_tracker(tracker)
        return TrackerInfo(
            current=current,
            birth=birth,
            machine_identifier=_first(_lower_keys(tracker), _MACHINE_KEYS),
            header_times=_header_times_from_lnk(lnk),
            raw=dict(tracker),
            source=None if isinstance(source, bytes) else str(source),
            source_kind=source_kind or "lnk",
        )

    if isinstance(source, (str, Path)):
        return TrackerInfo(source=str(source), source_kind="missing")
    if not isinstance(source, Mapping):
        raise TypeError(
            "Expected a LnkFile, LNK bytes, a local path, or a tracker mapping; "
            f"got {type(source).__name__}"
        )

    mapping_data = _first(source, _DATA_KEYS)
    if mapping_data is None:
        candidate_path = _first(source, ("path", "source_path", "filename", "file_name"))
        if isinstance(candidate_path, (str, Path)):
            path = Path(candidate_path)
            if path.exists() and path.is_file():
                mapping_data = candidate_path
    if isinstance(mapping_data, (LnkFile, bytes, bytearray, memoryview, str, Path)):
        lnk = _read_lnk(mapping_data)
    else:
        lnk = None

    if lnk is not None:
        tracker, source_kind = _tracker_from_lnk(lnk)
        tracker = tracker or {}
        header_times = _header_times_from_lnk(lnk)
    else:
        tracker, source_kind = _find_tracker_mapping(source)
        tracker = tracker or {}
        header_times = {}

    current, birth = _identities_from_tracker(tracker)
    machine = _first(_lower_keys(tracker), _MACHINE_KEYS)
    if machine is None:
        machine = _first(_lower_keys(source), _MACHINE_KEYS)

    explicit_header = _header_times_from_mapping(source)
    for key, value in explicit_header.items():
        if value is not None:
            header_times[key] = value

    return TrackerInfo(
        current=current,
        birth=birth,
        machine_identifier=machine,
        header_times=header_times,
        raw=dict(tracker),
        source=_source_label(source),
        source_kind=source_kind or "mapping",
    )


tracker_identity = parse_tracker_identity
extract_tracker_identity = parse_tracker_identity
reconcile_tracker_identities = parse_tracker_identity
extract_distributed_link_tracker = parse_tracker_identity
distributed_link_tracker_identity = parse_tracker_identity


def _source_label(mapping: Mapping) -> str | None:
    value = _first(_lower_keys(mapping), _SOURCE_KEYS)
    if value is None:
        return None
    if isinstance(value, (str, Path)):
        return str(value)
    return None


@dataclass
class Observation:
    """One local sample participating in lineage reconstruction."""

    sample_id: Any
    current: DroidIdentity = field(default_factory=DroidIdentity)
    birth: DroidIdentity | None = None
    machine_identifier: str | None = None
    collection_order: Any = None
    hardware_generation: Any = None
    collection_batch: str | None = None
    header_creation_time: datetime | None = None
    header_access_time: datetime | None = None
    header_modified_time: datetime | None = None
    source: Any = None
    source_path: str | None = None
    tracker_raw: dict[str, Any] = field(default_factory=dict)
    tracker_source: str | None = None
    input_id: Any = None
    index: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> Any:
        return self.sample_id

    @property
    def order(self) -> Any:
        return self.collection_order

    @property
    def generation(self) -> Any:
        return self.hardware_generation

    @property
    def machine_id(self) -> str | None:
        return self.machine_identifier

    @property
    def current_identity(self) -> DroidIdentity:
        return self.current

    @property
    def birth_identity(self) -> DroidIdentity | None:
        return self.birth

    @property
    def original_identity(self) -> DroidIdentity | None:
        return self.birth

    @property
    def current_key(self) -> tuple[str, str] | None:
        return self.current.key

    @property
    def birth_key(self) -> tuple[str, str] | None:
        return self.birth.key if self.birth else None

    @property
    def has_birth_identity(self) -> bool:
        return bool(self.birth and self.birth.is_complete)

    @property
    def identity_status(self) -> str:
        if not self.has_birth_identity or not self.current.is_complete:
            return STATUS_UNKNOWN_ORIGIN
        if self.current.key == self.birth.key:
            return STATUS_ORIGINAL
        return STATUS_DERIVED

    @property
    def is_original(self) -> bool:
        return self.identity_status == STATUS_ORIGINAL

    @property
    def status(self) -> str:
        return self.identity_status

    @property
    def identity_changed(self) -> bool:
        return self.identity_status == STATUS_DERIVED

    @property
    def original_key(self) -> tuple[str, str] | None:
        return self.birth_key

    @property
    def original_key_text(self) -> str | None:
        return self.birth.key_text if self.birth else None

    @property
    def header_times(self) -> dict[str, datetime | None]:
        return {
            "creation_time": self.header_creation_time,
            "access_time": self.header_access_time,
            "modified_time": self.header_modified_time,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.sample_id,
            "sample_id": self.sample_id,
            "input_id": self.input_id,
            "index": self.index,
            "machine_identifier": self.machine_identifier,
            "current": self.current.as_dict(),
            "birth": self.birth.as_dict() if self.birth else None,
            "original": self.birth.as_dict() if self.birth else None,
            "current_identity": self.current.as_dict(),
            "original_identity": self.birth.as_dict() if self.birth else None,
            "current_key": self.current.key_text,
            "birth_key": self.birth.key_text if self.birth else None,
            "original_key": self.original_key_text,
            "identity_status": self.identity_status,
            "is_original": self.is_original,
            "identity_changed": self.identity_changed,
            "has_birth_identity": self.has_birth_identity,
            "collection_order": _json_safe(self.collection_order),
            "hardware_generation": _json_safe(self.hardware_generation),
            "collection_batch": self.collection_batch,
            "source": _json_safe(self.source),
            "source_path": self.source_path,
            "header": _times_to_dict(self.header_times),
            "tracker_source": self.tracker_source,
            "tracker": _json_safe(self.tracker_raw),
            "droid_volume_identifier": self.current.volume_id,
            "droid_file_identifier": self.current.file_id,
            "birth_droid_volume_identifier": (self.birth.volume_id if self.birth else None),
            "birth_droid_file_identifier": self.birth.file_id if self.birth else None,
            "metadata": _json_safe(self.metadata),
        }

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_dict().get(key, default)


@dataclass
class LineageEdge:
    """A directed, provenance-bearing edge between two observations."""

    source: Any
    target: Any
    relation: str
    evidence_kind: str
    evidence: list[dict[str, Any]]
    provenance: dict[str, Any]
    support: float = 1.0
    confidence: str = "high"
    lineage: bool = True
    ambiguous: bool = False
    possible_relations: list[str] = field(default_factory=list)
    tied: bool = False
    tie_group: str | None = None
    constraints: dict[str, Any] = field(default_factory=dict)

    @property
    def from_id(self) -> Any:
        return self.source

    @property
    def to_id(self) -> Any:
        return self.target

    @property
    def edge_id(self) -> str:
        return f"{self.source}->{self.target}:{self.relation}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "source_id": self.source,
            "target_id": self.target,
            "predecessor": self.source,
            "successor": self.target,
            "from": self.source,
            "to": self.target,
            "relation": self.relation,
            "kind": self.relation,
            "type": self.relation,
            "lineage": self.lineage,
            "ambiguous": self.ambiguous,
            "possible_relations": list(self.possible_relations),
            "support": self.support,
            "confidence": self.confidence,
            "evidence_kind": self.evidence_kind,
            "evidence": _json_safe(self.evidence),
            "constraints": _json_safe(self.constraints),
            "provenance": _json_safe(self.provenance),
            "tied": self.tied,
            "tie_group": self.tie_group,
        }

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_dict().get(key, default)


@dataclass
class LineageResult:
    nodes: list[Observation] = field(default_factory=list)
    edges: list[LineageEdge] = field(default_factory=list)
    ties: list[dict[str, Any]] = field(default_factory=list)
    branches: list[dict[str, Any]] = field(default_factory=list)
    identifier_shares: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def edge_dicts(self) -> list[dict[str, Any]]:
        return [edge.as_dict() for edge in self.edges]

    @property
    def tied_edges(self) -> list[LineageEdge]:
        return [edge for edge in self.edges if edge.tied]

    def as_dict(
        self,
        edges_only: bool = False,
        include_snapshot_edges: bool = True,
        include_provenance: bool = True,
    ) -> Any:
        edges = [
            edge
            for edge in self.edges
            if include_snapshot_edges or edge.relation != RELATION_SNAPSHOT_REUSE
        ]
        edge_dicts = []
        for edge in edges:
            item = edge.as_dict()
            if not include_provenance:
                item.pop("provenance", None)
            edge_dicts.append(item)

        if edges_only:
            return edge_dicts

        lineage_edge_dicts = [edge for edge in edge_dicts if edge["lineage"]]
        snapshot_edge_dicts = [
            edge for edge in edge_dicts if edge["relation"] == RELATION_SNAPSHOT_REUSE
        ]
        return {
            "schema_version": SCHEMA_VERSION,
            "node_count": len(self.nodes),
            "edge_count": len(edge_dicts),
            "tie_count": len(self.ties),
            "branch_count": len(self.branches),
            "nodes": [node.as_dict() for node in self.nodes],
            "edges": edge_dicts,
            "lineage_edges": lineage_edge_dicts,
            "snapshot_reuse_edges": snapshot_edge_dicts,
            "ties": _json_safe(self.ties),
            "tied_predecessors": _json_safe(self.ties),
            "branches": _json_safe(self.branches),
            "identifier_shares": _json_safe(self.identifier_shares),
            "diagnostics": _json_safe(self.diagnostics),
        }

    def to_dict(self, **kwargs) -> dict[str, Any]:
        return self.as_dict(**kwargs)

    def to_json(self, **kwargs) -> str:
        return json.dumps(
            self.as_dict(**kwargs),
            indent=2,
            ensure_ascii=False,
            default=_json_safe,
        )

    def export(
        self,
        path: Any,
        edges_only: bool = False,
        format: str = "json",
        include_snapshot_edges: bool = True,
        include_provenance: bool = True,
    ) -> Path:
        """Write lineage edges (with provenance) to a local JSON/JSONL file."""
        output_path = Path(path)
        if output_path.parent and str(output_path.parent) != ".":
            output_path.parent.mkdir(parents=True, exist_ok=True)

        if format in {"jsonl", "jsonlines", "ndjson"}:
            edges = self.as_dict(
                edges_only=True,
                include_snapshot_edges=include_snapshot_edges,
                include_provenance=include_provenance,
            )
            with output_path.open("w", encoding="utf-8") as handle:
                for edge in edges:
                    handle.write(json.dumps(edge, ensure_ascii=False, default=_json_safe) + "\n")
            return output_path

        payload = self.as_dict(
            edges_only=edges_only,
            include_snapshot_edges=include_snapshot_edges,
            include_provenance=include_provenance,
        )
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, default=_json_safe)
            handle.write("\n")
        return output_path

    write = export

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, slice):
            return self.edge_dicts[key]
        if isinstance(key, int):
            return self.edge_dicts[key]
        return self.as_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_dict().get(key, default)

    def keys(self):
        return self.as_dict().keys()

    def items(self):
        return self.as_dict().items()

    def values(self):
        return self.as_dict().values()

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, str):
            return item in self.as_dict()
        return item in self.edges

    def __iter__(self):
        return iter(self.edge_dicts)

    def __len__(self) -> int:
        return len(self.edges)


def _rank(value: Any) -> tuple[int, Any] | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return (0, float(value))
    if isinstance(value, (int, float)):
        return (0, float(value))
    text = str(value).strip()
    if not text:
        return None
    try:
        return (0, float(text))
    except ValueError:
        pass
    parts = re.split(r"(\d+)", text.lower())
    natural = tuple((0, int(part)) if part.isdigit() else (1, part) for part in parts if part)
    return (1, natural)


def _compare(left: Any, right: Any) -> int | None:
    left_rank = _rank(left)
    right_rank = _rank(right)
    if left_rank is None or right_rank is None:
        return None
    if left_rank < right_rank:
        return -1
    if left_rank > right_rank:
        return 1
    return 0


def _generation_value(value: Any, generation_order: Any | None) -> Any:
    if generation_order is None or value is None:
        return value
    if callable(generation_order):
        try:
            return generation_order(value)
        except TypeError:
            return value
    if isinstance(generation_order, Mapping):
        if value in generation_order:
            return generation_order[value]
        if str(value) in generation_order:
            return generation_order[str(value)]
    if isinstance(generation_order, Sequence) and not isinstance(generation_order, str):
        for index, item in enumerate(generation_order):
            if item == value or str(item) == str(value):
                return index
    return value


def _lookup_meta(
    meta: Any,
    sample_id: Any,
    machine_id: str | None,
    index: int,
    sample_ids: set[str] | None = None,
) -> Any:
    if meta is None:
        return None
    if callable(meta):
        for candidate in (sample_id, machine_id, index):
            try:
                return meta(candidate)
            except (KeyError, TypeError, IndexError):
                continue
        return None
    if isinstance(meta, Mapping):
        lowered = _lower_keys(meta)
        for key in (sample_id, machine_id):
            if key is None:
                continue
            if key in meta:
                return meta[key]
            if str(key) in meta:
                return meta[str(key)]
            if str(key).lower() in lowered:
                return lowered[str(key).lower()]
        if index in meta:
            return meta[index]
        return None
    if isinstance(meta, Sequence) and not isinstance(meta, (str, bytes, bytearray)):
        if (
            sample_ids
            and len(meta) == len(sample_ids)
            and all(str(item) in sample_ids for item in meta)
        ):
            position = {str(item): idx for idx, item in enumerate(meta)}
            if str(sample_id) in position:
                return position[str(sample_id)]
            if machine_id and machine_id in position:
                return position[machine_id]
        if 0 <= index < len(meta):
            return meta[index]
        return None
    return meta


def _generation_from_meta(meta: Any, sample_id: Any, machine_id: str | None, index: int) -> Any:
    value = _lookup_meta(meta, sample_id, machine_id, index)
    if isinstance(value, Mapping):
        return _first(_lower_keys(value), _GENERATION_KEYS)
    return value


def _sample_id_for(spec: Mapping, tracker: TrackerInfo, index: int) -> Any:
    sample_id = _first(_lower_keys(spec), _SAMPLE_ID_KEYS)
    if sample_id is not None:
        return sample_id
    if tracker.source:
        return tracker.source
    return f"sample-{index}"


def _source_for(spec: Mapping, tracker: TrackerInfo) -> Any:
    source = _first(_lower_keys(spec), _SOURCE_KEYS)
    if source is not None:
        return source
    return tracker.source


def _collection_batch_for(spec: Mapping) -> str | None:
    value = _first(_lower_keys(spec), _BATCH_KEYS)
    if value is None:
        return None
    return str(value)


def _observation_from_item(
    item: Any,
    index: int,
    hardware_generations: Any,
    collection_order: Any,
    header_times: Any,
    generation_order: Any,
    sample_ids: set[str] | None,
) -> Observation:
    if isinstance(item, Observation):
        observation = Observation(
            sample_id=item.sample_id,
            current=item.current,
            birth=item.birth,
            machine_identifier=item.machine_identifier,
            collection_order=item.collection_order,
            hardware_generation=item.hardware_generation,
            collection_batch=item.collection_batch,
            header_creation_time=item.header_creation_time,
            header_access_time=item.header_access_time,
            header_modified_time=item.header_modified_time,
            source=item.source,
            source_path=item.source_path,
            tracker_raw=dict(item.tracker_raw),
            tracker_source=item.tracker_source,
            input_id=item.input_id if item.input_id is not None else item.sample_id,
            index=index,
            metadata=dict(item.metadata),
        )
        spec: Mapping = {}
    elif isinstance(item, Mapping):
        spec = item
        tracker = parse_tracker_identity(item)
        sample_id = _sample_id_for(spec, tracker, index)
        explicit_machine = _first(_lower_keys(spec), _MACHINE_KEYS)
        observation = Observation(
            sample_id=sample_id,
            current=tracker.current,
            birth=tracker.birth,
            machine_identifier=explicit_machine or tracker.machine_identifier,
            source=_source_for(spec, tracker),
            source_path=tracker.source,
            tracker_raw=tracker.raw,
            tracker_source=tracker.source_kind,
            header_creation_time=tracker.header_times.get("creation_time"),
            header_access_time=tracker.header_times.get("access_time"),
            header_modified_time=tracker.header_times.get("modified_time"),
            input_id=sample_id,
            index=index,
            metadata={
                key: value
                for key, value in spec.items()
                if str(key).lower() not in {*_DATA_KEYS, *_TRACKER_KEYS}
            },
        )
    else:
        spec = {}
        tracker = parse_tracker_identity(item)
        sample_id = tracker.source or f"sample-{index}"
        observation = Observation(
            sample_id=sample_id,
            current=tracker.current,
            birth=tracker.birth,
            machine_identifier=tracker.machine_identifier,
            source=tracker.source,
            source_path=tracker.source,
            tracker_raw=tracker.raw,
            tracker_source=tracker.source_kind,
            header_creation_time=tracker.header_times.get("creation_time"),
            header_access_time=tracker.header_times.get("access_time"),
            header_modified_time=tracker.header_times.get("modified_time"),
            input_id=sample_id,
            index=index,
        )

    lowered = _lower_keys(spec)
    explicit_machine = _first(lowered, _MACHINE_KEYS)
    if explicit_machine is not None:
        observation.machine_identifier = explicit_machine

    order = _first(lowered, _ORDER_KEYS)
    if order is None:
        order = _lookup_meta(
            collection_order,
            observation.sample_id,
            observation.machine_identifier,
            index,
            sample_ids,
        )
    observation.collection_order = order

    generation = _first(lowered, _GENERATION_KEYS)
    if generation is None:
        generation = _generation_from_meta(
            hardware_generations,
            observation.sample_id,
            observation.machine_identifier,
            index,
        )
    observation.hardware_generation = _generation_value(generation, generation_order)

    if observation.collection_batch is None:
        observation.collection_batch = _collection_batch_for(spec)

    explicit_times = _header_times_from_mapping(spec)
    if explicit_times.get("creation_time") is not None:
        observation.header_creation_time = explicit_times["creation_time"]
    if explicit_times.get("access_time") is not None:
        observation.header_access_time = explicit_times["access_time"]
    if explicit_times.get("modified_time") is not None:
        observation.header_modified_time = explicit_times["modified_time"]

    external_times = _lookup_meta(
        header_times,
        observation.sample_id,
        observation.machine_identifier,
        index,
        sample_ids,
    )
    if isinstance(external_times, Mapping):
        external_times = _header_times_from_mapping(external_times)
        for key, value in external_times.items():
            if value is None:
                continue
            if key == "creation_time" and observation.header_creation_time is None:
                observation.header_creation_time = value
            elif key == "access_time" and observation.header_access_time is None:
                observation.header_access_time = value
            elif key == "modified_time" and observation.header_modified_time is None:
                observation.header_modified_time = value

    return observation


def normalize_observations(
    samples: Any,
    hardware_generations: Any = None,
    collection_order: Any = None,
    header_times: Any = None,
    generation_order: Any = None,
) -> list[Observation]:
    """Normalize caller-provided samples into ordered :class:`Observation` objects."""
    if isinstance(samples, LineageResult):
        return list(samples.nodes)
    if isinstance(samples, (str, Path)):
        path = Path(samples)
        if path.exists() and path.is_file() and path.suffix.lower() in {".json", ".jsonl"}:
            if path.suffix.lower() == ".jsonl":
                payload = [
                    json.loads(line)
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            else:
                payload = json.loads(path.read_text(encoding="utf-8"))
            return normalize_observations(
                payload,
                hardware_generations=hardware_generations,
                collection_order=collection_order,
                header_times=header_times,
                generation_order=generation_order,
            )
    if isinstance(samples, Observation):
        samples = [samples]
    elif isinstance(samples, Mapping):
        lowered = _lower_keys(samples)
        if "samples" in lowered:
            samples = lowered["samples"]
            hardware_generations = (
                hardware_generations
                if hardware_generations is not None
                else _first(lowered, ("hardware_generations", "generations"))
            )
            collection_order = (
                collection_order
                if collection_order is not None
                else _first(lowered, ("collection_order", "order", "sequence"))
            )
            header_times = (
                header_times
                if header_times is not None
                else _first(lowered, ("header_times", "timestamps"))
            )
            generation_order = (
                generation_order
                if generation_order is not None
                else _first(lowered, ("generation_order", "generation_ranks"))
            )
        elif not _has_tracker_fields(samples) and all(
            isinstance(value, Mapping) for value in samples.values()
        ):
            samples = [{"sample_id": key, **value} for key, value in samples.items()]
        else:
            samples = [samples]
    elif isinstance(
        samples, (str, Path, bytes, bytearray, memoryview, LnkFile, TrackerInfo)
    ) or not isinstance(samples, Iterable):
        samples = [samples]

    raw_items = list(samples)
    items = []
    for item in raw_items:
        if (
            isinstance(item, (tuple, list))
            and 2 <= len(item) <= 4
            and isinstance(item[0], (str, int))
            and (
                not isinstance(item[1], (str, int))
                or (isinstance(item[1], str) and Path(item[1]).exists())
            )
        ):
            spec = {"sample_id": item[0], "data": item[1]}
            if len(item) >= 3:
                spec["collection_order"] = item[2]
            if len(item) >= 4:
                spec["hardware_generation"] = item[3]
            items.append(spec)
        else:
            items.append(item)
    sample_ids: set[str] = set()
    for _index, item in enumerate(items):
        if isinstance(item, Mapping):
            raw_id = _first(_lower_keys(item), _SAMPLE_ID_KEYS)
            if raw_id is not None:
                sample_ids.add(str(raw_id))
        else:
            raw_id = getattr(item, "sample_id", None)
            if raw_id is not None:
                sample_ids.add(str(raw_id))

    observations = []
    for index, item in enumerate(items):
        observations.append(
            _observation_from_item(
                item,
                index,
                hardware_generations,
                collection_order,
                header_times,
                generation_order,
                sample_ids,
            )
        )

    seen: dict[str, int] = {}
    for observation in observations:
        base = observation.sample_id
        if base is None:
            base = f"sample-{observation.index}"
        try:
            hash(base)
            key = base
        except TypeError:
            key = _json_safe(base)
        count = seen.get(str(key), 0)
        if count:
            observation.sample_id = f"{key}#{count + 1}"
        else:
            observation.sample_id = key
        seen[str(key)] = count + 1
        if observation.input_id is None:
            observation.input_id = base

    return observations


def _header_allows(source: Observation, target: Observation) -> tuple[bool, dict[str, Any]]:
    checked: dict[str, Any] = {}
    allowed = True
    for field_name in ("modified_time", "access_time", "creation_time"):
        source_time = getattr(source, f"header_{field_name}")
        target_time = getattr(target, f"header_{field_name}")
        if source_time is None or target_time is None:
            continue
        checked[field_name] = {
            "source": _json_safe(source_time),
            "target": _json_safe(target_time),
            "monotonic": source_time <= target_time,
        }
        if source_time > target_time:
            allowed = False
    return allowed, {
        "rule": "target_timestamp >= source_timestamp",
        "effect": "constraint_only",
        "checked": checked,
        "satisfied": allowed,
    }


def _order_constraint(source: Observation, target: Observation) -> dict[str, Any]:
    comparison = _compare(source.collection_order, target.collection_order)
    return {
        "source": _json_safe(source.collection_order),
        "target": _json_safe(target.collection_order),
        "comparison": comparison,
        "satisfied": comparison is None or comparison <= 0,
    }


def _generation_constraint(source: Observation, target: Observation) -> dict[str, Any]:
    comparison = _compare(source.hardware_generation, target.hardware_generation)
    return {
        "source": _json_safe(source.hardware_generation),
        "target": _json_safe(target.hardware_generation),
        "source_machine": source.machine_identifier,
        "target_machine": target.machine_identifier,
        "comparison": comparison,
        "satisfied": comparison is None or comparison <= 0,
    }


def _order_allows(
    source: Observation,
    target: Observation,
    source_index: int,
    target_index: int,
) -> bool:
    comparison = _compare(source.collection_order, target.collection_order)
    if comparison is None:
        return True
    if comparison < 0:
        return True
    if comparison > 0:
        return False
    return source_index < target_index


def _generation_allows(source: Observation, target: Observation) -> bool:
    comparison = _compare(source.hardware_generation, target.hardware_generation)
    return comparison is None or comparison <= 0


def _identity_evidence_kind(source: Observation, target: Observation) -> str | None:
    if not source.current.is_complete:
        return None
    if (
        target.birth
        and target.birth.is_complete
        and target.current.is_complete
        and source.current.key == target.birth.key
        and source.current.key != target.current.key
    ):
        return "birth_identifier"
    if target.current.is_complete and source.current.key == target.current.key:
        return "current_identifier"
    return None


def _relation_for_birth_edge(source: Observation, target: Observation) -> str:
    volume_changed = source.current.volume_id != target.current.volume_id
    generation_changed = _compare(source.hardware_generation, target.hardware_generation) not in (
        None,
        0,
    )
    machine_changed = bool(
        source.machine_identifier
        and target.machine_identifier
        and source.machine_identifier.lower() != target.machine_identifier.lower()
    )
    if volume_changed or generation_changed or machine_changed:
        return RELATION_MIGRATION
    return RELATION_COPY


def _same_relation(source: Observation, target: Observation) -> str:
    same_batch = bool(
        source.collection_batch
        and target.collection_batch
        and source.collection_batch == target.collection_batch
    )
    order_comparison = _compare(source.collection_order, target.collection_order)
    birth_conflict = bool(
        source.birth
        and target.birth
        and source.birth.key
        and target.birth.key
        and source.birth.key != target.birth.key
    )
    if same_batch or order_comparison == 0 or birth_conflict:
        return RELATION_SNAPSHOT_REUSE
    return RELATION_CONTINUATION


def _observation_provenance(observation: Observation) -> dict[str, Any]:
    return {
        "sample_id": observation.sample_id,
        "source": _json_safe(observation.source),
        "source_path": observation.source_path,
        "machine_identifier": observation.machine_identifier,
        "collection_order": _json_safe(observation.collection_order),
        "hardware_generation": _json_safe(observation.hardware_generation),
        "collection_batch": observation.collection_batch,
        "current": observation.current.as_dict(),
        "birth": observation.birth.as_dict() if observation.birth else None,
        "tracker_source": observation.tracker_source,
    }


def _base_evidence(
    source: Observation,
    target: Observation,
    evidence_kind: str,
    order_constraint: dict[str, Any],
    generation_constraint: dict[str, Any],
    header_constraint: dict[str, Any],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    if evidence_kind == "birth_identifier":
        evidence.append(
            {
                "kind": "birth_identifier",
                "role": "ancestry",
                "source_sample": source.sample_id,
                "target_sample": target.sample_id,
                "source_fields": [
                    "droid_volume_identifier",
                    "droid_file_identifier",
                ],
                "target_fields": [
                    "birth_droid_volume_identifier",
                    "birth_droid_file_identifier",
                ],
                "source_value": source.current.as_dict(),
                "target_value": target.birth.as_dict() if target.birth else None,
                "identity_key": source.current.key_text,
            }
        )
    else:
        evidence.append(
            {
                "kind": "current_identifier",
                "role": "identity_share",
                "source_sample": source.sample_id,
                "target_sample": target.sample_id,
                "source_fields": [
                    "droid_volume_identifier",
                    "droid_file_identifier",
                ],
                "target_fields": [
                    "droid_volume_identifier",
                    "droid_file_identifier",
                ],
                "source_value": source.current.as_dict(),
                "target_value": target.current.as_dict(),
                "identity_key": source.current.key_text,
            }
        )
    if order_constraint["comparison"] is not None:
        evidence.append(
            {
                "kind": "collection_order",
                "role": "ordering",
                "source_sample": source.sample_id,
                "target_sample": target.sample_id,
                "source": order_constraint["source"],
                "target": order_constraint["target"],
                "comparison": order_constraint["comparison"],
            }
        )
    if generation_constraint["comparison"] is not None:
        evidence.append(
            {
                "kind": "hardware_generation",
                "role": "ordering",
                "source_sample": source.sample_id,
                "target_sample": target.sample_id,
                "source": generation_constraint["source"],
                "target": generation_constraint["target"],
                "source_machine": generation_constraint["source_machine"],
                "target_machine": generation_constraint["target_machine"],
                "comparison": generation_constraint["comparison"],
            }
        )
    if header_constraint["checked"]:
        evidence.append(
            {
                "kind": "header_time",
                "role": "constraint",
                "source_sample": source.sample_id,
                "target_sample": target.sample_id,
                "effect": "constraint_only",
                "rule": header_constraint["rule"],
                "satisfied": header_constraint["satisfied"],
                "checked": header_constraint["checked"],
            }
        )
    return evidence


def _provenance(
    source: Observation,
    target: Observation,
    evidence: list[dict[str, Any]],
    order_constraint: dict[str, Any],
    generation_constraint: dict[str, Any],
    header_constraint: dict[str, Any],
) -> dict[str, Any]:
    return {
        "method": "distributed_link_tracker_identity_reconciliation",
        "source_sample": source.sample_id,
        "target_sample": target.sample_id,
        "source_path": source.source_path,
        "target_path": target.source_path,
        "source": _observation_provenance(source),
        "target": _observation_provenance(target),
        "identifiers": {
            "source_current": source.current.key_text,
            "target_birth": target.birth.key_text if target.birth else None,
            "target_current": target.current.key_text,
        },
        "evidence": evidence,
        "constraints": {
            "collection_order": order_constraint,
            "hardware_generation": generation_constraint,
            "header_time": header_constraint,
        },
    }


def _make_birth_edge(source: Observation, target: Observation) -> LineageEdge | None:
    order_constraint = _order_constraint(source, target)
    if not order_constraint["satisfied"]:
        return None
    generation_constraint = _generation_constraint(source, target)
    if not generation_constraint["satisfied"]:
        return None
    header_ok, header_constraint = _header_allows(source, target)
    if not header_ok:
        return None

    relation = _relation_for_birth_edge(source, target)
    evidence = _base_evidence(
        source,
        target,
        "birth_identifier",
        order_constraint,
        generation_constraint,
        header_constraint,
    )
    return LineageEdge(
        source=source.sample_id,
        target=target.sample_id,
        relation=relation,
        evidence_kind="birth_identifier",
        evidence=evidence,
        provenance=_provenance(
            source,
            target,
            evidence,
            order_constraint,
            generation_constraint,
            header_constraint,
        ),
        support=1.0,
        confidence="high",
        lineage=True,
        ambiguous=True,
        possible_relations=[RELATION_MIGRATION, RELATION_COPY],
        constraints={
            "collection_order": order_constraint,
            "hardware_generation": generation_constraint,
            "header_time": header_constraint,
        },
    )


def _make_same_identity_edge(source: Observation, target: Observation) -> LineageEdge | None:
    order_constraint = _order_constraint(source, target)
    if not order_constraint["satisfied"]:
        return None
    generation_constraint = _generation_constraint(source, target)
    header_ok, header_constraint = _header_allows(source, target)
    if not header_ok:
        return None

    relation = _same_relation(source, target)
    is_reuse = relation == RELATION_SNAPSHOT_REUSE
    if not is_reuse and not _generation_allows(source, target):
        return None
    evidence = _base_evidence(
        source,
        target,
        "current_identifier",
        order_constraint,
        generation_constraint,
        header_constraint,
    )
    return LineageEdge(
        source=source.sample_id,
        target=target.sample_id,
        relation=relation,
        evidence_kind="current_identifier",
        evidence=evidence,
        provenance=_provenance(
            source,
            target,
            evidence,
            order_constraint,
            generation_constraint,
            header_constraint,
        ),
        support=0.6 if is_reuse else 0.75,
        confidence="low" if is_reuse else "medium",
        lineage=not is_reuse,
        ambiguous=True,
        possible_relations=[RELATION_CONTINUATION, RELATION_SNAPSHOT_REUSE],
        constraints={
            "collection_order": order_constraint,
            "hardware_generation": generation_constraint,
            "header_time": header_constraint,
        },
    )


def _snapshot_sort_key(observation: Observation) -> tuple[int, Any, Any, int]:
    order_rank = _rank(observation.collection_order)
    generation_rank = _rank(observation.hardware_generation)
    if order_rank is not None:
        return (0, order_rank, generation_rank or (9, ()), observation.index)
    if generation_rank is not None:
        return (1, generation_rank, (9, ()), observation.index)
    return (2, (9, ()), (9, ()), observation.index)


def _build_edges(observations: list[Observation]) -> list[LineageEdge]:
    edges: list[LineageEdge] = []
    seen = set()

    def append(edge: LineageEdge | None) -> None:
        if edge is None:
            return
        key = (edge.source, edge.target, edge.relation, edge.evidence_kind)
        if key in seen:
            return
        seen.add(key)
        edges.append(edge)

    for source_index, source in enumerate(observations):
        for target_index, target in enumerate(observations):
            if source_index == target_index:
                continue
            if not _order_allows(source, target, source_index, target_index):
                continue
            evidence_kind = _identity_evidence_kind(source, target)
            if evidence_kind == "birth_identifier":
                if not _generation_allows(source, target):
                    continue
                append(_make_birth_edge(source, target))

    identity_groups: dict[tuple[str, str], list[Observation]] = {}
    for observation in observations:
        if observation.current.is_complete:
            identity_groups.setdefault(observation.current.key, []).append(observation)

    for group in identity_groups.values():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=_snapshot_sort_key)
        for source, target in pairwise(ordered):
            append(_make_same_identity_edge(source, target))

    return edges


def _compute_ties(
    edges: list[LineageEdge],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_target: dict[Any, list[LineageEdge]] = {}
    for edge in edges:
        if not edge.lineage:
            continue
        by_target.setdefault(edge.target, []).append(edge)

    ties: list[dict[str, Any]] = []
    branches: list[dict[str, Any]] = []
    for target, incoming in by_target.items():
        groups: dict[tuple[str, float], list[LineageEdge]] = {}
        for edge in incoming:
            groups.setdefault((edge.evidence_kind, edge.support), []).append(edge)

        target_tie_groups = []
        for (evidence_kind, support), group in groups.items():
            if len(group) < 2:
                continue
            tie_group = f"tie:{target}:{evidence_kind}:{support:g}"
            for edge in group:
                edge.tied = True
                edge.tie_group = tie_group
            tie = {
                "target": target,
                "predecessors": [edge.source for edge in group],
                "edges": [edge.edge_id for edge in group],
                "evidence_kind": evidence_kind,
                "support": support,
                "tie_group": tie_group,
                "note": (
                    "Multiple observations are equally supported predecessors; "
                    "all branches are retained for review."
                ),
            }
            ties.append(tie)
            target_tie_groups.append(tie_group)

        if len(incoming) > 1:
            branches.append(
                {
                    "target": target,
                    "predecessors": [edge.source for edge in incoming],
                    "relations": [edge.relation for edge in incoming],
                    "tied": bool(target_tie_groups),
                    "tie_groups": target_tie_groups,
                    "note": (
                        "Predecessors may represent continuation, migration, or "
                        "re-used snapshot identifiers."
                    ),
                }
            )
    return ties, branches


def _compute_identifier_shares(observations: list[Observation]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[Observation]] = {}
    for observation in observations:
        if observation.current.is_complete:
            groups.setdefault(observation.current.key, []).append(observation)
    shares = []
    for identity, group in groups.items():
        if len(group) < 2:
            continue
        shares.append(
            {
                "identity": f"{identity[0]}|{identity[1]}",
                "volume_id": identity[0],
                "file_id": identity[1],
                "samples": [observation.sample_id for observation in group],
                "collection_batches": sorted(
                    {
                        observation.collection_batch
                        for observation in group
                        if observation.collection_batch
                    }
                ),
                "interpretations": [
                    "continuation",
                    "snapshot_reuse",
                ],
                "note": (
                    "Shared current identifiers can be a surviving target or a "
                    "re-used/duplicated snapshot; both interpretations are retained."
                ),
            }
        )
    return shares


def build_lineage(
    samples: Any,
    hardware_generations: Any = None,
    collection_order: Any = None,
    header_times: Any = None,
    generation_order: Any = None,
    include_snapshot_edges: bool = True,
    **options: Any,
) -> LineageResult:
    """Build a conservative migration/copy lineage from local observations.

    Args:
        samples: Iterable of sample mappings, LNK paths/bytes, or
            :class:`Observation` objects.  A mapping with a ``samples`` key is
            treated as a manifest and may also supply the keyword metadata.
        hardware_generations: Mapping of sample id or machine id to a hardware
            generation, a sequence aligned with ``samples``, or a callable.
        collection_order: Mapping of sample id to collection order, a sequence
            aligned with ``samples``, a sequence of sample ids in collection
            order, or a callable.
        header_times: Optional mapping of sample id to header timestamps.  LNK
            header times are read automatically when available.
        generation_order: Optional mapping/sequence used to rank generation
            labels such as ``"old"`` and ``"new"``.

    Returns:
        :class:`LineageResult` with provenance-bearing edges, tie groups, and
        branch records.
    """
    if hardware_generations is None:
        hardware_generations = options.pop("hardware_generation", options.pop("generations", None))
    if collection_order is None:
        collection_order = options.pop("collection_sequence", options.pop("sequence", None))
    if header_times is None:
        header_times = options.pop("timestamps", None)
    if generation_order is None:
        generation_order = options.pop("generation_ranks", options.pop("generation_labels", None))
    if "include_snapshot" in options:
        include_snapshot_edges = bool(options.pop("include_snapshot"))
    if "include_snapshot_reuse" in options:
        include_snapshot_edges = bool(options.pop("include_snapshot_reuse"))
    observations = normalize_observations(
        samples,
        hardware_generations=hardware_generations,
        collection_order=collection_order,
        header_times=header_times,
        generation_order=generation_order,
    )
    edges = _build_edges(observations)
    if not include_snapshot_edges:
        edges = [edge for edge in edges if edge.relation != RELATION_SNAPSHOT_REUSE]
    ties, branches = _compute_ties(edges)
    identifier_shares = _compute_identifier_shares(observations)

    unresolved = [
        observation.sample_id for observation in observations if not observation.current.is_complete
    ]
    diagnostics = {
        "sample_count": len(observations),
        "edge_count": len(edges),
        "tie_count": len(ties),
        "branch_count": len(branches),
        "identifier_share_count": len(identifier_shares),
        "unresolved_samples": unresolved,
        "rules": {
            "ancestry": (
                "An edge is proposed only when source.current matches "
                "target.birth (migration/copy) or both current identities match "
                "(identity sharing)."
            ),
            "identifier_share": (
                "A shared current identity is retained as snapshot_reuse or "
                "ambiguous continuation; it is never dropped as a duplicate."
            ),
            "collection_order": "source.order <= target.order",
            "hardware_generation": (
                "source.generation <= target.generation for migration/copy edges"
            ),
            "header_time": (
                "Header timestamps only reject edges where target < source; "
                "they never create an edge."
            ),
            "ties": "All equally supported predecessors are retained.",
        },
    }
    return LineageResult(
        nodes=observations,
        edges=edges,
        ties=ties,
        branches=branches,
        identifier_shares=identifier_shares,
        diagnostics=diagnostics,
    )


build_migration_lineage = build_lineage
trace_lineage = build_lineage
reconstruct_lineage = build_lineage
build_tracker_lineage = build_lineage


def export_lineage(
    samples: Any,
    path: Any = None,
    edges_only: bool = False,
    format: str = "json",
    include_snapshot_edges: bool = True,
    include_provenance: bool = True,
    output: Any = None,
    output_path: Any = None,
    **build_kwargs,
) -> Any:
    """Build and optionally export a lineage with source-bearing edges.

    Without ``path``, returns the serialized lineage dictionary.  With
    ``path``, writes JSON/JSONL and returns the output :class:`Path`.
    """
    result = (
        samples if isinstance(samples, LineageResult) else build_lineage(samples, **build_kwargs)
    )
    path = path if path is not None else output if output is not None else output_path
    if path is None:
        return result.as_dict(
            edges_only=edges_only,
            include_snapshot_edges=include_snapshot_edges,
            include_provenance=include_provenance,
        )
    return result.export(
        path,
        edges_only=edges_only,
        format=format,
        include_snapshot_edges=include_snapshot_edges,
        include_provenance=include_provenance,
    )


def export_lineage_edges(
    samples: Any,
    path: Any = None,
    format: str = "json",
    include_snapshot_edges: bool = False,
    output: Any = None,
    output_path: Any = None,
    **build_kwargs,
) -> Any:
    """Export only provenance-bearing lineage edges."""
    return export_lineage(
        samples,
        path=path,
        edges_only=True,
        format=format,
        include_snapshot_edges=include_snapshot_edges,
        output=output,
        output_path=output_path,
        **build_kwargs,
    )


export_edges = export_lineage_edges
write_lineage = export_lineage
save_lineage = export_lineage
write_lineage_edges = export_lineage_edges
save_edges = export_lineage_edges


def lineage_edges(
    samples: Any,
    include_snapshot_edges: bool = False,
    include_provenance: bool = True,
    **build_kwargs,
) -> list[dict[str, Any]]:
    """Return provenance-bearing lineage edges as dictionaries."""
    return build_lineage(samples, **build_kwargs).as_dict(
        edges_only=True,
        include_snapshot_edges=include_snapshot_edges,
        include_provenance=include_provenance,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline DistributedLinkTracker migration/copy lineage builder. "
            "Input is a JSON manifest or a list of observation mappings."
        )
    )
    parser.add_argument("manifest", help="JSON manifest containing samples")
    parser.add_argument("-o", "--output", help="write lineage edges to this file")
    parser.add_argument(
        "--edges-only",
        action="store_true",
        help="write only edges (provenance is retained)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "jsonl"),
        default="json",
        help="output format when --output is used",
    )
    parser.add_argument(
        "--include-snapshot-edges",
        dest="include_snapshot_edges",
        action="store_true",
        default=True,
        help="include identifier-sharing snapshot edges (default)",
    )
    parser.add_argument(
        "--exclude-snapshot-edges",
        dest="include_snapshot_edges",
        action="store_false",
        help="omit identifier-sharing snapshot edges from the export",
    )
    args = parser.parse_args(argv)

    result = build_lineage(args.manifest)
    if args.output:
        result.export(
            args.output,
            edges_only=args.edges_only,
            format=args.format,
            include_snapshot_edges=args.include_snapshot_edges,
        )
    else:
        payload = result.as_dict(
            edges_only=args.edges_only,
            include_snapshot_edges=args.include_snapshot_edges,
        )
        try:
            print(json.dumps(payload, indent=2, ensure_ascii=False, default=_json_safe))
        except BrokenPipeError:
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
