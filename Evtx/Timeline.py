"""Offline timeline diagnostics for Windows EVTX files.

The diagnostic deliberately keeps three sources of ordering evidence apart:

``original-record``
    Evidence read from the EVTX bytes: physical record order, record numbers,
    chunk boundaries, and timestamps stored in the records.

``collection``
    Evidence supplied by the collector (a receipt/acknowledgement manifest):
    receipt sequence, receipt time, block/record identifiers, and explicit
    loss markers.

The two bases are never silently merged into a single "corrected" time.  A
backward jump in event time remains visible in the original-record timeline,
and missing chunks/records remain visible as gaps.  If a receipt manifest
corroborates the host clock change, that fact is recorded on the event; it does
not reorder or rewrite the EVTX records.

The module intentionally has no third-party runtime dependency.  Event XML is
parsed with :mod:`xml.etree.ElementTree` from the standard library.
"""

from __future__ import annotations

import re
import csv
import sys
import json
import mmap
import struct
import argparse
import contextlib
import datetime as _datetime
import xml.etree.ElementTree as ET

from dataclasses import field, fields, dataclass, is_dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = 0x2A2A
FILE_HEADER_SIZE = 0x1000
CHUNK_SIZE = 0x10000
CHUNK_HEADER_USABLE = 0x200
MIN_RECORD_SIZE = 0x18
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

_MISSING_STATUSES = {
    "missing",
    "lost",
    "absent",
    "bad",
    "corrupt",
    "corrupted",
    "failed",
    "failure",
    "error",
    "dropped",
    "unreadable",
    "incomplete",
}
_PRESENT_STATUSES = {
    "ok",
    "good",
    "present",
    "received",
    "complete",
    "completed",
    "acked",
    "ack",
    "accepted",
    "success",
    "read",
}


class TimelineDiagnosticError(Exception):
    """Base exception raised for invalid diagnostic inputs."""


class EvidenceBasis(str, Enum):
    """Who/which artifact supports an assertion in the timeline."""

    ORIGINAL_RECORD = "original-record"
    COLLECTION = "collection"


class EvidenceKind(str, Enum):
    """The concrete observation used to support an assertion."""

    FILE_ORDER = "file-order"
    RECORD_NUMBER = "record-number"
    CHUNK_STRUCTURE = "chunk-structure"
    EVENT_TIME = "event-time"
    RECORD_TIME = "record-header-time"
    EID_SEQUENCE = "eid-sequence"
    RECEIPT_ORDER = "receipt-order"
    RECEIPT_TIME = "receipt-time"


def _utcnow() -> _datetime.datetime:
    return _datetime.datetime.now(_datetime.timezone.utc)


def _as_utc(value: _datetime.datetime) -> _datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=_datetime.timezone.utc)
    return value.astimezone(_datetime.timezone.utc)


def format_datetime(value: Optional[_datetime.datetime]) -> Optional[str]:
    """Render an aware/naive datetime as a stable ISO-8601 UTC string."""

    if value is None:
        return None
    if value == _datetime.datetime.min or value == _datetime.datetime.max:
        return None
    value = _as_utc(value)
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_datetime(value: Any) -> Optional[_datetime.datetime]:
    """Parse common EVTX/system-time and collection-manifest timestamp forms.

    Numeric values are interpreted as Unix epoch seconds.  A Windows FILETIME
    (100 ns ticks since 1601) is recognized when the value is implausibly large
    for a Unix timestamp.
    """

    if value is None or value == "":
        return None
    if isinstance(value, _datetime.datetime):
        return _as_utc(value)
    if isinstance(value, _datetime.date):
        return _datetime.datetime(value.year, value.month, value.day, tzinfo=_datetime.timezone.utc)
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 1.0e15:
            # FILETIME uses 100 ns ticks since 1601-01-01.
            try:
                return _datetime.datetime(1601, 1, 1, tzinfo=_datetime.timezone.utc) + _datetime.timedelta(
                    microseconds=number / 10.0
                )
            except (OverflowError, ValueError):
                return None
        if number > 1.0e12:
            number /= 1000.0
        try:
            return _datetime.datetime.fromtimestamp(number, tz=_datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # Python versions before 3.11 reject more than six fractional digits.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        return _as_utc(_datetime.datetime.fromisoformat(text))
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return _as_utc(_datetime.datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, _datetime.datetime):
        return format_datetime(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.hex()
    if is_dataclass(value):
        return value.to_dict()  # type: ignore[attr-defined]
    if isinstance(value, dict):
        return {str(k): _json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(v) for v in value]
    return value


class _RecordMixin:
    def to_dict(self) -> Dict[str, Any]:
        return {field_.name: _json_value(getattr(self, field_.name)) for field_ in fields(self)}


@dataclass
class NumberingRule(_RecordMixin):
    """Explicit per-event-ID numbering rule supplied by the caller.

    ``field`` may be a record/system pseudo-field (``record_number``,
    ``EventRecordID``, ``event_id``) or a simple element path such as
    ``EventData/SequenceNumber`` or
    ``EventData/Data[@Name='SequenceNumber']``.
    """

    event_id: Union[int, str]
    field: str = "EventRecordID"
    step: int = 1
    start: Optional[int] = None
    scope: str = "event-id"

    def __post_init__(self) -> None:
        if not self.field:
            raise TimelineDiagnosticError("numbering rule field must not be empty")
        if self.step == 0:
            raise TimelineDiagnosticError("numbering rule step must not be zero")
        scope = str(self.scope).strip().lower().replace("_", "-")
        if scope in {"global", "shared", "file", "file-wide", "filewide"}:
            scope = "file"
        elif scope in {"event-id", "eventid", "per-event-id", "per-eventid", "per-eid", "eid", "local"}:
            scope = "event-id"
        elif scope in {"none", "off", "disabled"}:
            scope = "none"
        else:
            raise TimelineDiagnosticError("numbering rule scope must be 'event-id', 'file', or 'none': %r" % self.scope)
        self.scope = scope

    @property
    def eid(self) -> Union[int, str]:
        return self.event_id

    @property
    def key(self) -> str:
        return "%s:%s" % (self.event_id, self.field)

    def matches(self, event_id: Any) -> bool:
        if str(self.event_id) == "*":
            return True
        return event_id is not None and str(self.event_id) == str(event_id)


@dataclass
class CollectionReceipt(_RecordMixin):
    """One collection-side receipt/acknowledgement or block descriptor."""

    sequence: Optional[int] = None
    receipt_time: Optional[_datetime.datetime] = None
    record_number: Optional[int] = None
    event_record_id: Optional[int] = None
    event_id: Optional[Union[int, str]] = None
    file_offset: Optional[int] = None
    length: Optional[int] = None
    block_index: Optional[int] = None
    sha256: Optional[str] = None
    status: str = "received"
    kind: str = "receipt"
    index: int = 0
    record_index: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def ack_order(self) -> Optional[int]:
        return self.sequence

    @property
    def is_missing(self) -> bool:
        return str(self.status).strip().lower() in _MISSING_STATUSES

    @property
    def is_present(self) -> bool:
        return not self.is_missing


@dataclass
class CollectionManifest(_RecordMixin):
    """Normalized collection-side manifest."""

    receipts: List[CollectionReceipt] = field(default_factory=list)
    block_size: Optional[int] = None
    expected_count: Optional[int] = None
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __iter__(self) -> Iterator[CollectionReceipt]:
        return iter(self.receipts)

    def __len__(self) -> int:
        return len(self.receipts)

    def __getitem__(self, item: int) -> CollectionReceipt:
        return self.receipts[item]


@dataclass
class RecordObservation(_RecordMixin):
    """A structurally valid EVTX record in physical file order."""

    index: int
    chunk_index: int
    chunk_offset: int
    offset: int
    length: int
    record_number: Optional[int] = None
    event_record_id: Optional[int] = None
    event_id: Optional[Union[int, str]] = None
    record_time: Optional[_datetime.datetime] = None
    event_time: Optional[_datetime.datetime] = None
    time_source: Optional[str] = None
    xml_ok: bool = False
    error: Optional[str] = None
    receipt_sequence: Optional[int] = None
    receipt_time: Optional[_datetime.datetime] = None
    receipt_status: Optional[str] = None
    receipt_index: Optional[int] = None
    sequences: Dict[str, Optional[int]] = field(default_factory=dict)

    @property
    def file_order(self) -> int:
        return self.index

    @property
    def timestamp(self) -> Optional[_datetime.datetime]:
        return self.event_time if self.event_time is not None else self.record_time

    @property
    def timestamp_source(self) -> Optional[str]:
        if self.event_time is not None:
            return EvidenceKind.EVENT_TIME.value
        if self.record_time is not None:
            return EvidenceKind.RECORD_TIME.value
        return None

    def brief(self) -> Dict[str, Any]:
        return {
            "file_index": self.index,
            "record_number": self.record_number,
            "event_record_id": self.event_record_id,
            "event_id": self.event_id,
            "event_time": format_datetime(self.event_time),
            "record_time": format_datetime(self.record_time),
            "offset": self.offset,
        }


@dataclass
class Discontinuity(_RecordMixin):
    """A gap, corrupt block, or conflicting sequence in one evidence stream."""

    kind: str
    basis: str
    evidence: str
    detail: str
    severity: str = "warning"
    start_offset: Optional[int] = None
    end_offset: Optional[int] = None
    chunk_index: Optional[int] = None
    before_record_index: Optional[int] = None
    after_record_index: Optional[int] = None
    before_record_number: Optional[int] = None
    after_record_number: Optional[int] = None
    expected: Any = None
    observed: Any = None
    missing: Optional[int] = None
    event_id: Optional[Union[int, str]] = None
    receipt_sequence: Optional[int] = None
    bases: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.bases:
            self.bases = [self.basis]


@dataclass
class TimeInversion(_RecordMixin):
    """A backward jump in the timestamps carried by the original records."""

    kind: str
    before_record_index: int
    after_record_index: int
    before_record_number: Optional[int]
    after_record_number: Optional[int]
    before_time: _datetime.datetime
    after_time: _datetime.datetime
    delta_seconds: float
    rollback_seconds: float
    time_source: str
    significant: bool
    across_discontinuity: bool
    basis: str = EvidenceBasis.ORIGINAL_RECORD.value
    evidence: List[str] = field(default_factory=list)
    bases: List[str] = field(default_factory=list)
    corroborated_by_collection: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.evidence:
            self.evidence = [EvidenceKind.FILE_ORDER.value, self.time_source]
        if not self.bases:
            self.bases = [EvidenceBasis.ORIGINAL_RECORD.value]
        if not self.detail:
            self.detail = "event time moved backward by %.3f seconds in file order" % self.rollback_seconds


@dataclass
class TimelineEntry(_RecordMixin):
    """A single entry in the combined diagnostic timeline."""

    position: int
    kind: str
    basis: str
    evidence: List[str] = field(default_factory=list)
    bases: List[str] = field(default_factory=list)
    file_index: Optional[int] = None
    record_number: Optional[int] = None
    event_record_id: Optional[int] = None
    event_id: Optional[Union[int, str]] = None
    event_time: Optional[_datetime.datetime] = None
    record_time: Optional[_datetime.datetime] = None
    time_source: Optional[str] = None
    receipt_sequence: Optional[int] = None
    receipt_time: Optional[_datetime.datetime] = None
    start_offset: Optional[int] = None
    end_offset: Optional[int] = None
    missing: Optional[int] = None
    detail: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.bases:
            self.bases = [self.basis]


@dataclass
class ScanResult(_RecordMixin):
    """Result of the low-level byte scan."""

    file_size: int
    file_header: Dict[str, Any] = field(default_factory=dict)
    records: List[RecordObservation] = field(default_factory=list)
    discontinuities: List[Discontinuity] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def gaps(self) -> List[Discontinuity]:
        return self.discontinuities


@dataclass
class TimelineDiagnosis(_RecordMixin):
    """Complete offline diagnostic result."""

    source: str
    file_size: int
    records: List[RecordObservation] = field(default_factory=list)
    receipts: List[CollectionReceipt] = field(default_factory=list)
    discontinuities: List[Discontinuity] = field(default_factory=list)
    time_inversions: List[TimeInversion] = field(default_factory=list)
    clock_rollbacks: List[TimeInversion] = field(default_factory=list)
    timeline: List[TimelineEntry] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    numbering_rules: List[NumberingRule] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result["summary"] = self.summary
        return result

    def __getitem__(self, key: str) -> Any:
        if key == "summary":
            return self.summary
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    @property
    def gaps(self) -> List[Discontinuity]:
        return self.discontinuities

    @property
    def rollbacks(self) -> List[TimeInversion]:
        return self.clock_rollbacks

    @property
    def file_discontinuities(self) -> List[Discontinuity]:
        return [item for item in self.discontinuities if EvidenceBasis.ORIGINAL_RECORD.value in item.bases]

    @property
    def collection_discontinuities(self) -> List[Discontinuity]:
        return [item for item in self.discontinuities if EvidenceBasis.COLLECTION.value in item.bases]

    @property
    def original_record_timeline(self) -> List[TimelineEntry]:
        return [entry for entry in self.timeline if EvidenceBasis.ORIGINAL_RECORD.value in entry.bases]

    @property
    def collection_timeline(self) -> List[TimelineEntry]:
        return [entry for entry in self.timeline if EvidenceBasis.COLLECTION.value in entry.bases]

    @property
    def summary(self) -> Dict[str, Any]:
        original_discontinuities = [d for d in self.discontinuities if EvidenceBasis.ORIGINAL_RECORD.value in d.bases]
        collection_discontinuities = [d for d in self.discontinuities if EvidenceBasis.COLLECTION.value in d.bases]
        structural_kinds = {
            "bad-file-header",
            "file-header-integrity",
            "bad-record",
            "bad-chunk",
            "missing-record",
            "missing-records-in-chunk",
            "missing-file-block",
            "truncated-file",
            "truncated-chunk",
            "chunk-integrity",
            "record-number-regression",
        }
        return {
            "record_count": len(self.records),
            "parseable_event_time_count": sum(1 for r in self.records if r.event_time is not None),
            "receipt_count": len(self.receipts),
            "discontinuity_count": len(self.discontinuities),
            "original_record_discontinuity_count": len(original_discontinuities),
            "collection_discontinuity_count": len(collection_discontinuities),
            "has_file_discontinuity": any(d.kind in structural_kinds for d in self.discontinuities),
            "has_original_record_discontinuity": any(d.kind in structural_kinds for d in original_discontinuities),
            "has_collection_block_gap": any(
                d.kind in structural_kinds and EvidenceBasis.COLLECTION.value in d.bases for d in self.discontinuities
            ),
            "time_inversion_count": len(self.time_inversions),
            "has_timestamp_inversion": bool(self.time_inversions),
            "clock_rollback_count": len(self.clock_rollbacks),
            "has_clock_rollback": bool(self.clock_rollbacks),
            "largest_rollback_seconds": max((t.rollback_seconds for t in self.time_inversions), default=0.0),
            "timeline_entry_count": len(self.timeline),
        }


def _local_name(tag: Any) -> str:
    if not isinstance(tag, str):
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return None


def _record_number_from_value(value: Any) -> Optional[int]:
    return _int_or_none(value)


def _coerce_status(value: Any, default: str = "received") -> str:
    if value is None:
        return default
    if isinstance(value, bool):
        return "received" if value else "missing"
    text = str(value).strip().lower()
    if not text:
        return default
    if text in _MISSING_STATUSES:
        return "missing"
    if text in _PRESENT_STATUSES:
        return "received"
    return text


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    text = str(value).strip().lower()
    if text in {"", "0", "false", "no", "n", "off", "none", "null"}:
        return False
    return True


def _first(mapping: Dict[str, Any], names: Iterable[str]) -> Any:
    for name in names:
        if name in mapping and mapping[name] not in (None, ""):
            return mapping[name]
    # Case-insensitive fallback.
    lowered = {str(k).strip().lower(): v for k, v in mapping.items()}
    for name in names:
        value = lowered.get(name.strip().lower())
        if value not in (None, ""):
            return value
    return None


def _element_by_local_name(parent: ET.Element, name: str) -> Optional[ET.Element]:
    for child in list(parent):
        if _local_name(child.tag) == name:
            return child
    return None


def _attribute_by_local_name(element: ET.Element, name: str) -> Optional[str]:
    for key, value in element.attrib.items():
        if _local_name(key) == name:
            return value
    return None


def _match_path_segment(element: ET.Element, segment: str) -> Optional[ET.Element]:
    match = re.match(
        r"^([^\[]+)(?:\[@([^=]+)=['\"]?([^'\"]+)['\"]?\])?$",
        segment.strip(),
    )
    if not match:
        return None
    tag_name, attr_name, attr_value = match.groups()
    tag_name = tag_name.strip()
    if tag_name in ("", "*", "text()"):
        return element
    for child in list(element):
        if _local_name(child.tag) != tag_name:
            continue
        if attr_name is not None:
            actual = _attribute_by_local_name(child, attr_name.strip())
            if actual != attr_value:
                continue
        return child
    return None


def _extract_path_value(element: Optional[ET.Element], field_name: str) -> Any:
    if element is None:
        return None
    path = field_name.strip()
    if path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    if path.startswith("Event/"):
        path = path[len("Event/") :]
    current: Optional[ET.Element] = element
    for raw_segment in path.replace(".", "/").split("/"):
        segment = raw_segment.strip()
        if not segment:
            continue
        if segment.startswith("@"):
            if current is None:
                return None
            return _attribute_by_local_name(current, segment[1:])
        if current is None:
            return None
        current = _match_path_segment(current, segment)
        if current is None:
            return None
    if current is None:
        return None
    return current.text


def _extract_rule_value(
    root: Optional[ET.Element],
    field_name: str,
    record_number: Optional[int],
    event_record_id: Optional[int],
    event_id: Optional[Union[int, str]],
) -> Optional[int]:
    normalized = field_name.strip()
    lowered = normalized.lower()
    if lowered in {
        "record_number",
        "recordnumber",
        "record_num",
        "recordnum",
        "file_record_number",
        "evtx_record_number",
    }:
        return record_number
    if lowered in {
        "event_record_id",
        "eventrecordid",
        "event_recordid",
        "eventrecordnumber",
        "event_record_number",
    }:
        return event_record_id
    if lowered in {"event_id", "eventid", "eid"}:
        return _int_or_none(event_id)
    value = _extract_path_value(root, normalized)
    if value is None:
        return None
    return _int_or_none(value)


def _parse_filetime(value: int) -> Optional[_datetime.datetime]:
    if not value:
        return None
    try:
        return _datetime.datetime(1601, 1, 1, tzinfo=_datetime.timezone.utc) + _datetime.timedelta(
            microseconds=value / 10.0
        )
    except (OverflowError, ValueError):
        return None


def _unpack_from(fmt: str, buf: Any, offset: int) -> Optional[Tuple[Any, ...]]:
    try:
        return struct.unpack_from(fmt, buf, offset)
    except (struct.error, ValueError, TypeError):
        return None


def _looks_like_record(buf: Any, offset: int, end: int) -> bool:
    if offset < 0 or offset + MIN_RECORD_SIZE > end or offset + MIN_RECORD_SIZE > len(buf):
        return False
    header = _unpack_from("<IIQ", buf, offset)
    if header is None:
        return False
    magic, size, _record_number = header
    if magic != RECORD_MAGIC or size < MIN_RECORD_SIZE or offset + size > end:
        return False
    size2 = _unpack_from("<I", buf, offset + size - 4)
    if size2 is None or size2[0] != size:
        return False
    return True


def _find_next_record(buf: Any, start: int, end: int) -> Optional[int]:
    """Find the next plausible record, preferring EVTX's 8-byte alignment."""

    first = _align(start, 8)
    for offset in range(first, end - MIN_RECORD_SIZE + 1, 8):
        if _looks_like_record(buf, offset, end):
            return offset
    # Some damaged writers emit unaligned records.  Only use this fallback when
    # the aligned search produced nothing, to avoid excessive false positives.
    for offset in range(start + 1, end - MIN_RECORD_SIZE + 1):
        if _looks_like_record(buf, offset, end):
            return offset
    return None


def _align(offset: int, alignment: int) -> int:
    remainder = offset % alignment
    if remainder == 0:
        return offset
    return offset + (alignment - remainder)


def _chunk_is_zero(buf: Any, offset: int, length: int) -> bool:
    data = bytes(buf[offset : offset + length])
    return not data or not any(data)


def _chunk_header_dict(buf: Any, offset: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {"offset": offset}
    if offset + 0x38 > len(buf):
        result["error"] = "chunk header exceeds file"
        return result
    magic = bytes(buf[offset : offset + 8])
    result["magic"] = magic
    result["magic_ok"] = magic == CHUNK_MAGIC
    # magic (8), file first/last (8 each), log first/last (8 each),
    # header size (4), last record offset (4), next record offset (4).
    values = _unpack_from("<QQQQIII", buf, offset + 0x8)
    if values is None:
        result["error"] = "unable to unpack chunk header"
        return result
    (
        file_first,
        file_last,
        log_first,
        log_last,
        header_size,
        last_record_offset,
        next_record_offset,
    ) = values
    result.update(
        {
            "file_first_record_number": file_first,
            "file_last_record_number": file_last,
            "log_first_record_number": log_first,
            "log_last_record_number": log_last,
            "header_size": header_size,
            "last_record_offset": last_record_offset,
            "next_record_offset": next_record_offset,
        }
    )
    return result


def _file_header_dict(buf: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if len(buf) < 0x80:
        result["error"] = "file shorter than EVTX file header"
        return result
    result["magic"] = bytes(buf[0:8])
    result["magic_ok"] = result["magic"] == FILE_MAGIC
    values = _unpack_from("<QQQIHHHH", buf, 0x8)
    if values is None:
        result["error"] = "unable to unpack EVTX file header"
        return result
    (
        oldest_chunk,
        current_chunk_number,
        next_record_number,
        header_size,
        minor_version,
        major_version,
        header_chunk_size,
        chunk_count,
    ) = values
    result.update(
        {
            "oldest_chunk": oldest_chunk,
            "current_chunk_number": current_chunk_number,
            "next_record_number": next_record_number,
            "header_size": header_size,
            "minor_version": minor_version,
            "major_version": major_version,
            "header_chunk_size": header_chunk_size,
            "chunk_count": chunk_count,
        }
    )
    stored_checksum = _unpack_from("<I", buf, 0x7C)
    if stored_checksum is not None:
        import binascii

        result["checksum"] = stored_checksum[0]
        result["checksum_ok"] = (binascii.crc32(bytes(buf[0:0x78])) & 0xFFFFFFFF) == stored_checksum[0]
    return result


def _extract_event(
    record: Any,
    rules: Sequence[NumberingRule],
    record_number: Optional[int],
) -> Tuple[
    Optional[int],
    Optional[Union[int, str]],
    Optional[_datetime.datetime],
    bool,
    Optional[str],
    Dict[str, Optional[int]],
]:
    event_record_id: Optional[int] = None
    event_id: Optional[Union[int, str]] = None
    event_time: Optional[_datetime.datetime] = None
    sequences: Dict[str, Optional[int]] = {}
    root: Optional[ET.Element] = None
    error: Optional[str] = None

    try:
        root = ET.fromstring(record.xml())
    except Exception as exc:  # XML parse/rendering errors are expected on damage.
        error = "%s: %s" % (type(exc).__name__, exc)

    if root is not None:
        system = _element_by_local_name(root, "System")
        if system is not None:
            event_id_element = _element_by_local_name(system, "EventID")
            if event_id_element is not None:
                text = (event_id_element.text or "").strip()
                if text:
                    try:
                        event_id = int(text, 0)
                    except ValueError:
                        event_id = text
            event_record_id_element = _element_by_local_name(system, "EventRecordID")
            if event_record_id_element is not None:
                event_record_id = _int_or_none(event_record_id_element.text)
            time_element = _element_by_local_name(system, "TimeCreated")
            if time_element is not None:
                event_time = parse_datetime(_attribute_by_local_name(time_element, "SystemTime"))

    for rule in rules:
        # A file-wide numbering rule is a property of the whole EVTX file, so
        # read the field from every record.  Per-EID rules only read records
        # belonging to the declared event ID.
        if not rule.matches(event_id) and rule.scope != "file":
            continue
        sequences[rule.key] = _extract_rule_value(root, rule.field, record_number, event_record_id, event_id)

    return event_record_id, event_id, event_time, root is not None, error, sequences


def _scan_evtx_buffer(
    buf: Any,
    rules: Sequence[NumberingRule],
    *,
    source: str = "<memory>",
    resync: bool = True,
    include_inactive: bool = True,
) -> ScanResult:
    file_size = len(buf)
    header = _file_header_dict(buf)
    warnings: List[str] = []
    discontinuities: List[Discontinuity] = []
    records: List[RecordObservation] = []

    if not header.get("magic_ok"):
        discontinuities.append(
            Discontinuity(
                kind="bad-file-header",
                basis=EvidenceBasis.ORIGINAL_RECORD.value,
                evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                detail="EVTX file magic is not 'ElfFile\\x00'",
                start_offset=0,
                end_offset=min(file_size, 8),
            )
        )
    if header.get("error"):
        warnings.append(str(header["error"]))
    if header.get("magic_ok") and header.get("checksum_ok") is False:
        discontinuities.append(
            Discontinuity(
                kind="file-header-integrity",
                basis=EvidenceBasis.ORIGINAL_RECORD.value,
                evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                detail="EVTX file-header checksum does not verify",
                start_offset=0,
                end_offset=min(file_size, 0x80),
                expected=header.get("checksum"),
                observed="mismatch",
            )
        )

    start_offset = header.get("header_chunk_size") or FILE_HEADER_SIZE
    if start_offset <= 0 or start_offset > file_size:
        warnings.append("invalid header_chunk_size %r; falling back to 0x1000" % start_offset)
        start_offset = FILE_HEADER_SIZE

    declared_chunk_count = int(header.get("chunk_count") or 0)
    complete_chunks = max(0, (file_size - start_offset) // CHUNK_SIZE)

    # A valid EVTX chunk always starts on a 64 KiB boundary after the file
    # header.  Scanning physically present chunks (not only those declared in
    # the header) is important: a stale/dirty header must not hide damage.
    total_chunks = complete_chunks
    if not include_inactive and declared_chunk_count > 0:
        total_chunks = min(total_chunks, declared_chunk_count)
    if avail := file_size - start_offset:
        if avail % CHUNK_SIZE:
            partial_length = avail % CHUNK_SIZE
            partial_offset = file_size - partial_length
            total_chunks = complete_chunks
            if _chunk_is_zero(buf, partial_offset, partial_length):
                warnings.append("partial trailing chunk at 0x%x is all zero; treated as inactive" % partial_offset)
            else:
                discontinuities.append(
                    Discontinuity(
                        kind="truncated-file",
                        basis=EvidenceBasis.ORIGINAL_RECORD.value,
                        evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                        detail="file ends with a partial 64 KiB chunk",
                        start_offset=partial_offset,
                        end_offset=file_size,
                        chunk_index=complete_chunks,
                        missing=1,
                        expected=CHUNK_SIZE,
                        observed=partial_length,
                    )
                )

    if include_inactive and declared_chunk_count > total_chunks:
        missing = declared_chunk_count - total_chunks
        discontinuities.append(
            Discontinuity(
                kind="missing-file-block",
                basis=EvidenceBasis.ORIGINAL_RECORD.value,
                evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                detail="file header declares %d chunks but only %d are present" % (declared_chunk_count, total_chunks),
                start_offset=start_offset + total_chunks * CHUNK_SIZE,
                end_offset=start_offset + declared_chunk_count * CHUNK_SIZE,
                chunk_index=total_chunks,
                missing=missing,
                expected=declared_chunk_count,
                observed=total_chunks,
            )
        )

    for chunk_index in range(total_chunks):
        chunk_offset = start_offset + chunk_index * CHUNK_SIZE
        chunk_end = min(chunk_offset + CHUNK_SIZE, file_size)
        chunk_info = _chunk_header_dict(buf, chunk_offset)
        magic_ok = bool(chunk_info.get("magic_ok"))
        chunk_is_zero = _chunk_is_zero(buf, chunk_offset, chunk_end - chunk_offset)

        if not magic_ok:
            if chunk_is_zero and chunk_index >= declared_chunk_count:
                continue
            discontinuities.append(
                Discontinuity(
                    kind="bad-chunk",
                    basis=EvidenceBasis.ORIGINAL_RECORD.value,
                    evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                    detail="chunk magic is not 'ElfChnk\\x00'",
                    start_offset=chunk_offset,
                    end_offset=chunk_end,
                    chunk_index=chunk_index,
                    expected=CHUNK_MAGIC.decode("latin-1"),
                    observed=chunk_info.get("magic", b"").decode("latin-1", "replace"),
                )
            )
        elif chunk_index >= declared_chunk_count:
            discontinuities.append(
                Discontinuity(
                    kind="chunk-beyond-declared-count",
                    basis=EvidenceBasis.ORIGINAL_RECORD.value,
                    evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                    detail="non-empty chunk exists beyond file-header chunk_count",
                    start_offset=chunk_offset,
                    end_offset=chunk_end,
                    chunk_index=chunk_index,
                    expected=declared_chunk_count,
                    observed=chunk_index + 1,
                    severity="info",
                )
            )

        data_start = chunk_offset + CHUNK_HEADER_USABLE
        next_record_offset = int(chunk_info.get("next_record_offset") or 0)
        if next_record_offset < CHUNK_HEADER_USABLE or next_record_offset > CHUNK_SIZE:
            data_end = chunk_end
            if magic_ok:
                discontinuities.append(
                    Discontinuity(
                        kind="truncated-chunk",
                        basis=EvidenceBasis.ORIGINAL_RECORD.value,
                        evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                        detail="chunk next_record_offset is outside the 64 KiB chunk",
                        start_offset=chunk_offset,
                        end_offset=chunk_end,
                        chunk_index=chunk_index,
                        expected="0x200..0x10000",
                        observed=next_record_offset,
                    )
                )
        else:
            data_end = min(chunk_offset + next_record_offset, chunk_end)

        chunk_obj: Any = None
        try:
            from .Evtx import ChunkHeader

            chunk_obj = ChunkHeader(buf, chunk_offset)
        except Exception:
            chunk_obj = None

        if magic_ok and chunk_obj is not None:
            try:
                if not chunk_obj.verify():
                    discontinuities.append(
                        Discontinuity(
                            kind="chunk-integrity",
                            basis=EvidenceBasis.ORIGINAL_RECORD.value,
                            evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                            detail="chunk header or data checksum does not verify",
                            start_offset=chunk_offset,
                            end_offset=chunk_end,
                            chunk_index=chunk_index,
                            metadata={
                                "header_checksum_ok": chunk_obj.calculate_header_checksum()
                                == chunk_obj.header_checksum(),
                                "data_checksum_ok": chunk_obj.calculate_data_checksum() == chunk_obj.data_checksum(),
                            },
                        )
                    )
            except Exception as exc:
                warnings.append("chunk %d checksum check failed: %s" % (chunk_index, exc))

        chunk_records: List[RecordObservation] = []
        offset = data_start
        while offset + MIN_RECORD_SIZE <= data_end:
            if _looks_like_record(buf, offset, data_end):
                try:
                    record = None
                    if chunk_obj is not None:
                        from .Evtx import Record

                        record = Record(buf, offset, chunk_obj)
                    header_values = _unpack_from("<IIQ", buf, offset)
                    if header_values is None:
                        raise ValueError("unable to unpack record header")
                    _magic, size, record_number = header_values
                    filetime = _unpack_from("<Q", buf, offset + 0x10)
                    record_time = _parse_filetime(filetime[0]) if filetime is not None else None

                    event_record_id = None
                    event_id = None
                    event_time = None
                    xml_ok = False
                    error = "record XML unavailable because chunk header is unreadable"
                    sequences: Dict[str, Optional[int]] = {}
                    if record is not None:
                        (
                            event_record_id,
                            event_id,
                            event_time,
                            xml_ok,
                            error,
                            sequences,
                        ) = _extract_event(record, rules, record_number)

                    observation = RecordObservation(
                        index=len(records),
                        chunk_index=chunk_index,
                        chunk_offset=chunk_offset,
                        offset=offset,
                        length=size,
                        record_number=record_number,
                        event_record_id=event_record_id,
                        event_id=event_id,
                        record_time=record_time,
                        event_time=event_time,
                        time_source=(
                            EvidenceKind.EVENT_TIME.value
                            if event_time is not None
                            else EvidenceKind.RECORD_TIME.value if record_time is not None else None
                        ),
                        xml_ok=xml_ok,
                        error=error,
                        sequences=sequences,
                    )
                    records.append(observation)
                    chunk_records.append(observation)
                    offset += size
                    continue
                except Exception as exc:
                    warnings.append("record at 0x%x could not be parsed: %s" % (offset, exc))

            resync_at = _find_next_record(buf, offset + 8, data_end) if resync else None
            gap_end = resync_at if resync_at is not None else data_end
            if gap_end <= offset:
                gap_end = min(offset + 8, data_end)
            non_zero = not _chunk_is_zero(buf, offset, gap_end - offset)
            if non_zero:
                discontinuities.append(
                    Discontinuity(
                        kind="bad-record",
                        basis=EvidenceBasis.ORIGINAL_RECORD.value,
                        evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                        detail=(
                            "unparseable record region; resynchronized at 0x%x" % resync_at
                            if resync_at is not None
                            else "unparseable record region; no later record found in chunk"
                        ),
                        start_offset=offset,
                        end_offset=gap_end,
                        chunk_index=chunk_index,
                        missing=1,
                        metadata={"resynchronized": resync_at is not None},
                    )
                )
            else:
                discontinuities.append(
                    Discontinuity(
                        kind="empty-record-region",
                        basis=EvidenceBasis.ORIGINAL_RECORD.value,
                        evidence=EvidenceKind.CHUNK_STRUCTURE.value,
                        detail="zero-filled region inside allocated record area",
                        start_offset=offset,
                        end_offset=gap_end,
                        chunk_index=chunk_index,
                        severity="info",
                    )
                )
            if resync_at is None:
                break
            offset = resync_at

        file_first = chunk_info.get("file_first_record_number")
        file_last = chunk_info.get("file_last_record_number")
        if (
            magic_ok
            and isinstance(file_first, int)
            and isinstance(file_last, int)
            and file_last >= file_first
            and (file_last > 0 or bool(chunk_records))
        ):
            expected_count = file_last - file_first + 1
            if expected_count > len(chunk_records):
                actual_numbers = [r.record_number for r in chunk_records if r.record_number is not None]
                discontinuities.append(
                    Discontinuity(
                        kind="missing-records-in-chunk",
                        basis=EvidenceBasis.ORIGINAL_RECORD.value,
                        evidence=EvidenceKind.RECORD_NUMBER.value,
                        detail="chunk record-number range contains more records than were parsed",
                        start_offset=chunk_offset + CHUNK_HEADER_USABLE,
                        end_offset=data_end,
                        chunk_index=chunk_index,
                        before_record_number=min(actual_numbers) if actual_numbers else None,
                        after_record_number=max(actual_numbers) if actual_numbers else None,
                        expected=expected_count,
                        observed=len(chunk_records),
                        missing=expected_count - len(chunk_records),
                    )
                )

    # Record-number ordering constraints are separate from physical order:
    # physical order proves "this record was written before that one", while the
    # record number proves whether records were omitted from the file.
    for previous, current in zip(records, records[1:]):
        previous_number = previous.record_number
        current_number = current.record_number
        if previous_number is None or current_number is None:
            continue
        if current_number > previous_number + 1:
            missing = current_number - previous_number - 1
            discontinuities.append(
                Discontinuity(
                    kind="missing-record",
                    basis=EvidenceBasis.ORIGINAL_RECORD.value,
                    evidence=EvidenceKind.RECORD_NUMBER.value,
                    detail="record numbers skipped between physical neighbours",
                    start_offset=previous.offset + previous.length,
                    end_offset=current.offset,
                    before_record_index=previous.index,
                    after_record_index=current.index,
                    before_record_number=previous_number,
                    after_record_number=current_number,
                    expected=previous_number + 1,
                    observed=current_number,
                    missing=missing,
                )
            )
        elif current_number <= previous_number and current.index != previous.index:
            discontinuities.append(
                Discontinuity(
                    kind="record-number-regression",
                    basis=EvidenceBasis.ORIGINAL_RECORD.value,
                    evidence=EvidenceKind.RECORD_NUMBER.value,
                    detail="record number did not increase in physical file order",
                    start_offset=previous.offset,
                    end_offset=current.offset + current.length,
                    before_record_index=previous.index,
                    after_record_index=current.index,
                    before_record_number=previous_number,
                    after_record_number=current_number,
                    expected=previous_number + 1,
                    observed=current_number,
                )
            )

    for discontinuity in discontinuities:
        if discontinuity.before_record_index is None and discontinuity.after_record_index is None:
            if discontinuity.start_offset is not None:
                before = [r for r in records if r.offset + r.length <= discontinuity.start_offset]
                after = [r for r in records if r.offset >= (discontinuity.end_offset or discontinuity.start_offset)]
                if before:
                    discontinuity.before_record_index = before[-1].index
                    discontinuity.before_record_number = before[-1].record_number
                if after:
                    discontinuity.after_record_index = after[0].index
                    discontinuity.after_record_number = after[0].record_number

    return ScanResult(
        file_size=file_size,
        file_header=header,
        records=records,
        discontinuities=discontinuities,
        warnings=warnings,
    )


def _source_label(source: Any) -> str:
    if isinstance(source, str):
        return source
    if hasattr(source, "__fspath__"):
        return str(source)
    name = getattr(source, "name", None)
    if name:
        return str(name)
    return "<memory>"


@contextlib.contextmanager
def _as_buffer(source: Any) -> Iterator[Any]:
    if isinstance(source, mmap.mmap):
        yield source
        return
    if isinstance(source, memoryview):
        yield source
        return
    if isinstance(source, bytearray):
        yield bytes(source)
        return
    if isinstance(source, bytes):
        yield source
        return
    if hasattr(source, "read"):
        data = source.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        yield data
        return

    path = str(source)
    with open(path, "rb") as handle:
        if os_fstat_size(handle) == 0:
            raise TimelineDiagnosticError("cannot diagnose an empty EVTX file: %s" % path)
        with contextlib.closing(mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            yield buf


def os_fstat_size(handle: Any) -> int:
    try:
        import os

        return os.fstat(handle.fileno()).st_size
    except (OSError, AttributeError):
        position = handle.tell()
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(position)
        return size


def scan_evtx(
    source: Any,
    numbering_rules: Optional[Any] = None,
    *,
    resync: bool = True,
    include_inactive: bool = True,
) -> ScanResult:
    """Scan EVTX bytes/path and return records plus structural discontinuities."""

    rules = parse_numbering_rules(numbering_rules)
    with _as_buffer(source) as buf:
        return _scan_evtx_buffer(
            buf,
            rules,
            source=_source_label(source),
            resync=resync,
            include_inactive=include_inactive,
        )


def _numbering_rule_from_mapping(mapping: Dict[str, Any]) -> NumberingRule:
    data = dict(mapping)
    event_id = data.pop("event_id", data.pop("eid", None))
    if event_id is None:
        raise TimelineDiagnosticError("numbering rule object needs event_id/eid")
    field_name = data.pop("field", data.pop("path", "EventRecordID"))
    return NumberingRule(
        event_id=event_id,
        field=str(field_name),
        step=int(data.pop("step", 1)),
        start=_int_or_none(data.pop("start", None)),
        scope=str(
            data.pop(
                "scope",
                data.pop("mode", data.pop("numbering", data.pop("type", "event-id"))),
            )
        ),
    )


def parse_numbering_rules(value: Optional[Any]) -> List[NumberingRule]:
    # The caller must state how each EventID is numbered.  Nothing is inferred
    # from the presence of an EventRecordID or a similarly named field.

    if value is None:
        return []
    if isinstance(value, NumberingRule):
        return [value]
    if hasattr(value, "__fspath__"):
        value = str(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith(("{", "[")):
            return parse_numbering_rules(json.loads(stripped))
        if stripped.endswith(".json") or _path_exists(stripped):
            with open(stripped, "r", encoding="utf-8") as handle:
                return parse_numbering_rules(json.load(handle))
        rules: List[NumberingRule] = []
        for item in re.split(r";|,(?![A-Za-z_-]+=)", stripped):
            item = item.strip()
            if item:
                rules.append(_parse_rule_string(item))
        return rules
    if isinstance(value, dict):
        if "event_id" in value or "eid" in value:
            return [_numbering_rule_from_mapping(value)]
        if "rules" in value:
            return parse_numbering_rules(value["rules"])
        rules = []
        for event_id, spec in value.items():
            if isinstance(spec, str):
                rules.append(NumberingRule(event_id=event_id, field=spec))
            elif isinstance(spec, dict):
                spec = dict(spec)
                spec.setdefault("event_id", event_id)
                rules.append(_numbering_rule_from_mapping(spec))
            else:
                raise TimelineDiagnosticError("invalid numbering rule for EID %r" % event_id)
        return rules
    if isinstance(value, (list, tuple, set)):
        rules = []
        for item in value:
            if isinstance(item, NumberingRule):
                rules.append(item)
            elif isinstance(item, str):
                rules.append(_parse_rule_string(item))
            elif isinstance(item, dict):
                if "event_id" in item or "eid" in item:
                    rules.append(_numbering_rule_from_mapping(item))
                else:
                    rules.extend(parse_numbering_rules(item))
            else:
                raise TimelineDiagnosticError("invalid numbering rule: %r" % (item,))
        return rules
    raise TimelineDiagnosticError("invalid numbering rules: %r" % (value,))


def _path_exists(value: str) -> bool:
    try:
        import os

        return os.path.exists(value)
    except (OSError, ValueError):
        return False


def _parse_rule_string(value: str) -> NumberingRule:
    if "=" in value:
        event_id, field_name = value.split("=", 1)
    elif re.match(r"^\d+:", value):
        event_id, field_name = value.split(":", 1)
    else:
        raise TimelineDiagnosticError("numbering rule must be EID=FIELD (for example 4624=EventRecordID): %s" % value)
    event_id = event_id.strip()
    field_name = field_name.strip()
    step = 1
    start = None
    scope = "event-id"
    match = re.search(r"(?:,|;|\s|@)step=(-?\d+)$", field_name)
    if match:
        step = int(match.group(1))
        field_name = field_name[: match.start()].strip()
    match = re.search(r"(?:,|;|\s|@)start=(-?\d+)$", field_name)
    if match:
        start = int(match.group(1))
        field_name = field_name[: match.start()].strip()
    match = re.search(r"(?:,|;|\s|@)scope=([A-Za-z_-]+)$", field_name)
    if match:
        scope = match.group(1)
        field_name = field_name[: match.start()].strip()
    if not event_id or not field_name:
        raise TimelineDiagnosticError("numbering rule must contain both EID and field: %s" % value)
    return NumberingRule(event_id=event_id, field=field_name, step=step, start=start, scope=scope)


def _normalize_entry(entry: Any, index: int, kind: str, block_size: Optional[int]) -> CollectionReceipt:
    if isinstance(entry, CollectionReceipt):
        if entry.index is None:
            entry.index = index
        return entry
    if not isinstance(entry, dict):
        if isinstance(entry, int):
            if kind == "block":
                return CollectionReceipt(
                    sequence=index,
                    block_index=entry,
                    kind="block",
                    status="missing",
                    index=index,
                    raw={"value": entry},
                )
            return CollectionReceipt(
                sequence=entry,
                status="received",
                kind="receipt",
                index=index,
                raw={"value": entry},
            )
        raise TimelineDiagnosticError("invalid collection entry: %r" % (entry,))

    raw = dict(entry)
    status_value = _first(
        raw,
        (
            "status",
            "ack",
            "acknowledged",
            "result",
            "state",
            "received",
            "present",
            "complete",
        ),
    )
    missing_flag = _first(raw, ("missing", "lost", "dropped", "absent", "unreadable"))
    if missing_flag is not None:
        status = "missing" if _truthy(missing_flag) else "received"
    else:
        status = _coerce_status(status_value, "received")

    sequence = _int_or_none(
        _first(
            raw,
            (
                "receipt_sequence",
                "receipt_seq",
                "ack_sequence",
                "ack_seq",
                "ack_order",
                "receipt_order",
                "receipt_no",
                "ack_no",
                "sequence",
                "seq",
                "seq_no",
                "seqno",
                "order",
                "ordinal",
                "position",
            ),
        )
    )
    block_index = _int_or_none(
        _first(
            raw,
            (
                "block_index",
                "block",
                "block_no",
                "block_num",
                "block_id",
                "chunk_index",
                "chunk",
                "chunk_no",
                "chunk_num",
                "file_block",
            ),
        )
    )
    if block_index is None and kind == "block" and "index" in raw:
        block_index = _int_or_none(raw.get("index"))
    record_number = _record_number_from_value(
        _first(
            raw,
            (
                "record_number",
                "record_num",
                "recordnumber",
                "record_id",
                "file_record_number",
            ),
        )
    )
    event_record_id = _record_number_from_value(
        _first(
            raw,
            (
                "event_record_id",
                "event_recordid",
                "event_record_number",
                "event_record_num",
                "EventRecordID",
            ),
        )
    )
    event_id = _first(raw, ("event_id", "eventid", "eid", "EventID"))
    file_offset = _int_or_none(
        _first(raw, ("file_offset", "absolute_offset", "offset", "start_offset", "block_offset"))
    )
    length = _int_or_none(_first(raw, ("length", "size", "block_length", "byte_length")))
    receipt_time = parse_datetime(
        _first(
            raw,
            (
                "receipt_time",
                "receipt_timestamp",
                "received_at",
                "received_ts",
                "ack_time",
                "ack_ts",
                "acknowledged_at",
                "collected_at",
                "collected_ts",
                "collection_time",
                "timestamp",
                "time",
            ),
        )
    )
    sha256 = _first(raw, ("sha256", "sha-256", "hash", "digest"))

    if "index" in raw and sequence is None and block_index is None:
        sequence = _int_or_none(raw.get("index"))
    if sequence is None:
        sequence = index
    if file_offset is None and block_index is not None and block_size:
        file_offset = block_index * block_size
    if block_index is None and file_offset is not None and block_size and file_offset % block_size == 0:
        block_index = file_offset // block_size
    entry_kind = kind
    if block_index is not None and record_number is None and event_record_id is None:
        entry_kind = "block"

    return CollectionReceipt(
        sequence=sequence,
        receipt_time=receipt_time,
        record_number=record_number,
        event_record_id=event_record_id,
        event_id=event_id,
        file_offset=file_offset,
        length=length,
        block_index=block_index,
        sha256=str(sha256) if sha256 is not None else None,
        status=status,
        kind=entry_kind,
        index=index,
        raw=raw,
    )


def load_collection(source: Optional[Any]) -> CollectionManifest:
    """Load a collection receipt/acknowledgement manifest.

    JSON and CSV are supported.  The top-level JSON object may use
    ``receipts``, ``acks``, ``records``, ``blocks``, ``entries``, or
    ``collection`` as its entry list.  It may also contain ``missing_blocks``
    (a list of block indexes) and ``block_size``.
    """

    if source is None:
        return CollectionManifest()
    if isinstance(source, CollectionManifest):
        return source
    if isinstance(source, CollectionReceipt):
        return CollectionManifest(receipts=[source])
    if hasattr(source, "__fspath__"):
        return load_collection(str(source))
    if isinstance(source, (list, tuple)):
        return CollectionManifest(receipts=_normalize_entries(source, "receipt", None))
    if isinstance(source, dict):
        return _manifest_from_dict(source)
    if isinstance(source, str):
        text = source.strip()
        if not text:
            return CollectionManifest()
        if text.startswith(("{", "[")):
            return load_collection(json.loads(text))
        path = source
        if not _path_exists(path):
            raise TimelineDiagnosticError("collection manifest does not exist: %s" % source)
        suffix = path.lower().rsplit(".", 1)[-1] if "." in path else ""
        if suffix in {"json"}:
            with open(path, "r", encoding="utf-8") as handle:
                return load_collection(json.load(handle))
        if suffix in {"jsonl", "ndjson"}:
            entries = []
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
            return CollectionManifest(receipts=_normalize_entries(entries, "receipt", None), source=path)
        with open(path, "r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            entries = [dict(row) for row in reader]
        return CollectionManifest(receipts=_normalize_entries(entries, "receipt", None), source=path)
    raise TimelineDiagnosticError("invalid collection manifest: %r" % (source,))


def _manifest_from_dict(data: Dict[str, Any]) -> CollectionManifest:
    metadata = {
        k: v for k, v in data.items() if k not in {"receipts", "acks", "records", "blocks", "entries", "collection"}
    }
    entries: Any = None
    kind = "receipt"
    for key in ("receipts", "acks", "records", "blocks", "entries", "collection"):
        if key in data and isinstance(data[key], (list, tuple)):
            entries = data[key]
            kind = "block" if key == "blocks" else "receipt"
            break
    block_size = _int_or_none(_first(data, ("block_size", "block_size_bytes", "blockBytes")))
    expected_count = _int_or_none(_first(data, ("expected_count", "total_count", "record_count")))
    if entries is None:
        # A single receipt object is also accepted, but a metadata-only
        # manifest (for example one that only lists missing_blocks) must not
        # turn its metadata into a bogus received receipt.
        entry_hints = {
            "receipt_sequence",
            "receipt_seq",
            "ack_sequence",
            "ack_seq",
            "sequence",
            "seq",
            "record_number",
            "record_num",
            "event_record_id",
            "event_recordid",
            "block_index",
            "block",
            "file_offset",
            "offset",
            "status",
            "received",
            "missing",
            "lost",
            "sha256",
            "length",
            "size",
        }
        entries = [data] if entry_hints.intersection(data.keys()) else []
    receipts = _normalize_entries(entries, kind, block_size)
    missing_blocks = _first(data, ("missing_blocks", "lost_blocks", "dropped_blocks"))
    if missing_blocks:
        if not isinstance(missing_blocks, (list, tuple, set)):
            missing_blocks = [missing_blocks]
        for item in missing_blocks:
            if isinstance(item, dict):
                entry = dict(item)
                entry.setdefault("status", "missing")
                receipts.append(_normalize_entry(entry, len(receipts), "block", block_size))
                continue
            block_index = _int_or_none(item)
            if block_index is None:
                continue
            receipts.append(
                CollectionReceipt(
                    sequence=None,
                    file_offset=block_index * block_size if block_size else None,
                    block_index=block_index,
                    status="missing",
                    kind="block",
                    index=len(receipts),
                    raw={"missing_blocks": item},
                )
            )
    return CollectionManifest(
        receipts=receipts,
        block_size=block_size,
        expected_count=expected_count,
        source=str(data.get("source")) if data.get("source") else None,
        metadata=metadata,
    )


def _normalize_entries(entries: Iterable[Any], kind: str, block_size: Optional[int]) -> List[CollectionReceipt]:
    normalized = []
    for index, entry in enumerate(entries):
        normalized.append(_normalize_entry(entry, index, kind, block_size))
    return normalized


parse_collection = load_collection


def _map_receipts(records: Sequence[RecordObservation], manifest: CollectionManifest) -> None:
    by_record_number: Dict[int, RecordObservation] = {}
    by_event_record_id: Dict[int, RecordObservation] = {}
    for record in records:
        if record.record_number is not None:
            by_record_number.setdefault(record.record_number, record)
        if record.event_record_id is not None:
            by_event_record_id.setdefault(record.event_record_id, record)

    unmapped: List[CollectionReceipt] = []
    for receipt in manifest.receipts:
        record = None
        if receipt.record_number is not None:
            record = by_record_number.get(receipt.record_number)
        if record is None and receipt.event_record_id is not None:
            record = by_event_record_id.get(receipt.event_record_id)
        if record is None and receipt.file_offset is not None:
            for candidate in records:
                if candidate.offset <= receipt.file_offset < candidate.offset + candidate.length:
                    record = candidate
                    break
        if record is not None:
            receipt.record_index = record.index
            record.receipt_sequence = receipt.sequence
            record.receipt_time = receipt.receipt_time
            record.receipt_status = receipt.status
            record.receipt_index = receipt.index
        else:
            unmapped.append(receipt)

    # Positional fallback is deliberately conservative: only when the manifest
    # is record-shaped and has exactly one entry per record.
    positional = [
        receipt
        for receipt in unmapped
        if receipt.kind != "block"
        and receipt.status != "missing"
        and receipt.record_number is None
        and receipt.event_record_id is None
        and receipt.file_offset is None
        and receipt.block_index is None
    ]
    if len(positional) == len(records) and positional:
        for receipt, record in zip(positional, records):
            receipt.record_index = record.index
            record.receipt_sequence = receipt.sequence
            record.receipt_time = receipt.receipt_time
            record.receipt_status = receipt.status
            record.receipt_index = receipt.index


def _receipt_order_conflicts(
    receipts: Sequence[CollectionReceipt],
) -> List[Tuple[CollectionReceipt, CollectionReceipt]]:
    mapped = [r for r in receipts if r.record_index is not None and r.sequence is not None]
    mapped.sort(key=lambda r: (r.sequence, r.index))
    conflicts = []
    for previous, current in zip(mapped, mapped[1:]):
        if previous.record_index is None or current.record_index is None:
            continue
        if current.record_index < previous.record_index:
            conflicts.append((previous, current))
    return conflicts


def _discontinuity_position(discontinuity: Discontinuity, records: Sequence[RecordObservation]) -> Tuple[int, int]:
    """Return (before_index, after_index) used to place a gap in the timeline."""

    if discontinuity.before_record_index is not None or discontinuity.after_record_index is not None:
        before = discontinuity.before_record_index if discontinuity.before_record_index is not None else -1
        after = discontinuity.after_record_index if discontinuity.after_record_index is not None else len(records)
        return before, after
    start = discontinuity.start_offset
    if start is not None:
        before = -1
        after = len(records)
        for record in records:
            if record.offset + record.length <= start:
                before = record.index
            elif record.offset >= (discontinuity.end_offset or start):
                after = record.index
                break
        return before, after
    return -1, len(records)


def _receipt_gap_offsets(receipt: CollectionReceipt, block_size: Optional[int]) -> Tuple[Optional[int], Optional[int]]:
    start = receipt.file_offset
    length = receipt.length
    if start is None and receipt.block_index is not None and block_size:
        start = receipt.block_index * block_size
    if length is None and block_size:
        length = block_size
    if start is None:
        return None, None
    return start, start + (length or 0)


def _analyze_collection(
    records: Sequence[RecordObservation],
    manifest: CollectionManifest,
    receipt_step: Optional[int],
) -> List[Discontinuity]:
    discontinuities: List[Discontinuity] = []
    if not manifest.receipts:
        return discontinuities

    _map_receipts(records, manifest)

    for receipt in manifest.receipts:
        if not receipt.is_missing:
            continue
        start, end = _receipt_gap_offsets(receipt, manifest.block_size)
        if receipt.kind == "block":
            kind = "missing-file-block"
        elif receipt.record_index is not None:
            kind = "collection-record-missing"
        else:
            kind = "collection-entry-missing"
        detail_bits = ["collector marked entry as %s" % receipt.status]
        if receipt.block_index is not None:
            detail_bits.append("block %s" % receipt.block_index)
        if receipt.record_number is not None:
            detail_bits.append("record %s" % receipt.record_number)
        discontinuities.append(
            Discontinuity(
                kind=kind,
                basis=EvidenceBasis.COLLECTION.value,
                evidence=EvidenceKind.RECEIPT_ORDER.value,
                detail="; ".join(detail_bits),
                start_offset=start,
                end_offset=end,
                before_record_index=(receipt.record_index - 1) if receipt.record_index else None,
                after_record_index=receipt.record_index,
                after_record_number=receipt.record_number,
                receipt_sequence=receipt.sequence,
                missing=1,
                metadata={
                    "receipt_index": receipt.index,
                    "block_index": receipt.block_index,
                    "collection_block_missing": receipt.kind == "block",
                },
            )
        )

    if receipt_step:
        # Explicitly missing entries still occupy a receipt position; a gap
        # is only the range for which no receipt descriptor exists at all.
        sequences = sorted({r.sequence for r in manifest.receipts if r.sequence is not None})
        for previous, current in zip(sequences, sequences[1:]):
            if current - previous > receipt_step:
                missing = (current - previous) // receipt_step - 1
                if missing <= 0:
                    continue
                discontinuities.append(
                    Discontinuity(
                        kind="collection-receipt-gap",
                        basis=EvidenceBasis.COLLECTION.value,
                        evidence=EvidenceKind.RECEIPT_ORDER.value,
                        detail="collection receipt sequence skipped %d entries" % missing,
                        expected=previous + receipt_step,
                        observed=current,
                        missing=missing,
                        receipt_sequence=current,
                        metadata={"previous_sequence": previous},
                    )
                )

    if manifest.expected_count is not None:
        present = sum(1 for r in manifest.receipts if not r.is_missing)
        if present < manifest.expected_count:
            discontinuities.append(
                Discontinuity(
                    kind="collection-shortfall",
                    basis=EvidenceBasis.COLLECTION.value,
                    evidence=EvidenceKind.RECEIPT_ORDER.value,
                    detail="collection manifest received fewer entries than declared",
                    expected=manifest.expected_count,
                    observed=present,
                    missing=manifest.expected_count - present,
                )
            )

    for previous, current in _receipt_order_conflicts(manifest.receipts):
        discontinuities.append(
            Discontinuity(
                kind="collection-order-conflict",
                basis=EvidenceBasis.COLLECTION.value,
                evidence=EvidenceKind.RECEIPT_ORDER.value,
                detail="receipt sequence disagrees with original record order",
                before_record_index=previous.record_index,
                after_record_index=current.record_index,
                expected=None,
                observed=(previous.sequence, current.sequence),
                bases=[EvidenceBasis.COLLECTION.value, EvidenceBasis.ORIGINAL_RECORD.value],
                metadata={
                    "previous_receipt_sequence": previous.sequence,
                    "current_receipt_sequence": current.sequence,
                },
            )
        )

    receipt_times = sorted(
        [r for r in manifest.receipts if r.receipt_time is not None and r.sequence is not None],
        key=lambda r: (r.sequence, r.index),
    )
    for previous, current in zip(receipt_times, receipt_times[1:]):
        if previous.receipt_time is None or current.receipt_time is None:
            continue
        if current.receipt_time < previous.receipt_time:
            delta = (current.receipt_time - previous.receipt_time).total_seconds()
            discontinuities.append(
                Discontinuity(
                    kind="collection-time-inversion",
                    basis=EvidenceBasis.COLLECTION.value,
                    evidence=EvidenceKind.RECEIPT_TIME.value,
                    detail="collection receipt time moved backward in receipt order",
                    receipt_sequence=current.sequence,
                    observed=delta,
                    metadata={
                        "previous_sequence": previous.sequence,
                        "previous_time": format_datetime(previous.receipt_time),
                        "current_time": format_datetime(current.receipt_time),
                    },
                )
            )
    return discontinuities


def _analyze_sequence_values(
    values: Sequence[Tuple[RecordObservation, int]],
    *,
    event_id: Union[int, str, List[Any]],
    field_name: str,
    step: int,
    start: Optional[int],
    scope: str,
) -> Tuple[List[Discontinuity], Optional[Dict[str, Any]]]:
    if not values:
        return [], None

    constraint = {
        "event_id": event_id,
        "field": field_name,
        "step": step,
        "scope": scope,
        "basis": EvidenceBasis.ORIGINAL_RECORD.value,
        "evidence": EvidenceKind.EID_SEQUENCE.value,
        "values": [
            {"file_index": record.index, "record_number": record.record_number, "sequence": value}
            for record, value in values
        ],
    }
    discontinuities: List[Discontinuity] = []
    scope_text = "file-wide" if scope == "file" else "per-EID"

    if start is not None and values[0][1] != start:
        first_record, first_value = values[0]
        if step > 0 and first_value > start:
            missing = (first_value - start) // step
        elif step < 0 and first_value < start:
            missing = (start - first_value) // abs(step)
        else:
            missing = 0
        discontinuities.append(
            Discontinuity(
                kind="event-sequence-start",
                basis=EvidenceBasis.ORIGINAL_RECORD.value,
                evidence=EvidenceKind.EID_SEQUENCE.value,
                detail="first %s sequence does not equal the caller-declared start" % scope_text,
                before_record_index=first_record.index - 1,
                after_record_index=first_record.index,
                after_record_number=first_record.record_number,
                expected=start,
                observed=first_value,
                missing=missing or None,
                event_id=event_id,
                metadata={"field": field_name, "scope": scope},
            )
        )

    for previous, current in zip(values, values[1:]):
        previous_record, previous_value = previous
        current_record, current_value = current
        expected = previous_value + step
        if current_value == expected:
            continue
        difference = current_value - previous_value
        if (step > 0 and difference > step) or (step < 0 and difference < step):
            missing = abs((difference - step) // step)
            if missing <= 0:
                missing = 1
            kind = "missing-event-sequence"
            detail = "caller-declared %s numbering skipped values" % scope_text
        else:
            missing = None
            kind = "event-sequence-regression"
            detail = "caller-declared %s numbering moved backward" % scope_text
        discontinuities.append(
            Discontinuity(
                kind=kind,
                basis=EvidenceBasis.ORIGINAL_RECORD.value,
                evidence=EvidenceKind.EID_SEQUENCE.value,
                detail=detail,
                before_record_index=previous_record.index,
                after_record_index=current_record.index,
                before_record_number=previous_record.record_number,
                after_record_number=current_record.record_number,
                expected=expected,
                observed=current_value,
                missing=missing,
                event_id=event_id,
                metadata={
                    "field": field_name,
                    "scope": scope,
                    "previous_sequence": previous_value,
                    "step": step,
                },
            )
        )
    return discontinuities, constraint


def _analyze_numbering(
    records: Sequence[RecordObservation], rules: Sequence[NumberingRule]
) -> Tuple[List[Discontinuity], List[Dict[str, Any]]]:
    """Apply only the numbering rules explicitly supplied by the caller.

    ``scope="event-id"`` treats each EID as an independent counter.
    ``scope="file"`` treats the field as one file-wide counter shared by all
    records, regardless of their EventID.  ``scope="none"`` emits the observed
    values as a constraint but performs no gap inference.
    """

    discontinuities: List[Discontinuity] = []
    constraints: List[Dict[str, Any]] = []
    handled_file_rules: set[Tuple[str, int, Optional[int]]] = set()

    for rule in rules:
        if rule.scope == "file":
            group_key = (rule.field, rule.step, rule.start)
            if group_key in handled_file_rules:
                continue
            handled_file_rules.add(group_key)
            group_rules = [
                candidate
                for candidate in rules
                if candidate.scope == "file" and (candidate.field, candidate.step, candidate.start) == group_key
            ]
            values = []
            for record in records:
                for candidate in group_rules:
                    value = record.sequences.get(candidate.key)
                    if value is not None:
                        values.append((record, value))
                        break
            event_ids = sorted({str(candidate.event_id) for candidate in group_rules})
            event_label: Union[int, str, List[Any]] = event_ids[0] if len(event_ids) == 1 else event_ids
            found, constraint = _analyze_sequence_values(
                values,
                event_id=event_label,
                field_name=rule.field,
                step=rule.step,
                start=rule.start,
                scope="file",
            )
            discontinuities.extend(found)
            if constraint is not None:
                constraints.append(constraint)
            continue

        values = []
        for record in records:
            if not rule.matches(record.event_id):
                continue
            value = record.sequences.get(rule.key)
            if value is None:
                continue
            values.append((record, value))
        if rule.scope == "none":
            found, constraint = _analyze_sequence_values(
                values,
                event_id=rule.event_id,
                field_name=rule.field,
                step=rule.step,
                start=None,
                scope="none",
            )
            # Constraint only: no gap inference when the caller disables it.
            if constraint is not None:
                constraints.append(constraint)
            continue
        if str(rule.event_id) == "*":
            # A wildcard per-EID rule still means independent counters.  Split
            # the stream by the record EventID instead of treating it as one
            # file-wide sequence.
            groups: Dict[str, List[Tuple[RecordObservation, int]]] = {}
            for record, value in values:
                groups.setdefault(str(record.event_id), []).append((record, value))
            for event_id_text, group_values in sorted(groups.items(), key=lambda item: item[0]):
                event_id_value: Union[int, str] = (
                    int(event_id_text) if event_id_text.lstrip("-").isdigit() else event_id_text
                )
                found, constraint = _analyze_sequence_values(
                    group_values,
                    event_id=event_id_value,
                    field_name=rule.field,
                    step=rule.step,
                    start=rule.start,
                    scope="event-id",
                )
                discontinuities.extend(found)
                if constraint is not None:
                    constraints.append(constraint)
            continue
        found, constraint = _analyze_sequence_values(
            values,
            event_id=rule.event_id,
            field_name=rule.field,
            step=rule.step,
            start=rule.start,
            scope="event-id",
        )
        discontinuities.extend(found)
        if constraint is not None:
            constraints.append(constraint)
    return discontinuities, constraints


def _discontinuity_between(
    previous: RecordObservation,
    current: RecordObservation,
    discontinuities: Sequence[Discontinuity],
) -> bool:
    for discontinuity in discontinuities:
        if discontinuity.basis != EvidenceBasis.ORIGINAL_RECORD.value:
            continue
        if discontinuity.kind in {
            "empty-record-region",
            "chunk-integrity",
            "chunk-beyond-declared-count",
        }:
            continue
        start = discontinuity.start_offset
        end = discontinuity.end_offset
        if start is not None and previous.offset + previous.length <= start:
            if end is None or end <= current.offset:
                return True
        if previous.record_number is not None and current.record_number is not None:
            expected = discontinuity.expected
            observed = discontinuity.observed
            if (
                discontinuity.kind == "missing-record"
                and expected == previous.record_number + 1
                and observed == current.record_number
            ):
                return True
    return False


def _collection_corroborates(
    previous: RecordObservation, current: RecordObservation, records: Sequence[RecordObservation]
) -> bool:
    if previous.receipt_sequence is None or current.receipt_sequence is None:
        return False
    if current.receipt_sequence <= previous.receipt_sequence:
        return False
    if previous.receipt_time is not None and current.receipt_time is not None:
        if current.receipt_time < previous.receipt_time:
            return False
    return True


def _detect_time_inversions(
    records: Sequence[RecordObservation],
    discontinuities: Sequence[Discontinuity],
    *,
    min_rollback_seconds: float,
) -> List[TimeInversion]:
    inversions: List[TimeInversion] = []
    seen: set[Tuple[int, int]] = set()

    for time_source, getter in (
        (EvidenceKind.EVENT_TIME.value, lambda r: r.event_time),
        (EvidenceKind.RECORD_TIME.value, lambda r: r.record_time),
    ):
        stream = [record for record in records if getter(record) is not None]
        for previous, current in zip(stream, stream[1:]):
            previous_time = getter(previous)
            current_time = getter(current)
            if previous_time is None or current_time is None:
                continue
            if current_time >= previous_time:
                continue
            key = (previous.index, current.index)
            if key in seen:
                continue
            seen.add(key)
            delta = (current_time - previous_time).total_seconds()
            rollback = -delta
            across = _discontinuity_between(previous, current, discontinuities)
            corroborated = _collection_corroborates(previous, current, records)
            evidence = [EvidenceKind.FILE_ORDER.value, time_source]
            bases = [EvidenceBasis.ORIGINAL_RECORD.value]
            if corroborated:
                evidence.append(EvidenceKind.RECEIPT_ORDER.value)
                bases.append(EvidenceBasis.COLLECTION.value)
            kind = "clock-rollback" if rollback >= min_rollback_seconds else "timestamp-inversion"
            source_text = "event time" if time_source == EvidenceKind.EVENT_TIME.value else "record-header time"
            detail = "%s moved backward by %.3f seconds between file positions %d and %d" % (
                source_text,
                rollback,
                previous.index,
                current.index,
            )
            if across:
                detail += "; a file discontinuity lies between the two records"
            if corroborated:
                detail += "; collection receipt order corroborates the file order"
            inversions.append(
                TimeInversion(
                    kind=kind,
                    before_record_index=previous.index,
                    after_record_index=current.index,
                    before_record_number=previous.record_number,
                    after_record_number=current.record_number,
                    before_time=previous_time,
                    after_time=current_time,
                    delta_seconds=delta,
                    rollback_seconds=rollback,
                    time_source=time_source,
                    significant=rollback >= 60.0,
                    across_discontinuity=across,
                    evidence=evidence,
                    bases=bases,
                    corroborated_by_collection=corroborated,
                    detail=detail,
                )
            )
    return inversions


def _build_file_order_constraints(records: Sequence[RecordObservation]) -> List[Dict[str, Any]]:
    return [
        {
            "before": previous.brief(),
            "after": current.brief(),
            "basis": EvidenceBasis.ORIGINAL_RECORD.value,
            "evidence": EvidenceKind.FILE_ORDER.value,
        }
        for previous, current in zip(records, records[1:])
    ]


def _build_event_time_constraints(records: Sequence[RecordObservation]) -> List[Dict[str, Any]]:
    return [
        {
            "file_index": record.index,
            "record_number": record.record_number,
            "time": format_datetime(record.event_time),
            "basis": EvidenceBasis.ORIGINAL_RECORD.value,
            "evidence": EvidenceKind.EVENT_TIME.value,
        }
        for record in records
        if record.event_time is not None
    ]


def _build_event_time_order_constraints(records: Sequence[RecordObservation]) -> List[Dict[str, Any]]:
    stream = [record for record in records if record.event_time is not None]
    result: List[Dict[str, Any]] = []
    for previous, current in zip(stream, stream[1:]):
        if previous.event_time is None or current.event_time is None:
            continue
        delta = (current.event_time - previous.event_time).total_seconds()
        result.append(
            {
                "before_file_index": previous.index,
                "after_file_index": current.index,
                "before_record_number": previous.record_number,
                "after_record_number": current.record_number,
                "delta_seconds": delta,
                "relation": "nondecreasing" if delta >= 0 else "backward",
                "basis": EvidenceBasis.ORIGINAL_RECORD.value,
                "evidence": EvidenceKind.EVENT_TIME.value,
            }
        )
    return result


def _build_receipt_constraints(receipts: Sequence[CollectionReceipt]) -> List[Dict[str, Any]]:
    return [
        {
            "receipt_sequence": receipt.sequence,
            "record_index": receipt.record_index,
            "record_number": receipt.record_number,
            "event_record_id": receipt.event_record_id,
            "block_index": receipt.block_index,
            "status": receipt.status,
            "receipt_time": format_datetime(receipt.receipt_time),
            "basis": EvidenceBasis.COLLECTION.value,
            "evidence": EvidenceKind.RECEIPT_ORDER.value,
        }
        for receipt in receipts
    ]


def _entry_from_record(record: RecordObservation) -> TimelineEntry:
    evidence = [EvidenceKind.FILE_ORDER.value]
    if record.record_time is not None:
        evidence.append(EvidenceKind.RECORD_TIME.value)
    if record.event_time is not None:
        evidence.append(EvidenceKind.EVENT_TIME.value)
    bases = [EvidenceBasis.ORIGINAL_RECORD.value]
    if record.receipt_index is not None:
        evidence.append(EvidenceKind.RECEIPT_ORDER.value)
        bases.append(EvidenceBasis.COLLECTION.value)
    return TimelineEntry(
        position=0,
        kind="record",
        basis=EvidenceBasis.ORIGINAL_RECORD.value,
        bases=bases,
        evidence=evidence,
        file_index=record.index,
        record_number=record.record_number,
        event_record_id=record.event_record_id,
        event_id=record.event_id,
        event_time=record.event_time,
        record_time=record.record_time,
        time_source=record.timestamp_source,
        receipt_sequence=record.receipt_sequence,
        receipt_time=record.receipt_time,
        start_offset=record.offset,
        end_offset=record.offset + record.length,
        detail="EVTX record in physical file order",
        payload=record.brief(),
    )


def _entry_from_discontinuity(discontinuity: Discontinuity, records: Sequence[RecordObservation]) -> TimelineEntry:
    return TimelineEntry(
        position=0,
        kind="discontinuity",
        basis=discontinuity.basis,
        bases=list(discontinuity.bases),
        evidence=[discontinuity.evidence],
        file_index=discontinuity.after_record_index,
        record_number=(
            discontinuity.after_record_number
            if discontinuity.after_record_number is not None
            else discontinuity.before_record_number
        ),
        event_id=discontinuity.event_id,
        receipt_sequence=discontinuity.receipt_sequence,
        start_offset=discontinuity.start_offset,
        end_offset=discontinuity.end_offset,
        missing=discontinuity.missing,
        detail=discontinuity.detail,
        payload=discontinuity.to_dict(),
    )


def _entry_from_inversion(inversion: TimeInversion) -> TimelineEntry:
    return TimelineEntry(
        position=0,
        kind=inversion.kind,
        basis=EvidenceBasis.ORIGINAL_RECORD.value,
        bases=list(inversion.bases),
        evidence=list(inversion.evidence),
        file_index=inversion.after_record_index,
        record_number=inversion.after_record_number,
        event_time=inversion.after_time,
        time_source=inversion.time_source,
        detail=inversion.detail,
        payload=inversion.to_dict(),
    )


def _entry_from_receipt(receipt: CollectionReceipt) -> TimelineEntry:
    return TimelineEntry(
        position=0,
        kind="collection-receipt" if not receipt.is_missing else "collection-receipt-missing",
        basis=EvidenceBasis.COLLECTION.value,
        bases=[EvidenceBasis.COLLECTION.value],
        evidence=[EvidenceKind.RECEIPT_ORDER.value]
        + ([EvidenceKind.RECEIPT_TIME.value] if receipt.receipt_time is not None else []),
        file_index=receipt.record_index,
        record_number=receipt.record_number,
        event_id=receipt.event_id,
        receipt_sequence=receipt.sequence,
        receipt_time=receipt.receipt_time,
        start_offset=receipt.file_offset,
        end_offset=(
            (receipt.file_offset + receipt.length)
            if receipt.file_offset is not None and receipt.length is not None
            else None
        ),
        detail="collection %s (%s)" % (receipt.kind, receipt.status),
        payload=receipt.to_dict(),
    )


def build_timeline(
    records: Sequence[RecordObservation],
    discontinuities: Sequence[Discontinuity],
    inversions: Sequence[TimeInversion],
    receipts: Sequence[CollectionReceipt],
) -> List[TimelineEntry]:
    """Merge original-record and collection evidence into one annotated list.

    The original record order is the spine.  Gaps and clock rollbacks are
    inserted at their observed position.  Collection-only entries are anchored
    by their mapped record, or after the original-record spine when no mapping
    exists.  Entries keep a ``basis`` and ``bases`` field so that a consumer can
    filter by provenance without losing either stream.
    """

    keyed: List[Tuple[Tuple[float, float, int], TimelineEntry]] = []
    for record in records:
        entry = _entry_from_record(record)
        keyed.append(((float(record.index), 0.0, 0), entry))

    for discontinuity in discontinuities:
        before, after = _discontinuity_position(discontinuity, records)
        entry = _entry_from_discontinuity(discontinuity, records)
        if discontinuity.after_record_index is not None:
            key = (after - 0.25, 0.0, 0)
        elif discontinuity.before_record_index is not None:
            key = (before + 1.25, 0.0, 0)
        else:
            key = (float(len(records)) + 0.75, 0.0, 0)
        keyed.append((key, entry))

    for inversion in inversions:
        entry = _entry_from_inversion(inversion)
        keyed.append(((inversion.after_record_index - 0.50, 0.0, 0), entry))

    for receipt in receipts:
        entry = _entry_from_receipt(receipt)
        if receipt.record_index is not None:
            key = (float(receipt.record_index), 0.8, receipt.index)
        elif receipt.sequence is not None:
            key = (float(len(records)) + 1.0 + receipt.sequence, 1.0, receipt.index)
        else:
            key = (float(len(records)) + 1.0, 1.0, receipt.index)
        keyed.append((key, entry))

    keyed.sort(key=lambda item: item[0])
    timeline = [entry for _key, entry in keyed]
    for position, entry in enumerate(timeline):
        entry.position = position
    return timeline


def analyze_observations(
    records: Sequence[RecordObservation],
    discontinuities: Optional[Sequence[Discontinuity]] = None,
    receipts: Optional[Any] = None,
    numbering_rules: Optional[Any] = None,
    *,
    receipt_step: Optional[int] = 1,
    min_rollback_seconds: float = 60.0,
    source: str = "<memory>",
    file_size: Optional[int] = None,
    file_header: Optional[Dict[str, Any]] = None,
    warnings: Optional[Sequence[str]] = None,
    include_receipts: bool = True,
) -> TimelineDiagnosis:
    """Run evidence analysis over already-scanned record observations."""

    records = list(records)
    for index, record in enumerate(records):
        record.index = index
    rules = parse_numbering_rules(numbering_rules)
    manifest = load_collection(receipts)
    if file_size is None:
        file_size = max(
            (record.offset + record.length for record in records),
            default=0,
        )

    all_discontinuities = list(discontinuities or [])
    collection_discontinuities = _analyze_collection(records, manifest, receipt_step)
    all_discontinuities.extend(collection_discontinuities)
    numbering_discontinuities, eid_constraints = _analyze_numbering(records, rules)
    all_discontinuities.extend(numbering_discontinuities)

    inversions = _detect_time_inversions(
        records,
        all_discontinuities,
        min_rollback_seconds=min_rollback_seconds,
    )
    clock_rollbacks = [inversion for inversion in inversions if inversion.kind == "clock-rollback"]

    receipt_constraints = _build_receipt_constraints(manifest.receipts)
    constraints = {
        "file_order": _build_file_order_constraints(records),
        "file_record_order": [record.brief() for record in records],
        "record_number": [
            {
                "file_index": record.index,
                "record_number": record.record_number,
                "basis": EvidenceBasis.ORIGINAL_RECORD.value,
                "evidence": EvidenceKind.RECORD_NUMBER.value,
            }
            for record in records
            if record.record_number is not None
        ],
        "event_time": _build_event_time_constraints(records),
        "event_time_order": _build_event_time_order_constraints(records),
        "eid_sequence": eid_constraints,
        "receipt_order": receipt_constraints,
        "collection_receipt_order": receipt_constraints,
    }

    timeline_receipts = manifest.receipts if include_receipts else []
    timeline = build_timeline(records, all_discontinuities, inversions, timeline_receipts)
    result = TimelineDiagnosis(
        source=source,
        file_size=file_size,
        records=records,
        receipts=list(manifest.receipts),
        discontinuities=all_discontinuities,
        time_inversions=inversions,
        clock_rollbacks=clock_rollbacks,
        timeline=timeline,
        constraints=constraints,
        numbering_rules=rules,
        warnings=list(warnings or []),
        metadata={"file_header": file_header or {}, "collection_metadata": manifest.metadata},
    )
    if not rules:
        result.warnings.append("no per-EventID numbering rules supplied; per-EID sequence gaps were not inferred")
    return result


def diagnose_timeline(
    source: Any,
    collection: Optional[Any] = None,
    numbering_rules: Optional[Any] = None,
    *,
    receipt_step: Optional[int] = 1,
    min_rollback_seconds: float = 60.0,
    resync: bool = True,
    include_inactive: bool = True,
    include_receipts: bool = True,
) -> TimelineDiagnosis:
    """Scan an EVTX file and produce a combined diagnostic timeline.

    Args:
        source: path, bytes, mmap, or binary file-like object.
        collection: receipt manifest (path, dict, list, or CollectionManifest).
        numbering_rules: caller-supplied per-EventID numbering rules.  They are
            intentionally never inferred from the file.
        receipt_step: expected collection receipt sequence increment, or None
            to disable receipt-sequence gap detection.
        min_rollback_seconds: inversions at least this large are classified as
            ``clock-rollback``; smaller ones are still retained as
            ``timestamp-inversion``.
    """

    rules = parse_numbering_rules(numbering_rules)
    with _as_buffer(source) as buf:
        scan = _scan_evtx_buffer(
            buf,
            rules,
            source=_source_label(source),
            resync=resync,
            include_inactive=include_inactive,
        )
        return analyze_observations(
            scan.records,
            discontinuities=scan.discontinuities,
            receipts=collection,
            numbering_rules=rules,
            receipt_step=receipt_step,
            min_rollback_seconds=min_rollback_seconds,
            source=_source_label(source),
            file_size=scan.file_size,
            file_header=scan.file_header,
            warnings=scan.warnings,
            include_receipts=include_receipts,
        )


def diagnose_file(
    path: Any,
    collection: Optional[Any] = None,
    numbering_rules: Optional[Any] = None,
    **kwargs: Any,
) -> TimelineDiagnosis:
    return diagnose_timeline(path, collection=collection, numbering_rules=numbering_rules, **kwargs)


def diagnose_bytes(
    buf: Any,
    collection: Optional[Any] = None,
    numbering_rules: Optional[Any] = None,
    **kwargs: Any,
) -> TimelineDiagnosis:
    return diagnose_timeline(buf, collection=collection, numbering_rules=numbering_rules, **kwargs)


class TimelineAnalyzer:
    """Reusable wrapper around :func:`diagnose_timeline`."""

    def __init__(
        self,
        collection: Optional[Any] = None,
        numbering_rules: Optional[Any] = None,
        *,
        receipt_step: Optional[int] = 1,
        min_rollback_seconds: float = 60.0,
        resync: bool = True,
        include_inactive: bool = True,
        include_receipts: bool = True,
    ) -> None:
        self.collection = collection
        self.numbering_rules = numbering_rules
        self.receipt_step = receipt_step
        self.min_rollback_seconds = min_rollback_seconds
        self.resync = resync
        self.include_inactive = include_inactive
        self.include_receipts = include_receipts

    def run(self, source: Any) -> TimelineDiagnosis:
        return diagnose_timeline(
            source,
            collection=self.collection,
            numbering_rules=self.numbering_rules,
            receipt_step=self.receipt_step,
            min_rollback_seconds=self.min_rollback_seconds,
            resync=self.resync,
            include_inactive=self.include_inactive,
            include_receipts=self.include_receipts,
        )

    analyze = run
    __call__ = run


# Friendly aliases for callers that use shorter verb names.
diagnose = diagnose_timeline
analyze = diagnose_timeline
scan = scan_evtx
TimelineResult = TimelineDiagnosis
TimelineDiagnostic = TimelineDiagnosis
CollectionAck = CollectionReceipt
CollectionRecord = CollectionReceipt
Receipt = CollectionReceipt
Gap = Discontinuity
FileGap = Discontinuity
TimelineGap = Discontinuity
ClockRollback = TimeInversion
RecordEvidence = RecordObservation
Observation = RecordObservation
TimelineEvent = TimelineEntry
diagnose_evtx = diagnose_timeline
diagnose_evtx_timeline = diagnose_timeline
analyze_evtx = diagnose_timeline


def _print_text(result: TimelineDiagnosis, stream: Any = None) -> None:
    stream = stream or sys.stdout
    summary = result.summary
    print("source: %s (%d bytes)" % (result.source, result.file_size), file=stream)
    print(
        "records: %d; parseable event times: %d" % (summary["record_count"], summary["parseable_event_time_count"]),
        file=stream,
    )
    print(
        "discontinuities: %d (original-record %d, collection %d)"
        % (
            summary["discontinuity_count"],
            summary["original_record_discontinuity_count"],
            summary["collection_discontinuity_count"],
        ),
        file=stream,
    )
    print(
        "clock rollbacks: %d; largest: %.3fs" % (summary["clock_rollback_count"], summary["largest_rollback_seconds"]),
        file=stream,
    )
    print("", file=stream)
    for entry in result.timeline:
        if entry.kind == "record":
            print(
                "[%04d] original-record record=%s eid=%s time=%s"
                % (
                    entry.position,
                    entry.record_number,
                    entry.event_id,
                    format_datetime(entry.event_time or entry.record_time),
                ),
                file=stream,
            )
        else:
            print(
                "[%04d] %-16s basis=%s %s" % (entry.position, entry.kind, ",".join(entry.bases), entry.detail),
                file=stream,
            )


def _print_csv(result: TimelineDiagnosis, stream: Any = None) -> None:
    stream = stream or sys.stdout
    writer = csv.writer(stream)
    writer.writerow(
        [
            "position",
            "kind",
            "basis",
            "evidence",
            "record_number",
            "event_record_id",
            "event_id",
            "event_time",
            "record_time",
            "receipt_sequence",
            "receipt_time",
            "start_offset",
            "end_offset",
            "missing",
            "detail",
        ]
    )
    for entry in result.timeline:
        writer.writerow(
            [
                entry.position,
                entry.kind,
                entry.basis,
                ";".join(entry.evidence),
                entry.record_number,
                entry.event_record_id,
                entry.event_id,
                format_datetime(entry.event_time),
                format_datetime(entry.record_time),
                entry.receipt_sequence,
                format_datetime(entry.receipt_time),
                entry.start_offset,
                entry.end_offset,
                entry.missing,
                entry.detail,
            ]
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline EVTX timeline diagnostic: keep original-record order, "
            "parseable event time, and collection receipt order separate."
        )
    )
    parser.add_argument("evtx", help="Path to the Windows EVTX event log file")
    parser.add_argument(
        "-c",
        "--collection",
        help="Collection receipt/acknowledgement manifest (JSON, JSONL, or CSV)",
    )
    parser.add_argument(
        "--numbering-rules",
        action="append",
        default=[],
        metavar="FILE",
        help="JSON file defining per-EventID numbering rules (repeatable; never inferred)",
    )
    parser.add_argument(
        "--numbering",
        action="append",
        default=[],
        metavar="EID=FIELD",
        help="Caller-supplied numbering rule, repeatable (for example 4624=EventRecordID)",
    )
    parser.add_argument(
        "--receipt-step",
        type=int,
        default=1,
        help="Expected collection receipt sequence increment (default: 1)",
    )
    parser.add_argument(
        "--no-receipt-gap-detection",
        action="store_true",
        help="Disable collection receipt sequence-gap detection",
    )
    parser.add_argument(
        "--min-rollback",
        type=float,
        default=60.0,
        help="Minimum backward jump classified as a clock rollback (default: 60 seconds)",
    )
    parser.add_argument(
        "--no-resync",
        action="store_true",
        help="Do not look for a later record after a bad record",
    )
    parser.add_argument(
        "--no-inactive",
        action="store_true",
        help="Do not scan chunks beyond the file header's declared chunk count",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text", "csv"),
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument("-o", "--output", help="Write output to this file instead of stdout")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Emit only the summary (JSON format)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 2 when discontinuities or timestamp inversions are found",
    )
    args = parser.parse_args(argv)

    rules: List[Any] = []
    try:
        for rule_source in list(args.numbering_rules) + list(args.numbering):
            rules.extend(parse_numbering_rules(rule_source))
    except TimelineDiagnosticError as exc:
        parser.error(str(exc))
        return 2

    try:
        result = diagnose_timeline(
            args.evtx,
            collection=args.collection,
            numbering_rules=rules or None,
            receipt_step=None if args.no_receipt_gap_detection else args.receipt_step,
            min_rollback_seconds=args.min_rollback,
            resync=not args.no_resync,
            include_inactive=not args.no_inactive,
        )
    except (TimelineDiagnosticError, OSError) as exc:
        parser.error(str(exc))
        return 2

    if args.output:
        handle = open(args.output, "w", encoding="utf-8", newline="")
    else:
        handle = sys.stdout
    try:
        if args.summary_only:
            json.dump(result.summary, handle, indent=2, sort_keys=True)
            handle.write("\n")
        elif args.format == "json":
            json.dump(result.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
        elif args.format == "csv":
            _print_csv(result, handle)
        else:
            _print_text(result, handle)
    finally:
        if args.output:
            handle.close()

    if args.strict and (result.discontinuities or result.time_inversions):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "TimelineDiagnosticError",
    "EvidenceBasis",
    "EvidenceKind",
    "NumberingRule",
    "CollectionReceipt",
    "CollectionManifest",
    "RecordObservation",
    "Discontinuity",
    "TimeInversion",
    "TimelineEntry",
    "ScanResult",
    "TimelineDiagnosis",
    "TimelineAnalyzer",
    "format_datetime",
    "parse_datetime",
    "scan_evtx",
    "parse_numbering_rules",
    "load_collection",
    "parse_collection",
    "build_timeline",
    "analyze_observations",
    "diagnose_timeline",
    "diagnose_file",
    "diagnose_bytes",
    "diagnose",
    "analyze",
    "scan",
    "TimelineResult",
    "TimelineDiagnostic",
    "CollectionAck",
    "CollectionRecord",
    "Receipt",
    "Gap",
    "FileGap",
    "TimelineGap",
    "ClockRollback",
    "RecordEvidence",
    "Observation",
    "TimelineEvent",
    "diagnose_evtx",
    "diagnose_evtx_timeline",
    "analyze_evtx",
    "main",
]
