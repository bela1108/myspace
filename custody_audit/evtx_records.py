"""
Offline extraction of EVTX record metadata for custody reconciliation.

This module never prints full event contents.  It turns an EVTX file into a
list of :class:`RecordSummary` objects that carry only the metadata an
external handover manifest is allowed to contain.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import Evtx.Evtx as evtx


@dataclass(frozen=True)
class RecordRange:
    """
    Inclusive record-number range supplied by the caller.

    ``last`` may be ``None`` to mean "every remaining record".
    """

    first: int
    last: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> "RecordRange":
        first = int(data["first_record"])
        last = data.get("last_record")
        return cls(first=first, last=None if last is None else int(last))

    def contains(self, record_num: int) -> bool:
        if record_num < self.first:
            return False
        return self.last is None or record_num <= self.last

    def describe(self) -> str:
        return "%d-%s" % (self.first, "END" if self.last is None else str(self.last))


@dataclass(frozen=True)
class RecordSummary:
    """
    Non-sensitive, manifest-safe description of a single EVTX record.
    """

    record_num: int
    timestamp: Optional[str]
    event_id: Optional[int]
    channel: Optional[str]
    sha256: str
    xml_ok: bool
    parse_error: Optional[str]

    def as_manifest_row(self) -> dict:
        """Return the exact key set permitted on an external manifest."""
        return {
            "record_num": self.record_num,
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "channel": self.channel,
            "sha256": self.sha256,
            "xml_ok": self.xml_ok,
        }


_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _extract_system_fields(record: evtx.Record) -> tuple[Optional[int], Optional[str]]:
    import xml.etree.ElementTree as ET

    root = ET.fromstring(record.xml())
    system = root.find("%sSystem" % _EVENT_NS)
    if system is None:
        return None, None
    event_id_node = system.find("%sEventID" % _EVENT_NS)
    channel_node = system.find("%sChannel" % _EVENT_NS)
    event_id = int(event_id_node.text) if event_id_node is not None and event_id_node.text else None
    channel = channel_node.text if channel_node is not None else None
    return event_id, channel


def summarize_evtx(path: str, record_range: RecordRange) -> list[RecordSummary]:
    """
    Parse an EVTX file and summarize the records inside ``record_range``.

    Records that fail XML rendering are still enumerated by record number so
    that a damaged record cannot silently disappear from the custody trail.
    """
    summaries: list[RecordSummary] = []
    with evtx.Evtx(path) as log:
        for chunk in log.get_file_header().chunks():
            for record in chunk.records():
                record_num = record.record_num()
                if not record_range.contains(record_num):
                    continue

                raw = record.data()
                sha256 = hashlib.sha256(raw).hexdigest()
                timestamp: Optional[str]
                try:
                    timestamp = str(record.timestamp())
                except Exception:
                    timestamp = None

                event_id = None
                channel = None
                xml_ok = True
                parse_error: Optional[str] = None
                try:
                    event_id, channel = _extract_system_fields(record)
                except Exception as exc:
                    xml_ok = False
                    parse_error = "%s: %s" % (type(exc).__name__, exc)

                summaries.append(
                    RecordSummary(
                        record_num=record_num,
                        timestamp=timestamp,
                        event_id=event_id,
                        channel=channel,
                        sha256=sha256,
                        xml_ok=xml_ok,
                        parse_error=parse_error,
                    )
                )
    return summaries


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_iso8601(value: str) -> datetime:
    """Parse the ISO-8601 timestamps used in manifests, rosters and receipts."""
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)
