# -*- coding: utf-8 -*-
"""Read-only direction audit for mirrored TCP captures.

This module answers a narrow forensic question: *which observed TCP sessions
have enough evidence to say that a capture's declared direction is upright or
reversed?*  It deliberately does not use ports or packet counts as direction
evidence.  Ports, packet counts, and hashes are reported only as context.

The evidence model has three independent legs:

* TCP handshakes whose SYN, SYN-ACK, and (when present) final ACK can be
  connected by sequence/acknowledgement numbers, including when the legs were
  captured by different offline files;
* a small set of explicitly trusted time anchors that pin a capture's mirror
  polarity for a time interval;
* wiring records, which describe expected polarity changes but are *not*
  trusted by themselves.

Half-handshakes are retained as candidates.  If two investigators disagree
about such a sample, it stays undetermined with both opinions and the packet
references recorded.  A confirmed reversal carries the anchor/wiring trail
that was used to interpret the work-order label.
"""

from __future__ import absolute_import, division, print_function

import argparse
import datetime as _datetime
import hashlib
import json
import os
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import ethernet
from . import ip
from . import ip6
from . import loopback
from . import pcap
from . import sll
from . import sll2
from . import tcp as tcp_proto

__all__ = [
    "AuditCase",
    "CaptureSpec",
    "DirectionClaim",
    "InvestigatorOpinion",
    "PolarityEvent",
    "audit_case",
    "audit_case_file",
    "audit_files",
    "load_case",
    "main",
    "render_markdown",
    "write_report",
]

SCHEMA_VERSION = "1.0"
MOD32 = 1 << 32

CLIENT_TO_SERVER = "client_to_server"
SERVER_TO_CLIENT = "server_to_client"
BIDIRECTIONAL = "bidirectional"
UNKNOWN = "unknown"

ROLE_CLIENT = "client"
ROLE_SERVER = "server"
ROLE_BIDIRECTIONAL = "bidirectional"
ROLE_UNKNOWN = "unknown"

DEFAULT_OPTIONS = {
    "session_gap": 300.0,
    "syn_retry_window": 5.0,
    "cross_capture_join_window": 600.0,
    "max_evidence_refs": 40,
}


# ---------------------------------------------------------------------------
# Small parsing / normalisation helpers


def _now_utc():
    return _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat()


def _parse_time(value, field_name="time", default=None):
    if value is None:
        if default is not None:
            return float(default)
        raise ValueError("%s is required" % field_name)
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        if default is not None:
            return float(default)
        raise ValueError("%s is required" % field_name)
    try:
        return float(text)
    except ValueError:
        pass
    iso = text.replace("Z", "+00:00")
    try:
        parsed = _datetime.datetime.fromisoformat(iso)
    except ValueError:
        raise ValueError("cannot parse %s=%r as epoch seconds or ISO-8601" % (field_name, value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_datetime.timezone.utc)
    return parsed.timestamp()


def _squash(value):
    text = str(value).strip().lower()
    text = text.replace("\u2192", "->").replace(" ", "_").replace("-", "_")
    text = text.replace(">", "_to_")
    while "__" in text:
        text = text.replace("__", "_")
    return text.strip("_")


def _normalise_direction(value, declared=None):
    """Return client_to_server/server_to_client/bidirectional or None."""
    if value is None:
        return None
    key = _squash(value)
    aliases = {
        "c2s": CLIENT_TO_SERVER,
        "client2server": CLIENT_TO_SERVER,
        "client_to_server": CLIENT_TO_SERVER,
        "client_to_server_traffic": CLIENT_TO_SERVER,
        "from_client": CLIENT_TO_SERVER,
        "source_client": CLIENT_TO_SERVER,
        "source_is_client": CLIENT_TO_SERVER,
        "client_side": CLIENT_TO_SERVER,
        "forward": CLIENT_TO_SERVER,
        "uplink": CLIENT_TO_SERVER,
        "s2c": SERVER_TO_CLIENT,
        "server2client": SERVER_TO_CLIENT,
        "server_to_client": SERVER_TO_CLIENT,
        "server_to_client_traffic": SERVER_TO_CLIENT,
        "from_server": SERVER_TO_CLIENT,
        "source_server": SERVER_TO_CLIENT,
        "source_is_server": SERVER_TO_CLIENT,
        "server_side": SERVER_TO_CLIENT,
        "reverse": SERVER_TO_CLIENT,
        "downlink": SERVER_TO_CLIENT,
        "both": BIDIRECTIONAL,
        "bidi": BIDIRECTIONAL,
        "bidirectional": BIDIRECTIONAL,
        "duplex": BIDIRECTIONAL,
    }
    if key in aliases:
        return aliases[key]
    if key in ("normal", "upright", "as_declared", "unchanged"):
        return _normalise_direction(declared) if declared else None
    if key in ("reversed", "inverted", "swapped", "flipped", "mirror_swapped"):
        if not declared:
            return None
        base = _normalise_direction(declared)
        return _opposite_direction(base)
    return None


def _opposite_direction(direction):
    if direction == CLIENT_TO_SERVER:
        return SERVER_TO_CLIENT
    if direction == SERVER_TO_CLIENT:
        return CLIENT_TO_SERVER
    return direction


def _normalise_role(value):
    if value is None:
        return None
    key = _squash(value)
    if key in ("client", "c", "initiator", "syn_sender", "client_side", "source_is_client", "c2s"):
        return ROLE_CLIENT
    if key in ("server", "s", "responder", "syn_ack_sender", "server_side", "source_is_server", "s2c"):
        return ROLE_SERVER
    if key in ("bidirectional", "both", "bidi", "duplex"):
        return ROLE_BIDIRECTIONAL
    if key in ("unknown", "none", "?"):
        return ROLE_UNKNOWN
    return None


def _role_for_direction(direction):
    if direction == CLIENT_TO_SERVER:
        return ROLE_CLIENT
    if direction == SERVER_TO_CLIENT:
        return ROLE_SERVER
    if direction == BIDIRECTIONAL:
        return ROLE_BIDIRECTIONAL
    return ROLE_UNKNOWN


def _direction_for_role(role):
    if role == ROLE_CLIENT:
        return CLIENT_TO_SERVER
    if role == ROLE_SERVER:
        return SERVER_TO_CLIENT
    if role == ROLE_BIDIRECTIONAL:
        return BIDIRECTIONAL
    return UNKNOWN


def _endpoint_text(value):
    if value is None:
        return None
    if isinstance(value, dict):
        host = value.get("ip") or value.get("address") or value.get("host")
        port = value.get("port")
        if host is None:
            return None
        return _format_endpoint(str(host), int(port) if port is not None else None)
    text = str(value)
    if text.startswith("[") and "]:" in text:
        return text
    if text.count(":") > 1:
        return "[%s]" % text
    return text


def _format_endpoint(host, port):
    if port is None:
        return "[%s]" % host if ":" in host else host
    if ":" in host:
        return "[%s]:%d" % (host, int(port))
    return "%s:%d" % (host, int(port))


def _endpoint_tuple(host, port):
    return (str(host), int(port))


def _format_flow(flow_key):
    _proto, left, right = flow_key
    return "%s <-> %s tcp" % (_format_endpoint(*left), _format_endpoint(*right))


def _flags_text(flags):
    names = []
    for bit, name in (
        (tcp_proto.TH_FIN, "FIN"),
        (tcp_proto.TH_SYN, "SYN"),
        (tcp_proto.TH_RST, "RST"),
        (tcp_proto.TH_PUSH, "PSH"),
        (tcp_proto.TH_ACK, "ACK"),
        (tcp_proto.TH_URG, "URG"),
        (tcp_proto.TH_ECE, "ECE"),
        (tcp_proto.TH_CWR, "CWR"),
    ):
        if flags & bit:
            names.append(name)
    return ",".join(names) or "NONE"


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _json_safe(value):
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, float):
        if value == float("inf") or value == float("-inf"):
            return None
        return value
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return str(value)


# ---------------------------------------------------------------------------
# Input model


@dataclass
class CaptureSpec:
    id: str
    path: Path
    declared_direction: str = UNKNOWN
    note: str = ""


@dataclass
class PolarityEvent:
    id: str
    time: float
    capture: str
    kind: str
    role: str = ROLE_UNKNOWN
    trusted: bool = False
    note: str = ""
    client_endpoint: str = None
    server_endpoint: str = None
    raw_direction: str = None


@dataclass
class DirectionClaim:
    id: str
    capture: str
    time_from: float
    time_to: float
    direction: str
    source: str = "work order"
    sample: object = None
    note: str = ""
    raw_direction: str = None


@dataclass
class InvestigatorOpinion:
    investigator: str
    direction: str
    sample: object = None
    note: str = ""
    capture: str = None
    raw_direction: str = None


@dataclass
class AuditCase:
    captures: list
    anchors: list = field(default_factory=list)
    wiring: list = field(default_factory=list)
    claims: list = field(default_factory=list)
    opinions: list = field(default_factory=list)
    service: str = ""
    options: dict = field(default_factory=lambda: dict(DEFAULT_OPTIONS))
    source_path: Path = None
    warnings: list = field(default_factory=list)

    def capture_by_id(self, capture_id):
        for spec in self.captures:
            if spec.id == capture_id:
                return spec
        return None

    @property
    def capture_ids(self):
        return [spec.id for spec in self.captures]


@dataclass
class PacketObs:
    capture_id: str
    index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload_len: int
    ip_version: int
    link: dict = field(default_factory=dict)

    @property
    def ref(self):
        return "%s#%d" % (self.capture_id, self.index)

    @property
    def src_endpoint(self):
        return _endpoint_tuple(self.src_ip, self.sport)

    @property
    def dst_endpoint(self):
        return _endpoint_tuple(self.dst_ip, self.dport)

    @property
    def is_syn(self):
        return bool(self.flags & tcp_proto.TH_SYN)

    @property
    def is_ack(self):
        return bool(self.flags & tcp_proto.TH_ACK)

    @property
    def is_syn_only(self):
        return self.is_syn and not self.is_ack

    @property
    def is_synack(self):
        return self.is_syn and self.is_ack

    @property
    def is_fin_or_rst(self):
        return bool(self.flags & (tcp_proto.TH_FIN | tcp_proto.TH_RST))


@dataclass
class CaptureData:
    spec: CaptureSpec
    packets: list
    packet_count: int
    tcp_packet_count: int
    unsupported_count: int
    parse_errors: list
    first_time: float
    last_time: float
    sha256: str
    size_bytes: int
    linktype: int
    port_counts: dict


# ---------------------------------------------------------------------------
# Case loading


def _entries(raw, kind):
    """Normalise a list, a single record, or an id-keyed mapping of records."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return list(raw)
    if isinstance(raw, dict):
        marker_keys = {
            "capture": ("capture", "captures", "path", "file"),
            "claim": ("capture", "direction", "claimed_direction", "sample"),
            "opinion": ("investigator", "name", "analyst", "direction", "sample"),
            "dispute": ("sample", "opinions"),
        }.get(kind, ())
        if any(key in raw for key in marker_keys):
            return [raw]
        rows = []
        for key, value in raw.items():
            if isinstance(value, dict):
                row = dict(value)
                if kind in ("anchor", "wiring", "claim", "dispute"):
                    row.setdefault("id", key)
                elif kind == "opinion":
                    row.setdefault("investigator", key)
                rows.append(row)
            elif kind == "opinion":
                rows.append({"investigator": key, "direction": value})
            else:
                rows.append(value)
        return rows
    return [raw]


def _capture_specs_from_raw(raw, base_dir):
    if raw is None:
        raise ValueError("case must contain a non-empty 'captures' section")
    rows = []
    if isinstance(raw, dict):
        for capture_id, value in raw.items():
            if isinstance(value, dict):
                row = dict(value)
            else:
                row = {"path": value}
            row.setdefault("id", capture_id)
            rows.append(row)
    elif isinstance(raw, list):
        rows = list(raw)
    else:
        raise ValueError("'captures' must be a list or an object keyed by capture id")

    specs = []
    seen = set()
    for index, row in enumerate(rows, 1):
        if isinstance(row, (str, os.PathLike)):
            row = {"path": row}
        elif isinstance(row, (list, tuple)) and len(row) == 2:
            row = {"id": row[0], "path": row[1]}
        if not isinstance(row, dict):
            raise ValueError("capture entry %d must be an object" % index)
        capture_id = str(row.get("id") or "cap%d" % index)
        if capture_id in seen:
            raise ValueError("duplicate capture id %r" % capture_id)
        seen.add(capture_id)
        path_value = row.get("path") or row.get("file")
        if not path_value:
            raise ValueError("capture %r has no path" % capture_id)
        path = Path(os.path.expanduser(str(path_value)))
        if not path.is_absolute():
            path = (base_dir / path).resolve()
        declared_raw = row.get("declared_direction", row.get("declared", UNKNOWN))
        declared = _normalise_direction(declared_raw)
        if declared is None:
            declared = UNKNOWN
        specs.append(CaptureSpec(
            id=capture_id,
            path=path,
            declared_direction=declared,
            note=str(row.get("note") or ""),
        ))
    if not specs:
        raise ValueError("'captures' is empty")
    return specs


def _expand_capture_ids(raw, capture_ids):
    value = raw.get("capture", raw.get("captures"))
    if value is None or value == "*":
        return list(capture_ids)
    if isinstance(value, (list, tuple)):
        values = [str(v) for v in value]
    else:
        values = [str(value)]
    for capture_id in values:
        if capture_id not in capture_ids:
            raise ValueError("unknown capture id %r in event" % capture_id)
    return values


def _event_from_raw(raw, kind, index, specs, capture_ids):
    if not isinstance(raw, dict):
        raise ValueError("%s entry %d must be an object" % (kind, index))
    targets = _expand_capture_ids(raw, capture_ids)
    event_id = str(raw.get("id") or "%s-%02d" % (kind, index))
    when = _parse_time(raw.get("time", raw.get("at")), "%s.time" % kind, default=float("-inf"))
    trusted_default = kind == "anchor"
    trusted = bool(raw.get("trusted", trusted_default))
    role = _normalise_role(raw.get("source_role", raw.get("role")))
    raw_direction = raw.get("direction", raw.get("orientation"))
    note = str(raw.get("basis") or raw.get("note") or "")
    client_endpoint = _endpoint_text(raw.get("client_endpoint") or raw.get("client"))
    server_endpoint = _endpoint_text(raw.get("server_endpoint") or raw.get("server"))
    events = []
    for capture_id in targets:
        spec = next(s for s in specs if s.id == capture_id)
        direction = _normalise_direction(raw_direction, spec.declared_direction)
        event_role = role or _role_for_direction(direction)
        if event_role is None:
            event_role = ROLE_UNKNOWN
        event = PolarityEvent(
            id=event_id if len(targets) == 1 else "%s@%s" % (event_id, capture_id),
            time=when,
            capture=capture_id,
            kind=kind,
            role=event_role,
            trusted=trusted,
            note=note,
            client_endpoint=client_endpoint,
            server_endpoint=server_endpoint,
            raw_direction=raw_direction,
        )
        events.append(event)
    return events


def _claim_from_raw(raw, index, specs):
    if not isinstance(raw, dict):
        raise ValueError("claim entry %d must be an object" % index)
    capture_id = raw.get("capture")
    if not capture_id:
        raise ValueError("claim entry %d has no capture" % index)
    capture_id = str(capture_id)
    spec = next((s for s in specs if s.id == capture_id), None)
    if spec is None:
        raise ValueError("claim %r refers to unknown capture %r" % (raw.get("id"), capture_id))
    raw_direction = raw.get("direction", raw.get("claimed_direction", raw.get("claimed")))
    direction = _normalise_direction(raw_direction, spec.declared_direction)
    if direction is None:
        raise ValueError("claim %r has an unrecognised direction %r" % (raw.get("id"), raw_direction))
    time_from = _parse_time(raw.get("time_from", raw.get("from")), "claim.time_from", default=float("-inf"))
    time_to = _parse_time(raw.get("time_to", raw.get("to")), "claim.time_to", default=float("inf"))
    if time_to < time_from:
        raise ValueError("claim %r has time_to before time_from" % raw.get("id"))
    return DirectionClaim(
        id=str(raw.get("id") or "claim-%02d" % index),
        capture=capture_id,
        time_from=time_from,
        time_to=time_to,
        direction=direction,
        source=str(raw.get("source") or "work order"),
        sample=raw.get("sample"),
        note=str(raw.get("note") or ""),
        raw_direction=raw_direction,
    )


def _opinion_from_raw(raw, specs, default_sample=None):
    if not isinstance(raw, dict):
        raise ValueError("investigator opinion must be an object")
    investigator = str(raw.get("investigator") or raw.get("name") or raw.get("analyst") or "investigator")
    sample = raw.get("sample", default_sample)
    capture_id = raw.get("capture")
    if not capture_id and isinstance(default_sample, dict):
        capture_id = default_sample.get("capture") or default_sample.get("capture_id")
    spec = next((s for s in specs if s.id == str(capture_id)), None) if capture_id else None
    raw_direction = raw.get("direction", raw.get("claimed_direction", raw.get("claimed")))
    direction = _normalise_direction(raw_direction, spec.declared_direction if spec else None)
    if direction is None:
        raise ValueError("opinion by %r has an unrecognised direction %r" % (investigator, raw_direction))
    return InvestigatorOpinion(
        investigator=investigator,
        direction=direction,
        sample=sample,
        note=str(raw.get("note") or raw.get("basis") or ""),
        capture=str(capture_id) if capture_id else None,
        raw_direction=raw_direction,
    )


def load_case(path):
    """Load and validate a JSON audit case from *path*.

    Relative capture paths are resolved against the case file directory.
    """
    case_path = Path(path).expanduser().resolve()
    with open(case_path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("case file must contain a JSON object")
    return case_from_dict(raw, base_dir=case_path.parent, source_path=case_path)


def case_from_dict(raw, base_dir=None, source_path=None):
    """Build an :class:`AuditCase` from an already-decoded mapping."""
    if not isinstance(raw, dict):
        raise ValueError("case must be a JSON object")
    base_dir = Path(base_dir or os.getcwd()).resolve()
    specs = _capture_specs_from_raw(raw.get("captures"), base_dir)
    capture_ids = [s.id for s in specs]
    options = dict(DEFAULT_OPTIONS)
    options.update(raw.get("options") or {})
    case = AuditCase(
        captures=specs,
        service=str(raw.get("service") or raw.get("name") or ""),
        options=options,
        source_path=Path(source_path) if source_path else None,
    )

    for index, item in enumerate(_entries(raw.get("anchors"), "anchor"), 1):
        case.anchors.extend(_event_from_raw(item, "anchor", index, specs, capture_ids))
    for index, item in enumerate(_entries(raw.get("wiring") or raw.get("wiring_records"), "wiring"), 1):
        case.wiring.extend(_event_from_raw(item, "wiring", index, specs, capture_ids))
    for index, item in enumerate(_entries(raw.get("claims") or raw.get("work_order"), "claim"), 1):
        case.claims.append(_claim_from_raw(item, index, specs))

    for index, item in enumerate(_entries(raw.get("opinions"), "opinion"), 1):
        case.opinions.append(_opinion_from_raw(item, specs))
    for dinx, dispute in enumerate(_entries(raw.get("disputes"), "dispute"), 1):
        if not isinstance(dispute, dict):
            raise ValueError("dispute entry %d must be an object" % dinx)
        sample = dispute.get("sample")
        for oinx, opinion in enumerate(dispute.get("opinions") or [], 1):
            case.opinions.append(_opinion_from_raw(opinion, specs, default_sample=sample))

    for event in case.anchors + case.wiring:
        if event.role == ROLE_UNKNOWN and event.raw_direction:
            case.warnings.append(
                "event %s has direction %r which cannot be resolved against declared capture direction"
                % (event.id, event.raw_direction)
            )
    for claim in case.claims:
        if claim.raw_direction is not None and _normalise_direction(claim.raw_direction) is None:
            case.warnings.append(
                "claim %s uses relative direction %r; resolved using capture declaration %r"
                % (claim.id, claim.raw_direction, case.capture_by_id(claim.capture).declared_direction)
            )
    return case


# ---------------------------------------------------------------------------
# Read-only capture parsing


def _unpack_link_frame(dlt, buf):
    """Return ``(ip_packet, link_metadata)`` or ``(None, metadata)``."""
    meta = {}
    packet = None
    if dlt == pcap.DLT_EN10MB:
        frame = ethernet.Ethernet(buf)
        meta["mac_src"] = frame.src.hex(":")
        meta["mac_dst"] = frame.dst.hex(":")
        if getattr(frame, "vlan_tags", None):
            meta["vlan"] = [getattr(tag, "id", None) for tag in frame.vlan_tags]
        packet = frame.data
    elif dlt == pcap.DLT_LINUX_SLL:
        frame = sll.SLL(buf)
        meta["sll_type"] = frame.type
        meta["mac_src"] = frame.hdr[6:12].hex(":")
        packet = frame.data
    elif dlt == pcap.DLT_LINUX_SLL2:
        frame = sll2.SLL2(buf)
        meta["sll_type"] = frame.type
        meta["mac_src"] = frame.hdr[0:6].hex(":")
        packet = frame.data
    elif dlt in (pcap.DLT_NULL, pcap.DLT_LOOP):
        frame = loopback.Loopback(buf)
        packet = frame.data
    elif dlt in (pcap.DLT_RAW, getattr(pcap, "DLT_IPV4", 228), getattr(pcap, "DLT_IPV6", 229)):
        if buf and (buf[0] >> 4) == 6:
            packet = ip6.IP6(buf)
        else:
            packet = ip.IP(buf)
    else:
        raise ValueError("unsupported pcap link type %r" % dlt)
    return packet, meta


def _ip_strings(packet):
    if isinstance(packet, ip.IP):
        return (socket.inet_ntop(socket.AF_INET, packet.src),
                socket.inet_ntop(socket.AF_INET, packet.dst), 4)
    if isinstance(packet, ip6.IP6):
        return (socket.inet_ntop(socket.AF_INET6, packet.src),
                socket.inet_ntop(socket.AF_INET6, packet.dst), 6)
    return None, None, None


def read_capture(spec):
    """Read one pcap/pcapng file without modifying it."""
    packets = []
    parse_errors = []
    packet_count = 0
    tcp_packet_count = 0
    unsupported_count = 0
    first_time = float("inf")
    last_time = float("-inf")
    port_counts = Counter()
    linktype = None
    with open(spec.path, "rb") as handle:
        reader = pcap.UniversalReader(handle)
        try:
            linktype = reader.datalink()
        except Exception:
            linktype = None
        for index, (timestamp, buf) in enumerate(reader):
            packet_count += 1
            first_time = min(first_time, timestamp)
            last_time = max(last_time, timestamp)
            try:
                network, meta = _unpack_link_frame(linktype, buf)
            except Exception as exc:
                unsupported_count += 1
                if len(parse_errors) < 20:
                    parse_errors.append({"packet_index": index, "stage": "link", "error": repr(exc)})
                continue
            if network is None:
                unsupported_count += 1
                continue
            if isinstance(network, ip.IP):
                if getattr(network, "offset", 0) != 0:
                    unsupported_count += 1
                    continue
            src_ip, dst_ip, version = _ip_strings(network)
            if src_ip is None:
                unsupported_count += 1
                continue
            segment = network.data
            if not isinstance(segment, tcp_proto.TCP):
                unsupported_count += 1
                continue
            tcp_packet_count += 1
            port_counts[segment.sport] += 1
            port_counts[segment.dport] += 1
            packets.append(PacketObs(
                capture_id=spec.id,
                index=index,
                timestamp=float(timestamp),
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=int(segment.sport),
                dport=int(segment.dport),
                seq=int(segment.seq),
                ack=int(segment.ack),
                flags=int(segment.flags),
                payload_len=len(segment.data),
                ip_version=version,
                link=meta,
            ))
    if packet_count == 0:
        first_time = 0.0
        last_time = 0.0
    return CaptureData(
        spec=spec,
        packets=packets,
        packet_count=packet_count,
        tcp_packet_count=tcp_packet_count,
        unsupported_count=unsupported_count,
        parse_errors=parse_errors,
        first_time=first_time,
        last_time=last_time,
        sha256=_sha256_file(spec.path),
        size_bytes=os.path.getsize(spec.path),
        linktype=linktype,
        port_counts=dict(port_counts),
    )


def _flow_key(packet):
    left = packet.src_endpoint
    right = packet.dst_endpoint
    if left > right:
        left, right = right, left
    return ("tcp", left, right)


# ---------------------------------------------------------------------------
# Session construction and handshake linking


@dataclass
class _SessionDraft:
    flow_key: tuple
    packets: list = field(default_factory=list)

    @property
    def capture_ids(self):
        return {p.capture_id for p in self.packets}


def _packet_sort_key(packet, capture_rank):
    return (packet.timestamp, capture_rank.get(packet.capture_id, 0), packet.index)


def _split_flow_packets(flow_packets, options, capture_rank):
    gap_limit = float(options.get("session_gap", 300.0))
    retry_window = float(options.get("syn_retry_window", 5.0))
    drafts = []
    current = []
    syn_seqs = {}
    established = False
    last_time = None

    def flush():
        if current:
            drafts.append(_SessionDraft(flow_key=_flow_key(current[0]), packets=list(current)))

    for packet in sorted(flow_packets, key=lambda p: _packet_sort_key(p, capture_rank)):
        start_new = not current
        if current:
            gap = packet.timestamp - last_time
            if gap > gap_limit:
                start_new = True
            elif packet.is_syn_only and packet.seq not in syn_seqs:
                if established:
                    start_new = True
                elif syn_seqs and (packet.timestamp - max(syn_seqs.values())) > retry_window:
                    start_new = True
        if start_new:
            flush()
            current = []
            syn_seqs = {}
            established = False
        current.append(packet)
        last_time = packet.timestamp
        if packet.is_syn_only:
            syn_seqs[packet.seq] = packet.timestamp
        if packet.is_synack:
            if ((packet.ack - 1) % MOD32) in syn_seqs:
                established = True
    flush()
    return drafts


def _has_linked_handshake(packets):
    syns = [p for p in packets if p.is_syn_only]
    synacks = [p for p in packets if p.is_synack]
    for syn in syns:
        for synack in synacks:
            if (syn.src_endpoint == synack.dst_endpoint
                    and syn.dst_endpoint == synack.src_endpoint
                    and ((syn.seq + 1) % MOD32) == synack.ack):
                return True
    return False


def _merge_complementary_sessions(drafts, options):
    join_window = float(options.get("cross_capture_join_window", 600.0))
    merged = True
    while merged:
        merged = False
        for i in range(len(drafts)):
            for j in range(i + 1, len(drafts)):
                left = drafts[i]
                right = drafts[j]
                if left.flow_key != right.flow_key:
                    continue
                if not left.capture_ids.isdisjoint(right.capture_ids):
                    continue
                left_start = min(p.timestamp for p in left.packets)
                left_end = max(p.timestamp for p in left.packets)
                right_start = min(p.timestamp for p in right.packets)
                right_end = max(p.timestamp for p in right.packets)
                far = max(left_start, right_start) - min(left_end, right_end)
                # Complementary half-leg captures are joined by exact TCP
                # sequence/ack linkage even when the two recorders clocks are
                # offset; a time window alone would incorrectly split them.
                left_syn_only = [p for p in left.packets if p.is_syn_only]
                right_syn_only = [p for p in right.packets if p.is_syn_only]
                left_synack = [p for p in left.packets if p.is_synack]
                right_synack = [p for p in right.packets if p.is_synack]
                complementary = (
                    (left_syn_only and not left_synack and right_synack and not right_syn_only)
                    or (right_syn_only and not right_synack and left_synack and not left_syn_only)
                )
                if far > join_window and not complementary:
                    continue
                if _has_linked_handshake(left.packets + right.packets):
                    left.packets.extend(right.packets)
                    del drafts[j]
                    merged = True
                    break
            if merged:
                break
    return drafts


def _build_sessions(capture_data, options):
    by_flow = defaultdict(list)
    for data in capture_data:
        for packet in data.packets:
            by_flow[_flow_key(packet)].append(packet)
    capture_rank = {data.spec.id: index for index, data in enumerate(capture_data)}
    sessions = []
    for flow_key, packets in by_flow.items():
        sessions.extend(_split_flow_packets(packets, options, capture_rank))
    sessions = _merge_complementary_sessions(sessions, options)
    sessions.sort(key=lambda s: (min(p.timestamp for p in s.packets), _format_flow(s.flow_key)))
    for number, session in enumerate(sessions, 1):
        session.id = "S%02d" % number
    return sessions


def _dedupe_segments(packets, limit):
    groups = OrderedDictCompat()
    for packet in packets:
        key = (
            packet.src_ip, packet.sport, packet.dst_ip, packet.dport,
            packet.seq, packet.ack, packet.flags & 0x1ff, packet.payload_len,
        )
        groups.setdefault(key, []).append(packet)
        if len(groups) > limit * 4:
            break
    result = []
    for refs in groups.values():
        refs.sort(key=lambda p: (p.timestamp, p.capture_id, p.index))
        result.append((refs[0], refs[1:]))
    result.sort(key=lambda item: (item[0].timestamp, item[0].capture_id, item[0].index))
    return result


class OrderedDictCompat(dict):
    """dict that is ordered on all supported Python versions."""


def _segment_record(packet, role, also_seen, checks=None):
    record = {
        "ref": packet.ref,
        "capture": packet.capture_id,
        "packet_index": packet.index,
        "timestamp": packet.timestamp,
        "src": _format_endpoint(packet.src_ip, packet.sport),
        "dst": _format_endpoint(packet.dst_ip, packet.dport),
        "flags": _flags_text(packet.flags),
        "seq": packet.seq,
        "ack": packet.ack,
        "payload_len": packet.payload_len,
        "role": role,
    }
    if checks:
        record["link_checks"] = checks
    if also_seen:
        record["also_seen"] = [p.ref for p in also_seen]
    return record


def _analyse_handshake(packets, options):
    limit = int(options.get("max_evidence_refs", 40))
    syns = _dedupe_segments([p for p in packets if p.is_syn_only], limit)
    synacks = _dedupe_segments([p for p in packets if p.is_synack], limit)
    acks = _dedupe_segments([p for p in packets if p.is_ack and not p.is_syn], limit)
    attempts = []
    used_synacks = set()

    for syn, syn_also in syns:
        candidates = []
        for synack, synack_also in synacks:
            if syn.src_endpoint != synack.dst_endpoint or syn.dst_endpoint != synack.src_endpoint:
                continue
            if ((syn.seq + 1) % MOD32) != synack.ack:
                continue
            same_capture = syn.capture_id == synack.capture_id
            after = synack.timestamp >= syn.timestamp
            candidates.append((same_capture, after, abs(synack.timestamp - syn.timestamp), synack, synack_also))
        if not candidates:
            attempts.append({
                "state": "syn_only",
                "syn": _segment_record(syn, ROLE_CLIENT, syn_also),
                "synack": None,
                "ack": None,
                "strong": False,
                "cross_capture": False,
                "notes": ["SYN is not linked to a SYN-ACK; retained as a half-handshake candidate."],
            })
            continue
        candidates.sort(key=lambda row: (not row[0], not row[1], row[2]))
        _same, _after, _delta, synack, synack_also = candidates[0]
        used_synacks.add(synack.ref)
        final_candidates = []
        for ack_packet, ack_also in acks:
            if ack_packet.src_endpoint != syn.src_endpoint or ack_packet.dst_endpoint != syn.dst_endpoint:
                continue
            if ((ack_packet.ack + 0) % MOD32) != ((synack.seq + 1) % MOD32):
                continue
            if ack_packet.timestamp < synack.timestamp and ack_packet.capture_id == synack.capture_id:
                continue
            final_candidates.append((ack_packet, ack_also))
        final_candidates.sort(key=lambda item: (
            item[0].seq != ((syn.seq + 1) % MOD32),
            item[0].timestamp,
            item[0].capture_id,
            item[0].index,
        ))
        ack_packet, ack_also = final_candidates[0] if final_candidates else (None, [])
        state = "full" if ack_packet is not None else "two_way"
        captures = {syn.capture_id, synack.capture_id}
        if ack_packet is not None:
            captures.add(ack_packet.capture_id)
        notes = []
        if synack.timestamp < syn.timestamp:
            notes.append("SYN-ACK timestamp precedes SYN; exact sequence/ack linkage still matches (clock skew or merged captures).")
        if ack_packet is None:
            notes.append("Final ACK was not captured; SYN and SYN-ACK sequence/ack numbers still connect.")
        elif ack_packet.timestamp < synack.timestamp:
            notes.append("Final ACK timestamp precedes SYN-ACK; exact sequence/ack linkage still matches (cross-capture clock skew).")
        checks_syn = {
            "reverse_tuple": True,
            "synack_ack_equals_syn_seq_plus_1": True,
        }
        checks_ack = None
        if ack_packet is not None:
            checks_ack = {
                "ack_equals_synack_seq_plus_1": True,
                "seq_equals_syn_seq_plus_1": ack_packet.seq == ((syn.seq + 1) % MOD32),
            }
        attempts.append({
            "state": state,
            "syn": _segment_record(syn, ROLE_CLIENT, syn_also, checks_syn),
            "synack": _segment_record(synack, ROLE_SERVER, synack_also),
            "ack": _segment_record(ack_packet, ROLE_CLIENT, ack_also, checks_ack) if ack_packet else None,
            "strong": True,
            "cross_capture": len(captures) > 1,
            "notes": notes,
        })

    for synack, synack_also in synacks:
        if synack.ref in used_synacks:
            continue
        matching_syn = any(
            syn.src_endpoint == synack.dst_endpoint
            and syn.dst_endpoint == synack.src_endpoint
            and ((syn.seq + 1) % MOD32) == synack.ack
            for syn, _ in syns
        )
        if matching_syn:
            continue
        attempts.append({
            "state": "synack_only",
            "syn": None,
            "synack": _segment_record(synack, ROLE_SERVER, synack_also),
            "ack": None,
            "strong": False,
            "cross_capture": False,
            "notes": ["SYN-ACK is not linked to a SYN; retained as a half-handshake candidate."],
        })

    if not attempts:
        return {
            "state": "none",
            "strong": False,
            "cross_capture": False,
            "client": None,
            "server": None,
            "segments": [],
            "attempts": [],
            "notes": ["No complete or partial TCP handshake was captured."],
        }

    rank = {"full": 4, "two_way": 3, "synack_only": 2, "syn_only": 1}
    best = max(attempts, key=lambda row: (rank.get(row["state"], 0), row["syn"] is not None))
    if best["syn"]:
        client_packet = next(p for p in packets if p.ref == best["syn"]["ref"])
        client = client_packet.src_endpoint
        server = client_packet.dst_endpoint
    else:
        synack_packet = next(p for p in packets if p.ref == best["synack"]["ref"])
        client = synack_packet.dst_endpoint
        server = synack_packet.src_endpoint
    segments = [row for row in (best["syn"], best["synack"], best["ack"]) if row]
    return {
        "state": best["state"],
        "strong": bool(best["strong"]),
        "cross_capture": bool(best["cross_capture"]),
        "client": {"ip": client[0], "port": client[1], "endpoint": _format_endpoint(*client)},
        "server": {"ip": server[0], "port": server[1], "endpoint": _format_endpoint(*server)},
        "segments": segments,
        "attempts": attempts,
        "notes": list(best["notes"]) + (
            ["Multiple handshake attempts were observed; the strongest linked attempt is shown."]
            if len(attempts) > 1 else []
        ),
    }


def _packet_direction(packet, handshake):
    if not handshake.get("client") or not handshake.get("server"):
        return UNKNOWN
    client = (handshake["client"]["ip"], handshake["client"]["port"])
    server = (handshake["server"]["ip"], handshake["server"]["port"])
    if packet.src_endpoint == client and packet.dst_endpoint == server:
        return CLIENT_TO_SERVER
    if packet.src_endpoint == server and packet.dst_endpoint == client:
        return SERVER_TO_CLIENT
    return UNKNOWN


def _capture_direction_info(session, handshake):
    info = {}
    for packet in session.packets:
        bucket = info.setdefault(packet.capture_id, {
            "capture": packet.capture_id,
            "packet_count": 0,
            "first_time": packet.timestamp,
            "last_time": packet.timestamp,
            "directions": set(),
            "source_endpoints": set(),
            "ports": Counter(),
        })
        bucket["packet_count"] += 1
        bucket["first_time"] = min(bucket["first_time"], packet.timestamp)
        bucket["last_time"] = max(bucket["last_time"], packet.timestamp)
        bucket["source_endpoints"].add(packet.src_endpoint)
        bucket["ports"][packet.sport] += 1
        bucket["ports"][packet.dport] += 1
        direction = _packet_direction(packet, handshake)
        if direction != UNKNOWN:
            bucket["directions"].add(direction)
    result = []
    for capture_id in sorted(info):
        bucket = info[capture_id]
        directions = sorted(bucket["directions"])
        if len(directions) == 1:
            direction = directions[0]
        elif len(directions) > 1:
            direction = BIDIRECTIONAL
        else:
            direction = UNKNOWN
        role = ROLE_UNKNOWN
        if direction == CLIENT_TO_SERVER:
            role = ROLE_CLIENT
        elif direction == SERVER_TO_CLIENT:
            role = ROLE_SERVER
        elif direction == BIDIRECTIONAL:
            role = ROLE_BIDIRECTIONAL
        result.append({
            "capture": capture_id,
            "packet_count": bucket["packet_count"],
            "first_time": bucket["first_time"],
            "last_time": bucket["last_time"],
            "observed_direction": direction,
            "observed_source_role": role,
            "source_endpoints": [_format_endpoint(*ep) for ep in sorted(bucket["source_endpoints"])],
            "display_only": {
                "ports": dict(bucket["ports"]),
                "packet_count": bucket["packet_count"],
                "note": "Ports and counts are informational only; they are not direction evidence.",
            },
        })
    return result


# ---------------------------------------------------------------------------
# Trusted anchors, wiring records, and polarity resolution


def _epoch_evidence_kind(resolution):
    trace = resolution.get("anchor_trace") or []
    if resolution.get("status") == "confirmed":
        return "trusted_anchor"
    if resolution.get("status") == "supported":
        trusted = [row for row in trace if row.get("trusted")]
        untrusted = [row for row in trace if not row.get("trusted")]
        if trusted and untrusted:
            return "anchor_plus_wiring_record"
        if any(row.get("kind") == "anchor" for row in trusted):
            return "trusted_anchor"
        if trusted:
            return "trusted_wiring_record"
        return "trusted_anchor"
    return "wiring_record"


def _event_record(event):
    record = {
        "id": event.id,
        "kind": event.kind,
        "time": event.time,
        "capture": event.capture,
        "role": event.role,
        "trusted": event.trusted,
        "note": event.note,
    }
    if event.client_endpoint:
        record["client_endpoint"] = event.client_endpoint
    if event.server_endpoint:
        record["server_endpoint"] = event.server_endpoint
    return record


def _anchor_conflicts(case):
    conflicts = []
    counter = 0
    for capture_id in case.capture_ids:
        events = [e for e in case.anchors + case.wiring if e.capture == capture_id]
        events.sort(key=lambda e: (e.time, 0 if e.kind == "anchor" else 1, e.id))
        trusted = [e for e in events if e.trusted and e.role not in (None, ROLE_UNKNOWN)]
        for left, right in zip(trusted, trusted[1:]):
            if left.role == right.role:
                continue
            between = [e for e in events if not e.trusted and left.time < e.time < right.time]
            counter += 1
            if not between:
                conflicts.append({
                    "id": "CF-A%02d" % counter,
                    "kind": "trusted_anchor_disagreement",
                    "captures": [capture_id],
                    "time_from": left.time,
                    "time_to": right.time,
                    "sources": [_event_record(left), _event_record(right)],
                    "detail": (
                        "Trusted events %s and %s assign mutually exclusive polarities to capture %s "
                        "with no recorded wiring change between them."
                        % (left.id, right.id, capture_id)
                    ),
                    "affected_sessions": [],
                    "affected_claims": [],
                })
                continue
            last_wiring = max(between, key=lambda e: e.time)
            if last_wiring.role not in (None, ROLE_UNKNOWN, right.role):
                conflicts.append({
                    "id": "CF-A%02d" % counter,
                    "kind": "wiring_record_vs_trusted_anchor",
                    "captures": [capture_id],
                    "time_from": last_wiring.time,
                    "time_to": right.time,
                    "sources": [_event_record(last_wiring), _event_record(right)],
                    "detail": (
                        "Wiring record %s says capture %s has polarity %s, but trusted event %s "
                        "independently says %s; the hypotheses are mutually exclusive."
                        % (last_wiring.id, capture_id, last_wiring.role, right.id, right.role)
                    ),
                    "affected_sessions": [],
                    "affected_claims": [],
                })
    return conflicts


def _overlaps(time_value, conflict):
    return conflict["time_from"] <= time_value <= conflict["time_to"]


def _resolve_polarity_at(case, capture_id, when, anchor_conflicts):
    events = [e for e in case.anchors + case.wiring if e.capture == capture_id]
    events.sort(key=lambda e: (e.time, 0 if e.kind == "anchor" else 1, e.id))
    before = [e for e in events if e.time <= when]
    after = [e for e in events if e.time > when]
    latest = before[-1] if before else None
    latest_trusted = None
    for event in reversed(before):
        if event.trusted:
            latest_trusted = event
            break

    trace = []
    if latest_trusted is not None:
        trace.append(latest_trusted)
        if latest is not None and latest is not latest_trusted and latest.time >= latest_trusted.time:
            trace.extend(e for e in before if latest_trusted.time <= e.time and e is not latest_trusted)
    elif latest is not None:
        trace.append(latest)
    role = None
    status = "unknown"
    note = ""
    if latest is not None:
        role = latest.role
        if latest.trusted:
            status = "confirmed" if latest.kind == "anchor" else "supported"
            note = "Polarity taken from the latest trusted %s at or before the sample." % latest.kind
        elif latest_trusted is not None:
            status = "supported"
            note = (
                "Trusted anchor baseline plus a later recorded wiring change supports this "
                "polarity; the wiring record alone would only be a candidate."
            )
        else:
            status = "candidate"
            note = "Only an untrusted wiring record (or untrusted event) supports this polarity."
    elif after:
        # A later trusted anchor can backfill a short unanchored prefix, but the
        # inference is weaker because an earlier rewire cannot be excluded.
        later_trusted = next((e for e in after if e.trusted), None)
        chosen = later_trusted or after[0]
        role = chosen.role
        status = "candidate"
        trace = [chosen]
        note = "Polarity backfilled from the next event; no earlier trusted anchor brackets this time."
    else:
        note = "No anchor or wiring record covers this capture/time."

    active_conflicts = [c for c in anchor_conflicts if c["captures"] and capture_id in c["captures"] and _overlaps(when, c)]
    if active_conflicts:
        status = "conflict"
        note = "Mutually exclusive anchor/wiring evidence overlaps this sample."

    resolved_endpoints = None
    for event in reversed(trace):
        if event.client_endpoint and event.server_endpoint:
            resolved_endpoints = {
                "client": event.client_endpoint,
                "server": event.server_endpoint,
            }
            break
    return {
        "capture": capture_id,
        "time": when,
        "role": role,
        "status": status,
        "note": note,
        "anchor_trace": [_event_record(e) for e in trace],
        "conflict_ids": [c["id"] for c in active_conflicts],
        "endpoint_roles": resolved_endpoints,
    }


def _capture_is_unidirectional(session, capture_id):
    sources = {p.src_endpoint for p in session.packets if p.capture_id == capture_id}
    return len(sources) == 1


def _session_capture_source_endpoint(session, capture_id):
    sources = {p.src_endpoint for p in session.packets if p.capture_id == capture_id}
    return next(iter(sources)) if len(sources) == 1 else None


def _pick_sample_time(session):
    return sum(p.timestamp for p in session.packets) / float(len(session.packets))


def _unique_trace(records):
    seen = set()
    result = []
    for record in records:
        key = (record.get("id"), record.get("time"), record.get("capture"), record.get("role"))
        if key not in seen:
            seen.add(key)
            result.append(record)
    result.sort(key=lambda r: (r.get("time", 0), r.get("id") or ""))
    return result


def _best_epoch_trace(case, session, anchor_conflicts):
    trace = []
    resolutions = []
    for capture_id in sorted(session.capture_ids):
        packets = [p for p in session.packets if p.capture_id == capture_id]
        when = sum(p.timestamp for p in packets) / float(len(packets)) if packets else _pick_sample_time(session)
        resolution = _resolve_polarity_at(case, capture_id, when, anchor_conflicts)
        resolutions.append(resolution)
        trace.extend(resolution["anchor_trace"])
    return resolutions, _unique_trace(trace)


# ---------------------------------------------------------------------------
# Session direction verdicts


def _direction_status_rank(status):
    return {
        "confirmed": 5,
        "supported": 4,
        "candidate": 3,
        "claimed": 2,
        "undetermined": 1,
        "conflict": 0,
    }.get(status, 0)


def _matching_claims_for_session(case, session):
    matches = []
    start = min(p.timestamp for p in session.packets)
    end = max(p.timestamp for p in session.packets)
    for claim in case.claims:
        if claim.capture not in session.capture_ids:
            continue
        if claim.sample is not None:
            if not _sample_matches(claim.sample, session):
                continue
        elif claim.time_to < start or claim.time_from > end:
            continue
        matches.append(claim)
    return matches


def _session_direction_without_handshake(case, session, anchor_conflicts):
    evidence = []
    trace = []
    per_capture = []
    mapped_directions = set()
    statuses = []
    for capture_id in sorted(session.capture_ids):
        capture_packets = [p for p in session.packets if p.capture_id == capture_id]
        when = sum(p.timestamp for p in capture_packets) / float(len(capture_packets))
        resolution = _resolve_polarity_at(case, capture_id, when, anchor_conflicts)
        trace.extend(resolution["anchor_trace"])
        unidirectional = _capture_is_unidirectional(session, capture_id)
        source_endpoint = _session_capture_source_endpoint(session, capture_id)
        direction = UNKNOWN
        role = resolution["role"]
        usable = False
        if role in (ROLE_CLIENT, ROLE_SERVER) and unidirectional:
            direction = _direction_for_role(role)
            usable = True
            mapped_directions.add(direction)
            statuses.append(resolution["status"])
            evidence.append({
                "kind": _epoch_evidence_kind(resolution),
                "capture": capture_id,
                "role": role,
                "status": resolution["status"],
                "refs": [r.get("id") for r in resolution["anchor_trace"]],
                "detail": resolution["note"],
            })
        elif resolution["endpoint_roles"] and direction == UNKNOWN:
            client = resolution["endpoint_roles"]["client"]
            server = resolution["endpoint_roles"]["server"]
            dirs = set()
            for packet in capture_packets:
                src = _format_endpoint(packet.src_ip, packet.sport)
                dst = _format_endpoint(packet.dst_ip, packet.dport)
                if src == client and dst == server:
                    dirs.add(CLIENT_TO_SERVER)
                elif src == server and dst == client:
                    dirs.add(SERVER_TO_CLIENT)
            if dirs:
                direction = next(iter(dirs)) if len(dirs) == 1 else BIDIRECTIONAL
                usable = True
                mapped_directions.add(direction)
                statuses.append(resolution["status"])
                evidence.append({
                    "kind": "trusted_anchor_endpoint_roles",
                    "capture": capture_id,
                    "status": resolution["status"],
                    "refs": [r.get("id") for r in resolution["anchor_trace"]],
                    "detail": "Trusted event supplied explicit client/server endpoints.",
                })
        per_capture.append({
            "capture": capture_id,
            "observed_direction": direction,
            "source_endpoint": _format_endpoint(*source_endpoint) if source_endpoint else None,
            "epoch_status": resolution["status"],
            "epoch_role": role,
            "usable_for_direction": usable,
        })
    trace = _unique_trace(trace)
    if not evidence:
        return None, evidence, trace, per_capture
    if BIDIRECTIONAL in mapped_directions or len(mapped_directions) > 1:
        value = BIDIRECTIONAL
    else:
        value = next(iter(mapped_directions))
    if statuses and all(status in ("confirmed", "supported") for status in statuses):
        status = "supported"
    elif any(status == "conflict" for status in statuses):
        status = "conflict"
        value = UNKNOWN
    else:
        status = "candidate"
    return {
        "status": status,
        "value": value,
        "candidate_directions": (
            [CLIENT_TO_SERVER, SERVER_TO_CLIENT] if status == "conflict" else []
        ),
        "basis": "Mirror polarity inherited from a trusted anchor or wiring record; no linked TCP handshake for this session.",
    }, evidence, trace, per_capture


def _analyse_session_direction(case, session, handshake, anchor_conflicts):
    per_capture = _capture_direction_info(session, handshake)
    resolutions, trace = _best_epoch_trace(case, session, anchor_conflicts)
    evidence = []
    status = "undetermined"
    value = UNKNOWN
    basis = ""
    candidate_directions = []

    if handshake["state"] in ("full", "two_way"):
        status = "confirmed"
        dirs = set()
        for bucket in per_capture:
            direction = bucket["observed_direction"]
            if direction == BIDIRECTIONAL:
                dirs.add(CLIENT_TO_SERVER)
                dirs.add(SERVER_TO_CLIENT)
            elif direction != UNKNOWN:
                dirs.add(direction)
        if len(dirs) == 2:
            value = BIDIRECTIONAL
        elif len(dirs) == 1:
            value = next(iter(dirs))
        else:
            value = UNKNOWN
        refs = [segment["ref"] for segment in handshake["segments"]]
        evidence.append({
            "kind": "tcp_handshake",
            "state": handshake["state"],
            "cross_capture": handshake["cross_capture"],
            "refs": refs,
            "detail": (
                "SYN, SYN-ACK%s are connected by sequence/acknowledgement numbers."
                % (", and final ACK" if handshake["state"] == "full" else " (final ACK absent)")
            ),
        })
        basis = "Linked TCP handshake establishes which endpoint initiated the connection."
    elif handshake["state"] in ("syn_only", "synack_only"):
        status = "candidate"
        dirs = set()
        for bucket in per_capture:
            if bucket["observed_direction"] != UNKNOWN:
                dirs.add(bucket["observed_direction"])
        if len(dirs) == 2:
            value = BIDIRECTIONAL
        elif dirs:
            value = next(iter(dirs))
        else:
            value = UNKNOWN
        refs = [segment["ref"] for segment in handshake["segments"]]
        evidence.append({
            "kind": "tcp_handshake_half",
            "state": handshake["state"],
            "refs": refs,
            "detail": "Only one side of the TCP handshake was captured; kept as a candidate.",
        })
        basis = "Half-handshake: direction is retained as a candidate, not a confirmed verdict."
        candidate_directions = [value] if value in (CLIENT_TO_SERVER, SERVER_TO_CLIENT) else [CLIENT_TO_SERVER, SERVER_TO_CLIENT]

        # A half-handshake can still disagree with a trusted anchor.  Report the
        # contradiction instead of silently believing either side.
        for resolution in resolutions:
            role = resolution.get("role")
            if role in (ROLE_CLIENT, ROLE_SERVER):
                inferred_role = _role_for_direction(value)
                if inferred_role in (ROLE_CLIENT, ROLE_SERVER) and inferred_role != role:
                    status = "conflict"
                    value = UNKNOWN
                    candidate_directions = [CLIENT_TO_SERVER, SERVER_TO_CLIENT]
                    basis = (
                        "The half-handshake points one way, while the trusted anchor/wiring epoch "
                        "points the other way; the assumptions are mutually exclusive."
                    )
    else:
        fallback, fallback_evidence, fallback_trace, fallback_per_capture = _session_direction_without_handshake(
            case, session, anchor_conflicts
        )
        if fallback is not None:
            status = fallback["status"]
            value = fallback["value"]
            basis = fallback["basis"]
            candidate_directions = list(fallback.get("candidate_directions") or [])
            evidence.extend(fallback_evidence)
            per_capture = fallback_per_capture
            trace = _unique_trace(trace + fallback_trace)

    # If no handshake or anchor was available, use claims only as a claim, never
    # as independent direction proof.
    claims = _matching_claims_for_session(case, session)
    if status == "undetermined" and claims:
        claim_dirs = {claim.direction for claim in claims}
        if len(claim_dirs) == 1:
            value = next(iter(claim_dirs))
            status = "claimed"
            basis = "No independent direction evidence; work-order claim shown as a claim only."
            evidence.append({
                "kind": "work_order_claim",
                "refs": [claim.id for claim in claims],
                "detail": "Reported for comparison, not treated as proof.",
            })
        else:
            status = "conflict"
            basis = "Overlapping work-order claims disagree and no independent evidence resolves them."
            value = UNKNOWN
            candidate_directions = sorted(claim_dirs)

    return {
        "status": status,
        "value": value,
        "basis": basis,
        "evidence": evidence,
        "anchor_trace": trace,
        "candidate_directions": candidate_directions,
        "epoch_resolutions": [
            {
                "capture": r["capture"],
                "role": r["role"],
                "status": r["status"],
                "conflict_ids": r["conflict_ids"],
            } for r in resolutions
        ],
    }, per_capture, claims


# ---------------------------------------------------------------------------
# Claims, opinions, and disputes


def _session_value(session, key, default=None):
    """Read a field from either a session dict or an internal draft."""
    if isinstance(session, dict):
        return session.get(key, default)
    return getattr(session, key, default)


def _session_packets(session):
    return _session_value(session, "packets", []) or []


def _session_capture_ids(session):
    value = _session_value(session, "captures")
    if value is not None:
        return set(value)
    value = _session_value(session, "capture_ids")
    return set(value or [])


def _session_flow_key(session):
    return _session_value(session, "flow_key")


def _session_id(session):
    return str(_session_value(session, "id", ""))


def _sample_matches(selector, session):
    if selector is None:
        return False
    if isinstance(selector, str):
        text = selector.strip()
        if text.lower() == _session_id(session).lower():
            return True
        if text == _format_flow(_session_flow_key(session)):
            return True
        for packet in _session_packets(session):
            if text in (packet.ref, "%s:%d" % (packet.capture_id, packet.index)):
                return True
        return False
    if isinstance(selector, dict):
        if selector.get("session_id") and str(selector["session_id"]).lower() != _session_id(session).lower():
            return False
        if selector.get("flow") and str(selector["flow"]) != _format_flow(_session_flow_key(session)):
            return False
        capture = selector.get("capture") or selector.get("capture_id")
        if capture and str(capture) not in _session_capture_ids(session):
            return False
        packets = _session_packets(session)
        if not packets:
            return False
        start = min(p.timestamp for p in packets)
        end = max(p.timestamp for p in packets)
        if selector.get("time_from") is not None and _parse_time(selector["time_from"]) > end:
            return False
        if selector.get("time_to") is not None and _parse_time(selector["time_to"]) < start:
            return False
        ref = selector.get("ref")
        if ref and not any(p.ref == str(ref) or "%s:%d" % (p.capture_id, p.index) == str(ref) for p in packets):
            return False
        packet_index = selector.get("packet_index", selector.get("index"))
        if packet_index is not None:
            if not any(p.index == int(packet_index) for p in packets):
                return False
        src = selector.get("src") or selector.get("src_ip")
        dst = selector.get("dst") or selector.get("dst_ip")
        sport = selector.get("sport") or selector.get("src_port")
        dport = selector.get("dport") or selector.get("dst_port")
        if src or dst or sport or dport:
            found = False
            for packet in packets:
                if src and str(src) != packet.src_ip:
                    continue
                if dst and str(dst) != packet.dst_ip:
                    continue
                if sport is not None and int(sport) != packet.sport:
                    continue
                if dport is not None and int(dport) != packet.dport:
                    continue
                found = True
                break
            if not found:
                return False
        return True
    return False


def _attach_opinions_and_disputes(case, session, direction):
    opinions = []
    for opinion in case.opinions:
        if _sample_matches(opinion.sample, session):
            opinions.append({
                "investigator": opinion.investigator,
                "direction": opinion.direction,
                "note": opinion.note,
                "sample": opinion.sample,
            })
    if not opinions:
        return None
    distinct = {row["direction"] for row in opinions if row["direction"] in (CLIENT_TO_SERVER, SERVER_TO_CLIENT)}
    if len(distinct) < 2:
        return {
            "status": "no_disagreement",
            "opinions": opinions,
            "why_pending": None,
        }
    dispute = {
        "session": _session_id(session),
        "status": "disputed",
        "opinions": opinions,
        "evidence_status": direction["status"],
        "evidence": direction["evidence"],
        "handshake_state": (_session_value(session, "handshake", {}) or {}).get("state"),
        "packet_refs": [p.ref for p in _session_packets(session)[:20]],
    }
    if direction["status"] in ("candidate", "undetermined", "claimed"):
        direction["status"] = "undetermined"
        direction["value"] = UNKNOWN
        direction["candidate_directions"] = sorted(
            set(direction.get("candidate_directions") or []) | distinct
        )
        direction["basis"] = (
            "Investigators disagree on a half-handshake sample. The sample remains a candidate "
            "because the captured segments do not link to a reciprocal SYN-ACK/final ACK; it is "
            "not promoted to a confirmed session direction on investigator opinion alone."
        )
        dispute["status"] = "undetermined"
        dispute["why_pending"] = (
            "The half-handshake leaves both investigator assignments consistent with the "
            "captured bytes. A reciprocal handshake segment with matching sequence/acknowledgement "
            "numbers is required to connect the sample; without that link, the sample is retained "
            "as a candidate even if a nearby anchor is available."
        )
    elif direction["status"] in ("confirmed", "supported"):
        dispute["status"] = "resolved_by_evidence"
        dispute["why_pending"] = None
        dispute["resolution"] = (
            "The linked handshake or trusted anchor independently determines the direction, so "
            "the disagreement is resolved by evidence rather than by investigator opinion."
        )
    else:
        dispute["status"] = "undetermined"
        dispute["why_pending"] = (
            "Existing evidence is contradictory; the conflicting sources must be reconciled "
            "before either opinion can be adopted."
        )
    return dispute


def _claim_role(claim):
    return _role_for_direction(claim.direction)


def _claim_verdict(claim, case, sessions, polarity_samples, anchor_conflicts):
    trace = []
    evidence = []
    conflicts = []
    window_note = None
    claimed_role = _claim_role(claim)

    if claim.sample is not None:
        matched = [s for s in sessions if _sample_matches(claim.sample, s)]
        if not matched:
            return _claim_result(
                claim, "undetermined", "none",
                "The claim's sample selector did not match any discovered TCP session.",
                trace, evidence, conflicts,
            )
        values = []
        for session in matched:
            direction = session["direction"]
            if direction["status"] == "conflict" or direction["value"] == UNKNOWN:
                conflicts.append({"kind": "session_conflict", "sources": [session["id"]]})
            values.append((session["id"], direction["status"], direction["value"]))
            trace.extend(direction.get("anchor_trace") or [])
            evidence.extend(direction.get("evidence") or [])
        known_values = {value for _sid, _status, value in values if value in (CLIENT_TO_SERVER, SERVER_TO_CLIENT, BIDIRECTIONAL)}
        if conflicts or UNKNOWN in {value for _sid, _status, value in values}:
            return _claim_result(
                claim, "conflict", "mixed",
                "Matched session evidence is contradictory or undetermined.",
                trace, evidence, conflicts,
            )
        if len(known_values) > 1:
            return _claim_result(
                claim, "conflict", "mixed",
                "The sample resolves to mutually exclusive directions across matched sessions.",
                trace, evidence, conflicts,
            )
        value = next(iter(known_values))
        strongest = max((status for _sid, status, _v in values), key=_direction_status_rank)
        if claim.direction == BIDIRECTIONAL:
            match = value == BIDIRECTIONAL
        else:
            match = value == claim.direction and value != BIDIRECTIONAL
        if value == BIDIRECTIONAL and claim.direction in (CLIENT_TO_SERVER, SERVER_TO_CLIENT):
            return _claim_result(
                claim, "conflict", "mixed",
                "The sample contains both directions, so a single-direction claim is too narrow.",
                trace, evidence, conflicts,
            )
        if match:
            verdict = {
                "confirmed": "confirmed",
                "supported": "supported",
                "candidate": "candidate",
                "claimed": "candidate",
                "undetermined": "undetermined",
                "conflict": "conflict",
            }.get(strongest, "undetermined")
        else:
            verdict = "reversed" if strongest in ("confirmed", "supported") else "contradicted_candidate"
        return _claim_result(
            claim, verdict, strongest,
            "Compared against the matched session's %s direction evidence." % strongest,
            trace, evidence, conflicts,
        )

    # Capture-window claim: first use linked handshakes that actually started in
    # the window, then fall back to the anchored polarity epoch.
    direct = [
        sample for sample in polarity_samples
        if sample["capture"] == claim.capture
        and sample["status"] == "strong"
        and claim.time_from <= sample["time"] <= claim.time_to
    ]
    if direct:
        roles = {sample["source_role"] for sample in direct if sample["source_role"] != ROLE_BIDIRECTIONAL}
        if any(sample["source_role"] == ROLE_BIDIRECTIONAL for sample in direct):
            if claimed_role == ROLE_BIDIRECTIONAL and not roles:
                for sample in direct:
                    trace.extend(sample.get("anchor_trace") or [])
                    evidence.extend(sample.get("evidence") or [])
                return _claim_result(
                    claim, "confirmed", "handshake",
                    "Linked handshake(s) in the window show both directions, matching the bidirectional claim.",
                    trace, evidence, conflicts,
                )
            return _claim_result(
                claim, "conflict", "handshake",
                "A linked handshake in this window shows both directions on this capture; "
                "the capture is not unidirectional, so a single-direction claim is too narrow.",
                trace, evidence, conflicts,
            )
        if len(roles) > 1:
            conflicts.append({
                "kind": "handshake_polarity_disagreement",
                "sources": [sample["session"] for sample in direct],
            })
            return _claim_result(
                claim, "conflict", "handshake",
                "Different linked handshakes in the same capture/window imply mutually exclusive mirror polarities.",
                trace, evidence, conflicts,
            )
        role = next(iter(roles)) if roles else ROLE_UNKNOWN
        for sample in direct:
            trace.extend(sample.get("anchor_trace") or [])
            evidence.extend(sample.get("evidence") or [])
            if sample.get("conflict_ids"):
                conflicts.append({
                    "kind": "source_conflict",
                    "sources": list(sample["conflict_ids"]),
                })
        if role == claimed_role:
            return _claim_result(
                claim, "confirmed", "handshake",
                "Linked TCP handshake(s) in the window agree with the claimed direction.",
                trace, evidence, conflicts,
            )
        return _claim_result(
            claim, "reversed", "handshake",
            "Linked TCP handshake(s) in the window establish the opposite direction.",
            trace, evidence, conflicts,
        )

    sample_times = [claim.time_from, claim.time_to]
    if claim.time_from == float("-inf") or claim.time_to == float("inf"):
        sample_times = [value for value in sample_times if value not in (float("-inf"), float("inf"))]
    if not sample_times:
        for event in case.anchors + case.wiring:
            if event.capture == claim.capture:
                sample_times.append(event.time)
    if not sample_times:
        sample_times = [0.0]
    if claim.time_from != float("-inf") and claim.time_to != float("inf"):
        sample_times.append((claim.time_from + claim.time_to) / 2.0)
    resolutions = [_resolve_polarity_at(case, claim.capture, when, anchor_conflicts) for when in sample_times]
    roles = {r["role"] for r in resolutions if r["role"] in (ROLE_CLIENT, ROLE_SERVER, ROLE_BIDIRECTIONAL)}
    for resolution in resolutions:
        trace.extend(resolution["anchor_trace"])
        conflicts.extend(resolution["conflict_ids"])
        if resolution["status"] == "conflict":
            conflicts.append({"kind": "epoch_conflict", "sources": resolution["conflict_ids"]})
    if len(roles) > 1:
        conflicts.append({
            "kind": "claim_window_mixed_polarity",
            "sources": [r["anchor_trace"] for r in resolutions],
        })
        return _claim_result(
            claim, "conflict", "mixed",
            "The claim window spans mutually exclusive polarities; split the window at the wiring/anchor transition.",
            trace, evidence, conflicts, window_note,
        )
    resolution = resolutions[-1] if resolutions else None
    if any(r.get("status") == "conflict" for r in resolutions):
        return _claim_result(
            claim, "conflict", "mixed",
            "Overall capture polarity is occupied by mutually exclusive trusted evidence; "
            "the claim cannot be confirmed or reversed until the conflict is resolved.",
            trace, evidence, conflicts, window_note,
        )
    if resolution is None or resolution["role"] in (None, ROLE_UNKNOWN):
        return _claim_result(
            claim, "undetermined", "none",
            "No linked handshake, trusted anchor, or wiring record covers this capture/time.",
            trace, evidence, conflicts, window_note,
        )
    role = resolution["role"]
    evidence.append({
        "kind": _epoch_evidence_kind(resolution),
        "capture": claim.capture,
        "role": role,
        "status": resolution["status"],
        "refs": [r.get("id") for r in resolution["anchor_trace"]],
        "detail": resolution["note"],
    })
    if role == ROLE_BIDIRECTIONAL and claimed_role in (ROLE_CLIENT, ROLE_SERVER):
        return _claim_result(
            claim, "conflict", resolution["status"],
            "The capture epoch is bidirectional, so a single-direction claim cannot be verified.",
            trace, evidence, conflicts, window_note,
        )
    if role == claimed_role:
        verdict = {
            "confirmed": "confirmed",
            "supported": "supported",
            "candidate": "candidate",
            "conflict": "conflict",
        }.get(resolution["status"], "undetermined")
        return _claim_result(
            claim, verdict, resolution["status"],
            "Trusted/recorded capture polarity agrees with the claim.",
            trace, evidence, conflicts, window_note,
        )
    if resolution["status"] in ("confirmed", "supported"):
        return _claim_result(
            claim, "reversed", resolution["status"],
            "Trusted/anchored capture polarity is the opposite of the claim.",
            trace, evidence, conflicts, window_note,
        )
    return _claim_result(
        claim, "contradicted_candidate", resolution["status"],
        "An untrusted wiring record contradicts the claim, but the polarity is not independently confirmed.",
        trace, evidence, conflicts, window_note,
    )


def _claim_result(claim, verdict, grade, basis, trace, evidence, conflicts, window_note=None):
    trace = _unique_trace(trace or [])
    trusted_ids = [row.get("id") for row in trace if row.get("trusted")]
    result = {
        "id": claim.id,
        "capture": claim.capture,
        "window": [claim.time_from, claim.time_to],
        "claimed_direction": claim.direction,
        "source": claim.source,
        "sample": claim.sample,
        "note": claim.note,
        "verdict": verdict,
        "evidence_grade": grade,
        "basis": basis,
        "anchor_trace": trace,
        "trusted_anchor_ids": trusted_ids,
        "evidence": evidence,
        "conflicts": conflicts,
    }
    if verdict == "reversed":
        result["reversal_confirmed"] = True
        if not trusted_ids:
            result["traceability_warning"] = (
                "Reversal is supported by a linked handshake, but no trusted anchor was configured "
                "for a time-anchor traceback."
            )
    else:
        result["reversal_confirmed"] = False
    if window_note:
        result["window_note"] = window_note
    return result


# ---------------------------------------------------------------------------
# Conflict assembly


def _session_handshake_conflicts(case, sessions, anchor_conflicts):
    conflicts = []
    counter = 0
    for session in sessions:
        handshake = session["handshake"]
        if handshake["state"] not in ("full", "two_way", "syn_only", "synack_only"):
            continue
        for bucket in session["per_capture"]:
            role = bucket.get("observed_source_role")
            if role not in (ROLE_CLIENT, ROLE_SERVER):
                continue
            when = (bucket["first_time"] + bucket["last_time"]) / 2.0
            resolution = _resolve_polarity_at(case, bucket["capture"], when, anchor_conflicts)
            if resolution["role"] not in (ROLE_CLIENT, ROLE_SERVER):
                continue
            if resolution["role"] == role:
                continue
            counter += 1
            conflict = {
                "id": "CF-H%02d" % counter,
                "kind": (
                    "handshake_vs_trusted_epoch"
                    if handshake["state"] in ("full", "two_way")
                    else "half_handshake_vs_trusted_epoch"
                ),
                "captures": [bucket["capture"]],
                "time_from": bucket["first_time"],
                "time_to": bucket["last_time"],
                "sources": [
                    {
                        "kind": "tcp_handshake",
                        "session": session["id"],
                        "state": handshake["state"],
                        "refs": [segment["ref"] for segment in handshake["segments"]],
                        "role": role,
                    },
                    {
                        "kind": "anchor_or_wiring_trace",
                        "events": resolution["anchor_trace"],
                        "role": resolution["role"],
                        "status": resolution["status"],
                    },
                ],
                "detail": (
                    "TCP segments in %s imply source role %s, while the anchor/wiring epoch implies %s; "
                    "the two hypotheses are mutually exclusive."
                    % (bucket["capture"], role, resolution["role"])
                ),
                "affected_sessions": [session["id"]],
                "affected_claims": [],
            }
            conflicts.append(conflict)
            session["direction"].setdefault("conflict_ids", []).append(conflict["id"])
            if handshake["state"] in ("syn_only", "synack_only"):
                session["direction"]["status"] = "conflict"
                session["direction"]["value"] = UNKNOWN
                session["direction"]["basis"] = conflict["detail"]
    return conflicts


def _claim_conflicts(claims):
    conflicts = []
    counter = 0
    for i, left in enumerate(claims):
        for right in claims[i + 1:]:
            if left["capture"] != right["capture"]:
                continue
            if left["window"][1] < right["window"][0] or right["window"][1] < left["window"][0]:
                continue
            if left["sample"] is not None or right["sample"] is not None:
                continue
            left_role = _role_for_direction(left["claimed_direction"])
            right_role = _role_for_direction(right["claimed_direction"])
            if left_role == right_role:
                continue
            counter += 1
            conflicts.append({
                "id": "CF-C%02d" % counter,
                "kind": "overlapping_claims_disagree",
                "captures": [left["capture"]],
                "time_from": max(left["window"][0], right["window"][0]),
                "time_to": min(left["window"][1], right["window"][1]),
                "sources": [
                    {"kind": "claim", "id": left["id"], "direction": left["claimed_direction"], "source": left["source"]},
                    {"kind": "claim", "id": right["id"], "direction": right["claimed_direction"], "source": right["source"]},
                ],
                "detail": "Two overlapping claims assign mutually exclusive directions to the same capture window.",
                "affected_sessions": [],
                "affected_claims": [left["id"], right["id"]],
            })
    return conflicts


# ---------------------------------------------------------------------------
# Top-level audit


def _polarity_samples(case, sessions):
    samples = []
    for session in sessions:
        handshake = session["handshake"]
        if handshake["state"] not in ("full", "two_way", "syn_only", "synack_only"):
            continue
        for bucket in session["per_capture"]:
            role = bucket["observed_source_role"]
            if role not in (ROLE_CLIENT, ROLE_SERVER, ROLE_BIDIRECTIONAL):
                continue
            status = "strong" if handshake["state"] in ("full", "two_way") else "candidate"
            capture_trace = [
                row for row in session["direction"].get("anchor_trace") or []
                if row.get("capture") == bucket["capture"]
            ]
            samples.append({
                "session": session["id"],
                "capture": bucket["capture"],
                "time": (bucket["first_time"] + bucket["last_time"]) / 2.0,
                "source_role": role,
                "status": status,
                "evidence": session["direction"]["evidence"],
                "anchor_trace": capture_trace,
                "conflict_ids": list(session["direction"].get("conflict_ids") or []),
            })
    return samples


def audit_case(case):
    """Run the audit and return a JSON-serialisable report dictionary."""
    capture_data = [read_capture(spec) for spec in case.captures]
    drafts = _build_sessions(capture_data, case.options)
    anchor_conflicts = _anchor_conflicts(case)
    sessions = []
    for draft in drafts:
        handshake = _analyse_handshake(draft.packets, case.options)
        direction, per_capture, claims = _analyse_session_direction(case, draft, handshake, anchor_conflicts)
        session = {
            "id": draft.id,
            "flow_key": draft.flow_key,
            "flow": _format_flow(draft.flow_key),
            "captures": sorted(draft.capture_ids),
            "time_from": min(p.timestamp for p in draft.packets),
            "time_to": max(p.timestamp for p in draft.packets),
            "packet_count": len(draft.packets),
            "packets": draft.packets,
            "handshake": handshake,
            "direction": direction,
            "per_capture": per_capture,
            "claim_ids": [claim.id for claim in claims],
            "display_only": {
                "packet_count": len(draft.packets),
                "ports": dict(Counter(
                    port for packet in draft.packets for port in (packet.sport, packet.dport)
                )),
                "note": (
                    "Ports and packet counts are shown for context only. They are not used "
                    "to decide a session's direction."
                ),
            },
        }
        sessions.append(session)

    # Attach investigator opinions/disputes before claims are evaluated so an
    # unresolved half-handshake becomes undetermined consistently everywhere.
    disputes = []
    for session in sessions:
        dispute = _attach_opinions_and_disputes(case, session, session["direction"])
        session["opinions"] = dispute["opinions"] if dispute else []
        session["dispute"] = dispute
        if dispute and len(dispute.get("opinions") or []) >= 2:
            disputes.append(dispute)

    polarity_samples = _polarity_samples(case, sessions)
    claims = [_claim_verdict(claim, case, sessions, polarity_samples, anchor_conflicts) for claim in case.claims]
    claim_by_id = {claim["id"]: claim for claim in claims}
    for session in sessions:
        session["claim_ids"] = [
            claim_id for claim_id in session["claim_ids"]
            if claim_id in claim_by_id
        ]

    handshake_conflicts = _session_handshake_conflicts(case, sessions, anchor_conflicts)
    claim_conflicts = _claim_conflicts(claims)
    conflicts = anchor_conflicts + handshake_conflicts + claim_conflicts

    # Attach affected claims/sessions to conflicts in a second pass.
    for conflict in conflicts:
        for claim in claims:
            if claim["capture"] not in conflict["captures"]:
                continue
            claim_from = claim["window"][0] if claim["window"][0] != float("-inf") else conflict["time_from"]
            claim_to = claim["window"][1] if claim["window"][1] != float("inf") else conflict["time_to"]
            if claim_from <= conflict["time_to"] and conflict["time_from"] <= claim_to:
                conflict["affected_claims"].append(claim["id"])
        for session in sessions:
            if set(session["captures"]) & set(conflict["captures"]):
                if session["time_to"] >= conflict["time_from"] and session["time_from"] <= conflict["time_to"]:
                    if session["id"] not in conflict["affected_sessions"]:
                        conflict["affected_sessions"].append(session["id"])
        conflict["affected_claims"] = list(dict.fromkeys(conflict.get("affected_claims") or []))
        conflict["affected_sessions"] = list(dict.fromkeys(conflict.get("affected_sessions") or []))

    for claim in claims:
        conflict_ids = []
        for conflict in conflicts:
            if claim["id"] in conflict.get("affected_claims", []):
                conflict_ids.append(conflict["id"])
        for row in claim.get("conflicts") or []:
            if isinstance(row, dict):
                if row.get("kind") in ("epoch_conflict", "source_conflict"):
                    conflict_ids.extend(row.get("sources") or [])
        claim["conflict_ids"] = sorted(set(conflict_ids))

    for session in sessions:
        session.pop("packets", None)
        direction = session["direction"]
        for row in direction.get("evidence") or []:
            if row.get("kind") == "tcp_handshake_half":
                session["candidate_reason"] = row.get("detail")
        if direction["status"] in ("candidate", "claimed", "undetermined", "conflict"):
            session["candidate"] = True
        else:
            session["candidate"] = False

    candidates = []
    undetermined = []
    for session in sessions:
        direction = session["direction"]
        if session["candidate"]:
            candidates.append({
                "session": session["id"],
                "flow": session["flow"],
                "handshake_state": session["handshake"]["state"],
                "direction_status": direction["status"],
                "observed_direction": direction["value"],
                "candidate_directions": direction.get("candidate_directions") or [],
                "reason": session.get("candidate_reason") or direction.get("basis"),
                "refs": [segment["ref"] for segment in session["handshake"].get("segments") or []],
            })
        if direction["status"] in ("undetermined", "conflict"):
            undetermined.append(session["id"])

    reversed_claims = [claim for claim in claims if claim["verdict"] == "reversed"]
    summary = {
        "captures": len(capture_data),
        "sessions": len(sessions),
        "confirmed_sessions": sum(1 for s in sessions if s["direction"]["status"] == "confirmed"),
        "supported_sessions": sum(1 for s in sessions if s["direction"]["status"] == "supported"),
        "candidate_sessions": len(candidates),
        "undetermined_sessions": sum(1 for s in sessions if s["direction"]["status"] == "undetermined"),
        "conflict_sessions": sum(1 for s in sessions if s["direction"]["status"] == "conflict"),
        "claims": len(claims),
        "confirmed_claims": sum(1 for c in claims if c["verdict"] == "confirmed"),
        "reversed_claims": len(reversed_claims),
        "candidate_claims": sum(1 for c in claims if c["verdict"] in ("candidate", "contradicted_candidate")),
        "undetermined_claims": sum(1 for c in claims if c["verdict"] == "undetermined"),
        "conflicts": len(conflicts),
        "disputes": len(disputes),
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": "dpkt.capture_audit",
        "generated_at_utc": _now_utc(),
        "service": case.service,
        "read_only": True,
        "assumptions": [
            "Only linked TCP handshake segments, explicitly trusted anchors, and recorded wiring changes are direction evidence.",
            "Ports and packet counts are displayed for context and are never used to decide direction.",
            "Half-handshakes are retained as candidates, not confirmations.",
            "A trusted anchor is assumed to hold until a later trusted event or recorded wiring change; the trace is reported.",
            "No clock-offset correction is attempted across captures; exact sequence/acknowledgement linkage is preferred.",
        ],
        "captures": [
            {
                "id": data.spec.id,
                "path": str(data.spec.path),
                "declared_direction": data.spec.declared_direction,
                "note": data.spec.note,
                "packet_count": data.packet_count,
                "tcp_packet_count": data.tcp_packet_count,
                "unsupported_count": data.unsupported_count,
                "first_time": data.first_time,
                "last_time": data.last_time,
                "sha256": data.sha256,
                "size_bytes": data.size_bytes,
                "linktype": data.linktype,
                "parse_errors": data.parse_errors,
                "display_only": {
                    "ports": data.port_counts,
                    "packet_count": data.packet_count,
                    "note": "Ports and packet counts are informational; they are not direction evidence.",
                },
            } for data in capture_data
        ],
        "anchors": [_event_record(event) for event in case.anchors],
        "wiring": [_event_record(event) for event in case.wiring],
        "claims": claims,
        "sessions": sessions,
        "candidates": candidates,
        "undetermined": undetermined,
        "conflicts": conflicts,
        "disputes": disputes,
        "reversed_claims": [
            {
                "id": c["id"],
                "capture": c["capture"],
                "window": c["window"],
                "trusted_anchor_ids": c["trusted_anchor_ids"],
                "anchor_trace": c["anchor_trace"],
                "evidence": c["evidence"],
                "basis": c["basis"],
            } for c in reversed_claims
        ],
        "summary": summary,
        "warnings": list(case.warnings),
    }
    return _json_safe(report)


def audit_files(captures, anchors=None, wiring=None, claims=None, opinions=None,
                disputes=None, service="", options=None, base_dir=None):
    """Convenience wrapper around :func:`audit_case`."""
    raw = {
        "captures": captures,
        "anchors": anchors or [],
        "wiring": wiring or [],
        "claims": claims or [],
        "opinions": opinions or [],
        "disputes": disputes or [],
        "service": service,
        "options": options or {},
    }
    case = case_from_dict(raw, base_dir=base_dir)
    return audit_case(case)


def audit_case_file(path):
    return audit_case(load_case(path))


# ---------------------------------------------------------------------------
# Markdown report


def _fmt_time(value):
    if value is None:
        return "n/a"
    if value == float("inf"):
        return "+inf"
    if value == float("-inf"):
        return "-inf"
    try:
        return "%.6f" % float(value)
    except (TypeError, ValueError):
        return str(value)


def _md_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report):
    """Render a human-readable Markdown report."""
    lines = []
    add = lines.append
    add("# Capture Direction Audit")
    add("")
    add("Read-only audit of offline mirrored TCP captures. No capture file is modified.")
    add("")
    if report.get("service"):
        add("**Service:** %s" % report["service"])
        add("")
    add("**Generated (UTC):** %s" % report.get("generated_at_utc"))
    add("")
    add("## Summary")
    add("")
    summary = report.get("summary") or {}
    add("| Metric | Count |")
    add("| --- | ---: |")
    for key in (
        "captures", "sessions", "confirmed_sessions", "supported_sessions",
        "candidate_sessions", "undetermined_sessions", "conflict_sessions",
        "claims", "confirmed_claims", "reversed_claims", "candidate_claims",
        "undetermined_claims", "conflicts", "disputes",
    ):
        add("| %s | %s |" % (key.replace("_", " "), summary.get(key, 0)))
    add("")
    add("## Evidence Rules")
    add("")
    for assumption in report.get("assumptions") or []:
        add("- %s" % assumption)
    add("")
    add("Ports and packet counts are listed only as context and are **not** used as direction evidence.")
    add("")

    add("## Inputs")
    add("")
    add("| Capture | Declared direction | Packets | TCP | SHA-256 | Link type |")
    add("| --- | --- | ---: | ---: | --- | ---: |")
    for capture in report.get("captures") or []:
        add("| %s | %s | %s | %s | `%s` | %s |" % (
            _md_escape(capture["id"]),
            _md_escape(capture.get("declared_direction")),
            capture.get("packet_count"),
            capture.get("tcp_packet_count"),
            (capture.get("sha256") or "")[:16],
            capture.get("linktype"),
        ))
    add("")

    add("## Trusted Time Anchors")
    add("")
    anchors = report.get("anchors") or []
    if not anchors:
        add("_No trusted anchors were supplied._")
    else:
        add("| Anchor | Time | Capture | Polarity role | Trusted | Basis |")
        add("| --- | ---: | --- | --- | --- | --- |")
        for anchor in anchors:
            add("| %s | %s | %s | %s | %s | %s |" % (
                _md_escape(anchor["id"]), _fmt_time(anchor["time"]),
                _md_escape(anchor["capture"]), _md_escape(anchor["role"]),
                anchor["trusted"], _md_escape(anchor.get("note") or ""),
            ))
    add("")

    add("## Wiring Records")
    add("")
    wiring = report.get("wiring") or []
    if not wiring:
        add("_No wiring records were supplied._")
    else:
        add("| Record | Time | Capture | Recorded polarity | Trusted | Note |")
        add("| --- | ---: | --- | --- | --- | --- |")
        for record in wiring:
            add("| %s | %s | %s | %s | %s | %s |" % (
                _md_escape(record["id"]), _fmt_time(record["time"]),
                _md_escape(record["capture"]), _md_escape(record["role"]),
                record["trusted"], _md_escape(record.get("note") or ""),
            ))
    add("")

    add("## Claim Verdicts")
    add("")
    claims = report.get("claims") or []
    if not claims:
        add("_No work-order claims were supplied._")
    else:
        add("| Claim | Capture | Window | Claimed | Verdict | Evidence | Trusted anchors |")
        add("| --- | --- | --- | --- | --- | --- | --- |")
        for claim in claims:
            window = "[%s, %s]" % (_fmt_time(claim["window"][0]), _fmt_time(claim["window"][1]))
            anchors_text = ", ".join(claim.get("trusted_anchor_ids") or []) or "none"
            add("| %s | %s | %s | %s | **%s** | %s | %s |" % (
                _md_escape(claim["id"]), _md_escape(claim["capture"]),
                _md_escape(window), _md_escape(claim["claimed_direction"]),
                _md_escape(claim["verdict"]), _md_escape(claim["evidence_grade"]),
                _md_escape(anchors_text),
            ))
        add("")
        for claim in claims:
            add("### Claim %s" % claim["id"])
            add("")
            add("- Basis: %s" % claim["basis"])
            add("- Verdict: `%s` (evidence: `%s`)" % (claim["verdict"], claim["evidence_grade"]))
            if claim.get("sample") is not None:
                add("- Sample selector: `%s`" % json.dumps(claim["sample"], ensure_ascii=False))
            if claim.get("trusted_anchor_ids"):
                add("- Trusted anchor trace: %s" % ", ".join(claim["trusted_anchor_ids"]))
            if claim.get("traceability_warning"):
                add("- Traceability warning: %s" % claim["traceability_warning"])
            if claim.get("conflict_ids"):
                add("- Related conflicts: %s" % ", ".join(claim["conflict_ids"]))
            add("")

    add("## Sessions")
    add("")
    sessions = report.get("sessions") or []
    if not sessions:
        add("_No TCP sessions were discovered._")
    else:
        add("| Session | Flow | Captures | Handshake | Direction | Status | Packets |")
        add("| --- | --- | --- | --- | --- | --- | ---: |")
        for session in sessions:
            add("| %s | %s | %s | %s | %s | **%s** | %s |" % (
                _md_escape(session["id"]), _md_escape(session["flow"]),
                _md_escape(", ".join(session["captures"])),
                _md_escape(session["handshake"]["state"]),
                _md_escape(session["direction"]["value"]),
                _md_escape(session["direction"]["status"]),
                session["packet_count"],
            ))
        add("")
        for session in sessions:
            add("### Session %s" % session["id"])
            add("")
            add("- Flow: `%s`" % session["flow"])
            add("- Time range: %s .. %s" % (_fmt_time(session["time_from"]), _fmt_time(session["time_to"])))
            add("- Handshake state: `%s`" % session["handshake"]["state"])
            if session["handshake"].get("client"):
                add("- Client (SYN sender): `%s`" % session["handshake"]["client"]["endpoint"])
                add("- Server (SYN-ACK sender): `%s`" % session["handshake"]["server"]["endpoint"])
            add("- Direction: `%s`; status: `%s`" % (
                session["direction"]["value"], session["direction"]["status"]))
            add("- Basis: %s" % session["direction"]["basis"])
            if session["direction"].get("candidate_directions"):
                add("- Candidate directions: %s" % ", ".join(session["direction"]["candidate_directions"]))
            for segment in session["handshake"].get("segments") or []:
                add("  - %s `%s` %s -> %s seq=%s ack=%s" % (
                    segment["role"], segment["ref"], segment["src"], segment["dst"],
                    segment["seq"], segment["ack"],
                ))
            for evidence in session["direction"].get("evidence") or []:
                add("- Evidence `%s`: %s" % (evidence.get("kind"), evidence.get("detail") or ""))
            if session["direction"].get("anchor_trace"):
                ids = [row.get("id") for row in session["direction"]["anchor_trace"] if row.get("id")]
                if ids:
                    add("- Anchor/wiring trace: %s" % ", ".join(ids))
            if session.get("dispute"):
                add("- Investigator opinions: %s" % "; ".join(
                    "%s=%s" % (row["investigator"], row["direction"])
                    for row in session["dispute"].get("opinions") or []
                ))
            add("- Display only (not evidence): packets=%s, ports=%s" % (
                session["display_only"]["packet_count"], session["display_only"]["ports"]))
            add("")
            refs = [
                "%s#%s" % (segment["capture"], segment["packet_index"])
                for segment in session["handshake"].get("segments") or []
            ]
            add("  Packet references: %s" % (", ".join(refs) if refs else "none"))
            add("")

    add("## Candidates")
    add("")
    candidates = report.get("candidates") or []
    if not candidates:
        add("_No candidate sessions._")
    else:
        add("| Session | Handshake | Status | Observed | Candidate directions | Reason | Refs |")
        add("| --- | --- | --- | --- | --- | --- | --- |")
        for candidate in candidates:
            add("| %s | %s | %s | %s | %s | %s | %s |" % (
                _md_escape(candidate["session"]), _md_escape(candidate["handshake_state"]),
                _md_escape(candidate["direction_status"]), _md_escape(candidate["observed_direction"]),
                _md_escape(", ".join(candidate.get("candidate_directions") or []) or "n/a"),
                _md_escape(candidate.get("reason") or ""),
                _md_escape(", ".join(candidate.get("refs") or []) or "n/a"),
            ))
    add("")

    add("## Conflicts")
    add("")
    conflicts = report.get("conflicts") or []
    if not conflicts:
        add("_No mutually exclusive evidence was detected._")
    else:
        for conflict in conflicts:
            add("### %s — %s" % (conflict["id"], conflict["kind"]))
            add("")
            add("- Captures: %s" % ", ".join(conflict.get("captures") or []))
            add("- Time range: %s .. %s" % (_fmt_time(conflict.get("time_from")), _fmt_time(conflict.get("time_to"))))
            add("- Detail: %s" % conflict.get("detail"))
            add("- Sources:")
            for source in conflict.get("sources") or []:
                add("  - `%s`" % json.dumps(source, ensure_ascii=False, sort_keys=True))
            if conflict.get("affected_sessions"):
                add("- Affected sessions: %s" % ", ".join(conflict["affected_sessions"]))
            if conflict.get("affected_claims"):
                add("- Affected claims: %s" % ", ".join(conflict["affected_claims"]))
            add("")

    add("## Investigator Disputes")
    add("")
    disputes = report.get("disputes") or []
    if not disputes:
        add("_No investigator disagreements were supplied or detected._")
    else:
        for dispute in disputes:
            add("### %s — %s" % (dispute["session"], dispute["status"]))
            add("")
            for opinion in dispute.get("opinions") or []:
                add("- %s: `%s`%s" % (
                    opinion["investigator"], opinion["direction"],
                    (" — " + opinion["note"]) if opinion.get("note") else "",
                ))
            add("- Handshake state: `%s`" % dispute.get("handshake_state"))
            add("- Packet references: %s" % ", ".join(dispute.get("packet_refs") or []))
            if dispute.get("why_pending"):
                add("- Why still pending: %s" % dispute["why_pending"])
            if dispute.get("resolution"):
                add("- Resolution: %s" % dispute["resolution"])
            add("")

    add("## Reversal Traceability")
    add("")
    reversed_claims = report.get("reversed_claims") or []
    if not reversed_claims:
        add("_No claim was confirmed as reversed._")
    else:
        for item in reversed_claims:
            add("### Claim %s" % item["id"])
            add("")
            trace = item.get("anchor_trace") or []
            if not trace:
                add("- No trusted anchor was configured for this reversal.")
            for event in trace:
                add("- %s `%s` at %s on %s: role=%s%s" % (
                    "trusted anchor" if event.get("trusted") else "wiring/event",
                    event.get("id"), _fmt_time(event.get("time")), event.get("capture"),
                    event.get("role"), (" — " + event["note"]) if event.get("note") else "",
                ))
            for evidence in item.get("evidence") or []:
                refs = evidence.get("refs") or []
                add("- Evidence `%s`%s" % (
                    evidence.get("kind"),
                    (": " + ", ".join(refs)) if refs else "",
                ))
            add("")

    warnings = report.get("warnings") or []
    if warnings:
        add("## Warnings")
        add("")
        for warning in warnings:
            add("- %s" % warning)
        add("")

    add("## Provenance")
    add("")
    add("Packet references use `capture#index`, where `index` is the zero-based packet position in that offline file.")
    add("")
    return "\n".join(lines)


def write_report(report, json_path=None, markdown_path=None):
    """Write JSON and/or Markdown output.  Capture inputs are never written."""
    if json_path:
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
    if markdown_path:
        with open(markdown_path, "w", encoding="utf-8") as handle:
            handle.write(render_markdown(report))
            handle.write("\n")


# ---------------------------------------------------------------------------
# CLI


def _read_json_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _assemble_cli_case(args):
    if args.case:
        case = load_case(args.case)
        base_dir = None
    else:
        captures = []
        for item in args.capture or []:
            if "=" not in item:
                raise ValueError("--capture must be ID=PATH")
            capture_id, path = item.split("=", 1)
            captures.append({"id": capture_id, "path": path})
        if not captures:
            raise ValueError("supply a case file or at least one --capture ID=PATH")
        raw = {"captures": captures, "service": args.service or ""}
        for option, key in (
            (args.anchors, "anchors"),
            (args.wiring, "wiring"),
            (args.claims, "claims"),
            (args.opinions, "opinions"),
            (args.disputes, "disputes"),
        ):
            if option:
                raw[key] = _read_json_file(option)
        if args.options:
            raw["options"] = _read_json_file(args.options)
        base_dir = Path.cwd()
        case = case_from_dict(raw, base_dir=base_dir)
    if args.service:
        case.service = args.service
    return case


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Read-only dpkt audit of mirror direction / wiring reversal claims for offline TCP captures."
        )
    )
    parser.add_argument("case", nargs="?", help="JSON case file")
    parser.add_argument("--capture", action="append", metavar="ID=PATH",
                        help="capture input when not using a case file (repeatable)")
    parser.add_argument("--anchors", help="JSON list of trusted anchors")
    parser.add_argument("--wiring", help="JSON list of wiring records")
    parser.add_argument("--claims", help="JSON list of work-order direction claims")
    parser.add_argument("--opinions", help="JSON list of investigator opinions")
    parser.add_argument("--disputes", help="JSON list of grouped investigator disputes")
    parser.add_argument("--options", help="JSON object of analysis options")
    parser.add_argument("--service", help="service name/description")
    parser.add_argument("--json", dest="json_out", help="write the full JSON report here")
    parser.add_argument("--markdown", dest="markdown_out", help="write the Markdown report here")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown",
                        help="stdout format when no output file is given")
    parser.add_argument("--strict", action="store_true",
                        help="return non-zero when conflicts or unresolved disputes remain")
    parser.add_argument("--quiet", action="store_true", help="do not print the report to stdout")
    args = parser.parse_args(argv)

    try:
        case = _assemble_cli_case(args)
        report = audit_case(case)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
        return 2

    input_paths = {str(spec.path.resolve()) for spec in case.captures}
    if args.case:
        input_paths.add(str(Path(args.case).expanduser().resolve()))
    for output in (args.json_out, args.markdown_out):
        if output and str(Path(output).expanduser().resolve()) in input_paths:
            parser.error("refusing to overwrite a capture input: %s" % output)

    write_report(report, json_path=args.json_out, markdown_path=args.markdown_out)
    if not args.quiet:
        if args.markdown_out and args.json_out:
            pass
        elif args.markdown_out:
            if args.format == "json":
                print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
        elif args.json_out:
            if args.format == "markdown":
                print(render_markdown(report))
        elif args.format == "json":
            print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
        else:
            print(render_markdown(report))

    if args.strict:
        if report["summary"]["conflicts"]:
            return 2
        if report["summary"]["undetermined_sessions"] or report["summary"]["undetermined_claims"]:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
