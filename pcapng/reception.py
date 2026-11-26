"""Read-only handover reception audit for pcap-ng volumes."""

from collections import defaultdict
from datetime import date, datetime
import hashlib
import io
import os

from . import blocks
from .scanner import FileScanner


__all__ = [
    "Interval",
    "Record",
    "audit_reception",
    "bilateral_gaps",
    "scan_volumes",
]


_START_KEYS = (
    "start", "start_time", "begin", "begin_time", "from_time", "since", "lower"
)
_END_KEYS = (
    "end", "end_time", "finish", "finish_time", "until", "to_time", "stop", "upper"
)
_TIME_KEYS = ("boundary", "handoff_at", "handover_at", "at", "time", "moment")
_SOURCE_KEYS = (
    "source", "source_id", "material_source", "material", "volume", "volume_id",
    "volume_name", "file", "filename", "path", "origin",
)
_TARGET_KEYS = (
    "stream", "handle", "reader", "target", "fileobj", "file_object",
    "data", "bytes", "path", "filename",
)
_FLUSH_KEYS = (
    "flushed_at", "flush_time", "final_flush", "final_flush_at",
    "finalized_at", "landed_at", "final_write_time",
)
_INTERFACE_KEYS = (
    "interface", "interface_id", "iface", "idb", "interface_number", "if_id"
)


class Record(dict):
    """Dictionary with attribute access used in audit results."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class Interval(tuple):
    """A two-endpoint interval that still compares as a plain tuple."""

    def __new__(cls, start, end, meta=None, **kwargs):
        obj = super(Interval, cls).__new__(cls, (start, end))
        values = dict(meta or {})
        values.update(kwargs)
        object.__setattr__(obj, "meta", values)
        return obj

    @property
    def start(self):
        return self[0]

    @property
    def end(self):
        return self[1]

    def __getattr__(self, name):
        meta = object.__getattribute__(self, "meta")
        if name in meta:
            return meta[name]
        raise AttributeError(name)

    def as_dict(self):
        result = dict(self.meta)
        result["start"] = self[0]
        result["end"] = self[1]
        return result


def _first(mapping, keys, default=None):
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            return value
    return default


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if isinstance(value, dict):
        return [value]
    return [value]


def coerce_time(value):
    """Coerce ISO date strings while leaving numeric calibration values intact."""
    if value is None or isinstance(value, (int, float, datetime, date)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return text
    return value


def _time_sort_key(value):
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day).timestamp()
    return value


def _sort_intervals(intervals):
    return sorted(
        intervals,
        key=lambda item: (
            str(type(_time_sort_key(item.start))),
            _safe_sort(_time_sort_key(item.start)),
            _safe_sort(_time_sort_key(item.end)),
            str(item.meta.get("pair_key", "")),
            str(item.meta.get("source", "")),
        ),
    )


def _safe_sort(value):
    try:
        return (0, value)
    except Exception:
        return (1, str(value))


def _is_time_like(value):
    return isinstance(value, (int, float, datetime, date, str)) and not isinstance(value, (bytes, bytearray))


def _is_empty_kind(value):
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    markers = ("empty", "silent", "quiet", "no_packet", "no_traffic", "blank")
    return any(marker in text for marker in markers)


def interval_from(value, default_meta=None):
    """Normalize a tuple, mapping, or :class:`Interval` to an Interval."""
    meta = dict(default_meta or {})
    if isinstance(value, Interval):
        merged = dict(value.meta)
        merged.update(meta)
        return Interval(value.start, value.end, merged)

    if isinstance(value, dict):
        start = _first(value, _START_KEYS)
        end = _first(value, _END_KEYS)
        if start is None and end is None:
            window = value.get("interval") or value.get("range") or value.get("window")
            if isinstance(window, (list, tuple)) and len(window) >= 2:
                start, end = window[0], window[1]
        boundary = _first(value, _TIME_KEYS)
        if start is None:
            start = boundary
        if end is None:
            end = boundary if boundary is not None else start
        for target, keys in (
            ("id", ("id", "interval_id", "window_id")),
            ("label", ("name", "label", "title")),
            ("kind", ("kind", "type", "category", "window_type", "status")),
            ("group", ("group", "team", "investigation_group", "party", "custodian", "owner", "side")),
            ("location", ("location", "site", "capture_location", "probe")),
            ("source", _SOURCE_KEYS),
            ("flushed_at", _FLUSH_KEYS),
            ("interface_id", _INTERFACE_KEYS),
            ("interface_name", ("interface_name", "if_name", "canonical_interface", "channel", "link")),
            ("section", ("section", "section_index")),
            ("handoff_id", ("handoff_id", "handover_id", "pair", "pair_key", "chain")),
            ("boundary", _TIME_KEYS),
        ):
            extracted = _first(value, keys)
            if extracted is not None:
                meta[target] = extracted
        if value.get("empty") is True or value.get("is_empty") is True or value.get("expect_packets") is False:
            meta["is_empty"] = True
        if _is_empty_kind(meta.get("kind")):
            meta["is_empty"] = True
    elif isinstance(value, (list, tuple)):
        if len(value) < 2:
            raise ValueError("interval requires at least two endpoints: {!r}".format(value))
        start, end = value[0], value[1]
        if len(value) >= 3 and not isinstance(value[2], (list, tuple, dict)):
            meta.setdefault("label", value[2])
        elif len(value) >= 3 and isinstance(value[2], dict):
            meta.update(value[2])
        if len(value) >= 4 and value[3] is not None:
            meta.setdefault("group", value[3])
    else:
        raise TypeError("unsupported interval: {!r}".format(value))

    start = coerce_time(start)
    end = coerce_time(end)
    if meta.get("boundary") is not None:
        meta["boundary"] = coerce_time(meta["boundary"])
    if start is not None and end is not None:
        try:
            if start > end:
                start, end = end, start
                meta["reversed"] = True
        except TypeError:
            pass
    return Interval(start, end, meta)


def merge_intervals(intervals):
    values = _sort_intervals([interval_from(item) for item in intervals])
    merged = []
    for interval in values:
        if interval.start is None or interval.end is None:
            continue
        if not merged:
            merged.append(interval)
            continue
        current = merged[-1]
        try:
            touching = interval.start <= current.end
        except TypeError:
            touching = False
        if touching:
            try:
                new_end = max(current.end, interval.end)
            except TypeError:
                new_end = current.end
            merged[-1] = Interval(current.start, new_end, current.meta)
        else:
            merged.append(interval)
    return merged


def subtract_intervals(source, cuts):
    """Return source intervals with all merged cut intervals removed."""
    cut_ranges = merge_intervals(cuts)
    result = []
    for original in source:
        interval = interval_from(original)
        cursor = interval.start
        pieces = [interval]
        for cut in cut_ranges:
            next_pieces = []
            for piece in pieces:
                a, b = piece.start, piece.end
                try:
                    left_overlap = max(a, cut.start)
                    right_overlap = min(b, cut.end)
                    overlaps = left_overlap < right_overlap
                except TypeError:
                    left_overlap = right_overlap = None
                    overlaps = False
                if not overlaps:
                    next_pieces.append(piece)
                    continue
                if a < left_overlap:
                    next_pieces.append(Interval(a, left_overlap, piece.meta))
                if right_overlap < b:
                    next_pieces.append(Interval(right_overlap, b, piece.meta))
            pieces = next_pieces
        result.extend(pieces)
    return _sort_intervals(result)


def _contains(interval, timestamp):
    if timestamp is None:
        return False
    try:
        return interval.start <= timestamp <= interval.end
    except TypeError:
        return False


def _interface_key(source, section, interface_id):
    return "{}/s{}/i{}".format(source, section, interface_id)


class _OffsetReader(object):
    """Read wrapper retaining a byte offset even for non-seekable streams."""

    def __init__(self, stream):
        self.stream = stream
        try:
            self.offset = stream.tell()
        except Exception:
            self.offset = 0

    def read(self, size=-1):
        if size is None or size < 0:
            data = self.stream.read()
        else:
            data = self.stream.read(size)
        self.offset += len(data or b"")
        return data

    def tell(self):
        try:
            return self.stream.tell()
        except Exception:
            return self.offset

    def seek(self, offset, whence=0):
        result = self.stream.seek(offset, whence)
        try:
            self.offset = self.stream.tell()
        except Exception:
            pass
        return result

    def close(self):
        return self.stream.close()

    def __getattr__(self, name):
        return getattr(self.stream, name)


def _is_target(value):
    return (
        isinstance(value, (str, os.PathLike, bytes, bytearray))
        or hasattr(value, "read")
    )


def normalize_volume(item, index=0, flush_times=None, location=None):
    flush_times = flush_times or {}
    meta = {"order": index}
    source = None
    target = None

    if isinstance(item, dict):
        source = _first(item, _SOURCE_KEYS)
        target = _first(item, _TARGET_KEYS)
        if target is None and _is_target(item.get("target")):
            target = item["target"]
        flush = _first(item, _FLUSH_KEYS)
        if flush is not None:
            meta["flushed_at"] = coerce_time(flush)
        if item.get("location") is not None:
            meta["location"] = item.get("location")
        elif location is not None:
            meta["location"] = location
        for key in ("material_source", "section", "note", "label", "group"):
            if item.get(key) is not None:
                meta[key] = item[key]
    elif isinstance(item, (tuple, list)):
        if len(item) == 2 and _is_target(item[0]) and _is_time_like(item[1]):
            target, flush = item
            meta["flushed_at"] = coerce_time(flush)
        elif len(item) >= 2:
            source, target = item[0], item[1]
            if len(item) >= 3 and _is_time_like(item[2]):
                meta["flushed_at"] = coerce_time(item[2])
            elif len(item) >= 3 and isinstance(item[2], dict):
                meta.update(item[2])
        elif len(item) == 1:
            target = item[0]
    else:
        target = item

    if target is None and source is not None and _is_target(source):
        target = source
        source = None

    if source is None:
        if isinstance(target, (str, os.PathLike)):
            source = os.path.basename(os.fspath(target).rstrip(os.sep)) or "path-{}".format(index)
        elif hasattr(target, "name"):
            name = getattr(target, "name")
            source = os.path.basename(os.fspath(name)) if name else "stream-{}".format(id(target))
        elif isinstance(target, (bytes, bytearray)):
            source = "material-{}".format(hashlib.sha1(bytes(target)).hexdigest()[:12])
        else:
            source = "volume-{}".format(index + 1)

    if "flushed_at" not in meta:
        for key in (source, str(source)):
            if key in flush_times:
                meta["flushed_at"] = coerce_time(flush_times[key])
                break
        if "flushed_at" not in meta and isinstance(target, (str, os.PathLike)):
            basename = os.path.basename(os.fspath(target))
            if basename in flush_times:
                meta["flushed_at"] = coerce_time(flush_times[basename])

    return Record(source=str(source), target=target, **meta)


def _timestamp_for(block):
    raw = None
    resolution = None
    warning = None
    if not isinstance(block, blocks.BlockWithTimestampMixin):
        return None, None, None, "block_has_no_timestamp"
    try:
        raw = (int(block.timestamp_high) << 32) + int(block.timestamp_low)
    except Exception:
        raw = None
    interface_id = getattr(block, "interface_id", None)
    interface = None
    try:
        interface = block.section.interfaces.get(interface_id)
    except Exception:
        interface = None
    if interface is not None:
        try:
            resolution = interface.timestamp_resolution
        except Exception as exc:
            warning = "timestamp_resolution_unavailable: {}".format(exc)
            resolution = 1e-6
    else:
        resolution = 1e-6
        warning = "interface_description_missing_using_default_resolution"
    try:
        timestamp = raw * resolution if raw is not None else block.timestamp
    except Exception as exc:
        return None, raw, resolution, "timestamp_unavailable: {}".format(exc)
    return timestamp, raw, resolution, warning


def scan_volumes(volumes, flush_times=None, location=None):
    """Scan pcap-ng inputs without writing or seeking them unnecessarily."""
    if isinstance(volumes, dict):
        normalized = [
            normalize_volume((key, value), index, flush_times, location)
            for index, (key, value) in enumerate(volumes.items())
        ]
    else:
        normalized = [
            normalize_volume(item, index, flush_times, location)
            for index, item in enumerate(_as_list(volumes))
        ]

    packet_records = []
    interface_records = []
    section_records = []
    error_records = []
    volume_reports = []

    for volume in normalized:
        target = volume.target
        owned_stream = False
        if isinstance(target, (str, os.PathLike)):
            stream = open(os.fspath(target), "rb")
            owned_stream = True
        elif isinstance(target, (bytes, bytearray)):
            stream = io.BytesIO(bytes(target))
            owned_stream = True
        elif hasattr(target, "read"):
            stream = target
        else:
            raise TypeError("volume is not a path, bytes, or binary stream: {!r}".format(target))

        reader = _OffsetReader(stream)
        scanner = iter(FileScanner(reader))
        section_index = -1
        block_index = 0
        packet_index = 0

        try:
            while True:
                offset = reader.tell()
                try:
                    block = next(scanner)
                except StopIteration:
                    break
                except Exception as exc:
                    error_records.append(Record(
                        source=volume.source,
                        offset=offset,
                        block_index=block_index,
                        error_type=type(exc).__name__,
                        error=str(exc),
                    ))
                    break

                block_index += 1
                block_name = type(block).__name__

                if isinstance(block, blocks.SectionHeader):
                    section_index += 1
                    section_records.append(Record(
                        source=volume.source,
                        section=section_index,
                        section_number=section_index + 1,
                        offset=offset,
                        endianness=getattr(block, "endianness", None),
                        version=getattr(block, "version", None),
                    ))
                    continue

                current_section = max(section_index, 0)
                interface_id = getattr(block, "interface_id", None)

                if isinstance(block, blocks.InterfaceDescription):
                    key = _interface_key(volume.source, current_section, interface_id)
                    interface_records.append(Record(
                        source=volume.source,
                        section=current_section,
                        section_number=current_section + 1,
                        interface_id=interface_id,
                        interface_key=key,
                        offset=offset,
                        link_type=getattr(block, "link_type", None),
                        snaplen=getattr(block, "snaplen", None),
                        interface_name=_safe_option(block, "if_name"),
                        interface_description=_safe_option(block, "if_description"),
                    ))

                if not isinstance(block, blocks.BasePacketBlock):
                    continue

                packet_index += 1
                key = _interface_key(volume.source, current_section, interface_id)
                timestamp, raw_ticks, resolution, warning = _timestamp_for(block)
                location_text = "{}#section-{}/block-{}@offset-{}".format(
                    volume.source, current_section + 1, block_index, offset
                )
                packet_records.append(Record(
                    source=volume.source,
                    volume=volume.source,
                    section=current_section,
                    section_number=current_section + 1,
                    interface_id=interface_id,
                    interface_key=key,
                    offset=offset,
                    block_index=block_index,
                    packet_index=packet_index,
                    locator=location_text,
                    location=Record(
                        volume=volume.source,
                        source=volume.source,
                        section=current_section,
                        section_number=current_section + 1,
                        interface_id=interface_id,
                        interface_key=key,
                        offset=offset,
                        block_index=block_index,
                    ),
                    block_type=block_name,
                    timestamp=timestamp,
                    timestamp_raw=raw_ticks,
                    timestamp_resolution=resolution,
                    timestamp_warning=warning,
                    has_timestamp=timestamp is not None,
                ))
        finally:
            if owned_stream:
                try:
                    stream.close()
                except Exception:
                    pass

        volume_packets = [p for p in packet_records if p.source == volume.source]
        timestamps = [p.timestamp for p in volume_packets if p.timestamp is not None]
        volume_reports.append(Record(
            source=volume.source,
            location=volume.get("location", location),
            flushed_at=volume.get("flushed_at"),
            order=volume.order,
            packet_count=len(volume_packets),
            timestamped_packet_count=len(timestamps),
            untimestamped_packet_count=len(volume_packets) - len(timestamps),
            observed_start=min(timestamps) if timestamps else None,
            observed_end=max(timestamps) if timestamps else None,
            read_error_count=len([e for e in error_records if e.source == volume.source]),
        ))

    return Record(
        location=location,
        volumes=volume_reports,
        sections=section_records,
        interfaces=interface_records,
        packets=packet_records,
        read_errors=error_records,
        untimestamped_packets=[p for p in packet_records if p.timestamp is None],
    )


def _safe_option(block, name):
    try:
        return block.options[name]
    except Exception:
        return None


def bilateral_gaps(left, right, boundary, empty_windows=None):
    """Pure helper returning the two canonical gaps around one boundary."""
    boundary = coerce_time(boundary)
    left = interval_from(left) if not isinstance(left, Interval) else left
    right = interval_from(right) if not isinstance(right, Interval) else right
    left_gap = Interval(left.end, boundary, side="early") if _safe_lt(left.end, boundary) else None
    right_gap = Interval(boundary, right.start, side="missing") if _safe_lt(boundary, right.start) else None
    cuts = merge_intervals(empty_windows or [])
    left_net = subtract_intervals([left_gap], cuts) if left_gap else []
    right_net = subtract_intervals([right_gap], cuts) if right_gap else []
    return Record(
        boundary=boundary,
        left_gap=left_gap,
        right_gap=right_gap,
        gaps=[gap for gap in (left_gap, right_gap) if gap is not None],
        net_left_gaps=left_net,
        net_right_gaps=right_net,
        bilateral_gaps=left_net + right_net,
    )


def _safe_lt(a, b):
    try:
        return a < b
    except TypeError:
        return False


def _safe_le(a, b):
    try:
        return a <= b
    except TypeError:
        return False


def _max_time(values):
    values = [value for value in values if value is not None]
    if not values:
        return None
    try:
        return max(values)
    except TypeError:
        return sorted(values, key=_time_sort_key)[-1]


def _min_time(values):
    values = [value for value in values if value is not None]
    if not values:
        return None
    try:
        return min(values)
    except TypeError:
        return sorted(values, key=_time_sort_key)[0]


def _dedupe_intervals(intervals):
    seen = set()
    result = []
    for interval in _sort_intervals(intervals):
        key = (interval.start, interval.end)
        if key in seen:
            continue
        seen.add(key)
        result.append(interval)
    return result


def _pick_kwargs(kwargs, names, default=None):
    for name in names:
        value = kwargs.get(name)
        if value is not None:
            return kwargs.pop(name)
    return default


_LOCATION_NAMES = ("location", "capture_location", "site", "probe")
_VOLUME_NAMES = (
    "volumes", "captures", "capture_volumes", "sources", "materials",
    "files", "readers", "volume_inputs",
)
_PERIOD_NAMES = (
    "calibrated_periods", "calibrated_windows", "periods", "windows",
    "handover_windows", "handover_periods", "manifest", "schedule",
    "independent_list", "handoff_windows",
)
_TAKEOVER_NAMES = (
    "takeover_intervals", "interface_takeover_intervals", "custody_intervals",
    "interface_intervals", "takeovers", "interfaces", "custody_windows",
)
_FLUSH_NAMES = ("flush_times", "volume_flush_times", "final_flush_times", "flushed_at")
_EMPTY_NAMES = ("empty_windows", "silent_windows", "empty_gaps", "quiet_windows")


def _is_path_string(value):
    if not isinstance(value, str):
        return False
    return (
        os.path.exists(value)
        or "/" in value
        or "\\\\" in value
        or value.lower().endswith((".pcap", ".pcapng", ".ntar", ".cap"))
    )


def _volume_like(value):
    if _is_path_string(value) or isinstance(value, (bytes, bytearray)) or hasattr(value, "read"):
        return True
    if isinstance(value, dict):
        return any(_first(value, (key,)) is not None for key in _TARGET_KEYS)
    if isinstance(value, (tuple, list)):
        return any(_volume_like(item) for item in value)
    return False


def _looks_like_flush_mapping(value):
    if not isinstance(value, dict) or not value:
        return False
    if any(isinstance(item, (dict, list, tuple, set)) for item in value.values()):
        return False
    return all(_is_time_like(item) or item is None for item in value.values())


def _looks_like_interval_dict(value):
    return isinstance(value, dict) and any(
        key in value for key in _START_KEYS + _END_KEYS + _TIME_KEYS
    )


def _looks_like_takeover_list(value):
    if not isinstance(value, (list, tuple)) or not value:
        return False
    first = value[0]
    if isinstance(first, dict):
        return any(key in first for key in _INTERFACE_KEYS + ("interface_name", "if_name"))
    if isinstance(first, (tuple, list)) and first:
        return not _is_time_like(first[0])
    return False


def _extract_audit_inputs(args, kwargs):
    result = {
        "location": _pick_kwargs(kwargs, _LOCATION_NAMES),
        "volumes": _as_list(_pick_kwargs(kwargs, _VOLUME_NAMES, [])),
        "periods": _pick_kwargs(kwargs, _PERIOD_NAMES),
        "takeovers": _pick_kwargs(kwargs, _TAKEOVER_NAMES),
        "flush_times": _pick_kwargs(kwargs, _FLUSH_NAMES, {}),
        "empty_windows": _pick_kwargs(kwargs, _EMPTY_NAMES, []),
    }

    for config_name in ("input_data", "config", "manifest_data"):
        config = kwargs.pop(config_name, None)
        if isinstance(config, dict):
            for key, value in config.items():
                if value is not None and key in result and result[key] in (None, [], {}):
                    result[key] = value
                for names, target in (
                    (_LOCATION_NAMES, "location"), (_VOLUME_NAMES, "volumes"),
                    (_PERIOD_NAMES, "periods"), (_TAKEOVER_NAMES, "takeovers"),
                    (_FLUSH_NAMES, "flush_times"), (_EMPTY_NAMES, "empty_windows"),
                ):
                    if key in names and result.get(target) in (None, [], {}):
                        result[target] = value

    interval_lists = []
    for arg in args:
        if _volume_like(arg):
            if isinstance(arg, (list, tuple)) and not _is_path_string(arg):
                result["volumes"].extend(arg)
            else:
                result["volumes"].append(arg)
        elif isinstance(arg, str):
            result["location"] = arg
        elif _looks_like_flush_mapping(arg):
            result["flush_times"] = arg
        elif isinstance(arg, dict):
            if _looks_like_interval_dict(arg):
                interval_lists.append([arg])
            else:
                for names, target in (
                    (_LOCATION_NAMES, "location"), (_VOLUME_NAMES, "volumes"),
                    (_PERIOD_NAMES, "periods"), (_TAKEOVER_NAMES, "takeovers"),
                    (_FLUSH_NAMES, "flush_times"), (_EMPTY_NAMES, "empty_windows"),
                ):
                    value = _pick_kwargs(arg, names)
                    if value is not None:
                        result[target] = value
        elif isinstance(arg, (list, tuple)):
            if _looks_like_takeover_list(arg):
                result["takeovers"] = arg
            else:
                interval_lists.append(arg)

    for interval_list in interval_lists:
        if _looks_like_takeover_list(interval_list) and result["takeovers"] is None:
            result["takeovers"] = interval_list
        elif result["periods"] is None:
            result["periods"] = interval_list
        elif result["takeovers"] is None:
            result["takeovers"] = interval_list

    if result["periods"] is None:
        result["periods"] = []
    if result["takeovers"] is None:
        result["takeovers"] = []
    return result


def _interface_meta_from_key(key):
    if isinstance(key, (tuple, list)):
        if len(key) >= 3:
            return {"source": key[0], "section": key[1], "interface_id": key[2]}
        if len(key) == 2:
            return {"source": key[0], "interface_id": key[1]}
        return {"interface_id": key[0]}
    if isinstance(key, int):
        return {"interface_id": key}
    text = str(key)
    if "/" in text and not text.replace("/", "").startswith("s"):
        source, interface_id = text.rsplit("/", 1)
        meta = {"source": source}
        if interface_id.isdigit():
            meta["interface_id"] = int(interface_id)
        else:
            meta["interface_name"] = interface_id
        return meta
    if text.isdigit():
        return {"interface_id": int(text)}
    return {"interface_name": text}


def _normalize_selector_meta(meta):
    iid = meta.get("interface_id")
    if isinstance(iid, str):
        if iid.isdigit():
            meta["interface_id"] = int(iid)
        else:
            meta.setdefault("interface_name", iid)
            meta.pop("interface_id", None)
    section = meta.get("section")
    if isinstance(section, str) and section.isdigit():
        meta["section"] = int(section)
    source = meta.get("source")
    if isinstance(source, (str, os.PathLike)) and _is_path_string(str(source)):
        meta["source_path"] = str(source)
    return meta


def _normalize_takeovers(value):
    if not value:
        return []
    if isinstance(value, dict) and _looks_like_interval_dict(value):
        raw_items = [value]
    elif isinstance(value, dict):
        raw_items = []
        for key, item in value.items():
            key_meta = _normalize_selector_meta(_interface_meta_from_key(key))
            for raw in _as_list(item):
                if isinstance(raw, Interval):
                    raw = raw.as_dict()
                if isinstance(raw, dict):
                    merged = dict(raw)
                    for key_name, key_value in key_meta.items():
                        merged.setdefault(key_name, key_value)
                    raw_items.append(merged)
                else:
                    raw_items.append((key_meta, raw))
    else:
        raw_items = list(value)

    result = []
    for item in raw_items:
        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], dict):
            meta, raw = item
            if isinstance(raw, (tuple, list)) and len(raw) >= 2:
                interval = interval_from(raw, meta)
            else:
                continue
        else:
            interval = interval_from(item)
        result.append(interval)
    return _sort_intervals(result)


def _source_matches(actual, selector):
    if actual == selector:
        return True
    try:
        if os.path.basename(str(actual)) == os.path.basename(str(selector)):
            return True
    except Exception:
        pass
    return False


def _resolve_interface_keys(meta, interfaces):
    _normalize_selector_meta(meta)
    candidates = list(interfaces)
    constrained = False

    key = meta.get("interface_key")
    if key is not None:
        constrained = True
        found = [item.interface_key for item in candidates if item.interface_key == key]
        if found:
            return found

    source = meta.get("source")
    if source is not None:
        constrained = True
        candidates = [item for item in candidates if _source_matches(item.source, source)]

    section = meta.get("section")
    if section is not None:
        constrained = True
        candidates = [
            item for item in candidates
            if item.section == section or item.section_number == section
        ]

    iid = meta.get("interface_id")
    if iid is not None:
        constrained = True
        candidates = [item for item in candidates if item.interface_id == iid]

    name = meta.get("interface_name")
    if name is not None:
        constrained = True
        candidates = [
            item for item in candidates
            if item.interface_name == name or item.interface_description == name
        ]

    if not constrained:
        return None
    return [item.interface_key for item in candidates]


def _select_packets(packets, meta):
    keys = meta.get("interface_keys")
    source = meta.get("source")
    section = meta.get("section")
    iid = meta.get("interface_id")
    selected = []
    for packet in packets:
        if keys is not None and packet.interface_key not in keys:
            continue
        if source is not None and not _source_matches(packet.source, source):
            continue
        if section is not None and packet.section != section and packet.section_number != section:
            continue
        if iid is not None and keys is None and packet.interface_id != iid:
            continue
        selected.append(packet)
    return selected


def _flush_for_meta(meta, inventory):
    sources = set()
    keys = meta.get("interface_keys")
    if keys is not None:
        key_set = set(keys)
        for interface in inventory.interfaces:
            if interface.interface_key in key_set:
                sources.add(interface.source)
    source = meta.get("source")
    if source is not None:
        for volume in inventory.volumes:
            if _source_matches(volume.source, source):
                sources.add(volume.source)
    if not sources and keys is None and source is None:
        values = [volume.flushed_at for volume in inventory.volumes]
    else:
        values = [
            volume.flushed_at
            for volume in inventory.volumes
            if volume.source in sources
        ]
    return _max_time(values)


def _window_findings(windows, packets, cuts, empty=False):
    findings = []
    gaps = []
    for window in windows:
        if window.start is None or window.end is None:
            continue
        hits = [
            packet for packet in _select_packets(packets, window.meta)
            if _contains(window, packet.timestamp)
        ]
        finding = Interval(
            window.start,
            window.end,
            dict(window.meta, packet_count=len(hits),
                 packet_locations=[packet.locator for packet in hits]),
        )
        findings.append(finding)
        if not empty and not hits:
            for gap in subtract_intervals([window], cuts):
                gap.meta.setdefault("reason", "no_observable_packets")
                gaps.append(gap)
    return findings, gaps


def audit_reception(*args, **kwargs):
    return _compose_report_v2(args, kwargs)


def _compose_report_v2(args, kwargs):
    """Placeholder marker used while composing report helpers."""
    extracted = _extract_audit_inputs(args, kwargs)
    inventory = scan_volumes(
        extracted["volumes"], extracted["flush_times"], extracted["location"]
    )
    periods = [interval_from(item) for item in _as_list(extracted["periods"])]
    explicit_empty = [
        interval_from(item, {"kind": "empty_window", "is_empty": True})
        for item in _as_list(extracted["empty_windows"])
    ]
    empty_windows = list(explicit_empty)
    for period in periods:
        if period.meta.get("is_empty"):
            empty_windows.append(period)
    expected_periods = [p for p in periods if not p.meta.get("is_empty")]
    takeovers = _normalize_takeovers(extracted["takeovers"])
    for takeover in takeovers:
        takeover.meta["interface_keys"] = _resolve_interface_keys(
            takeover.meta, inventory.interfaces
        )
    return _compose_report(
        extracted["location"],
        inventory,
        expected_periods,
        empty_windows,
        takeovers,
    )


def main(argv=None):
    return _main_impl(argv)


def _pair_key(takeover):
    meta = takeover.meta
    explicit = meta.get("handoff_id") or meta.get("pair") or meta.get("chain")
    if explicit is not None:
        return "handoff:" + str(explicit)
    name = meta.get("interface_name") or meta.get("channel") or meta.get("link")
    if name is not None:
        return "ifname:" + str(name)
    interface_id = meta.get("interface_id")
    if interface_id is not None:
        return "ifid:" + str(interface_id)
    source = meta.get("source")
    if source is not None:
        return "source:" + str(source)
    return "all-interfaces"


def _takeover_findings(takeovers, packets, cuts, inventory):
    findings = []
    gaps = []
    for takeover in takeovers:
        selected = _select_packets(packets, takeover.meta)
        in_range = [p for p in selected if _contains(takeover, p.timestamp)]
        timestamps = [p.timestamp for p in in_range if p.timestamp is not None]
        first = _min_time(timestamps)
        last = _max_time(timestamps)
        flush = _flush_for_meta(takeover.meta, inventory)
        evidence_end = _max_time([last, flush])
        raw_gaps = []
        if takeover.start is not None and takeover.end is not None:
            if not timestamps:
                if flush is None:
                    raw_gaps.append(Interval(takeover.start, takeover.end, {"side": "coverage"}))
                elif _safe_lt(flush, takeover.start):
                    raw_gaps.append(Interval(takeover.start, takeover.end, {"side": "coverage"}))
                elif _safe_lt(flush, takeover.end):
                    raw_gaps.append(Interval(flush, takeover.end, {"side": "finalization"}))
            else:
                if _safe_lt(takeover.start, first):
                    raw_gaps.append(Interval(takeover.start, first, {"side": "leading"}))
                if evidence_end is not None and _safe_lt(evidence_end, takeover.end):
                    raw_gaps.append(Interval(evidence_end, takeover.end, {"side": "trailing"}))
        net_gaps = []
        for gap in raw_gaps:
            for net_gap in subtract_intervals([gap], cuts):
                net_gap.meta.setdefault("reason", "interface_coverage_gap")
                net_gap.meta["source"] = takeover.meta.get("source")
                net_gaps.append(net_gap)
                gaps.append(net_gap)
        finding = Interval(takeover.start, takeover.end, dict(takeover.meta))
        finding.meta.update({
            "packet_count": len(in_range),
            "observed_start": first,
            "observed_end": last,
            "flushed_at": flush,
            "raw_gaps": raw_gaps,
            "missing_gaps": net_gaps,
        })
        findings.append(finding)
    return findings, gaps


def _boundary_reports(takeovers, packets, cuts, inventory):
    groups = defaultdict(list)
    for takeover in takeovers:
        groups[_pair_key(takeover)].append(takeover)

    reports = []
    for pair_key, group in groups.items():
        group = _sort_intervals(group)
        for left, right in zip(group, group[1:]):
            boundary = left.meta.get("boundary") or right.meta.get("boundary")
            if boundary is None:
                boundary = left.end
            boundary = coerce_time(boundary)
            if boundary is None:
                continue

            left_times = [
                packet.timestamp
                for packet in _select_packets(packets, left.meta)
                if packet.timestamp is not None
                and _safe_le(packet.timestamp, boundary)
            ]
            right_all_times = [
                packet.timestamp
                for packet in _select_packets(packets, right.meta)
                if packet.timestamp is not None
            ]
            right_times = [
                timestamp for timestamp in right_all_times
                if _safe_le(boundary, timestamp)
            ]
            right_before = [
                timestamp for timestamp in right_all_times
                if _safe_lt(timestamp, boundary)
            ]

            left_last = _max_time(left_times)
            left_flush = _flush_for_meta(left.meta, inventory)
            left_anchor = _max_time([left.start, left_last, left_flush])
            if left_anchor is not None and _safe_lt(boundary, left_anchor):
                left_anchor = boundary
            left_gap = None
            if left_anchor is not None and _safe_lt(left_anchor, boundary):
                left_gap = Interval(left_anchor, boundary, {
                    "side": "early",
                    "group": left.meta.get("group"),
                    "source": left.meta.get("source"),
                    "pair_key": pair_key,
                    "last_packet": left_last,
                    "flushed_at": left_flush,
                })

            right_first = _min_time(right_times)
            right_anchor = right_first if right_first is not None else right.start
            right_gap = None
            if right_anchor is not None and _safe_lt(boundary, right_anchor):
                right_gap = Interval(boundary, right_anchor, {
                    "side": "missing",
                    "group": right.meta.get("group"),
                    "source": right.meta.get("source"),
                    "pair_key": pair_key,
                    "first_packet": right_first,
                })

            early_start = None
            if right.start is not None and _safe_lt(right.start, boundary):
                early_start = right.start
            if right_before:
                first_before = _min_time(right_before)
                early_start = _min_time([early_start, first_before])
            early_takeover = None
            if early_start is not None and _safe_lt(early_start, boundary):
                early_takeover = Interval(early_start, boundary, {
                    "side": "early_takeover",
                    "group": right.meta.get("group"),
                    "source": right.meta.get("source"),
                    "pair_key": pair_key,
                })

            left_net = subtract_intervals([left_gap], cuts) if left_gap else []
            right_net = subtract_intervals([right_gap], cuts) if right_gap else []
            reports.append(Record(
                pair_key=pair_key,
                boundary=boundary,
                left=left.as_dict(),
                right=right.as_dict(),
                left_gap=left_gap,
                right_gap=right_gap,
                early_interval=left_gap or early_takeover,
                early_takeover=early_takeover,
                gaps=[gap for gap in (left_gap, right_gap) if gap is not None],
                net_left_gaps=left_net,
                net_right_gaps=right_net,
                bilateral_gaps=left_net + right_net,
            ))
    return sorted(
        reports,
        key=lambda item: _safe_sort(_time_sort_key(item.boundary))
        + (str(item.pair_key),),
    )


def _compose_report(location, inventory, expected_periods, empty_windows, takeovers):
    cuts = merge_intervals(empty_windows)
    empty_checks, _ = _window_findings(empty_windows, inventory.packets, cuts, empty=True)
    confirmed_empty = [item for item in empty_checks if item.packet_count == 0]
    empty_conflicts = [item for item in empty_checks if item.packet_count > 0]
    period_findings, period_gaps = _window_findings(
        expected_periods, inventory.packets, cuts, empty=False
    )
    takeover_findings, coverage_gaps = _takeover_findings(
        takeovers, inventory.packets, cuts, inventory
    )
    boundary_reports = _boundary_reports(
        takeovers, inventory.packets, cuts, inventory
    )

    early_handovers = []
    raw_bilateral = []
    net_bilateral = []
    for boundary in boundary_reports:
        if boundary.left_gap is not None:
            early_handovers.append(boundary.left_gap)
            raw_bilateral.append(boundary.left_gap)
        if boundary.early_takeover is not None:
            early_handovers.append(boundary.early_takeover)
        if boundary.right_gap is not None:
            raw_bilateral.append(boundary.right_gap)
        net_bilateral.extend(boundary.bilateral_gaps)

    missing_handovers = _dedupe_intervals(period_gaps + coverage_gaps)
    early_handovers = _dedupe_intervals(early_handovers)
    raw_bilateral = _dedupe_intervals(raw_bilateral)
    net_bilateral = _dedupe_intervals(net_bilateral)
    complete = not missing_handovers and not inventory.read_errors

    return Record(
        location=location,
        read_only=True,
        ok=complete,
        reception_complete=complete,
        has_early_handovers=bool(early_handovers),
        has_missing_handovers=bool(missing_handovers),
        volumes=inventory.volumes,
        sections=inventory.sections,
        interfaces=inventory.interfaces,
        packets=inventory.packets,
        untimestamped_packets=inventory.untimestamped_packets,
        missing_timestamp_packets=inventory.untimestamped_packets,
        packet_locations=[packet.location for packet in inventory.packets],
        read_errors=inventory.read_errors,
        calibrated_periods=period_findings,
        period_checks=period_findings,
        takeover_intervals=takeover_findings,
        interface_takeover_intervals=takeover_findings,
        empty_window_checks=empty_checks,
        empty_windows=confirmed_empty,
        silent_windows=confirmed_empty,
        empty_window_conflicts=empty_conflicts,
        unexpected_packets_in_empty_windows=empty_conflicts,
        handover_checks=boundary_reports,
        boundary_reports=boundary_reports,
        bilateral_gap_reports=boundary_reports,
        bilateral_gaps=raw_bilateral,
        bilateral_gap_intervals=raw_bilateral,
        bilateral_net_gaps=net_bilateral,
        bilateral_net_gap_intervals=net_bilateral,
        early_handovers=early_handovers,
        handed_over_too_early=early_handovers,
        missing_handovers=missing_handovers,
        should_have_been_handed_over=missing_handovers,
        undelivered_intervals=missing_handovers,
        data_loss=missing_handovers,
        data_loss_intervals=missing_handovers,
        gap_intervals=missing_handovers,
    )


def _jsonable(value):
    if isinstance(value, Interval):
        result = value.as_dict()
        result["start"] = _jsonable(result.get("start"))
        result["end"] = _jsonable(result.get("end"))
        return result
    if isinstance(value, Record):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return value


def _main_impl(argv=None):
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Read-only pcapng handover reception check")
    parser.add_argument("--input", "-i", help="JSON check configuration")
    parser.add_argument("--location")
    parser.add_argument("--volumes-json")
    parser.add_argument("--periods-json")
    parser.add_argument("--takeovers-json")
    parser.add_argument("--flush-times-json")
    parser.add_argument("--empty-windows-json")
    parser.add_argument("--output", "-o")
    args = parser.parse_args(argv)

    config = {}
    if args.input:
        with open(args.input, "r", encoding="utf-8") as handle:
            config = json.load(handle)
    for argument, key in (
        (args.location, "location"),
        (args.volumes_json, "volumes"),
        (args.periods_json, "calibrated_periods"),
        (args.takeovers_json, "takeover_intervals"),
        (args.flush_times_json, "flush_times"),
        (args.empty_windows_json, "empty_windows"),
    ):
        if argument is not None:
            config[key] = json.loads(argument) if argument.strip().startswith(("[", "{") ) else argument

    report = audit_reception(**config)
    payload = json.dumps(_jsonable(report), ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
    else:
        print(payload)
    return 0


check_reception = audit_reception
reception_check = audit_reception
run_reception_check = audit_reception
audit_handover = audit_reception
audit_handovers = audit_reception
check_handover = audit_reception
check_handovers = audit_reception
scan_pcapng_volumes = scan_volumes
