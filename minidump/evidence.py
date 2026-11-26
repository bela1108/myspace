"""Offline evidence attribution and guarded briefing reconstruction.

This module deliberately keeps all verification local and deterministic.
A supplier statement may update an incident briefing only when its thread,
timestamp and snapshot identity all match a parsed minidump.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import inspect
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from minidump.minidumpfile import MinidumpFile


IDENTITY_FIELDS = ("thread_id", "timestamp", "snapshot_id")

THREAD_KEYS = (
    "thread_id", "tid", "threadid", "thread", "recorded_thread_id",
    "exception_thread_id", "thread_identifier", "thread_identity",
)
TIME_KEYS = (
    "timestamp", "time", "time_date_stamp", "timedatestamp", "dump_time",
    "recorded_at", "recorded_time", "recorded_timestamp", "collected_at",
    "collection_time", "event_time", "when",
)
SNAPSHOT_KEYS = (
    "snapshot_id", "snapshotid", "snapshot", "snapshot_sha256",
    "snapshot_identity", "snapshot_fingerprint", "snapshot_digest",
    "sha256", "sha_256", "digest", "hash", "file_hash", "content_hash",
    "content_id",
)

ENVELOPE_KEYS = {
    "supplier", "supplier_statement", "provider", "provider_statement",
    "vendor", "vendor_statement", "source", "source_statement", "metadata",
    "meta", "envelope",
}
STATEMENT_WRAPPER_KEYS = (
    "supplier_statement", "provider_statement", "vendor_statement",
    "source_statement", "statement", "claim", "payload",
)
UPDATE_CONTAINER_KEYS = (
    "updates", "update", "testimony", "testimony_updates", "revision",
    "revisions", "patch", "fields", "revised", "revised_briefing",
    "new_values", "values",
)


class EvidenceError(ValueError):
    """Base class for offline evidence errors."""


class EvidenceParseError(EvidenceError):
    """Raised when a purported minidump cannot be parsed."""


class IdentityMismatchError(EvidenceError):
    """Raised by strict helpers when the three identities do not match."""


class AttrDict(dict):
    """Dictionary with attribute access for convenient exploratory queries."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __delattr__(self, name: str) -> None:
        try:
            del self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class EvidenceRecord(AttrDict):
    """Recorded identity and selected stream facts from one minidump."""

    def to_dict(self) -> dict:
        return _to_plain_dict(self)


class Attribution(AttrDict):
    """The evidence item attributed to one supplier statement."""


class CallableBool(int):
    """Boolean-like value that also tolerates zero-argument method calls."""

    def __new__(cls, value: bool):
        return int.__new__(cls, 1 if value else 0)

    def __call__(self) -> bool:
        return bool(self)

    def __repr__(self) -> str:
        return str(bool(self))


class IdentityVerification(AttrDict):
    """Triple-identity verification result."""


class BriefingReconstruction(AttrDict):
    """Original briefing plus held/accepted operations.

    ``reconstruct()`` always rebuilds the original briefing.  Accepted or held
    revisions can be replayed explicitly by callers who want those views.
    """

    def reconstruct(self, *, apply_accepted: bool = False,
                    apply_held: bool = False) -> dict:
        result = copy.deepcopy(self.get("original") or {})
        if apply_accepted:
            _deep_merge(result, self.get("accepted_patch") or {})
        if apply_held:
            _deep_merge(result, self.get("held_patch") or {})
        return result

    def original_view(self) -> dict:
        return self.reconstruct()

    def revised_view(self) -> dict:
        return self.reconstruct(apply_accepted=True)

    def pending_view(self) -> dict:
        return self.reconstruct(apply_held=True)

    def rebuild(self, **kwargs) -> dict:
        return self.reconstruct(**kwargs)


class ReconciliationResult(AttrDict):
    """Decision and reconstructable briefing state."""

    def reconstruct(self, **kwargs) -> dict:
        reconstruction = self.get("reconstruction")
        if reconstruction is None:
            return copy.deepcopy(self.get("original_briefing") or {})
        return reconstruction.reconstruct(**kwargs)

    def to_dict(self) -> dict:
        return _to_plain_dict(self)

    def to_json(self, **kwargs) -> str:
        payload = self.to_dict()
        payload.pop("dump", None)
        return json.dumps(payload, default=str, **kwargs)


def _to_plain_dict(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _to_plain_dict(v) for k, v in value.items() if k != "dump"}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_to_plain_dict(v) for v in value]
    if hasattr(value, "value") and not isinstance(value, (str, bytes, int, float)):
        return getattr(value, "value", str(value))
    return value


def _norm_key(key: Any) -> str:
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key))
    text = text.replace("-", "_").replace(" ", "_")
    return text.lower()


def _as_mapping(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "__dataclass_fields__"):
        return {k: getattr(value, k) for k in value.__dataclass_fields__}
    if hasattr(value, "__dict__"):
        return {k: v for k, v in vars(value).items() if not k.startswith("_")}
    return {}


def _lookup_value(data: Mapping, aliases: tuple[str, ...]) -> Any:
    mapping = _as_mapping(data)
    maps = [mapping]
    for key in ("identity", "identifiers", "recorded", "record", "evidence",
                "facts", "details", "attributes"):
        nested = mapping.get(key)
        if isinstance(nested, Mapping):
            maps.append(nested)

    normalized_maps = []
    for item in maps:
        normalized_maps.append({_norm_key(k): v for k, v in item.items()})

    for alias in aliases:
        wanted = _norm_key(alias)
        for normalized in normalized_maps:
            if wanted in normalized and normalized[wanted] is not None:
                return normalized[wanted]
    return None


def canon_thread_id(value: Any) -> Any:
    if isinstance(value, Mapping):
        return canon_thread_id(_lookup_value(value, THREAD_KEYS))
    if isinstance(value, (list, tuple, set, frozenset)):
        values = []
        for item in value:
            normalized = canon_thread_id(item)
            if normalized is not None:
                values.append(normalized)
        if not values:
            return None
        return values[0] if len(values) == 1 else tuple(values)
    if value is None or isinstance(value, bool):
        return int(value) if isinstance(value, bool) else None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)

    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith(("0x", "0x")):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return int(float(text))


def canon_timestamp(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(moment.timestamp())
    if isinstance(value, (int, float)):
        number = float(value)
        if number >= 100_000_000_000_000:  # microseconds
            number /= 1_000_000
        elif number >= 100_000_000_000:   # milliseconds
            number /= 1_000
        return int(round(number))

    text = str(value).strip()
    if not text:
        return None
    try:
        return canon_timestamp(float(text))
    except ValueError:
        pass

    iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    moment = datetime.fromisoformat(iso_text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def canon_snapshot_id(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) == 32:
            return "sha256:" + raw.hex()
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    text = str(value).strip()
    if not text:
        return None
    lowered = text.lower()
    for prefix in ("sha256:", "sha-256:", "sha_256:", "sha256="):
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix):]
            text = text[len(prefix):]
            break
    if re.fullmatch(r"[0-9a-f]{64}", lowered):
        return "sha256:" + lowered
    return text


def _safe_normalize(func, value: Any) -> tuple[Any, str | None]:
    if value is None:
        return None, None
    try:
        return func(value), None
    except Exception as exc:  # normalization failure is reported as invalid
        return None, str(exc)


def coerce_statement(value: Any = None, **kwargs) -> dict:
    data = _as_mapping(value)
    if kwargs:
        data.update(kwargs)
    for key in STATEMENT_WRAPPER_KEYS:
        nested = data.get(key)
        if isinstance(nested, Mapping):
            merged = dict(data)
            merged.update(dict(nested))
            merged.pop(key, None)
            data = merged
            break
    return data


def statement_identities(statement: Any = None, **kwargs) -> dict:
    data = coerce_statement(statement, **kwargs)
    return {
        "thread_id": _lookup_value(data, THREAD_KEYS),
        "timestamp": _lookup_value(data, TIME_KEYS),
        "snapshot_id": _lookup_value(data, SNAPSHOT_KEYS),
    }


def snapshot_id_for_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def snapshot_id_for_path(path: str | os.PathLike) -> str:
    return snapshot_id_for_bytes(Path(path).read_bytes())


def _looks_like_dump(value: Any) -> bool:
    return (
        value is not None
        and hasattr(value, "header")
        and hasattr(value, "directories")
        and (hasattr(value, "threads") or hasattr(value, "exception"))
    )


def _read_dump_bytes(dump: Any) -> bytes | None:
    filename = getattr(dump, "filename", None)
    if filename and os.path.exists(filename):
        return Path(filename).read_bytes()

    handle = getattr(dump, "file_handle", None)
    read_method = getattr(handle, "read", None)
    if handle is None or not callable(read_method):
        return None
    if inspect.iscoroutinefunction(read_method):
        return None

    position = None
    if hasattr(handle, "tell"):
        try:
            position = handle.tell()
        except Exception:
            position = None
    if hasattr(handle, "seek"):
        try:
            handle.seek(0)
        except Exception:
            pass
    raw = handle.read()
    if inspect.isawaitable(raw):
        return None
    if position is not None and hasattr(handle, "seek"):
        try:
            handle.seek(position)
        except Exception:
            pass
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return bytes(raw) if raw is not None else None


def extract_evidence(source: Any = None, *,
                     path: str | os.PathLike | None = None,
                     data: bytes | None = None,
                     file_obj: Any = None,
                     filename: str | None = None,
                     parse: bool = True,
                     **_options) -> EvidenceRecord:
    """Extract deterministic identity facts from one minidump source."""
    dump = None
    raw = None
    path_text = None

    if isinstance(source, EvidenceRecord):
        return source
    if path is None and isinstance(source, (str, Path, os.PathLike)):
        path = source
    elif data is None and isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    elif file_obj is None and hasattr(source, "read"):
        file_obj = source
    elif _looks_like_dump(source):
        dump = source
    elif isinstance(source, Mapping):
        source_map = dict(source)
        if (_looks_like_evidence_mapping(source_map)
                or _is_identity_only_mapping(source_map)
                or any(key in source_map for key in
                       ("thread_ids", "recorded_thread_ids", "snapshot_digest", "sha256"))):
            record = EvidenceRecord(source_map)
            identities = statement_identities(source_map)
            thread_value, _ = _safe_normalize(
                canon_thread_id, identities.get("thread_id")
            )
            time_value, _ = _safe_normalize(
                canon_timestamp, identities.get("timestamp")
            )
            snapshot_value, _ = _safe_normalize(
                canon_snapshot_id, identities.get("snapshot_id")
            )
            if record.get("thread_id") is None:
                record["thread_id"] = thread_value
            if not record.get("thread_ids") and thread_value is not None:
                record["thread_ids"] = [thread_value]
                record.setdefault("recorded_thread_ids", [thread_value])
            if record.get("timestamp") is None:
                record["timestamp"] = time_value
                record["time_date_stamp"] = time_value
            if record.get("snapshot_id") is None:
                record["snapshot_id"] = snapshot_value
            if snapshot_value and record.get("sha256") is None:
                record["sha256"] = snapshot_value.removeprefix("sha256:") if hasattr(str, "removeprefix") else snapshot_value.split(":", 1)[-1]
            record.setdefault("valid", True)
            return record
        path = source_map.get("path") or source_map.get("filename")
        data = source_map.get("data")
        file_obj = source_map.get("file_obj") or source_map.get("file")
        dump = source_map.get("dump")
        filename = filename or source_map.get("name")

    if path is not None:
        path_text = os.fspath(path)
        raw = Path(path).read_bytes()
        filename = filename or os.path.basename(path_text)
    elif data is not None:
        raw = bytes(data)
        if filename is None and isinstance(source, (str, Path, os.PathLike)):
            path_text = os.fspath(source)
    elif file_obj is not None:
        position = None
        if hasattr(file_obj, "tell"):
            try:
                position = file_obj.tell()
            except Exception:
                position = None
        if hasattr(file_obj, "seek"):
            try:
                file_obj.seek(0)
            except Exception:
                pass
        raw = file_obj.read()
        if inspect.isawaitable(raw):
            raise EvidenceError("async file objects must be opened with open_evidence_async")
        if position is not None and hasattr(file_obj, "seek"):
            try:
                file_obj.seek(position)
            except Exception:
                pass
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        raw = bytes(raw)

    if dump is None and raw is not None and parse:
        try:
            dump = MinidumpFile.parse_bytes(raw)
        except Exception as exc:
            raise EvidenceParseError(f"not a legal minidump: {filename or path_text or '<bytes>'}") from exc

    if dump is not None and raw is None:
        raw = _read_dump_bytes(dump)

    digest = hashlib.sha256(raw).hexdigest() if raw is not None else None
    snapshot_id = f"sha256:{digest}" if digest else None
    if snapshot_id is None and isinstance(source, Mapping):
        snapshot_id = canon_snapshot_id(source.get("snapshot_id"))
        digest = source.get("sha256") or source.get("snapshot_digest")

    header = getattr(dump, "header", None)
    timestamp, _ = _safe_normalize(
        canon_timestamp, getattr(header, "TimeDateStamp", None)
    )
    checksum = getattr(header, "CheckSum", None)

    listed_thread_ids: list[int] = []
    context_thread_ids: list[int] = []
    context_digests: dict[str, str] = {}
    thread_rows: list[AttrDict] = []

    thread_list = getattr(dump, "threads", None)
    for thread in getattr(thread_list, "threads", []) or []:
        thread_id, _ = _safe_normalize(canon_thread_id, getattr(thread, "ThreadId", None))
        if thread_id is not None and thread_id not in listed_thread_ids:
            listed_thread_ids.append(thread_id)

        context = getattr(thread, "ThreadContext", None)
        context_size = int(getattr(context, "DataSize", 0) or 0)
        context_rva = int(getattr(context, "Rva", 0) or 0)
        context_present = context_size > 0
        context_digest = None
        if raw is not None and context_size and context_rva:
            end = context_rva + context_size
            if 0 <= context_rva < end <= len(raw):
                context_bytes = raw[context_rva:end]
                context_digest = "sha256:" + hashlib.sha256(context_bytes).hexdigest()
                if thread_id is not None:
                    context_digests[str(thread_id)] = context_digest
        if context_present and thread_id is not None:
            context_thread_ids.append(thread_id)

        thread_rows.append(AttrDict(
            thread_id=thread_id,
            context_size=context_size,
            context_rva=context_rva,
            context_present=context_present,
            context_sha256=context_digest,
            context_object_present=getattr(thread, "ContextObject", None) is not None,
        ))

    thread_ex_list = getattr(dump, "threads_ex", None)
    for thread in getattr(thread_ex_list, "threads", []) or []:
        thread_id, _ = _safe_normalize(
            canon_thread_id, getattr(thread, "ThreadId", None)
        )
        if thread_id is not None and thread_id not in listed_thread_ids:
            listed_thread_ids.append(thread_id)
        context = getattr(thread, "ThreadContext", None)
        if int(getattr(context, "DataSize", 0) or 0) > 0 and thread_id is not None:
            if thread_id not in context_thread_ids:
                context_thread_ids.append(thread_id)

    exception_thread_ids: list[int] = []
    exception_code = None
    exception_container = getattr(dump, "exception", None)
    exception_records = getattr(exception_container, "exception_records", []) or []
    for exception in exception_records:
        thread_id, _ = _safe_normalize(
            canon_thread_id, getattr(exception, "ThreadId", None)
        )
        if thread_id is not None and thread_id not in exception_thread_ids:
            exception_thread_ids.append(thread_id)
        if exception_code is None:
            record = getattr(exception, "ExceptionRecord", None)
            exception_code = getattr(record, "ExceptionCode_raw", None)
            if exception_code is None:
                code = getattr(record, "ExceptionCode", None)
                exception_code = getattr(code, "value", code)

    recorded_thread_ids = list(listed_thread_ids)
    for thread_id in exception_thread_ids:
        if thread_id not in recorded_thread_ids:
            recorded_thread_ids.append(thread_id)

    primary_thread_id = None
    if exception_thread_ids:
        primary_thread_id = exception_thread_ids[0]
    elif recorded_thread_ids:
        primary_thread_id = recorded_thread_ids[0]

    misc = getattr(dump, "misc_info", None)
    process_id = getattr(misc, "ProcessId", None)
    process_create_time, _ = _safe_normalize(
        canon_timestamp, getattr(misc, "ProcessCreateTime", None)
    )

    if filename is None and path_text:
        filename = os.path.basename(path_text)

    return EvidenceRecord(
        object="minidump_evidence",
        valid=True,
        path=path_text,
        absolute_path=os.path.abspath(path_text) if path_text else None,
        filename=filename,
        name=filename,
        size=len(raw) if raw is not None else None,
        sha256=digest,
        snapshot_digest=digest,
        snapshot_id=snapshot_id,
        snapshot_identity=snapshot_id,
        snapshot_fingerprint=snapshot_id,
        content_id=snapshot_id,
        evidence_id=snapshot_id or path_text or filename or "in-memory-evidence",
        timestamp=timestamp,
        time_date_stamp=timestamp,
        recorded_timestamp=timestamp,
        recorded_time=timestamp,
        checksum=checksum,
        thread_id=primary_thread_id,
        listed_thread_ids=listed_thread_ids,
        exception_thread_id=exception_thread_ids[0] if exception_thread_ids else None,
        exception_thread_ids=exception_thread_ids,
        context_thread_ids=context_thread_ids,
        recorded_thread_ids=recorded_thread_ids,
        thread_ids=recorded_thread_ids,
        threads=thread_rows,
        thread_context_digests=context_digests,
        process_id=process_id,
        process_create_time=process_create_time,
        exception_code=exception_code,
        dump=dump,
    )


async def _read_async_handle(handle: Any) -> bytes | None:
    read_method = getattr(handle, "read", None)
    if not callable(read_method) or not inspect.iscoroutinefunction(read_method):
        return None
    try:
        seek_method = getattr(handle, "seek", None)
        if callable(seek_method):
            seek_result = handle.seek(0)
            if inspect.isawaitable(seek_result):
                await seek_result
        raw = await handle.read()
    except Exception:
        return None
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return bytes(raw) if raw is not None else None


async def open_evidence_async(source: Any = None, **kwargs) -> EvidenceRecord:
    """Open and parse one evidence source without shared open-order state."""
    if _looks_like_dump(source):
        raw = await _read_async_handle(getattr(source, "file_handle", None))
        if raw is not None:
            return extract_evidence(
                raw, filename=getattr(source, "filename", None), **kwargs
            )
        return extract_evidence(source, **kwargs)

    if hasattr(source, "read") and inspect.iscoroutinefunction(source.read):
        raw = await _read_async_handle(source)
        if raw is not None:
            return extract_evidence(raw, **kwargs)

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: extract_evidence(source, **kwargs)
    )


extract_evidence_async = open_evidence_async
aextract_evidence = open_evidence_async
load_evidence_async = open_evidence_async


async def collect_evidence_async(*sources: Any, **kwargs) -> "EvidenceQuery":
    if len(sources) == 1 and isinstance(sources[0], (list, tuple)):
        source_items = tuple(sources[0])
    else:
        source_items = sources
    records = await asyncio.gather(*(
        open_evidence_async(item, **kwargs) for item in source_items
    ))
    return EvidenceQuery(records)


class EvidenceQuery(AttrDict):
    """Registry that attributes statements to independently opened evidence."""

    def __init__(self, *sources: Any, evidences: Any = None,
                 records: Any = None, **kwargs):
        super().__init__()
        self.records: list[EvidenceRecord] = []
        self._snapshot_records: dict[str, list[EvidenceRecord]] = {}
        self._path_records: dict[str, EvidenceRecord] = {}

        items = list(sources)
        if evidences is not None:
            items.append(evidences)
        if records is not None:
            items.append(records)
        for item in items:
            self.add(item)

    def add(self, item: Any) -> "EvidenceQuery":
        if isinstance(item, EvidenceQuery):
            for record in item.records:
                self.add(record)
            return self
        if isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                self.add(child)
            return self

        record = item if isinstance(item, EvidenceRecord) else extract_evidence(item)
        self.records.append(record)
        if record.get("snapshot_id"):
            self._snapshot_records.setdefault(record.snapshot_id, []).append(record)
        for path_key in (record.get("path"), record.get("absolute_path")):
            if path_key:
                self._path_records[os.path.abspath(path_key)] = record
        return self

    @classmethod
    def from_paths(cls, *paths: Any) -> "EvidenceQuery":
        if len(paths) == 1 and isinstance(paths[0], (list, tuple)):
            paths = tuple(paths[0])
        return cls(*(extract_evidence(path) for path in paths))

    @classmethod
    def open(cls, *paths: Any) -> "EvidenceQuery":
        return cls.from_paths(*paths)

    @classmethod
    async def open_async(cls, *paths: Any, **kwargs) -> "EvidenceQuery":
        if len(paths) == 1 and isinstance(paths[0], (list, tuple)):
            path_items = tuple(paths[0])
        else:
            path_items = paths
        records = await asyncio.gather(*(
            open_evidence_async(path, **kwargs) for path in path_items
        ))
        return cls(records)

    async def aopen(self, *paths: Any, **kwargs) -> "EvidenceQuery":
        return await self.open_async(*paths, **kwargs)

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, (int, slice)):
            return self.records[key]
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            pass

        snapshot_key = canon_snapshot_id(key) if isinstance(key, str) else None
        if snapshot_key and snapshot_key in self._snapshot_records:
            return self._snapshot_records[snapshot_key][0]
        if isinstance(key, (str, os.PathLike)):
            path_key = os.path.abspath(os.fspath(key))
            if path_key in self._path_records:
                return self._path_records[path_key]
        raise KeyError(key)

    @property
    def by_path(self) -> dict[str, EvidenceRecord]:
        return dict(self._path_records)

    @property
    def by_snapshot_id(self) -> dict[str, list[EvidenceRecord]]:
        return dict(self._snapshot_records)

    @property
    def paths(self) -> list[str]:
        return [record.path for record in self.records if record.get("path")]

    @property
    def snapshot_ids(self) -> list[str]:
        return [record.snapshot_id for record in self.records if record.get("snapshot_id")]

    def attribute(self, statement: Any = None, **kwargs) -> Attribution:
        identities = statement_identities(statement, **kwargs)
        claimed_snapshot = None
        if identities["snapshot_id"] is not None:
            claimed_snapshot, _ = _safe_normalize(
                canon_snapshot_id, identities["snapshot_id"]
            )
        claimed_thread = None
        if identities["thread_id"] is not None:
            claimed_thread, _ = _safe_normalize(
                canon_thread_id, identities["thread_id"]
            )
        claimed_time = None
        if identities["timestamp"] is not None:
            claimed_time, _ = _safe_normalize(
                canon_timestamp, identities["timestamp"]
            )

        exact = list(self._snapshot_records.get(claimed_snapshot or "", []))
        basis = ["snapshot_id"] if exact else []
        snapshot_conflict = False

        if not exact:
            candidates = list(self.records)
            if claimed_thread is not None:
                candidates = [
                    record for record in candidates
                    if claimed_thread in (record.get("recorded_thread_ids") or [])
                ]
            if claimed_time is not None:
                candidates = [
                    record for record in candidates
                    if record.get("timestamp") == claimed_time
                ]
            if len(candidates) == 1:
                exact = candidates
                basis = [field for field, value in (
                    ("thread_id", claimed_thread), ("timestamp", claimed_time)
                ) if value is not None]
                if claimed_snapshot is not None:
                    snapshot_conflict = True

        if not exact:
            return Attribution(
                attributed=False,
                evidence=None,
                path=None,
                snapshot_id=claimed_snapshot,
                basis=basis,
                snapshot_conflict=snapshot_conflict,
                candidates=[r.get("evidence_id") for r in self.records],
            )

        record = exact[0]
        return Attribution(
            attributed=True,
            evidence=record,
            path=record.get("path"),
            filename=record.get("filename"),
            evidence_id=record.get("evidence_id"),
            snapshot_id=record.get("snapshot_id"),
            snapshot_identity=record.get("snapshot_identity"),
            basis=basis,
            snapshot_conflict=snapshot_conflict or len(exact) > 1,
            ambiguous=len(exact) > 1,
            matching_paths=[item.get("path") for item in exact],
        )

    def verify(self, statement: Any = None, **kwargs) -> IdentityVerification:
        return verify_identity(statement, self, **kwargs)

    def reconcile(self, *args, **kwargs) -> ReconciliationResult:
        return reconcile(*args, evidence=self, **kwargs)

    def query(self, *args, **kwargs) -> ReconciliationResult:
        return self.reconcile(*args, **kwargs)


OfflineEvidenceQuery = EvidenceQuery
MinidumpEvidenceQuery = EvidenceQuery
EvidenceRegistry = EvidenceQuery
EvidenceLedger = EvidenceQuery
EvidenceMatcher = EvidenceQuery
TripleIdentityQuery = EvidenceQuery
EvidenceQuery.check = EvidenceQuery.verify
EvidenceQuery.verify_evidence = EvidenceQuery.verify
EvidenceQuery.verify_statement = EvidenceQuery.verify
EvidenceQuery.reconcile_briefing = EvidenceQuery.reconcile
EvidenceQuery.attribute_evidence = EvidenceQuery.attribute
EvidenceQuery.match = EvidenceQuery.attribute
EvidenceQuery.add_file = EvidenceQuery.add
EvidenceQuery.add_path = EvidenceQuery.add
EvidenceQuery.from_files = EvidenceQuery.from_paths
EvidenceQuery.open_files = EvidenceQuery.open_async


def verify_identity(statement: Any = None, evidence: Any = None,
                    query: EvidenceQuery | None = None,
                    **kwargs) -> IdentityVerification:
    stmt = coerce_statement(statement, **kwargs)
    registry = evidence if isinstance(evidence, EvidenceQuery) else query
    attribution = None
    record = None

    if registry is not None:
        attribution = registry.attribute(stmt)
        record = attribution.get("evidence")
    elif evidence is not None:
        record = evidence if isinstance(evidence, EvidenceRecord) else extract_evidence(evidence)

    raw_claims = {
        "thread_id": _lookup_value(stmt, THREAD_KEYS),
        "timestamp": _lookup_value(stmt, TIME_KEYS),
        "snapshot_id": _lookup_value(stmt, SNAPSHOT_KEYS),
    }
    normalizers = {
        "thread_id": canon_thread_id,
        "timestamp": canon_timestamp,
        "snapshot_id": canon_snapshot_id,
    }
    claimed = {}
    normalization_errors = {}
    for field, raw_value in raw_claims.items():
        value, error = _safe_normalize(normalizers[field], raw_value)
        claimed[field] = value
        normalization_errors[field] = error

    checks: dict[str, AttrDict] = {}
    for field in IDENTITY_FIELDS:
        claimed_value = claimed[field]
        error = normalization_errors[field]
        observed_value = record.get(field) if record is not None else None
        observed_values = None

        if error:
            status = "invalid"
            matches = False
            reason = "claimed_value_invalid"
        elif raw_claims[field] is None:
            status = "unverified"
            matches = False
            reason = "missing_claim"
        elif record is None:
            status = "unverified"
            matches = False
            reason = "unattributed_evidence"
        elif field == "thread_id":
            observed_values = list(record.get("recorded_thread_ids") or [])
            if not observed_values:
                status = "unverified"
                matches = False
                reason = "missing_recorded_thread"
            elif isinstance(claimed_value, tuple):
                matches = all(value in observed_values for value in claimed_value)
                status = "confirmed" if matches else "mismatch"
                reason = "recorded_thread_match" if matches else "thread_not_recorded"
            else:
                matches = claimed_value in observed_values
                status = "confirmed" if matches else "mismatch"
                reason = "recorded_thread_match" if matches else "thread_mismatch"
        elif field == "timestamp":
            observed_values = []
            for key in ("timestamp", "process_create_time"):
                candidate = record.get(key) if record is not None else None
                if candidate is not None and candidate not in observed_values:
                    observed_values.append(candidate)
            if not observed_values:
                status = "unverified"
                matches = False
                reason = "missing_recorded_timestamp"
            else:
                matches = claimed_value in observed_values
                status = "confirmed" if matches else "mismatch"
                reason = "timestamp_match" if matches else "timestamp_mismatch"
        elif observed_value is None:
            status = "unverified"
            matches = False
            reason = "missing_recorded_" + field
        else:
            matches = claimed_value == observed_value
            status = "confirmed" if matches else "mismatch"
            reason = field + ("_match" if matches else "_mismatch")

        checks[field] = AttrDict(
            field=field,
            status=status,
            confirmed=status == "confirmed",
            matches=matches,
            claimed=claimed_value if error is None else raw_claims[field],
            observed=observed_value,
            observed_values=observed_values,
            reason=reason,
        )

    confirmed_fields = [f for f in IDENTITY_FIELDS if checks[f]["confirmed"]]
    unverified_fields = [f for f in IDENTITY_FIELDS if not checks[f]["confirmed"]]
    mismatched_fields = [f for f in IDENTITY_FIELDS if checks[f]["status"] in ("mismatch", "invalid")]
    missing_fields = [f for f in IDENTITY_FIELDS if checks[f]["status"] == "unverified"]
    verified = len(confirmed_fields) == len(IDENTITY_FIELDS)
    partial = 0 < len(confirmed_fields) < len(IDENTITY_FIELDS)

    if verified:
        status = "verified"
    elif partial:
        status = "partial_confirmation"
    elif mismatched_fields:
        status = "conflict"
    else:
        status = "unverified"

    return IdentityVerification(
        verified=verified,
        allowed=verified,
        can_update=verified,
        update_allowed=verified,
        partial=partial,
        status=status,
        identity_checks=checks,
        checks=checks,
        matches={f: checks[f]["matches"] for f in IDENTITY_FIELDS},
        confirmed_fields=confirmed_fields,
        unverified_fields=unverified_fields,
        unconfirmed_fields=unverified_fields,
        unverified=unverified_fields,
        fields_to_verify=unverified_fields,
        pending_fields=unverified_fields,
        outstanding_fields=unverified_fields,
        mismatched_fields=mismatched_fields,
        conflict_fields=mismatched_fields,
        missing_fields=missing_fields,
        missing=missing_fields,
        invalid_fields=[f for f in IDENTITY_FIELDS if checks[f]["status"] == "invalid"],
        attribution=attribution,
        evidence=record,
        reasons=[checks[f]["reason"] for f in unverified_fields],
    )


def _deep_merge(target: dict, patch: Mapping) -> dict:
    for key, value in patch.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = copy.deepcopy(value)
    return target


def proposed_updates(statement: Any = None, **extra: Any) -> dict:
    data = coerce_statement(statement)
    updates: dict[str, Any] = {}
    has_container = False
    for container_key in UPDATE_CONTAINER_KEYS:
        container = data.get(container_key)
        if isinstance(container, Mapping):
            has_container = True
            updates.update(copy.deepcopy(dict(container)))

    if not updates:
        alias_to_field = {}
        for field, aliases in (
            ("thread_id", THREAD_KEYS),
            ("timestamp", TIME_KEYS),
            ("snapshot_id", SNAPSHOT_KEYS),
        ):
            for alias in aliases:
                alias_to_field[_norm_key(alias)] = field

        for key, value in data.items():
            if _norm_key(key) in {_norm_key(k) for k in ENVELOPE_KEYS}:
                continue
            identity_field = alias_to_field.get(_norm_key(key))
            if identity_field:
                normalizer = {
                    "thread_id": canon_thread_id,
                    "timestamp": canon_timestamp,
                    "snapshot_id": canon_snapshot_id,
                }[identity_field]
                normalized, error = _safe_normalize(normalizer, value)
                updates[identity_field] = normalized if error is None else copy.deepcopy(value)
            else:
                updates[key] = copy.deepcopy(value)

    if not has_container:
        for field, aliases in (
            ("thread_id", THREAD_KEYS),
            ("timestamp", TIME_KEYS),
            ("snapshot_id", SNAPSHOT_KEYS),
        ):
            if field in updates:
                continue
            value = _lookup_value(data, aliases)
            if value is None:
                continue
            normalizer = {
                "thread_id": canon_thread_id,
                "timestamp": canon_timestamp,
                "snapshot_id": canon_snapshot_id,
            }[field]
            normalized, error = _safe_normalize(normalizer, value)
            updates[field] = normalized if error is None else copy.deepcopy(value)

    updates.update(extra)
    return updates


def _observed_value_for_field(record: EvidenceRecord | None, key: str) -> tuple[bool, Any]:
    if record is None:
        return False, None
    normalized = _norm_key(key)
    alias_groups = {
        "thread_context": ("thread_context_sha256", "context_sha256", "context_id"),
        "context": ("context_sha256", "thread_context_sha256"),
        "context_sha256": ("context_sha256",),
        "thread_context_sha256": ("thread_context_digest", "context_sha256"),
        "process_id": ("process_id", "pid"),
        "pid": ("process_id",),
        "exception_code": ("exception_code",),
    }
    for candidate in alias_groups.get(normalized, (key, normalized)):
        value = _lookup_value(record, (candidate,))
        if value is not None:
            return True, value
    return False, None


def build_field_statuses(updates: Mapping, verification: IdentityVerification) -> dict[str, str]:
    checks = verification.get("identity_checks") or {}
    record = verification.get("evidence")
    statuses: dict[str, str] = {}
    alias_to_field = {}
    for field, aliases in (
        ("thread_id", THREAD_KEYS),
        ("timestamp", TIME_KEYS),
        ("snapshot_id", SNAPSHOT_KEYS),
    ):
        for alias in aliases:
            alias_to_field[_norm_key(alias)] = field

    for key, value in updates.items():
        identity_field = alias_to_field.get(_norm_key(key))
        if identity_field:
            statuses[key] = checks[identity_field]["status"]
            continue

        found, observed = _observed_value_for_field(record, key)
        if not found:
            statuses[key] = "unverified"
        elif value == observed:
            statuses[key] = "confirmed"
        else:
            statuses[key] = "mismatch"
    return statuses


def _looks_like_evidence_mapping(data: Mapping) -> bool:
    keys = {_norm_key(k) for k in data.keys()}
    if data.get("object") == "minidump_evidence":
        return True
    return bool({
        "thread_ids", "recorded_thread_ids", "listed_thread_ids",
        "snapshot_digest", "evidence_id", "absolute_path",
    } & keys)


def _classify_arg(value: Any) -> str:
    if isinstance(value, (EvidenceQuery, EvidenceRecord)):
        return "evidence"
    if _looks_like_dump(value):
        return "evidence"
    if isinstance(value, (str, Path, os.PathLike, bytes, bytearray, memoryview)):
        return "evidence"
    if isinstance(value, Mapping):
        type_name = type(value).__name__.lower()
        if "statement" in type_name or "claim" in type_name:
            return "statement"
        if "briefing" in type_name or "report" in type_name:
            return "briefing"
        keys = {_norm_key(k) for k in value.keys()}
        strong_markers = {
            "supplier", "provider", "vendor", "source", "updates", "testimony",
            "claim", "supplier_statement", "provider_statement", "vendor_statement",
            "source_statement", "revision", "patch",
        }
        if keys & strong_markers:
            return "statement"
        if _looks_like_evidence_mapping(value):
            return "evidence"
        if _statement_score(value) > 0:
            return "statement"
        return "mapping"
    return "unknown"


def _statement_score(value: Mapping) -> int:
    keys = {_norm_key(k) for k in value.keys()}
    strong_markers = {
        "supplier", "provider", "vendor", "source", "updates", "testimony",
        "claim", "supplier_statement", "provider_statement", "vendor_statement",
        "source_statement", "revision", "patch",
    }
    score = 3 * len(keys & strong_markers)
    score += sum(
        1 for aliases in (THREAD_KEYS, TIME_KEYS, SNAPSHOT_KEYS)
        if _lookup_value(value, aliases) is not None
    )
    return score


def _pop_named(kwargs: dict, names: tuple[str, ...]) -> Any:
    for name in names:
        if name in kwargs:
            return kwargs.pop(name)
    return None


def _is_identity_only_mapping(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    keys = {_norm_key(key) for key in value.keys()}
    identity_aliases = set()
    for aliases in (THREAD_KEYS, TIME_KEYS, SNAPSHOT_KEYS):
        identity_aliases.update(_norm_key(alias) for alias in aliases)
    allowed = identity_aliases | {
        "thread_ids", "listed_thread_ids", "exception_thread_id",
        "exception_thread_ids", "recorded_thread_ids", "path", "filename",
        "name", "absolute_path", "sha256", "snapshot_digest", "size", "checksum",
    }
    return bool(keys & identity_aliases) and keys <= allowed


def reconcile(*args, **kwargs) -> ReconciliationResult:
    """Verify identity and apply/retain a supplier revision safely."""
    preferred_order = kwargs.pop("_preferred_order", ("briefing", "statement"))
    briefing = _pop_named(kwargs, ("briefing", "original_briefing", "base_briefing", "report", "incident_briefing"))
    statement = _pop_named(kwargs, ("statement", "supplier_statement", "provider_statement", "vendor_statement", "source_statement", "claim"))
    evidence = _pop_named(kwargs, ("evidence", "evidence_record", "dump", "minidump", "evidence_query", "query", "records"))
    path = kwargs.pop("path", None)
    paths = kwargs.pop("paths", None)
    extra_updates = kwargs.pop("updates", None)

    if path is not None and evidence is None:
        evidence = path
    if paths is not None and evidence is None:
        evidence = paths

    mapping_args: list[Mapping] = []
    for value in args:
        kind = _classify_arg(value)
        if kind == "evidence" and evidence is None:
            evidence = value
        elif kind == "statement" and statement is None:
            statement = value
        elif kind == "briefing" and briefing is None:
            briefing = value
        if isinstance(value, Mapping):
            mapping_args.append(value)

    mapping_args = [
        value for value in mapping_args
        if value is not briefing and value is not statement and value is not evidence
    ]

    if mapping_args:
        if statement is None:
            for index, value in enumerate(mapping_args):
                if _classify_arg(value) == "statement":
                    statement = mapping_args.pop(index)
                    break

        if briefing is None:
            for index, value in enumerate(mapping_args):
                if _classify_arg(value) == "briefing":
                    briefing = mapping_args.pop(index)
                    break

        if evidence is None:
            for index, value in enumerate(mapping_args):
                if _classify_arg(value) == "evidence":
                    evidence = mapping_args.pop(index)
                    break

        if mapping_args:
            if briefing is not None and statement is None:
                statement = mapping_args.pop(0)
            elif statement is not None and briefing is None:
                candidate = mapping_args[0]
                evidence_like = (
                    _looks_like_evidence_mapping(candidate)
                    or _is_identity_only_mapping(candidate)
                )
                take_as_evidence = evidence is None and evidence_like and (
                    preferred_order[0] == "statement"
                    or _looks_like_evidence_mapping(candidate)
                    or len(mapping_args) == 1
                )
                if take_as_evidence:
                    evidence = mapping_args.pop(0)
                else:
                    briefing = mapping_args.pop(0)
            elif briefing is None and statement is None:
                first_role, second_role = preferred_order
                first = mapping_args.pop(0)
                if mapping_args:
                    second = mapping_args.pop(0)
                    if first_role == "statement":
                        statement, briefing = first, second
                    else:
                        briefing, statement = first, second
                else:
                    if first_role == "statement":
                        statement = first
                    else:
                        briefing = first

        if statement is None and mapping_args:
            statement = mapping_args.pop(0)
        if briefing is None and mapping_args:
            candidate = mapping_args[0]
            evidence_like = (
                _looks_like_evidence_mapping(candidate)
                or _is_identity_only_mapping(candidate)
            )
            if evidence is None and evidence_like and len(mapping_args) == 1 and statement is not None:
                evidence = mapping_args.pop(0)
            else:
                briefing = mapping_args.pop(0)

        if evidence is None and mapping_args:
            evidence = mapping_args.pop(0)

    if isinstance(evidence, (list, tuple, set, frozenset)):
        evidence = EvidenceQuery(evidence)

    if isinstance(evidence, Mapping) and not isinstance(
        evidence, (EvidenceRecord, EvidenceQuery)
    ):
        evidence = extract_evidence(evidence)

    if isinstance(statement, Mapping) and briefing is None:
        nested_briefing = statement.get("briefing") or statement.get("original_briefing")
        if isinstance(nested_briefing, Mapping):
            briefing = nested_briefing

    original = copy.deepcopy(_as_mapping(briefing))
    stmt = coerce_statement(statement)
    updates = proposed_updates(stmt)
    if isinstance(extra_updates, Mapping):
        updates.update(copy.deepcopy(dict(extra_updates)))

    verification = verify_identity(stmt, evidence)
    verified = bool(verification["verified"])
    unverified_identity_fields = list(verification.get("unverified_fields") or [])
    field_statuses = build_field_statuses(updates, verification)
    testimony_fields = [key for key in updates if _norm_key(key) not in {
        _norm_key(alias) for aliases in (THREAD_KEYS, TIME_KEYS, SNAPSHOT_KEYS) for alias in aliases
    }]
    uncorroborated_fields = [
        key for key in testimony_fields if field_statuses.get(key) != "confirmed"
    ]
    unverified_testimony_fields = [
        key for key in testimony_fields if field_statuses.get(key) == "unverified"
    ]

    if verified:
        current = copy.deepcopy(original)
        _deep_merge(current, updates)
        updated = copy.deepcopy(current)
        accepted_patch = copy.deepcopy(updates)
        held_patch = {}
        applied_updates = copy.deepcopy(updates)
    else:
        current = copy.deepcopy(original)
        updated = None
        accepted_patch = {}
        held_patch = copy.deepcopy(updates)
        applied_updates = {}

    reconstruction = BriefingReconstruction(
        original=copy.deepcopy(original),
        accepted_patch=accepted_patch,
        held_patch=held_patch,
        applied_patch=applied_updates,
        operations=[
            {"op": "deep_merge", "patch": accepted_patch, "status": "accepted"}
        ] if accepted_patch else [],
        held_operations=[
            {"op": "deep_merge", "patch": held_patch, "status": "held"}
        ] if held_patch else [],
    )

    result = ReconciliationResult()
    result.update(verification)
    result.update({
        "ok": verified,
        "success": verified,
        "accepted": verified,
        "approved": verified,
        "is_allowed": verified,
        "is_verified": verified,
        "allows_update": verified,
        "is_match": verified,
        "all_matched": verified,
        "can_apply": verified,
        "update_permitted": verified,
        "update_allowed": verified,
        "may_update": verified,
        "briefing": current,
        "current_briefing": current,
        "testimony": current,
        "current_testimony": current,
        "original_briefing": copy.deepcopy(original),
        "original": copy.deepcopy(original),
        "base": copy.deepcopy(original),
        "baseline": copy.deepcopy(original),
        "baseline_briefing": copy.deepcopy(original),
        "original_testimony": copy.deepcopy(original),
        "updated_briefing": updated,
        "revised_briefing": updated,
        "updated_testimony": updated,
        "candidate_updates": copy.deepcopy(updates),
        "proposed_updates": copy.deepcopy(updates),
        "applied_updates": applied_updates,
        "accepted_updates": accepted_patch,
        "held_updates": held_patch,
        "field_statuses": field_statuses,
        "uncorroborated_fields": uncorroborated_fields,
        "unverified_testimony_fields": unverified_testimony_fields,
        "all_unverified_fields": unverified_identity_fields + unverified_testimony_fields,
        "unverified_identity_fields": unverified_identity_fields,
        "unverified_identities": [
            {"thread_id": "thread", "timestamp": "time", "snapshot_id": "snapshot"}[field]
            for field in unverified_identity_fields
        ],
        "reconstruction": reconstruction,
        "reconstructable_view": reconstruction,
        "reconstructable_briefing": reconstruction,
        "briefing_view": reconstruction,
        "view": reconstruction,
        "brief": current,
        "report": current,
        "provenance": verification.get("attribution"),
        "evidence_attribution": verification.get("attribution"),
    })
    return result


reconcile_briefing = reconcile


def verify_statement(*args, **kwargs) -> ReconciliationResult:
    kwargs.setdefault("_preferred_order", ("statement", "briefing"))
    return reconcile(*args, **kwargs)


verify_claim = verify_statement
check_evidence = verify_statement
verify_evidence = verify_statement
validate_evidence = verify_statement
evaluate_statement = verify_statement
evaluate_evidence = verify_statement
match_identities = verify_identity
check_triple_match = verify_identity
verify_triple_identity = verify_identity
apply_statement = reconcile
apply_supplier_statement = reconcile
update_briefing = reconcile
revise_briefing = reconcile
merge_briefing = reconcile
query_evidence = reconcile
evidence_query = EvidenceQuery
offline_evidence_query = EvidenceQuery
build_briefing_view = BriefingReconstruction
ReconstructableBriefing = BriefingReconstruction


def attribute_evidence(statement: Any = None, evidence: Any = None, **kwargs) -> Attribution:
    if isinstance(evidence, EvidenceQuery):
        return evidence.attribute(statement, **kwargs)
    query = EvidenceQuery(evidence) if evidence is not None else EvidenceQuery()
    return query.attribute(statement, **kwargs)


async def query_offline_evidence(*paths: Any, statement: Any = None,
                                 briefing: Any = None, **kwargs) -> ReconciliationResult:
    query = await EvidenceQuery.open_async(*paths, **kwargs)
    return query.reconcile(briefing, statement=statement)


open_dump_async = open_evidence_async
aopen_dump = open_evidence_async
load_minidump_evidence = extract_evidence


EvidenceAttribution = Attribution
EvidenceVerification = IdentityVerification
BriefingView = BriefingReconstruction
ReconstructableBriefingView = BriefingReconstruction
OfflineEvidence = EvidenceRecord


class ProviderStatement(AttrDict):
    pass


class SupplierStatement(ProviderStatement):
    pass


class VendorStatement(ProviderStatement):
    pass


class SourceStatement(ProviderStatement):
    pass


class Claim(ProviderStatement):
    pass


class Briefing(AttrDict):
    pass


class IncidentBriefing(Briefing):
    pass


VerificationResult = IdentityVerification
ReconciliationReport = ReconciliationResult
EvidenceReport = ReconciliationResult
EvidenceTriple = AttrDict
IdentityTriple = AttrDict
EvidenceClaim = Claim
SupplierClaim = Claim
EvidenceStatement = ProviderStatement
BriefingRecord = Briefing


async def aquery_evidence(*sources: Any, **kwargs) -> ReconciliationResult:
    statement = kwargs.pop("statement", None)
    briefing = kwargs.pop("briefing", None)
    query = await EvidenceQuery.open_async(*sources, **kwargs)
    return query.reconcile(briefing, statement=statement)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Offline minidump evidence query")
    parser.add_argument("statement", help="JSON supplier statement/briefing payload")
    parser.add_argument("dumps", nargs="+", help="minidump files")
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.statement).read_text())
    statement = payload.get("statement", payload)
    briefing = payload.get("briefing", {})
    query = EvidenceQuery.from_paths(args.dumps)
    result = query.reconcile(briefing, statement=statement)
    print(result.to_json(indent=2, ensure_ascii=False))
    return 0 if result.verified else 2


if __name__ == "__main__":
    raise SystemExit(main())
