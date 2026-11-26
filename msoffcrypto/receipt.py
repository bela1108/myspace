"""Read-only forensic receipts for Office format observations.

The receipt layer is deliberately separate from OfficeFile.  Inspecting a
sample never loads a key, decrypts a package, or asks for a credential.  It
records only facts that can be derived from the public container structure:
the detected Office family, the container layout, and a deterministic digest
over the sample.

A receipt is an append-only adjudication record.  Every event is written as a
single JSON line to a journal and a JSON snapshot is refreshed atomically next
to it.  A process that stops while a journal line is being written leaves a
partial tail; Receipt discards only that tail when it is reopened.  All
complete observations remain effective.

The two review actions that matter to a case are:

correction
    A later finding that changes one observation (for example a corrected
    format name or a permission finding).  It is appended; it never rewrites
    another observation and it never removes a pending one.

renewal
    A confirmed format conclusion may be renewed once.  The limit is stored in
    the journal, so an interrupted run that is executed again cannot grant a
    second renewal.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import struct
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from xml.etree import ElementTree

import olefile


SCHEMA_VERSION = 1
RECEIPT_KIND = "msoffcrypto.read_only_receipt"
JOURNAL_KIND = "msoffcrypto.read_only_receipt.event"

PENDING = "pending"
CONFIRMED = "confirmed"
CORRECTED = "corrected"

MAX_RENEWALS = 1

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_OOXML_CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"

_KNOWN_FORMATS = {"doc97", "xls97", "ppt97", "ooxml"}
_EVENT_KINDS = {
    "case_opened",
    "run_started",
    "observation",
    "confirmation",
    "correction",
    "renewal",
    "checkpoint",
    "journal_repaired",
}

_PENDING_ALIASES = {
    "pending",
    "pending_verification",
    "pending-verification",
    "needs_review",
    "needs-review",
    "needs_verification",
    "unconfirmed",
    "unverified",
    "unknown",
    "indeterminate",
    "manual_review",
    "review_required",
    "待查",
    "待核",
    "待核验",
    "待验证",
    "待确认",
    "未确认",
}

_CONFIRMED_ALIASES = {
    "confirmed",
    "confirm",
    "verified",
    "verify",
    "accepted",
    "accept",
    "retained",
    "retain",
    "resolved",
    "approved",
    "valid",
    "已确认",
    "已核实",
    "确认",
    "保留",
}


class ReceiptError(Exception):
    """Base class for receipt errors."""


class ReceiptReadOnlyError(ReceiptError):
    """Raised when a caller tries to mutate a read-only receipt."""


class InterruptedWriteError(ReceiptError):
    """Raised after a deliberately interrupted journal write."""

    def __init__(
        self,
        message: str,
        *,
        path: Any = None,
        events_written: int = 0,
        observations_written: int = 0,
        partial_bytes: int = 0,
        receipt: Any = None,
    ):
        super().__init__(message)
        self.path = path
        self.events_written = events_written
        self.observations_written = observations_written
        self.partial_bytes = partial_bytes
        self.receipt = receipt


class RenewalLimitError(ReceiptError):
    """Raised when a caller requests more renewals than the receipt allows."""


class ObservationNotFoundError(ReceiptError, KeyError):
    """Raised when an observation id is not in the receipt."""


class InspectionError(ReceiptError):
    """Raised when a sample cannot be inspected at all."""


class ReviewStatus(str):
    """A status string that also compares equal to common review synonyms."""

    __slots__ = ("aliases", "name")

    def __new__(cls, value: str, aliases: Iterable[str] = (), name: str | None = None):
        obj = str.__new__(cls, value)
        object.__setattr__(obj, "aliases", frozenset({value.casefold(), *(str(a).casefold() for a in aliases)}))
        object.__setattr__(obj, "name", name or value.upper())
        return obj

    @property
    def value(self) -> str:
        return str(self)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return str.__eq__(self, other) or str(other).strip().casefold() in self.aliases
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self) -> int:
        return str.__hash__(self)


PENDING_STATUS = ReviewStatus(PENDING, _PENDING_ALIASES, "PENDING")
CONFIRMED_STATUS = ReviewStatus(CONFIRMED, _CONFIRMED_ALIASES, "CONFIRMED")
CORRECTED_STATUS = ReviewStatus(CORRECTED, _CONFIRMED_ALIASES | {CORRECTED}, "CORRECTED")


class ObservationStatus:
    """Status names used by observations."""

    PENDING = PENDING_STATUS
    PENDING_VERIFICATION = PENDING_STATUS
    UNCONFIRMED = PENDING_STATUS
    NEEDS_REVIEW = PENDING_STATUS
    CONFIRMED = CONFIRMED_STATUS
    VERIFIED = CONFIRMED_STATUS
    CORRECTED = CORRECTED_STATUS


class ConclusionStatus(ObservationStatus):
    """Compatibility alias for ObservationStatus."""


class ReceiptStatus(ObservationStatus):
    """Compatibility alias for ObservationStatus."""


class Record(dict):
    """Dictionary record with attribute access and JSON helpers."""

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

    def to_dict(self) -> dict[str, Any]:
        return _plain(self)

    def to_json(self, path: str | os.PathLike[str] | None = None, **json_kwargs: Any) -> str:
        json_kwargs.setdefault("indent", 2)
        json_kwargs.setdefault("ensure_ascii", False)
        payload = json.dumps(_plain(self), **json_kwargs)
        if path is not None:
            Path(path).write_text(payload, encoding="utf-8")
        return payload


class ObservationCollection(list):
    """A list of observations that also supports lookup by observation id."""

    def __init__(self, values=(), by_id: Mapping[str, Any] | None = None):
        super().__init__(values)
        self._by_id = dict(by_id or {})

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._by_id[key]
        return super().__getitem__(key)

    def get(self, key, default=None):
        if isinstance(key, str):
            return self._by_id.get(key, default)
        try:
            return super().__getitem__(key)
        except (IndexError, TypeError):
            return default

    def keys(self):
        return self._by_id.keys()

    def values(self):
        return self._by_id.values()

    def items(self):
        return self._by_id.items()


Observation = Record
FormatObservation = Record
FormatConclusion = Record
PublicProperties = Record
Correction = Record
Renewal = Record
ResumeResult = Record
VerificationResult = Record
ReviewRecord = Record
ReceiptRecord = Record
ObservationRecord = Record
ConclusionRecord = Record


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, ReviewStatus):
        return str(value)
    if isinstance(value, (Path, os.PathLike)):
        return os.fspath(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


def _wrap(value: Any) -> Any:
    if isinstance(value, Mapping):
        return Record({key: _wrap(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_wrap(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_wrap(item) for item in value)
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now(clock: Any = None) -> str:
    if clock is not None:
        value = clock() if callable(clock) else clock
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.isoformat()
        return str(value)
    return datetime.now(timezone.utc).isoformat()


def _normalize_status(value: Any, *, default: str = PENDING) -> str:
    if value is None:
        return default
    text = str(value).strip().casefold()
    if text in _PENDING_ALIASES:
        return PENDING
    if text in _CONFIRMED_ALIASES:
        return CONFIRMED
    if text == CORRECTED:
        return CORRECTED
    return default


def _status_object(value: Any, *, default: str = PENDING) -> ReviewStatus:
    status = _normalize_status(value, default=default)
    if status == CONFIRMED:
        return CONFIRMED_STATUS
    if status == CORRECTED:
        return CORRECTED_STATUS
    return PENDING_STATUS


def _normalize_stream_name(name: Any) -> str:
    if name is None:
        return ""
    text = str(name).replace("\\", "/")
    parts = []
    for part in text.split("/"):
        part = part.strip().lstrip("\x06").strip()
        if part:
            parts.append(part)
    return "/".join(parts)


def _as_bytes(source: Any) -> tuple[bytes, str | None, str]:
    """Return (data, source_path, default_subject) without closing handles."""

    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source), None, "memory"

    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        with open(path, "rb") as handle:
            return handle.read(), path, Path(path).name

    if hasattr(source, "getvalue"):
        try:
            data = source.getvalue()
            if isinstance(data, str):
                data = data.encode("utf-8")
            name = getattr(source, "name", None)
            return bytes(data), name, Path(str(name or "memory")).name
        except Exception:
            pass

    if hasattr(source, "read"):
        position = None
        if hasattr(source, "tell"):
            try:
                position = source.tell()
            except Exception:
                position = None
        try:
            if hasattr(source, "seek"):
                source.seek(0)
            data = source.read()
        finally:
            if position is not None and hasattr(source, "seek"):
                with contextlib.suppress(Exception):
                    source.seek(position)
        if isinstance(data, str):
            data = data.encode("utf-8")
        name = getattr(source, "name", None)
        return bytes(data), name, Path(str(name or "memory")).name

    raise InspectionError(f"Unsupported sample source: {type(source)!r}")


def _ole_entries(ole: olefile.OleFileIO) -> tuple[dict[str, list[str]], list[str]]:
    streams: dict[str, list[str]] = {}
    storages: list[str] = []
    for entry in ole.listdir(streams=True, storages=False):
        key = _normalize_stream_name("/".join(entry)).casefold()
        if key:
            streams[key] = list(entry)
    for entry in ole.listdir(streams=False, storages=True):
        key = _normalize_stream_name("/".join(entry))
        if key:
            storages.append(key)
    return streams, sorted(storages, key=str.casefold)


def _read_ole_stream(ole: olefile.OleFileIO, entry: list[str], limit: int | None = None) -> bytes:
    stream = ole.openstream(entry)
    try:
        return stream.read() if limit is None else stream.read(limit)
    finally:
        with contextlib.suppress(Exception):
            stream.close()


def _find_stream(streams: Mapping[str, list[str]], *names: str) -> list[str] | None:
    for name in names:
        key = name.casefold()
        if key in streams:
            return streams[key]
    return None


def _parse_ooxml_encryption(data: bytes) -> Record:
    result = Record({"encrypted": True, "scheme": "unknown", "metadata": {}})
    if len(data) < 4:
        result["parse_error"] = "EncryptionInfo is shorter than 4 bytes"
        return result
    major, minor = struct.unpack_from("<HH", data, 0)
    result["version"] = {"major": major, "minor": minor}
    if (major, minor) == (4, 4):
        result["scheme"] = "agile"
        result["metadata"] = _parse_agile_metadata(data[8:])
    elif major in (2, 3, 4) and minor == 2:
        result["scheme"] = "standard"
        result["metadata"] = _parse_standard_metadata(data)
    elif major in (3, 4) and minor == 3:
        result["scheme"] = "extensible"
        result["metadata"] = {}
    else:
        result["parse_error"] = f"Unsupported EncryptionInfo version {major}:{minor}"
    return result


def _local_name(tag: Any) -> str:
    text = str(tag)
    return text.rsplit("}", 1)[-1] if "}" in text else text


def _attrs_without_secrets(element: ElementTree.Element) -> dict[str, str]:
    secret_markers = ("salt", "encrypted", "verifier", "hmac", "value")
    return {
        _local_name(key): value
        for key, value in element.attrib.items()
        if not any(marker in _local_name(key).casefold() for marker in secret_markers)
    }


def _parse_agile_metadata(xml_bytes: bytes) -> Record:
    try:
        root = ElementTree.fromstring(xml_bytes)
    except Exception as exc:
        return Record({"parse_error": f"Agile EncryptionInfo is not valid XML: {exc}"})

    metadata: dict[str, Any] = {}
    encrypted_key_count = 0
    for element in root.iter():
        name = _local_name(element.tag)
        attrs = _attrs_without_secrets(element)
        if name == "keyData":
            metadata["key_data"] = attrs
        elif name == "encryptedKey":
            encrypted_key_count += 1
            metadata.setdefault("encrypted_keys", []).append(attrs)
    metadata["encrypted_key_count"] = encrypted_key_count

    keys = metadata.get("encrypted_keys") or []
    if keys:
        first = keys[0]
        metadata["password"] = {
            "spin_count": _maybe_int(first.get("spinCount")),
            "key_bits": _maybe_int(first.get("keyBits")),
            "hash_algorithm": first.get("hashAlgorithm"),
            "cipher_algorithm": first.get("cipherAlgorithm"),
            "cipher_chaining": first.get("cipherChaining"),
            "block_size": _maybe_int(first.get("blockSize")),
        }
    return Record(metadata)


def _maybe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_standard_metadata(data: bytes) -> Record:
    metadata: dict[str, Any] = {}
    try:
        flags = struct.unpack_from("<I", data, 0)[0]
        header_size = struct.unpack_from("<I", data, 4)[0]
        header = data[8 : 8 + header_size]
        if len(header) < 32:
            raise ValueError("encryption header is too short")
        fields = struct.unpack_from("<IIIIIIII", header, 0)
        alg_id = fields[2]
        metadata.update(
            {
                "flags": flags,
                "header_size": header_size,
                "alg_id": alg_id,
                "alg_id_hash": fields[3],
                "key_size": fields[4],
                "provider_type": fields[5],
                "cipher": {
                    0x6801: "RC4",
                    0x660E: "AES-128",
                    0x660F: "AES-192",
                    0x6610: "AES-256",
                }.get(alg_id, "unknown"),
            }
        )
    except Exception as exc:
        metadata["parse_error"] = str(exc)
    return Record(metadata)


def _doc97_encryption(ole: olefile.OleFileIO, streams: Mapping[str, list[str]]) -> Record:
    entry = _find_stream(streams, "WordDocument")
    result = Record({"encrypted": None, "scheme": None, "metadata": {}})
    if entry is None:
        return result
    try:
        header = _read_ole_stream(ole, entry, 0x44)
        if len(header) < 12:
            result["parse_error"] = "WordDocument FIB is too short"
            return result
        flags = struct.unpack_from("<H", header, 10)[0]
        encrypted = bool(flags & (1 << 8))
        obfuscated = bool(flags & (1 << 15))
        which_table = (flags >> 9) & 1
        ikey = struct.unpack_from("<I", header, 14)[0] if len(header) >= 18 else None
        result.update(
            {
                "encrypted": encrypted,
                "metadata": {
                    "n_fib": struct.unpack_from("<H", header, 2)[0],
                    "f_obfuscation": obfuscated,
                    "which_table": which_table,
                    "ikey_present": bool(ikey),
                },
            }
        )
        if not encrypted:
            return result
        if obfuscated:
            result["scheme"] = "xor"
            return result
        table_entry = _find_stream(streams, "1Table" if which_table else "0Table")
        if table_entry is None:
            result["scheme"] = "unknown"
            result["parse_error"] = "encryption table stream is missing"
            return result
        version = _read_ole_stream(ole, table_entry, 4)
        if len(version) < 4:
            result["scheme"] = "unknown"
            return result
        major, minor = struct.unpack_from("<HH", version, 0)
        result["version"] = {"major": major, "minor": minor}
        if (major, minor) == (1, 1):
            result["scheme"] = "rc4"
        elif major in (2, 3, 4) and minor == 2:
            result["scheme"] = "rc4_cryptoapi"
        else:
            result["scheme"] = "unknown"
    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


def _xls97_encryption(ole: olefile.OleFileIO, streams: Mapping[str, list[str]]) -> Record:
    entry = _find_stream(streams, "Workbook", "Book")
    result = Record({"encrypted": False, "scheme": None, "metadata": {}})
    if entry is None:
        result["encrypted"] = None
        return result
    try:
        data = _read_ole_stream(ole, entry, 4 * 1024 * 1024)
        position = 0
        while position + 4 <= len(data):
            record_id, record_size = struct.unpack_from("<HH", data, position)
            payload_start = position + 4
            payload_end = payload_start + record_size
            if payload_end > len(data):
                break
            if record_id == 0x002F:
                result["encrypted"] = True
                if record_size >= 2:
                    encryption_type = struct.unpack_from("<H", data, payload_start)[0]
                    result["metadata"] = {"encryption_type": encryption_type}
                    if encryption_type == 0x0000:
                        result["scheme"] = "xor"
                    elif encryption_type == 0x0001 and record_size >= 6:
                        major, minor = struct.unpack_from("<HH", data, payload_start + 2)
                        result["version"] = {"major": major, "minor": minor}
                        if (major, minor) == (1, 1):
                            result["scheme"] = "rc4"
                        elif major in (2, 3, 4) and minor == 2:
                            result["scheme"] = "rc4_cryptoapi"
                        else:
                            result["scheme"] = "unknown"
                else:
                    result["scheme"] = "unknown"
                break
            if record_id == 0x000A:
                break
            position = payload_end
    except Exception as exc:
        result["encrypted"] = None
        result["parse_error"] = str(exc)
    return result


def _ppt97_encryption(data: bytes) -> Record:
    result = Record({"encrypted": None, "scheme": None, "metadata": {}})
    try:
        from msoffcrypto.format.ppt97 import Ppt97File

        office_file = Ppt97File(io.BytesIO(data))
        encrypted = bool(office_file.is_encrypted())
        result["encrypted"] = encrypted
        result["scheme"] = "rc4_cryptoapi" if encrypted else None
    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


def _zip_members(data: bytes) -> tuple[list[str], bool, str | None, bool]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = sorted(archive.namelist(), key=str.casefold)
            is_ooxml = False
            if "[Content_Types].xml" in names:
                try:
                    root = ElementTree.fromstring(archive.read("[Content_Types].xml"))
                    namespace = root.tag.split("}", 1)[0].lstrip("{") if "}" in root.tag else ""
                    is_ooxml = _local_name(root.tag) == "Types" and namespace == _OOXML_CONTENT_TYPES_NS
                except Exception:
                    is_ooxml = any(name.casefold().startswith(("word/", "xl/", "ppt/")) for name in names)
            lowered = {name.casefold() for name in names}
            document_type = None
            if "word/document.xml" in lowered:
                document_type = "docx"
            elif "xl/workbook.xml" in lowered:
                document_type = "xlsx"
            elif "ppt/presentation.xml" in lowered:
                document_type = "pptx"
            macro_present = any(name.endswith("vbaproject.bin") for name in lowered)
            return names, is_ooxml, document_type, macro_present
    except Exception:
        return [], False, None, False


def _inspect_bytes(data: bytes, *, subject: str, source: str | None, observed_at: str | None = None) -> Record:
    digest = _sha256_hex(data)
    size = len(data)
    extension = Path(subject).suffix.casefold().lstrip(".") or None
    declared_document_type = {
        "doc": "doc",
        "docx": "docx",
        "docm": "docx",
        "xls": "xls",
        "xlsx": "xlsx",
        "xlsm": "xlsx",
        "ppt": "ppt",
        "pptx": "pptx",
        "pptm": "pptx",
    }.get(extension or "")
    container = "unknown"
    streams: list[str] = []
    storages: list[str] = []
    parts: list[str] = []
    fmt = "unknown"
    family = "unknown"
    document_type: str | None = None
    encrypted: bool | None = None
    encryption: Record | None = None
    macro_present: bool | None = None
    basis: list[str] = []
    candidates: list[str] = []
    parse_errors: list[str] = []
    confidence = "low"

    if data.startswith(_OLE_MAGIC):
        container = "ole"
        basis.append("magic:ole-cfb")
        try:
            ole = olefile.OleFileIO(io.BytesIO(data))
            try:
                stream_map, storages = _ole_entries(ole)
                streams = sorted((_normalize_stream_name("/".join(entry)) for entry in stream_map.values()), key=str.casefold)
                has_encryption_info = _find_stream(stream_map, "EncryptionInfo") is not None
                has_encrypted_package = _find_stream(stream_map, "EncryptedPackage") is not None
                has_word = _find_stream(stream_map, "WordDocument") is not None
                has_excel = _find_stream(stream_map, "Workbook", "Book") is not None
                has_ppt = _find_stream(stream_map, "PowerPoint Document") is not None

                if has_encryption_info:
                    candidates.append("ooxml")
                    entry = _find_stream(stream_map, "EncryptionInfo")
                    info_bytes = _read_ole_stream(ole, entry, 8 * 1024 * 1024) if entry else b""
                    encryption = _parse_ooxml_encryption(info_bytes)
                    encrypted = True
                    if encryption.get("parse_error"):
                        parse_errors.append(f"ooxml: {encryption['parse_error']}")
                    metadata = encryption.get("metadata")
                    if isinstance(metadata, Mapping) and metadata.get("parse_error"):
                        parse_errors.append(f"ooxml: {metadata['parse_error']}")
                    fmt = "ooxml"
                    family = "ooxml"
                    basis.append("ole:EncryptionInfo")
                    if has_encrypted_package:
                        basis.append("ole:EncryptedPackage")
                    else:
                        parse_errors.append("EncryptionInfo exists without EncryptedPackage")
                if has_word:
                    candidates.append("doc97")
                    if fmt == "unknown":
                        fmt, family = "doc97", "word"
                        basis.append("ole:WordDocument")
                    doc_info = _doc97_encryption(ole, stream_map)
                    if encryption is None:
                        encryption = doc_info
                        encrypted = doc_info.get("encrypted")
                    if doc_info.get("parse_error"):
                        parse_errors.append(f"doc97: {doc_info['parse_error']}")
                if has_excel:
                    candidates.append("xls97")
                    if fmt == "unknown":
                        fmt, family = "xls97", "excel"
                        basis.append("ole:Workbook")
                    xls_info = _xls97_encryption(ole, stream_map)
                    if encryption is None:
                        encryption = xls_info
                        encrypted = xls_info.get("encrypted")
                    if xls_info.get("parse_error"):
                        parse_errors.append(f"xls97: {xls_info['parse_error']}")
                if has_ppt:
                    candidates.append("ppt97")
                    if fmt == "unknown":
                        fmt, family = "ppt97", "powerpoint"
                        basis.append("ole:PowerPoint Document")
                    ppt_info = _ppt97_encryption(data)
                    if encryption is None:
                        encryption = ppt_info
                        encrypted = ppt_info.get("encrypted")
                    if ppt_info.get("parse_error"):
                        parse_errors.append(f"ppt97: {ppt_info['parse_error']}")

                if len(candidates) > 1:
                    parse_errors.append("multiple Office format markers: " + ", ".join(candidates))
                if fmt == "ooxml":
                    document_type = None
                    if encryption and encryption.get("scheme") in {"agile", "standard", "extensible"}:
                        confidence = "high"
                    else:
                        confidence = "medium"
                elif fmt in {"doc97", "xls97", "ppt97"}:
                    confidence = "high" if encrypted is not None else "medium"
                elif fmt == "unknown":
                    confidence = "low"
                    basis.append("ole:no-recognized-office-stream")
            finally:
                with contextlib.suppress(Exception):
                    ole.close()
        except Exception as exc:
            parse_errors.append(f"ole: {exc}")
            confidence = "low"
    elif data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) or zipfile.is_zipfile(io.BytesIO(data)):
        container = "zip"
        basis.append("magic:zip")
        parts, is_ooxml, document_type, macro_present = _zip_members(data)
        encrypted = False
        encryption = None
        if is_ooxml:
            fmt, family = "ooxml", "ooxml"
            confidence = "high"
            basis.append("zip:[Content_Types].xml")
            if document_type:
                basis.append(f"zip:{document_type}-main-part")
        elif parts:
            fmt, family = "zip", "unknown"
            confidence = "low"
            basis.append("zip:not-ooxml")
        else:
            fmt, family = "zip", "unknown"
            confidence = "low"
            parse_errors.append("zip central directory could not be read")
    else:
        basis.append("magic:unrecognized")
        parse_errors.append("unrecognized file signature")

    if fmt in _KNOWN_FORMATS and encrypted is not None and not parse_errors:
        status = CONFIRMED_STATUS
    elif fmt == "ooxml" and encrypted is not None and len(candidates) == 1:
        status = CONFIRMED_STATUS
    else:
        status = PENDING_STATUS

    if fmt == "ooxml" and encrypted is True and encryption is None:
        status = PENDING_STATUS

    properties = Record(
        {
            "size": size,
            "sha256": digest,
            "magic": data[:8].hex(),
            "extension": extension,
            "container": container,
            "format": fmt,
            "streams": streams,
            "stream_names": streams,
            "storages": storages,
            "parts": parts,
            "part_names": parts,
            "document_type": document_type,
            "declared_document_type": declared_document_type,
            "macro_present": macro_present,
            "encrypted": encrypted,
            "encryption": encryption,
            "encryption_scheme": encryption.get("scheme") if encryption else None,
        }
    )

    conclusion = Record(
        {
            "format": fmt,
            "family": family,
            "container": container,
            "type": (encryption.get("scheme") if encryption else "plain") if fmt == "ooxml" else None,
            "document_type": document_type,
            "declared_document_type": declared_document_type,
            "encrypted": encrypted,
            "encryption_scheme": encryption.get("scheme") if encryption else None,
            "confidence": confidence,
            "basis": basis,
            "candidates": candidates,
            "detector": "msoffcrypto-read-only",
            "compatible_with": "msoffcrypto.OfficeFile",
            "initial": True,
            "read_only": True,
            "status": status,
            "confirmed": status == CONFIRMED,
            "pending": status == PENDING,
        }
    )

    observation_id = "obs-" + _sha256_hex(f"observation\0{subject}\0{digest}".encode("utf-8"))[:32]
    observed_at = observed_at
    permission = "pending_review" if encrypted else "not_applicable"
    observation = Record(
        {
            "id": observation_id,
            "observation_id": observation_id,
            "kind": "format_observation",
            "subject": subject,
            "sample": subject,
            "sample_id": subject,
            "specimen": subject,
            "source": source,
            "sample_sha256": digest,
            "digest": digest,
            "size": size,
            "public_properties": properties,
            "public": properties,
            "properties_digest": _sha256_hex(_canonical_json(properties)),
            "initial_conclusion": copy.deepcopy(conclusion),
            "initial_format_conclusion": copy.deepcopy(conclusion),
            "format_conclusion": copy.deepcopy(conclusion),
            "conclusion": copy.deepcopy(conclusion),
            "format": fmt,
            "initial_format": fmt,
            "type": conclusion["type"],
            "family": family,
            "container": container,
            "document_type": document_type,
            "declared_document_type": declared_document_type,
            "encrypted": encrypted,
            "encryption_scheme": conclusion["encryption_scheme"],
            "confidence": confidence,
            "basis": basis,
            "status": status,
            "pending": status == PENDING,
            "confirmed": status == CONFIRMED,
            "handling_permission": permission,
            "permission_reviewed": False,
            "read_only": True,
            "decrypted": False,
            "credential_used": False,
            "renewal_count": 0,
            "renewal_limit": MAX_RENEWALS,
            "renewable": status == CONFIRMED,
            "corrections": [],
            "parse_errors": parse_errors,
            "observed_at": observed_at,
        }
    )
    return observation


def inspect_file(
    source: Any, *, subject: str | None = None, observed_at: str | None = None, **kwargs: Any
) -> Record:
    """Inspect a sample without decrypting it or asking for a credential."""

    # A password is deliberately ignored: observations are read-only and do
    # not attempt decryption.
    data, path, default_subject = _as_bytes(source)
    return _inspect_bytes(data, subject=subject or default_subject, source=path, observed_at=observed_at)


def inspect_bytes(
    data: bytes, *, subject: str = "memory", observed_at: str | None = None, **kwargs: Any
) -> Record:
    """Inspect an in-memory sample without decrypting it."""

    return _inspect_bytes(bytes(data), subject=subject, source=None, observed_at=observed_at)


def _unreadable_observation(source: Any, subject: str | None, error: Exception, observed_at: str | None = None) -> Record:
    source_path = os.fspath(source) if isinstance(source, (str, os.PathLike)) else None
    label = subject or (Path(source_path).name if source_path else "unreadable")
    message = f"{type(error).__name__}: {error}"
    observation_id = "obs-" + _sha256_hex(f"unreadable\0{label}\0{message}".encode("utf-8"))[:32]
    properties = Record(
        {
            "size": None,
            "sha256": None,
            "container": "unavailable",
            "format": "unknown",
            "streams": [],
            "parts": [],
            "encrypted": None,
            "encryption": None,
        }
    )
    conclusion = Record(
        {
            "format": "unknown",
            "family": "unknown",
            "container": "unavailable",
            "type": None,
            "encrypted": None,
            "encryption_scheme": None,
            "confidence": "low",
            "basis": ["source:unreadable"],
            "detector": "msoffcrypto-read-only",
            "compatible_with": "msoffcrypto.OfficeFile",
            "initial": True,
            "read_only": True,
            "status": PENDING_STATUS,
            "confirmed": False,
            "pending": True,
        }
    )
    return Record(
        {
            "id": observation_id,
            "observation_id": observation_id,
            "kind": "format_observation",
            "subject": label,
            "sample": label,
            "sample_id": label,
            "specimen": label,
            "source": source_path,
            "sample_sha256": None,
            "digest": None,
            "size": None,
            "public_properties": properties,
            "public": properties,
            "properties_digest": _sha256_hex(_canonical_json(properties)),
            "initial_conclusion": copy.deepcopy(conclusion),
            "initial_format_conclusion": copy.deepcopy(conclusion),
            "format_conclusion": copy.deepcopy(conclusion),
            "conclusion": copy.deepcopy(conclusion),
            "format": "unknown",
            "initial_format": "unknown",
            "type": None,
            "family": "unknown",
            "container": "unavailable",
            "document_type": None,
            "encrypted": None,
            "encryption_scheme": None,
            "confidence": "low",
            "basis": ["source:unreadable"],
            "status": PENDING_STATUS,
            "pending": True,
            "confirmed": False,
            "handling_permission": "unknown",
            "permission_reviewed": False,
            "read_only": True,
            "decrypted": False,
            "credential_used": False,
            "renewal_count": 0,
            "renewal_limit": MAX_RENEWALS,
            "renewable": False,
            "corrections": [],
            "parse_errors": [message],
            "observed_at": observed_at,
        }
    )


inspect_office_file = inspect_file
read_only_inspect = inspect_file
observe_format = inspect_file
format_observation = inspect_file
observe_file = inspect_file
detect_format = inspect_file
identify_format = inspect_file
inspect_office = inspect_file
create_observation = inspect_file
build_observation = inspect_file


def _event_with_digest(event: Mapping[str, Any]) -> Record:
    result = Record(copy.deepcopy(dict(event)))
    result.pop("digest", None)
    result["digest"] = _sha256_hex(_canonical_json(result))
    return result


def _event_digest(event: Mapping[str, Any]) -> str:
    return str(event.get("digest") or "")


def _new_case_id(path: Path | None) -> str:
    seed = os.fspath(path.resolve()) if path is not None else "memory"
    return "case-" + _sha256_hex(f"case\0{seed}".encode("utf-8"))[:16]


def _planned_sample(source: Any) -> str | None:
    if isinstance(source, (str, os.PathLike)):
        return os.fspath(source)
    return None


def _read_journal(path: Path) -> tuple[list[Record], bool, bytes]:
    if not path.exists() or not path.is_file():
        return [], False, b""
    data = path.read_bytes()
    if not data:
        return [], False, b""
    lines = data.split(b"\n")
    events: list[Record] = []
    partial = b""
    for index, raw in enumerate(lines):
        if not raw.strip():
            continue
        is_last = index == len(lines) - 1
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            if is_last:
                partial = raw
                break
            continue
        if isinstance(payload, Mapping):
            events.append(Record(payload))
    return events, bool(partial), partial


def _read_snapshot(path: Path) -> tuple[Any, bool]:
    if not path.exists() or not path.is_file():
        return None, False
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text), False
    except json.JSONDecodeError:
        salvaged = _salvage_json_objects(text)
        if not salvaged:
            return None, True
        if len(salvaged) == 1:
            return salvaged[0], True
        return salvaged, True


def _salvage_json_objects(text: str) -> list[Any]:
    """Recover complete JSON objects from a truncated JSON document."""

    objects: list[Any] = []
    depth = 0
    start: int | None = None
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                chunk = text[start : index + 1]
                try:
                    objects.append(json.loads(chunk))
                except json.JSONDecodeError:
                    pass
                start = None
    return objects


def _events_from_payload(payload: Any) -> list[Record]:
    if payload is None:
        return []
    if isinstance(payload, list):
        if all(
            isinstance(item, Mapping)
            and ((item.get("event") or item.get("kind")) in _EVENT_KINDS)
            and ("event" in item or "seq" in item)
            for item in payload
        ):
            return [Record(item) for item in payload]
        return []
    if not isinstance(payload, Mapping):
        return []
    events = payload.get("events")
    if isinstance(events, list) and all(isinstance(item, Mapping) for item in events):
        return [Record(item) for item in events]
    return []


def _legacy_observations(payload: Any) -> list[Record]:
    if isinstance(payload, list):
        return [Record(item) for item in payload if isinstance(item, Mapping)]
    if not isinstance(payload, Mapping):
        return []
    for key in ("observations", "items", "materials", "records", "conclusions"):
        value = payload.get(key)
        if isinstance(value, list):
            return [Record(item) for item in value if isinstance(item, Mapping)]
        if isinstance(value, Mapping):
            records = []
            for key, item in value.items():
                if isinstance(item, Mapping):
                    record = Record(item)
                    record.setdefault("id", key)
                    records.append(record)
            return records
    if any(key in payload for key in ("format", "conclusion", "initial_conclusion", "public_properties")):
        return [Record(payload)]
    return []


def _normalize_legacy_observation(value: Mapping[str, Any], index: int) -> Record:
    record = Record(copy.deepcopy(dict(value)))
    conclusion = record.get("conclusion") or record.get("initial_conclusion") or {}
    if not isinstance(conclusion, Mapping):
        conclusion = {}
    fmt = record.get("format") or conclusion.get("format") or record.get("type") or "unknown"
    properties = record.get("public_properties") or record.get("properties") or record.get("public") or {}
    if not isinstance(properties, Mapping):
        properties = {}
    digest = record.get("sample_sha256") or properties.get("sha256") or ""
    subject = record.get("subject") or record.get("sample") or record.get("path") or record.get("name") or f"legacy-{index}"
    subject = str(subject)
    observation_id = record.get("observation_id") or record.get("id")
    if not observation_id:
        observation_id = "obs-" + _sha256_hex(f"observation\0{subject}\0{digest}".encode("utf-8"))[:32]
    status = _status_object(record.get("status") or record.get("state"), default=PENDING)
    if status == CORRECTED:
        status = CONFIRMED_STATUS
    encrypted = record.get("encrypted", properties.get("encrypted"))
    conclusion_record = Record(copy.deepcopy(dict(conclusion))) if conclusion else Record({})
    conclusion_record.setdefault("format", fmt)
    conclusion_record.setdefault("initial", True)
    conclusion_record.setdefault("read_only", True)
    record.update(
        {
            "id": observation_id,
            "observation_id": observation_id,
            "kind": record.get("kind", "format_observation"),
            "subject": subject,
            "source": record.get("source") or record.get("path"),
            "sample_sha256": digest,
            "public_properties": Record(copy.deepcopy(dict(properties))),
            "properties_digest": record.get("properties_digest") or _sha256_hex(_canonical_json(properties)),
            "initial_conclusion": conclusion_record,
            "conclusion": copy.deepcopy(conclusion_record),
            "format": fmt,
            "initial_format": record.get("initial_format", fmt),
            "status": status,
            "pending": status == PENDING,
            "confirmed": status == CONFIRMED,
            "encrypted": encrypted,
            "read_only": True,
            "decrypted": False,
            "credential_used": False,
            "renewal_count": int(record.get("renewal_count") or 0),
            "renewal_limit": int(record.get("renewal_limit") or MAX_RENEWALS),
            "renewable": status == CONFIRMED,
            "corrections": list(record.get("corrections") or []),
            "legacy": True,
        }
    )
    return record


def _legacy_events(payload: Any) -> list[Record]:
    events = _events_from_payload(payload)
    if events:
        return events
    observations = _legacy_observations(payload)
    if not observations:
        return []
    case_id = payload.get("case_id") if isinstance(payload, Mapping) else None
    at = payload.get("created_at") if isinstance(payload, Mapping) else None
    result: list[Record] = []
    result.append(
        _event_with_digest(
            {
                "schema": JOURNAL_KIND,
                "seq": 1,
                "event": "case_opened",
                "case_id": case_id,
                "at": at,
            }
        )
    )
    for index, observation in enumerate(observations):
        normalized = _normalize_legacy_observation(observation, index)
        result.append(
            _event_with_digest(
                {
                    "schema": JOURNAL_KIND,
                    "seq": len(result) + 1,
                    "event": "observation",
                    "at": normalized.get("observed_at"),
                    "observation_id": normalized["observation_id"],
                    "observation": normalized,
                }
            )
        )
    return result


def _merge_events(*groups: Iterable[Mapping[str, Any]]) -> list[Record]:
    merged: list[Record] = []
    seen: set[str] = set()
    for group in groups:
        for event in group:
            record = Record(copy.deepcopy(dict(event)))
            key = _event_digest(record)
            if not key:
                key = _sha256_hex(_canonical_json(record))
            if key in seen:
                continue
            seen.add(key)
            merged.append(record)
    merged.sort(key=lambda item: (int(item.get("seq") or 0), str(item.get("digest") or "")))
    return merged


class Receipt:
    """An append-only, read-only-observation receipt for Office samples."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        case_id: str | None = None,
        clock: Any = None,
        read_only: bool = False,
        readonly: bool | None = None,
        create: bool = True,
    ):
        self.clock = clock
        self.read_only = bool(read_only if readonly is None else readonly)
        self.path = Path(path) if path is not None else None
        if self.path is not None and self.path.suffix.casefold() in {".jsonl", ".ndjson"}:
            self.journal_path = self.path
            self.snapshot_path = self.path.with_name(self.path.stem + ".snapshot.json")
        else:
            self.journal_path = self.path.with_name(self.path.name + ".journal") if self.path is not None else None
            self.snapshot_path = self.path
        self.case_id = case_id or _new_case_id(self.path)
        self.events: list[Record] = []
        self.state: Record = Record(
            {"case_id": self.case_id, "created_at": None, "updated_at": None, "observations": {}, "corrections": [], "renewals": [], "checkpoints": []}
        )
        self.recovered_partial = False
        self.partial_tail: bytes = b""
        self.last_resume: Record | None = None
        self._interrupt_after: int | None = None
        self._observation_appends = 0
        if self.path is not None and (self.path.exists() or (self.journal_path is not None and self.journal_path.exists())):
            self.load()
        elif create and not self.read_only:
            self._append_event({"event": "case_opened", "case_id": self.case_id, "at": _now(self.clock)})

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        data = self.to_dict(include_events=False)
        if name in data:
            return data[name]
        raise AttributeError(name)

    def __contains__(self, observation_id: object) -> bool:
        return observation_id in self.state["observations"]

    @property
    def observations(self) -> list[Record]:
        values = [copy.deepcopy(value) for value in self.state["observations"].values()]
        return ObservationCollection(values, {item["observation_id"]: item for item in values})

    @property
    def observation_map(self) -> dict[str, Record]:
        return {key: copy.deepcopy(value) for key, value in self.state["observations"].items()}

    @property
    def observations_by_id(self) -> dict[str, Record]:
        return self.observation_map

    @property
    def conclusions(self) -> list[Record]:
        return self.observations

    @property
    def conclusion_map(self) -> dict[str, Record]:
        return self.observation_map

    @property
    def pending_observations(self) -> list[Record]:
        values = [item for item in self.observations if item.get("status") == PENDING]
        return ObservationCollection(values, {item["observation_id"]: item for item in values})

    @property
    def confirmed_observations(self) -> list[Record]:
        values = [item for item in self.observations if item.get("status") == CONFIRMED]
        return ObservationCollection(values, {item["observation_id"]: item for item in values})

    @property
    def pending(self) -> list[Record]:
        return self.pending_observations

    @property
    def unconfirmed(self) -> list[Record]:
        return self.pending_observations

    @property
    def unconfirmed_observations(self) -> list[Record]:
        return self.pending_observations

    @property
    def unverified_observations(self) -> list[Record]:
        return self.pending_observations

    @property
    def confirmed(self) -> list[Record]:
        return self.confirmed_observations

    @property
    def pending_count(self) -> int:
        return len(self.pending_observations)

    @property
    def confirmed_count(self) -> int:
        return len(self.confirmed_observations)

    @property
    def retained_count(self) -> int:
        return self.confirmed_count

    @property
    def verified_count(self) -> int:
        return self.confirmed_count

    @property
    def unconfirmed_count(self) -> int:
        return self.pending_count

    @property
    def unverified_count(self) -> int:
        return self.pending_count

    @property
    def observation_count(self) -> int:
        return len(self.observations)

    @property
    def correction_count(self) -> int:
        return sum(len(item.get("corrections") or []) for item in self.observations)

    @property
    def renewal_count(self) -> int:
        return sum(len(item.get("renewals") or []) for item in self.observations)

    @property
    def records(self) -> list[Record]:
        return copy.deepcopy(self.events)

    @property
    def journal(self) -> list[Record]:
        return copy.deepcopy(self.events)

    @property
    def history(self) -> list[Record]:
        return copy.deepcopy(self.events)

    @property
    def receipt(self) -> Record:
        return self.to_dict()

    @property
    def snapshot(self) -> Record:
        return self.to_dict()

    def as_dict(self) -> Record:
        return self.to_dict()

    @property
    def corrections(self) -> list[Record]:
        return [
            copy.deepcopy(correction)
            for item in self.observations
            for correction in (item.get("corrections") or [])
        ]

    @property
    def renewals(self) -> list[Record]:
        return [
            copy.deepcopy(renewal)
            for item in self.observations
            for renewal in (item.get("renewals") or [])
        ]

    def get(self, observation_id: str, default: Any = None) -> Any:
        if observation_id in self.state["observations"]:
            return copy.deepcopy(self.state["observations"][observation_id])
        data = self.to_dict(include_events=False)
        if observation_id in data:
            return data[observation_id]
        return default

    def require(self, observation_id: str) -> Record:
        observation = self.state["observations"].get(observation_id)
        if observation is None:
            text = str(observation_id)
            for candidate in self.state["observations"].values():
                if text in {str(candidate.get("subject")), str(candidate.get("sample")), str(candidate.get("source"))}:
                    return candidate
        if observation is None:
            raise ObservationNotFoundError(observation_id)
        return observation

    def _load_data(self) -> tuple[list[Record], bool, bytes]:
        events: list[Record] = []
        partial = False
        tail = b""
        if self.journal_path is not None:
            journal_events, journal_partial, journal_tail = _read_journal(self.journal_path)
            events.extend(journal_events)
            partial = partial or journal_partial
            if journal_partial:
                tail = journal_tail
        if events and not any((event.get("event") or event.get("kind")) in _EVENT_KINDS for event in events):
            events = _legacy_events({"observations": events})
        snapshot_payload = None
        snapshot_truncated = False
        if self.snapshot_path is not None and self.snapshot_path != self.journal_path:
            snapshot_payload, snapshot_truncated = _read_snapshot(self.snapshot_path)
        snapshot_events = _events_from_payload(snapshot_payload)
        if not snapshot_events and snapshot_payload is not None:
            snapshot_events = _legacy_events(snapshot_payload)
        if snapshot_truncated:
            partial = True
        if not events and snapshot_events:
            events = snapshot_events
        elif events and snapshot_events:
            events = _merge_events(snapshot_events, events)
        return events, partial, tail

    def load(self) -> "Receipt":
        events, partial, tail = self._load_data()
        self.events = events
        self.recovered_partial = partial
        self.partial_tail = tail
        self._rebuild()
        if partial and not self.read_only:
            self._repair_journal()
        return self

    refresh = load

    def _repair_journal(self) -> None:
        if self.journal_path is None or not self.journal_path.exists() or self.read_only:
            return
        data = self.journal_path.read_bytes()
        if not data:
            return
        if data.endswith(b"\n"):
            self.recovered_partial = False
            return
        last_newline = data.rfind(b"\n")
        keep = data[: last_newline + 1] if last_newline >= 0 else b""
        if self.partial_tail:
            self.partial_tail_path = self.journal_path.with_name(self.journal_path.name + ".partial")
            with contextlib.suppress(OSError):
                self.partial_tail_path.write_bytes(self.partial_tail)
        with self.journal_path.open("r+b") as handle:
            handle.seek(0)
            handle.write(keep)
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
        if not any(event.get("event") == "journal_repaired" for event in self.events):
            self._append_event(
                {
                    "event": "journal_repaired",
                    "partial_sha256": _sha256_hex(self.partial_tail) if self.partial_tail else None,
                    "partial_bytes": len(self.partial_tail),
                    "at": _now(self.clock),
                }
            )

    def _rebuild(self) -> None:
        state = Record(
            {
                "case_id": self.case_id,
                "created_at": None,
                "updated_at": None,
                "observations": {},
                "corrections": [],
                "renewals": [],
                "checkpoints": [],
            }
        )
        for event in self.events:
            self._apply_event(state, event)
        if state.get("recovered_partial"):
            self.recovered_partial = True
        if state.get("case_id"):
            self.case_id = str(state["case_id"])
        self.state = state

    def _apply_event(self, state: Record, event: Mapping[str, Any]) -> None:
        kind = event.get("event") or event.get("kind")
        if kind == "case_opened":
            state["case_id"] = event.get("case_id") or state.get("case_id") or self.case_id
            state["created_at"] = event.get("at")
            state["updated_at"] = event.get("at") or state.get("updated_at")
            return
        if kind == "run_started":
            state["planned_samples"] = list(event.get("samples") or [])
            state["planned_count"] = event.get("sample_count")
            state["updated_at"] = event.get("at") or state.get("updated_at")
            return
        if kind == "observation":
            observation = event.get("observation")
            if isinstance(observation, Mapping):
                record = _wrap(copy.deepcopy(dict(observation)))
                observation_id = str(record.get("observation_id") or record.get("id") or event.get("observation_id"))
                record["id"] = observation_id
                record["observation_id"] = observation_id
                record.setdefault("corrections", [])
                record.setdefault("renewal_count", 0)
                record.setdefault("renewal_limit", MAX_RENEWALS)
                record["status"] = _status_object(record.get("status"), default=PENDING)
                record["pending"] = record.get("status") == PENDING
                record["confirmed"] = record.get("status") == CONFIRMED
                record["renewable"] = record.get("status") == CONFIRMED
                state["observations"][observation_id] = record
            state["updated_at"] = event.get("at") or state.get("updated_at")
            return
        observation_id = event.get("observation_id")
        observation = state["observations"].get(observation_id) if observation_id else None
        if kind == "confirmation" and observation is not None:
            observation["status"] = CONFIRMED_STATUS
            observation["pending"] = False
            observation["confirmed"] = True
            observation["renewable"] = observation.get("renewal_count", 0) < MAX_RENEWALS
            observation.setdefault("confirmations", []).append(
                Record({"at": event.get("at"), "actor": event.get("actor"), "basis": event.get("basis")})
            )
            state["updated_at"] = event.get("at") or state.get("updated_at")
            return
        if kind == "correction" and observation is not None:
            correction = Record(
                {
                    "correction_id": event.get("correction_id"),
                    "observation_id": observation_id,
                    "field": event.get("field"),
                    "previous": event.get("previous"),
                    "value": event.get("value"),
                    "reason": event.get("reason"),
                    "actor": event.get("actor"),
                    "at": event.get("at"),
                    "status": event.get("status") or CONFIRMED,
                }
            )
            observation.setdefault("corrections", []).append(correction)
            state["corrections"].append(correction)
            field = str(event.get("field") or "")
            value = copy.deepcopy(event.get("value"))
            if field:
                observation[field] = value
                conclusion = observation.get("conclusion")
                if isinstance(conclusion, Mapping):
                    conclusion[field] = value
                effective = observation.get("format_conclusion")
                if isinstance(effective, Mapping):
                    effective[field] = value
                if field == "format":
                    observation["format"] = value
                elif field == "encrypted":
                    observation["encrypted"] = value
                    observation["handling_permission"] = "pending_review" if value else "not_applicable"
                elif field in {"handling_permission", "permission"}:
                    observation["handling_permission"] = value
                    observation["permission_reviewed"] = True
            status = _status_object(event.get("status"), default=CONFIRMED)
            observation["status"] = status
            observation["pending"] = status == PENDING
            observation["confirmed"] = status == CONFIRMED
            observation["renewable"] = status == CONFIRMED and observation.get("renewal_count", 0) < MAX_RENEWALS
            state["updated_at"] = event.get("at") or state.get("updated_at")
            return
        if kind == "renewal" and observation is not None:
            requested = int(event.get("renewal_count") or 1)
            current = int(observation.get("renewal_count") or 0)
            if current < MAX_RENEWALS and requested <= MAX_RENEWALS:
                observation["renewal_count"] = min(current + 1, MAX_RENEWALS)
                observation["renewable"] = observation["renewal_count"] < MAX_RENEWALS
                renewal = Record(
                    {
                        "observation_id": observation_id,
                        "renewal_count": observation["renewal_count"],
                        "limit": MAX_RENEWALS,
                        "at": event.get("at"),
                        "actor": event.get("actor"),
                        "reason": event.get("reason"),
                    }
                )
                observation.setdefault("renewals", []).append(renewal)
                state["renewals"].append(renewal)
            state["updated_at"] = event.get("at") or state.get("updated_at")
            return
        if kind == "checkpoint":
            checkpoint = Record(copy.deepcopy(dict(event)))
            state["checkpoints"].append(checkpoint)
            state["last_checkpoint"] = checkpoint
            state["updated_at"] = event.get("at") or state.get("updated_at")
            return
        if kind == "journal_repaired":
            state["recovered_partial"] = True
            state.setdefault("recovery", []).append(
                Record(
                    {
                        "at": event.get("at"),
                        "partial_sha256": event.get("partial_sha256"),
                        "partial_bytes": event.get("partial_bytes"),
                    }
                )
            )
            state["updated_at"] = event.get("at") or state.get("updated_at")

    def _append_event(self, event: Mapping[str, Any], *, partial: bool = False) -> Record:
        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        payload = Record(copy.deepcopy(dict(event)))
        payload.setdefault("schema", JOURNAL_KIND)
        if "event" in payload:
            payload.setdefault("kind", payload["event"])
            payload.setdefault("type", payload["event"])
        elif "kind" in payload:
            payload.setdefault("event", payload["kind"])
        payload.setdefault("seq", max((int(item.get("seq") or 0) for item in self.events), default=0) + 1)
        payload.setdefault("at", _now(self.clock))
        payload["case_id"] = payload.get("case_id") or self.case_id
        payload["prev"] = self.events[-1].get("digest") if self.events else None
        payload = _event_with_digest(payload)
        line = (json.dumps(_plain(payload), ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if self.journal_path is not None:
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_journal_line(line, partial=partial)
        if partial:
            raise InterruptedWriteError(
                "journal write was interrupted",
                path=self.journal_path,
                events_written=len(self.events),
                observations_written=self._observation_appends,
                partial_bytes=len(line) // 2,
                receipt=self,
            )
        self.events.append(payload)
        self._apply_event(self.state, payload)
        self.state["updated_at"] = payload["at"]
        if self.snapshot_path is not None:
            self._write_snapshot()
        return copy.deepcopy(payload)

    def _write_journal_line(self, line: bytes, *, partial: bool = False) -> None:
        if self.journal_path is None:
            if partial:
                raise InterruptedWriteError(
                    "journal write was interrupted",
                    path=None,
                    events_written=len(self.events),
                    observations_written=self._observation_appends,
                    partial_bytes=len(line) // 2,
                    receipt=self,
                )
            return
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        chunk = line[: max(1, len(line) // 2)] if partial else line
        descriptor = os.open(self.journal_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            written = 0
            while written < len(chunk):
                count = os.write(descriptor, chunk[written:])
                if count <= 0:
                    raise OSError("short write to receipt journal")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_snapshot(self) -> None:
        if self.snapshot_path is None or self.read_only:
            return
        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict(include_events=True)
        text = json.dumps(_plain(payload), ensure_ascii=False, indent=2)
        descriptor, temp_path = tempfile.mkstemp(
            prefix=self.snapshot_path.name + ".", suffix=".tmp", dir=os.fspath(self.snapshot_path.parent)
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = -1
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.snapshot_path)
            with contextlib.suppress(OSError):
                directory = os.open(os.fspath(self.snapshot_path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            with contextlib.suppress(OSError):
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

    def _check_interrupt_before_observation(self) -> None:
        if self._interrupt_after is not None and self._observation_appends >= self._interrupt_after:
            self._append_event(
                {
                    "event": "observation",
                    "observation_id": "interrupted",
                    "observation": {"observation_id": "interrupted"},
                },
                partial=True,
            )

    def observe(
        self,
        source: Any,
        *,
        subject: str | None = None,
        confirm: bool | None = None,
        metadata: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> Record:
        """Inspect and record a sample.  Existing observations are not duplicated."""

        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        self._check_interrupt_before_observation()
        try:
            observation = inspect_file(source, subject=subject, observed_at=_now(self.clock))
        except Exception as exc:
            observation = _unreadable_observation(source, subject, exc, observed_at=_now(self.clock))
        if metadata:
            observation["metadata"] = Record(copy.deepcopy(dict(metadata)))
        if confirm is True and observation["status"] != CONFIRMED:
            observation["status"] = CONFIRMED
            observation["pending"] = False
            observation["confirmed"] = True
        elif confirm is False and observation["status"] != PENDING:
            observation["status"] = PENDING
            observation["pending"] = True
            observation["confirmed"] = False
        existing = self.state["observations"].get(observation["observation_id"])
        if existing is not None:
            if confirm is True and existing.get("status") != CONFIRMED:
                self._append_event(
                    {
                        "event": "confirmation",
                        "observation_id": observation["observation_id"],
                        "basis": observation.get("basis"),
                        "at": _now(self.clock),
                    }
                )
                return self.state["observations"][observation["observation_id"]]
            if (
                existing.get("status") == PENDING
                and observation.get("status") == CONFIRMED
                and not existing.get("corrections")
            ):
                self._append_event(
                    {
                        "event": "confirmation",
                        "observation_id": observation["observation_id"],
                        "basis": observation.get("basis"),
                        "at": _now(self.clock),
                    }
                )
                return self.state["observations"][observation["observation_id"]]
            return existing
        self._observation_appends += 1
        self._append_event(
            {"event": "observation", "observation_id": observation["observation_id"], "observation": observation}
        )
        return self.state["observations"][observation["observation_id"]]

    def observe_bytes(self, data: bytes, *, subject: str = "memory", confirm: bool | None = None, **kwargs: Any) -> Record:
        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        self._check_interrupt_before_observation()
        observation = inspect_bytes(data, subject=subject, observed_at=_now(self.clock))
        if confirm is True:
            observation["status"] = CONFIRMED
            observation["pending"] = False
            observation["confirmed"] = True
        elif confirm is False:
            observation["status"] = PENDING
            observation["pending"] = True
            observation["confirmed"] = False
        existing = self.state["observations"].get(observation["observation_id"])
        if existing is not None:
            if confirm is True and existing.get("status") != CONFIRMED:
                self._append_event(
                    {
                        "event": "confirmation",
                        "observation_id": observation["observation_id"],
                        "basis": observation.get("basis"),
                        "at": _now(self.clock),
                    }
                )
                return self.state["observations"][observation["observation_id"]]
            return existing
        self._observation_appends += 1
        self._append_event(
            {"event": "observation", "observation_id": observation["observation_id"], "observation": observation}
        )
        return self.state["observations"][observation["observation_id"]]

    record_observation = observe
    add_observation = observe

    def observe_many(
        self,
        samples: Iterable[Any],
        *,
        interrupt_after: int | None = None,
        confirm: bool | None = None,
        **kwargs: Any,
    ) -> "Receipt":
        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        if isinstance(samples, (str, os.PathLike)):
            sources = [samples]
        else:
            sources = list(samples)
        self._interrupt_after = interrupt_after
        self._observation_appends = 0
        self._append_event(
            {
                "event": "run_started",
                "samples": [_planned_sample(source) for source in sources],
                "sample_count": len(sources),
                "resume": False,
                "at": _now(self.clock),
            }
        )
        try:
            for source in sources:
                self.observe(source, confirm=confirm, **kwargs)
        finally:
            self._interrupt_after = None
        return self

    record_many = observe_many

    def confirm(self, observation_id: str, *, actor: str | None = None, basis: Any = None) -> Record:
        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        observation = self.require(observation_id)
        observation_id = observation["observation_id"]
        if observation.get("status") == CONFIRMED:
            return observation
        return self._append_event(
            {
                "event": "confirmation",
                "observation_id": observation_id,
                "actor": actor,
                "basis": basis,
                "at": _now(self.clock),
            }
        )

    def correct(
        self,
        observation_id: str,
        field: str,
        value: Any,
        *,
        reason: str | None = None,
        actor: str | None = None,
        status: str | None = CONFIRMED,
        correction_id: str | None = None,
    ) -> Record:
        """Append a correction for one observation.  Other observations are untouched."""

        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        observation = self.require(observation_id)
        observation_id = observation["observation_id"]
        previous = observation.get(field)
        correction_id = correction_id or "corr-" + _sha256_hex(
            f"correction\0{observation_id}\0{field}\0{_canonical_json(value)!r}\0{len(self.events)}".encode("utf-8")
        )[:20]
        for existing_correction in observation.get("corrections") or []:
            if existing_correction.get("correction_id") == correction_id:
                return copy.deepcopy(existing_correction)
        return self._append_event(
            {
                "event": "correction",
                "correction_id": correction_id,
                "observation_id": observation_id,
                "field": field,
                "previous": previous,
                "value": value,
                "reason": reason,
                "actor": actor,
                "status": status,
                "at": _now(self.clock),
            }
        )

    def accept_correction(self, observation_id: Any, field: str | None = None, value: Any = None, **kwargs: Any) -> Record:
        """Accept a correction record or the explicit observation/field/value form."""

        if isinstance(observation_id, str) and field is None and value is None:
            for correction in self.corrections:
                if correction.get("correction_id") == observation_id:
                    return copy.deepcopy(correction)
        if isinstance(observation_id, Mapping):
            correction = observation_id
            target = (
                correction.get("observation_id")
                or correction.get("target_id")
                or correction.get("target")
                or correction.get("subject")
            )
            if target is None:
                raise ObservationNotFoundError("correction has no observation_id")
            if field is None:
                field = correction.get("field")
            if value is None:
                value = correction.get("value")
            if value is None and isinstance(correction.get("conclusion"), Mapping):
                conclusion = correction["conclusion"]
                if field is None and len(conclusion) == 1:
                    field, value = next(iter(conclusion.items()))
            if field is None:
                raise ReceiptError("correction has no field")
            if "reason" in correction and "reason" not in kwargs:
                kwargs["reason"] = correction.get("reason")
            if "actor" in correction and "actor" not in kwargs:
                kwargs["actor"] = correction.get("actor")
            if "status" in correction and "status" not in kwargs:
                kwargs["status"] = correction.get("status")
            if "accepted" in correction and "status" not in kwargs:
                kwargs["status"] = CONFIRMED if correction.get("accepted") else PENDING
            if "correction_id" in correction and "correction_id" not in kwargs:
                kwargs["correction_id"] = correction.get("correction_id") or correction.get("id")
            observation_id = str(target)
        target_id = str(observation_id)
        if target_id not in self.state["observations"]:
            for candidate in self.observations:
                if target_id in {str(candidate.get("subject")), str(candidate.get("sample")), str(candidate.get("source"))}:
                    target_id = candidate["observation_id"]
                    break
        observation_id = target_id
        if field is None:
            raise ReceiptError("correction field is required")
        existing = kwargs.get("correction_id")
        if existing:
            for correction in self.corrections:
                if correction.get("correction_id") == existing:
                    return copy.deepcopy(correction)
        return self.correct(str(observation_id), field, value, **kwargs)

    apply_correction = accept_correction
    record_correction = accept_correction
    add_correction = correct

    def renew(self, observation_id: str, *, actor: str | None = None, reason: str | None = None) -> Record:
        """Renew a confirmed conclusion at most once."""

        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        observation = self.require(observation_id)
        observation_id = observation["observation_id"]
        if observation.get("status") != CONFIRMED:
            return Record(
                {
                    "observation_id": observation_id,
                    "renewed": False,
                    "renewal_count": int(observation.get("renewal_count") or 0),
                    "limit": MAX_RENEWALS,
                    "reason": "observation is not confirmed",
                    "status": observation.get("status"),
                }
            )
        current = int(observation.get("renewal_count") or 0)
        if current >= MAX_RENEWALS:
            return Record(
                {
                    "observation_id": observation_id,
                    "renewed": False,
                    "renewal_count": current,
                    "limit": MAX_RENEWALS,
                    "reason": "renewal limit reached",
                    "status": observation.get("status"),
                }
            )
        self._append_event(
            {
                "event": "renewal",
                "observation_id": observation_id,
                "renewal_count": current + 1,
                "limit": MAX_RENEWALS,
                "actor": actor,
                "reason": reason,
                "at": _now(self.clock),
            }
        )
        updated = self.require(observation_id)
        return Record(
            {
                "observation_id": observation_id,
                "renewed": True,
                "renewal_count": updated.get("renewal_count"),
                "limit": MAX_RENEWALS,
                "status": updated.get("status"),
            }
        )

    renew_observation = renew
    renew_conclusion = renew
    extend_receipt = renew

    def resume(
        self,
        samples: Iterable[Any] | None = None,
        *,
        renew_confirmed: bool = True,
        confirm_known: bool = True,
        interrupt_after: int | None = None,
    ) -> Record:
        """Continue after an interruption without losing confirmed or pending items."""

        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        if interrupt_after is not None:
            self._interrupt_after = interrupt_after
            self._observation_appends = 0
        before_confirmed = {item["observation_id"] for item in self.confirmed_observations}
        pending_before = {item["observation_id"] for item in self.pending_observations}
        if isinstance(samples, (str, os.PathLike)):
            sources = [samples]
        else:
            sources = list(samples or [])
        if not sources:
            sources = [item for item in (self.state.get("planned_samples") or []) if item]
        if not sources:
            for observation in self.observations:
                source = observation.get("source")
                if source and Path(str(source)).exists():
                    sources.append(source)
        self._append_event(
            {
                "event": "run_started",
                "samples": [_planned_sample(source) for source in sources],
                "sample_count": len(sources),
                "resume": True,
                "at": _now(self.clock),
            }
        )
        observed: list[str] = []
        renewed: list[str] = []
        renewal_skipped: list[str] = []
        for source in sources:
            observation = self.observe(source, confirm=None if confirm_known else False)
            observed.append(observation["observation_id"])
        for observation_id in list(self.state["observations"]):
            observation = self.state["observations"][observation_id]
            if observation.get("status") == CONFIRMED:
                if renew_confirmed and int(observation.get("renewal_count") or 0) == 0:
                    result = self.renew(observation_id, reason="resume after interruption")
                    if result.get("renewed"):
                        renewed.append(observation_id)
                    else:
                        renewal_skipped.append(observation_id)
                elif int(observation.get("renewal_count") or 0) >= MAX_RENEWALS:
                    renewal_skipped.append(observation_id)
        summary = Record(
            {
                "recovered_partial": self.recovered_partial,
                "observed": observed,
                "renewed": renewed,
                "renewed_previously_confirmed": [item for item in renewed if item in before_confirmed],
                "renewal_skipped": renewal_skipped,
                "confirmed_before": sorted(before_confirmed),
                "pending_before": sorted(pending_before),
                "pending_after": [item["observation_id"] for item in self.pending_observations],
                "confirmed_after": [item["observation_id"] for item in self.confirmed_observations],
            }
        )
        self._append_event(
            {
                "event": "checkpoint",
                "run_id": "run-" + _sha256_hex(f"{self.case_id}\0{len(self.events)}".encode("utf-8"))[:16],
                "complete": True,
                "summary": summary,
                "at": _now(self.clock),
            }
        )
        self.last_resume = summary
        self._interrupt_after = None
        return summary

    def checkpoint(self, *, complete: bool = True, summary: Mapping[str, Any] | None = None) -> Record:
        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        return self._append_event(
            {
                "event": "checkpoint",
                "run_id": "run-" + _sha256_hex(f"{self.case_id}\0{len(self.events)}".encode("utf-8"))[:16],
                "complete": complete,
                "summary": Record(copy.deepcopy(dict(summary or {}))),
                "at": _now(self.clock),
            }
        )

    def verify_observation(self, observation_id: str, *, source: Any = None) -> Record:
        observation = self.require(observation_id)
        observation_id = observation["observation_id"]
        candidate_source = source if source is not None else observation.get("source")
        if candidate_source is None:
            return Record(
                {
                    "observation_id": observation_id,
                    "status": "unverifiable",
                    "reproducible": False,
                    "matches": False,
                    "reason": "original sample source is not available",
                }
            )
        try:
            current = inspect_file(candidate_source, subject=observation.get("subject"))
        except Exception as exc:
            return Record(
                {
                    "observation_id": observation_id,
                    "status": "unverifiable",
                    "reproducible": False,
                    "matches": False,
                    "reason": str(exc),
                }
            )
        differences: list[Record] = []
        if current.get("sample_sha256") != observation.get("sample_sha256"):
            differences.append(
                Record(
                    {
                        "field": "sample_sha256",
                        "recorded": observation.get("sample_sha256"),
                        "current": current.get("sample_sha256"),
                    }
                )
            )
        recorded_properties = observation.get("public_properties") or {}
        current_properties = current.get("public_properties") or {}
        if _canonical_json(recorded_properties) != _canonical_json(current_properties):
            differences.append(Record({"field": "public_properties"}))
        matches = not differences
        return Record(
            {
                "observation_id": observation_id,
                "status": "verified" if matches else "mismatch",
                "reproducible": True,
                "matches": matches,
                "recorded_properties_digest": observation.get("properties_digest"),
                "current_properties_digest": current.get("properties_digest"),
                "differences": differences,
            }
        )

    def verify_journal(self) -> Record:
        """Recompute the append-only event digests and predecessor links."""

        errors: list[Record] = []
        previous = None
        for event in self.events:
            digest = event.get("digest")
            expected = _event_with_digest(event).get("digest")
            if digest != expected:
                errors.append(Record({"seq": event.get("seq"), "kind": "digest_mismatch", "expected": expected, "actual": digest}))
            if "prev" in event and event.get("prev") != previous:
                errors.append(
                    Record(
                        {
                            "seq": event.get("seq"),
                            "kind": "predecessor_mismatch",
                            "expected": previous,
                            "actual": event.get("prev"),
                        }
                    )
                )
            previous = digest
        return Record(
            {
                "ok": not errors,
                "event_count": len(self.events),
                "head": self.events[0].get("digest") if self.events else None,
                "tail": self.events[-1].get("digest") if self.events else None,
                "errors": errors,
            }
        )

    def verify(self, *, sources: Mapping[str, Any] | None = None, source: Any = None) -> Record:
        source_map = dict(sources or {})
        results = []
        for observation in self.observations:
            observation_id = observation["observation_id"]
            supply = source if source is not None else (source_map.get(observation_id) or source_map.get(str(observation.get("subject"))))
            results.append(self.verify_observation(observation_id, source=supply))
        counts = {
            "verified": sum(1 for item in results if item.get("status") == "verified"),
            "mismatch": sum(1 for item in results if item.get("status") == "mismatch"),
            "unverifiable": sum(1 for item in results if item.get("status") == "unverifiable"),
        }
        journal = self.verify_journal()
        return Record(
            {
                "ok": counts["mismatch"] == 0 and counts["unverifiable"] == 0 and journal.get("ok"),
                "journal": journal,
                "journal_ok": journal.get("ok"),
                "counts": counts,
                "verified_count": counts["verified"],
                "mismatch_count": counts["mismatch"],
                "unverifiable_count": counts["unverifiable"],
                "results": results,
            }
        )

    def summary(self) -> Record:
        corrections = sum(len(item.get("corrections") or []) for item in self.observations)
        renewals = sum(len(item.get("renewals") or []) for item in self.observations)
        return Record(
            {
                "case_id": self.case_id,
                "observation_count": len(self.observations),
                "confirmed_count": self.confirmed_count,
                "pending_count": self.pending_count,
                "correction_count": corrections,
                "renewal_count": renewals,
                "renewed_count": sum(1 for item in self.observations if int(item.get("renewal_count") or 0) > 0),
                "recovered_partial": self.recovered_partial,
                "event_count": len(self.events),
            }
        )

    def to_dict(self, *, include_events: bool = True) -> Record:
        observations = self.observations
        pending = [item for item in observations if item.get("status") == PENDING]
        confirmed = [item for item in observations if item.get("status") == CONFIRMED]
        corrections = [correction for item in observations for correction in (item.get("corrections") or [])]
        renewals = [renewal for item in observations for renewal in (item.get("renewals") or [])]
        payload = Record(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": RECEIPT_KIND,
                "case_id": self.case_id,
                "created_at": self.state.get("created_at"),
                "updated_at": self.state.get("updated_at"),
                "read_only_analysis": True,
                "decrypted": False,
                "credential_used": False,
                "event_count": len(self.events),
                "journal_digest": self.events[-1].get("digest") if self.events else None,
                "recovered_partial": self.recovered_partial,
                "status": (
                    PENDING_STATUS
                    if pending
                    else (CONFIRMED_STATUS if confirmed else ReviewStatus("empty", {"empty", "none"}, "EMPTY"))
                ),
                "observations": observations,
                "observations_by_id": self.observation_map,
                "conclusions": observations,
                "conclusion_map": self.observation_map,
                "pending": pending,
                "confirmed": confirmed,
                "pending_observations": pending,
                "confirmed_observations": confirmed,
                "corrections": corrections,
                "renewals": renewals,
                "checkpoints": copy.deepcopy(self.state.get("checkpoints") or []),
                "runs": copy.deepcopy(self.state.get("checkpoints") or []),
                "last_checkpoint": copy.deepcopy(self.state.get("last_checkpoint")),
                "resume_count": sum(
                    1
                    for checkpoint in (self.state.get("checkpoints") or [])
                    if isinstance(checkpoint.get("summary"), Mapping)
                    and "recovered_partial" in checkpoint["summary"]
                ),
                "last_resume": copy.deepcopy(self.last_resume),
                "renewed": copy.deepcopy((self.last_resume or {}).get("renewed", [])),
                "renewal_skipped": copy.deepcopy((self.last_resume or {}).get("renewal_skipped", [])),
                "observed": copy.deepcopy((self.last_resume or {}).get("observed", [])),
                "planned_samples": copy.deepcopy(self.state.get("planned_samples") or []),
                "planned_count": self.state.get("planned_count"),
                "observation_count": len(observations),
                "confirmed_count": len(confirmed),
                "pending_count": len(pending),
                "retained_count": len(confirmed),
                "verified_count": len(confirmed),
                "unconfirmed_count": len(pending),
                "unverified_count": len(pending),
                "correction_count": len(corrections),
                "renewal_count": len(renewals),
                "renewed_count": sum(1 for item in observations if int(item.get("renewal_count") or 0) > 0),
                "summary": self.summary(),
            }
        )
        if len(observations) == 1:
            only = observations[0]
            payload.update(
                {
                    "format": only.get("format"),
                    "format_status": only.get("status"),
                    "encrypted": only.get("encrypted"),
                    "sample_sha256": only.get("sample_sha256"),
                    "sample": only.get("subject"),
                }
            )
        if include_events:
            payload["events"] = copy.deepcopy(self.events)
        return payload

    def to_json(self, path: str | os.PathLike[str] | None = None, **json_kwargs: Any) -> str:
        json_kwargs.setdefault("indent", 2)
        json_kwargs.setdefault("ensure_ascii", False)
        text = json.dumps(_plain(self.to_dict()), **json_kwargs)
        if path is not None:
            Path(path).write_text(text, encoding="utf-8")
        return text

    def save(self, path: str | os.PathLike[str] | None = None) -> "Receipt":
        if self.read_only:
            raise ReceiptReadOnlyError("receipt is read-only")
        if path is not None:
            Path(path).write_text(self.to_json(), encoding="utf-8")
            return self
        self._write_snapshot()
        return self

    write = save
    flush = save

    def close(self) -> None:
        return None

    def __enter__(self) -> "Receipt":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    @classmethod
    def from_path(cls, path: Any, **kwargs: Any) -> "Receipt":
        return cls(path, **kwargs)


ReceiptLedger = Receipt
AdjudicationRecord = Receipt
AdjudicationLedger = Receipt
AdjudicationLog = Receipt
ReviewLedger = Receipt
ReadOnlyReceipt = Receipt
ForensicReceipt = Receipt
read_only_receipt = Receipt
FormatReceipt = Receipt
ReceiptReport = Receipt
ForensicReviewReport = Receipt


def load_receipt(path: Any, *, read_only: bool = False, readonly: bool | None = None, **kwargs: Any) -> Receipt:
    """Load a receipt snapshot, a JSONL journal, or a legacy receipt."""

    if isinstance(path, (Mapping, list)):
        receipt = Receipt(None, read_only=read_only, readonly=readonly, create=False)
        receipt.events = _merge_events(_legacy_events(path))
        receipt._rebuild()
        return receipt
    return Receipt(path, read_only=read_only, readonly=readonly, create=False, **kwargs)


def read_receipt(path: Any, *, read_only: bool = True, readonly: bool | None = None, **kwargs: Any) -> Receipt:
    return load_receipt(path, read_only=read_only, readonly=readonly, **kwargs)


open_receipt = load_receipt


def write_receipt(
    samples: Iterable[Any],
    path: Any,
    *,
    case_id: str | None = None,
    resume: bool = True,
    renew_confirmed: bool = True,
    interrupt_after: int | None = None,
    clock: Any = None,
    corrections: Iterable[Mapping[str, Any]] | None = None,
    renewals: Iterable[str] | None = None,
    **kwargs: Any,
) -> Receipt:
    """Create or continue a receipt for one or more samples.

    interrupt_after writes that many complete observation events and then
    leaves a half-written next journal line before raising
    InterruptedWriteError.  Calling this function again resumes from the
    complete prefix.
    """

    if isinstance(samples, (str, os.PathLike)) and not isinstance(path, (str, os.PathLike)):
        samples, path = path, samples
    if isinstance(samples, (str, os.PathLike)):
        samples = [samples]
    else:
        samples = list(samples)
    if interrupt_after is None:
        for alias in ("fault_after", "stop_after", "fail_after", "interrupt_at"):
            if kwargs.get(alias) is not None:
                interrupt_after = int(kwargs[alias])
                break
    receipt = Receipt(path, case_id=case_id, clock=clock)
    had_observations = bool(receipt.state["observations"])
    if interrupt_after is not None:
        receipt._interrupt_after = interrupt_after
        receipt._observation_appends = 0
    try:
        if resume and had_observations:
            receipt.resume(samples, renew_confirmed=renew_confirmed)
        else:
            receipt._append_event(
                {
                    "event": "run_started",
                    "samples": [_planned_sample(sample) for sample in samples],
                    "sample_count": len(samples),
                    "resume": False,
                    "at": _now(receipt.clock),
                }
            )
            for sample in samples:
                receipt.observe(sample)
            receipt.checkpoint(
                complete=True,
                summary={
                    "observation_count": len(receipt.observations),
                    "confirmed_count": receipt.confirmed_count,
                    "pending_count": receipt.pending_count,
                },
            )
        for correction in corrections or []:
            receipt.accept_correction(correction)
        for observation_id in renewals or []:
            receipt.renew(observation_id)
    finally:
        receipt._interrupt_after = None
    return receipt


create_receipt = write_receipt


def _resume_receipt(path: Any, samples: Iterable[Any] | None = None, **kwargs: Any) -> Receipt:
    receipt = Receipt(path)
    receipt.resume(samples, **kwargs)
    return receipt


def resume_receipt(path: Any, samples: Iterable[Any] | None = None, **kwargs: Any) -> Receipt:
    return _resume_receipt(path, samples, **kwargs)


def correct_observation(path: Any, observation_id: str, field: str, value: Any, **kwargs: Any) -> Record:
    receipt = Receipt(path)
    return receipt.correct(observation_id, field, value, **kwargs)


def renew_observation(path: Any, observation_id: str, **kwargs: Any) -> Record:
    receipt = Receipt(path)
    return receipt.renew(observation_id, **kwargs)


def accept_correction(path: Any, correction: Mapping[str, Any], **kwargs: Any) -> Record:
    receipt = Receipt(path)
    return receipt.accept_correction(correction, **kwargs)


def record_observation(source: Any, *, subject: str | None = None, **kwargs: Any) -> Record:
    return inspect_file(source, subject=subject, **kwargs)


def initial_format_conclusion(source: Any, **kwargs: Any) -> Record:
    return inspect_file(source, **kwargs)


initial_conclusion = initial_format_conclusion


def verify_receipt(path: Any, *, sources: Mapping[str, Any] | None = None, source: Any = None) -> Record:
    return load_receipt(path, read_only=True).verify(sources=sources, source=source)


def migrate_legacy_receipt(payload: Any) -> Record:
    """Convert an old format-identification receipt into the current view."""

    events = _legacy_events(payload)
    receipt = Receipt(None, create=False)
    receipt.events = _merge_events(events)
    receipt._rebuild()
    return receipt.to_dict(include_events=False)


__all__ = [
    "SCHEMA_VERSION",
    "MAX_RENEWALS",
    "PENDING",
    "CONFIRMED",
    "CORRECTED",
    "ReceiptError",
    "ReceiptReadOnlyError",
    "InterruptedWriteError",
    "RenewalLimitError",
    "ObservationNotFoundError",
    "InspectionError",
    "ReviewStatus",
    "ObservationStatus",
    "ConclusionStatus",
    "ReceiptStatus",
    "Record",
    "Observation",
    "FormatObservation",
    "FormatConclusion",
    "PublicProperties",
    "Correction",
    "Renewal",
    "ResumeResult",
    "VerificationResult",
    "ReviewRecord",
    "ReceiptRecord",
    "ObservationRecord",
    "ConclusionRecord",
    "Receipt",
    "ReceiptLedger",
    "AdjudicationRecord",
    "AdjudicationLedger",
    "AdjudicationLog",
    "ReviewLedger",
    "ReadOnlyReceipt",
    "ForensicReceipt",
    "read_only_receipt",
    "FormatReceipt",
    "ReceiptReport",
    "ForensicReviewReport",
    "inspect_file",
    "inspect_bytes",
    "inspect_office_file",
    "read_only_inspect",
    "observe_file",
    "observe_format",
    "format_observation",
    "detect_format",
    "identify_format",
    "inspect_office",
    "create_observation",
    "build_observation",
    "load_receipt",
    "read_receipt",
    "open_receipt",
    "write_receipt",
    "create_receipt",
    "resume_receipt",
    "correct_observation",
    "renew_observation",
    "accept_correction",
    "record_observation",
    "initial_format_conclusion",
    "initial_conclusion",
    "verify_receipt",
    "migrate_legacy_receipt",
]
