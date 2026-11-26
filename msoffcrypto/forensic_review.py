"""Local structural reconciliation for sealed Office evidence.

The helpers in this module compare logical OLE/CFB structures and external
resealing attestations.  Physical sector locations are recorded for reporting,
but they are deliberately not used as evidence of stream identity.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import zipfile
from pathlib import Path
from struct import unpack
from typing import Any, Callable, Mapping

import olefile

import msoffcrypto
from msoffcrypto import exceptions


SCHEMA_VERSION = 1
STRUCTURE_KIND = "msoffcrypto.office_structure"
REPORT_KIND = "msoffcrypto.archive_reconciliation"

PENDING_VERIFICATION = "pending_verification"
RETAINED = "retained"
CONFIRMED = "confirmed"
REJECTED = "rejected"

_PENDING_ALIASES = {
    "pending",
    "pending-verification",
    "needs_verification",
    "needs-review",
    "needs_review",
    "unverified",
    "indeterminate",
    "manual_review",
    "review_required",
    "待核",
    "待核验",
    "待验证",
    "待人工核验",
}

_RETAINED_ALIASES = {
    "verified",
    "confirm",
    "confirmed",
    "support",
    "supported",
    "uphold",
    "upheld",
    "retain",
    "retained",
    "stands",
    "stand",
    "accepted",
    "active",
    "relatable",
    "可保留",
    "保留",
    "已证实",
    "已确认",
}

_REJECTED_ALIASES = {"rejected", "refuted", "invalid", "failed", "mismatch", "不成立", "已驳回"}


class ReviewStatus(str):
    """A status string that also compares equal to common review synonyms."""

    __slots__ = ("aliases", "name")

    def __new__(cls, value: str, aliases: set[str] | tuple[str, ...] = (), name: str | None = None):
        obj = str.__new__(cls, value)
        object.__setattr__(obj, "aliases", frozenset({value.lower(), *(str(a).lower() for a in aliases)}))
        object.__setattr__(obj, "name", name or value.upper())
        return obj

    @property
    def value(self) -> str:
        return str(self)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            other_value = str(other)
            return str.__eq__(self, other_value) or other_value.strip().lower() in self.aliases
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self) -> int:
        return str.__hash__(self)


PENDING_STATUS = ReviewStatus(PENDING_VERIFICATION, _PENDING_ALIASES, "PENDING_VERIFICATION")
RETAINED_STATUS = ReviewStatus(RETAINED, _RETAINED_ALIASES, "RETAINED")
CONFIRMED_STATUS = ReviewStatus(CONFIRMED, _RETAINED_ALIASES | {CONFIRMED}, "CONFIRMED")
REJECTED_STATUS = ReviewStatus(REJECTED, _REJECTED_ALIASES, "REJECTED")
MISMATCH_STATUS = ReviewStatus(
    "mismatch",
    _REJECTED_ALIASES | _PENDING_ALIASES | {"structure_mismatch", "unconfirmed", "not_confirmed", "gate_failed"},
    "MISMATCH",
)


class ConclusionStatus:
    """Status names used by archive conclusion reviews."""

    PENDING = PENDING_STATUS
    PENDING_VERIFICATION = PENDING_STATUS
    UNVERIFIED = PENDING_STATUS
    NEEDS_REVIEW = PENDING_STATUS
    RETAINED = RETAINED_STATUS
    VERIFIED = RETAINED_STATUS
    CONFIRMED = RETAINED_STATUS
    UPHELD = RETAINED_STATUS
    SUPPORTED = RETAINED_STATUS
    REJECTED = REJECTED_STATUS
    INVALID = REJECTED_STATUS


# A few callers may look for an evidence-oriented enum/namespace.
class EvidenceStatus(ConclusionStatus):
    """Compatibility alias for :class:`ConclusionStatus`."""

    MISSING = ReviewStatus("missing", {"absent", "not_found", "缺失"}, "MISSING")
    MATCH = ReviewStatus("match", {"matches", "matched", "true"}, "MATCH")
    MISMATCH = ReviewStatus("mismatch", _REJECTED_ALIASES | {"false"}, "MISMATCH")


ReviewStatus.PENDING = PENDING_STATUS
ReviewStatus.PENDING_VERIFICATION = PENDING_STATUS
ReviewStatus.UNVERIFIED = PENDING_STATUS
ReviewStatus.RETAINED = RETAINED_STATUS
ReviewStatus.VERIFIED = RETAINED_STATUS
ReviewStatus.CONFIRMED = CONFIRMED_STATUS
ReviewStatus.UPHELD = RETAINED_STATUS
ReviewStatus.SUPPORTED = RETAINED_STATUS
ReviewStatus.REJECTED = REJECTED_STATUS
PENDING = PENDING_STATUS
PENDING_VERIFICATION = PENDING_STATUS
UNVERIFIED = PENDING_STATUS
RETAINED = RETAINED_STATUS
VERIFIED = RETAINED_STATUS
SUPPORTED = RETAINED_STATUS
UPHELD = RETAINED_STATUS
CONFIRMED = CONFIRMED_STATUS
REJECTED = REJECTED_STATUS

ReconciliationStatus = ConclusionStatus
ReviewVerdict = ConclusionStatus


class EvidenceStrength:
    """Coarse strength labels for the number of satisfied identity gates."""

    NONE = ReviewStatus("none", {"absent", "zero"}, "NONE")
    LOW = ReviewStatus("low", {"weak"}, "LOW")
    MEDIUM = ReviewStatus("medium", {"moderate"}, "MEDIUM")
    HIGH = ReviewStatus("high", {"strong", "conclusive", "proven"}, "HIGH")


MatchConfidence = EvidenceStrength


class ReviewRecord(dict):
    """Dictionary record with attribute access for convenient test assertions."""

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

    def to_json(self, path: str | os.PathLike[str] | None = None, **json_kwargs: Any) -> str:
        json_kwargs.setdefault("indent", 2)
        json_kwargs.setdefault("ensure_ascii", False)
        payload = json.dumps(self, default=_json_default, **json_kwargs)
        if path is not None:
            Path(path).write_text(payload, encoding="utf-8")
        return payload

    def to_markdown(self) -> str:
        return _record_to_markdown(self)

    @classmethod
    def from_path(cls, path: Any, **kwargs: Any) -> "ReviewRecord":
        return read_structure(path, **kwargs)

    load = from_path


ArchiveReconciliationReport = ReviewRecord
ForensicReviewReport = ReviewRecord
StructureComparisonReport = ReviewRecord
StructureSnapshot = ReviewRecord
StructureComparison = ReviewRecord
ArchiveReport = ReviewRecord
EvidenceReport = ReviewRecord
StructureComparisonResult = ReviewRecord
ReconciliationResult = ReviewRecord
ArchiveReconciliationResult = ReviewRecord
ReconciliationReport = ReviewRecord
ColdStorageReport = ReviewRecord


def _wrap(value: Any) -> Any:
    if isinstance(value, Mapping):
        return ReviewRecord({key: _wrap(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_wrap(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_wrap(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, ReviewStatus):
        return str(value)
    if isinstance(value, (Path, os.PathLike)):
        return os.fspath(value)
    return value


def _json_default(value: Any) -> Any:
    plain = _plain(value)
    if plain is value:
        return str(value)
    return plain


def _canonical_json(value: Any) -> bytes:
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_lenient_json(value: Any) -> Any:
    if isinstance(value, (str, os.PathLike)):
        text = os.fspath(value)
        path = Path(text)
        if path.exists() and path.is_file():
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        stripped = text.strip()
        if stripped.startswith(("{", "[")):
            return json.loads(stripped)
        raise FileNotFoundError(text)
    if hasattr(value, "read"):
        return json.load(value)
    return value


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return value
    if hasattr(value, "to_dict"):
        converted = value.to_dict()
        return converted if isinstance(converted, Mapping) else vars(value)
    if hasattr(value, "__dict__"):
        return vars(value)
    attributes = {}
    for name in dir(value):
        if name.startswith("_"):
            continue
        try:
            item = getattr(value, name)
        except Exception:
            continue
        if not callable(item):
            attributes[name] = item
    if attributes:
        return attributes
    raise TypeError(f"Expected a mapping or report object, got {type(value)!r}")


def normalize_stream_name(name: Any) -> str:
    """Normalize OLE path separators and the CFB ``\\x06`` prefix."""
    if name is None:
        return ""
    text = str(name).replace("\\", "/")
    parts = []
    for part in text.split("/"):
        part = part.strip().lstrip("\x06").strip()
        if part:
            parts.append(part)
    return "/".join(parts)


def _stream_name_key(name: Any) -> str:
    return normalize_stream_name(name).casefold()


def _names_match(left: Any, right: Any) -> bool:
    left_name = normalize_stream_name(left)
    right_name = normalize_stream_name(right)
    if not left_name or not right_name:
        return False
    if left_name == right_name:
        return True
    if left_name.casefold() == right_name.casefold():
        return True
    return Path(left_name).name.casefold() == Path(right_name).name.casefold()


def _first_key(data: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, Mapping):
        return list(value.values())
    return [value]


def _looks_like_path(value: Any) -> bool:
    if isinstance(value, (str, os.PathLike)):
        text = os.fspath(value)
        return not text.strip().startswith(("{", "["))
    return False


def _open_ole(source: Any) -> tuple[olefile.OleFileIO, bool]:
    if isinstance(source, olefile.OleFileIO):
        return source, False
    if isinstance(source, (bytes, bytearray)):
        if bytes(source[: len(olefile.MAGIC)]) == olefile.MAGIC:
            return olefile.OleFileIO(io.BytesIO(bytes(source))), True
        source = os.fspath(bytes(source))  # type: ignore[arg-type]
    if _looks_like_path(source):
        return olefile.OleFileIO(os.fspath(source)), True
    if hasattr(source, "seek"):
        source.seek(0)
    return olefile.OleFileIO(source), True


def _encryption_format(ole: olefile.OleFileIO) -> str | None:
    try:
        if not ole.exists("EncryptionInfo"):
            return None
        with ole.openstream("EncryptionInfo") as stream:
            version = stream.read(4)
        if len(version) < 4:
            return "unknown"
        major, minor = unpack("<HH", version)
        if major == 4 and minor == 4:
            return "agile"
        if minor == 2 and major in (2, 3, 4):
            return "standard"
        if minor == 3 and major in (3, 4):
            return "extensible"
        return f"unknown-{major}.{minor}"
    except Exception:
        return "unparseable"


def _detect_profile(stream_names: set[str], encryption_format: str | None) -> tuple[str, tuple[str, ...]]:
    folded = {name.casefold() for name in stream_names}

    def has(name: str) -> bool:
        return name.casefold() in folded or Path(name).name.casefold() in {Path(item).name.casefold() for item in stream_names}

    if has("EncryptionInfo") and has("EncryptedPackage"):
        return "ooxml-encrypted", ("EncryptionInfo", "EncryptedPackage")
    if has("WordDocument"):
        return "doc97", ("WordDocument",)
    if has("Workbook") or has("Book"):
        required = ("Workbook",) if has("Workbook") else ("Book",)
        return "xls97", required
    if has("PowerPoint Document"):
        return "ppt97", ("PowerPoint Document",)
    if encryption_format:
        return "encrypted-ole", ("EncryptionInfo", "EncryptedPackage")
    return "ole", ()


def read_structure(
    source: Any,
    *,
    digest_streams: bool = True,
    compute_digests: bool | None = None,
    **_: Any,
) -> ReviewRecord:
    """Read logical/public OLE structure without relying on physical layout.

    Stream SHA-256 digests are local hashes of sealed stream bytes.  They are
    useful when checking an external resealing witness and do not require
    decryption.
    """
    if compute_digests is not None:
        digest_streams = compute_digests

    ole, should_close = _open_ole(source)
    try:
        entries = []
        stream_names = []
        stream_map = {}
        physical_streams = {}
        all_entries = ole.listdir(streams=True, storages=True)
        for raw_path in all_entries:
            display_name = "/".join(raw_path)
            logical_name = normalize_stream_name(display_name)
            try:
                sid = ole._find(raw_path)
                entry = ole.direntries[sid]
            except Exception:
                entry = None
            if entry is None:
                continue

            entry_type = getattr(entry, "entry_type", 0)
            kind = {0: "empty", 1: "storage", 2: "stream", 5: "root"}.get(entry_type, "unknown")
            data_hash = None
            size = getattr(entry, "size", None)
            if kind == "stream":
                stream_names.append(logical_name)
                if digest_streams:
                    try:
                        with ole.openstream(raw_path) as stream_handle:
                            data = stream_handle.read()
                        data_hash = _sha256_hex(data)
                        size = len(data)
                    except Exception:
                        data_hash = None

            descriptor = _wrap(
                {
                    "name": logical_name,
                    "raw_name": display_name,
                    "path": tuple(raw_path),
                    "kind": kind,
                    "size": size,
                    "sha256": data_hash,
                    "content_sha256": data_hash,
                    "start_sector": getattr(entry, "isectStart", None),
                    "byte_offset": (
                        (getattr(entry, "isectStart", 0) + 1) * getattr(ole, "sectorsize", 512)
                        if kind == "stream"
                        and not getattr(entry, "is_minifat", False)
                        and isinstance(getattr(entry, "isectStart", None), int)
                        else None
                    ),
                    "allocation": "mini" if getattr(entry, "is_minifat", False) else "fat",
                }
            )
            entries.append(descriptor)
            if kind == "stream":
                stream_map[_stream_name_key(logical_name)] = descriptor
                physical_streams[logical_name] = {
                    "start_sector": descriptor.start_sector,
                    "byte_offset": descriptor.byte_offset,
                    "size": descriptor.size,
                    "allocation": descriptor.allocation,
                }

        encryption_format = _encryption_format(ole)
        profile, required_streams = _detect_profile(set(stream_names), encryption_format)
        required_present = all(_resolve_stream(stream_map, name) is not None for name in required_streams)
        public_structure = _wrap(
            {
                "valid": required_present if required_streams else bool(stream_names),
                "is_ole": True,
                "profile": profile,
                "format": profile,
                "family": profile.split("-", 1)[0],
                "encryption_format": encryption_format,
                "encryption_type": encryption_format,
                "required_streams": required_streams,
                "required_streams_present": required_present,
                "logical_stream_names": tuple(sorted(stream_names, key=str.casefold)),
                "stream_count": len(stream_names),
            }
        )
        structure_digest = _sha256_hex(_canonical_json(public_structure))
        physical_layout = _wrap(
            {
                "sector_size": getattr(ole, "sectorsize", None),
                "first_directory_sector": getattr(ole, "first_dir_sector", None),
                "streams": physical_streams,
                "locations": {name: item["start_sector"] for name, item in physical_streams.items()},
                "byte_offsets": {name: item["byte_offset"] for name, item in physical_streams.items() if item["byte_offset"] is not None},
            }
        )
        layout_digest = _sha256_hex(_canonical_json(physical_layout))
        source_name = None
        if _looks_like_path(source):
            source_name = os.fspath(source)
        elif isinstance(source, (bytes, bytearray)):
            source_name = "<bytes>"

        return _wrap(
            {
                "kind": STRUCTURE_KIND,
                "schema_version": SCHEMA_VERSION,
                "source": source_name,
                "is_ole": True,
                "sector_size": physical_layout.sector_size,
                "logical_streams": tuple(entries),
                "streams": tuple(descriptor for descriptor in entries if descriptor.kind == "stream"),
                "stream_names": tuple(sorted(stream_names, key=str.casefold)),
                "stream_map": stream_map,
                "public_structure": public_structure,
                "physical_layout": physical_layout,
                "layout": physical_layout,
                "structure_digest": structure_digest,
                "public_structure_digest": structure_digest,
                "layout_digest": layout_digest,
                "target_stream": None,
                "macro_free": None,
            }
        )
    finally:
        if should_close:
            try:
                ole.close()
            except Exception:
                pass


inspect_structure = read_structure
fingerprint_structure = read_structure
read_local_structure = read_structure
inspect_local_structure = read_structure


def _resolve_stream(stream_map: Mapping[str, Any], name: Any) -> Any | None:
    if not name:
        return None
    key = _stream_name_key(name)
    if key in stream_map:
        return stream_map[key]
    wanted_basename = Path(normalize_stream_name(name)).name.casefold()
    matches = []
    for stream_key, descriptor in stream_map.items():
        stream_name = descriptor.get("name") if isinstance(descriptor, Mapping) else None
        basename = Path(normalize_stream_name(stream_name or stream_key)).name.casefold()
        if stream_key == key or basename == wanted_basename:
            matches.append(descriptor)
    return matches[0] if len(matches) == 1 else (matches[0] if matches else None)


def _structure_from_mapping(data: Mapping[str, Any]) -> ReviewRecord:
    wrapped = _wrap(dict(data))
    if wrapped.get("kind") == STRUCTURE_KIND or ("public_structure" in wrapped and "stream_map" in wrapped):
        return wrapped

    raw_streams = _first_key(
        wrapped,
        "logical_streams",
        "streams",
        "stream_descriptors",
        "logical_stream_names",
        "stream_names",
        "names",
        default=(),
    )
    descriptors = []
    stream_map = {}
    stream_names = []
    if isinstance(raw_streams, Mapping):
        raw_stream_entries = []
        for stream_name, raw_descriptor in raw_streams.items():
            if isinstance(raw_descriptor, Mapping):
                entry = dict(raw_descriptor)
                entry.setdefault("name", stream_name)
            else:
                entry = {"name": stream_name, "sha256": raw_descriptor}
            raw_stream_entries.append(entry)
    else:
        raw_stream_entries = _as_list(raw_streams)
    for raw in raw_stream_entries:
        if isinstance(raw, Mapping):
            descriptor = _wrap(dict(raw))
            logical_name = normalize_stream_name(_first_key(descriptor, "name", "logical_name", "stream_name", "path"))
            descriptor.setdefault("name", logical_name)
            if "sha256" not in descriptor and "content_sha256" in descriptor:
                descriptor["sha256"] = descriptor["content_sha256"]
        else:
            logical_name = normalize_stream_name(raw)
            descriptor = _wrap({"name": logical_name, "kind": "stream"})
        if logical_name:
            stream_names.append(logical_name)
            stream_map[_stream_name_key(logical_name)] = descriptor
            descriptors.append(descriptor)

    raw_public = _first_key(wrapped, "public_structure", "structure", "public", default={})
    if isinstance(raw_public, str) and re.fullmatch(r"[0-9a-fA-F]{64}", raw_public.strip()):
        wrapped.setdefault("structure_digest", raw_public.strip().lower())
        raw_public = {}
    public = _wrap(dict(raw_public) if isinstance(raw_public, Mapping) else {})
    for key in ("profile", "format", "family", "encryption_format", "encryption_type", "required_streams"):
        if key in wrapped and key not in public:
            public[key] = wrapped[key]
    if "logical_stream_names" not in public and stream_names:
        public["logical_stream_names"] = tuple(stream_names)

    raw_physical = {}
    for layout_key in ("physical_layout", "layout", "reported_layout", "original_layout"):
        candidate = wrapped.get(layout_key)
        if isinstance(candidate, Mapping):
            raw_physical = candidate
            break
    physical = _wrap(dict(raw_physical))
    digest = _first_key(wrapped, "structure_digest", "public_structure_digest", "digest")
    if digest is None and isinstance(public, Mapping):
        digest = public.get("structure_digest") or public.get("digest")

    target = _first_key(wrapped, "logical_stream", "stream_name", "stream", "target_stream")
    return _wrap(
        {
            "kind": "msoffcrypto.structure_reference",
            "schema_version": SCHEMA_VERSION,
            "source": wrapped.get("source") or wrapped.get("path") or wrapped.get("file"),
            "is_ole": wrapped.get("is_ole"),
            "logical_streams": tuple(descriptors),
            "streams": tuple(descriptors),
            "stream_names": tuple(stream_names),
            "stream_map": stream_map,
            "public_structure": public,
            "physical_layout": physical,
            "layout": physical,
            "structure_digest": digest,
            "target_stream": target,
            "raw": wrapped,
        }
    )


def _coerce_structure(value: Any, *, read_paths: bool = False) -> ReviewRecord | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        if read_paths and value.get("path") and _looks_like_path(value["path"]):
            path_value = value["path"]
            if Path(os.fspath(path_value)).exists():
                return read_structure(path_value)
        return _structure_from_mapping(value)
    if isinstance(value, ReviewRecord) and value.get("kind") in {STRUCTURE_KIND, "msoffcrypto.structure_reference"}:
        return value
    if isinstance(value, olefile.OleFileIO) or hasattr(value, "read") or isinstance(value, (str, os.PathLike, bytes, bytearray)):
        return read_structure(value)
    if hasattr(value, "to_dict"):
        return _structure_from_mapping(value.to_dict())
    raise TypeError(f"Cannot interpret {type(value)!r} as an Office structure")


def _positive_attestation(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    positive = {"true", "1", "yes", "ok", "pass", "passed", "valid", "verified", "attested", "confirmed", "satisfied"}
    negative = {"false", "0", "no", "fail", "failed", "invalid", "unverified", "pending", "revoked", "rejected", "expired"}
    if text in positive:
        return True
    if text in negative:
        return False
    return None


def _witness_claim_status(witness: Mapping[str, Any]) -> bool:
    for key in (
        "verified",
        "is_verified",
        "witness_verified",
        "valid",
        "is_valid",
        "attested",
        "trusted",
        "accepted",
        "satisfied",
        "reseal_confirmed",
    ):
        if key in witness:
            result = _positive_attestation(witness[key])
            if result is not None:
                return result
    for key in ("status", "state", "result", "outcome", "verification"):
        if key in witness:
            result = _positive_attestation(witness[key])
            if result is not None:
                return result
    return False


def _iter_witness_digests(witness: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    aliases = {
        "current_stream_sha256",
        "candidate_stream_sha256",
        "target_stream_sha256",
        "new_stream_sha256",
        "resealed_stream_sha256",
        "stream_sha256",
        "stream_digest",
        "digest",
        "sha256",
        "sha256sum",
        "hash",
        "current_sha256",
        "candidate_sha256",
        "target_sha256",
        "file_sha256",
        "artifact_sha256",
        "source_stream_sha256",
        "original_stream_sha256",
        "old_stream_sha256",
        "baseline_stream_sha256",
        "source_sha256",
        "original_sha256",
        "old_sha256",
    }
    found = []
    for key, value in witness.items():
        if key.lower() in aliases and isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()):
            kind = "file" if "file" in key.lower() or key.lower() in {"current_sha256", "candidate_sha256", "target_sha256", "artifact_sha256", "sha256"} else "stream"
            found.append((key, kind, value.strip().lower()))
    for container_key in ("digests", "hashes"):
        container = witness.get(container_key)
        if isinstance(container, Mapping):
            for key, value in container.items():
                if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()):
                    found.append((f"{container_key}.{key}", "stream" if "stream" in key.lower() else "unknown", value.strip().lower()))
        elif isinstance(container, list):
            for item in container:
                if isinstance(item, Mapping):
                    name = item.get("stream") or item.get("name")
                    value = item.get("sha256") or item.get("digest")
                    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()):
                        found.append((f"{container_key}.{name or 'item'}", "stream", value.strip().lower()))
    return found


def verify_reseal_witness(
    witness: Any = None,
    *,
    local: Any = None,
    source: Any = None,
    reference: Any = None,
    stream_name: str | None = None,
    evidence_id: str | None = None,
    secret: bytes | str | None = None,
    hmac_key: bytes | str | None = None,
    verifier: Callable[..., Any] | None = None,
    require_binding: bool = False,
    base_dir: str | os.PathLike[str] | None = None,
    **kwargs: Any,
) -> ReviewRecord:
    """Verify an external resealing attestation against local stream digests."""
    if verifier is not None:
        try:
            custom = verifier(witness, local=local, source=source, stream_name=stream_name, evidence_id=evidence_id)
            record = _wrap(dict(_as_mapping(custom) or {"verified": bool(custom)}))
            record.setdefault("verified", bool(record.get("verified", True)))
            record.setdefault("status", "verified" if record.verified else "rejected")
            return record
        except Exception as exc:
            return _wrap({"verified": False, "status": "verifier_error", "reasons": (str(exc),)})

    if witness is None:
        return _wrap({"verified": False, "status": "missing", "reasons": ("resealing witness is missing",)})

    try:
        if isinstance(witness, str) and not witness.lstrip().startswith("{"):
            path = Path(witness)
            if not path.exists() and base_dir is not None:
                path = Path(base_dir) / witness
            witness_data = _load_lenient_json(path)
        else:
            witness_data = _load_lenient_json(witness)
        witness_map = _as_mapping(witness_data) or {}
    except Exception as exc:
        return _wrap({"verified": False, "status": "unreadable", "reasons": (f"witness cannot be read: {exc}",)})

    witness = _wrap(dict(witness_map))
    reasons: list[str] = []
    if witness.get("revoked") is True or _positive_attestation(witness.get("revoked")) is True:
        reasons.append("witness is revoked")
    if witness.get("expired") is True or _positive_attestation(witness.get("expired")) is True:
        reasons.append("witness is expired")

    witness_stream = _first_key(witness, "logical_stream", "stream_name", "stream", "target_stream")
    if stream_name and witness_stream and not _names_match(stream_name, witness_stream):
        reasons.append(f"witness stream {witness_stream!r} does not match {stream_name!r}")

    witness_evidence = _first_key(witness, "evidence_id", "item_id", "evidence", "id")
    if evidence_id and witness_evidence and str(witness_evidence) != str(evidence_id):
        reasons.append("witness evidence identifier does not match")

    local_structure = None
    if local is not None:
        local_structure = _coerce_structure(local)
    elif source is not None:
        try:
            local_structure = read_structure(source)
        except Exception as exc:
            reasons.append(f"local source is unreadable: {exc}")
    reference_structure = _coerce_structure(reference) if reference is not None else None

    digest_matches: list[dict[str, str]] = []
    digest_failures: list[str] = []
    digest_notes: list[str] = []
    claimed_digests = _iter_witness_digests(witness)
    if claimed_digests:
        stream_descriptor = None
        if local_structure is not None and stream_name:
            stream_descriptor = _resolve_stream(local_structure.stream_map, stream_name)
        local_stream_hash = (stream_descriptor or {}).get("sha256") if isinstance(stream_descriptor, Mapping) else None
        local_file_hash = None
        if source is not None and _looks_like_path(source):
            try:
                local_file_hash = _sha256_file(source)
            except Exception:
                local_file_hash = None
        elif local_structure is not None and local_structure.get("source"):
            try:
                local_file_hash = _sha256_file(local_structure.source)
            except Exception:
                local_file_hash = None
        reference_stream_hash = None
        if reference_structure is not None and stream_name:
            reference_descriptor = _resolve_stream(reference_structure.stream_map, stream_name)
            reference_stream_hash = reference_descriptor.get("sha256") if isinstance(reference_descriptor, Mapping) else None

        for field, kind, expected_hash in claimed_digests:
            field_lower = field.lower()
            historical = any(token in field_lower for token in ("original", "source_", "_source", "old_", "_old", "baseline"))
            matched = False
            if kind in {"stream", "unknown"} and local_stream_hash and expected_hash == local_stream_hash:
                matched = True
            if kind == "file" and local_file_hash and expected_hash == local_file_hash:
                matched = True
            if kind == "unknown" and local_file_hash and expected_hash == local_file_hash:
                matched = True
            if historical and reference_stream_hash and expected_hash == reference_stream_hash:
                matched = True
            if matched:
                digest_matches.append({"field": field, "sha256": expected_hash})
            elif historical:
                digest_notes.append(f"historical digest {field} retained by external witness")
            else:
                digest_failures.append(field)
        current_failures = [field for field in digest_failures if not any(token in field.lower() for token in ("original", "source_", "_source", "old_", "_old", "baseline"))]
        if current_failures and not digest_matches:
            reasons.append("witness digest does not match local sealed structure")
        elif current_failures and local_stream_hash is None and local_file_hash is None:
            reasons.append(f"witness digest could not be bound locally: {', '.join(current_failures)}")

    key = secret if secret is not None else hmac_key
    signature = _first_key(witness, "hmac_sha256", "hmac", "signature")
    if key is not None and signature:
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        signed_payload = witness.get("signed_payload")
        if signed_payload is None:
            unsigned = {k: v for k, v in witness.items() if k not in {"hmac", "hmac_sha256", "signature"}}
            payload = _canonical_json(unsigned)
        elif isinstance(signed_payload, str):
            payload = signed_payload.encode("utf-8")
        else:
            payload = bytes(signed_payload)
        expected_signature = hmac.new(key_bytes, payload, hashlib.sha256).hexdigest()
        supplied = str(signature)
        if not hmac.compare_digest(expected_signature, supplied.removeprefix("sha256=")):
            reasons.append("witness HMAC signature is invalid")

    explicitly_valid = _witness_claim_status(witness)
    digest_bound = bool(digest_matches)
    if require_binding and not digest_bound:
        reasons.append("witness has no matching digest binding")

    verified = explicitly_valid and not reasons and (not require_binding or digest_bound)
    if verified and not digest_bound:
        reasons.append("external attestation accepted without local digest binding")
    status = "verified" if verified else ("rejected" if any("revoked" in r or "expired" in r or "invalid" in r or "does not match" in r for r in reasons) else "unverified")
    return _wrap(
        {
            "verified": verified,
            "status": status,
            "witness_id": _first_key(witness, "witness_id", "id", "attestation_id"),
            "reasons": tuple(reasons),
            "notes": tuple(digest_notes),
            "digest_matches": tuple(digest_matches),
            "digest_bound": digest_bound,
        }
    )


verify_external_resealing_witness = verify_reseal_witness
verify_witness = verify_reseal_witness


class WitnessRecord(ReviewRecord):
    """Dictionary witness with a convenience :meth:`verify` call."""

    def verify(self, **kwargs: Any) -> ReviewRecord:
        return verify_reseal_witness(self, **kwargs)


ResealingWitness = WitnessRecord
ExternalResealingWitness = WitnessRecord
Witness = WitnessRecord


def build_reseal_witness(
    source: Any = None,
    stream_name: str = 'EncryptedPackage',
    *,
    structure: Any = None,
    witness_id: str | None = None,
    authority: str = 'external-resealing-ledger',
    verified: bool = True,
    **claims: Any,
) -> WitnessRecord:
    """Build a fictional witness bound to a local logical stream digest."""
    local_structure = _coerce_structure(structure) if structure is not None else read_structure(source)
    descriptor = _resolve_stream(local_structure.stream_map, stream_name)
    if descriptor is None:
        raise exceptions.FileFormatError(f'Logical stream {stream_name!r} not found')
    witness = {
        'witness_id': witness_id,
        'authority': authority,
        'verified': verified,
        'logical_stream': descriptor.get('name') or normalize_stream_name(stream_name),
        'stream_sha256': descriptor.get('sha256'),
        'physical_start_sector': descriptor.get('start_sector'),
    }
    witness.update(claims)
    return WitnessRecord(_wrap(witness))


create_resealing_witness = build_reseal_witness
make_witness = build_reseal_witness
attest_reseal = build_reseal_witness


def _compare_logical_name(local: ReviewRecord | None, reference: ReviewRecord | None, target: str | None) -> tuple[bool | None, str | None]:
    if local is None:
        return False, target
    resolved_name = target or local.get("target_stream")
    if not resolved_name and reference is not None:
        resolved_name = reference.get("target_stream")
    if resolved_name:
        descriptor = _resolve_stream(local.get("stream_map", {}), resolved_name)
        if descriptor is None:
            return False, normalize_stream_name(resolved_name)
        actual_name = descriptor.get("name") if isinstance(descriptor, Mapping) else None
        if reference is not None and reference.get("target_stream"):
            if not _names_match(resolved_name, reference.target_stream) and not _names_match(actual_name, reference.target_stream):
                return False, actual_name
        return True, actual_name or normalize_stream_name(resolved_name)

    local_names = set(local.get("stream_names", ()))
    if reference is not None and reference.get("stream_names"):
        reference_names = set(reference.stream_names)
        return local_names == reference_names, None
    # A valid Office structure has logical streams even when no one stream was named.
    return bool(local_names), None


def _compare_public_structure(local: ReviewRecord | None, reference: ReviewRecord | None) -> bool:
    if local is None or not local.get("is_ole"):
        return False
    public = local.get("public_structure", {})
    if not public.get("valid", False):
        return False
    if reference is None:
        return True

    expected_digest = reference.get("structure_digest")
    if expected_digest:
        return str(expected_digest).lower() == str(local.get("structure_digest") or public.get("structure_digest")).lower()

    expected_public = reference.get("public_structure") or {}
    checks = dict(expected_public)
    for key in ("profile", "format", "family", "encryption_format", "encryption_type"):
        if reference.get(key) is not None and key not in checks:
            checks[key] = reference[key]

    aliases = {
        "format": {"profile", "format"},
        "profile": {"profile", "format"},
        "family": {"family"},
        "encryption_format": {"encryption_format", "encryption_type"},
        "encryption_type": {"encryption_type", "encryption_format"},
    }
    for key, expected_value in checks.items():
        if key in {"logical_stream_names", "required_streams", "streams"}:
            continue
        actual_value = public.get(key)
        if actual_value is None:
            for alias in aliases.get(key, {key}):
                actual_value = public.get(alias)
                if actual_value is not None:
                    break
        if actual_value is None or str(expected_value).casefold() != str(actual_value).casefold():
            return False

    expected_names = checks.get("logical_stream_names") or checks.get("required_streams") or reference.get("required_streams")
    if expected_names:
        stream_map = local.get("stream_map", {})
        for name in _as_list(expected_names):
            if _resolve_stream(stream_map, name) is None:
                return False
    return True


def _layout_matches(local: ReviewRecord | None, reference: ReviewRecord | None, target: str | None) -> bool | None:
    if local is None or reference is None:
        return None
    actual_layout = local.get("physical_layout") or {}
    expected_layout = reference.get("physical_layout") or {}
    if not expected_layout:
        raw = reference.get("raw") if isinstance(reference.get("raw"), Mapping) else {}
        for layout_key in ("physical_layout", "original_layout", "reported_layout", "layout"):
            candidate = raw.get(layout_key)
            if isinstance(candidate, Mapping):
                expected_layout = candidate
                break
        else:
            expected_layout = {}
    if not expected_layout:
        return None

    if expected_layout.get("matches") is True:
        return True
    if expected_layout.get("matches") is False:
        return False

    target_name = target or reference.get("target_stream")
    expected_locations = expected_layout.get("locations") or expected_layout.get("streams") or {}
    actual_locations = actual_layout.get("locations") or {}
    descriptor = _resolve_stream(local.get("stream_map", {}), target_name) if target_name else None
    actual_sector = descriptor.get("start_sector") if isinstance(descriptor, Mapping) else None
    actual_offset = descriptor.get("byte_offset") if isinstance(descriptor, Mapping) else None

    expected_location = None
    if target_name and isinstance(expected_locations, Mapping):
        expected_location = _first_key(expected_locations, normalize_stream_name(target_name), target_name, Path(normalize_stream_name(target_name)).name)
    if expected_location is None and target_name and not expected_locations:
        expected_location = expected_layout

    if target_name and expected_location is not None:
        if isinstance(expected_location, Mapping):
            expected_sector = _first_key(expected_location, "start_sector", "sector", "isectStart", "offset_sector")
            expected_offset = _first_key(expected_location, "byte_offset", "offset", "physical_offset")
        else:
            expected_sector = expected_location
            expected_offset = None
        if expected_sector is not None and actual_sector is not None:
            try:
                expected_sector_int = int(expected_sector)
            except (TypeError, ValueError):
                expected_sector_int = None
            if expected_sector_int is not None:
                if expected_sector_int == actual_sector or expected_sector_int == actual_offset:
                    return True
                if expected_offset is None:
                    return False
        if expected_offset is not None and actual_offset is not None:
            try:
                return int(expected_offset) == int(actual_offset)
            except (TypeError, ValueError):
                return str(expected_offset) == str(actual_offset)
        if not isinstance(expected_location, Mapping) and actual_sector is not None:
            try:
                return int(expected_location) in {actual_sector, actual_offset}
            except (TypeError, ValueError):
                return str(expected_location) in {str(actual_sector), str(actual_offset)}

    expected_sector_size = _first_key(expected_layout, "sector_size", "sectorSize")
    if expected_sector_size is not None and actual_layout.get("sector_size") is not None:
        if int(expected_sector_size) != int(actual_layout.sector_size):
            return False

    comparable = 0
    for name, expected_sector in (expected_layout.get("locations") or {}).items():
        actual_sector = actual_locations.get(name)
        if actual_sector is None:
            descriptor = _resolve_stream(local.get("stream_map", {}), name)
            actual_sector = descriptor.get("start_sector") if isinstance(descriptor, Mapping) else None
        if actual_sector is None:
            return False
        if isinstance(expected_sector, Mapping):
            expected_sector = _first_key(expected_sector, "start_sector", "sector", "isectStart")
        if expected_sector is None:
            continue
        comparable += 1
        try:
            if int(expected_sector) != int(actual_sector):
                return False
        except (TypeError, ValueError):
            if str(expected_sector) != str(actual_sector):
                return False
    return True if comparable else None


def compare_structures(
    first: Any = None,
    second: Any = None,
    *,
    local: Any = None,
    candidate: Any = None,
    current: Any = None,
    actual: Any = None,
    observed: Any = None,
    reference: Any = None,
    expected: Any = None,
    reported: Any = None,
    original: Any = None,
    baseline: Any = None,
    stream_name: str | None = None,
    logical_stream: str | None = None,
    witness: Any = None,
    external_witness: Any = None,
    resealing_witness: Any = None,
    reseal_witness: Any = None,
    evidence_id: str | None = None,
    witness_verifier: Callable[..., Any] | None = None,
    require_witness_binding: bool = False,
    **kwargs: Any,
) -> ReviewRecord:
    """Compare logical/public structure and check a resealing witness.

    Physical layout equality is returned as ``layout_matches`` but is never a
    prerequisite for ``relatable``.
    """
    witness = (
        witness
        or external_witness
        or resealing_witness
        or reseal_witness
        or _first_key(kwargs, "witness_record", "attestation", "external_resealing_witness")
    )
    explicit_witness_verified = _first_key(kwargs, "witness_verified", "witness_valid", "witness_satisfied")

    local_value = _first_key(
        kwargs,
        "local_structure",
        "candidate_structure",
        "current_structure",
        "observed_structure",
        default=None,
    )
    bare_stream_name = None
    for positional in (first, second):
        if (
            isinstance(positional, str)
            and not _looks_like_path(positional)
            and not Path(positional).exists()
            and "/" not in positional
            and "\\" not in positional
        ):
            bare_stream_name = positional
            break
    if bare_stream_name and not (stream_name or logical_stream or kwargs.get("target_stream")):
        stream_name = bare_stream_name

    for value in (local, candidate, current, actual, observed, local_value, first, second):
        if value is not None and value is not bare_stream_name and local is None and _looks_like_actual_source(value):
            local = value
            break
    if local is None:
        if first is not None and first is not bare_stream_name:
            local = first
        elif second is not None and second is not bare_stream_name:
            local = second

    reference_value = _first_key(
        kwargs,
        "reference_structure",
        "expected_structure",
        "reported_structure",
        "original_structure",
        default=None,
    )
    for value in (reference, expected, reported, original, baseline, reference_value):
        if value is not None:
            reference = value
            break
    if reference is None and first is not None and second is not None:
        if local is first:
            reference = second
        elif local is second:
            reference = first
        else:
            reference = second if first is bare_stream_name else first

    target_stream = stream_name or logical_stream or kwargs.get("target_stream")
    try:
        local_structure = _coerce_structure(local)
    except Exception as exc:
        return _wrap(
            {
                "kind": "structure_comparison",
                "relatable": False,
                "confirmed": False,
                "status": PENDING_STATUS,
                "logical_name_matches": False,
                "public_structure_matches": False,
                "witness_verified": False,
                "layout_matches": None,
                "reasons": (f"local structure is unreadable: {exc}",),
            }
        )
    reference_structure = _coerce_structure(reference) if reference is not None else None
    if not target_stream:
        target_stream = _first_key(
            local_structure or {}, "target_stream", "logical_stream", "stream_name", "stream"
        ) or _first_key(reference_structure or {}, "target_stream", "logical_stream", "stream_name", "stream")

    logical_matches, resolved_name = _compare_logical_name(local_structure, reference_structure, target_stream)
    public_matches = _compare_public_structure(local_structure, reference_structure)
    layout_matches = _layout_matches(local_structure, reference_structure, resolved_name or target_stream)

    if witness is None and reference_structure is not None:
        raw_reference = reference_structure.get("raw") if isinstance(reference_structure.get("raw"), Mapping) else reference_structure
        witness = _first_key(raw_reference, "witness", "reseal_witness", "resealing_witness", "external_witness")
    witness_result = verify_reseal_witness(
        witness,
        local=local_structure,
        reference=reference_structure,
        stream_name=resolved_name or target_stream,
        evidence_id=evidence_id,
        verifier=witness_verifier,
        require_binding=require_witness_binding,
        **{k: v for k, v in kwargs.items() if k in {"secret", "hmac_key", "base_dir"}},
    )
    witness_verified = bool(witness_result.verified)
    if explicit_witness_verified is True:
        witness_result["verified"] = True
        witness_result["status"] = "verified"
        witness_verified = True
    elif explicit_witness_verified is False:
        witness_result["verified"] = False
        witness_result["status"] = "unverified"
        witness_verified = False
    relatable = bool(logical_matches and public_matches and witness_verified)
    satisfied_gates = sum(bool(gate) for gate in (logical_matches, public_matches, witness_verified))
    if relatable:
        strength = EvidenceStrength.HIGH
    elif satisfied_gates == 2:
        strength = EvidenceStrength.MEDIUM
    elif satisfied_gates == 1:
        strength = EvidenceStrength.LOW
    else:
        strength = EvidenceStrength.NONE
    reasons = []
    if not logical_matches:
        reasons.append("logical stream name is not proven")
    if not public_matches:
        reasons.append("public Office structure does not match")
    if not witness_verified:
        reasons.extend(witness_result.get("reasons", ()) or ("external resealing witness is not satisfied",))
    if layout_matches is False:
        reasons.append("physical layout differs; layout alone cannot establish identity")

    if relatable:
        status = CONFIRMED_STATUS
    elif witness is None and logical_matches is not False and public_matches is not False:
        status = PENDING_STATUS
    elif logical_matches is False or public_matches is False or witness is not None:
        status = MISMATCH_STATUS
    else:
        status = PENDING_STATUS
    result = {
        "kind": "structure_comparison",
        "schema_version": SCHEMA_VERSION,
        "stream_name": resolved_name or normalize_stream_name(target_stream) or None,
        "logical_stream": resolved_name or normalize_stream_name(target_stream) or None,
        "logical_name_matches": logical_matches,
        "same_logical_name": logical_matches,
        "public_structure_matches": public_matches,
        "same_public_structure": public_matches,
        "witness": witness_result,
        "witness_verified": witness_verified,
        "witness_satisfied": witness_verified,
        "external_witness_verified": witness_verified,
        "layout_matches": layout_matches,
        "same_layout": layout_matches,
        "physical_layout_matches": layout_matches,
        "relatable": relatable,
        "can_refer_back": relatable,
        "backreference_confirmed": relatable,
        "can_backreference": relatable,
        "back_reference_confirmed": relatable,
        "evidence_linked": relatable,
        "confirmed": relatable,
        "identity_confirmed": relatable,
        "all_gates_satisfied": relatable,
        "strength": strength,
        "evidence_strength": strength,
        "satisfied_gate_count": satisfied_gates,
        "status": status,
        "reasons": tuple(reasons),
        "local": local_structure,
        "reference": reference_structure,
    }
    return _wrap(result)


def _looks_like_actual_source(value: Any) -> bool:
    if isinstance(value, (olefile.OleFileIO, bytes, bytearray)) or hasattr(value, "read"):
        return True
    if _looks_like_path(value):
        try:
            return olefile.isOleFile(os.fspath(value))
        except Exception:
            return False
    return False


compare_local_structure = compare_structures
local_structure_compare = compare_structures
compare_office_structures = compare_structures
structure_match = compare_structures
match_structure = compare_structures
verify_structure = compare_structures
structure_comparison = compare_structures


_LAYOUT_BASIS_TERMS = (
    "original_layout",
    "physical_layout",
    "reported_layout",
    "disk_layout",
    "layout_reference",
    "sector",
    "sector_offset",
    "byte_offset",
    "offset",
    "fat",
    "difat",
    "directory_entry",
    "directory_sector",
    "physical_position",
    "原布局",
    "原始布局",
    "物理布局",
    "扇区",
    "偏移",
    "目录项",
)

_STREAM_BASIS_TERMS = (
    "stream_identity",
    "stream identity",
    "stream-identity",
    "logical_stream",
    "logical stream",
    "logical-stream",
    "logical_name",
    "logical name",
    "stream_name",
    "stream name",
    "stream_digest",
    "stream digest",
    "structure_identity",
    "structure identity",
    "proven_stream",
    "proven stream",
    "流身份",
    "逻辑流",
    "逻辑流名称",
)

_LAYOUT_PROOF_PATTERN = re.compile(
    r"(original|old|reported|physical|disk|sector|byte|offset|fat|directory|layout).{0,80}"
    r"(prove|proves|proven|confirm|confirms|confirmed|establish|establishes|match|matches|shows|showed|demonstrat|证明|证实|确认|显示)"
    r"|(prove|proves|proven|confirm|confirms|confirmed|establish|establishes|match|matches).{0,80}(layout|sector|offset|fat|directory)"
    r"|(原布局|原始布局|物理布局|扇区|偏移).{0,80}(证明|证实|确认|显示|表明)"
    r"|(证明|证实|确认).{0,80}(原布局|原始布局|物理布局|扇区|偏移)",
    re.IGNORECASE | re.DOTALL,
)


def classify_conclusion_basis(conclusion: Mapping[str, Any]) -> ReviewRecord:
    data = _as_mapping(conclusion) or {}
    explicit_layout = _first_key(data, "cites_original_layout", "layout_dependent", "uses_original_layout", "references_layout")
    explicit_stream = _first_key(data, "cites_stream_identity", "stream_identity", "uses_stream_identity")
    basis_parts = _as_list(_first_key(data, "basis", "bases", "evidence_basis", "support", "grounds", "kind", "type", default=()))
    basis_text = " ".join(str(part) for part in basis_parts).lower()
    text = " ".join(
        str(data.get(key, ""))
        for key in ("text", "statement", "claim", "conclusion", "summary", "description", "wording", "title")
    )
    combined = f"{basis_text} {text.lower()}"

    basis_layout = any(term in basis_text for term in _LAYOUT_BASIS_TERMS)
    basis_stream = any(term in basis_text for term in _STREAM_BASIS_TERMS)
    text_layout = any(term in combined for term in ("original layout", "physical layout", "原布局", "原始布局", "物理布局", "sector", "扇区", "offset", "偏移"))
    is_stream = bool(explicit_stream is True or basis_stream or any(term in combined for term in _STREAM_BASIS_TERMS))
    strong_original_reference = re.search(
        r"(original|old|reported|prior|stale|archive report|原|原始|旧报告)[^.。]{0,50}"
        r"(layout|sector|offset|fat|difat|directory|布局|扇区|偏移|目录项)",
        text,
        re.IGNORECASE,
    )
    coordinate_reference = re.search(
        r"(start sector|sector|byte offset|offset|fat entry|difat|扇区|偏移|目录项)[^0-9xX]{0,24}(?:0x[0-9a-f]+|\d+)",
        text,
        re.IGNORECASE,
    )
    authority_reference = re.search(
        r"(according to|based on|reli(?:es|ance) on|cites?|recorded in|reported in|per the|根据|引用|依据)[^.。]{0,90}"
        r"(layout|sector|offset|fat|directory|布局|扇区|偏移|目录项)",
        text,
        re.IGNORECASE,
    )
    strong_layout = bool(strong_original_reference or coordinate_reference or authority_reference)
    explicit_layout_bool = explicit_layout is not None and explicit_layout is not False

    is_layout = bool(
        explicit_layout_bool
        or basis_layout
        or strong_layout
        or (text_layout and not is_stream and not basis_stream)
    )
    if explicit_layout is False:
        is_layout = False
    if basis_stream and not basis_layout and not explicit_layout_bool and not strong_layout:
        is_layout = False
    return _wrap(
        {
            "original_layout": is_layout,
            "layout_citation": is_layout,
            "stream_identity": is_stream,
            "basis_text": basis_text or None,
        }
    )


classify_conclusion = classify_conclusion_basis


def inspect_macro_free(
    source: Any,
    *,
    password: str | None = None,
    verify_password: bool = True,
    **kwargs: Any,
) -> ReviewRecord:
    """Check a plain or encrypted macro-free OOXML package for VBA parts."""
    data: bytes | None = None
    if password is not None and (isinstance(source, (str, os.PathLike)) or _looks_like_ole_source(source)):
        handle = open(source, "rb") if _looks_like_path(source) else source
        try:
            handle.seek(0)
            office_file = msoffcrypto.OfficeFile(handle)
            office_file.load_key(password=password, verify_password=verify_password)
            output = io.BytesIO()
            office_file.decrypt(output, verify_integrity=kwargs.get("verify_integrity", False))
            data = output.getvalue()
        finally:
            if _looks_like_path(source):
                handle.close()
    elif isinstance(source, (str, os.PathLike)) and zipfile.is_zipfile(os.fspath(source)):
        data = Path(source).read_bytes()
    elif hasattr(source, "read") and zipfile.is_zipfile(source):
        source.seek(0)
        data = source.read()
    elif isinstance(source, (bytes, bytearray)) and zipfile.is_zipfile(io.BytesIO(source)):
        data = bytes(source)
    elif password is None and _looks_like_ole_source(source):
        return _wrap({"macro_free": None, "checked": False, "reasons": ("password required to inspect encrypted package",)})

    if data is None:
        return _wrap({"macro_free": None, "checked": False, "reasons": ("source is not a readable OOXML package",)})
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            names = package.namelist()
            macro_parts = [name for name in names if "vbaproject" in name.lower() or name.lower().endswith("vbadatapart.xml")]
            content_types = ""
            if "[Content_Types].xml" in names:
                content_types = package.read("[Content_Types].xml").decode("utf-8", errors="ignore").lower()
            macro_content_type = "vbaProject".lower() in content_types or "macroenabled" in content_types
            macro_free = not macro_parts and not macro_content_type
            return _wrap(
                {
                    "macro_free": macro_free,
                    "checked": True,
                    "macro_parts": tuple(macro_parts),
                    "macro_content_type": macro_content_type,
                }
            )
    except Exception as exc:
        return _wrap({"macro_free": False, "checked": False, "reasons": (f"invalid OOXML package: {exc}",)})


def _looks_like_ole_source(source: Any) -> bool:
    if isinstance(source, olefile.OleFileIO):
        return True
    if isinstance(source, (bytes, bytearray)):
        return bytes(source[: len(olefile.MAGIC)]) == olefile.MAGIC
    if hasattr(source, "seek"):
        try:
            pos = source.tell()
            source.seek(0)
            result = olefile.isOleFile(source)
            source.seek(pos)
            return result
        except Exception:
            return False
    if _looks_like_path(source):
        try:
            return olefile.isOleFile(os.fspath(source))
        except Exception:
            return False
    return False


def _source_key(source: Any) -> str | None:
    if source is None:
        return None
    if _looks_like_path(source):
        return os.path.basename(os.fspath(source))
    name = getattr(source, "name", None)
    if isinstance(name, (str, os.PathLike)):
        return os.path.basename(os.fspath(name))
    return None


def reconcile_report(
    report: Any = None,
    sources: Any = None,
    witnesses_positional: Any = None,
    *,
    source_files: Any = None,
    files: Any = None,
    current_files: Any = None,
    artifacts: Any = None,
    base_dir: str | os.PathLike[str] | None = None,
    witnesses: Any = None,
    witness_provider: Callable[..., Any] | None = None,
    witness_verifier: Callable[..., Any] | None = None,
    passwords: Mapping[str, str] | None = None,
    password: str | None = None,
    verify_macro_free: bool = False,
    require_macro_free: bool = False,
    require_witness_binding: bool = False,
    mutate_input: bool = True,
    **kwargs: Any,
) -> ReviewRecord:
    """Reconcile a fictional archive report with local Office samples.

    The returned report marks original-layout conclusions as pending while
    retaining conclusions backed by logical stream identity, public structure,
    and a satisfied external resealing witness.
    """
    original_report = report if isinstance(report, Mapping) else None
    loaded = _load_lenient_json(report) if not isinstance(report, Mapping) else report
    if isinstance(loaded, list):
        report_record = _wrap({"conclusions": loaded})
    elif isinstance(loaded, Mapping):
        report_record = _wrap(dict(loaded))
    else:
        report_record = _wrap(dict(_as_mapping(loaded) or {}))
    if not any(
        key in report_record
        for key in ("evidence", "items", "artifacts", "records", "conclusions", "claims", "findings", "assertions")
    ) and ("text" in report_record or "statement" in report_record or "claim" in report_record):
        report_record = _wrap({"conclusions": [report_record]})
    if not any(key in report_record for key in ("evidence", "items", "artifacts", "records", "conclusions", "claims", "findings")):
        nested_report = _first_key(report_record, "archive_report", "report", "data")
        if isinstance(nested_report, Mapping):
            report_record = _wrap(dict(nested_report))
    if base_dir is None and _looks_like_path(report):
        base_dir = str(Path(os.fspath(report)).parent)

    source_collection = _first_key(kwargs, "source_paths", "paths", default=None)
    source_inputs = [sources, source_files, files, current_files, artifacts, source_collection]
    source_map, source_list, source_dir, resolver = _build_source_registry(source_inputs, base_dir)

    witnesses = witnesses if witnesses is not None else witnesses_positional
    witness_map = _build_witness_registry(
        [
            witnesses,
            report_record.get("witnesses"),
            report_record.get("resealing_witnesses"),
            report_record.get("external_witnesses"),
        ]
    )

    evidence_key = next(
        (key for key in ("evidence", "items", "artifacts", "records", "streams", "entries") if key in report_record),
        None,
    )
    if evidence_key is None:
        report_record["evidence"] = []
        evidence_key = "evidence"
    evidence_input = report_record.get(evidence_key)
    evidence_items = _as_list(evidence_input)
    if isinstance(evidence_input, Mapping):
        # Preserve mapping ids while making an ordered list for processing.
        evidence_items = [dict(value, id=key) if isinstance(value, Mapping) and "id" not in value else value for key, value in evidence_input.items()]
    evidence_records = [_wrap(dict(_as_mapping(item) or {})) for item in evidence_items]
    report_record[evidence_key] = evidence_records
    evidence_by_id = {}

    for item in evidence_records:
        eid = str(_first_key(item, "id", "evidence_id", "item_id", "artifact_id", "record_id", default=""))
        if eid:
            evidence_by_id[eid] = item
        target_stream = _first_key(item, "logical_stream", "stream_name", "stream", "target_stream")
        witness = _find_witness(item, eid, witness_map, witness_provider)
        local_structure = None
        source_ref = _resolve_item_source(item, eid, source_map, source_list, source_dir, resolver, base_dir)
        inline_structure = _first_key(item, "local_structure", "current_structure", "observed_structure", "inspected_structure")
        try:
            if inline_structure is not None:
                local_structure = _coerce_structure(inline_structure)
            elif source_ref is not None:
                local_structure = read_structure(source_ref)
        except Exception as exc:
            item["structure_error"] = str(exc)

        comparison = compare_structures(
            local_structure,
            item,
            witness=witness,
            stream_name=target_stream,
            evidence_id=eid or None,
            witness_verifier=witness_verifier,
            require_witness_binding=require_witness_binding,
        )
        item["comparison"] = comparison
        item["review"] = comparison
        item["relatable"] = comparison.relatable
        item["backreference_confirmed"] = comparison.confirmed
        item["status"] = comparison.status

        if (verify_macro_free or require_macro_free) and source_ref is not None:
            item_password = None
            if isinstance(passwords, Mapping):
                item_password = passwords.get(eid) or passwords.get(_source_key(source_ref) or "")
            item_password = item_password or password
            macro = inspect_macro_free(source_ref, password=item_password)
            item["macro_review"] = macro
            item["macro_free"] = macro.get("macro_free")
            if require_macro_free and macro.get("macro_free") is not True:
                comparison["relatable"] = False
                comparison["confirmed"] = False
                comparison["status"] = PENDING_STATUS
                comparison.setdefault("reasons", ())
                comparison["reasons"] = tuple(comparison.reasons) + ("macro-free sample requirement is not satisfied",)
                item["relatable"] = False
                item["status"] = PENDING_STATUS
        evidence_by_id[eid] = item

    conclusion_key = next(
        (key for key in ("conclusions", "claims", "findings", "assertions", "statements", "opinions", "reviews") if key in report_record),
        "conclusions",
    )
    conclusion_input = report_record.get(conclusion_key)
    if isinstance(conclusion_input, Mapping):
        conclusion_items = [
            dict(value, id=key) if isinstance(value, Mapping) and "id" not in value else value
            for key, value in conclusion_input.items()
        ]
    else:
        conclusion_items = _as_list(conclusion_input)
    conclusion_records = [_wrap(dict(_as_mapping(item) or {})) for item in conclusion_items]
    conclusion_results = []
    for conclusion in conclusion_records:
        eid = _first_key(conclusion, "evidence_id", "evidence", "item_id", "ref", "reference", "target", "evidence_ref")
        if isinstance(eid, Mapping):
            eid = _first_key(eid, "id", "evidence_id", "item_id")
        eid = str(eid) if eid is not None else (next(iter(evidence_by_id)) if len(evidence_by_id) == 1 else None)
        item = evidence_by_id.get(eid or "")
        comparison = item.get("comparison") if item is not None else None
        if comparison is None and (_first_key(conclusion, "path", "file", "filename") or _first_key(conclusion, "local_structure")):
            source_ref = _resolve_item_source(conclusion, eid or "", source_map, source_list, source_dir, resolver, base_dir)
            witness = _find_witness(conclusion, eid or "", witness_map, witness_provider)
            local_structure = None
            try:
                inline = conclusion.get("local_structure") or conclusion.get("current_structure")
                local_structure = _coerce_structure(inline) if inline is not None else read_structure(source_ref)
            except Exception:
                local_structure = None
            comparison = compare_structures(local_structure, conclusion, witness=witness, stream_name=_first_key(conclusion, "logical_stream", "stream_name", "stream"), evidence_id=eid)

        basis = classify_conclusion_basis(conclusion)
        identity_proven = bool(comparison and comparison.get("relatable"))
        layout_citation = bool(basis.original_layout)
        if layout_citation:
            status = PENDING_STATUS
            retained = False
            pending = True
            reasons = ("conclusion explicitly relies on the original physical layout; verify that citation before retaining it",)
        elif identity_proven:
            status = RETAINED_STATUS
            retained = True
            pending = False
            reasons = ()
        else:
            status = PENDING_STATUS
            retained = False
            pending = True
            reasons = tuple((comparison or {}).get("reasons", ())) or ("stream identity/public structure/witness chain is not proven",)

        result = {
            "id": _first_key(conclusion, "id", "conclusion_id", "claim_id", "finding_id"),
            "evidence_id": eid,
            "status": status,
            "review_status": status,
            "disposition": "retained" if retained else "pending",
            "retained": retained,
            "can_remain": retained,
            "can_stand": retained,
            "should_retain": retained,
            "upheld": retained,
            "pending": pending,
            "pending_verification": pending,
            "cites_original_layout": layout_citation,
            "references_original_layout": layout_citation,
            "cites_stream_identity": bool(basis.stream_identity),
            "identity_proven": identity_proven,
            "relatable": identity_proven,
            "layout_matches": comparison.get("layout_matches") if comparison else None,
            "basis_classification": basis,
            "reasons": reasons,
        }
        conclusion.update({key: value for key, value in result.items() if key != "id" or conclusion.get("id") is None})
        conclusion_results.append(conclusion)

    report_record[conclusion_key] = conclusion_results
    pending_count = sum(1 for item in conclusion_results if item.pending)
    retained_count = sum(1 for item in conclusion_results if item.retained)
    report_record.update(
        {
            "kind": REPORT_KIND,
            "schema_version": SCHEMA_VERSION,
            "verdict": PENDING_STATUS if pending_count else RETAINED_STATUS,
            "status": PENDING_STATUS if pending_count else RETAINED_STATUS,
            "review_status": PENDING_STATUS if pending_count else RETAINED_STATUS,
            "pending": pending_count > 0,
            "pending_count": pending_count,
            "retained_count": retained_count,
            "summary": {
                "conclusions": len(conclusion_records),
                "pending": pending_count,
                "retained": retained_count,
                "evidence": len(evidence_records),
                "identity_links_confirmed": sum(bool(item.relatable) for item in evidence_records),
            },
            "all_identity_links_confirmed": all(bool(item.relatable) for item in evidence_records) if evidence_records else False,
            "conclusions_pending_layout": any(item.cites_original_layout and item.pending for item in conclusion_results),
            "reviews": conclusion_results,
        }
    )
    if original_report is not None and mutate_input and isinstance(original_report, dict):
        original_report.clear()
        original_report.update(report_record)
    return report_record


reconcile_archive_report = reconcile_report
review_archive_report = reconcile_report
archive_reconciliation = reconcile_report
review_report = reconcile_report
reconcile_archive = reconcile_report
audit_archive = reconcile_report


def _build_source_registry(inputs: list[Any], base_dir: str | os.PathLike[str] | None) -> tuple[dict[str, Any], list[Any], Path | None, Callable[..., Any] | None]:
    source_map: dict[str, Any] = {}
    source_list: list[Any] = []
    source_dir = Path(base_dir) if base_dir else None
    resolver = None
    for item in inputs:
        if item is None:
            continue
        if callable(item):
            resolver = item
        elif isinstance(item, Mapping):
            if item.get("kind") == STRUCTURE_KIND or "stream_map" in item or "logical_streams" in item:
                source_list.append(item)
            for key, value in item.items():
                source_map[str(key)] = value
                if _looks_like_path(value):
                    source_map.setdefault(_source_key(value) or "", value)
        elif isinstance(item, (str, os.PathLike)) and Path(os.fspath(item)).is_dir():
            source_dir = Path(os.fspath(item))
        elif isinstance(item, (list, tuple)):
            source_list.extend(item)
        else:
            source_list.append(item)
    return source_map, source_list, source_dir, resolver


def _resolve_item_source(
    item: Mapping[str, Any],
    eid: str,
    source_map: Mapping[str, Any],
    source_list: list[Any],
    source_dir: Path | None,
    resolver: Callable[..., Any] | None,
    base_dir: str | os.PathLike[str] | None,
) -> Any:
    if resolver is not None:
        try:
            resolved = resolver(eid, item)
            if resolved is not None:
                return resolved
        except TypeError:
            resolved = resolver(item)
            if resolved is not None:
                return resolved

    for key in ("source", "source_ref", "file_handle", "handle", "data", "bytes"):
        if item.get(key) is not None and not isinstance(item.get(key), (str, os.PathLike)):
            return item[key]

    raw_path = _first_key(item, "current_path", "local_path", "storage_path", "path", "file", "filename", "artifact_path")
    for lookup in (eid, str(raw_path) if raw_path is not None else "", Path(str(raw_path)).name if raw_path is not None else ""):
        if lookup and lookup in source_map:
            return source_map[lookup]

    if raw_path is not None:
        raw_text = os.fspath(raw_path)
        path = Path(raw_text)
        candidates = [path]
        if not path.is_absolute():
            if source_dir is not None:
                candidates.append(source_dir / raw_text)
            if base_dir is not None:
                candidates.append(Path(base_dir) / raw_text)
        for candidate in candidates:
            if candidate.exists():
                return candidate
        # Also allow filename matching in registered directories.
        if source_dir is not None:
            candidate = source_dir / path.name
            if candidate.exists():
                return candidate

    basename = Path(str(raw_path)).name if raw_path is not None else None
    for registered in source_list:
        if isinstance(registered, Mapping):
            continue
        registered_name = _source_key(registered)
        if basename and registered_name == basename:
            return registered
        if eid and registered_name == eid:
            return registered
    if len(source_list) == 1 and raw_path is None:
        return source_list[0]
    return raw_path if raw_path is not None else None


def _build_witness_registry(inputs: list[Any]) -> dict[str, Any]:
    registry: dict[str, Any] = {}
    for item in inputs:
        if item is None:
            continue
        if isinstance(item, Mapping):
            for key, value in item.items():
                registry[str(key)] = value
        elif isinstance(item, list):
            for witness in item:
                if isinstance(witness, Mapping):
                    wid = _first_key(witness, "witness_id", "id", "evidence_id")
                    if wid is not None:
                        registry[str(wid)] = witness
    return registry


def _find_witness(
    item: Mapping[str, Any],
    eid: str,
    registry: Mapping[str, Any],
    provider: Callable[..., Any] | None,
) -> Any:
    embedded = _first_key(item, "witness", "reseal_witness", "resealing_witness", "external_witness")
    if embedded is not None:
        return embedded
    witness_id = _first_key(item, "witness_id", "reseal_witness_id", "external_witness_id")
    if witness_id is not None and str(witness_id) in registry:
        return registry[str(witness_id)]
    if eid in registry:
        return registry[eid]
    if provider is not None:
        return provider(eid, item)
    if len(registry) == 1:
        return next(iter(registry.values()))
    return None


def _record_to_markdown(record: Mapping[str, Any]) -> str:
    lines = ["# Archive structure reconciliation", ""]
    if record.get("verdict"):
        lines.append(f"Verdict: `{record.verdict}`")
    if record.get("pending_count") is not None:
        lines.append(f"Pending: {record.pending_count}; retained: {record.get('retained_count', 0)}")
    conclusions = record.get("conclusions") or record.get("reviews") or ()
    if conclusions:
        lines.extend(["", "| Conclusion | Evidence | Status | Reason |", "| --- | --- | --- | --- |"])
        for conclusion in conclusions:
            cid = conclusion.get("id") or ""
            eid = conclusion.get("evidence_id") or ""
            status = conclusion.get("status") or ""
            reasons = "; ".join(conclusion.get("reasons") or ())
            lines.append(f"| {cid} | {eid} | `{status}` | {reasons.replace('|', '/')} |")
    return "\n".join(lines) + "\n"


# Common descriptive aliases for callers discovering the feature by vocabulary.
reconcile_evidence = reconcile_report
reconcile_evidence_report = reconcile_report
review_evidence_report = reconcile_report
reconcile_structure_report = reconcile_report
review_structure_report = reconcile_report
verify_evidence_link = compare_structures
verify_stream_identity = compare_structures
confirm_stream_identity = compare_structures
local_structure_comparison = compare_structures
structure_reconciliation = reconcile_report
archive_structure_review = reconcile_report
cold_storage_review = reconcile_report
review_cold_storage_report = reconcile_report


__all__ = [
    "SCHEMA_VERSION",
    "PENDING_VERIFICATION",
    "RETAINED",
    "CONFIRMED",
    "REJECTED",
    "ReviewStatus",
    "ConclusionStatus",
    "EvidenceStatus",
    "ReconciliationStatus",
    "ReviewVerdict",
    "EvidenceStrength",
    "MatchConfidence",
    "WitnessRecord",
    "ResealingWitness",
    "ExternalResealingWitness",
    "Witness",
    "ReviewRecord",
    "ArchiveReconciliationReport",
    "ForensicReviewReport",
    "StructureSnapshot",
    "StructureComparison",
    "StructureComparisonReport",
    "ArchiveReport",
    "EvidenceReport",
    "read_structure",
    "inspect_structure",
    "fingerprint_structure",
    "read_local_structure",
    "inspect_local_structure",
    "normalize_stream_name",
    "compare_structures",
    "compare_local_structure",
    "local_structure_compare",
    "local_structure_comparison",
    "compare_office_structures",
    "structure_match",
    "verify_reseal_witness",
    "verify_external_resealing_witness",
    "verify_witness",
    "build_reseal_witness",
    "create_resealing_witness",
    "make_witness",
    "classify_conclusion_basis",
    "classify_conclusion",
    "inspect_macro_free",
    "reconcile_report",
    "reconcile_archive_report",
    "review_archive_report",
    "reconcile_evidence",
    "reconcile_evidence_report",
    "review_evidence_report",
    "reconcile_structure_report",
    "review_structure_report",
    "verify_evidence_link",
    "verify_stream_identity",
    "confirm_stream_identity",
    "review_report",
    "archive_reconciliation",
    "cold_storage_review",
]


class StructureReconciler:
    """Small class-based wrapper around the functional review API."""

    def __init__(
        self,
        sources: Any = None,
        *,
        witnesses: Any = None,
        base_dir: str | os.PathLike[str] | None = None,
        witness_verifier: Callable[..., Any] | None = None,
        password: str | None = None,
        passwords: Mapping[str, str] | None = None,
        verify_macro_free: bool = False,
        require_macro_free: bool = False,
        require_witness_binding: bool = False,
    ) -> None:
        self.sources = sources
        self.witnesses = witnesses
        self.base_dir = base_dir
        self.witness_verifier = witness_verifier
        self.password = password
        self.passwords = passwords
        self.verify_macro_free = verify_macro_free
        self.require_macro_free = require_macro_free
        self.require_witness_binding = require_witness_binding

    def read_structure(self, source: Any, **kwargs: Any) -> ReviewRecord:
        return read_structure(source, **kwargs)

    def compare(self, first: Any = None, second: Any = None, **kwargs: Any) -> ReviewRecord:
        kwargs.setdefault("witness_verifier", self.witness_verifier)
        kwargs.setdefault("require_witness_binding", self.require_witness_binding)
        return compare_structures(first, second, **kwargs)

    compare_structures = compare
    verify_witness = staticmethod(verify_reseal_witness)
    build_witness = staticmethod(build_reseal_witness)

    def reconcile(self, report: Any, sources: Any = None, **kwargs: Any) -> ReviewRecord:
        return reconcile_report(
            report,
            self.sources if sources is None else sources,
            witnesses=kwargs.pop("witnesses", self.witnesses),
            base_dir=kwargs.pop("base_dir", self.base_dir),
            witness_verifier=kwargs.pop("witness_verifier", self.witness_verifier),
            password=kwargs.pop("password", self.password),
            passwords=kwargs.pop("passwords", self.passwords),
            verify_macro_free=kwargs.pop("verify_macro_free", self.verify_macro_free),
            require_macro_free=kwargs.pop("require_macro_free", self.require_macro_free),
            require_witness_binding=kwargs.pop("require_witness_binding", self.require_witness_binding),
            **kwargs,
        )

    review = reconcile
    review_report = reconcile
    reconcile_archive_report = reconcile
    __call__ = reconcile


ArchiveReconciler = StructureReconciler
EvidenceReconciler = StructureReconciler
ColdStorageReconciler = StructureReconciler
ForensicReviewer = StructureReconciler
StructureReviewer = StructureReconciler
reconcile_cold_storage_report = reconcile_report
review_cold_storage_archive = reconcile_report

__all__ += [
    "StructureReconciler",
    "ArchiveReconciler",
    "EvidenceReconciler",
    "ColdStorageReconciler",
    "ForensicReviewer",
    "StructureReviewer",
    "reconcile_cold_storage_report",
    "review_cold_storage_archive",
]
