"""Offline identity corroboration for registry exports.

This module is deliberately conservative.  It separates three things that are
easy to conflate in a registry case:

* **Sampling provenance** - where an export came from and whether it is a
  derivative of another export.
* **Volume identity** - which volume the export claims to belong to.
* **Name associations** - registry-derived links between identifiers
  (SID/profile path/account name/computer name) that can be checked in the
  hive itself.

The result is one of three explicit verdicts: ``same_subject``,
``missing_evidence`` or ``conflict``.  Plugin output is carried as
supplemental evidence only; it is never promoted to an original source.

The module is offline-only and has no network dependencies.  It can read plain
REGF hives or ``.xz``-compressed test fixtures.
"""

from __future__ import annotations

import copy
import hashlib
import json
import lzma
import ntpath
import os
import re
import shutil
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

TOOL_NAME = "regipy-corroboration"
TOOL_VERSION = "1.0"

DEFAULT_NTUSER_ANCHOR_PATHS = [
    r"\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
    r"\Control Panel\Desktop",
    r"\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
]

DEFAULT_NTUSER_PLUGINS = [
    "typed_urls",
    "typed_paths",
    "user_assist",
    "ntuser_persistence",
    "recentdocs",
    "runmru",
]

DEFAULT_SOFTWARE_ANCHOR_PATHS = [
    r"\Microsoft\Windows NT\CurrentVersion\ProfileList",
    r"\Microsoft\Windows NT\CurrentVersion",
    r"\Microsoft\Windows\CurrentVersion\Uninstall",
]

DEFAULT_SYSTEM_ANCHOR_PATHS = [
    r"\ControlSet001\Control\ComputerName\ComputerName",
    r"\ControlSet001\Control\TimeZoneInformation",
    r"\ControlSet001\Services\Disk\Enum",
]

DEFAULT_SAM_ANCHOR_PATHS = [
    r"\SAM\Domains\Account\Users\Names",
]

DEFAULT_SOFTWARE_PLUGINS = ["profilelist_plugin", "installed_programs_software"]
DEFAULT_SYSTEM_PLUGINS = ["computer_name", "services"]
DEFAULT_SAM_PLUGINS = ["samparse"]

# A clone is suspected when two exports share a hive creation GUID, a volume
# fingerprint, and nearly all observed key timestamps.  This is deliberately
# conservative: suspected clones are collapsed into one lineage so they cannot
# be counted as independent corroboration.
CLONE_ANCHOR_OVERLAP_THRESHOLD = 0.8
CLONE_MIN_IDENTICAL_ANCHORS = 2

SHELL_FOLDERS_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
PROFILE_LIST_PATH = r"\Microsoft\Windows NT\CurrentVersion\ProfileList"
COMPUTER_NAME_PATHS = [
    r"\ControlSet001\Control\ComputerName\ComputerName",
    r"\ControlSet002\Control\ComputerName\ComputerName",
]
VOLATILE_ENVIRONMENT_PATH = r"\Volatile Environment"

_PATH_VALUE_NAMES = ("appdata", "local appdata", "personal")
_WINDOWS_PATH_RE = re.compile(r"(?i)([a-z]:[\\/][^\"']+)")
_USER_PROFILE_RE = re.compile(r"(?i)users[\\/]+([^\\/]+)[\\/]+ntuser\.dat")
_ROOT_GUID_RE = re.compile(r"\{[0-9a-fA-F-]{20,}\}")


class Verdict(str, Enum):
    """The only three disposition values emitted by the reviewer."""

    SAME_SUBJECT = "same_subject"
    MISSING_EVIDENCE = "missing_evidence"
    CONFLICT = "conflict"


class Origin(str, Enum):
    """Where a value came from.

    ``PLUGIN`` is intentionally distinct from ``HIVE``.  Plugin values are
    derived observations and must never be rendered as an original source.
    """

    CALLER = "caller"
    HIVE = "hive"
    PLUGIN = "plugin"


class EvidenceRole(str, Enum):
    PRIMARY = "primary"
    SUPPLEMENTAL = "supplemental"


def _as_enum(value: Any, enum_type: Any, default: Any) -> Any:
    if isinstance(value, enum_type):
        return value
    if value is None:
        return default
    try:
        return enum_type(str(value).lower())
    except ValueError:
        return default


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=_json_default, ensure_ascii=False)


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _norm_text(value: Any) -> str:
    """Case-fold a registry identifier while keeping it readable in output."""

    if value is None:
        return ""
    text = str(value).strip().replace("/", "\\")
    while len(text) > 3 and text.endswith("\\"):
        text = text[:-1]
    return text.casefold()


def _norm_type(value: Any) -> str:
    raw = str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")
    aliases = {
        "username": "account_name",
        "user_name": "account_name",
        "account": "account_name",
        "account_alias": "account_name",
        "alias": "account_name",
        "user": "account_name",
        "profile": "profile_path",
        "user_profile": "profile_path",
        "profileimagepath": "profile_path",
        "user_sid": "sid",
        "hostname": "computer_name",
        "machine_name": "computer_name",
        "computername": "computer_name",
    }
    return aliases.get(raw, raw or "unknown")


def _is_path_type(value_type: str) -> bool:
    return _norm_type(value_type) in {"profile_path", "volume_path", "file_path"}


def _profile_root_from_path(path: str) -> str | None:
    """Derive a Windows user profile root from a known shell folder path."""

    if not path:
        return None
    normalized = str(path).strip().strip('"')
    lowered = normalized.casefold().replace("/", "\\")
    for marker in ("\\appdata\\", "\\documents", "\\desktop", "\\downloads"):
        position = lowered.find(marker)
        if position > 2:
            return normalized[:position].rstrip("\\")
    match = _WINDOWS_PATH_RE.search(normalized)
    return match.group(1).rstrip("\\") if match else None


def _profile_from_header_file_name(file_name: str | None) -> tuple[str, str] | None:
    if not file_name:
        return None
    match = _USER_PROFILE_RE.search(file_name)
    if not match:
        return None
    alias = match.group(1)
    drive_match = re.search(r"(?i)([a-z]:)[\\/]+users[\\/]+", file_name)
    drive = drive_match.group(1).upper() if drive_match else "C:"
    return f"{drive}\\Users\\{alias}", alias


def _basename(path: str) -> str:
    return ntpath.basename(str(path).rstrip("\\/")) or str(path)


def _slug(value: str, limit: int = 48) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", str(value)).strip("-").lower()
    if len(cleaned) > limit:
        cleaned = cleaned[:limit].rstrip("-") + "-" + hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:8]
    return cleaned or "item"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class IdentityRecord:
    """A single, addressable identity input.

    Records are the dependency unit for replacement analysis.  Every
    association in the review names the records it depends on.
    """

    export_id: str
    record_id: str
    kind: str
    value: dict[str, Any]
    origin: Origin = Origin.CALLER
    role: EvidenceRole = EvidenceRole.PRIMARY
    independently_verifiable: bool = False
    depends_on: list[str] = field(default_factory=list)
    note: str | None = None

    def __post_init__(self) -> None:
        self.origin = _as_enum(self.origin, Origin, Origin.CALLER)
        self.role = _as_enum(self.role, EvidenceRole, EvidenceRole.PRIMARY)

    @property
    def full_id(self) -> str:
        return f"{self.export_id}:{self.record_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "export_id": self.export_id,
            "record_id": self.record_id,
            "full_id": self.full_id,
            "kind": self.kind,
            "value": self.value,
            "origin": self.origin.value,
            "role": self.role.value,
            "independently_verifiable": self.independently_verifiable,
            "depends_on": list(self.depends_on),
            "note": self.note,
        }


@dataclass
class SamplingSource:
    """Caller-registered acquisition provenance."""

    source_id: str
    acquisition_id: str | None = None
    collected_from: str | None = None
    collected_at: str | None = None
    collector: str | None = None
    image_sha256: str | None = None
    derived_from: str | None = None
    notes: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SamplingSource:
        return cls(
            source_id=str(data.get("source_id") or data.get("id") or "source"),
            acquisition_id=data.get("acquisition_id"),
            collected_from=data.get("collected_from"),
            collected_at=data.get("collected_at"),
            collector=data.get("collector"),
            image_sha256=data.get("image_sha256"),
            derived_from=data.get("derived_from"),
            notes=data.get("notes"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "acquisition_id": self.acquisition_id,
            "collected_from": self.collected_from,
            "collected_at": self.collected_at,
            "collector": self.collector,
            "image_sha256": self.image_sha256,
            "derived_from": self.derived_from,
            "notes": self.notes,
        }


@dataclass
class VolumeIdentity:
    """Caller-registered volume identity.

    Volume identity ties exports to a volume; it does not by itself prove that
    the same person used that volume.  A clone normally preserves the volume
    identity, which is why cloned content cannot be counted twice.
    """

    volume_serial: str | None = None
    disk_signature: str | None = None
    disk_guid: str | None = None
    volume_label: str | None = None
    device_serial: str | None = None
    image_sha256: str | None = None
    origin: Origin = Origin.CALLER
    independently_verifiable: bool = False
    evidence_path: str | None = None
    fixture: bool = False
    note: str | None = None

    def __post_init__(self) -> None:
        self.origin = _as_enum(self.origin, Origin, Origin.CALLER)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VolumeIdentity:
        return cls(
            volume_serial=data.get("volume_serial"),
            disk_signature=data.get("disk_signature"),
            disk_guid=data.get("disk_guid"),
            volume_label=data.get("volume_label"),
            device_serial=data.get("device_serial"),
            image_sha256=data.get("image_sha256"),
            origin=_as_enum(data.get("origin"), Origin, Origin.CALLER),
            independently_verifiable=bool(data.get("independently_verifiable", False)),
            evidence_path=data.get("evidence_path"),
            fixture=bool(data.get("fixture", False)),
            note=data.get("note"),
        )

    def fingerprint(self) -> str | None:
        parts: list[str] = []
        if self.disk_guid:
            parts.append(f"disk_guid={_norm_text(self.disk_guid)}")
        if self.disk_signature:
            parts.append(f"disk_signature={_norm_text(self.disk_signature)}")
        if self.volume_serial:
            parts.append(f"volume_serial={_norm_text(self.volume_serial)}")
        if self.device_serial:
            parts.append(f"device_serial={_norm_text(self.device_serial)}")
        if not parts and self.volume_label:
            parts.append(f"volume_label={_norm_text(self.volume_label)}")
        return "|".join(parts) if parts else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "volume_serial": self.volume_serial,
            "disk_signature": self.disk_signature,
            "disk_guid": self.disk_guid,
            "volume_label": self.volume_label,
            "device_serial": self.device_serial,
            "image_sha256": self.image_sha256,
            "origin": self.origin.value,
            "independently_verifiable": self.independently_verifiable,
            "evidence_path": self.evidence_path,
            "fixture": self.fixture,
            "note": self.note,
        }


@dataclass
class NameAssociation:
    """A registry-derived link between two identity values.

    ``identifier_type``/``identifier`` and ``name_type``/``name`` are symmetric
    endpoints.  Examples::

        profile_path: C:\\Users\\alice  <->  account_name: alice
        sid: S-1-5-21-...-1001          <->  account_name: alice
        sid: S-1-5-21-...-1001          <->  profile_path: C:\\Users\\alice

    A caller-provided association is only treated as primary evidence when it
    is marked independently verifiable and either carries a verification result
    or can be checked against the referenced hive value.
    """

    identifier_type: str
    identifier: str
    name_type: str = "account_name"
    name: str = ""
    method: str = "caller_assertion"
    evidence_path: str | None = None
    value_name: str | None = None
    value_role: str = "identifier"
    origin: Origin = Origin.HIVE
    independently_verifiable: bool = True
    verified: bool | None = None
    observed_value: str | None = None
    association_id: str | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        self.origin = _as_enum(self.origin, Origin, Origin.HIVE)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NameAssociation:
        identifier_type = data.get("identifier_type")
        identifier = data.get("identifier")
        name_type = data.get("name_type", "account_name")
        name = data.get("name")

        if identifier_type is None and "sid" in data:
            identifier_type, identifier = "sid", data["sid"]
            name_type, name = "account_name", data.get("username") or data.get("account_name")
        if identifier_type is None and "profile_path" in data:
            identifier_type, identifier = "profile_path", data["profile_path"]
            name_type, name = "account_name", data.get("username") or data.get("account_name")
        if name is None and "username" in data:
            name_type, name = "account_name", data["username"]

        return cls(
            identifier_type=str(identifier_type or "unknown"),
            identifier=str(identifier or ""),
            name_type=str(name_type),
            name=str(name or ""),
            method=str(data.get("method", "caller_assertion")),
            evidence_path=data.get("evidence_path"),
            value_name=data.get("value_name"),
            value_role=str(data.get("value_role", "identifier")),
            origin=_as_enum(data.get("origin"), Origin, Origin.HIVE),
            independently_verifiable=bool(data.get("independently_verifiable", True)),
            verified=data.get("verified"),
            observed_value=data.get("observed_value"),
            association_id=data.get("association_id"),
            note=data.get("note"),
        )

    @property
    def identifier_key(self) -> tuple[str, str]:
        return _norm_type(self.identifier_type), _norm_text(self.identifier)

    @property
    def name_key(self) -> tuple[str, str]:
        return _norm_type(self.name_type), _norm_text(self.name)

    @property
    def canonical_key(self) -> tuple[str, str, str, str]:
        return (self.identifier_key[0], self.identifier_key[1], self.name_key[0], self.name_key[1])

    def is_primary(self) -> bool:
        return (
            self.origin != Origin.PLUGIN
            and self.independently_verifiable
            and self.verified is True
            and bool(self.identifier)
            and bool(self.name)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier_type": self.identifier_type,
            "identifier": self.identifier,
            "name_type": self.name_type,
            "name": self.name,
            "method": self.method,
            "evidence_path": self.evidence_path,
            "value_name": self.value_name,
            "value_role": self.value_role,
            "origin": self.origin.value,
            "independently_verifiable": self.independently_verifiable,
            "verified": self.verified,
            "observed_value": self.observed_value,
            "association_id": self.association_id,
            "note": self.note,
        }


@dataclass
class ContentAnchor:
    """A key path + timestamp + value digest observation.

    Identical anchors are useful for detecting copying, but they are not
    subject evidence.  If the two exports are clone-related, identical anchors
    are expected and cannot corroborate identity independently.
    """

    path: str
    timestamp: str | None = None
    value_digest: str | None = None
    values_count: int = 0
    origin: Origin = Origin.HIVE
    record_id: str | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        self.origin = _as_enum(self.origin, Origin, Origin.HIVE)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ContentAnchor:
        return cls(
            path=str(data.get("path", "")),
            timestamp=data.get("timestamp"),
            value_digest=data.get("value_digest"),
            values_count=int(data.get("values_count", 0)),
            origin=_as_enum(data.get("origin"), Origin, Origin.HIVE),
            record_id=data.get("record_id"),
            note=data.get("note"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "timestamp": self.timestamp,
            "value_digest": self.value_digest,
            "values_count": self.values_count,
            "origin": self.origin.value,
            "record_id": self.record_id,
            "note": self.note,
        }


@dataclass
class PluginObservation:
    """A plugin result, explicitly marked as supplemental."""

    plugin_name: str
    digest: str | None = None
    entry_count: int | None = None
    last_write: str | None = None
    key_path: str | None = None
    sample: Any = None
    error: str | None = None
    record_id: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PluginObservation:
        return cls(
            plugin_name=str(data.get("plugin_name") or data.get("plugin") or "plugin"),
            digest=data.get("digest"),
            entry_count=data.get("entry_count"),
            last_write=data.get("last_write"),
            key_path=data.get("key_path"),
            sample=data.get("sample"),
            error=data.get("error"),
            record_id=data.get("record_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "digest": self.digest,
            "entry_count": self.entry_count,
            "last_write": self.last_write,
            "key_path": self.key_path,
            "sample": self.sample,
            "error": self.error,
            "record_id": self.record_id,
        }


@dataclass
class ExportRecord:
    """One registry export and its caller-registered provenance."""

    export_id: str
    hive_path: str | None = None
    hive_type: str | None = None
    sampling_source: SamplingSource | None = None
    volume_identity: VolumeIdentity | None = None
    name_associations: list[NameAssociation] = field(default_factory=list)
    content_anchors: list[ContentAnchor] = field(default_factory=list)
    plugin_observations: list[PluginObservation] = field(default_factory=list)
    auto_extract: bool = True
    anchor_paths: list[str] | None = None
    plugins: list[str] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    records: list[IdentityRecord] = field(default_factory=list)
    materialize_error: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExportRecord:
        source = data.get("sampling_source") or data.get("source")
        volume = data.get("volume_identity") or data.get("volume")
        return cls(
            export_id=str(data.get("export_id") or data.get("id") or "export"),
            hive_path=data.get("hive_path"),
            hive_type=data.get("hive_type"),
            sampling_source=SamplingSource.from_dict(source) if isinstance(source, Mapping) else None,
            volume_identity=VolumeIdentity.from_dict(volume) if isinstance(volume, Mapping) else None,
            name_associations=[
                NameAssociation.from_dict(x) for x in data.get("name_associations", []) if isinstance(x, Mapping)
            ],
            content_anchors=[ContentAnchor.from_dict(x) for x in data.get("content_anchors", []) if isinstance(x, Mapping)],
            plugin_observations=[
                PluginObservation.from_dict(x) for x in data.get("plugin_observations", []) if isinstance(x, Mapping)
            ],
            auto_extract=bool(data.get("auto_extract", True)),
            anchor_paths=list(data["anchor_paths"]) if data.get("anchor_paths") else None,
            plugins=list(data["plugins"]) if data.get("plugins") else None,
            metadata=dict(data.get("metadata", {})),
        )

    def to_dict(self, include_records: bool = False) -> dict[str, Any]:
        result = {
            "export_id": self.export_id,
            "hive_path": self.hive_path,
            "hive_type": self.hive_type,
            "sampling_source": self.sampling_source.to_dict() if self.sampling_source else None,
            "volume_identity": self.volume_identity.to_dict() if self.volume_identity else None,
            "name_associations": [x.to_dict() for x in self.name_associations],
            "content_anchors": [x.to_dict() for x in self.content_anchors],
            "plugin_observations": [x.to_dict() for x in self.plugin_observations],
            "auto_extract": self.auto_extract,
            "anchor_paths": self.anchor_paths,
            "plugins": self.plugins,
            "metadata": self.metadata,
            "materialize_error": self.materialize_error,
        }
        if include_records:
            result["records"] = [x.to_dict() for x in self.records]
        return result


@dataclass
class CorroborationCase:
    """A set of exports and the caller's same-subject claim."""

    case_id: str
    exports: list[ExportRecord]
    claim: str | None = None
    target_export_ids: list[str] | None = None
    notes: str | None = None
    classification: str = "internal_review"
    metadata: dict[str, Any] = field(default_factory=dict)
    materialized: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CorroborationCase:
        exports = [ExportRecord.from_dict(x) for x in data.get("exports", []) if isinstance(x, Mapping)]
        return cls(
            case_id=str(data.get("case_id") or data.get("id") or "case"),
            exports=exports,
            claim=data.get("claim"),
            target_export_ids=list(data["target_exports"]) if data.get("target_exports") else None,
            notes=data.get("notes"),
            classification=str(data.get("classification", "internal_review")),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_json_file(cls, path: str) -> CorroborationCase:
        with open(path, encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    def export_map(self) -> dict[str, ExportRecord]:
        return {record.export_id: record for record in self.exports}

    def targets(self) -> list[str]:
        if self.target_export_ids:
            return list(self.target_export_ids)
        return [record.export_id for record in self.exports]

    def to_dict(self, include_records: bool = False) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "claim": self.claim,
            "target_exports": self.targets(),
            "notes": self.notes,
            "classification": self.classification,
            "metadata": self.metadata,
            "exports": [record.to_dict(include_records=include_records) for record in self.exports],
        }

    def materialize(self) -> CorroborationCase:
        if self.materialized:
            return self
        for export in self.exports:
            _materialize_export(export)
        self.materialized = True
        return self

    def all_records(self) -> list[IdentityRecord]:
        self.materialize()
        records: list[IdentityRecord] = []
        for export in self.exports:
            records.extend(export.records)
        return records


@dataclass
class AssociationFinding:
    """One relationship in the dependency-aware review ledger."""

    association_id: str
    kind: str
    status: str
    exports: list[str]
    origin: str
    role: str
    depends_on: list[str]
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "association_id": self.association_id,
            "kind": self.kind,
            "status": self.status,
            "exports": self.exports,
            "origin": self.origin,
            "role": self.role,
            "depends_on": self.depends_on,
            "summary": self.summary,
            "evidence": self.evidence,
        }


@dataclass
class ReviewResult:
    """The internal review result."""

    case_id: str
    verdict: Verdict
    claim: str | None
    rationale: list[str]
    exports: list[dict[str, Any]]
    pairwise: list[dict[str, Any]]
    associations: list[AssociationFinding]
    conflicts: list[dict[str, Any]]
    missing_evidence: list[dict[str, Any]]
    anchors: list[dict[str, Any]]
    plugin_evidence: list[dict[str, Any]]
    provenance: dict[str, Any]
    generated_at: str
    classification: str = "internal_review"
    replacement: dict[str, Any] | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "classification": self.classification,
            "case_id": self.case_id,
            "claim": self.claim,
            "verdict": self.verdict.value,
            "rationale": self.rationale,
            "notes": self.notes,
            "generated_at": self.generated_at,
            "provenance": self.provenance,
            "exports": self.exports,
            "pairwise": self.pairwise,
            "associations": [x.to_dict() for x in self.associations],
            "conflicts": self.conflicts,
            "missing_evidence": self.missing_evidence,
            "anchors": self.anchors,
            "plugin_evidence": self.plugin_evidence,
            "replacement": self.replacement,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=_json_default)

    def write_json(self, path: str, indent: int = 2) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.to_json(indent=indent))
            handle.write("\n")

    def to_markdown(self) -> str:
        return _render_markdown(self)

    def write_markdown(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.to_markdown())
            handle.write("\n")


# ---------------------------------------------------------------------------
# Hive loading and materialsation
# ---------------------------------------------------------------------------


def _temp_root() -> str:
    return os.environ.get("REGIPY_CORROBORATION_TMPDIR") or os.getcwd()


@contextmanager
def _open_hive(path: str, hive_type: str | None = None) -> Iterator[RegistryHive]:
    """Open a plain REGF hive or a .xz fixture without touching the network."""

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    temp_dir = None
    load_path = path
    if path.lower().endswith(".xz"):
        temp_dir = tempfile.mkdtemp(prefix="regipy-corroboration-", dir=_temp_root())
        load_path = os.path.join(temp_dir, ntpath.basename(path)[:-3])
        with lzma.open(path, "rb") as source, open(load_path, "wb") as target:
            shutil.copyfileobj(source, target)

    try:
        yield RegistryHive(load_path, hive_type=hive_type)
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def _hive_payload_sha256(hive: RegistryHive) -> str | None:
    stream = getattr(hive, "_stream", None)
    if stream is None:
        return None
    try:
        return hashlib.sha256(stream.getvalue()).hexdigest()
    except Exception:
        return None


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _stringify_value(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _truncate(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "..."
    if isinstance(value, str):
        return value if len(value) <= 240 else value[:237] + "..."
    if isinstance(value, bytes):
        return value.hex()[:240]
    if isinstance(value, list):
        return [_truncate(item, depth + 1) for item in value[:3]]
    if isinstance(value, dict):
        return {str(key): _truncate(item, depth + 1) for key, item in list(value.items())[:12]}
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _append_note(existing: str | None, addition: str | None) -> str | None:
    if not addition:
        return existing
    if not existing:
        return addition
    if addition in existing:
        return existing
    return existing + " " + addition


def _path_matches(observed: str, expected: str) -> bool:
    left = _norm_text(observed)
    right = _norm_text(expected)
    if not left or not right:
        return False
    if left == right:
        return True
    return left.startswith(right.rstrip("\\") + "\\") or right.startswith(left.rstrip("\\") + "\\")


def _anchor_paths_for(export: ExportRecord) -> list[str]:
    if export.anchor_paths:
        return list(export.anchor_paths)
    hive_type = (export.hive_type or "").lower()
    if hive_type == "software":
        return [PROFILE_LIST_PATH, r"\Microsoft\Windows\CurrentVersion\Uninstall"]
    if hive_type == "system":
        return [
            r"\ControlSet001\Control\ComputerName\ComputerName",
            r"\ControlSet001\Services\Disk\Enum",
            r"\ControlSet001\Control\TimeZoneInformation",
        ]
    if hive_type == "sam":
        return [r"\SAM\Domains\Account\Users\Names"]
    return list(DEFAULT_NTUSER_ANCHOR_PATHS)


def _plugins_for(export: ExportRecord) -> list[str]:
    if export.plugins is not None:
        return list(export.plugins)
    hive_type = (export.hive_type or "").lower()
    if hive_type == "ntuser":
        return list(DEFAULT_NTUSER_PLUGINS)
    if hive_type == "software":
        return ["profilelist_plugin", "installed_programs_software"]
    if hive_type == "sam":
        return ["samparse", "local_sid"]
    if hive_type == "system":
        return ["computer_name", "services", "timezone_data"]
    return []


def _hive_identity_record(export: ExportRecord, hive: RegistryHive) -> IdentityRecord:
    root_key = getattr(hive.root, "name", "") or ""
    match = _ROOT_GUID_RE.search(root_key)
    root_guid = match.group(0) if match else None
    return IdentityRecord(
        export_id=export.export_id,
        record_id="hive_identity",
        kind="hive_identity",
        value={
            "root_key": root_key,
            "root_guid": root_guid,
            "hive_type": hive.hive_type,
        },
        origin=Origin.HIVE,
        role=EvidenceRole.PRIMARY,
        independently_verifiable=bool(root_guid),
        note="Registry-internal hive creation identity. It is not a volume serial.",
    )


def _hive_header_record(export: ExportRecord, hive: RegistryHive) -> IdentityRecord:
    header = hive.header
    return IdentityRecord(
        export_id=export.export_id,
        record_id="hive_header",
        kind="hive_header",
        value={
            "file_name": getattr(header, "file_name", None),
            "primary_sequence_num": getattr(header, "primary_sequence_num", None),
            "secondary_sequence_num": getattr(header, "secondary_sequence_num", None),
            "payload_sha256": _hive_payload_sha256(hive),
            "hive_type": hive.hive_type,
        },
        origin=Origin.HIVE,
        role=EvidenceRole.PRIMARY,
        independently_verifiable=True,
        note="Parsed directly from the REGF header.",
    )


def _materialize_export(export: ExportRecord) -> None:
    export.records = []
    export.materialize_error = None

    if export.sampling_source:
        source = export.sampling_source
        export.records.append(
            IdentityRecord(
                export_id=export.export_id,
                record_id="source",
                kind="sampling_source",
                value=source.to_dict(),
                origin=Origin.CALLER,
                role=EvidenceRole.PRIMARY,
                independently_verifiable=False,
                note="Caller-registered sampling provenance. Used for lineage, not subject identity.",
            )
        )

    if export.volume_identity:
        volume = export.volume_identity
        value = volume.to_dict()
        value["fingerprint"] = volume.fingerprint()
        export.records.append(
            IdentityRecord(
                export_id=export.export_id,
                record_id="volume",
                kind="volume_identity",
                value=value,
                origin=volume.origin,
                role=EvidenceRole.PRIMARY,
                independently_verifiable=volume.independently_verifiable,
                note="Caller-registered volume identity. A clone can preserve it.",
            )
        )

    explicit_associations = list(export.name_associations)
    associations: list[NameAssociation] = []
    anchors: list[ContentAnchor] = []
    plugins: list[PluginObservation] = []

    if export.hive_path:
        try:
            with _open_hive(export.hive_path, export.hive_type) as hive:
                export.records.append(_hive_identity_record(export, hive))
                export.records.append(_hive_header_record(export, hive))
                if export.auto_extract:
                    associations.extend(_extract_auto_associations(hive, export))
                    anchors.extend(_extract_auto_anchors(hive, export))
                    plugins.extend(_extract_plugin_observations(hive, export))
                for association in explicit_associations:
                    associations.append(_verify_association(hive, association))
        except Exception as exc:
            export.materialize_error = f"{type(exc).__name__}: {exc}"
            for association in explicit_associations:
                item = copy.deepcopy(association)
                if item.verified is None:
                    item.note = _append_note(
                        item.note,
                        "Hive unavailable; association was not independently verified.",
                    )
                associations.append(item)
    else:
        for association in explicit_associations:
            item = copy.deepcopy(association)
            if item.verified is None and not item.evidence_path:
                item.independently_verifiable = False
                item.note = _append_note(item.note, "No verifiable hive value path was supplied.")
            associations.append(item)

    anchors.extend(copy.deepcopy(export.content_anchors))
    plugins.extend(copy.deepcopy(export.plugin_observations))

    associations = _dedupe_associations(associations)
    anchors = _dedupe_anchors(anchors)
    plugins = _dedupe_plugins(plugins)

    for index, association in enumerate(associations):
        record_id = association.association_id or f"name:{index}"
        export.records.append(
            IdentityRecord(
                export_id=export.export_id,
                record_id=record_id,
                kind="name_association",
                value=association.to_dict(),
                origin=association.origin,
                role=EvidenceRole.PRIMARY if association.is_primary() else EvidenceRole.SUPPLEMENTAL,
                independently_verifiable=association.independently_verifiable,
                note=association.note,
            )
        )

    for anchor in anchors:
        record_id = anchor.record_id or f"anchor:{_slug(anchor.path)}"
        export.records.append(
            IdentityRecord(
                export_id=export.export_id,
                record_id=record_id,
                kind="content_anchor",
                value=anchor.to_dict(),
                origin=anchor.origin,
                role=EvidenceRole.PRIMARY,
                independently_verifiable=False,
                note=anchor.note,
            )
        )

    for observation in plugins:
        record_id = observation.record_id or f"plugin:{_slug(observation.plugin_name)}"
        export.records.append(
            IdentityRecord(
                export_id=export.export_id,
                record_id=record_id,
                kind="plugin_observation",
                value=observation.to_dict(),
                origin=Origin.PLUGIN,
                role=EvidenceRole.SUPPLEMENTAL,
                independently_verifiable=False,
                note="Plugin-derived. Supplemental only; never an original source.",
            )
        )


def _extract_auto_associations(hive: RegistryHive, export: ExportRecord) -> list[NameAssociation]:
    hive_type = (hive.hive_type or export.hive_type or "").lower()
    if hive_type == "ntuser":
        return _extract_ntuser_associations(hive)
    if hive_type == "software":
        return _extract_software_associations(hive)
    if hive_type == "sam":
        return _extract_sam_associations(hive)
    if hive_type == "system":
        return _extract_system_associations(hive)
    return []


def _extract_ntuser_associations(hive: RegistryHive) -> list[NameAssociation]:
    result: list[NameAssociation] = []

    try:
        key = hive.get_key(SHELL_FOLDERS_PATH)
    except RegistryKeyNotFoundException:
        key = None

    if key is not None:
        for value in key.iter_values(as_json=False):
            if str(value.name).casefold() not in _PATH_VALUE_NAMES:
                continue
            if not isinstance(value.value, str):
                continue
            profile = _profile_root_from_path(value.value)
            if not profile:
                continue
            alias = _basename(profile)
            result.append(
                NameAssociation(
                    identifier_type="profile_path",
                    identifier=profile,
                    name_type="account_name",
                    name=alias,
                    method=f"shell_folders:{value.name}",
                    evidence_path=SHELL_FOLDERS_PATH,
                    value_name=str(value.name),
                    value_role="identifier",
                    origin=Origin.HIVE,
                    independently_verifiable=True,
                    verified=True,
                    observed_value=value.value,
                    association_id=f"profile:{_slug(profile)}",
                    note="Profile root read directly from the Shell Folders key.",
                )
            )

    parsed_header = _profile_from_header_file_name(getattr(hive.header, "file_name", None))
    if parsed_header:
        profile, alias = parsed_header
        result.append(
            NameAssociation(
                identifier_type="profile_path",
                identifier=profile,
                name_type="account_name",
                name=alias,
                method="hive_header:file_name",
                evidence_path="<REGF header:file_name>",
                value_role="identifier",
                origin=Origin.HIVE,
                independently_verifiable=True,
                verified=True,
                observed_value=getattr(hive.header, "file_name", None),
                association_id=f"profile:{_slug(profile)}",
                note="Profile path parsed from the REGF header file name.",
            )
        )

    try:
        volatile = hive.get_key(VOLATILE_ENVIRONMENT_PATH)
    except RegistryKeyNotFoundException:
        volatile = None

    if volatile is not None:
        values = {str(item.name).upper(): item.value for item in volatile.iter_values(as_json=False)}
        username = values.get("USERNAME")
        userprofile = values.get("USERPROFILE")
        if isinstance(username, str) and isinstance(userprofile, str) and username and userprofile:
            profile = userprofile.rstrip("\\")
            result.append(
                NameAssociation(
                    identifier_type="profile_path",
                    identifier=profile,
                    name_type="account_name",
                    name=username,
                    method="volatile_environment",
                    evidence_path=VOLATILE_ENVIRONMENT_PATH,
                    value_name="USERPROFILE",
                    value_role="identifier",
                    origin=Origin.HIVE,
                    independently_verifiable=True,
                    verified=True,
                    observed_value=userprofile,
                    association_id=f"profile:{_slug(profile)}",
                    note="Profile path and account name read from Volatile Environment.",
                )
            )

    return result


def _extract_software_associations(hive: RegistryHive) -> list[NameAssociation]:
    result: list[NameAssociation] = []
    try:
        key = hive.get_key(PROFILE_LIST_PATH)
    except RegistryKeyNotFoundException:
        return result

    for subkey in key.iter_subkeys():
        sid = str(subkey.name)
        if not sid.upper().startswith("S-1-5-"):
            continue
        try:
            profile = subkey.get_value("ProfileImagePath", as_json=False)
        except Exception:
            profile = None
        if not isinstance(profile, str) or not profile.strip():
            continue
        profile = profile.strip().rstrip("\\")
        alias = _basename(profile)
        base_id = f"profilelist:{_slug(sid)}"
        result.append(
            NameAssociation(
                identifier_type="sid",
                identifier=sid,
                name_type="profile_path",
                name=profile,
                method="profilelist:ProfileImagePath",
                evidence_path=PROFILE_LIST_PATH + "\\" + sid,
                value_name="ProfileImagePath",
                value_role="name",
                origin=Origin.HIVE,
                independently_verifiable=True,
                verified=True,
                observed_value=profile,
                association_id=base_id,
                note="SID to profile path read directly from ProfileList.",
            )
        )
        result.append(
            NameAssociation(
                identifier_type="profile_path",
                identifier=profile,
                name_type="account_name",
                name=alias,
                method="profilelist:basename",
                evidence_path=PROFILE_LIST_PATH + "\\" + sid,
                value_name="ProfileImagePath",
                value_role="identifier",
                origin=Origin.HIVE,
                independently_verifiable=True,
                verified=True,
                observed_value=profile,
                association_id=base_id + ":alias",
                note="Account alias derived from the ProfileList path.",
            )
        )
    return result


def _extract_sam_associations(hive: RegistryHive) -> list[NameAssociation]:
    result: list[NameAssociation] = []
    try:
        key = hive.get_key(r"\SAM\Domains\Account\Users\Names")
    except RegistryKeyNotFoundException:
        return result

    for subkey in key.iter_subkeys():
        rid = None
        try:
            for value in subkey.iter_values(as_json=False):
                if str(value.name) not in ("(default)", ""):
                    continue
                if str(value.value_type).isdigit():
                    rid = int(str(value.value_type))
                elif isinstance(value.value, int):
                    rid = value.value
                elif isinstance(value.value, str) and value.value.isdigit():
                    rid = int(value.value)
                break
        except Exception:
            continue
        if rid is None:
            continue
        username = str(subkey.name)
        result.append(
            NameAssociation(
                identifier_type="rid",
                identifier=str(rid),
                name_type="account_name",
                name=username,
                method="sam_names_default_value",
                evidence_path=r"\SAM\Domains\Account\Users\Names" + "\\" + username,
                value_role="identifier",
                origin=Origin.HIVE,
                independently_verifiable=True,
                verified=True,
                observed_value=str(rid),
                association_id=f"sam:{_slug(username)}",
                note="RID to account name read from the SAM Names key; the fixture encodes the RID in the default value metadata.",
            )
        )
    return result


def _extract_system_associations(hive: RegistryHive) -> list[NameAssociation]:
    result: list[NameAssociation] = []
    for path in COMPUTER_NAME_PATHS:
        try:
            key = hive.get_key(path)
        except RegistryKeyNotFoundException:
            continue
        try:
            name = key.get_value("ComputerName", as_json=False)
        except Exception:
            name = None
        if not isinstance(name, str) or not name:
            continue
        result.append(
            NameAssociation(
                identifier_type="computer_name",
                identifier=name,
                name_type="computer_name",
                name=name,
                method="computer_name_value",
                evidence_path=path,
                value_name="ComputerName",
                value_role="identifier",
                origin=Origin.HIVE,
                independently_verifiable=True,
                verified=True,
                observed_value=name,
                association_id=f"computer:{_slug(name)}",
                note="Computer name read directly from the SYSTEM hive.",
            )
        )
        break
    return result


def _verify_association(hive: RegistryHive, association: NameAssociation) -> NameAssociation:
    result = copy.deepcopy(association)
    if result.origin == Origin.PLUGIN:
        result.independently_verifiable = False
        result.note = _append_note(result.note, "Plugin origin; supplemental only.")
        return result

    if not result.evidence_path or result.evidence_path.startswith("<"):
        if result.verified is None:
            result.independently_verifiable = False
            result.note = _append_note(result.note, "No verifiable hive value path was supplied.")
        return result

    try:
        key = hive.get_key(result.evidence_path)
        value_name = result.value_name if result.value_name not in (None, "", "(default)") else ""
        observed = key.get_value(value_name, as_json=False)
    except Exception as exc:
        result.verified = None
        result.note = _append_note(result.note, f"Verification unavailable: {type(exc).__name__}: {exc}.")
        return result

    if observed is None:
        result.verified = False
        result.note = _append_note(result.note, "Referenced hive value was not found.")
        return result

    expected = result.name if result.value_role == "name" else result.identifier
    result.observed_value = _stringify_value(observed)
    if not expected:
        result.verified = True
    elif _is_path_type(result.identifier_type) or _is_path_type(result.name_type):
        result.verified = _path_matches(result.observed_value, expected)
    else:
        result.verified = _norm_text(result.observed_value) == _norm_text(expected)

    if not result.verified:
        result.note = _append_note(
            result.note,
            f"Observed value {result.observed_value!r} does not match {expected!r}.",
        )
    return result


def _extract_auto_anchors(hive: RegistryHive, export: ExportRecord) -> list[ContentAnchor]:
    result: list[ContentAnchor] = []
    for path in _anchor_paths_for(export):
        try:
            key = hive.get_key(path)
        except Exception:
            continue
        try:
            values = []
            for value in key.iter_values(as_json=True, trim_values=False):
                values.append(
                    {
                        "name": value.name,
                        "type": value.value_type,
                        "value": _json_value(value.value),
                        "corrupted": value.is_corrupted,
                    }
                )
            values.sort(key=lambda item: item["name"])
            result.append(
                ContentAnchor(
                    path=path,
                    timestamp=convert_wintime(key.header.last_modified, as_json=True),
                    value_digest=_digest(values),
                    values_count=len(values),
                    origin=Origin.HIVE,
                    note="Read directly from the hive.",
                )
            )
        except Exception:
            continue
    return result


def _extract_plugin_observations(hive: RegistryHive, export: ExportRecord) -> list[PluginObservation]:
    plugin_names = _plugins_for(export)
    if not plugin_names:
        return []
    try:
        from regipy.plugins.utils import run_relevant_plugins

        results = run_relevant_plugins(
            hive,
            as_json=True,
            plugins=set(plugin_names),
            include_unvalidated=False,
            continue_on_error=True,
        )
    except Exception as exc:
        return [PluginObservation(plugin_name="plugin_runner", error=f"{type(exc).__name__}: {exc}")]

    result: list[PluginObservation] = []
    for name, plugin_result in results.items():
        if isinstance(plugin_result, dict) and "error" in plugin_result and len(plugin_result) == 1:
            result.append(PluginObservation(plugin_name=name, error=str(plugin_result["error"])))
            continue
        entry_count = len(plugin_result) if isinstance(plugin_result, (list, dict)) else None
        last_write = plugin_result.get("last_write") if isinstance(plugin_result, dict) else None
        result.append(
            PluginObservation(
                plugin_name=name,
                digest=_digest(plugin_result),
                entry_count=entry_count,
                last_write=last_write,
                sample=_truncate(plugin_result),
            )
        )
    return result


def _dedupe_associations(associations: Sequence[NameAssociation]) -> list[NameAssociation]:
    by_key: dict[tuple[str, str, str, str], NameAssociation] = {}
    order: list[tuple[str, str, str, str]] = []
    for association in associations:
        key = association.canonical_key
        if key not in by_key:
            by_key[key] = association
            order.append(key)
            continue
        existing = by_key[key]
        methods = set()
        for method in (existing.method, association.method):
            methods.update(part for part in str(method).split("|") if part)
        existing.method = "|".join(sorted(methods))
        if association.verified is True and existing.verified is not True:
            existing.verified = True
            existing.observed_value = association.observed_value or existing.observed_value
        elif association.verified is False:
            existing.verified = False
        existing.independently_verifiable = existing.independently_verifiable or association.independently_verifiable
        if existing.origin == Origin.PLUGIN and association.origin != Origin.PLUGIN:
            existing.origin = association.origin
        if association.evidence_path and association.evidence_path != existing.evidence_path:
            existing.evidence_path = "; ".join(filter(None, [existing.evidence_path, association.evidence_path]))
        if association.association_id and not existing.association_id:
            existing.association_id = association.association_id
        existing.note = _append_note(existing.note, association.note)
    return [by_key[key] for key in order]


def _dedupe_anchors(anchors: Sequence[ContentAnchor]) -> list[ContentAnchor]:
    seen = set()
    result = []
    for anchor in anchors:
        key = (anchor.path, anchor.timestamp, anchor.value_digest)
        if key in seen:
            continue
        seen.add(key)
        result.append(anchor)
    return result


def _dedupe_plugins(observations: Sequence[PluginObservation]) -> list[PluginObservation]:
    by_name: dict[str, PluginObservation] = {}
    order: list[str] = []
    for observation in observations:
        key = observation.plugin_name
        if key not in by_name:
            by_name[key] = observation
            order.append(key)
            continue
        if by_name[key].error and not observation.error:
            by_name[key] = observation
    return [by_name[key] for key in order]


# ---------------------------------------------------------------------------
# Evidence graph and verdict engine
# ---------------------------------------------------------------------------


class _DisjointSet:
    def __init__(self) -> None:
        self.parent: dict[Any, Any] = {}

    def add(self, item: Any) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: Any) -> Any:
        self.add(item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            next_item = self.parent[item]
            self.parent[item] = root
            item = next_item
        return root

    def union(self, first: Any, second: Any) -> None:
        root_first = self.find(first)
        root_second = self.find(second)
        if root_first != root_second:
            self.parent[root_second] = root_first


def _facts(case: CorroborationCase) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for export in case.exports:
        records = {record.record_id: record for record in export.records}
        result[export.export_id] = {
            "export": export,
            "records": records,
            "source": records.get("source"),
            "volume": records.get("volume"),
            "hive_identity": records.get("hive_identity"),
            "hive_header": records.get("hive_header"),
        }
    return result


def _anchors_by_export(case: CorroborationCase) -> dict[str, dict[str, IdentityRecord]]:
    result: dict[str, dict[str, IdentityRecord]] = {}
    for export in case.exports:
        anchors: dict[str, IdentityRecord] = {}
        for record in export.records:
            if record.kind == "content_anchor":
                anchors[str(record.value.get("path", ""))] = record
        result[export.export_id] = anchors
    return result


def _plugins_by_export(case: CorroborationCase) -> dict[str, dict[str, IdentityRecord]]:
    result: dict[str, dict[str, IdentityRecord]] = {}
    for export in case.exports:
        plugins: dict[str, IdentityRecord] = {}
        for record in export.records:
            if record.kind == "plugin_observation":
                plugins[str(record.value.get("plugin_name", ""))] = record
        result[export.export_id] = plugins
    return result


def _volume_fingerprint(fact: dict[str, Any]) -> str | None:
    record = fact.get("volume")
    if not record:
        return None
    fingerprint = record.value.get("fingerprint")
    if fingerprint:
        return str(fingerprint)
    return VolumeIdentity.from_dict(record.value).fingerprint()


_VOLUME_MATCH_FIELDS = ("disk_guid", "disk_signature", "volume_serial", "device_serial")


def _volume_comparison(first_fact: dict[str, Any], second_fact: dict[str, Any]) -> dict[str, Any]:
    """Compare volume identity field by field using overlapping strong fields."""

    first_record = first_fact.get("volume")
    second_record = second_fact.get("volume")
    if not first_record or not second_record:
        return {
            "comparable": False,
            "match": False,
            "status": "incomparable",
            "conflicts": [],
            "matches": [],
        }

    matches = []
    conflicts = []
    for field_name in _VOLUME_MATCH_FIELDS:
        first_value = first_record.value.get(field_name)
        second_value = second_record.value.get(field_name)
        if not first_value or not second_value:
            continue
        item = {"field": field_name, "first": first_value, "second": second_value}
        if _norm_text(first_value) == _norm_text(second_value):
            matches.append(item)
        else:
            conflicts.append(item)

    if not matches and not conflicts:
        first_label = first_record.value.get("volume_label")
        second_label = second_record.value.get("volume_label")
        if first_label and second_label:
            item = {"field": "volume_label", "first": first_label, "second": second_label}
            if _norm_text(first_label) == _norm_text(second_label):
                matches.append(item)
            else:
                conflicts.append(item)

    if matches and conflicts:
        status = "conflict"
    elif matches:
        status = "match"
    elif conflicts:
        status = "different"
    else:
        status = "incomparable"

    return {
        "comparable": status != "incomparable",
        "match": status == "match",
        "status": status,
        "conflicts": conflicts,
        "matches": matches,
    }


def _hive_identity_key(fact: dict[str, Any]) -> str | None:
    record = fact.get("hive_identity")
    if not record:
        return None
    guid = record.value.get("root_guid")
    if guid:
        return "guid:" + _norm_text(guid)
    root_key = str(record.value.get("root_key", ""))
    if root_key and root_key.upper() != "ROOT":
        return "root:" + _norm_text(root_key)
    return None


def _compute_lineage(
    case: CorroborationCase,
    facts: dict[str, dict[str, Any]],
    anchors_by_export: dict[str, dict[str, IdentityRecord]],
) -> tuple[dict[str, str], set[tuple[str, str]], set[tuple[str, str]], list[str]]:
    disjoint = _DisjointSet()
    for export in case.exports:
        disjoint.add(export.export_id)

    source_to_export: dict[str, str] = {}
    for export in case.exports:
        source = facts[export.export_id]["source"]
        if source and source.value.get("source_id"):
            source_to_export[str(source.value["source_id"])] = export.export_id

    explicit_clone: set[tuple[str, str]] = set()
    notes: list[str] = []

    for export in case.exports:
        source = facts[export.export_id]["source"]
        if not source:
            continue
        derived = source.value.get("derived_from")
        if not derived:
            continue
        target = derived if derived in disjoint.parent else source_to_export.get(str(derived))
        if not target:
            notes.append(f"{export.export_id}: unresolved derived_from reference {derived!r}.")
            continue
        if target != export.export_id:
            disjoint.union(export.export_id, target)
            explicit_clone.add(tuple(sorted((export.export_id, target))))

    hash_groups: dict[str, list[str]] = {}
    for export in case.exports:
        source = facts[export.export_id]["source"]
        if source and source.value.get("image_sha256"):
            hash_groups.setdefault(str(source.value["image_sha256"]), []).append(export.export_id)
    for ids in hash_groups.values():
        for other in ids[1:]:
            disjoint.union(ids[0], other)
            explicit_clone.add(tuple(sorted((ids[0], other))))

    acquisition_groups: dict[str, list[str]] = {}
    for export in case.exports:
        source = facts[export.export_id]["source"]
        if source and source.value.get("acquisition_id"):
            acquisition_groups.setdefault(str(source.value["acquisition_id"]), []).append(export.export_id)
    for ids in acquisition_groups.values():
        for other in ids[1:]:
            disjoint.union(ids[0], other)

    clone_suspected: set[tuple[str, str]] = set()
    for index, first in enumerate(case.exports):
        for second in case.exports[index + 1 :]:
            first_id = first.export_id
            second_id = second.export_id
            if disjoint.find(first_id) == disjoint.find(second_id):
                continue
            first_fact = facts[first_id]
            second_fact = facts[second_id]
            volume_comparison = _volume_comparison(first_fact, second_fact)
            first_identity = _hive_identity_key(first_fact)
            second_identity = _hive_identity_key(second_fact)
            if not (volume_comparison["match"] and first_identity and first_identity == second_identity):
                continue
            first_anchors = anchors_by_export.get(first_id, {})
            second_anchors = anchors_by_export.get(second_id, {})
            common = set(first_anchors) & set(second_anchors)
            if len(common) < 2:
                continue
            identical = [
                path
                for path in common
                if first_anchors[path].value.get("timestamp") == second_anchors[path].value.get("timestamp")
                and first_anchors[path].value.get("value_digest") == second_anchors[path].value.get("value_digest")
            ]
            if len(identical) / len(common) >= 0.8:
                disjoint.union(first_id, second_id)
                clone_suspected.add(tuple(sorted((first_id, second_id))))
                notes.append(
                    f"{first_id} and {second_id}: shared volume, shared hive identity and "
                    f"{len(identical)}/{len(common)} identical anchors indicate a clone; treated as one lineage."
                )

    roots = {export.export_id: disjoint.find(export.export_id) for export in case.exports}
    return roots, explicit_clone | clone_suspected, clone_suspected, notes


def _name_edges(case: CorroborationCase) -> list[tuple[str, IdentityRecord, NameAssociation]]:
    result = []
    for export in case.exports:
        for record in export.records:
            if record.kind != "name_association":
                continue
            result.append((export.export_id, record, NameAssociation.from_dict(record.value)))
    return result


def _build_subject_graph(
    edges: Sequence[tuple[str, IdentityRecord, NameAssociation]],
) -> dict[str, Any]:
    disjoint = _DisjointSet()
    primary: list[tuple[str, IdentityRecord, NameAssociation]] = []
    supplemental: list[tuple[str, IdentityRecord, NameAssociation]] = []
    for export_id, record, association in edges:
        if association.is_primary():
            primary.append((export_id, record, association))
        else:
            supplemental.append((export_id, record, association))

    for _, _, association in primary:
        disjoint.union(association.identifier_key, association.name_key)

    export_nodes: dict[str, set[tuple[str, str]]] = {}
    export_types: dict[str, set[str]] = {}
    node_exports: dict[tuple[str, str], set[str]] = {}
    for export_id, _, association in primary:
        nodes = {association.identifier_key, association.name_key}
        export_nodes.setdefault(export_id, set()).update(nodes)
        export_types.setdefault(export_id, set()).update({association.identifier_key[0], association.name_key[0]})
        for node in nodes:
            node_exports.setdefault(node, set()).add(export_id)

    return {
        "disjoint": disjoint,
        "primary": primary,
        "supplemental": supplemental,
        "export_nodes": export_nodes,
        "export_types": export_types,
        "node_exports": node_exports,
    }


def _functional_conflicts(
    primary: Sequence[tuple[str, IdentityRecord, NameAssociation]],
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    seen: set[tuple[str, Any, str]] = set()

    by_identifier: dict[tuple[str, str], dict[str, dict[str, list[tuple[str, IdentityRecord]]]]] = {}
    by_name: dict[tuple[str, str], dict[str, dict[str, list[tuple[str, IdentityRecord]]]]] = {}
    for export_id, record, association in primary:
        by_identifier.setdefault(association.identifier_key, {}).setdefault(association.name_key[0], {}).setdefault(
            association.name_key[1], []
        ).append((export_id, record))
        by_name.setdefault(association.name_key, {}).setdefault(association.identifier_key[0], {}).setdefault(
            association.identifier_key[1], []
        ).append((export_id, record))

    for identifier_key, name_types in by_identifier.items():
        for name_type, values in name_types.items():
            if len(values) <= 1:
                continue
            marker = ("identifier", identifier_key, name_type)
            if marker in seen:
                continue
            seen.add(marker)
            depends: list[str] = []
            exports: list[str] = []
            for items in values.values():
                for export_id, record in items:
                    depends.append(record.full_id)
                    exports.append(export_id)
            conflicts.append(
                {
                    "kind": "functional_name_conflict",
                    "identifier_type": identifier_key[0],
                    "identifier": identifier_key[1],
                    "name_type": name_type,
                    "values": sorted(values),
                    "exports": sorted(set(exports)),
                    "depends_on": sorted(set(depends)),
                    "summary": f"{identifier_key[0]}={identifier_key[1]!r} maps to multiple {name_type} values: "
                    + ", ".join(sorted(values))
                    + ".",
                }
            )

    for name_key, identifier_types in by_name.items():
        for identifier_type, values in identifier_types.items():
            if len(values) <= 1:
                continue
            marker = ("name", name_key, identifier_type)
            if marker in seen:
                continue
            seen.add(marker)
            depends = []
            exports = []
            for items in values.values():
                for export_id, record in items:
                    depends.append(record.full_id)
                    exports.append(export_id)
            conflicts.append(
                {
                    "kind": "functional_name_conflict",
                    "identifier_type": identifier_type,
                    "identifier": None,
                    "name_type": name_key[0],
                    "name": name_key[1],
                    "values": sorted(values),
                    "exports": sorted(set(exports)),
                    "depends_on": sorted(set(depends)),
                    "summary": f"{name_key[0]}={name_key[1]!r} maps to multiple {identifier_type} values: "
                    + ", ".join(sorted(values))
                    + ".",
                }
            )
    return conflicts


def _records_with_node(fact: dict[str, Any], node: tuple[str, str]) -> list[str]:
    result = []
    for record in fact["records"].values():
        if record.kind != "name_association":
            continue
        association = NameAssociation.from_dict(record.value)
        if association.is_primary() and node in (association.identifier_key, association.name_key):
            result.append(record.full_id)
    return result


def _records_with_type(fact: dict[str, Any], node_type: str) -> list[str]:
    result = []
    for record in fact["records"].values():
        if record.kind != "name_association":
            continue
        association = NameAssociation.from_dict(record.value)
        if not association.is_primary():
            continue
        if association.identifier_key[0] == node_type or association.name_key[0] == node_type:
            result.append(record.full_id)
    return result


def _origin_label(records: Sequence[IdentityRecord | None]) -> str:
    origins = {record.origin.value for record in records if record is not None}
    if not origins:
        return "caller"
    if len(origins) == 1:
        return next(iter(origins))
    return "mixed"


def _verification_failures(case: CorroborationCase) -> list[dict[str, Any]]:
    result = []
    for export in case.exports:
        for record in export.records:
            if record.kind != "name_association":
                continue
            association = NameAssociation.from_dict(record.value)
            if association.verified is False:
                result.append(
                    {
                        "kind": "name_verification_failure",
                        "export_id": export.export_id,
                        "record_id": record.record_id,
                        "depends_on": [record.full_id],
                        "summary": f"{export.export_id}:{record.record_id} claims "
                        f"{association.identifier_type}={association.identifier!r} -> "
                        f"{association.name_type}={association.name!r}, but the hive value "
                        f"{association.observed_value!r} does not match.",
                    }
                )
    return result


def _pair_assessment(
    first_id: str,
    second_id: str,
    facts: dict[str, dict[str, Any]],
    roots: dict[str, str],
    clone_pairs: set[tuple[str, str]],
    graph: dict[str, Any],
    anchors_by_export: dict[str, dict[str, IdentityRecord]],
    plugins_by_export: dict[str, dict[str, IdentityRecord]],
    functional_conflicts: Sequence[dict[str, Any]],
    verification_failures: Sequence[dict[str, Any]],
) -> tuple[dict[str, Any], list[AssociationFinding]]:
    first = facts[first_id]
    second = facts[second_id]
    independent = roots.get(first_id) != roots.get(second_id)
    clone_related = tuple(sorted((first_id, second_id))) in clone_pairs
    volume_comparison = _volume_comparison(first, second)
    shared_volume = volume_comparison["match"]
    volume_conflict = volume_comparison["status"] == "conflict"
    first_identity = _hive_identity_key(first)
    second_identity = _hive_identity_key(second)
    shared_hive_identity = bool(first_identity and first_identity == second_identity)

    reasons: list[str] = []
    depends: set[str] = set()
    associations: list[AssociationFinding] = []

    source_records = [first.get("source"), second.get("source")]
    for record in source_records:
        if record:
            depends.add(record.full_id)
    volume_records = [first.get("volume"), second.get("volume")]
    if volume_comparison["comparable"]:
        for record in volume_records:
            if record:
                depends.add(record.full_id)
    hive_records = [first.get("hive_identity"), second.get("hive_identity")]
    if shared_hive_identity:
        for record in hive_records:
            if record:
                depends.add(record.full_id)

    if roots.get(first_id) == roots.get(second_id):
        source_ids = [record.full_id for record in source_records if record]
        associations.append(
            AssociationFinding(
                association_id=f"link:source:{first_id}:{second_id}",
                kind="shared_lineage",
                status="valid" if len(source_ids) == 2 else "missing",
                exports=[first_id, second_id],
                origin=_origin_label(source_records),
                role="primary",
                depends_on=source_ids,
                summary="Exports share one acquisition lineage; repeated observations are not independent.",
                evidence={"lineage_root": roots.get(first_id)},
            )
        )

    if clone_related:
        declared = any(record and record.value.get("derived_from") for record in source_records)
        associations.append(
            AssociationFinding(
                association_id=f"link:clone:{first_id}:{second_id}",
                kind="clone_or_copy",
                status="valid",
                exports=[first_id, second_id],
                origin="caller" if declared else "content",
                role="primary",
                depends_on=[record.full_id for record in source_records if record],
                summary="Clone or copy lineage declared by sampling source or inferred from shared hive identity and anchors.",
                evidence={"declared": declared},
            )
        )

    if shared_volume:
        volume_verified = all(record.independently_verifiable for record in volume_records if record)
        associations.append(
            AssociationFinding(
                association_id=f"link:volume:{first_id}:{second_id}",
                kind="shared_volume_identity",
                status="valid" if volume_verified else "caller_asserted",
                exports=[first_id, second_id],
                origin=_origin_label(volume_records),
                role="primary",
                depends_on=[record.full_id for record in volume_records if record],
                summary="Exports report the same volume fingerprint. Volume identity groups artifacts; it does not prove a user.",
                evidence={"comparison": volume_comparison, "verified": volume_verified},
            )
        )

    if shared_hive_identity:
        associations.append(
            AssociationFinding(
                association_id=f"link:hive_identity:{first_id}:{second_id}",
                kind="shared_hive_identity",
                status="valid",
                exports=[first_id, second_id],
                origin="hive",
                role="primary",
                depends_on=[record.full_id for record in hive_records if record],
                summary="Exports share the registry-internal hive creation identity.",
                evidence={"identity": first_identity},
            )
        )

    anchors_first = anchors_by_export.get(first_id, {})
    anchors_second = anchors_by_export.get(second_id, {})
    common_paths = sorted(set(anchors_first) & set(anchors_second))
    identical_anchors: list[str] = []
    same_timestamp_different_digest: list[str] = []
    timestamp_drift: list[str] = []
    for path in common_paths:
        first_anchor = anchors_first[path]
        second_anchor = anchors_second[path]
        first_value = first_anchor.value
        second_value = second_anchor.value
        if first_value.get("timestamp") != second_value.get("timestamp"):
            timestamp_drift.append(path)
            continue
        if first_value.get("value_digest") == second_value.get("value_digest"):
            identical_anchors.append(path)
            depends.add(first_anchor.full_id)
            depends.add(second_anchor.full_id)
            associations.append(
                AssociationFinding(
                    association_id=f"link:anchor:{first_id}:{second_id}:{_slug(path)}",
                    kind="content_anchor_match",
                    status="valid",
                    exports=[first_id, second_id],
                    origin="hive",
                    role="primary",
                    depends_on=[first_anchor.full_id, second_anchor.full_id],
                    summary="Identical key path and timestamp with identical value digest. This is content identity, not subject identity.",
                    evidence={
                        "path": path,
                        "timestamp": first_value.get("timestamp"),
                        "value_digest": first_value.get("value_digest"),
                        "clone_related": clone_related,
                    },
                )
            )
        else:
            same_timestamp_different_digest.append(path)
            depends.add(first_anchor.full_id)
            depends.add(second_anchor.full_id)
            associations.append(
                AssociationFinding(
                    association_id=f"conflict:anchor:{first_id}:{second_id}:{_slug(path)}",
                    kind="content_anchor_conflict",
                    status="conflict",
                    exports=[first_id, second_id],
                    origin="hive",
                    role="primary",
                    depends_on=[first_anchor.full_id, second_anchor.full_id],
                    summary="Same key path and timestamp but different value digest; the exports are not content-identical.",
                    evidence={
                        "path": path,
                        "timestamp": first_value.get("timestamp"),
                        "digest_first": first_value.get("value_digest"),
                        "digest_second": second_value.get("value_digest"),
                    },
                )
            )

    nodes_first = graph["export_nodes"].get(first_id, set())
    nodes_second = graph["export_nodes"].get(second_id, set())
    types_first = graph["export_types"].get(first_id, set())
    types_second = graph["export_types"].get(second_id, set())
    shared_nodes = sorted(nodes_first & nodes_second)
    shared_types = sorted(types_first & types_second)
    different_values: dict[str, Any] = {}
    for node_type in shared_types:
        values_first = sorted({value for value_type, value in nodes_first if value_type == node_type})
        values_second = sorted({value for value_type, value in nodes_second if value_type == node_type})
        if set(values_first).isdisjoint(values_second):
            different_values[node_type] = {"first": values_first, "second": values_second}

    for node in shared_nodes:
        node_type, node_value = node
        node_records = sorted(set(_records_with_node(first, node) + _records_with_node(second, node)))
        depends.update(node_records)
        record_objects = [
            record
            for record in list(first["records"].values()) + list(second["records"].values())
            if record.full_id in node_records
        ]
        node_slug = _slug(node_type + chr(45) + node_value)
        associations.append(
            AssociationFinding(
                association_id=f"link:name:{first_id}:{second_id}:{node_slug}",
                kind="shared_name_node",
                status="valid",
                exports=[first_id, second_id],
                origin=_origin_label(record_objects),
                role="primary",
                depends_on=node_records,
                summary=f"Both exports independently resolve {node_type}={node_value!r}.",
                evidence={"node_type": node_type, "node_value": node_value, "clone_related": clone_related},
            )
        )

    for node_type, values in different_values.items():
        node_records = sorted(set(_records_with_type(first, node_type) + _records_with_type(second, node_type)))
        depends.update(node_records)
        record_objects = [
            record
            for record in list(first["records"].values()) + list(second["records"].values())
            if record.full_id in node_records
        ]
        first_values = values["first"]
        second_values = values["second"]
        associations.append(
            AssociationFinding(
                association_id=f"conflict:name:{first_id}:{second_id}:{node_type}",
                kind="name_value_conflict",
                status="conflict",
                exports=[first_id, second_id],
                origin=_origin_label(record_objects),
                role="primary",
                depends_on=node_records,
                summary=f"Exports resolve {node_type} to different values: {first_values} vs {second_values}.",
                evidence={"node_type": node_type, "values": values},
            )
        )

    plugins_first = plugins_by_export.get(first_id, {})
    plugins_second = plugins_by_export.get(second_id, {})
    plugin_matches = []
    plugin_divergences = []
    for plugin_name in sorted(set(plugins_first) & set(plugins_second)):
        first_plugin = plugins_first[plugin_name]
        second_plugin = plugins_second[plugin_name]
        first_digest = first_plugin.value.get("digest")
        second_digest = second_plugin.value.get("digest")
        depends.add(first_plugin.full_id)
        depends.add(second_plugin.full_id)
        if first_digest and first_digest == second_digest:
            plugin_matches.append(plugin_name)
            associations.append(
                AssociationFinding(
                    association_id=f"link:plugin:{first_id}:{second_id}:{_slug(plugin_name)}",
                    kind="plugin_corroboration",
                    status="supplemental",
                    exports=[first_id, second_id],
                    origin="plugin",
                    role="supplemental",
                    depends_on=[first_plugin.full_id, second_plugin.full_id],
                    summary=f"Plugin {plugin_name} output digest matches. Supplemental only; it cannot establish identity.",
                    evidence={"plugin": plugin_name, "digest": first_digest},
                )
            )
        elif first_digest or second_digest:
            plugin_divergences.append(plugin_name)
            associations.append(
                AssociationFinding(
                    association_id=f"divergence:plugin:{first_id}:{second_id}:{_slug(plugin_name)}",
                    kind="plugin_divergence",
                    status="supplemental",
                    exports=[first_id, second_id],
                    origin="plugin",
                    role="supplemental",
                    depends_on=[first_plugin.full_id, second_plugin.full_id],
                    summary=f"Plugin {plugin_name} output differs. This is supplemental activity evidence, not an identity source.",
                    evidence={
                        "plugin": plugin_name,
                        "digest_first": first_digest,
                        "digest_second": second_digest,
                    },
                )
            )

    relevant_functional = [
        conflict
        for conflict in functional_conflicts
        if first_id in conflict.get("exports", []) or second_id in conflict.get("exports", [])
    ]
    relevant_failures = [failure for failure in verification_failures if failure.get("export_id") in (first_id, second_id)]

    if same_timestamp_different_digest:
        verdict = Verdict.CONFLICT
        reasons.append(
            "Same key path and timestamp but different value digest at: " + ", ".join(same_timestamp_different_digest[:3]) + "."
        )
    elif volume_conflict:
        verdict = Verdict.CONFLICT
        conflicts_text = []
        for item in volume_comparison["conflicts"]:
            item_field = item["field"]
            item_first = item["first"]
            item_second = item["second"]
            conflicts_text.append(f"{item_field}={item_first} vs {item_second}")
        reasons.append("Volume identity fields conflict: " + "; ".join(conflicts_text) + ".")
    elif relevant_failures:
        verdict = Verdict.CONFLICT
        reasons.append("At least one name association failed verification against its cited hive value.")
    elif relevant_functional:
        verdict = Verdict.CONFLICT
        reasons.append("A functional identity constraint is violated by the combined associations.")
    elif different_values:
        verdict = Verdict.CONFLICT
        disagreement_text = []
        for key, value in different_values.items():
            first_value = value["first"]
            second_value = value["second"]
            disagreement_text.append(f"{key}={first_value} vs {second_value}")
        reasons.append("Exports disagree on comparable identity values: " + "; ".join(disagreement_text) + ".")
    elif not nodes_first or not nodes_second:
        verdict = Verdict.MISSING_EVIDENCE
        reasons.append("At least one export has no independently verifiable name association.")
    elif shared_nodes:
        if not independent:
            verdict = Verdict.MISSING_EVIDENCE
            reasons.append(
                "Exports share one acquisition or clone lineage; identical content cannot count as independent corroboration."
            )
        else:
            verdict = Verdict.SAME_SUBJECT
            reasons.append("Independent exports resolve shared name nodes to the same values.")
    elif shared_types:
        verdict = Verdict.MISSING_EVIDENCE
        reasons.append("The exports share identifier types but no shared value links them.")
    else:
        verdict = Verdict.MISSING_EVIDENCE
        reasons.append("No comparable name identifier type links the exports.")

    if plugin_matches:
        reasons.append("Matching plugin output is supplemental only and was not used to establish identity.")

    priority_anchor_paths = [
        SHELL_FOLDERS_PATH,
        r"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    ]
    ordered_identical_anchors = [path for path in priority_anchor_paths if path in identical_anchors]
    ordered_identical_anchors.extend(path for path in identical_anchors if path not in priority_anchor_paths)

    pair = {
        "pair_id": f"{first_id}|{second_id}",
        "exports": [first_id, second_id],
        "verdict": verdict.value,
        "reasons": reasons,
        "independent": independent,
        "clone_related": clone_related,
        "shared_lineage": roots.get(first_id) == roots.get(second_id),
        "lineage_roots": [roots.get(first_id), roots.get(second_id)],
        "shared_volume": shared_volume,
        "volume_conflict": volume_conflict,
        "volume_comparison": volume_comparison,
        "volume_status": (
            "caller_asserted"
            if shared_volume and not all(r.independently_verifiable for r in volume_records if r)
            else "valid"
            if shared_volume
            else volume_comparison["status"]
        ),
        "shared_hive_identity": shared_hive_identity,
        "identical_anchor_count": len(identical_anchors),
        "comparable_anchor_count": len(common_paths),
        "identical_anchor_ratio": round(len(identical_anchors) / len(common_paths), 4) if common_paths else 0.0,
        "identical_anchor_examples": [
            {
                "path": path,
                "timestamp": anchors_first[path].value.get("timestamp"),
            }
            for path in ordered_identical_anchors[:5]
        ],
        "content_conflicts": same_timestamp_different_digest,
        "content_drift": timestamp_drift,
        "shared_name_nodes": [{"type": node_type, "value": node_value} for node_type, node_value in shared_nodes],
        "comparable_name_types": shared_types,
        "different_name_values": different_values,
        "plugin_matches": plugin_matches,
        "plugin_divergences": plugin_divergences,
        "depends_on": sorted(depends),
    }
    return pair, associations


def _export_components(graph: dict[str, Any]) -> dict[str, set[Any]]:
    result: dict[str, set[Any]] = {}
    for export_id, nodes in graph["export_nodes"].items():
        result[export_id] = {graph["disjoint"].find(node) for node in nodes}
    return result


def _overall_verdict(
    targets: Sequence[str],
    pairs: Sequence[dict[str, Any]],
    functional_conflicts: Sequence[dict[str, Any]],
    verification_failures: Sequence[dict[str, Any]],
    components: dict[str, set[Any]],
    facts: dict[str, dict[str, Any]],
) -> tuple[Verdict, list[str]]:
    target_set = set(targets)
    relevant_functional = [conflict for conflict in functional_conflicts if target_set & set(conflict.get("exports", []))]
    relevant_failures = [failure for failure in verification_failures if failure.get("export_id") in target_set]

    if any(pair["verdict"] == Verdict.CONFLICT.value for pair in pairs):
        return Verdict.CONFLICT, ["At least one export pair is in direct conflict."]
    if relevant_functional:
        return Verdict.CONFLICT, ["A functional identity constraint is violated across the case."]
    if relevant_failures:
        return Verdict.CONFLICT, ["At least one name association failed verification against its hive value."]
    if len(targets) < 2:
        return Verdict.MISSING_EVIDENCE, [
            "At least two target exports are required before a same-subject verdict can be considered."
        ]

    support_gaps = []
    for target in targets:
        fact = facts.get(target)
        if not fact:
            support_gaps.append(f"{target}: no export record")
            continue
        export = fact["export"]
        if not fact.get("source") and not export.metadata.get("source_not_applicable"):
            support_gaps.append(f"{target}: no sampling source")
        if not fact.get("volume") and not export.metadata.get("volume_not_applicable"):
            support_gaps.append(f"{target}: no volume identity")
        primary_count = sum(
            1
            for record in fact["records"].values()
            if record.kind == "name_association" and NameAssociation.from_dict(record.value).is_primary()
        )
        if primary_count == 0:
            support_gaps.append(f"{target}: no independently verifiable name association")
    if support_gaps:
        return Verdict.MISSING_EVIDENCE, ["Required identity inputs are missing: " + "; ".join(support_gaps) + "."]

    common_components: set[Any] | None = None
    for target in targets:
        current = components.get(target, set())
        common_components = current if common_components is None else common_components & current
        if not common_components:
            break

    independent_same = any(pair["verdict"] == Verdict.SAME_SUBJECT.value and pair["independent"] for pair in pairs)
    if common_components and independent_same:
        return Verdict.SAME_SUBJECT, ["At least two independent export lineages resolve the same subject name nodes."]
    return Verdict.MISSING_EVIDENCE, [
        "The available evidence does not contain independent, verifiable name links for every target export."
    ]


def _global_associations(
    case: CorroborationCase,
    facts: dict[str, dict[str, Any]],
    functional_conflicts: Sequence[dict[str, Any]],
    verification_failures: Sequence[dict[str, Any]],
    targets: Sequence[str],
    lineage_notes: Sequence[str],
) -> list[AssociationFinding]:
    result: list[AssociationFinding] = []
    target_set = set(targets)

    for conflict in functional_conflicts:
        if not target_set & set(conflict.get("exports", [])):
            continue
        evidence = {key: value for key, value in conflict.items() if key not in {"summary", "depends_on", "exports", "kind"}}
        result.append(
            AssociationFinding(
                association_id="conflict:functional:" + _slug(conflict.get("summary", "")),
                kind=str(conflict.get("kind", "functional_conflict")),
                status="conflict",
                exports=list(conflict.get("exports", [])),
                origin="mixed",
                role="primary",
                depends_on=list(conflict.get("depends_on", [])),
                summary=str(conflict.get("summary", "Functional identity conflict.")),
                evidence=evidence,
            )
        )

    for failure in verification_failures:
        if failure.get("export_id") not in target_set:
            continue
        failure_export = failure["export_id"]
        failure_record = failure["record_id"]
        result.append(
            AssociationFinding(
                association_id=f"conflict:verification:{failure_export}:{_slug(failure_record)}",
                kind="name_verification_failure",
                status="conflict",
                exports=[failure["export_id"]],
                origin="caller",
                role="primary",
                depends_on=list(failure.get("depends_on", [])),
                summary=str(failure["summary"]),
                evidence={"record_id": failure["record_id"]},
            )
        )

    for target in targets:
        fact = facts.get(target)
        if not fact:
            result.append(
                AssociationFinding(
                    association_id=f"missing:export:{target}",
                    kind="missing_export",
                    status="missing",
                    exports=[target],
                    origin="caller",
                    role="primary",
                    depends_on=[],
                    summary=f"{target} was named as a target but no export record exists.",
                    evidence={},
                )
            )
            continue

        primary_count = sum(
            1
            for record in fact["records"].values()
            if record.kind == "name_association" and NameAssociation.from_dict(record.value).is_primary()
        )
        if primary_count == 0:
            result.append(
                AssociationFinding(
                    association_id=f"missing:name:{target}",
                    kind="missing_name_association",
                    status="missing",
                    exports=[target],
                    origin="caller",
                    role="primary",
                    depends_on=[],
                    summary=f"{target} has no independently verifiable name association. Plugin output cannot fill this gap.",
                    evidence={},
                )
            )
        export = fact["export"]
        if not fact.get("source") and not export.metadata.get("source_not_applicable"):
            result.append(
                AssociationFinding(
                    association_id=f"missing:source:{target}",
                    kind="missing_sampling_source",
                    status="missing",
                    exports=[target],
                    origin="caller",
                    role="primary",
                    depends_on=[],
                    summary=f"{target} has no caller-registered sampling source; independence cannot be established.",
                    evidence={},
                )
            )
        if not fact.get("volume") and not export.metadata.get("volume_not_applicable"):
            result.append(
                AssociationFinding(
                    association_id=f"missing:volume:{target}",
                    kind="missing_volume_identity",
                    status="missing",
                    exports=[target],
                    origin="caller",
                    role="primary",
                    depends_on=[],
                    summary=f"{target} has no caller-registered volume identity.",
                    evidence={},
                )
            )
        if not fact.get("hive_identity") and not fact.get("hive_header") and not export.metadata.get("hive_not_applicable"):
            result.append(
                AssociationFinding(
                    association_id=f"missing:hive:{target}",
                    kind="missing_hive_observation",
                    status="missing",
                    exports=[target],
                    origin="caller",
                    role="primary",
                    depends_on=[],
                    summary=f"{target} has no parsed hive observation; regipy could not verify its identity evidence.",
                    evidence={},
                )
            )

        for record in fact["records"].values():
            if record.kind == "plugin_observation":
                plugin_name = str(record.value.get("plugin_name", "plugin"))
                result.append(
                    AssociationFinding(
                        association_id=f"plugin:supplemental:{target}:{_slug(plugin_name)}",
                        kind="plugin_supplemental",
                        status="supplemental",
                        exports=[target],
                        origin="plugin",
                        role="supplemental",
                        depends_on=[record.full_id],
                        summary="Plugin-derived value retained as supplemental evidence only; it is not an original source.",
                        evidence={
                            "plugin_name": plugin_name,
                            "digest": record.value.get("digest"),
                            "error": record.value.get("error"),
                        },
                    )
                )

    for note in lineage_notes:
        result.append(
            AssociationFinding(
                association_id="missing:lineage:" + _slug(note),
                kind="lineage_note",
                status="missing",
                exports=[],
                origin="caller",
                role="primary",
                depends_on=[],
                summary=note,
                evidence={},
            )
        )
    return result


def _merge_associations(associations: Sequence[AssociationFinding]) -> list[AssociationFinding]:
    rank = {"conflict": 5, "missing": 4, "valid": 3, "caller_asserted": 3, "supplemental": 2}
    merged: dict[str, AssociationFinding] = {}
    for association in associations:
        existing = merged.get(association.association_id)
        if existing is None:
            merged[association.association_id] = association
            continue
        combined_depends = sorted(set(existing.depends_on) | set(association.depends_on))
        combined_evidence = {**existing.evidence, **association.evidence}
        if rank.get(association.status, 0) > rank.get(existing.status, 0):
            association.depends_on = combined_depends
            association.evidence = combined_evidence
            merged[association.association_id] = association
        else:
            existing.depends_on = combined_depends
            existing.evidence = combined_evidence
    return [merged[key] for key in sorted(merged)]


def _build_exports(
    case: CorroborationCase,
    facts: dict[str, dict[str, Any]],
    roots: dict[str, str],
    clone_pairs: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    lineage_count = len(set(roots.values()))
    result = []
    for export in case.exports:
        fact = facts[export.export_id]
        name_records = [record for record in export.records if record.kind == "name_association"]
        primary_count = sum(1 for record in name_records if NameAssociation.from_dict(record.value).is_primary())
        verified_count = sum(1 for record in name_records if NameAssociation.from_dict(record.value).verified is True)
        hive_header = fact.get("hive_header")
        result.append(
            {
                "export_id": export.export_id,
                "hive_path": export.hive_path,
                "hive_type": export.hive_type or (hive_header.value.get("hive_type") if hive_header else None),
                "materialize_error": export.materialize_error,
                "source": fact["source"].value if fact.get("source") else None,
                "volume": fact["volume"].value if fact.get("volume") else None,
                "volume_fingerprint": _volume_fingerprint(fact),
                "hive_identity": fact["hive_identity"].value if fact.get("hive_identity") else None,
                "hive_header": hive_header.value if hive_header else None,
                "lineage_root": roots.get(export.export_id),
                "independent_lineage_count": lineage_count,
                "name_association_counts": {
                    "primary": primary_count,
                    "supplemental": len(name_records) - primary_count,
                    "verified": verified_count,
                },
                "content_anchor_count": sum(1 for record in export.records if record.kind == "content_anchor"),
                "plugin_observation_count": sum(1 for record in export.records if record.kind == "plugin_observation"),
                "is_clone_of": sorted(
                    other for pair in clone_pairs for other in pair if export.export_id in pair and other != export.export_id
                ),
            }
        )
    return result


def _dedupe_entries(entries: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for entry in entries:
        key = _canonical_json(entry)
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
    return result


def _build_missing_evidence(
    pairs: Sequence[dict[str, Any]],
    associations: Sequence[AssociationFinding],
) -> list[dict[str, Any]]:
    result = []
    for pair in pairs:
        if pair["verdict"] == Verdict.MISSING_EVIDENCE.value:
            result.append(
                {
                    "kind": "pairwise_missing_evidence",
                    "exports": pair["exports"],
                    "reasons": pair["reasons"],
                }
            )
    for association in associations:
        if association.status == "missing":
            result.append(
                {
                    "kind": "association_missing",
                    "association_id": association.association_id,
                    "exports": association.exports,
                    "summary": association.summary,
                }
            )
    return _dedupe_entries(result)


def _build_conflicts(
    pairs: Sequence[dict[str, Any]],
    associations: Sequence[AssociationFinding],
) -> list[dict[str, Any]]:
    result = []
    for pair in pairs:
        if pair["verdict"] == Verdict.CONFLICT.value:
            result.append(
                {
                    "kind": "pairwise_conflict",
                    "exports": pair["exports"],
                    "reasons": pair["reasons"],
                }
            )
    for association in associations:
        if association.status == "conflict":
            result.append(
                {
                    "kind": association.kind,
                    "association_id": association.association_id,
                    "exports": association.exports,
                    "summary": association.summary,
                    "depends_on": association.depends_on,
                }
            )
    return _dedupe_entries(result)


def _build_anchors(case: CorroborationCase) -> list[dict[str, Any]]:
    by_path: dict[str, list[dict[str, Any]]] = {}
    for export in case.exports:
        for record in export.records:
            if record.kind != "content_anchor":
                continue
            path = str(record.value.get("path", ""))
            by_path.setdefault(path, []).append(
                {
                    "export_id": export.export_id,
                    "timestamp": record.value.get("timestamp"),
                    "value_digest": record.value.get("value_digest"),
                    "values_count": record.value.get("values_count"),
                }
            )
    return [
        {
            "path": path,
            "observations": sorted(by_path[path], key=lambda item: item["export_id"]),
        }
        for path in sorted(by_path)
    ]


def _build_plugin_evidence(case: CorroborationCase) -> list[dict[str, Any]]:
    result = []
    for export in case.exports:
        for record in export.records:
            if record.kind != "plugin_observation":
                continue
            result.append(
                {
                    "export_id": export.export_id,
                    "plugin_name": record.value.get("plugin_name"),
                    "origin": "plugin",
                    "role": "supplemental",
                    "used_as_source": False,
                    "can_establish_identity": False,
                    "digest": record.value.get("digest"),
                    "entry_count": record.value.get("entry_count"),
                    "last_write": record.value.get("last_write"),
                    "error": record.value.get("error"),
                    "sample": record.value.get("sample"),
                }
            )
    return sorted(result, key=lambda item: (item["export_id"], str(item["plugin_name"])))


def _build_provenance() -> dict[str, Any]:
    return {
        "plugin_values_are_supplemental": True,
        "plugin_values_used_as_original_source": False,
        "plugin_values_can_establish_identity": False,
        "caller_metadata_is_asserted_not_forensically_verified": True,
        "content_anchor_identity_is_not_subject_identity": True,
        "clone_content_is_not_independent_corroboration": True,
        "independence_rule": "Exports sharing a declared derivative chain, an image hash or an acquisition id are treated as one lineage.",
        "verification_rule": "A caller name association becomes primary only when it is independently verifiable and verified against the cited hive value.",
    }


def _build_rationale(
    verdict: Verdict,
    pairs: Sequence[dict[str, Any]],
    clone_pairs: set[tuple[str, str]],
    functional_conflicts: Sequence[dict[str, Any]],
    plugin_count: int,
) -> list[str]:
    result = []
    if verdict is Verdict.SAME_SUBJECT:
        result.append("No identity or integrity conflict was found.")
    elif verdict is Verdict.CONFLICT:
        result.append("The same-subject claim is contradicted by conflicting identity or content evidence.")
    else:
        result.append("The evidence is insufficient for an independent same-subject finding.")

    for pair in pairs:
        pair_exports = pair["exports"]
        pair_verdict = pair["verdict"]
        pair_reasons = pair["reasons"]
        result.append(f"{pair_exports[0]} vs {pair_exports[1]}: {pair_verdict} - " + " ".join(pair_reasons))
    if clone_pairs:
        result.append(
            "Clone or copy lineage was detected; identical keys and timestamps from cloned content were not counted as independent corroboration."
        )
    if functional_conflicts:
        result.append("At least one identifier maps to more than one name, which violates a functional identity constraint.")
    if plugin_count:
        result.append(
            "Plugin-derived values were retained as supplemental evidence and were not promoted to an original source."
        )
    return result


def _evaluate(case: CorroborationCase) -> ReviewResult:
    facts = _facts(case)
    anchors_by_export = _anchors_by_export(case)
    plugins_by_export = _plugins_by_export(case)
    roots, clone_pairs, clone_suspected, lineage_notes = _compute_lineage(case, facts, anchors_by_export)
    graph = _build_subject_graph(_name_edges(case))
    functional_conflicts = _functional_conflicts(graph["primary"])
    verification_failures = _verification_failures(case)
    targets = list(case.targets())
    known_targets = [target for target in targets if target in facts]

    pairs: list[dict[str, Any]] = []
    pair_associations: list[AssociationFinding] = []
    for index, first_id in enumerate(known_targets):
        for second_id in known_targets[index + 1 :]:
            pair, associations = _pair_assessment(
                first_id,
                second_id,
                facts,
                roots,
                clone_pairs,
                graph,
                anchors_by_export,
                plugins_by_export,
                functional_conflicts,
                verification_failures,
            )
            pairs.append(pair)
            pair_associations.extend(associations)

    components = _export_components(graph)
    verdict, verdict_reasons = _overall_verdict(
        targets,
        pairs,
        functional_conflicts,
        verification_failures,
        components,
        facts,
    )
    associations = _merge_associations(
        pair_associations
        + _global_associations(
            case,
            facts,
            functional_conflicts,
            verification_failures,
            targets,
            lineage_notes,
        )
    )
    plugin_count = sum(1 for export in case.exports for record in export.records if record.kind == "plugin_observation")
    rationale = verdict_reasons + _build_rationale(
        verdict,
        pairs,
        clone_pairs,
        functional_conflicts,
        plugin_count,
    )
    if clone_suspected and not any("clone" in reason.lower() for reason in rationale):
        rationale.append("Content-based clone suspicion was applied conservatively.")

    return ReviewResult(
        case_id=case.case_id,
        verdict=verdict,
        claim=case.claim,
        rationale=rationale,
        exports=_build_exports(case, facts, roots, clone_pairs),
        pairwise=pairs,
        associations=associations,
        conflicts=_build_conflicts(pairs, associations),
        missing_evidence=_build_missing_evidence(pairs, associations),
        anchors=_build_anchors(case),
        plugin_evidence=_build_plugin_evidence(case),
        provenance=_build_provenance(),
        generated_at=str(case.metadata.get("generated_at") or _utc_now_iso()),
        classification=case.classification,
        notes=case.notes,
    )


def corroborate(case: CorroborationCase) -> ReviewResult:
    """Materialise the case with regipy and return the internal review."""

    case.materialize()
    return _evaluate(case)


def replace_identity_record(
    case: CorroborationCase,
    export_id: str,
    record_id: str,
    replacement: Any,
    note: str | None = None,
) -> ReviewResult:
    """Replace one identity record and report which associations stop holding.

    The record is addressed by local id (for example ``volume``, ``source`` or
    ``name:0``) or by full id (for example ``EXP-B:volume``).  Dictionary
    replacements are merged into the existing record value, so a partial
    replacement such as ``{"volume_serial": "OTHER"}`` is valid.
    """

    baseline_case = copy.deepcopy(case)
    baseline_case.materialize()
    baseline = _evaluate(baseline_case)

    mutated_case = copy.deepcopy(baseline_case)
    export = mutated_case.export_map().get(export_id)
    if export is None:
        raise KeyError(f"Unknown export: {export_id}")

    target: IdentityRecord | None = None
    for record in export.records:
        if record.record_id == record_id or record.full_id == record_id:
            target = record
            break
    if target is None:
        raise KeyError(f"Unknown identity record {record_id!r} on export {export_id!r}")

    old_value = copy.deepcopy(target.value)
    if isinstance(replacement, Mapping):
        new_value = {**target.value, **dict(replacement)}
    else:
        new_value = {"value": replacement}
    target.value = new_value

    if target.kind == "sampling_source":
        export.sampling_source = SamplingSource.from_dict(new_value)
    elif target.kind == "volume_identity":
        volume = VolumeIdentity.from_dict(new_value)
        new_value["fingerprint"] = volume.fingerprint()
        target.value = new_value
        export.volume_identity = volume
    elif target.kind == "name_association":
        association = NameAssociation.from_dict(new_value)
        target.role = EvidenceRole.PRIMARY if association.is_primary() else EvidenceRole.SUPPLEMENTAL
        target.independently_verifiable = association.independently_verifiable

    mutated = _evaluate(mutated_case)
    active_statuses = {"valid", "caller_asserted", "supplemental"}
    baseline_associations = {item.association_id: item for item in baseline.associations}
    mutated_associations = {item.association_id: item for item in mutated.associations}
    baseline_active = {key for key, item in baseline_associations.items() if item.status in active_statuses}
    mutated_active = {key for key, item in mutated_associations.items() if item.status in active_statuses}

    invalidated = [baseline_associations[key] for key in sorted(baseline_active - mutated_active)]
    surviving = [baseline_associations[key] for key in sorted(baseline_active & mutated_active)]
    added = [mutated_associations[key] for key in sorted(mutated_active - baseline_active)]
    resolved = [
        item
        for key, item in baseline_associations.items()
        if item.status == "conflict" and (key not in mutated_associations or mutated_associations[key].status != "conflict")
    ]

    pairwise_changes = []
    mutated_pairs = {pair["pair_id"]: pair for pair in mutated.pairwise}
    for before in baseline.pairwise:
        after = mutated_pairs.get(before["pair_id"])
        if after is None:
            continue
        if before["verdict"] != after["verdict"] or before["independent"] != after["independent"]:
            pairwise_changes.append(
                {
                    "pair_id": before["pair_id"],
                    "verdict_before": before["verdict"],
                    "verdict_after": after["verdict"],
                    "independent_before": before["independent"],
                    "independent_after": after["independent"],
                }
            )

    mutated.replacement = {
        "export_id": export_id,
        "record_id": target.record_id,
        "full_id": target.full_id,
        "kind": target.kind,
        "old_value": old_value,
        "new_value": new_value,
        "note": note,
        "verdict_before": baseline.verdict.value,
        "verdict_after": mutated.verdict.value,
        "invalidated_associations": [item.to_dict() for item in invalidated],
        "surviving_associations": [item.to_dict() for item in surviving],
        "added_associations": [item.to_dict() for item in added],
        "resolved_conflicts": [item.to_dict() for item in resolved],
        "invalidated_association_ids": [item.association_id for item in invalidated],
        "surviving_association_ids": [item.association_id for item in surviving],
        "pairwise_changes": pairwise_changes,
    }
    return mutated


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _md_cell(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\n", " ")


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_md_cell(cell) for cell in row) + " |")
    return "\n".join(lines)


def _short_digest(value: Any) -> str:
    text = str(value or "")
    return text[:12] + "..." if len(text) > 12 else text


def _render_markdown(result: ReviewResult) -> str:
    data = result.to_dict()
    case_id = data["case_id"]
    verdict_value = data["verdict"]
    generated_at = data["generated_at"]
    claim_text = data.get("claim")
    lines: list[str] = []
    lines.append(f"# Internal Registry Corroboration Review - {case_id}")
    lines.append("")
    lines.append("**Classification:** internal review only. Not a court exhibit.")
    lines.append("")
    lines.append(f"**Verdict:** `{verdict_value}`")
    lines.append("")
    lines.append(f"**Generated:** {generated_at}")
    lines.append("")
    if claim_text:
        lines.append(f"**Claim under review:** {claim_text}")
        lines.append("")
    lines.append("## Rationale")
    lines.append("")
    for reason in data["rationale"]:
        lines.append(f"- {reason}")
    lines.append("")

    lines.append("## Exports")
    lines.append("")
    export_rows = []
    for export in data["exports"]:
        source = export.get("source") or {}
        counts = export.get("name_association_counts") or {}
        export_rows.append(
            [
                export["export_id"],
                export.get("hive_type"),
                source.get("source_id"),
                source.get("derived_from") or "",
                _short_digest(export.get("volume_fingerprint")),
                export.get("lineage_root"),
                counts.get("primary"),
                counts.get("supplemental"),
                export.get("content_anchor_count"),
                export.get("plugin_observation_count"),
                ", ".join(export.get("is_clone_of") or []),
                export.get("materialize_error") or "",
            ]
        )
    lines.append(
        _md_table(
            [
                "export",
                "type",
                "source",
                "derived_from",
                "volume fingerprint",
                "lineage",
                "primary names",
                "suppl. names",
                "anchors",
                "plugins",
                "clone of",
                "error",
            ],
            export_rows,
        )
    )
    lines.append("")

    lines.append("## Pairwise assessment")
    lines.append("")
    pair_rows = []
    for pair in data["pairwise"]:
        identical_anchor_count = pair["identical_anchor_count"]
        comparable_anchor_count = pair["comparable_anchor_count"]
        pair_rows.append(
            [
                pair["pair_id"],
                pair["verdict"],
                pair["independent"],
                pair["clone_related"],
                pair["shared_volume"],
                pair["shared_hive_identity"],
                f"{identical_anchor_count}/{comparable_anchor_count}",
                " ".join(pair["reasons"]),
            ]
        )
    lines.append(
        _md_table(
            [
                "pair",
                "verdict",
                "independent",
                "clone",
                "same volume",
                "same hive id",
                "identical anchors",
                "reasons",
            ],
            pair_rows,
        )
    )
    lines.append("")

    anchor_example_lines = []
    for pair in data["pairwise"]:
        pair_id = pair["pair_id"]
        for example in pair["identical_anchor_examples"]:
            example_path = example["path"]
            example_timestamp = example["timestamp"]
            anchor_example_lines.append(f"- `{pair_id}`: `{example_path}` at `{example_timestamp}`")
    if anchor_example_lines:
        lines.append("### Coincident content anchors")
        lines.append("")
        lines.extend(anchor_example_lines)
        lines.append("")
        lines.append(
            "These are content identity observations only. For clone-related pairs they are expected and are not independent subject evidence."
        )
        lines.append("")

    if data["conflicts"]:
        lines.append("## Conflicts")
        lines.append("")
        for conflict in data["conflicts"]:
            conflict_kind = conflict.get("kind")
            lines.append(f"- **{conflict_kind}**: " + str(conflict.get("summary") or conflict.get("reasons")))
        lines.append("")

    if data["missing_evidence"]:
        lines.append("## Missing evidence")
        lines.append("")
        for item in data["missing_evidence"]:
            item_kind = item.get("kind")
            lines.append(f"- **{item_kind}**: " + str(item.get("summary") or item.get("reasons")))
        lines.append("")

    lines.append("## Content anchors")
    lines.append("")
    anchor_rows = []
    for anchor in data["anchors"]:
        observations = anchor["observations"]
        anchor_rows.append(
            [
                anchor["path"],
                ", ".join(item["export_id"] for item in observations),
                ", ".join(str(item.get("timestamp")) for item in observations[:3]),
                ", ".join(_short_digest(item.get("value_digest")) for item in observations[:3]),
            ]
        )
    if anchor_rows:
        lines.append(_md_table(["key path", "exports", "timestamps", "digests"], anchor_rows))
    else:
        lines.append("No content anchors were observed.")
    lines.append("")

    lines.append("## Association ledger")
    lines.append("")
    association_rows = []
    for association in data["associations"]:
        association_rows.append(
            [
                association["association_id"],
                association["kind"],
                association["status"],
                ", ".join(association["exports"]),
                association["origin"],
                association["role"],
                len(association["depends_on"]),
                association["summary"],
            ]
        )
    lines.append(
        _md_table(
            ["association", "kind", "status", "exports", "origin", "role", "deps", "summary"],
            association_rows,
        )
    )
    lines.append("")

    lines.append("## Plugin evidence (supplemental only)")
    lines.append("")
    plugin_rows = []
    for plugin in data["plugin_evidence"]:
        plugin_rows.append(
            [
                plugin["export_id"],
                plugin["plugin_name"],
                plugin["origin"],
                plugin["role"],
                plugin["used_as_source"],
                plugin["can_establish_identity"],
                _short_digest(plugin.get("digest")),
                plugin.get("error") or "",
            ]
        )
    if plugin_rows:
        lines.append(
            _md_table(
                [
                    "export",
                    "plugin",
                    "origin",
                    "role",
                    "used as source",
                    "can establish identity",
                    "digest",
                    "error",
                ],
                plugin_rows,
            )
        )
    else:
        lines.append("No plugin observations were collected.")
    lines.append("")

    replacement = data.get("replacement")
    if replacement:
        replacement_full_id = replacement["full_id"]
        replacement_kind = replacement["kind"]
        replacement_old_value = replacement["old_value"]
        replacement_new_value = replacement["new_value"]
        replacement_verdict_before = replacement["verdict_before"]
        replacement_verdict_after = replacement["verdict_after"]
        replacement_note = replacement.get("note")
        lines.append("## Record replacement and invalidation")
        lines.append("")
        lines.append(f"- Replaced record: `{replacement_full_id}` ({replacement_kind})")
        lines.append(f"- Old value: `{json.dumps(replacement_old_value, default=_json_default)}`")
        lines.append(f"- New value: `{json.dumps(replacement_new_value, default=_json_default)}`")
        lines.append(f"- Verdict before: `{replacement_verdict_before}`")
        lines.append(f"- Verdict after: `{replacement_verdict_after}`")
        if replacement_note:
            lines.append(f"- Note: {replacement_note}")
        lines.append("")
        lines.append("**Invalidated associations**")
        lines.append("")
        if replacement["invalidated_associations"]:
            for item in replacement["invalidated_associations"]:
                item_association_id = item["association_id"]
                item_summary = item["summary"]
                lines.append(f"- `{item_association_id}` - {item_summary}")
        else:
            lines.append("- None.")
        lines.append("")
        lines.append("**Surviving associations**")
        lines.append("")
        surviving_primary = [item for item in replacement["surviving_associations"] if item.get("role") == "primary"]
        if surviving_primary:
            for item in surviving_primary:
                item_association_id = item["association_id"]
                item_summary = item["summary"]
                lines.append(f"- `{item_association_id}` - {item_summary}")
        else:
            lines.append("- No primary associations survive.")
        omitted_supplemental = len(replacement["surviving_associations"]) - len(surviving_primary)
        if omitted_supplemental:
            lines.append(f"- {omitted_supplemental} supplemental associations also survive and are listed in the JSON result.")
        lines.append("")
        if replacement.get("pairwise_changes"):
            lines.append("**Pairwise verdict changes**")
            lines.append("")
            for change in replacement["pairwise_changes"]:
                change_pair_id = change["pair_id"]
                change_verdict_before = change["verdict_before"]
                change_verdict_after = change["verdict_after"]
                change_independent_before = change["independent_before"]
                change_independent_after = change["independent_after"]
                lines.append(
                    f"- `{change_pair_id}`: `{change_verdict_before}` -> `{change_verdict_after}` "
                    f"(independent: {change_independent_before} -> {change_independent_after})"
                )
            lines.append("")

    lines.append("## Provenance policy")
    lines.append("")
    for key, value in data["provenance"].items():
        lines.append(f"- **{key}:** {value}")
    lines.append("")

    lines.append("## Limitations")
    lines.append("")
    lines.append(
        "- Caller-registered sampling sources and volume identities are assertions until checked against acquisition records."
    )
    lines.append("- Registry-internal hive identity is not a volume serial and does not by itself identify a person.")
    lines.append(
        "- Identical key paths and timestamps prove content similarity; under cloning they do not prove independent use."
    )
    lines.append("- Plugin-derived values are derived observations. They supplement but never replace an original source.")
    lines.append("- Missing acquisition metadata produces `missing_evidence`, not an inference.")
    if data.get("notes"):
        lines.append("")
        lines.append("## Case notes")
        lines.append("")
        lines.append(str(data["notes"]))
    return "\n".join(lines)


review_case = corroborate
replace_record = replace_identity_record


__all__ = [
    "AssociationFinding",
    "ContentAnchor",
    "CorroborationCase",
    "EvidenceRole",
    "ExportRecord",
    "IdentityRecord",
    "NameAssociation",
    "Origin",
    "PluginObservation",
    "ReviewResult",
    "SamplingSource",
    "Verdict",
    "VolumeIdentity",
    "corroborate",
    "replace_record",
    "replace_identity_record",
    "review_case",
]


if __name__ == "__main__":
    from regipy.corroboration_cli import main

    main()
