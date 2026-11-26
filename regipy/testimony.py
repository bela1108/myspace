"""Deterministic dependency receipts for offline forensic exports.

This module is opt-in and does not change regipy's existing plugin output.
A receipt binds one testimony/conclusion to:

* the exact registry key/value byte ranges it read (with optional hashes);
* the plugin name and version which produced it;
* the caller's interpretation name/version and definition; and
* a digest of the conclusion embedded in the offline export.

Receipts are canonicalized before hashing, so identical inputs produce stable
receipt/export bytes.  Auditing an old export never requires the original hive:
the JSON export remains readable.  A missing historical interpretation version
is reported separately from testimonies suspended by a known plugin/interpretation
change.
"""

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

RECEIPT_SCHEMA_VERSION = "regipy.testimony-receipt/v1"
EXPORT_SCHEMA_VERSION = "regipy.offline-testimony-export/v1"
AUDIT_REPORT_SCHEMA_VERSION = "regipy.testimony-audit-report/v1"

DISPOSITION_REUSABLE = "reusable"
DISPOSITION_SUSPENDED = "suspended"
DISPOSITION_MISSING_INTERPRETATION = "missing_interpretation_version"
DISPOSITION_INVALID = "invalid"
DISPOSITION_UNKNOWN_ENVIRONMENT = "environment_incomplete"

_SEVERITY_BLOCKING = {
    DISPOSITION_SUSPENDED,
    DISPOSITION_MISSING_INTERPRETATION,
    DISPOSITION_INVALID,
    DISPOSITION_UNKNOWN_ENVIRONMENT,
}


def canonical_json_bytes(payload: Any) -> bytes:
    """Return deterministic canonical JSON bytes for JSON-compatible ``payload``."""

    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")


def canonical_json_dumps(payload: Any, indent: Optional[int] = None) -> str:
    if indent is None:
        return canonical_json_bytes(payload).decode("utf-8")
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        indent=indent,
        separators=(",", ": "),
        default=_json_default,
    )


def sha256_jsonable(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, tuple)):
        return list(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, bytes):
        return {"bytes_sha256": sha256_bytes(value), "byte_length": len(value)}
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _to_plain(value: Any) -> Any:
    return json.loads(canonical_json_bytes(value))


def canonical_key_path(key_path: str) -> str:
    """Normalize a registry path for case-insensitive scope matching."""

    normalized = str(key_path).replace("/", "\\").strip()
    parts = [part.strip().casefold() for part in normalized.split("\\")]
    return "\\".join(part for part in parts if part)


@dataclass(frozen=True)
class HiveValueRange:
    """A registry key/value coordinate, optionally narrowed to byte offsets.

    ``start`` and ``end`` are zero-based byte offsets into the raw registry value
    data.  ``end`` is exclusive.  When no offsets are supplied, the dependency is
    the complete named value (or key metadata component).
    """

    key_path: str
    value_name: Optional[str] = None
    component: str = "value"
    start: int = 0
    end: Optional[int] = None
    hive_name: Optional[str] = None
    hive_sha256: Optional[str] = None
    value_type: Optional[str] = None
    sha256: Optional[str] = None
    digest_basis: Optional[str] = None

    def __post_init__(self) -> None:
        if self.end is not None and self.end < self.start:
            raise ValueError("HiveValueRange end must be greater than or equal to start")
        if self.start < 0:
            raise ValueError("HiveValueRange start must not be negative")

    @property
    def canonical_key(self) -> str:
        return canonical_key_path(self.key_path)

    @property
    def canonical_value_name(self) -> Optional[str]:
        return self.value_name.casefold() if self.value_name is not None else None

    @property
    def locator(self) -> str:
        value_part = self.canonical_value_name or f"<{self.component.lower()}>"
        range_part = ""
        if self.start or self.end is not None:
            range_part = f"#{self.start}:{'' if self.end is None else self.end}"
        hive_part = f"{self.hive_name}!" if self.hive_name else ""
        return f"{hive_part}{self.canonical_key}::{value_part}{range_part}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HiveValueRange":
        allowed = cls.__dataclass_fields__.keys()  # type: ignore[attr-defined]
        return cls(**{key: value for key, value in data.items() if key in allowed})

    def matches_scope(self, scope: "DependencyScope") -> bool:
        if scope.component is not None and scope.component.casefold() != self.component.casefold():
            return False
        if scope.value_name is not None and scope.value_name.casefold() != (self.canonical_value_name or ""):
            return False
        if scope.key_path is not None and canonical_key_path(scope.key_path) != self.canonical_key:
            return False
        if scope.key_prefix is not None:
            prefix = canonical_key_path(scope.key_prefix)
            key = self.canonical_key
            if key != prefix and not key.startswith(prefix + "\\"):
                return False
        return True


def observe_hive_value(
    key_path: str,
    value_name: Optional[str] = None,
    *,
    data: Union[bytes, str, None] = None,
    observed_value: Any = None,
    start: int = 0,
    end: Optional[int] = None,
    component: str = "value",
    hive_name: Optional[str] = None,
    hive_sha256: Optional[str] = None,
    value_type: Optional[str] = None,
) -> HiveValueRange:
    """Create a dependency range and fingerprint the observed source material."""

    digest: Optional[str] = None
    digest_basis: Optional[str] = None
    if data is not None:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        selected = raw[start:end]
        digest = sha256_bytes(selected)
        digest_basis = "selected-raw-bytes"
        if end is None:
            end = len(raw)
    elif observed_value is not None:
        digest = sha256_jsonable(observed_value)
        digest_basis = "canonical-json-value"

    return HiveValueRange(
        key_path=key_path,
        value_name=value_name,
        component=component,
        start=start,
        end=end,
        hive_name=hive_name,
        hive_sha256=hive_sha256,
        value_type=value_type,
        sha256=digest,
        digest_basis=digest_basis,
    )


@dataclass(frozen=True)
class DependencyScope:
    """An explicit change scope used to decide which receipts are affected."""

    key_path: Optional[str] = None
    key_prefix: Optional[str] = None
    value_name: Optional[str] = None
    component: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DependencyScope":
        allowed = cls.__dataclass_fields__.keys()  # type: ignore[attr-defined]
        return cls(**{key: value for key, value in data.items() if key in allowed})


@dataclass(frozen=True)
class PluginRef:
    name: str
    version: str
    digest: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_value(cls, value: Union["PluginRef", Mapping[str, Any], str], version: Optional[str] = None) -> "PluginRef":
        if isinstance(value, PluginRef):
            return value
        if isinstance(value, str):
            if version is None:
                raise ValueError("version is required when plugin is a name")
            return cls(name=value, version=version)
        if isinstance(value, Mapping):
            return cls(
                name=value["name"],
                version=str(value["version"]),
                digest=value.get("digest"),
            )
        plugin_name = getattr(value, "NAME", None) or getattr(value, "name", None)
        plugin_version = (
            version
            or getattr(value, "VERSION", None)
            or getattr(value, "version", None)
            or getattr(value, "PLUGIN_VERSION", None)
        )
        if plugin_name and not plugin_version:
            import regipy

            plugin_version = getattr(regipy, "__version__", None)
        if plugin_name and plugin_version:
            return cls(name=str(plugin_name), version=str(plugin_version))
        raise TypeError("Unsupported plugin reference")


@dataclass(frozen=True)
class InterpretationRef:
    name: str
    version: str
    digest: Optional[str] = None
    definition: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.digest is None and self.definition:
            object.__setattr__(self, "digest", sha256_jsonable(dict(self.definition)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InterpretationRef":
        return cls(
            name=data["name"],
            version=str(data["version"]),
            digest=data.get("digest"),
            definition=data.get("definition", {}) or {},
        )


@dataclass
class TestimonyDependencyReceipt:
    testimony_id: str
    plugin: PluginRef
    interpretation: InterpretationRef
    dependencies: list[HiveValueRange]
    conclusion_sha256: str
    schema_version: str = RECEIPT_SCHEMA_VERSION
    receipt_id: str = ""
    caller: Optional[str] = None
    created_at: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.receipt_id:
            self.receipt_id = derive_receipt_id(self)

    @property
    def hive_value_ranges(self) -> list[HiveValueRange]:
        return self.dependencies

    @property
    def caller_interpretation(self) -> InterpretationRef:
        return self.interpretation

    def to_dict(self, *, include_receipt_id: bool = True) -> dict[str, Any]:
        payload = asdict(self)
        payload["hive_value_ranges"] = payload["dependencies"]
        payload["caller_interpretation"] = payload["interpretation"]
        if not include_receipt_id:
            payload.pop("receipt_id", None)
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TestimonyDependencyReceipt":
        dependencies = data.get("hive_value_ranges", data.get("dependencies", []))
        interpretation = data.get("caller_interpretation", data.get("interpretation"))
        return cls(
            schema_version=data.get("schema_version", RECEIPT_SCHEMA_VERSION),
            receipt_id=data.get("receipt_id", ""),
            testimony_id=data["testimony_id"],
            plugin=PluginRef.from_value(data["plugin"]),
            interpretation=InterpretationRef.from_dict(interpretation),
            dependencies=[HiveValueRange.from_dict(item) for item in dependencies],
            conclusion_sha256=data["conclusion_sha256"],
            caller=data.get("caller"),
            created_at=data.get("created_at"),
            metadata=data.get("metadata", {}) or {},
        )


# Readable aliases for callers/tests that use the shorter vocabulary.
TestimonyReceipt = TestimonyDependencyReceipt
Receipt = TestimonyDependencyReceipt
ValueRange = HiveValueRange
HiveValueDependency = HiveValueRange
Dependency = HiveValueRange


def derive_receipt_id(receipt: Union[TestimonyDependencyReceipt, Mapping[str, Any]]) -> str:
    if isinstance(receipt, TestimonyDependencyReceipt):
        payload = receipt.to_dict(include_receipt_id=False)
    else:
        payload = dict(receipt)
        payload.pop("receipt_id", None)
    return sha256_jsonable(payload)


def hash_conclusion(conclusion: Any) -> str:
    return sha256_jsonable(conclusion)


def build_receipt(
    testimony_id: str,
    conclusion: Any,
    *,
    plugin: Union[PluginRef, Mapping[str, Any], str, None] = None,
    plugin_name: Optional[str] = None,
    plugin_version: Optional[str] = None,
    plugin_digest: Optional[str] = None,
    interpretation: Union[InterpretationRef, Mapping[str, Any], None] = None,
    interpretation_name: Optional[str] = None,
    interpretation_version: Optional[str] = None,
    interpretation_definition: Optional[Mapping[str, Any]] = None,
    interpretation_digest: Optional[str] = None,
    dependencies: Sequence[HiveValueRange] = (),
    caller: Optional[str] = None,
    created_at: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> TestimonyDependencyReceipt:
    """Build and identify one receipt from plain Python values."""

    if plugin is None:
        if plugin_name is None or plugin_version is None:
            raise ValueError("plugin or plugin_name/plugin_version is required")
        plugin_ref = PluginRef(plugin_name, str(plugin_version), plugin_digest)
    else:
        plugin_ref = PluginRef.from_value(plugin, plugin_version)
        if plugin_digest and plugin_ref.digest is None:
            plugin_ref = PluginRef(plugin_ref.name, plugin_ref.version, plugin_digest)

    if interpretation is None:
        if interpretation_name is None or interpretation_version is None:
            raise ValueError("interpretation or interpretation_name/version is required")
        interpretation_ref = InterpretationRef(
            interpretation_name,
            str(interpretation_version),
            interpretation_digest,
            dict(interpretation_definition or {}),
        )
    elif isinstance(interpretation, Mapping):
        interpretation_ref = InterpretationRef.from_dict(interpretation)
    else:
        interpretation_ref = interpretation

    return TestimonyDependencyReceipt(
        testimony_id=testimony_id,
        plugin=plugin_ref,
        interpretation=interpretation_ref,
        dependencies=list(dependencies),
        conclusion_sha256=hash_conclusion(conclusion),
        caller=caller,
        created_at=created_at,
        metadata=dict(metadata or {}),
    )


class ReceiptRecorder:
    """Small factory that keeps plugin/interpretation coordinates consistent."""

    def __init__(
        self,
        *,
        plugin: Union[PluginRef, Mapping[str, Any], str, None] = None,
        plugin_name: Optional[str] = None,
        plugin_version: Optional[str] = None,
        plugin_digest: Optional[str] = None,
        interpretation: Union[InterpretationRef, Mapping[str, Any], None] = None,
        interpretation_name: Optional[str] = None,
        interpretation_version: Optional[str] = None,
        interpretation_definition: Optional[Mapping[str, Any]] = None,
        caller: Optional[str] = None,
    ) -> None:
        if plugin is None:
            if plugin_name is None or plugin_version is None:
                raise ValueError("plugin coordinates are required")
            self.plugin = PluginRef(plugin_name, str(plugin_version), plugin_digest)
        else:
            self.plugin = PluginRef.from_value(plugin, plugin_version)

        if interpretation is not None:
            if isinstance(interpretation, Mapping):
                self.interpretation: Optional[InterpretationRef] = InterpretationRef.from_dict(interpretation)
            else:
                self.interpretation = interpretation
        elif interpretation_name is not None or interpretation_version is not None:
            if interpretation_name is None or interpretation_version is None:
                raise ValueError("interpretation_name and interpretation_version must be supplied together")
            self.interpretation = InterpretationRef(
                interpretation_name,
                str(interpretation_version),
                definition=dict(interpretation_definition or {}),
            )
        else:
            self.interpretation = None
        self.caller = caller

    def observe(self, *args: Any, **kwargs: Any) -> HiveValueRange:
        return observe_hive_value(*args, **kwargs)

    def receipt(
        self,
        testimony_id: str,
        conclusion: Any,
        dependencies: Sequence[HiveValueRange] = (),
        *,
        created_at: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        interpretation: Union[InterpretationRef, Mapping[str, Any], None] = None,
        interpretation_name: Optional[str] = None,
        interpretation_version: Optional[str] = None,
        interpretation_digest: Optional[str] = None,
        interpretation_definition: Optional[Mapping[str, Any]] = None,
    ) -> TestimonyDependencyReceipt:
        interpretation_ref: Optional[InterpretationRef]
        if interpretation_name is not None or interpretation_version is not None:
            if interpretation is not None:
                raise ValueError("pass either interpretation or interpretation_name/version, not both")
            if interpretation_name is None or interpretation_version is None:
                raise ValueError("interpretation_name and interpretation_version must be supplied together")
            interpretation_ref = InterpretationRef(
                interpretation_name,
                str(interpretation_version),
                interpretation_digest,
                dict(interpretation_definition or {}),
            )
        elif interpretation is not None:
            interpretation_ref = (
                InterpretationRef.from_dict(interpretation) if isinstance(interpretation, Mapping) else interpretation
            )
        else:
            interpretation_ref = self.interpretation
        if interpretation_ref is None:
            raise ValueError("interpretation coordinates are required for a receipt")
        return build_receipt(
            testimony_id,
            conclusion,
            plugin=self.plugin,
            interpretation=interpretation_ref,
            dependencies=dependencies,
            caller=self.caller,
            created_at=created_at,
            metadata=metadata,
        )


@dataclass
class OfflineExport:
    findings: list[dict[str, Any]] = field(default_factory=list)
    receipts: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = EXPORT_SCHEMA_VERSION
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "metadata": _to_plain(self.metadata),
            "findings": _sorted_findings(self.findings),
            "receipts": _sorted_receipts(self.receipts),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OfflineExport":
        return cls(
            schema_version=data.get("schema_version", EXPORT_SCHEMA_VERSION),
            metadata=dict(data.get("metadata", {}) or {}),
            findings=list(data.get("findings", []) or []),
            receipts=list(data.get("receipts", []) or []),
        )


TestimonyExport = OfflineExport
ReceiptBundle = OfflineExport


def _testimony_sort_key(item: Mapping[str, Any]) -> str:
    return str(item.get("testimony_id") or item.get("id") or canonical_json_bytes(item)[:32].hex())


def _sorted_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    plain = [dict(item) for item in findings]
    return sorted(plain, key=_testimony_sort_key)


def _sorted_receipts(receipts: Iterable[Union[TestimonyDependencyReceipt, Mapping[str, Any]]]) -> list[dict[str, Any]]:
    plain = [item.to_dict() if isinstance(item, TestimonyDependencyReceipt) else dict(item) for item in receipts]
    return sorted(plain, key=lambda item: str(item.get("testimony_id", "")))


def build_offline_export(
    findings: Union[Mapping[str, Any], Sequence[dict[str, Any]]],
    receipts: Sequence[Union[TestimonyDependencyReceipt, Mapping[str, Any]]],
    *,
    metadata: Optional[Mapping[str, Any]] = None,
) -> OfflineExport:
    """Create a deterministic export, accepting an id->conclusion map or lists."""

    if isinstance(findings, Mapping):
        finding_list = []
        for testimony_id, conclusion in findings.items():
            item = dict(conclusion) if isinstance(conclusion, Mapping) else {"value": conclusion}
            item.setdefault("testimony_id", testimony_id)
            finding_list.append(item)
    else:
        finding_list = [dict(item) for item in findings]

    return OfflineExport(
        findings=finding_list,
        receipts=[item.to_dict() if isinstance(item, TestimonyDependencyReceipt) else dict(item) for item in receipts],
        metadata=dict(metadata or {}),
    )


def write_offline_export(export: Union[OfflineExport, Mapping[str, Any]], path: Union[str, Path]) -> Path:
    payload = export.to_dict() if isinstance(export, OfflineExport) else dict(export)
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(canonical_json_dumps(payload, indent=2) + "\n", encoding="utf-8")
    return output


def dumps_offline_export(export: Union[OfflineExport, Mapping[str, Any]]) -> str:
    payload = export.to_dict() if isinstance(export, OfflineExport) else dict(export)
    return canonical_json_dumps(payload, indent=2) + "\n"


def read_offline_export(path: Union[str, Path]) -> OfflineExport:
    return loads_offline_export(Path(path).read_text(encoding="utf-8"))


def loads_offline_export(text: Union[str, bytes]) -> OfflineExport:
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    return OfflineExport.from_dict(json.loads(text))


@dataclass(frozen=True)
class InterpretationInfo:
    name: str
    version: str
    digest: Optional[str] = None
    definition: Mapping[str, Any] = field(default_factory=dict)
    superseded_by: Optional[str] = None

    def to_ref(self) -> InterpretationRef:
        return InterpretationRef(self.name, self.version, self.digest, dict(self.definition))


@dataclass(frozen=True)
class ChangeNotice:
    """Declares that a plugin and/or interpretation change affects given scopes.

    Empty ``affected_scopes`` is intentionally conservative: every dependency of
    matching receipts is treated as affected.  Supply scopes to avoid reopening
    unrelated testimonies.
    """

    plugin_name: str
    change_id: Optional[str] = None
    new_plugin_version: Optional[str] = None
    old_plugin_versions: tuple[str, ...] = ()
    interpretation_name: Optional[str] = None
    old_interpretation_version: Optional[str] = None
    new_interpretation_version: Optional[str] = None
    affected_scopes: tuple[DependencyScope, ...] = ()
    reason: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ChangeNotice":
        scopes = tuple(DependencyScope.from_dict(item) for item in data.get("affected_scopes", []))
        versions = tuple(str(item) for item in data.get("old_plugin_versions", ()))
        return cls(
            plugin_name=data["plugin_name"],
            change_id=data.get("change_id"),
            new_plugin_version=data.get("new_plugin_version"),
            old_plugin_versions=versions,
            interpretation_name=data.get("interpretation_name"),
            old_interpretation_version=data.get("old_interpretation_version"),
            new_interpretation_version=data.get("new_interpretation_version"),
            affected_scopes=scopes,
            reason=data.get("reason", ""),
        )


@dataclass
class AuditFinding:
    testimony_id: str
    receipt_id: str
    disposition: str
    review_required: bool
    missing_interpretation: bool
    reasons: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)
    plugin: dict[str, Any] = field(default_factory=dict)
    interpretation: dict[str, Any] = field(default_factory=dict)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    affected_dependencies: list[dict[str, Any]] = field(default_factory=list)
    conclusion: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.disposition
        payload["suspended"] = self.disposition == DISPOSITION_SUSPENDED
        payload["pending_review"] = self.disposition == DISPOSITION_SUSPENDED
        return payload


@dataclass
class AuditReport:
    total: int
    findings: list[AuditFinding]
    schema_version: str = AUDIT_REPORT_SCHEMA_VERSION
    readable: bool = True
    export_schema_version: Optional[str] = None
    export_metadata: dict[str, Any] = field(default_factory=dict)

    def _with_status(self, status: str) -> list[AuditFinding]:
        return [finding for finding in self.findings if finding.disposition == status]

    @property
    def suspended(self) -> list[AuditFinding]:
        return self._with_status(DISPOSITION_SUSPENDED)

    @property
    def missing_interpretation(self) -> list[AuditFinding]:
        return [finding for finding in self.findings if finding.missing_interpretation]

    @property
    def missing_interpretations(self) -> list[AuditFinding]:
        return self.missing_interpretation

    @property
    def missing_interpretation_versions(self) -> list[AuditFinding]:
        return self.missing_interpretation

    @property
    def reusable(self) -> list[AuditFinding]:
        return self._with_status(DISPOSITION_REUSABLE)

    @property
    def invalid(self) -> list[AuditFinding]:
        return self._with_status(DISPOSITION_INVALID)

    @property
    def incomplete_environment(self) -> list[AuditFinding]:
        return self._with_status(DISPOSITION_UNKNOWN_ENVIRONMENT)

    @property
    def review_queue(self) -> list[AuditFinding]:
        return [finding for finding in self.findings if finding.review_required]

    @property
    def pending_review(self) -> list[AuditFinding]:
        """Testimonies suspended by a detected new plugin/interpretation change."""

        return self.suspended

    @property
    def pending_testimonies(self) -> list[AuditFinding]:
        return self.suspended

    def testimony_ids(self, findings: Iterable[AuditFinding]) -> list[str]:
        return [finding.testimony_id for finding in findings]

    def to_dict(self) -> dict[str, Any]:
        buckets = {
            "suspended": self.suspended,
            "pending_review_all": self.review_queue,
            "missing_interpretation": self.missing_interpretation,
            "interpretation_version_missing": self.missing_interpretation,
            "missing_interpretation_version": self.missing_interpretation,
            "reusable": self.reusable,
            "invalid": self.invalid,
            "environment_incomplete": self.incomplete_environment,
        }
        return {
            "schema_version": self.schema_version,
            "readable": self.readable,
            "export_schema_version": self.export_schema_version,
            "export_metadata": self.export_metadata,
            "total": self.total,
            "review_queue": [item.to_dict() for item in self.review_queue],
            "pending_review": [item.to_dict() for item in self.pending_review],
            "counts": {key: len(value) for key, value in buckets.items()},
            "findings": [item.to_dict() for item in self.findings],
            **{key: [item.to_dict() for item in value] for key, value in buckets.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        return canonical_json_dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        lines = [
            "# Testimony dependency audit",
            "",
            f"- Export readable: `{self.readable}`",
            f"- Total testimonies: `{self.total}`",
            f"- Suspended by a detected change: `{len(self.suspended)}`",
            f"- Missing historical interpretation: `{len(self.missing_interpretation)}`",
            f"- Reusable: `{len(self.reusable)}`",
            f"- Invalid: `{len(self.invalid)}`",
            "",
        ]
        lines.extend(_markdown_finding_section("Suspended testimonies", self.suspended, include_reason=True))
        lines.extend(
            _markdown_finding_section(
                "Readable exports missing the used interpretation version",
                self.missing_interpretation,
                include_reason=True,
            )
        )
        lines.extend(_markdown_finding_section("Invalid receipts", self.invalid, include_reason=True))
        lines.extend(_markdown_reusable_section(self.reusable))
        return "\n".join(lines).rstrip() + "\n"


def _markdown_finding_section(title: str, findings: Sequence[AuditFinding], *, include_reason: bool) -> list[str]:
    if not findings:
        return [f"## {title}", "", "_None._", ""]
    lines = [f"## {title}", ""]
    for finding in findings:
        lines.append(f"### `{finding.testimony_id}`")
        lines.append("")
        lines.append(f"- Disposition: `{finding.disposition}`")
        lines.append(f"- Receipt: `{finding.receipt_id}`")
        lines.append(
            f"- Plugin: `{finding.plugin.get('name')}@{finding.plugin.get('version')}`; "
            f"interpretation: `{finding.interpretation.get('name')}@{finding.interpretation.get('version')}`"
        )
        if include_reason:
            for reason in finding.reasons:
                lines.append(f"- Reason: {reason}")
        for dep in finding.affected_dependencies or finding.dependencies:
            name = dep.get("value_name") or f"<{dep.get('component', 'key')}>"
            byte_range = ""
            if dep.get("start") or dep.get("end") is not None:
                byte_range = f" bytes `{dep.get('start', 0)}:{dep.get('end')}`"
            lines.append(f"- Affected hive range: `{dep.get('key_path')}` :: `{name}`{byte_range}")
        for explanation in finding.explanations:
            lines.append(f"- Note: {explanation}")
        lines.append("")
    return lines


def _markdown_reusable_section(findings: Sequence[AuditFinding]) -> list[str]:
    lines = ["## Reusable testimonies", ""]
    if not findings:
        lines.extend(["_None._", ""])
        return lines
    for finding in findings:
        details = (
            "; ".join(finding.explanations)
            if finding.explanations
            else "receipt verified and dependencies are outside every declared change scope"
        )
        lines.append(f"- `{finding.testimony_id}` — {details}")
    lines.append("")
    return lines


class SourceSnapshot:
    """In-memory source values used to verify receipt dependency hashes.

    The mapping shape is ``{key_path: {value_name: raw_bytes_or_json_value}}``.
    """

    def __init__(self, values: Mapping[str, Mapping[str, Any]]) -> None:
        self.values = values

    def digest_for(self, dependency: HiveValueRange) -> Optional[str]:
        key_values = _lookup_key_mapping(self.values, dependency.key_path)
        if key_values is None or dependency.value_name is None:
            return None
        value = _lookup_value(key_values, dependency.value_name)
        if value is None:
            return None
        if isinstance(value, bytes):
            return sha256_bytes(value[dependency.start : dependency.end])
        return sha256_jsonable(value)


def _lookup_key_mapping(values: Mapping[str, Mapping[str, Any]], key_path: str) -> Optional[Mapping[str, Any]]:
    wanted = canonical_key_path(key_path)
    for path, mapping in values.items():
        if canonical_key_path(path) == wanted:
            return mapping
    return None


def _lookup_value(mapping: Mapping[str, Any], value_name: str) -> Any:
    wanted = value_name.casefold()
    for name, value in mapping.items():
        if str(name).casefold() == wanted:
            return value
    return None


def normalize_interpretations(
    interpretations: Union[None, InterpretationInfo, Mapping[str, Any], Sequence[Any], "InterpretationRegistry"],
) -> Optional[dict[tuple[str, str], InterpretationInfo]]:
    if interpretations is None:
        return None
    if isinstance(interpretations, InterpretationRegistry):
        return dict(interpretations.items)
    if isinstance(interpretations, InterpretationInfo):
        return {(interpretations.name, interpretations.version): interpretations}
    if isinstance(interpretations, Mapping):
        result: dict[tuple[str, str], InterpretationInfo] = {}
        for key, value in interpretations.items():
            if isinstance(key, tuple):
                name, version = key
            elif "@" in str(key):
                name, version = str(key).rsplit("@", 1)
            else:
                item = value if isinstance(value, InterpretationInfo) else InterpretationInfo(**value)
                result[(item.name, item.version)] = item
                continue
            if isinstance(value, InterpretationInfo):
                item = value
            elif isinstance(value, Mapping):
                data = dict(value)
                data.setdefault("name", name)
                data.setdefault("version", version)
                item = InterpretationInfo(**data)
            else:
                item = InterpretationInfo(name, version, str(value))
            result[(name, str(version))] = item
        return result
    result = {}
    for item in interpretations:
        info = item if isinstance(item, InterpretationInfo) else InterpretationInfo(**item)
        result[(info.name, info.version)] = info
    return result


class InterpretationRegistry:
    def __init__(self, interpretations: Optional[Sequence[InterpretationInfo]] = None) -> None:
        self.items: dict[tuple[str, str], InterpretationInfo] = {}
        for item in interpretations or ():
            self.register(item)

    def register(self, item: InterpretationInfo) -> None:
        self.items[(item.name, item.version)] = item

    def get(self, name: str, version: str) -> Optional[InterpretationInfo]:
        return self.items.get((name, version))


def normalize_plugin_environment(
    active_plugins: Union[None, Mapping[str, Any], Sequence[Any]],
) -> Optional[dict[str, PluginRef]]:
    if active_plugins is None:
        return None
    result = {}
    if isinstance(active_plugins, Mapping):
        for name, value in active_plugins.items():
            if isinstance(value, str):
                result[name] = PluginRef(name=name, version=value)
            else:
                ref = PluginRef.from_value(value)
                if ref.name != name:
                    ref = PluginRef(name=name, version=ref.version, digest=ref.digest)
                result[name] = ref
        return result
    for value in active_plugins:
        ref = PluginRef.from_value(value)
        result[ref.name] = ref
    return result


def audit_export(
    export: Union[OfflineExport, Mapping[str, Any], str, Path],
    *,
    active_plugins: Union[Mapping[str, Any], Sequence[Any], None] = None,
    interpretations: Any = None,
    changes: Optional[Sequence[Union[ChangeNotice, Mapping[str, Any]]]] = None,
    source: Optional[Union[SourceSnapshot, Callable[[HiveValueRange], Optional[str]]]] = None,
    include_conclusions: bool = False,
) -> AuditReport:
    """Audit an offline export against current plugin/interpretation coordinates."""

    if isinstance(export, (str, Path)):
        bundle = read_offline_export(export)
    elif isinstance(export, OfflineExport):
        bundle = export
    else:
        bundle = OfflineExport.from_dict(export)

    plugin_env = normalize_plugin_environment(active_plugins)
    interpretation_env = normalize_interpretations(interpretations)
    notices = [item if isinstance(item, ChangeNotice) else ChangeNotice.from_dict(item) for item in (changes or [])]
    findings_by_id = {str(item.get("testimony_id")): item for item in bundle.findings if item.get("testimony_id") is not None}

    findings: list[AuditFinding] = []
    for receipt_data in bundle.receipts:
        receipt = TestimonyDependencyReceipt.from_dict(receipt_data)
        findings.append(
            _audit_one(
                receipt=receipt,
                receipt_data=receipt_data,
                bundle=bundle,
                conclusion=findings_by_id.get(receipt.testimony_id),
                plugin_env=plugin_env,
                interpretation_env=interpretation_env,
                notices=notices,
                source=source,
                include_conclusions=include_conclusions,
            )
        )

    return AuditReport(
        total=len(findings),
        findings=findings,
        export_schema_version=bundle.schema_version,
        export_metadata=bundle.metadata,
    )


def _audit_one(
    *,
    receipt: TestimonyDependencyReceipt,
    receipt_data: Mapping[str, Any],
    bundle: OfflineExport,
    conclusion: Optional[Mapping[str, Any]],
    plugin_env: Optional[dict[str, PluginRef]],
    interpretation_env: Optional[dict[tuple[str, str], InterpretationInfo]],
    notices: Sequence[ChangeNotice],
    source: Optional[Union[SourceSnapshot, Callable[[HiveValueRange], Optional[str]]]],
    include_conclusions: bool,
) -> AuditFinding:
    reasons: list[str] = []
    explanations: list[str] = []
    affected: list[HiveValueRange] = []
    invalid = False
    incomplete_environment = False

    expected_receipt_id = derive_receipt_id(receipt)
    if receipt.receipt_id != expected_receipt_id or receipt_data.get("receipt_id") != expected_receipt_id:
        invalid = True
        reasons.append("receipt_id does not match its canonical dependency payload")

    if conclusion is None:
        invalid = True
        reasons.append("export does not contain a finding with the receipt testimony_id")
    elif hash_conclusion(conclusion) != receipt.conclusion_sha256:
        invalid = True
        reasons.append("exported conclusion digest does not match receipt")

    for dependency in receipt.dependencies:
        actual_digest = _source_digest(source, dependency)
        if actual_digest and dependency.sha256 and actual_digest != dependency.sha256:
            reasons.append(f"source fingerprint changed for {dependency.locator}")
            affected.append(dependency)

    relevant_notices = _matching_notices(receipt, notices)
    explicit_notice_exists = any(
        notice.affected_scopes or notice.interpretation_name is not None for notice in relevant_notices
    )
    for notice in relevant_notices:
        hits = _notice_hits(receipt, notice)
        if hits:
            for dependency in hits:
                if dependency not in affected:
                    affected.append(dependency)
            target = notice.change_id or notice.reason or "declared change"
            reasons.append(f"associated with change {target}: {notice.reason or 'affected dependency scope'}".rstrip(": "))
        elif notice.affected_scopes:
            explanations.append(
                f"change {notice.change_id or notice.plugin_name} is scoped outside this testimony's dependencies"
            )

    active_plugin: Optional[PluginRef] = None
    if plugin_env is not None:
        active_plugin = plugin_env.get(receipt.plugin.name)
        if active_plugin is None:
            reasons.append(f"plugin {receipt.plugin.name!r} is not available in the active environment")
        elif active_plugin.version != receipt.plugin.version or (
            active_plugin.digest and receipt.plugin.digest and active_plugin.digest != receipt.plugin.digest
        ):
            if not relevant_notices:
                for dependency in receipt.dependencies:
                    if dependency not in affected:
                        affected.append(dependency)
                reasons.append(
                    f"plugin version changed from {receipt.plugin.version} to {active_plugin.version} without a scoped change manifest"
                )
            elif not affected and explicit_notice_exists:
                explanations.append(
                    f"plugin is {active_plugin.version}, but the declared changed scope does not intersect this testimony"
                )

    missing_interpretation = False
    if interpretation_env is not None:
        info = interpretation_env.get((receipt.interpretation.name, receipt.interpretation.version))
        if info is None:
            missing_interpretation = True
            reasons.append(
                f"used interpretation version {receipt.interpretation.name}@{receipt.interpretation.version} is not registered; export remains readable"
            )
        elif receipt.interpretation.digest and info.digest and receipt.interpretation.digest != info.digest:
            affected.extend(dep for dep in receipt.dependencies if dep not in affected)
            reasons.append("registered interpretation definition digest does not match the receipt")

    if plugin_env is not None and active_plugin is None and not any("not available" in reason for reason in reasons):
        incomplete_environment = True

    if invalid:
        disposition = DISPOSITION_INVALID
    elif reasons and (
        affected or any("changed" in reason or "digest" in reason or "not available" in reason for reason in reasons)
    ):
        disposition = DISPOSITION_SUSPENDED
    elif missing_interpretation:
        disposition = DISPOSITION_MISSING_INTERPRETATION
    elif plugin_env is None or interpretation_env is None:
        disposition = DISPOSITION_UNKNOWN_ENVIRONMENT
        explanations.append("audit did not receive complete plugin and interpretation version catalogs")
    else:
        disposition = DISPOSITION_REUSABLE
        if not explanations:
            explanations.append("receipt verified; plugin and caller interpretation versions match the active catalog")

    if incomplete_environment and disposition == DISPOSITION_UNKNOWN_ENVIRONMENT:
        # A missing active plugin already produced a blocking reason above.
        disposition = DISPOSITION_SUSPENDED

    return AuditFinding(
        testimony_id=receipt.testimony_id,
        receipt_id=receipt.receipt_id,
        disposition=disposition,
        review_required=disposition in _SEVERITY_BLOCKING,
        missing_interpretation=missing_interpretation,
        reasons=reasons,
        explanations=explanations,
        plugin=receipt.plugin.to_dict(),
        interpretation=receipt.interpretation.to_dict(),
        dependencies=[dep.to_dict() for dep in receipt.dependencies],
        affected_dependencies=[dep.to_dict() for dep in affected],
        conclusion=dict(conclusion) if include_conclusions and conclusion is not None else None,
    )


def _source_digest(
    source: Optional[Union[SourceSnapshot, Callable[[HiveValueRange], Optional[str]]]],
    dependency: HiveValueRange,
) -> Optional[str]:
    if source is None:
        return None
    if isinstance(source, SourceSnapshot):
        return source.digest_for(dependency)
    return source(dependency)


def _matching_notices(receipt: TestimonyDependencyReceipt, notices: Sequence[ChangeNotice]) -> list[ChangeNotice]:
    result = []
    for notice in notices:
        if notice.plugin_name != "*" and notice.plugin_name != receipt.plugin.name:
            continue
        if notice.old_plugin_versions and receipt.plugin.version not in notice.old_plugin_versions:
            continue
        result.append(notice)
    return result


def _notice_hits(receipt: TestimonyDependencyReceipt, notice: ChangeNotice) -> list[HiveValueRange]:
    if notice.interpretation_name is not None and notice.interpretation_name != receipt.interpretation.name:
        return []
    if notice.old_interpretation_version is not None and notice.old_interpretation_version != receipt.interpretation.version:
        return []
    if not notice.affected_scopes:
        return list(receipt.dependencies)
    hits = []
    for dependency in receipt.dependencies:
        if any(dependency.matches_scope(scope) for scope in notice.affected_scopes):
            hits.append(dependency)
    return hits


# Verb-first aliases for callers and tests written around the user story.
create_receipt = build_receipt
record_dependency_receipt = build_receipt
create_offline_export = build_offline_export
verify_export = audit_export
verify_receipts = audit_export
audit_receipts = audit_export


def create_dependency_receipt(
    testimony_id: str,
    conclusion: Any,
    *,
    hive_value_ranges: Optional[Sequence[HiveValueRange]] = None,
    caller_interpretation: Union[InterpretationRef, Mapping[str, Any], str, None] = None,
    caller_interpretation_name: Optional[str] = None,
    caller_interpretation_version: Optional[str] = None,
    caller_interpretation_definition: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> TestimonyDependencyReceipt:
    """Story-language wrapper around :func:`build_receipt`."""

    interpretation = caller_interpretation
    interpretation_name = caller_interpretation_name
    if isinstance(caller_interpretation, str) and caller_interpretation_version is not None:
        interpretation_name = interpretation_name or caller_interpretation
        interpretation = None

    return build_receipt(
        testimony_id,
        conclusion,
        interpretation=interpretation,
        interpretation_name=interpretation_name,
        interpretation_version=caller_interpretation_version,
        interpretation_definition=caller_interpretation_definition,
        dependencies=hive_value_ranges or (),
        **kwargs,
    )


class ReceiptAuditor:
    """Reusable audit environment for repeated offline export checks."""

    def __init__(
        self,
        *,
        active_plugins: Union[Mapping[str, Any], Sequence[Any], None] = None,
        interpretations: Any = None,
        changes: Optional[Sequence[Union[ChangeNotice, Mapping[str, Any]]]] = None,
        source: Optional[Union[SourceSnapshot, Callable[[HiveValueRange], Optional[str]]]] = None,
    ) -> None:
        self.active_plugins = active_plugins
        self.interpretations = interpretations
        self.changes = changes
        self.source = source

    def audit(
        self,
        export: Union[OfflineExport, Mapping[str, Any], str, Path],
        *,
        active_plugins: Any = None,
        interpretations: Any = None,
        changes: Any = None,
        source: Any = None,
        include_conclusions: bool = False,
    ) -> AuditReport:
        return audit_export(
            export,
            active_plugins=self.active_plugins if active_plugins is None else active_plugins,
            interpretations=self.interpretations if interpretations is None else interpretations,
            changes=self.changes if changes is None else changes,
            source=self.source if source is None else source,
            include_conclusions=include_conclusions,
        )

    verify = audit


ReceiptValidator = ReceiptAuditor
ImpactAnalyzer = ReceiptAuditor


def generate_audit_report(
    export: Union[OfflineExport, Mapping[str, Any], str, Path],
    *,
    output_format: str = "markdown",
    **kwargs: Any,
) -> Union[str, AuditReport]:
    """Audit an export and render ``markdown`` (default), ``json``, or report."""

    report = audit_export(export, **kwargs)
    normalized_format = output_format.lower()
    if normalized_format in {"report", "object"}:
        return report
    if normalized_format == "json":
        return report.to_json()
    if normalized_format in {"markdown", "md"}:
        return report.to_markdown()
    raise ValueError(f"Unsupported output_format: {output_format}")
