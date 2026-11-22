"""Export-range auditing against a computed static layout.

The caller supplies which member paths are part of the public ABI and which
inclusive byte ranges are proposed for export. Every touched byte is then
explained in terms of the regions produced by LayoutEngine, so a verdict
always points at a concrete declaration location.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json

from .config import AbiConfig, parse_byte_range
from .errors import AuditError, Location
from .layout import LayoutEngine, Region, TypeLayout
from .parser import ParsedUnit


@dataclass(frozen=True)
class ExportRange:
    label: str
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start + 1


@dataclass
class ByteFinding:
    """A single audited byte slice inside an export range."""

    offset: int
    size: int
    classification: str
    paths: list[str]
    location: Location | None
    explanation: str

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "size": self.size,
            "classification": self.classification,
            "paths": list(self.paths),
            "location": self.location.to_dict() if self.location else None,
            "explanation": self.explanation,
        }


@dataclass
class RangeVerdict:
    label: str
    start: int
    end: int
    verdict: str
    findings: list[ByteFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "start": self.start,
            "end": self.end,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AuditReport:
    type_name: str
    abi_name: str
    layout: TypeLayout
    verdicts: list[RangeVerdict] = field(default_factory=list)
    review_items: list[dict] = field(default_factory=list)

    @property
    def worst_verdict(self) -> str:
        order = {"ok": 0, "violation": 1, "review": 2}
        if not self.verdicts:
            return "ok"
        return max((v.verdict for v in self.verdicts),
                   key=lambda value: order[value])

    def to_dict(self) -> dict:
        return {
            "type": self.type_name,
            "abi": self.abi_name,
            "type_size": self.layout.size,
            "type_alignment": self.layout.alignment,
            "worst_verdict": self.worst_verdict,
            "verdicts": [v.to_dict() for v in self.verdicts],
            "review_items": list(self.review_items),
            "layout": self.layout.to_dict(),
        }


@dataclass
class AuditConfig:
    """Caller-supplied audit scope for one declarations file."""

    type_name: str
    public_paths: list[str]
    export_ranges: list[ExportRange]

    @classmethod
    def from_dict(cls, data: dict) -> "AuditConfig":
        if "type" not in data:
            raise AuditError("audit config requires a target type")
        public_paths = data.get("public_fields", [])
        if not isinstance(public_paths, list) or not all(
                isinstance(item, str) for item in public_paths):
            raise AuditError("public_fields must be a list of dotted paths")
        raw_ranges = data.get("export_ranges", [])
        if not isinstance(raw_ranges, list):
            raise AuditError("export_ranges must be a list")
        ranges = []
        for index, item in enumerate(raw_ranges):
            if isinstance(item, str):
                start, end = parse_byte_range(item)
                ranges.append(ExportRange(f"range-{index}", start, end))
                continue
            if not isinstance(item, dict) or "range" not in item:
                raise AuditError(
                    f"export_ranges[{index}] needs a range string")
            start, end = parse_byte_range(item["range"])
            label = str(item.get("label", f"range-{index}"))
            ranges.append(ExportRange(label, start, end))
        return cls(str(data["type"]), list(public_paths), ranges)


def load_audit_config(path: str) -> tuple[AbiConfig, AuditConfig]:
    """Load one JSON file holding both the ABI geometry and the audit scope."""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    abi_data = data.get("abi")
    if not isinstance(abi_data, dict):
        raise AuditError("config file requires an abi object")
    audit_data = data.get("audit")
    if not isinstance(audit_data, dict):
        raise AuditError("config file requires an audit object")
    return AbiConfig.from_dict(abi_data), AuditConfig.from_dict(audit_data)


def _normalize_public_paths(paths: list[str]) -> set[str]:
    normalized = set()
    for path in paths:
        cleaned = ".".join(part for part in path.split(".") if part)
        if cleaned:
            normalized.add(cleaned)
    return normalized


def _is_public(region: Region, public_paths: set[str]) -> bool:
    if region.kind == "padding":
        return False
    dotted = ".".join(part for part in region.path if not part.startswith("["))
    if dotted in public_paths:
        return True
    return any(
        dotted == public or dotted.startswith(public + ".")
        for public in public_paths)


def _region_path_text(region: Region) -> str:
    text = ""
    for part in region.path:
        if part.startswith("["):
            text += part
        else:
            text = f"{text}.{part}" if text else part
    return text


def _intersect(start: int, end: int, region: Region):
    low = max(start, region.offset)
    high = min(end, region.end - 1)
    if low <= high:
        return low, high
    return None


def audit_type(unit: ParsedUnit, config: AbiConfig,
               audit_config: AuditConfig) -> AuditReport:
    """Compute the layout and audit every requested export range."""

    engine = LayoutEngine(unit, config)
    layout = engine.layout_named(audit_config.type_name)
    report = AuditReport(audit_config.type_name, config.name, layout)
    public_paths = _normalize_public_paths(audit_config.public_paths)

    for rule in layout.unsupported:
        report.review_items.append({
            "kind": rule.kind,
            "message": rule.message,
            "location": rule.location.to_dict(),
        })

    for export in audit_config.export_ranges:
        report.verdicts.append(
            _audit_range(export, layout, public_paths))
    return report


def _audit_range(export: ExportRange, layout: TypeLayout,
                 public_paths: set[str]) -> RangeVerdict:
    findings: list[ByteFinding] = []
    if export.end >= layout.size:
        findings.append(ByteFinding(
            export.start, export.size, "out_of_bounds", [],
            layout.location,
            f"range {export.start}-{export.end} exceeds type size "
            f"{layout.size}"))
        return RangeVerdict(export.label, export.start, export.end,
                            "violation", findings)

    covered: list[tuple[int, int]] = []
    for region in layout.regions:
        overlap = _intersect(export.start, export.end, region)
        if overlap is None:
            continue
        low, high = overlap
        covered.append((low, high))
        findings.append(_classify_slice(region, low, high, public_paths))

    missing = _uncovered(export.start, export.end, covered)
    for low, high in missing:
        findings.append(ByteFinding(
            low, high - low + 1, "unmapped", [], layout.location,
            "byte is not described by any layout region; manual review needed"))

    findings.sort(key=lambda item: item.offset)
    verdict = _summarize(findings)
    return RangeVerdict(export.label, export.start, export.end,
                        verdict, findings)


def _classify_slice(region: Region, low: int, high: int,
                    public_paths: set[str]) -> ByteFinding:
    size = high - low + 1
    path_text = _region_path_text(region)
    if region.kind == "bitfield":
        return ByteFinding(
            low, size, "review", [path_text], region.location,
            f"bitfield storage at {path_text}: {region.note}")
    if region.kind == "padding":
        return ByteFinding(
            low, size, "padding", [path_text], region.location,
            f"implicit padding byte ({region.note}); not a public field")
    if _is_public(region, public_paths):
        return ByteFinding(
            low, size, "public", [path_text], region.location,
            f"public field {path_text} ({region.type_text})")
    return ByteFinding(
        low, size, "internal", [path_text], region.location,
        f"internal field {path_text} ({region.type_text}) is not in "
        "public_fields")


def _uncovered(start: int, end: int,
               covered: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not covered:
        return [(start, end)]
    covered = sorted(covered)
    gaps = []
    cursor = start
    for low, high in covered:
        if low > cursor:
            gaps.append((cursor, low - 1))
        cursor = max(cursor, high + 1)
    if cursor <= end:
        gaps.append((cursor, end))
    return gaps


def _summarize(findings: list[ByteFinding]) -> str:
    classes = {item.classification for item in findings}
    if classes & {"internal", "out_of_bounds", "unmapped"}:
        return "violation"
    if classes & {"review", "padding"}:
        return "review"
    return "ok"
