# -------------------------------------------------------------------------------
# elftools: elf/gnu_properties.py
#
# Cross-artifact GNU property inventory.
# -------------------------------------------------------------------------------
"""Aggregate GNU_PROPERTY note declarations across a deployment.

The GNU property ABI is deliberately conservative: an ELF file that does not
contain a property type has not made a negative claim.  This module therefore
keeps "the type is absent" separate from "the type is present but a feature
bit is clear".

The same property note commonly has both a PT_NOTE program-header view and a
SHT_NOTE section-header view.  Notes are de-duplicated by their file location
before they are used as evidence.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from os import PathLike
from pathlib import Path
from typing import Iterable

from .elffile import ELFFile
from .sections import NoteSection
from .segments import NoteSegment


class CoverageStatus(str, Enum):
    """Deployment-level coverage of one architecture feature bit."""

    FULL = "full"
    PENDING = "pending"
    NOT_SET = "not_set"
    NOT_DECLARED = "not_declared"


@dataclass(frozen=True)
class PropertyFlag:
    """One bit in an architecture-specific GNU property bitmap."""

    mask: int
    name: str


@dataclass(frozen=True)
class PropertyEntry:
    """A raw property entry retained for unsupported architectures."""

    property_type: str | int
    data_size: int
    data: int | bytes


@dataclass(frozen=True)
class NoteEvidence:
    """One unique GNU property note and the ELF views that point at it."""

    offset: int
    size: int
    views: tuple[str, ...]
    properties: tuple[PropertyEntry, ...]


@dataclass(frozen=True)
class ArtifactProperties:
    """GNU property declarations found in one deployment artifact."""

    path: str
    machine: str | int
    architecture: str
    notes: tuple[NoteEvidence, ...]
    raw_properties: tuple[PropertyEntry, ...]
    property_values: tuple[tuple[str | int, int], ...]


@dataclass(frozen=True)
class FeatureCoverage:
    """Evidence for one feature bit across all artifacts of an architecture."""

    name: str
    mask: int
    status: CoverageStatus
    declared_by: tuple[str, ...]
    set_by: tuple[str, ...]
    missing_declaration_by: tuple[str, ...]
    bit_not_set_by: tuple[str, ...]


@dataclass(frozen=True)
class ArchitectureReport:
    """Coverage for one ELF machine architecture."""

    machine: str | int
    architecture: str
    property_type: str
    artifacts: tuple[str, ...]
    declared_intersection: int | None
    declaration_missing_from: tuple[str, ...]
    features: tuple[FeatureCoverage, ...]


@dataclass(frozen=True)
class PropertyInventory:
    """Result returned to callers and rendered by the command-line tool."""

    artifacts: tuple[ArtifactProperties, ...]
    architectures: tuple[ArchitectureReport, ...]
    uninterpretable_artifacts: tuple[ArtifactProperties, ...]


@dataclass(frozen=True)
class _ArchitectureSchema:
    architecture: str
    property_type: str
    flags: tuple[PropertyFlag, ...]


_X86_FEATURE_1_AND = "GNU_PROPERTY_X86_FEATURE_1_AND"
_AARCH64_FEATURE_1_AND = "GNU_PROPERTY_AARCH64_FEATURE_1_AND"

_X86_SCHEMA = _ArchitectureSchema(
    architecture="x86",
    property_type=_X86_FEATURE_1_AND,
    flags=(
        PropertyFlag(1 << 0, "IBT"),
        PropertyFlag(1 << 1, "SHSTK"),
        PropertyFlag(1 << 2, "LAM_U48"),
        PropertyFlag(1 << 3, "LAM_U57"),
    ),
)

_AARCH64_SCHEMA = _ArchitectureSchema(
    architecture="AArch64",
    property_type=_AARCH64_FEATURE_1_AND,
    flags=(
        PropertyFlag(1 << 0, "BTI"),
        PropertyFlag(1 << 1, "PAC"),
    ),
)

_RISCV_SCHEMA = _ArchitectureSchema(
    architecture="RISC-V",
    # pyelftools names the shared 0xc0000000 value after AArch64.  The machine
    # field disambiguates it as RISC-V.
    property_type=_AARCH64_FEATURE_1_AND,
    flags=(
        PropertyFlag(1 << 0, "CFI_LP_UNLABELED"),
        PropertyFlag(1 << 1, "CFI_SS"),
        PropertyFlag(1 << 2, "CFI_LP_FUNC_SIG"),
    ),
)

_MACHINE_SCHEMAS: dict[str | int, _ArchitectureSchema] = {
    "EM_X86_64": _X86_SCHEMA,
    "EM_386": _X86_SCHEMA,
    "EM_AARCH64": _AARCH64_SCHEMA,
    "EM_RISCV": _RISCV_SCHEMA,
    # Accept numeric values too, for callers working with stripped-down header
    # structures rather than ELFFile's normally enum-decoded value.
    62: _X86_SCHEMA,
    3: _X86_SCHEMA,
    183: _AARCH64_SCHEMA,
    243: _RISCV_SCHEMA,
}

_MACHINE_FOR_NUMBER: dict[int, str] = {
    3: "EM_386",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
}


def _normalize_machine(machine: str | int) -> str | int:
    if isinstance(machine, int):
        return _MACHINE_FOR_NUMBER.get(machine, machine)
    return machine


def _machine_display(machine: str | int) -> str:
    if isinstance(machine, int):
        return f"EM_UNKNOWN ({machine:#x})"
    return machine


def _entry_data(data: object) -> int | bytes:
    if isinstance(data, int):
        return data
    return bytes(data)  # type: ignore[arg-type]


def _property_entries(note: object) -> tuple[PropertyEntry, ...]:
    entries = []
    for prop in note["n_desc"]:  # type: ignore[index]
        entries.append(
            PropertyEntry(
                property_type=prop.pr_type,
                data_size=prop.pr_datasz,
                data=_entry_data(prop.pr_data),
            )
        )
    return tuple(entries)


def _unique_property_notes(elf: ELFFile) -> tuple[NoteEvidence, ...]:
    """Return each property note once, even when two ELF views see it.

    Note offsets are absolute file offsets in pyelftools' note API.  Including
    the descriptor bytes in the key also protects against unusual files that
    reuse an offset for distinct note payloads.
    """
    notes: dict[tuple[int, int, bytes], dict[str, object]] = {}

    section_notes = (
        note
        for section in elf.iter_sections()
        if isinstance(section, NoteSection)
        for note in section.iter_notes()
    )
    segment_notes = (
        note
        for segment in elf.iter_segments()
        if isinstance(segment, NoteSegment)
        for note in segment.iter_notes()
    )

    for view, iterator in (
        ("section", section_notes),
        ("program", segment_notes),
    ):
        for note in iterator:
            if note["n_type"] != "NT_GNU_PROPERTY_TYPE_0":
                continue
            key = (
                int(note["n_offset"]),
                int(note["n_size"]),
                bytes(note["n_descdata"]),
            )
            record = notes.get(key)
            if record is None:
                record = {
                    "views": [],
                    "properties": _property_entries(note),
                }
                notes[key] = record
            views = record["views"]
            assert isinstance(views, list)
            if view not in views:
                views.append(view)

    result = []
    for (offset, size, _), record in sorted(notes.items()):
        views = record["views"]
        properties = record["properties"]
        assert isinstance(views, list)
        assert isinstance(properties, tuple)
        result.append(
            NoteEvidence(
                offset=offset,
                size=size,
                views=tuple(views),
                properties=properties,
            )
        )
    return tuple(result)


def _aggregate_property_values(
    notes: tuple[NoteEvidence, ...],
) -> tuple[tuple[str | int, int], ...]:
    """AND duplicate declarations of the same bitmap property.

    All property types interpreted by this module are ``*_AND`` properties.
    Applying AND here also makes two independently visible copies of one note
    harmless.
    """
    values: dict[str | int, int] = {}
    for note in notes:
        for entry in note.properties:
            if not isinstance(entry.data, int):
                continue
            old_value = values.get(entry.property_type)
            if old_value is None:
                values[entry.property_type] = entry.data
            else:
                values[entry.property_type] = old_value & entry.data
    return tuple(sorted(values.items(), key=lambda item: str(item[0])))


def _load_artifact(path: PathLike[str] | str) -> ArtifactProperties:
    path_string = str(path)
    with ELFFile.load_from_path(path_string) as elf:
        machine = _normalize_machine(elf.header["e_machine"])
        schema = _MACHINE_SCHEMAS.get(machine)
        notes = _unique_property_notes(elf)

    raw_properties = tuple(entry for note in notes for entry in note.properties)
    return ArtifactProperties(
        path=path_string,
        machine=machine,
        architecture=schema.architecture if schema is not None else "uninterpretable",
        notes=notes,
        raw_properties=raw_properties,
        property_values=_aggregate_property_values(notes),
    )


def _feature_coverage(
    schema: _ArchitectureSchema,
    artifacts: tuple[ArtifactProperties, ...],
) -> tuple[FeatureCoverage, ...]:
    values_by_path = {
        artifact.path: dict(artifact.property_values) for artifact in artifacts
    }
    declared = tuple(
        artifact.path
        for artifact in artifacts
        if schema.property_type in values_by_path[artifact.path]
    )
    missing = tuple(
        artifact.path
        for artifact in artifacts
        if schema.property_type not in values_by_path[artifact.path]
    )

    coverages = []
    for flag in schema.flags:
        set_by = tuple(
            path
            for path in declared
            if values_by_path[path][schema.property_type] & flag.mask
        )
        bit_not_set = tuple(
            path
            for path in declared
            if not values_by_path[path][schema.property_type] & flag.mask
        )
        if not declared:
            status = CoverageStatus.NOT_DECLARED
        elif missing:
            status = CoverageStatus.PENDING
        elif len(set_by) == len(artifacts):
            status = CoverageStatus.FULL
        else:
            status = CoverageStatus.NOT_SET

        coverages.append(
            FeatureCoverage(
                name=flag.name,
                mask=flag.mask,
                status=status,
                declared_by=declared,
                set_by=set_by,
                missing_declaration_by=missing,
                bit_not_set_by=bit_not_set,
            )
        )
    return tuple(coverages)


def _architecture_report(
    schema: _ArchitectureSchema,
    artifacts: tuple[ArtifactProperties, ...],
) -> ArchitectureReport:
    values = [
        dict(artifact.property_values)[schema.property_type]
        for artifact in artifacts
        if schema.property_type in dict(artifact.property_values)
    ]
    declared_intersection = values[0]
    for value in values[1:]:
        declared_intersection &= value

    return ArchitectureReport(
        machine=artifacts[0].machine,
        architecture=schema.architecture,
        property_type=schema.property_type,
        artifacts=tuple(artifact.path for artifact in artifacts),
        declared_intersection=declared_intersection if values else None,
        declaration_missing_from=tuple(
            artifact.path
            for artifact in artifacts
            if schema.property_type not in dict(artifact.property_values)
        ),
        features=_feature_coverage(schema, artifacts),
    )


def build_property_inventory(
    paths: Iterable[PathLike[str] | str],
) -> PropertyInventory:
    """Build a GNU property inventory for an explicit deployment file list.

    Files are grouped by ELF machine.  A feature is only ``FULL`` when every
    artifact in that machine group declares the relevant property type and
    sets the bit.  If one artifact omits the property type, the feature is
    ``PENDING`` rather than being treated as a negative claim.

    Machines without a known property-bit schema are returned separately and
    are never folded into an intersection.
    """
    path_list = list(paths)
    if not path_list:
        raise ValueError("at least one deployment artifact is required")

    artifacts = []
    seen_files: set[tuple[int, int]] = set()
    for path in path_list:
        stat_result = Path(path).stat()
        identity = (stat_result.st_dev, stat_result.st_ino)
        if identity in seen_files:
            continue
        seen_files.add(identity)
        artifacts.append(_load_artifact(path))

    artifacts_by_machine: dict[str | int, list[ArtifactProperties]] = {}
    for artifact in artifacts:
        artifacts_by_machine.setdefault(artifact.machine, []).append(artifact)

    architecture_reports = []
    unsupported = []
    for machine, machine_artifacts in artifacts_by_machine.items():
        schema = _MACHINE_SCHEMAS.get(machine)
        if schema is None:
            unsupported.extend(machine_artifacts)
            continue
        architecture_reports.append(
            _architecture_report(schema, tuple(machine_artifacts))
        )

    architecture_reports.sort(
        key=lambda report: (
            report.architecture,
            str(report.machine),
        )
    )
    unsupported.sort(key=lambda artifact: artifact.path)
    return PropertyInventory(
        artifacts=tuple(artifacts),
        architectures=tuple(architecture_reports),
        uninterpretable_artifacts=tuple(unsupported),
    )


inventory_files = build_property_inventory


_STATUS_LABELS = {
    CoverageStatus.FULL: "全覆盖",
    CoverageStatus.PENDING: "待确认",
    CoverageStatus.NOT_SET: "未覆盖",
    CoverageStatus.NOT_DECLARED: "未声明",
}


def _format_flags(value: int, flags: tuple[PropertyFlag, ...]) -> str:
    names = [flag.name for flag in flags if value & flag.mask]
    return f"{value:#x} ({', '.join(names)})" if names else f"{value:#x}"


def _format_raw_entry(entry: PropertyEntry) -> str:
    data = f"{entry.data:#x}" if isinstance(entry.data, int) else entry.data.hex(" ")
    return f"{entry.property_type!r} size={entry.data_size} data=[{data}]"


def render_text(inventory: PropertyInventory) -> str:
    """Render a deterministic, human-readable inventory."""
    lines = [
        "Cross-artifact GNU property inventory / 跨制品架构属性清单",
        f"Deployment artifacts / 部署制品: {len(inventory.artifacts)}",
    ]

    for artifact in inventory.artifacts:
        views = ", ".join("+".join(note.views) for note in artifact.notes)
        evidence = f"{len(artifact.notes)} unique note(s)" + (
            f" [{views}]" if views else ""
        )
        lines.append(
            f"  - {artifact.path}: {_machine_display(artifact.machine)}; {evidence}"
        )

    for report in inventory.architectures:
        lines.extend(
            (
                "",
                f"Architecture / 架构: {report.architecture} "
                f"({_machine_display(report.machine)}), "
                f"{len(report.artifacts)} artifact(s)",
                f"  Property type / 属性类型: {report.property_type}",
            )
        )
        if report.declared_intersection is None:
            lines.append(
                "  Declared-only intersection / 已声明属性交集: none (no declarations)"
            )
        else:
            schema = _MACHINE_SCHEMAS[report.machine]
            lines.append(
                "  Declared-only intersection / 已声明属性交集: "
                + _format_flags(report.declared_intersection, schema.flags)
            )

        for feature in report.features:
            label = _STATUS_LABELS[feature.status]
            lines.append(
                f"  {feature.name}: {label} ({feature.status.value}); "
                f"{len(feature.set_by)}/{len(report.artifacts)} "
                "artifact(s) declare and set the bit"
            )
            if feature.status is CoverageStatus.PENDING:
                gap = ", ".join(feature.missing_declaration_by)
                lines.append(
                    f"    声明缺失 / declaration missing in: {gap}; "
                    "the absent type is not a zero-valued claim"
                )
            if feature.status is CoverageStatus.NOT_SET:
                gap = ", ".join(feature.bit_not_set_by)
                lines.append(f"    bit clear in: {gap}")
            if feature.status is CoverageStatus.NOT_DECLARED:
                lines.append(
                    f"    {report.property_type} is absent from every "
                    "artifact in this architecture group"
                )

        if report.declaration_missing_from:
            lines.append(
                "  Declaration gaps / 声明缺失: "
                + ", ".join(report.declaration_missing_from)
            )

    if inventory.uninterpretable_artifacts:
        lines.extend(
            ("", "Uninterpretable machine architectures / 无法解释的机器架构:")
        )
        for artifact in inventory.uninterpretable_artifacts:
            lines.append(f"  {artifact.path}: {_machine_display(artifact.machine)}")
            if artifact.raw_properties:
                for entry in artifact.raw_properties:
                    lines.append(f"    raw property: {_format_raw_entry(entry)}")
            else:
                lines.append("    raw property: none")
            lines.append(
                "    no architecture feature table is available; "
                "excluded from all intersections"
            )

    return "\n".join(lines)


def _json_default(value: object) -> str:
    if isinstance(value, bytes):
        return value.hex(" ")
    raise TypeError(f"object of type {type(value).__name__} is not JSON serializable")


def render_json(inventory: PropertyInventory) -> str:
    """Render the complete inventory as JSON, encoding raw bytes as hex."""
    return json.dumps(
        asdict(inventory),
        indent=2,
        ensure_ascii=False,
        default=_json_default,
    )
