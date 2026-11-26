"""Offline append-compatibility checks for dissect.cstruct declarations.

The verifier parses every declaration through the interpreted ``compiled=False``
path, generates a few deterministic ordinary samples, and compares marked
observable prefixes by parsed values and field read lengths rather than by byte
count alone.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from dataclasses import field as dc_field
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from dissect.cstruct.cstruct import cstruct
from dissect.cstruct.expression import Expression
from dissect.cstruct.types import Field, Structure, Union
from dissect.cstruct.types.base import EOF, BaseArray
from dissect.cstruct.types.char import Char, CharArray
from dissect.cstruct.types.wchar import Wchar, WcharArray

if TYPE_CHECKING:
    from collections.abc import Sequence

Verdict = Literal["stable", "added-tail", "changed", "blocked"]
SampleStatus = Literal["compatible", "incompatible", "generation-error"]

_MARKER_RE = re.compile(
    r"(?:@(?:observable|compat)[_-]?prefix|observable[-_ ]prefix|compat[-_ ]prefix)",
    re.IGNORECASE,
)
_FIELD_FROM_COMMENT_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?::\s*\d+)?\s*;")
_SIZE_OF_RE = re.compile(r"\bsizeof\s*\(\s*([A-Za-z_]\w*)\s*\)")
_OFFSETOF_RE = re.compile(r"\boffsetof\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)")
_LENGTH_NAME_RE = re.compile(r"(?:^|_)(?:n|len|length|count|num|size|entries)$", re.IGNORECASE)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")


@dataclass(frozen=True)
class VersionSpec:
    """A named declaration and the version constraint represented by it."""

    label: str
    cdef: str | None = None
    struct_type: type[Structure] | None = None
    constraint: str | None = None
    version: str | None = None
    endian: str = "<"

    def effective_constraint(self) -> str:
        """Return the supplied constraint or an exact-label fallback."""
        return self.constraint or f"=={self.version or self.label}"


@dataclass(frozen=True)
class PathObservation:
    """One parsed or intended observable path."""

    path: str
    value: Any
    length: int | None
    offset: int | None = None
    type_name: str | None = None


@dataclass(frozen=True)
class Difference:
    """A mismatch found while checking a sample."""

    path: str
    kind: str
    expected: Any = None
    actual: Any = None
    message: str = ""
    version: str | None = None


@dataclass(frozen=True)
class ParseObservation:
    """The result of reading one sample with one declaration."""

    version: str
    scope: Literal["prefix", "full"]
    ok: bool
    consumed: int | None
    error: str | None
    paths: dict[str, PathObservation] = dc_field(default_factory=dict)


@dataclass
class SampleReport:
    """Generated sample and its cross-version interpretation checks."""

    sample_id: str
    origin: str
    description: str
    hex: str
    length: int
    status: SampleStatus
    applicable_versions: list[str] = dc_field(default_factory=list)
    applicable_constraints: list[str] = dc_field(default_factory=list)
    full_read_versions: list[str] = dc_field(default_factory=list)
    exact_read_versions: list[str] = dc_field(default_factory=list)
    read_dispositions: dict[str, str] = dc_field(default_factory=dict)
    parses: dict[str, ParseObservation] = dc_field(default_factory=dict)
    differences: list[Difference] = dc_field(default_factory=list)
    generation_error: str | None = None

    @property
    def compatible(self) -> bool:
        """Whether the origin round trip and all prefix checks passed."""
        return self.status == "compatible" and not self.differences

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    """A static compatibility risk."""

    severity: Literal["error", "warning", "info"]
    code: str
    message: str
    path: str | None = None


@dataclass(frozen=True)
class FieldConstraint:
    """Version information for one top-level field."""

    path: str
    status: Verdict
    constraints: list[str]
    reason: str


@dataclass
class CompatibilityReport:
    """Complete offline compatibility report."""

    struct_name: str
    observable: list[str]
    compatible: bool
    append_only: bool
    suggested_prefix_constraint: str | None
    versions: list[VersionSpec]
    findings: list[Finding] = dc_field(default_factory=list)
    field_constraints: list[FieldConstraint] = dc_field(default_factory=list)
    samples: list[SampleReport] = dc_field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        data = asdict(self)
        for version in data.get("versions", []):
            version.pop("struct_type", None)
        return data

    def markdown(self) -> str:
        """Render a compact human-readable report."""
        icon = "PASS" if self.compatible else "FAIL"
        lines = [
            f"# Compatibility report: {self.struct_name} [{icon}]",
            "",
            f"Observable prefix: `{', '.join(self.observable)}`",
            f"Append-only field order: `{self.append_only}`",
            f"Suggested prefix constraint: `{self.suggested_prefix_constraint or 'none'}`",
            "",
            "## Versions",
        ]
        lines.extend(f"- `{version.label}` => `{version.effective_constraint()}`" for version in self.versions)

        lines.extend(["", "## Static findings"])
        if not self.findings:
            lines.append("- none")
        for finding in self.findings:
            location = f" `{finding.path}`" if finding.path else ""
            lines.append(f"- {finding.severity.upper()} `{finding.code}`{location}: {finding.message}")

        lines.extend(["", "## Samples"])
        for sample in self.samples:
            verdict = "PASS" if sample.compatible else sample.status.upper()
            constraints = ", ".join(f"`{item}`" for item in sample.applicable_constraints) or "none"
            exact = ", ".join(f"`{item}`" for item in sample.exact_read_versions) or "none"
            lines.append(
                f"- `{sample.sample_id}` [{verdict}] {sample.length} bytes "
                f"`{sample.hex}`; prefix constraints: {constraints}; exact reads: {exact}"
            )
            lines.extend(
                f"  - `{difference.path}` {difference.kind}: {difference.message}" for difference in sample.differences
            )

        lines.extend(["", "## Field constraints"])
        for item in self.field_constraints:
            constraints = ", ".join(f"`{value}`" for value in item.constraints) or "none"
            lines.append(f"- `{item.path}` {item.status}: {item.reason} ({constraints})")
        return "\n".join(lines) + "\n"


def markers_from_cdef(cdef: str) -> list[str]:
    """Extract fields marked with ``@compat-prefix`` comments from a cdef."""
    markers: list[str] = []
    pending = False
    for raw_line in cdef.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("//", "/*", "*")):
            if _MARKER_RE.search(line):
                pending = True
            continue

        marker_here = bool(_MARKER_RE.search(line))
        code = _MARKER_RE.sub("", line)
        match = _FIELD_FROM_COMMENT_RE.search(code)
        if match and (marker_here or pending):
            name = match.group(1)
            if name not in markers:
                markers.append(name)
        pending = False
    return markers


def _top_level_name(path: str) -> str:
    return path.split(".", 1)[0].split("[", 1)[0]


def _join_path(parent: str, name: str | None) -> str:
    if not name:
        return parent
    return f"{parent}.{name}" if parent else name


def canonical_value(value: Any) -> Any:
    """Convert cstruct values to stable JSON-comparable Python data."""
    if isinstance(value, Structure):
        return {
            field.name or field._name: canonical_value(getattr(value, field._name))
            for field in value.__class__.__fields__
        }
    if isinstance(value, dict):
        return {str(key): canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [canonical_value(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"__bytes__": bytes(value).hex()}
    if isinstance(value, float):
        return value
    if isinstance(value, int):
        return int(value)
    return str(value)


def _type_dimensions(type_: type[BaseArray | Any]) -> list[Any]:
    dimensions: list[Any] = []
    current = type_
    while isinstance(current, type) and issubclass(current, BaseArray):
        count = current.__num_entries__
        if isinstance(count, Expression):
            dimensions.append(count.expression)
        else:
            dimensions.append(count)
        current = current.__type__
    return dimensions


def field_signature(field: Field) -> dict[str, Any]:
    """Return a stable structural signature for a field and its array dimensions."""
    current = field.type
    dimensions = _type_dimensions(current)
    while isinstance(current, type) and issubclass(current, BaseArray):
        current = current.__type__
    return {
        "type": current.__name__,
        "dimensions": dimensions,
        "bits": field.bits,
    }


def _expression_strings(field: Field) -> list[str]:
    expressions: list[str] = []
    current = field.type
    while isinstance(current, type) and issubclass(current, BaseArray):
        count = current.__num_entries__
        if isinstance(count, Expression):
            expressions.append(count.expression)
        elif count is None:
            expressions.append("EOF")
        current = current.__type__
    return expressions


def _expression_identifiers(expression: str) -> set[str]:
    identifiers = set(_IDENTIFIER_RE.findall(expression))
    identifiers.difference_update({"sizeof", "offsetof", "EOF"})
    return identifiers


def _load_version(spec: VersionSpec, struct_name: str, endian: str) -> VersionSpec:
    if spec.struct_type is not None:
        return spec
    if spec.cdef is None:
        raise ValueError(f"Version {spec.label!r} requires cdef or struct_type")
    loaded = cstruct(endian=spec.endian or endian).load(spec.cdef, compiled=False)
    struct_type = loaded.resolve(struct_name)
    return VersionSpec(
        label=spec.label,
        cdef=spec.cdef,
        struct_type=struct_type,
        constraint=spec.constraint,
        version=spec.version,
        endian=spec.endian or endian,
    )


def _copy_prefix_type(spec: VersionSpec, cutoff: int, cache: dict[str, type[Structure]]) -> type[Structure]:
    assert spec.struct_type is not None
    struct_type = spec.struct_type
    cache_key = f"{spec.label}:{cutoff}"
    if cache_key in cache:
        return cache[cache_key]

    copied_fields = [
        Field(field.name, field.type, bits=field.bits, offset=None) for field in struct_type.__fields__[: cutoff + 1]
    ]
    base_type: type[Structure] = Union if issubclass(struct_type, Union) else Structure
    assert struct_type.__cs__ is not None
    safe_label = re.sub(r"\W", "_", spec.label)
    prefix_type = struct_type.__cs__._make_type(
        f"_CompatPrefix_{safe_label}_{cutoff}",
        (base_type,),
        None,
        alignment=struct_type.__alignment__,
    )
    align = getattr(struct_type, "__align__", False)
    prefix_type.__align__ = align
    meta_type = type(struct_type)
    classdict = meta_type._update_fields(
        prefix_type,
        copied_fields,
        align=align,
    )
    for key, value in classdict.items():
        setattr(prefix_type, key, value)
    cache[cache_key] = prefix_type
    return prefix_type


def collect_paths(value: Structure, prefix: str = "") -> dict[str, PathObservation]:
    """Collect canonical values and byte lengths from a parsed cstruct object."""
    paths: dict[str, PathObservation] = {}

    def walk(node: Any, node_type: type[Any], parent: str, base_offset: int | None) -> None:
        if not isinstance(node, Structure):
            return
        node_sizes = getattr(node, "__sizes__", {})
        for field in node_type.__fields__:
            path = _join_path(parent, field.name)
            field_value = getattr(node, field._name)
            offset = None
            if base_offset is not None and field.offset is not None:
                offset = base_offset + field.offset
            paths[path] = PathObservation(
                path=path,
                value=canonical_value(field_value),
                length=node_sizes.get(field._name),
                offset=offset,
                type_name=field.type.__name__,
            )

            child_offset = offset if field.offset is not None else None
            if isinstance(field_value, Structure):
                walk(field_value, field.type, path, child_offset)
            elif isinstance(field_value, (list, tuple)):
                element_type = getattr(field.type, "__type__", None)
                for index, item in enumerate(field_value):
                    item_path = f"{path}[{index}]"
                    if isinstance(item, Structure) and element_type is not None:
                        walk(item, element_type, item_path, child_offset)

    walk(value, value.__class__, prefix, 0)
    return paths


def _encoded_length(field_type: type[Any], value: Any) -> int | None:
    try:
        return len(field_type.dumps(value))
    except Exception:
        return None


def expected_paths(struct_type: type[Structure], value: Structure) -> dict[str, PathObservation]:
    """Build value/length expectations from generated ordinary Python values."""
    paths: dict[str, PathObservation] = {}

    def walk(node: Any, node_type: type[Structure], parent: str) -> None:
        for field in node_type.__fields__:
            path = _join_path(parent, field.name)
            field_value = getattr(node, field._name)
            paths[path] = PathObservation(
                path=path,
                value=canonical_value(field_value),
                length=_encoded_length(field.type, field_value),
                offset=field.offset,
                type_name=field.type.__name__,
            )
            if isinstance(field_value, Structure):
                walk(field_value, field.type, path)
            elif isinstance(field_value, (list, tuple)):
                element_type = getattr(field.type, "__type__", None)
                for index, item in enumerate(field_value):
                    if isinstance(item, Structure) and element_type is not None:
                        walk(item, element_type, f"{path}[{index}]")

    walk(value, struct_type, "")
    return paths


def _parse(
    sample: bytes,
    read_type: type[Structure],
    version: str,
    scope: Literal["prefix", "full"],
) -> ParseObservation:
    stream = BytesIO(sample)
    error: str | None = None
    obj: Structure | None = None
    try:
        obj = read_type._read(stream, endian=read_type.__cs__.endian)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    return ParseObservation(
        version=version,
        scope=scope,
        ok=error is None,
        consumed=stream.tell(),
        error=error,
        paths=collect_paths(obj) if obj is not None else {},
    )


SAMPLE_PLANS: tuple[dict[str, Any], ...] = (
    {"name": "zero", "length": 0, "number": 0x11, "text_count": 2},
    {"name": "small", "length": 3, "number": 0x2A, "text_count": 3},
    {"name": "packed", "length": 6, "number": 0x43, "text_count": 4},
)


class SampleGenerator:
    """Deterministic ordinary-value generator used when no samples are supplied."""

    def __init__(self, plan_index: int = 1) -> None:
        self.plan = SAMPLE_PLANS[plan_index % len(SAMPLE_PLANS)]

    def generate(self, struct_type: type[Structure]) -> tuple[Structure, dict[str, PathObservation]]:
        """Generate one structure value and its expected paths."""
        value = self._structure(struct_type, context={})
        obj = struct_type(**value)
        return obj, expected_paths(struct_type, obj)

    def _structure(self, struct_type: type[Structure], context: dict[str, Any]) -> dict[str, Any]:
        values: dict[str, Any] = {}
        field_identifiers = self._referenced_identifiers(struct_type)
        for field in struct_type.__fields__:
            field_context = dict(context)
            field_context.update(values)
            values[field._name] = self._field_value(field, field_context, field.name in field_identifiers)
        return values

    def _referenced_identifiers(self, struct_type: type[Structure]) -> set[str]:
        referenced: set[str] = set()
        for field in struct_type.__fields__:
            for expression in _expression_strings(field):
                referenced.update(_expression_identifiers(expression))
        return referenced

    def _field_value(self, field: Field, context: dict[str, Any], referenced: bool) -> Any:
        name_is_length = bool(field.name and _LENGTH_NAME_RE.search(field.name))
        return self._value(field.type, context, length_like=referenced or name_is_length)

    def _value(self, type_: type[Any], context: dict[str, Any], *, length_like: bool) -> Any:
        if isinstance(type_, type) and issubclass(type_, Structure):
            return type_(**self._structure(type_, context))

        if isinstance(type_, type) and issubclass(type_, BaseArray):
            return self._array_value(type_, context)

        if isinstance(type_, type) and issubclass(type_, CharArray):
            return b"AB"

        if isinstance(type_, type) and issubclass(type_, WcharArray):
            return "AB"

        if isinstance(type_, type) and issubclass(type_, Char):
            return b"A"

        if isinstance(type_, type) and issubclass(type_, str):
            return "A"

        if hasattr(type_, "_value2member_map_"):
            members = list(type_)
            if members:
                return members[min(1, len(members) - 1)]

        if isinstance(type_, type) and issubclass(type_, float):
            return 1.5

        if isinstance(type_, type) and issubclass(type_, int):
            if length_like:
                return int(self.plan["length"])
            size = max(1, type_.__size__ or 1)
            value = int(self.plan["number"])
            if size == 1:
                return value
            return value * min(size, 4)

        raise TypeError(f"Cannot synthesize ordinary value for {getattr(type_, '__name__', type_)}")

    def _array_value(self, array_type: type[BaseArray], context: dict[str, Any]) -> Any:
        count = array_type._num_entries(context)
        if count == EOF or count is None or count < 0:
            count = int(self.plan["text_count"])
        count = max(0, int(count))

        element_type = array_type.__type__
        if issubclass(element_type, Char):
            return bytes(65 + index % 26 for index in range(count))
        if issubclass(element_type, Wchar):
            return "".join(chr(65 + index % 26) for index in range(count))
        return [self._value(element_type, context, length_like=False) for _ in range(count)]


def _compare_paths(
    expected: dict[str, PathObservation],
    actual: ParseObservation,
    *,
    paths: set[str] | None = None,
    version: str | None = None,
) -> list[Difference]:
    differences: list[Difference] = []
    wanted = paths if paths is not None else set(expected)
    for path in sorted(wanted):
        wanted_expected = expected.get(path)
        actual_path = actual.paths.get(path)
        if wanted_expected is None:
            continue
        if actual_path is None:
            differences.append(
                Difference(
                    path,
                    "missing-path",
                    wanted_expected.value,
                    None,
                    "path was not parsed",
                    version,
                )
            )
            continue
        if canonical_value(wanted_expected.value) != actual_path.value:
            differences.append(
                Difference(
                    path,
                    "value",
                    wanted_expected.value,
                    actual_path.value,
                    "parsed value differs",
                    version,
                )
            )
        if wanted_expected.length is not None and wanted_expected.length != actual_path.length:
            differences.append(
                Difference(
                    path,
                    "read-length",
                    wanted_expected.length,
                    actual_path.length,
                    f"expected {wanted_expected.length} byte field read, got {actual_path.length}",
                    version,
                )
            )
    return differences


def _static_findings(
    versions: list[VersionSpec],
    struct_name: str,
    observable: list[str],
) -> tuple[list[Finding], bool, list[FieldConstraint]]:
    old = versions[0].struct_type
    new = versions[-1].struct_type
    assert old is not None
    assert new is not None
    findings: list[Finding] = []
    old_fields = old.__fields__
    new_fields = new.__fields__
    old_names = [field._name for field in old_fields]
    new_names = [field._name for field in new_fields]
    append_only = len(new_names) >= len(old_names) and new_names[: len(old_names)] == old_names

    if not append_only:
        findings.append(Finding("error", "field-order", "New declaration is not append-only relative to the baseline"))

    old_by_name = {field._name: field for field in old_fields}
    new_by_name = {field._name: field for field in new_fields}
    constraints: list[FieldConstraint] = []

    for name in old_names:
        old_field = old_by_name[name]
        new_field = new_by_name.get(name)
        if new_field is None:
            findings.append(Finding("error", "missing-field", "Baseline field is missing", name))
            constraints.append(FieldConstraint(name, "changed", [], "field missing from new declaration"))
            continue
        if field_signature(old_field) != field_signature(new_field):
            findings.append(Finding("error", "signature-change", "Field type or length expression changed", name))
            constraints.append(FieldConstraint(name, "changed", [], "type or length expression changed"))
        elif old_field.offset != new_field.offset:
            findings.append(Finding("error", "offset-change", "Static field offset changed", name))
            constraints.append(FieldConstraint(name, "changed", [], "field offset changed"))
        else:
            constraints.append(
                FieldConstraint(
                    name,
                    "stable",
                    [version.effective_constraint() for version in versions],
                    "same declaration signature and offset",
                )
            )

    constraints.extend(
        FieldConstraint(
            field._name,
            "added-tail",
            [versions[-1].effective_constraint()],
            f"tail field added in {versions[-1].label}",
        )
        for field in new_fields[len(old_fields) :]
    )

    for index, field in enumerate(new_fields):
        expressions = _expression_strings(field)
        has_eof = any(expression == "EOF" for expression in expressions)
        if has_eof and index < len(new_fields) - 1:
            following = new_fields[index + 1]._name
            findings.append(
                Finding(
                    "error",
                    "eof-tail-extension",
                    f"EOF/greedy length reads to end of input, but {following!r} follows it; "
                    "tail extension is swallowed and the following field cannot be read",
                    field._name,
                )
            )
            for item in constraints:
                if item.path == field._name:
                    constraints[constraints.index(item)] = FieldConstraint(
                        item.path, "blocked", [], "EOF length is changed by tail extension"
                    )

        for expression in expressions:
            for referenced_name in _SIZE_OF_RE.findall(expression):
                old_size = _resolve_type_size(old.__cs__, referenced_name)
                new_size = _resolve_type_size(new.__cs__, referenced_name)
                if old_size != new_size and referenced_name in old.__cs__.types and referenced_name in new.__cs__.types:
                    findings.append(
                        Finding(
                            "error",
                            "sizeof-extension",
                            f"sizeof({referenced_name}) changes from {old_size} to {new_size}; "
                            "this length expression changes under tail extension",
                            field._name,
                        )
                    )

    if not observable:
        findings.append(
            Finding(
                "warning",
                "no-observable-marker",
                "No prefix markers were supplied; using all baseline fields",
            )
        )

    return findings, append_only, constraints


def _resolve_type_size(cs_instance: cstruct, name: str) -> int | None | str:
    try:
        return cs_instance.resolve(name).__size__
    except Exception:
        return "unresolved"


class CompatibilityVerifier:
    """Run offline declaration and sample checks across named versions."""

    def __init__(
        self,
        struct_name: str,
        *versions: VersionSpec,
        observable: str | Sequence[str] | None = None,
        endian: str = "<",
        samples_per_version: int = 2,
        extra_samples: Sequence[bytes | tuple[str, bytes]] | None = None,
    ) -> None:
        self.struct_name = struct_name
        self.versions = list(versions)
        self.endian = endian
        self.samples_per_version = max(0, min(samples_per_version, len(SAMPLE_PLANS)))
        self.extra_samples = list(extra_samples or [])
        if observable is None:
            self.observable_input: list[str] = []
        elif isinstance(observable, str):
            self.observable_input = [observable]
        else:
            self.observable_input = list(observable)
        self._prefix_cache: dict[str, type[Structure]] = {}

    def add_cdef(
        self,
        label: str,
        definition: str,
        *,
        constraint: str | None = None,
        version: str | None = None,
    ) -> CompatibilityVerifier:
        """Add a cdef version to verify."""
        self.versions.append(VersionSpec(label=label, cdef=definition, constraint=constraint, version=version))
        return self

    def check(self) -> CompatibilityReport:
        """Load declarations, generate samples, and return the compatibility report."""
        if len(self.versions) < 2:
            raise ValueError("At least two versions are required")
        loaded = [_load_version(spec, self.struct_name, self.endian) for spec in self.versions]
        observable = self._resolve_observable(loaded)
        findings, append_only, field_constraints = _static_findings(loaded, self.struct_name, observable)

        samples: list[SampleReport] = []
        samples.extend(
            self._check_generated_sample(spec, loaded, plan_index, observable)
            for spec in loaded
            for plan_index in range(self.samples_per_version)
        )

        for index, sample in enumerate(self.extra_samples):
            label, data = sample if isinstance(sample, tuple) else (f"raw-{index}", sample)
            samples.append(self._check_raw_sample(label, data, loaded, observable))

        compatible = not any(finding.severity == "error" for finding in findings) and all(
            sample.compatible for sample in samples
        )
        suggested = self._suggest_constraint(loaded, compatible)
        return CompatibilityReport(
            struct_name=self.struct_name,
            observable=observable,
            compatible=compatible,
            append_only=append_only,
            suggested_prefix_constraint=suggested,
            versions=loaded,
            findings=findings,
            field_constraints=field_constraints,
            samples=samples,
        )

    def _resolve_observable(self, versions: list[VersionSpec]) -> list[str]:
        if self.observable_input:
            return self.observable_input
        marked: list[str] = []
        for spec in versions:
            if spec.cdef:
                for marker in markers_from_cdef(spec.cdef):
                    if marker not in marked:
                        marked.append(marker)
        if marked:
            return marked
        assert versions[0].struct_type is not None
        return [field._name for field in versions[0].struct_type.__fields__]

    def _cutoff(self, spec: VersionSpec, observable: list[str]) -> int:
        assert spec.struct_type is not None
        names = [field._name for field in spec.struct_type.__fields__]
        cutoff = -1
        for marker in observable:
            top_name = _top_level_name(marker)
            if top_name in names:
                cutoff = max(cutoff, names.index(top_name))
        if cutoff < 0:
            raise ValueError(f"None of the observable prefix fields {observable!r} exist in {spec.label} {names!r}")
        return cutoff

    def _prefix_type(self, spec: VersionSpec, observable: list[str]) -> type[Structure]:
        return _copy_prefix_type(spec, self._cutoff(spec, observable), self._prefix_cache)

    def _selected_paths(self, expected: dict[str, PathObservation], observable: list[str]) -> set[str]:
        top_names = {_top_level_name(marker) for marker in observable}
        selected: set[str] = set()
        for path in expected:
            root = _top_level_name(path)
            if root in top_names:
                selected.add(path)
        return selected

    def _check_generated_sample(
        self,
        origin: VersionSpec,
        versions: list[VersionSpec],
        plan_index: int,
        observable: list[str],
    ) -> SampleReport:
        assert origin.struct_type is not None
        plan = SAMPLE_PLANS[plan_index]
        sample_id = f"{origin.label}-{plan['name']}"
        try:
            generator = SampleGenerator(plan_index)
            obj, expected = generator.generate(origin.struct_type)
            data = obj.dumps()
        except Exception as exc:
            return SampleReport(
                sample_id=sample_id,
                origin=origin.label,
                description="deterministic ordinary sample",
                hex="",
                length=0,
                status="generation-error",
                generation_error=f"{type(exc).__name__}: {exc}",
            )

        return self._evaluate_sample(
            sample_id,
            origin.label,
            "deterministic ordinary sample",
            data,
            expected,
            versions,
            observable,
        )

    def _check_raw_sample(
        self,
        label: str,
        data: bytes,
        versions: list[VersionSpec],
        observable: list[str],
    ) -> SampleReport:
        baseline = versions[0]
        prefix_type = self._prefix_type(baseline, observable)
        baseline_parse = _parse(data, prefix_type, baseline.label, "prefix")
        expected = baseline_parse.paths if baseline_parse.ok else {}
        return self._evaluate_sample(
            f"raw-{label}",
            baseline.label,
            "user-supplied wire sample",
            bytes(data),
            expected,
            versions,
            observable,
            raw_baseline=baseline_parse if not baseline_parse.ok else None,
            require_origin_exact=False,
        )

    def _evaluate_sample(
        self,
        sample_id: str,
        origin_label: str,
        description: str,
        data: bytes,
        expected: dict[str, PathObservation],
        versions: list[VersionSpec],
        observable: list[str],
        raw_baseline: ParseObservation | None = None,
        require_origin_exact: bool = True,
    ) -> SampleReport:
        parses: dict[str, ParseObservation] = {}
        differences: list[Difference] = []
        applicable: list[str] = []
        constraints: list[str] = []
        full_read_versions: list[str] = []
        exact_read_versions: list[str] = []
        dispositions: dict[str, str] = {}

        for spec in versions:
            assert spec.struct_type is not None
            prefix_type = self._prefix_type(spec, observable)
            prefix_parse = _parse(data, prefix_type, spec.label, "prefix")
            parses[f"{spec.label}:prefix"] = prefix_parse
            full_parse = _parse(data, spec.struct_type, spec.label, "full")
            parses[f"{spec.label}:full"] = full_parse

            selected = self._selected_paths(expected, observable)
            prefix_differences = _compare_paths(
                expected,
                prefix_parse,
                paths=selected,
                version=f"{spec.label}:prefix",
            )
            if raw_baseline is not None and spec is versions[0]:
                differences.append(Difference("<parse>", "parse", None, raw_baseline.error, "baseline prefix failed"))
            differences.extend(prefix_differences)

            if prefix_parse.ok and not prefix_differences:
                applicable.append(spec.label)
                constraints.append(spec.effective_constraint())

            if full_parse.ok:
                full_read_versions.append(spec.label)
                if full_parse.consumed == len(data):
                    exact_read_versions.append(spec.label)
                    dispositions[spec.label] = "exact"
                else:
                    dispositions[spec.label] = f"trailing {len(data) - (full_parse.consumed or 0)} bytes ignored"
            elif prefix_parse.ok:
                dispositions[spec.label] = "prefix readable; full tail read failed"
            else:
                dispositions[spec.label] = "prefix read failed"

        origin_full = parses[f"{origin_label}:full"]
        if not origin_full.ok:
            differences.append(
                Difference("<full-read>", "parse", None, origin_full.error, "origin declaration cannot read sample")
            )
        else:
            full_differences = _compare_paths(expected, origin_full, version=f"{origin_label}:full")
            differences.extend(full_differences)
            if require_origin_exact and origin_full.consumed != len(data):
                differences.append(
                    Difference(
                        "<consumed>",
                        "trailing-bytes",
                        len(data),
                        origin_full.consumed,
                        "origin read did not consume the generated sample",
                    )
                )

        unique_differences = _dedupe_differences(differences)
        status: SampleStatus = "compatible" if not unique_differences else "incompatible"
        return SampleReport(
            sample_id=sample_id,
            origin=origin_label,
            description=description,
            hex=data.hex(),
            length=len(data),
            status=status,
            applicable_versions=applicable,
            applicable_constraints=constraints,
            full_read_versions=full_read_versions,
            exact_read_versions=exact_read_versions,
            read_dispositions=dispositions,
            parses=parses,
            differences=unique_differences,
        )

    def _suggest_constraint(self, versions: list[VersionSpec], compatible: bool) -> str | None:
        if not compatible or not versions:
            return None
        first = versions[0].version or versions[0].label
        match = re.match(r"^(\d+)\.(\d+)(?:\.\d+)?$", first)
        if not match:
            return " && ".join(version.effective_constraint() for version in versions)
        major = int(match.group(1))
        return f">={first},<{major + 1}.0"


def _dedupe_differences(differences: Sequence[Difference]) -> list[Difference]:
    seen: set[tuple[str, str, str | None, str | None]] = set()
    result: list[Difference] = []
    for difference in differences:
        key = (
            difference.version,
            difference.path,
            difference.kind,
            repr(difference.expected),
            repr(difference.actual),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(difference)
    return result


def verify_compatibility(
    old_cdef: str | VersionSpec | type[Structure],
    new_cdef: str | VersionSpec | type[Structure],
    struct_name: str | None = None,
    *,
    observable: str | Sequence[str] | None = None,
    old_label: str = "v1",
    new_label: str = "v2",
    old_constraint: str | None = None,
    new_constraint: str | None = None,
    old_version: str | None = "1.0",
    new_version: str | None = "1.1",
    samples_per_version: int = 2,
    extra_samples: Sequence[bytes | tuple[str, bytes]] | None = None,
    endian: str = "<",
) -> CompatibilityReport:
    """Compare two cstruct declarations and generate offline sample checks."""
    old_spec = _coerce_version(
        old_cdef,
        old_label,
        constraint=old_constraint,
        version=old_version,
        endian=endian,
    )
    new_spec = _coerce_version(
        new_cdef,
        new_label,
        constraint=new_constraint,
        version=new_version,
        endian=endian,
    )
    name = struct_name or _struct_name_from_spec(old_spec)
    verifier = CompatibilityVerifier(
        name,
        old_spec,
        new_spec,
        observable=observable,
        endian=endian,
        samples_per_version=samples_per_version,
        extra_samples=extra_samples,
    )
    return verifier.check()


def _coerce_version(
    value: str | VersionSpec | type[Structure],
    label: str,
    *,
    constraint: str | None,
    version: str | None,
    endian: str,
) -> VersionSpec:
    if isinstance(value, VersionSpec):
        return value
    if isinstance(value, str):
        return VersionSpec(
            label=label,
            cdef=value,
            constraint=constraint,
            version=version,
            endian=endian,
        )
    if isinstance(value, type) and issubclass(value, Structure):
        return VersionSpec(
            label=label,
            struct_type=value,
            constraint=constraint,
            version=version,
            endian=endian,
        )
    raise TypeError("version must be a cdef string, VersionSpec, or Structure class")


def _struct_name_from_spec(spec: VersionSpec) -> str:
    if spec.struct_type is not None:
        return spec.struct_type.__name__
    raise ValueError("struct_name is required when declarations are cdef strings")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline compatibility checker from cdef file arguments."""
    parser = argparse.ArgumentParser(description="Check append compatibility for two dissect.cstruct cdef files.")
    parser.add_argument("old_cdef", type=Path, help="Path to the baseline cdef file")
    parser.add_argument("new_cdef", type=Path, help="Path to the candidate cdef file")
    parser.add_argument("struct_name", help="Structure name to compare")
    parser.add_argument(
        "--observable",
        action="append",
        default=[],
        help="Observable prefix field; may be repeated or comma-separated",
    )
    parser.add_argument("--old-label", default="v1")
    parser.add_argument("--new-label", default="v2")
    parser.add_argument("--old-constraint")
    parser.add_argument("--new-constraint")
    parser.add_argument("--old-version", default="1.0")
    parser.add_argument("--new-version", default="1.1")
    parser.add_argument("--samples", type=int, default=2)
    parser.add_argument("--endian", default="<")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    args = parser.parse_args(argv)

    observable = [item for value in args.observable for item in value.split(",") if item]
    report = verify_compatibility(
        args.old_cdef.read_text(encoding="utf-8"),
        args.new_cdef.read_text(encoding="utf-8"),
        args.struct_name,
        observable=observable or None,
        old_label=args.old_label,
        new_label=args.new_label,
        old_constraint=args.old_constraint,
        new_constraint=args.new_constraint,
        old_version=args.old_version,
        new_version=args.new_version,
        samples_per_version=args.samples,
        endian=args.endian,
    )
    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(report.markdown())
    return 0 if report.compatible else 1


__all__ = [
    "CompatibilityReport",
    "CompatibilityVerifier",
    "Difference",
    "FieldConstraint",
    "Finding",
    "ParseObservation",
    "PathObservation",
    "SampleGenerator",
    "SampleReport",
    "VersionSpec",
    "main",
    "markers_from_cdef",
    "verify_compatibility",
]


if __name__ == "__main__":
    raise SystemExit(main())
