from __future__ import annotations

import json
from dataclasses import dataclass, field
from io import BytesIO
from typing import TYPE_CHECKING, Any

from dissect.cstruct.compiler import compile_structure
from dissect.cstruct.types.base import EOF, BaseArray, _is_eof
from dissect.cstruct.types.char import CharArray
from dissect.cstruct.types.enum import EnumMetaType
from dissect.cstruct.types.structure import Structure, StructureMetaType, UnionMetaType
from dissect.cstruct.types.void import VoidArray
from dissect.cstruct.types.wchar import WcharArray
from dissect.cstruct.util import normalize_endianness

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import BinaryIO

    from typing_extensions import Self

    from dissect.cstruct.cstruct import AllowedEndianness, Endianness

_MISSING = object()


class Span(tuple[int, int]):
    """Half-open [start, end) range."""

    __slots__ = ()

    def __new__(cls, start: int, end: int) -> Self:
        return tuple.__new__(cls, (int(start), int(end)))

    @property
    def start(self) -> int:
        return self[0]

    @property
    def end(self) -> int:
        return self[1]

    @property
    def offset(self) -> int:
        return self.start

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def length(self) -> int:
        return self.size

    @property
    def range(self) -> Span:
        return self

    def __eq__(self, other: object) -> bool:
        if tuple.__eq__(self, other):
            return True
        if isinstance(other, tuple) and len(other) == 2:
            return other == (self.start, self.size)
        if isinstance(other, range):
            return other.start == self.start and other.stop == self.end and other.step == 1
        if isinstance(other, slice):
            return other.start == self.start and other.stop == self.end and other.step is None
        return NotImplemented

    def to_dict(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end, "offset": self.start, "size": self.size}


@dataclass(eq=False)
class Segment:
    """Categorized interval."""

    start: int
    end: int
    kind: str
    path: str | None = None
    name: str | None = None
    type_name: str | None = None
    reason: str | None = None
    alignment: int | None = None

    def __iter__(self):
        yield self.start
        yield self.end

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Segment):
            return self.start == other.start and self.end == other.end and self.kind == other.kind
        if isinstance(other, tuple) and len(other) == 2:
            return other in ((self.start, self.end), (self.start, self.size))
        if isinstance(other, range):
            return other.start == self.start and other.stop == self.end and other.step == 1
        return NotImplemented

    @property
    def offset(self) -> int:
        return self.start

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def span(self) -> Span:
        return Span(self.start, self.end)

    @property
    def range(self) -> Span:
        return self.span

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "offset": self.start,
            "size": self.size,
            "kind": self.kind,
            "path": self.path,
            "name": self.name,
            "type": self.type_name,
            "reason": self.reason,
        }


@dataclass
class FieldLayout:
    """Layout evidence for a field or array element."""

    path: str
    name: str | None
    kind: str
    type_name: str | None
    start: int | None
    end: int | None
    size: int | None = None
    alignment: int | None = None
    declared_offset: int | None = None
    endianness: str | None = None
    bits: int | None = None
    value: Any = None
    raw: bytes | None = field(default=None, repr=False, compare=False)
    children: list[FieldLayout] = field(default_factory=list)
    padding: list[Segment] = field(default_factory=list)

    @property
    def offset(self) -> int | None:
        return self.start

    @property
    def span(self) -> Span | None:
        return None if self.start is None or self.end is None else Span(self.start, self.end)

    @property
    def range(self) -> Span | None:
        return self.span

    @property
    def byte_range(self) -> Span | None:
        return self.span

    @property
    def real_start(self) -> int | None:
        return self.start

    @property
    def real_end(self) -> int | None:
        return self.end

    @property
    def fields(self) -> list[FieldLayout]:
        return self.children

    def walk(self) -> Iterable[FieldLayout]:
        yield self
        for child in self.children:
            yield from child.walk()

    def find(self, path: str) -> FieldLayout | None:
        return next((node for node in self.walk() if node.path == path), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "kind": self.kind,
            "type": self.type_name,
            "start": self.start,
            "end": self.end,
            "size": self.size,
            "value": _serializable_value(self.value),
            "children": [child.to_dict() for child in self.children],
            "padding": [item.to_dict() for item in self.padding],
        }

    def __getitem__(self, key: str) -> Any:
        if key in {"path", "name", "kind", "start", "end", "size", "value", "children", "padding"}:
            return getattr(self, key)
        if key in {"offset", "range", "span"}:
            return self.span
        raise KeyError(key)


@dataclass
class LayoutEvidence:
    """Field ranges, padding and unconsumed bytes for one binary page."""

    cls: type[Structure]
    root: FieldLayout
    data: bytes = field(repr=False)
    endianness: Endianness = "<"
    declared_endianness: Endianness = "<"
    align: bool = False
    alignment: int = 1
    declared_size: int | None = None
    consumed: int = 0
    segments: list[Segment] = field(default_factory=list)
    padding: list[Segment] = field(default_factory=list)
    unconsumed: Segment | None = None
    label: str | None = None
    base_offset: int = 0
    parsed: Any = field(default=None, repr=False, compare=False)
    nodes: dict[str, FieldLayout] = field(default_factory=dict, repr=False, compare=False)

    @property
    def name(self) -> str:
        return self.cls.__name__

    @property
    def fields(self) -> list[FieldLayout]:
        return self.root.children

    @property
    def size(self) -> int:
        return self.consumed

    @property
    def buffer_size(self) -> int:
        return len(self.data)

    @property
    def unconsumed_size(self) -> int:
        return 0 if self.unconsumed is None else self.unconsumed.size

    @property
    def span(self) -> Span:
        return Span(self.base_offset, self.base_offset + self.consumed)

    @property
    def range(self) -> Span:
        return self.span

    @property
    def field_ranges(self) -> dict[str, Span]:
        return {
            path: node.span
            for path, node in self.nodes.items()
            if path and node.span is not None and node.kind != "bitfield"
        }

    @property
    def flat_fields(self) -> list[FieldLayout]:
        return [node for node in self.root.walk() if node is not self.root]

    @property
    def field_layouts(self) -> list[FieldLayout]:
        return self.flat_fields

    @property
    def ranges(self) -> list[Segment]:
        return self.segments

    @property
    def entries(self) -> list[Segment]:
        return self.segments

    @property
    def records(self) -> list[Segment]:
        return self.segments

    @property
    def actual_ranges(self) -> dict[str, Span]:
        return self.field_ranges

    @property
    def real_ranges(self) -> dict[str, Span]:
        return self.field_ranges

    @property
    def read_ranges(self) -> dict[str, Span]:
        return self.field_ranges

    @property
    def padding_ranges(self) -> list[Segment]:
        return self.padding

    @property
    def unconsumed_range(self) -> Span | None:
        return None if self.unconsumed is None else self.unconsumed.span

    @property
    def unconsumed_bytes(self) -> bytes:
        if self.unconsumed is None:
            return b""
        return self.data[self.unconsumed.start : self.unconsumed.end]

    @property
    def remaining(self) -> Segment | None:
        return self.unconsumed

    def find(self, path: str) -> FieldLayout | None:
        return self.nodes.get(path) or self.root.find(path)

    def get(self, path: str) -> FieldLayout:
        node = self.find(path)
        if node is None:
            raise KeyError(path)
        return node

    def range_for(self, path: str) -> Span:
        node = self.get(path)
        if node.span is None:
            raise KeyError(path)
        return node.span

    def canonical(self) -> dict[str, Any]:
        return {
            "endianness": self.endianness,
            "align": self.align,
            "consumed": self.consumed,
            "segments": [(s.start, s.end, s.kind, s.path) for s in self.segments],
            "field_ranges": {path: tuple(span) for path, span in self.field_ranges.items()},
            "padding": [tuple(s.span) for s in self.padding],
            "unconsumed": tuple(self.unconsumed.span) if self.unconsumed else None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "name": self.name,
            "endianness": self.endianness,
            "align": self.align,
            "alignment": self.alignment,
            "consumed": self.consumed,
            "buffer_size": self.buffer_size,
            "unconsumed": self.unconsumed.to_dict() if self.unconsumed else None,
            "root": self.root.to_dict(),
            "segments": [segment.to_dict() for segment in self.segments],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    def __getitem__(self, key: str) -> Any:
        if key in {"name", "align", "alignment", "consumed", "segments", "padding", "unconsumed", "label"}:
            return getattr(self, key)
        if key in {"endian", "endianness"}:
            return self.endianness
        if key == "fields":
            return self.fields
        if key == "field_ranges":
            return self.field_ranges
        raise KeyError(key)

    def explain(self) -> str:
        return _format_evidence(self)

    def __str__(self) -> str:
        return self.explain()


@dataclass
class LayoutReconciliation:
    """Compiled/interpeted reconciliation result."""

    evidence: LayoutEvidence
    interpreted_object: Any = None
    compiled_object: Any = None
    interpreted_consumed: int | None = None
    compiled_consumed: int | None = None
    compiled_backend: str = "unknown"
    values_match: bool = False
    consumed_match: bool = False
    differences: list[str] = field(default_factory=list)

    @property
    def matches(self) -> bool:
        return not self.differences and self.values_match and self.consumed_match

    def assert_matches(self) -> None:
        if not self.matches:
            raise AssertionError("\n".join(self.differences))


@dataclass
class EvidenceComparison:
    """Comparison between two device samples."""

    left: LayoutEvidence
    right: LayoutEvidence
    same_structure_name: bool
    same_values: bool
    same_ranges: bool
    common_paths: list[str]
    equal_value_paths: list[str]
    shared_range_paths: list[str]
    range_differences: list[dict[str, Any]]
    reasons: list[str]
    value_differences: list[str] = field(default_factory=list)

    @property
    def can_share_physical_range(self) -> bool:
        return False

    @property
    def same_physical_range(self) -> bool:
        return self.same_ranges

    def shares_physical_range(self) -> bool:
        return False

    @property
    def explanation(self) -> str:
        return "\n".join(self.reasons)

    def explain(self) -> str:
        return self.explanation


class _LayoutTracer:
    def __init__(self, cls: type[Structure], data: bytes, *, endian: Endianness, label: str | None) -> None:
        self.cls = cls
        self.data = data
        self.stream = BytesIO(data)
        self.endian = endian
        self.label = label
        self.segments: list[Segment] = []
        self.padding: list[Segment] = []
        self.nodes: dict[str, FieldLayout] = {}

    def build(self) -> LayoutEvidence:
        root, parsed = self._trace_type(
            self.cls, path="", name=self.cls.__name__, context=None, declared_offset=0, alignment=None
        )
        consumed = self.stream.tell()
        unconsumed = None
        if consumed < len(self.data):
            unconsumed = Segment(consumed, len(self.data), "unconsumed", "<unconsumed>", "<unconsumed>")
            self.segments.append(unconsumed)
        root.start, root.end, root.size = 0, consumed, consumed
        root.raw = self.data[:consumed]
        return LayoutEvidence(
            cls=self.cls,
            root=root,
            data=self.data,
            endianness=self.endian,
            declared_endianness=self.cls.__cs__.endian,
            align=bool(getattr(self.cls, "__align__", False)),
            alignment=self.cls.__alignment__ or 1,
            declared_size=self.cls.__size__,
            consumed=consumed,
            segments=sorted(self.segments, key=lambda s: (s.start, s.end, s.kind)),
            padding=list(self.padding),
            unconsumed=unconsumed,
            label=self.label,
            parsed=parsed,
            nodes=self.nodes,
        )

    def _trace_type(
        self,
        type_: type[Any],
        *,
        path: str,
        name: str | None,
        context: dict[str, Any] | None,
        declared_offset: int | None,
        alignment: int | None,
    ) -> tuple[FieldLayout, Any]:
        if isinstance(type_, StructureMetaType) and not isinstance(type_, UnionMetaType):
            return self._trace_structure(type_, path=path, name=name, declared_offset=declared_offset)
        if issubclass(type_, BaseArray):
            return self._trace_array(type_, path=path, name=name, context=context, declared_offset=declared_offset)
        return self._trace_leaf(type_, path=path, name=name, context=context, declared_offset=declared_offset)

    def _trace_leaf(
        self,
        type_: type[Any],
        *,
        path: str,
        name: str | None,
        context: dict[str, Any] | None,
        declared_offset: int | None,
    ) -> tuple[FieldLayout, Any]:
        start = self.stream.tell()
        value = type_._read(self.stream, context=context, endian=self.endian)
        end = self.stream.tell()
        self.segments.append(Segment(start, end, "field", path or None, name, type_.__name__))
        node = FieldLayout(
            path,
            name,
            "value",
            type_.__name__,
            start,
            end,
            end - start,
            type_.__alignment__,
            declared_offset,
            self.endian,
            value=value,
            raw=self.data[start:end],
        )
        self._remember(node)
        return node, value

    def _trace_structure(
        self,
        type_: type[Structure],
        *,
        path: str,
        name: str | None,
        declared_offset: int | None,
    ) -> tuple[FieldLayout, Any]:
        start = struct_start = self.stream.tell()
        values: dict[str, Any] = {}
        children: list[FieldLayout] = []
        structure_padding: list[Segment] = []
        bit_buffer = None
        bit_storage_start: int | None = None
        bit_storage_end: int | None = None

        for cfield in type_.__fields__:
            current = self.stream.tell()
            target = struct_start + cfield.offset if cfield.offset is not None else current
            if cfield.offset is None and type_.__align__:
                alignment = cfield.alignment or 1
                target += -target & (alignment - 1)
            if target > current:
                padding = self._padding(current, target, path or type_.__name__, cfield.alignment)
                structure_padding.append(padding)
            if target != current:
                self.stream.seek(target)

            field_path = _join(path, cfield._name)
            if cfield.bits:
                if bit_buffer is None:
                    from dissect.cstruct.bitbuffer import BitBuffer

                    bit_buffer = BitBuffer(self.stream, endian=self.endian)
                read_type = cfield.type.__type__ if isinstance(cfield.type, EnumMetaType) else cfield.type
                starts_storage = bit_buffer._remaining == 0 or bit_buffer._type != read_type
                if starts_storage:
                    bit_storage_start = self.stream.tell()
                raw_value = bit_buffer.read(read_type, cfield.bits)
                value = cfield.type(raw_value) if isinstance(cfield.type, EnumMetaType) else raw_value
                if starts_storage:
                    bit_storage_end = self.stream.tell()
                    self.segments.append(
                        Segment(
                            bit_storage_start,
                            bit_storage_end,
                            "field",
                            field_path,
                            cfield._name,
                            read_type.__name__,
                        )
                    )
                storage_start = bit_storage_start if bit_storage_start is not None else self.stream.tell()
                storage_end = bit_storage_end if bit_storage_end is not None else storage_start
                node = FieldLayout(
                    field_path,
                    cfield.name or cfield._name,
                    "bitfield",
                    cfield.type.__name__,
                    storage_start,
                    storage_end,
                    read_type.__size__,
                    cfield.alignment,
                    cfield.offset,
                    self.endian,
                    cfield.bits,
                    value,
                    self.data[storage_start:storage_end],
                )
                children.append(node)
                self._remember(node)
                values[cfield._name] = value
                continue

            if bit_buffer is not None:
                bit_buffer = None
                bit_storage_start = bit_storage_end = None
            child, value = self._trace_type(
                cfield.type,
                path=field_path,
                name=cfield.name or cfield._name,
                context=values,
                declared_offset=cfield.offset,
                alignment=cfield.alignment,
            )
            children.append(child)
            values[cfield._name] = value

        current = self.stream.tell()
        end = current
        if type_.__align__:
            alignment = type_.__alignment__ or 1
            target = current + (-current & (alignment - 1))
            if target > current:
                structure_padding.append(
                    self._padding(current, target, path or type_.__name__, alignment, reason="tail-alignment")
                )
                self.stream.seek(target)
            end = self.stream.tell()

        try:
            parsed = type.__call__(type_, **values)
        except Exception:
            parsed = values
        node = FieldLayout(
            path,
            name,
            "structure",
            type_.__name__,
            start,
            end,
            end - start,
            type_.__alignment__,
            declared_offset,
            self.endian,
            value=parsed,
            raw=self.data[start:end],
            children=children,
            padding=structure_padding,
        )
        self._remember(node)
        return node, parsed

    def _trace_array(
        self,
        type_: type[BaseArray],
        *,
        path: str,
        name: str | None,
        context: dict[str, Any] | None,
        declared_offset: int | None,
    ) -> tuple[FieldLayout, Any]:
        start = self.stream.tell()
        if type_.__null_terminated__ or issubclass(type_, (CharArray, WcharArray, VoidArray)):
            node, value = self._trace_leaf(
                type_, path=path, name=name, context=context, declared_offset=declared_offset
            )
            node.kind = "array"
            self.nodes[path] = node
            return node, value

        count = type_._num_entries(context)
        element_type = type_.__type__
        children, values = [], []
        indices = iter(int, 1) if count == EOF else range(max(0, count))
        for index in indices:
            if count == EOF and _is_eof(self.stream):
                break
            child, value = self._trace_type(
                element_type,
                path=f"{path}[{index}]",
                name=f"[{index}]",
                context=context,
                declared_offset=None,
                alignment=element_type.__alignment__,
            )
            children.append(child)
            values.append(value)
        end = self.stream.tell()
        try:
            value = type_(values)
        except Exception:
            value = values
        node = FieldLayout(
            path,
            name,
            "array",
            type_.__name__,
            start,
            end,
            end - start,
            type_.__alignment__,
            declared_offset,
            self.endian,
            value=value,
            raw=self.data[start:end],
            children=children,
        )
        self._remember(node)
        return node, value

    def _padding(self, start: int, end: int, owner: str, alignment: int | None, reason: str = "alignment") -> Segment:
        segment = Segment(
            start, end, "padding", f"{owner}.<padding:{start}>", "<padding>", reason=reason, alignment=alignment
        )
        self.segments.append(segment)
        self.padding.append(segment)
        return segment

    def _remember(self, node: FieldLayout) -> None:
        if node.path:
            self.nodes[node.path] = node


def _join(parent: str, name: str) -> str:
    return name if not parent else f"{parent}{name}" if name.startswith("[") else f"{parent}.{name}"


def _coerce_data(data: Any) -> bytes:
    if data is None:
        raise ValueError("data is required")
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    if hasattr(data, "read"):
        return bytes(data.read())
    raise TypeError(f"unsupported data: {type(data).__name__}")


def _resolve(target: type[Structure] | Structure) -> type[Structure]:
    if isinstance(target, type) and issubclass(target, Structure):
        return target
    if isinstance(target, Structure):
        return target.__class__
    raise TypeError("expected a Structure class or instance")


def layout_evidence(
    target: type[Structure] | Structure,
    data: bytes | bytearray | memoryview | BinaryIO | None = None,
    *,
    endian: AllowedEndianness | None = None,
    label: str | None = None,
    base_offset: int = 0,
) -> LayoutEvidence:
    """Build field layout evidence from a structure type and binary page."""
    cls = _resolve(target)
    if data is None and isinstance(target, Structure):
        data = target.dumps()
    raw = _coerce_data(data)
    used_endian = normalize_endianness(endian) if endian is not None else cls.__cs__.endian
    tracer = _LayoutTracer(cls, raw, endian=used_endian, label=label)
    evidence = tracer.build()
    evidence.base_offset = base_offset
    return evidence


def reconcile_layout(target: Any, data: Any, *, endian: AllowedEndianness | None = None) -> LayoutReconciliation:
    """Read through interpreted and compiled entry points and compare the results."""
    cls = _resolve(target)
    raw = _coerce_data(data)
    evidence = layout_evidence(cls, raw, endian=endian)
    used_endian = evidence.endianness
    differences: list[str] = []

    interp_obj = interp_pos = None
    try:
        stream = BytesIO(raw)
        interp_obj = type(cls)._read(cls, stream, context=None, endian=used_endian)
        interp_pos = stream.tell()
    except Exception as exc:
        differences.append(f"interpreted failed: {type(exc).__name__}: {exc}")

    compiled_obj = compiled_pos = None
    saved_read, saved_compiled = cls.__dict__.get("_read", _MISSING), cls.__dict__.get("__compiled__", _MISSING)
    backend = "interpreted-fallback"
    try:
        compile_structure(cls)
        stream = BytesIO(raw)
        compiled_obj = cls._read(stream, context=None, endian=used_endian)
        compiled_pos = stream.tell()
        backend = "compiled" if cls.__dict__.get("__compiled__", getattr(cls, "__compiled__", False)) else backend
    except Exception as exc:
        differences.append(f"compiled failed: {type(exc).__name__}: {exc}")
    finally:
        if saved_read is _MISSING:
            with _ignore_attribute_error():
                del cls._read
        else:
            cls._read = saved_read
        if saved_compiled is _MISSING:
            with _ignore_attribute_error():
                del cls.__compiled__
        else:
            cls.__compiled__ = saved_compiled

    values_match = (
        interp_obj is not None
        and compiled_obj is not None
        and (_canonical(interp_obj) == _canonical(compiled_obj) or interp_obj == compiled_obj)
    )
    if interp_obj is not None and compiled_obj is not None and not values_match:
        differences.append("field values differ between compiled and interpreted reads")
    consumed_match = interp_pos == compiled_pos == evidence.consumed
    if not consumed_match:
        differences.append(
            f"consumed differs: evidence={evidence.consumed}, interpreted={interp_pos}, compiled={compiled_pos}"
        )
    return LayoutReconciliation(
        evidence, interp_obj, compiled_obj, interp_pos, compiled_pos, backend, values_match, consumed_match, differences
    )


class _ignore_attribute_error:
    def __enter__(self) -> None:
        pass

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        return exc_type is None or issubclass(exc_type, AttributeError)


def compare_evidence(
    left: LayoutEvidence,
    right: LayoutEvidence,
    *,
    distinct_buffer: bool = True,
) -> EvidenceComparison:
    """Explain why equal values in two samples do not imply one physical range."""
    common = sorted(set(left.field_ranges) & set(right.field_ranges))
    equal_values, shared_ranges, range_diffs = [], [], []
    value_diffs = []
    for path in common:
        ln, rn = left.get(path), right.get(path)
        same_value = _values_equal(ln.value, rn.value)
        same_range = ln.span == rn.span
        equal_values.append(path) if same_value else value_diffs.append(path)
        shared_ranges.append(path) if same_range else range_diffs.append(
            {"path": path, "left": tuple(ln.span), "right": tuple(rn.span), "values_equal": same_value}
        )
    same_values = not value_diffs and bool(common)
    same_ranges = not range_diffs and set(left.field_ranges) == set(right.field_ranges)
    reasons = (
        [f"structure name {left.name!r} is equal, but a name is not a byte offset"] if left.name == right.name else []
    )
    reasons.extend(
        f"{item['path']}: equal decoded value, but ranges {item['left']} != {item['right']}"
        for item in [x for x in range_diffs if x["values_equal"]][:3]
    )
    if left.padding != right.padding:
        reasons.append("padding intervals differ")
    if distinct_buffer:
        reasons.append("distinct device buffers cannot be the same physical bytes")
    if range_diffs:
        reasons.append("different alignment maps the same fields to different offsets")
    return EvidenceComparison(
        left,
        right,
        left.name == right.name,
        same_values,
        same_ranges,
        common,
        equal_values,
        shared_ranges,
        range_diffs,
        reasons,
        value_diffs,
    )


def _values_equal(left: Any, right: Any) -> bool:
    try:
        if bool(left == right):
            return True
    except Exception:
        pass
    return _canonical(left) == _canonical(right)


def _canonical(value: Any) -> Any:
    if isinstance(value, Structure):
        return type(value).__name__, {k: _canonical(v) for k, v in value.__values__.items()}
    if hasattr(value, "__target__") and hasattr(value, "__attr__"):
        return "proxy", getattr(value, "__attr__", None), _canonical(value.__target__)
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return value


def _serializable_value(value: Any) -> Any:
    result = _canonical(value)
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return {"__type__": result[0], "fields": result[1]}
    return result


def _format_evidence(ev: LayoutEvidence) -> str:
    lines = [f"{ev.label or ev.name} endian={ev.endianness} align={ev.align} consumed={ev.consumed}/{ev.buffer_size}"]
    for segment in ev.segments:
        if segment.kind != "field":
            detail = segment.kind + (f" ({segment.reason})" if segment.reason else "")
        else:
            node = ev.find(segment.path or "")
            value = f" value={node.value!r}" if node is not None else ""
            detail = f"field {segment.type_name}{value}"
        lines.append(f"[{segment.start:04d},{segment.end:04d}) {segment.path}: {detail}")
    return "\n".join(lines)


def explain_layout(target: Any, data: Any = None, *, endian: Any = None) -> str:
    if isinstance(target, LayoutEvidence):
        return target.explain()
    return layout_evidence(target, data, endian=endian).explain()


def verify_layout_paths(target: Any, data: Any, *, endian: Any = None) -> LayoutReconciliation:
    result = reconcile_layout(target, data, endian=endian)
    result.assert_matches()
    return result


def field_layouts(target: Any, data: Any = None, **kwargs: Any) -> list[FieldLayout]:
    """Return flattened field layout nodes."""
    return layout_evidence(target, data, **kwargs).field_layouts


def get_field_ranges(target: Any, data: Any = None, **kwargs: Any) -> dict[str, Span]:
    """Return field paths mapped to half-open ranges."""
    return layout_evidence(target, data, **kwargs).field_ranges


class EvidenceRegistry:
    """Small registry for device samples and their layout evidence."""

    def __init__(self) -> None:
        self._items: dict[str, LayoutEvidence] = {}

    def register(self, key: str, target: Any, data: Any = None, **kwargs: Any) -> LayoutEvidence:
        evidence = layout_evidence(target, data, label=kwargs.pop("label", key), **kwargs)
        self._items[key] = evidence
        return evidence

    add = register

    def get(self, key: str) -> LayoutEvidence:
        return self._items[key]

    def compare(self, left: str | LayoutEvidence, right: str | LayoutEvidence, **kwargs: Any) -> EvidenceComparison:
        left_evidence = left if isinstance(left, LayoutEvidence) else self._items[left]
        right_evidence = right if isinstance(right, LayoutEvidence) else self._items[right]
        return compare_evidence(left_evidence, right_evidence, **kwargs)

    def reconcile(self, key: str, data: Any = None, **kwargs: Any) -> LayoutReconciliation:
        evidence = self._items[key]
        return reconcile_layout(evidence.cls, data if data is not None else evidence.data, **kwargs)

    def __getitem__(self, key: str) -> LayoutEvidence:
        return self._items[key]


inspect_layout = trace_layout = field_layout_evidence = field_layout = layoutstruct = layout_evidence
build_layout_evidence = collect_layout_evidence = generate_layout_evidence = create_layout_evidence = layout_evidence
describe_layout = layout_evidence
LayoutReport = LayoutEvidence
FieldLayoutEvidence = Evidence = Layout = LayoutEvidence
FieldEvidence = FieldLayout
FieldRange = LayoutRange = Segment
PathReconciliation = ReconciliationReport = LayoutReconciliation
LayoutComparison = EvidenceComparison
reconcile = audit_layout = reconcile_layout
compare_layouts = diff_layouts = compare_evidence
assert_layouts_match = verify_layout_paths
reconcile_compiled_and_interpreted = reconcile_layout
compare_compiled_and_interpreted = reconcile_layout
verify_compiled_and_interpreted = verify_layout_paths
field_layout_reconciliation = LayoutReconciliation
ReadRange = Segment
ActualRange = Span


__all__ = [
    "Evidence",
    "EvidenceComparison",
    "EvidenceRegistry",
    "FieldEvidence",
    "FieldLayout",
    "FieldLayoutEvidence",
    "FieldRange",
    "Layout",
    "LayoutEvidence",
    "LayoutRange",
    "LayoutReconciliation",
    "LayoutReport",
    "PathReconciliation",
    "Segment",
    "Span",
    "assert_layouts_match",
    "audit_layout",
    "build_layout_evidence",
    "compare_evidence",
    "compare_layouts",
    "create_layout_evidence",
    "describe_layout",
    "diff_layouts",
    "explain_layout",
    "field_layout_evidence",
    "field_layouts",
    "generate_layout_evidence",
    "get_field_ranges",
    "inspect_layout",
    "layout_evidence",
    "layoutstruct",
    "reconcile",
    "reconcile_layout",
    "trace_layout",
    "verify_layout_paths",
]
