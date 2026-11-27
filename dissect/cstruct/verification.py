from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from io import BytesIO
from typing import Any

from dissect.cstruct.bitbuffer import BitBuffer
from dissect.cstruct.expression import Expression
from dissect.cstruct.types.base import BaseArray, BaseType
from dissect.cstruct.types.char import Char
from dissect.cstruct.types.enum import EnumMetaType
from dissect.cstruct.types.structure import Field, Structure, StructureMetaType, UnionMetaType
from dissect.cstruct.types.wchar import Wchar


Range = tuple[int, int]


@dataclass(frozen=True, slots=True)
class CollectionMethod:
    """An approved collection method and the byte ranges it preserved."""

    name: str
    ranges: tuple[Range, ...]

    def __init__(self, name: str, ranges: Range | Sequence[Range]):
        normalized = _coerce_ranges(ranges)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "ranges", tuple(_normalize_range(r) for r in normalized))


@dataclass(frozen=True, slots=True)
class Observation:
    """A contiguous byte range observed while proving a claim."""

    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class FieldClaim:
    """A field value that can be proven without leaving a preserved range."""

    path: str
    value: Any
    observations: tuple[Observation, ...]
    dependencies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnprovableField:
    """A field that cannot be fully proven from the available observations."""

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """The provable part of a structure for one collection method."""

    method: str
    claims: tuple[FieldClaim, ...]
    unprovable: tuple[UnprovableField, ...]
    observations: tuple[Observation, ...]


class _BoundedStream:
    def __init__(
        self,
        stream: BytesIO,
        ranges: tuple[Range, ...],
        parent: _BoundedStream | None = None,
        data_end: int | None = None,
    ):
        self._stream = stream
        self._ranges = merge_ranges(ranges)
        self._position = stream.tell()
        self._observations: list[Range] = []
        self._parents = ([*parent._parents, parent] if parent else [])
        self._data_end = (
            data_end if data_end is not None else (parent._data_end if parent else stream.seek(0, 2))
        )

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(Observation(start, end) for start, end in merge_ranges(self._observations))

    def seekable(self) -> bool:
        return True

    def write(self, data: bytes) -> int:
        raise OSError("Verification streams are read-only")

    def writable(self) -> bool:
        return False

    def readable(self) -> bool:
        return True

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

    @property
    def closed(self) -> bool:
        return self._stream.closed

    def fileno(self) -> int:
        return self._stream.fileno()

    def isatty(self) -> bool:
        return False

    def readline(self, size: int = -1) -> bytes:
        raise OSError("Line-based reads are not supported")

    def readlines(self, hint: int = -1) -> list[bytes]:
        raise OSError("Line-based reads are not supported")

    def truncate(self, size: int | None = None) -> int:
        raise OSError("Verification streams are read-only")

    def writelines(self, lines: Sequence[bytes]) -> None:
        raise OSError("Verification streams are read-only")

    def __enter__(self) -> _BoundedStream:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 1:
            target = self._position + offset
        elif whence == 2:
            raise ValueError("Seeking relative to the end is not supported")
        else:
            target = offset

        if target < 0:
            raise ValueError("Negative seek position")
        if whence == 0 and not any(start <= target < end for start, end in self._ranges):
            raise ValueError("Seek position is outside preserved ranges")
        self._position = target
        self._stream.seek(target)
        return self._position

    def read(self, size: int = -1) -> bytes:
        start = self._position
        available = self._available(start, size)
        if available <= 0:
            return b""

        self._stream.seek(start)
        data = self._stream.read(available)
        self._position = start + len(data)
        if data:
            observed_range = (start, self._position)
            self._observations.append(observed_range)
            for parent in self._parents:
                parent._observations.append(observed_range)
        return data

    def trim_observations(self, end: int) -> None:
        kept: list[Range] = []
        for start, observed_end in self._observations:
            if start >= end:
                continue
            kept.append((start, min(observed_end, end)))
        self._observations = kept

    def _available(self, position: int, size: int) -> int:
        for start, end in self._ranges:
            if start <= position < end:
                if size < 0:
                    return end - position
                return min(size, end - position)
        return 0

    def is_actual_eof(self) -> bool:
        actual_end = self._data_end
        return any(end == actual_end for _, end in self._ranges if self._position < end)


def verify_structure(
    structure: StructureMetaType,
    data: bytes | BytesIO,
    methods: CollectionMethod | Mapping[str, Range | Sequence[Range]] | Sequence[CollectionMethod],
) -> dict[str, VerificationResult]:
    """Verify which fields of ``structure`` are supported by each collection method.

    The input data and cstruct definitions are not modified. Every parse is wrapped in a stream that only returns
    bytes from that method's preserved ranges.
    """
    if not isinstance(structure, StructureMetaType):
        raise TypeError("structure must be a cstruct structure type")

    normalized_methods = _normalize_methods(methods)
    stream = data if isinstance(data, BytesIO) else BytesIO(data)
    base_position = stream.tell()
    stream.seek(0, 2)
    data_end = stream.tell()
    stream.seek(base_position)
    results = {}

    for method in normalized_methods:
        ranges = tuple((base_position + start, base_position + end) for start, end in method.ranges)
        stream.seek(base_position)
        bounded = _BoundedStream(stream, ranges, data_end=data_end)
        claims, unprovable = _verify_fields(structure, bounded, base_position, ())
        results[method.name] = VerificationResult(
            method=method.name,
            claims=tuple(claims),
            unprovable=tuple(unprovable),
            observations=bounded.observations,
        )

    return results


def _verify_fields(
    structure: StructureMetaType,
    parent_stream: _BoundedStream,
    base_position: int,
    parent_path: tuple[str, ...],
) -> tuple[list[FieldClaim], list[UnprovableField]]:
    claims: list[FieldClaim] = []
    unprovable: list[UnprovableField] = []
    context: dict[str, Any] = {}
    is_union = isinstance(structure, UnionMetaType)
    current_position = base_position
    pending_bits: list[tuple[Field, int]] = []
    pending_start: int | None = None

    for field in structure.__fields__:
        field_path = _join_path(parent_path, field._name)

        if field.bits:
            if not pending_bits:
                pending_start = current_position
            pending_bits.append((field, current_position))
            storage_size = field.type.__size__
            if sum(bits for _, bits in pending_bits) == storage_size * 8:
                _read_bitfield_group(
                    structure, pending_bits, pending_start, parent_stream, parent_path, claims, unprovable, context
                )
                pending_bits = []
                pending_start = None
                if not is_union:
                    current_position += storage_size
            continue

        if pending_bits:
            _read_bitfield_group(
                structure, pending_bits, pending_start, parent_stream, parent_path, claims, unprovable, context
            )
            storage_size = pending_bits[0][0].type.__size__
            pending_bits = []
            pending_start = None
            if not is_union:
                current_position += storage_size

        field_start = current_position
        if field.offset is not None:
            field_start = base_position + field.offset
        elif structure.__align__:
            field_start += -field_start & (field.alignment - 1)

        if is_union:
            field_start = base_position + (field.offset or 0)

        dependencies = _field_dependencies(field)
        dependency_paths = tuple(_join_path(parent_path, dependency) for dependency in dependencies)
        if any(path not in _claim_paths(claims) for path in dependency_paths):
            unprovable.append(UnprovableField(field_path, "undecidable"))
            if is_union:
                continue
            next_position = _advance_after_failure(structure, field, base_position, is_union)
            if next_position is None:
                break
            current_position = next_position
            continue

        try:
            field_stream = _child_stream(parent_stream, field_start)
        except ValueError:
            unprovable.append(UnprovableField(field_path, "truncated"))
            next_position = _advance_after_failure(structure, field, base_position, is_union)
            if next_position is None:
                break
            current_position = next_position
            continue
        if issubclass(field.type, Structure) and isinstance(field.type, UnionMetaType):
            nested_path = (*parent_path, field.name or field._name)
            nested_claims, nested_unprovable = _verify_fields(field.type, field_stream, field_start, nested_path)
            claims.extend(nested_claims)
            unprovable.extend(nested_unprovable)
            current_position = field_start + len(field.type)
            context[field._name] = None
        elif issubclass(field.type, Structure) and not is_union:
            nested_path = (*parent_path, field.name or field._name)
            nested_claims, nested_unprovable = _verify_fields(field.type, field_stream, field_start, nested_path)
            claims.extend(nested_claims)
            unprovable.extend(nested_unprovable)
            if not nested_unprovable:
                field_stream.seek(field_start)
                context[field._name] = field.type._read(
                    field_stream, context=context, endian=structure.__cs__.endian
                )
            if field.type.__size__ is not None:
                current_position = field_start + len(field.type)
            elif nested_unprovable:
                break
            else:
                current_position = field_stream.tell()
        else:
            if _reads_to_eof(field.type) and not field_stream.is_actual_eof():
                unprovable.append(UnprovableField(field_path, "undecidable"))
                break

            try:
                value = _read_field(field.type, field_stream, structure.__cs__.endian, context)
            except (EOFError, ValueError) as exc:
                unprovable.append(UnprovableField(field_path, _reason(exc)))
                if is_union:
                    continue
                next_position = _advance_after_failure(structure, field, base_position, is_union)
                if next_position is None:
                    break
                current_position = next_position
                continue

            observations = field_stream.observations
            claims.append(FieldClaim(field_path, value, observations, dependency_paths))

            if not is_union:
                current_position = field_stream.tell()
                context[field._name] = value

    if pending_bits:
        _read_bitfield_group(
            structure, pending_bits, pending_start, parent_stream, parent_path, claims, unprovable, context
        )

    return claims, unprovable


def _read_bitfield_group(
    structure: StructureMetaType,
    pending: list[tuple[Field, int]],
    start: int | None,
    parent_stream: _BoundedStream,
    parent_path: tuple[str, ...],
    claims: list[FieldClaim],
    unprovable: list[UnprovableField],
    context: dict[str, Any],
) -> None:
    first_field, _ = pending[0]
    field_stream = _child_stream(parent_stream, start)
    bit_buffer = BitBuffer(field_stream, endian=structure.__cs__.endian)
    try:
        values = {
            field._name: _read_bitfield_value(bit_buffer, field, structure.__cs__.endian)
            for field, _ in pending
        }
    except (EOFError, ValueError) as exc:
        for field, _ in pending:
            unprovable.append(UnprovableField(_join_path(parent_path, field._name), _reason(exc)))
        return

    observations = field_stream.observations
    for field, _ in pending:
        path = _join_path(parent_path, field._name)
        field_value = values[field._name]
        claims.append(FieldClaim(path, field_value, observations, ()))
        context[field._name] = field_value


def _read_bitfield_value(bit_buffer: BitBuffer, field: Field, endian: str) -> Any:
    field_type = field.type.__type__ if isinstance(field.type, EnumMetaType) else field.type
    value = bit_buffer.read(field_type, field.bits)
    if isinstance(field.type, EnumMetaType):
        return field.type(value)
    return value


def _child_stream(parent: _BoundedStream, position: int) -> _BoundedStream:
    child = _BoundedStream(parent._stream, parent._ranges, parent=parent, data_end=parent._data_end)
    child.seek(position)
    return child


def _reads_to_eof(field_type: BaseType) -> bool:
    while issubclass(field_type, BaseArray):
        count = field_type.__num_entries__
        if isinstance(count, Expression) and count.expression == "EOF":
            return True
        field_type = field_type.__type__
    return False


def _read_field(field_type: BaseType, stream: _BoundedStream, endian: str, context: dict[str, Any]) -> Any:
    if _is_null_terminated(field_type):
        return _read_null_terminated(field_type, stream, endian)
    return field_type._read(stream, context=context, endian=endian)


def _is_null_terminated(field_type: BaseType) -> bool:
    return issubclass(field_type, BaseArray) and field_type.__null_terminated__


def _read_null_terminated(field_type: BaseArray, stream: _BoundedStream, endian: str) -> Any:
    element_type = field_type.__type__
    width = element_type.__size__
    chunks = []

    while True:
        chunk_start = stream.tell()
        chunk = stream.read(128 * width)
        if not chunk:
            raise EOFError("Read 0 bytes, but expected a null terminator")

        chunks.append(chunk)
        terminator = b"\x00" * width
        index = chunk.find(terminator)
        while index != -1 and index % width:
            index = chunk.find(terminator, index + 1)

        if index != -1:
            end = chunk_start + index + width
            stream.seek(end)
            stream.trim_observations(end)
            raw = b"".join(chunks[:-1]) + chunk[: index + width]
            if issubclass(element_type, Wchar):
                byteorder = "little" if endian == "<" else "big"
                value = raw[:-width].decode(f"utf-16-{byteorder[0]}e", "surrogatepass")
                return str.__new__(field_type, value)
            if issubclass(element_type, Char):
                return bytes.__new__(field_type, raw[:-width])
            raise TypeError("Only character arrays support null-terminated verification")

        if len(chunk) % width:
            remainder = len(chunk) % width
            raise EOFError(f"Read {remainder} bytes, but expected {width}")


def _advance_after_failure(
    structure: StructureMetaType, field: Field, base_position: int, is_union: bool
) -> int | None:
    if is_union or field.type.__size__ is None:
        return None

    next_offset = _next_static_offset(structure, field)
    if next_offset is None:
        return None
    return base_position + next_offset


def _next_static_offset(structure: StructureMetaType, field: Field) -> int | None:
    fields = structure.__fields__
    index = fields.index(field)
    for next_field in fields[index + 1 :]:
        if next_field.offset is not None:
            return next_field.offset
    return structure.__size__


def _field_dependencies(field: Field) -> tuple[str, ...]:
    dependencies: list[str] = []
    field_type: BaseType = field.type
    cs = field.type.__cs__
    while issubclass(field_type, BaseArray):
        count = field_type.__num_entries__
        if isinstance(count, Expression):
            dependencies.extend(
                token.value
                for token in count._tokens
                if token.type.name == "IDENTIFIER"
                and token.value not in cs.consts
                and not _is_type_identifier(cs, token.value)
                and token.value != "EOF"
            )
        field_type = field_type.__type__
    return tuple(dict.fromkeys(dependencies))


def _normalize_methods(
    methods: CollectionMethod | Mapping[str, Range | Sequence[Range]] | Sequence[CollectionMethod],
) -> tuple[CollectionMethod, ...]:
    if isinstance(methods, CollectionMethod):
        return (methods,)

    if isinstance(methods, Mapping):
        return tuple(CollectionMethod(name, ranges) for name, ranges in methods.items())

    normalized = tuple(methods)
    if not all(isinstance(method, CollectionMethod) for method in normalized):
        raise TypeError("methods must be CollectionMethod instances or a mapping of names to ranges")
    return normalized


def _is_type_identifier(cs: Any, identifier: str) -> bool:
    return identifier in getattr(cs, "types", {})


def _normalize_range(value: Range | Sequence[int]) -> Range:
    start, end = value
    if start < 0 or end <= start:
        raise ValueError("Ranges must be non-empty and start before end")
    return start, end


def _coerce_ranges(ranges: Range | Sequence[Range]) -> Sequence[Range]:
    if _is_range(ranges):
        return [ranges]
    return ranges


def _is_range(value: object) -> bool:
    return isinstance(value, tuple) and len(value) == 2 and all(isinstance(item, int) for item in value)


def merge_ranges(ranges: Sequence[Range]) -> tuple[Range, ...]:
    if not ranges:
        return ()

    ordered = sorted(ranges)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        previous_start, previous_end = merged[-1]
        if start <= previous_end:
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _join_path(parent: tuple[str, ...], name: str) -> str:
    return ".".join((*parent, name)) if parent else name


def _claim_paths(claims: Sequence[FieldClaim]) -> set[str]:
    return {claim.path for claim in claims}


def _reason(exc: Exception) -> str:
    if isinstance(exc, EOFError):
        return "truncated"
    return "undecidable"
