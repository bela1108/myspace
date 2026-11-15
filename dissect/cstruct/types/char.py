from __future__ import annotations

from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cstruct.exception import ArraySizeError
from dissect.cstruct.types.base import (
    EOF,
    BaseArray,
    BaseType,
    StringReadError,
    _read_bounded_null_terminated,
)

if TYPE_CHECKING:
    from typing_extensions import Self

    from dissect.cstruct.cstruct import Endianness
    from dissect.cstruct.types.base import BoundedString


class CharArray(bytes, BaseArray):
    """Character array type for reading and writing byte strings."""

    @classmethod
    def __default__(cls) -> Self:
        return type.__call__(cls, b"\x00" * (0 if cls.__dynamic__ or cls.__null_terminated__ else cls.__num_entries__))

    @classmethod
    def _read(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> Self:
        return type.__call__(cls, super()._read(stream, context=context, endian=endian))

    @classmethod
    def _write(cls, stream: BinaryIO, data: bytes | bytearray | str | list[int], *, endian: Endianness) -> int:
        # Copy mutable data types to bytes so we don't modify them in place
        if isinstance(data, (list, bytearray)):
            data = bytes(data)
        elif isinstance(data, str):
            data = data.encode("latin-1")

        if cls.__null_terminated__:
            data += b"\x00"

        if not cls.__dynamic__ and (remaining := cls.__num_entries__ - (actual_size := len(data))):
            if remaining < 0:
                raise ArraySizeError(f"Expected static array size {cls.__num_entries__}, got {actual_size} instead.")
            data += b"\x00" * remaining

        return stream.write(data)


class Char(bytes, BaseType):
    """Character type for reading and writing bytes."""

    __ArrayType__ = CharArray

    @classmethod
    def __default__(cls) -> Self:
        return type.__call__(cls, b"\x00")

    @classmethod
    def _read(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> Self:
        return cls._read_array(stream, 1, context=context, endian=endian)

    @classmethod
    def _read_array(
        cls, stream: BinaryIO, count: int, *, context: dict[str, Any] | None = None, endian: Endianness
    ) -> Self:
        if count == 0:
            return type.__call__(cls, b"")

        data = stream.read(-1 if count == EOF else count)
        if count != EOF and len(data) != count:
            raise EOFError(f"Read {len(data)} bytes, but expected {count}")

        return type.__call__(cls, data)

    @classmethod
    def _read_0(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> Self:
        return cls._read_0_bounded(stream, None, context=context, endian=endian)

    @classmethod
    def _read_0_bounded(
        cls,
        stream: BinaryIO,
        max_length: int | None,
        *,
        context: dict[str, Any] | None = None,
        endian: Endianness,
    ) -> Self:
        """Read a null-terminated byte string, optionally restricted to ``max_length`` bytes.

        With a bound, reading never consumes bytes past the field's parent buffer. A field that reaches the
        bound without a terminator raises a :class:`StringReadError` carrying the raw field bytes.
        """
        result = _read_bounded_null_terminated(stream, 1, max_length)
        cls._raise_if_invalid(result)
        return type.__call__(cls, result.raw)

    @classmethod
    def read_string(
        cls,
        buffer: bytes | bytearray | memoryview | BinaryIO,
        max_length: int | None = None,
        *,
        endian: Endianness | None = None,
    ) -> Self:
        """Read a (bounded) null-terminated byte string from a parent buffer or stream.

        Args:
            buffer: The parent buffer (or stream) that owns the string. Only its bytes are ever read.
            max_length: Maximum amount of bytes that belong to the string. ``None`` reads to a terminator
                or the end of the buffer.
            endian: Optional endianness override.
        """
        from io import BytesIO

        from dissect.cstruct.util import normalize_endianness

        if not hasattr(buffer, "read"):
            buffer = BytesIO(bytes(buffer))

        if max_length is None:
            endian = normalize_endianness(endian) if endian is not None else cls.__cs__.endian
            return cls._read_0(buffer, endian=endian)

        if max_length < 0:
            raise ValueError("max_length must be non-negative")

        endian = normalize_endianness(endian) if endian is not None else cls.__cs__.endian
        return cls._read_0_bounded(buffer, max_length, endian=endian)

    @staticmethod
    def _raise_if_invalid(result: BoundedString) -> None:
        if not result.terminated:
            raise StringReadError(result.raw, "unterminated")

    @classmethod
    def _write(cls, stream: BinaryIO, data: bytes | int | str, *, endian: Endianness) -> int:
        if isinstance(data, int):
            data = chr(data)

        if isinstance(data, str):
            data = data.encode("latin-1")

        if (actual_size := len(data)) > 1:
            raise ValueError(f"Expected a single character, got {actual_size} instead.")

        return stream.write(data or b"\x00")
