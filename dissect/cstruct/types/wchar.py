from __future__ import annotations

import sys
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, ClassVar

from dissect.cstruct.exception import ArraySizeError
from dissect.cstruct.types.base import (
    EOF,
    BaseArray,
    BaseType,
    StringReadError,
    _read_bounded_null_terminated,
)
from dissect.cstruct.util import normalize_endianness

if TYPE_CHECKING:
    from dissect.cstruct.cstruct import Endianness
    from dissect.cstruct.types.base import BoundedString


class WcharArray(str, BaseArray):
    """Wide-character array type for reading and writing UTF-16 strings."""

    __slots__ = ()

    @classmethod
    def __default__(cls) -> WcharArray:
        return type.__call__(cls, "\x00" * (0 if cls.__dynamic__ or cls.__null_terminated__ else cls.__num_entries__))

    @classmethod
    def _read(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> WcharArray:
        return type.__call__(cls, super()._read(stream, context=context, endian=endian))

    @classmethod
    def _write(cls, stream: BinaryIO, data: str, *, endian: Endianness) -> int:
        if cls.__null_terminated__:
            data += "\x00"

        buf = data.encode(Wchar.__encoding_map__[endian], "surrogatepass")

        # A surrogate pair is a single character that takes up two entries of the array
        if not cls.__dynamic__ and (remaining := cls.__num_entries__ - (actual_size := len(buf) // 2)):
            if remaining < 0:
                raise ArraySizeError(f"Expected static array size {cls.__num_entries__}, got {actual_size} instead.")
            buf += b"\x00\x00" * remaining

        return stream.write(buf)


class Wchar(str, BaseType):
    """Wide-character type for reading and writing UTF-16 characters."""

    __ArrayType__ = WcharArray

    __slots__ = ()
    # Decode with "surrogatepass" so lone surrogates are handled correctly
    __encoding_map__: ClassVar[dict[Endianness, str]] = {
        "@": f"utf-16-{sys.byteorder[0]}e",
        "=": f"utf-16-{sys.byteorder[0]}e",
        "<": "utf-16-le",
        ">": "utf-16-be",
        "!": "utf-16-be",
    }

    @classmethod
    def __default__(cls) -> Wchar:
        return type.__call__(cls, "\x00")

    @classmethod
    def _read(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> Wchar:
        return cls._read_array(stream, 1, context=context, endian=endian)

    @classmethod
    def _read_array(
        cls, stream: BinaryIO, count: int, *, context: dict[str, Any] | None = None, endian: Endianness
    ) -> Wchar:
        if count == 0:
            return type.__call__(cls, "")

        if count != EOF:
            count *= 2

        data = stream.read(-1 if count == EOF else count)
        if count != EOF and len(data) != count:
            raise EOFError(f"Read {len(data)} bytes, but expected {count}")

        return type.__call__(cls, str(data, cls.__encoding_map__[endian], "surrogatepass"))

    @classmethod
    def _read_0(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> Wchar:
        return cls._read_0_bounded(stream, None, context=context, endian=endian)

    @classmethod
    def _read_0_bounded(
        cls,
        stream: BinaryIO,
        max_length: int | None,
        *,
        context: dict[str, Any] | None = None,
        endian: Endianness,
    ) -> Wchar:
        """Read a null-terminated UTF-16 string, optionally restricted to ``max_length`` bytes.

        With a bound, reading never consumes bytes past the field's parent buffer. A truncated code unit,
        an unterminated field or a split surrogate pair at the boundary is reported with the raw field bytes
        and an explicit error, instead of silently including neighbouring memory.
        """
        result = _read_bounded_null_terminated(stream, 2, max_length)
        return type.__call__(cls, cls._decode_bounded(result, endian, max_length is not None))

    @classmethod
    def read_string(
        cls,
        buffer: bytes | bytearray | memoryview | BinaryIO,
        max_length: int | None = None,
        *,
        endian: Endianness | None = None,
    ) -> Wchar:
        """Read a (bounded) null-terminated UTF-16 string from a parent buffer or stream.

        Args:
            buffer: The parent buffer (or stream) that owns the string. Only its bytes are ever read.
            max_length: Maximum amount of bytes that belong to the string. ``None`` reads to a terminator
                or the end of the buffer.
            endian: Optional endianness override.
        """
        if not hasattr(buffer, "read"):
            buffer = BytesIO(bytes(buffer))

        if max_length is not None and max_length < 0:
            raise ValueError("max_length must be non-negative")

        resolved = normalize_endianness(endian) if endian is not None else cls.__cs__.endian
        return cls._read_0_bounded(buffer, max_length, endian=resolved)

    @classmethod
    def _decode_bounded(cls, result: BoundedString, endian: Endianness, bounded: bool) -> str:
        encoding = cls.__encoding_map__[endian]
        raw = result.raw

        if result.truncated or len(raw) % 2:
            # Half a code unit: the same UnicodeDecodeError a full decode of these bytes would raise.
            return raw.decode(encoding, "surrogatepass")

        if bounded and not result.terminated:
            # Only a bounded read has a field boundary that could be crossed.
            # A high surrogate at the very end may have its low surrogate stored past the boundary.
            cls._raise_on_split_surrogate(raw, encoding)
            raise StringReadError(raw, "unterminated")

        return raw.decode(encoding, "surrogatepass")

    @staticmethod
    def _raise_on_split_surrogate(raw: bytes, encoding: str) -> None:
        if len(raw) >= 2:
            last = int.from_bytes(raw[-2:], "little" if encoding.endswith("le") else "big")
            if 0xD800 <= last <= 0xDBFF:
                raise StringReadError(raw, "truncated-surrogate-pair")

    @classmethod
    def _write(cls, stream: BinaryIO, data: str, *, endian: Endianness) -> int:
        buf = data.encode(cls.__encoding_map__[endian], "surrogatepass")

        # A surrogate pair is a single character that doesn't fit in a single wchar
        if (actual_size := len(buf) // 2) > 1:
            raise ValueError(f"Expected a single character, got {actual_size} instead.")

        return stream.write(buf or b"\x00\x00")
