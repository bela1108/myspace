"""Opt-in confirmed-delivery reading sessions for CBOR object streams.

A :class:`ReadSession` wraps a binary source (a file-like object such as
:class:`io.BytesIO`, a ``bytes`` payload, or an iterable of ``bytes`` chunks)
and decodes one top-level object at a time. Every confirmed object is bound to
a :class:`Receipt`, its reception statement, carrying the object's sequence
number, exact byte span in the stream, and a SHA-256 digest of its encoded
bytes as confirmation evidence.

The session can be withdrawn at any point. Withdrawal never discards confirmed
objects: their receipts remain available through :meth:`ReadSession.handoff`,
which yields them one at a time. After a withdrawal the session must be
re-validated with :meth:`ReadSession.accept` before the next object can be
confirmed.

This is an opt-in layer on top of the classic API; :func:`cbor2.load`,
:func:`cbor2.loads` and :class:`cbor2.CBORDecoder` are unaffected.
"""

from __future__ import annotations

import hashlib
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import IO, Any, TypeAlias

from ._cbor2 import CBORDecoder

__all__ = ["Receipt", "ReadSession", "SessionStateError"]

ChunkSource: TypeAlias = IO[bytes] | Iterable[bytes] | bytes | bytearray | memoryview


class SessionStateError(RuntimeError):
    """Raised when a session operation conflicts with the session's state."""


@dataclass(frozen=True)
class Receipt:
    """Reception statement and confirmation evidence for one top-level object."""

    sequence: int
    """Ordinal of the object among those confirmed by the session (0-based)."""

    value: Any
    """The decoded top-level object."""

    start: int
    """Byte offset at which the object's encoding starts in the stream."""

    end: int
    """Byte offset one past the end of the object's encoding."""

    digest: str
    """SHA-256 hex digest of the object's encoded bytes (confirmation evidence)."""

    @property
    def size(self) -> int:
        """Number of encoded bytes the object occupies in the stream."""
        return self.end - self.start


class _ChunkedReader:
    """Blocking, non-seekable read facade over an iterator of byte chunks.

    Because the reader reports itself as non-seekable, the decoder requests
    exactly the bytes it needs, so every byte served corresponds to a decoded
    object. Served bytes are counted and recorded so that each confirmed
    object can be bound to its exact byte span.
    """

    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._chunks = chunks
        self._pending = bytearray()
        self._recorded = bytearray()
        self._exhausted = False
        self.bytes_served = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def _fill(self, size: int) -> None:
        while len(self._pending) < size and not self._exhausted:
            chunk = next(self._chunks, None)
            if chunk is None:
                self._exhausted = True
            else:
                self._pending += chunk

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            while not self._exhausted:
                self._fill(len(self._pending) + 1)
            size = len(self._pending)
        else:
            self._fill(size)
        data = bytes(self._pending[:size])
        del self._pending[:size]
        self.bytes_served += len(data)
        self._recorded += data
        return data

    def has_more(self) -> bool:
        """Return ``True`` if at least one more byte is available."""
        self._fill(1)
        return bool(self._pending)

    def mark(self) -> None:
        """Start recording served bytes for the next object."""
        del self._recorded[:]

    @property
    def recorded(self) -> bytes:
        """Bytes served since the last :meth:`mark`."""
        return bytes(self._recorded)


def _iter_chunks(source: ChunkSource, chunk_size: int) -> Iterator[bytes]:
    read = getattr(source, "read", None)
    if callable(read):
        while chunk := read(chunk_size):
            yield bytes(chunk)
    elif isinstance(source, (bytes, bytearray, memoryview)):
        yield bytes(source)
    else:
        for chunk in source:
            if chunk:
                yield bytes(chunk)


class ReadSession:
    """Incremental reading session binding each top-level object to a receipt.

    :param source: a binary file-like object (e.g. :class:`io.BytesIO`), a
        ``bytes``-like payload, or an iterable of ``bytes`` chunks
    :param chunk_size: read size used when pulling chunks from a file-like
        ``source``; ignored for other source kinds
    :param decoder_kwargs: forwarded to :class:`cbor2.CBORDecoder`
    """

    def __init__(
        self, source: ChunkSource, *, chunk_size: int = 65536, **decoder_kwargs: Any
    ) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be a positive integer")
        self._reader = _ChunkedReader(_iter_chunks(source, chunk_size))
        self._decoder = CBORDecoder(self._reader, **decoder_kwargs)
        self._pending: deque[Receipt] = deque()
        self._sequence = 0
        self._withdrawn = False
        self._exhausted = False

    @property
    def withdrawn(self) -> bool:
        """``True`` while the session is withdrawn and needs re-validation."""
        return self._withdrawn

    @property
    def exhausted(self) -> bool:
        """``True`` once the source ended cleanly on an object boundary."""
        return self._exhausted

    @property
    def confirmed_count(self) -> int:
        """Number of top-level objects confirmed so far."""
        return self._sequence

    @property
    def pending_count(self) -> int:
        """Number of confirmed receipts not yet collected via :meth:`handoff`."""
        return len(self._pending)

    def confirm_next(self, *, immutable: bool = False) -> Receipt | None:
        """Decode the next top-level object and bind it to a receipt.

        Returns the object's receipt, or ``None`` when the source is cleanly
        exhausted. A truncated or malformed object raises
        :exc:`~cbor2.CBORDecodeEOF` or :exc:`~cbor2.CBORDecodeError`
        respectively, leaving previously confirmed receipts intact.

        :raises SessionStateError: if the session is withdrawn; call
            :meth:`accept` to re-validate before confirming the next object
        """
        if self._withdrawn:
            raise SessionStateError(
                "session is withdrawn; call accept() to re-validate the next object"
            )
        if self._exhausted or not self._reader.has_more():
            self._exhausted = True
            return None
        start = self._reader.bytes_served
        self._reader.mark()
        value = self._decoder.decode(immutable=immutable)
        raw = self._reader.recorded
        receipt = Receipt(
            sequence=self._sequence,
            value=value,
            start=start,
            end=start + len(raw),
            digest=hashlib.sha256(raw).hexdigest(),
        )
        self._sequence += 1
        self._pending.append(receipt)
        return receipt

    def withdraw(self) -> None:
        """Cancel acceptance of further objects.

        Already confirmed objects remain available for handoff; confirming the
        next object requires re-validation via :meth:`accept`.
        """
        self._withdrawn = True

    def accept(self) -> None:
        """Re-validate the session after :meth:`withdraw`."""
        self._withdrawn = False

    def handoff(self) -> Iterator[Receipt]:
        """Yield the receipts of confirmed objects, one at a time.

        Only objects confirmed before the call are handed off; each receipt is
        yielded exactly once.
        """
        while self._pending:
            yield self._pending.popleft()
