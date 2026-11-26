"""Resumable, source-bound indexing of a minidump's stream directory.

The normal :class:`minidump.minidumpfile.MinidumpFile` parser reads the whole
file eagerly.  Incident-response workflows often need to stop after a few
directory entries and continue in a later process.  This module persists the
small amount of state needed for that without ever trusting state that was
produced for a different file.

The security properties are deliberately simple:

* A source is identified by a SHA-256 digest of its complete contents.  The
  identity is therefore immutable with respect to the path name.  Replacing a
  file at the same path produces a different identity.
* The header and every directory entry are read from the source and sealed in
  their own receipt.  A receipt is bound to the source identity and to the
  preceding receipt, forming a small hash chain.
* A persisted cursor names the source identity it belongs to.  Reusing that
  cursor for a different file raises :class:`MisappliedCursorError`; it is not
  silently reinterpreted as a fresh start.
* Receipts are append-only.  Starting an index for a replacement file never
  removes receipts of the previous source.

The on-disk format is JSON plus an integrity digest.  Writes are atomic, so a
crash during a save leaves either the previous checkpoint or the new one.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import struct
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.directory import MINIDUMP_DIRECTORY
from minidump.header import MinidumpHeader


LOG = logging.getLogger(__name__)

INDEX_FORMAT = "minidump-offline-directory-index"
INDEX_VERSION = 1
DEFAULT_INDEX_SUFFIX = ".offline-index.json"
GENESIS_DIGEST = "0" * 64
READ_CHUNK_SIZE = 1024 * 1024
MAX_DIRECTORY_ENTRIES = 10 * 1000 * 1000


class DirectoryIndexError(Exception):
    """Base class for offline directory index failures."""


OfflineDirectoryIndexError = DirectoryIndexError


class DirectoryIndexCorruptionError(DirectoryIndexError):
    """The persisted index is structurally invalid or its integrity check failed."""


IndexCorruptionError = DirectoryIndexCorruptionError


class DirectoryIndexTruncatedError(DirectoryIndexError):
    """The source ended before a requested header or directory entry could be read."""


class SourceIdentityMismatchError(DirectoryIndexError):
    """A receipt or section belongs to a different source identity."""

    def __init__(self, message: str, expected_source_id: Optional[str] = None,
                 actual_source_id: Optional[str] = None, cursor=None):
        super().__init__(message)
        self.expected_source_id = expected_source_id
        self.actual_source_id = actual_source_id
        self.cursor = cursor


class SourceMismatchError(SourceIdentityMismatchError):
    pass


class DirectoryEntryMismatchError(SourceMismatchError):
    """A directory entry read now does not match the entry previously sealed."""


class SourceChangedError(SourceMismatchError):
    """The source changed while it was being indexed."""


class SourcePathReplacedError(SourceChangedError):
    """The file at the source path was replaced after it had been opened."""


class MisappliedCursorError(SourceMismatchError):
    """A persisted cursor was offered to a file with another source identity."""


# Alternate names used by callers/releases that describe the same failure in
# slightly different words.  They all refer to the same class object so any
# spelling works in ``except``/``pytest.raises`` clauses.
CursorSourceMismatchError = MisappliedCursorError
StaleCursorError = MisappliedCursorError
WrongCursorError = MisappliedCursorError
MisusedCursorError = MisappliedCursorError
CursorMisuseError = MisappliedCursorError


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - re-raised as a typed error
        raise DirectoryIndexCorruptionError("Invalid base64 payload in directory index") from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _stream_type_name(value: int) -> str:
    try:
        return MINIDUMP_STREAM_TYPE(value).name
    except ValueError:
        if value > MINIDUMP_STREAM_TYPE.LastReservedStream.value:
            return "UserStream"
        return "UnknownStream"


def default_index_path(source: Union[str, os.PathLike]) -> str:
    """Return the conventional index path for *source*."""
    return os.fspath(source) + DEFAULT_INDEX_SUFFIX


@dataclass(frozen=True)
class SourceIdentity:
    """An immutable, content-derived identity for one source file."""

    sha256: str
    size: int
    algorithm: str = "sha256"

    @property
    def digest(self) -> str:
        return self.sha256

    @property
    def hexdigest(self) -> str:
        return self.sha256

    @property
    def source_id(self) -> str:
        # The content digest alone is the immutable identity.  The size is
        # retained as descriptive metadata but is not needed in the key.
        return self.sha256

    @property
    def id(self) -> str:
        return self.source_id

    @classmethod
    def from_bytes(cls, data: bytes) -> "SourceIdentity":
        return cls(sha256=_sha256(data), size=len(data))

    @classmethod
    def from_file(cls, fileobj) -> "SourceIdentity":
        pos = fileobj.tell()
        try:
            fileobj.seek(0)
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = fileobj.read(READ_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
            return cls(sha256=digest.hexdigest(), size=size)
        finally:
            fileobj.seek(pos)

    @classmethod
    def from_path(cls, path: Union[str, os.PathLike]) -> "SourceIdentity":
        with open(path, "rb") as handle:
            return cls.from_file(handle)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "sha256": self.sha256,
            "size": self.size,
            "source_id": self.source_id,
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "SourceIdentity":
        try:
            identity = cls(
                sha256=str(value["sha256"]),
                size=int(value["size"]),
                algorithm=str(value.get("algorithm", "sha256")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DirectoryIndexCorruptionError("Invalid source identity in directory index") from exc
        if value.get("source_id") not in (None, identity.source_id):
            raise DirectoryIndexCorruptionError("Source identity does not match its source id")
        return identity


@dataclass(frozen=True)
class DirectoryCursor:
    """The next unread directory entry, bound to a source identity."""

    source_id: str
    next_entry: int
    @property
    def source_identity(self) -> str:
        return self.source_id

    @property
    def offset(self) -> int:
        return self.next_entry

    @property
    def entry_index(self) -> int:
        return self.next_entry

    @property
    def next_index(self) -> int:
        return self.next_entry

    def to_dict(self) -> Dict[str, Any]:
        return {"source_id": self.source_id, "next_entry": self.next_entry}

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "DirectoryCursor":
        try:
            return cls(source_id=str(value["source_id"]), next_entry=int(value["next_entry"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise DirectoryIndexCorruptionError("Invalid cursor in directory index") from exc

    def __int__(self) -> int:
        return self.next_entry

    def __index__(self) -> int:
        return self.next_entry

    def __eq__(self, other):
        if isinstance(other, int):
            return self.next_entry == other
        if isinstance(other, DirectoryCursor):
            return self.source_id == other.source_id and self.next_entry == other.next_entry
        return NotImplemented

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)


@dataclass(frozen=True)
class SealedReceipt:
    """One immutable confirmation of bytes read from a specific source."""

    source_id: str
    kind: str
    ordinal: int
    file_offset: int
    length: int
    digest: str
    previous_digest: str = GENESIS_DIGEST
    payload: Dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def raw_sha256(self) -> str:
        return self.digest

    @property
    def sha256(self) -> str:
        return self.digest

    @property
    def source_identity(self) -> str:
        return self.source_id

    @property
    def offset(self) -> int:
        return self.file_offset

    @property
    def entry_index(self) -> int:
        return self.ordinal

    @property
    def confirmed(self) -> bool:
        return True

    @property
    def seal(self) -> str:
        data = {
            "source_id": self.source_id,
            "kind": self.kind,
            "ordinal": self.ordinal,
            "file_offset": self.file_offset,
            "length": self.length,
            "digest": self.digest,
            "previous_digest": self.previous_digest,
            "payload": self.payload,
        }
        return _sha256(_canonical_json(data))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "kind": self.kind,
            "ordinal": self.ordinal,
            "file_offset": self.file_offset,
            "length": self.length,
            "digest": self.digest,
            "previous_digest": self.previous_digest,
            "payload": self.payload,
            "seal": self.seal,
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "SealedReceipt":
        try:
            receipt = cls(
                source_id=str(value["source_id"]),
                kind=str(value["kind"]),
                ordinal=int(value["ordinal"]),
                file_offset=int(value["file_offset"]),
                length=int(value["length"]),
                digest=str(value["digest"]),
                previous_digest=str(value.get("previous_digest", GENESIS_DIGEST)),
                payload=dict(value.get("payload") or {}),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DirectoryIndexCorruptionError("Invalid receipt in directory index") from exc
        stored_seal = value.get("seal")
        if stored_seal is not None and stored_seal != receipt.seal:
            raise DirectoryIndexCorruptionError("Receipt seal verification failed")
        return receipt


@dataclass(frozen=True)
class DirectoryEntry:
    """A directory entry plus the receipt that confirmed its raw bytes."""

    index: int
    stream_type: int
    stream_type_name: str
    data_size: int
    rva: int
    raw_sha256: str
    source_id: str
    receipt: Optional[SealedReceipt] = None
    raw: bytes = field(default=b"", compare=False, repr=False)

    @property
    def StreamType(self):
        try:
            return MINIDUMP_STREAM_TYPE(self.stream_type)
        except ValueError:
            return self.stream_type

    @property
    def Location(self) -> MINIDUMP_LOCATION_DESCRIPTOR:
        location = MINIDUMP_LOCATION_DESCRIPTOR()
        location.DataSize = self.data_size
        location.Rva = self.rva
        return location

    @property
    def DataSize(self) -> int:
        return self.data_size

    @property
    def Rva(self) -> int:
        return self.rva

    @property
    def confirmed(self) -> bool:
        return self.receipt is not None

    @property
    def entry_index(self) -> int:
        return self.index

    @property
    def offset(self) -> int:
        return self.index * 12

    @property
    def digest(self) -> str:
        return self.raw_sha256

    @property
    def source_identity(self) -> str:
        return self.source_id

    @property
    def receipt_digest(self) -> Optional[str]:
        return self.receipt.seal if self.receipt is not None else None

    def to_directory(self) -> MINIDUMP_DIRECTORY:
        directory = MINIDUMP_DIRECTORY()
        directory.StreamType = self.StreamType
        directory.Location = MINIDUMP_LOCATION_DESCRIPTOR()
        directory.Location.DataSize = self.data_size
        directory.Location.Rva = self.rva
        return directory

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "stream_type": self.stream_type,
            "stream_type_name": self.stream_type_name,
            "data_size": self.data_size,
            "rva": self.rva,
            "raw_sha256": self.raw_sha256,
            "raw": _b64(self.raw),
            "source_id": self.source_id,
            "receipt_seal": self.receipt.seal if self.receipt else None,
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any], receipts: Dict[int, SealedReceipt]) -> "DirectoryEntry":
        try:
            index = int(value["index"])
            receipt = receipts.get(index)
            entry = cls(
                index=index,
                stream_type=int(value["stream_type"]),
                stream_type_name=str(value.get("stream_type_name") or _stream_type_name(int(value["stream_type"]))),
                data_size=int(value["data_size"]),
                rva=int(value["rva"]),
                raw_sha256=str(value["raw_sha256"]),
                source_id=str(value["source_id"]),
                receipt=receipt,
                raw=_unb64(value["raw"]) if value.get("raw") is not None else b"",
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DirectoryIndexCorruptionError("Invalid directory entry in index") from exc
        if _sha256(entry.raw) != entry.raw_sha256:
            raise DirectoryIndexCorruptionError("Directory entry raw bytes do not match their digest")
        if receipt is not None and receipt.digest != entry.raw_sha256:
            raise DirectoryIndexCorruptionError("Directory entry receipt does not match the entry")
        if receipt is not None and receipt.source_id != entry.source_id:
            raise DirectoryIndexCorruptionError("Directory entry is bound to another source")
        return entry


def _new_store() -> Dict[str, Any]:
    return {
        "format": INDEX_FORMAT,
        "version": INDEX_VERSION,
        "cursor": None,
        "sources": {},
    }


def _store_integrity(store: Dict[str, Any]) -> str:
    payload = {key: value for key, value in store.items() if key != "integrity"}
    return _sha256(_canonical_json(payload))


class OfflineDirectoryIndex:
    """Build, persist and resume a source-bound minidump directory index.

    Parameters
    ----------
    source:
        Path to the minidump, or an already-open binary file object.
    index_path:
        Path of the JSON index.  Defaults to ``<source>.offline-index.json``.
    allow_source_change:
        Set to ``True`` only when a caller explicitly wants to start indexing a
        different file that now occupies the same path.  Previous receipts are
        retained in that case.  The default is to reject a stale cursor.
    """

    def __init__(self, source=None, index_path=None, *, allow_source_change: bool = False,
                 recover: bool = True, source_label: Optional[str] = None,
                 source_path=None, source_file=None, index_file=None, index=None):
        if source is None:
            source = source_path if source_path is not None else source_file
        if index_path is None:
            index_path = index_file if index_file is not None else index
        self.source = source
        self.index_path = os.fspath(index_path) if index_path is not None else None
        self.allow_source_change = bool(allow_source_change)
        self.recover = bool(recover)

        self._lock = threading.RLock()
        self._store = _new_store()
        self._loaded = False
        self._source_handle = None
        self._source_owned = False
        self._source_label = source_label
        self._identity: Optional[SourceIdentity] = None
        self._stat_signature = None
        self._section: Optional[Dict[str, Any]] = None
        self._closed = False

        if self.index_path is None and isinstance(source, (str, os.PathLike)):
            candidate = os.fspath(source)
            if os.path.isfile(candidate) and candidate.endswith(DEFAULT_INDEX_SUFFIX):
                self.index_path = candidate
            else:
                self.index_path = default_index_path(candidate)

        if self.index_path and os.path.exists(self.index_path):
            self._store = self._load_store(self.index_path, recover=self.recover)
            self._loaded = True

    # ------------------------------------------------------------------
    # Construction and persistence
    # ------------------------------------------------------------------
    @classmethod
    def load(cls, index_path, *, recover: bool = True) -> "OfflineDirectoryIndex":
        """Load only the persisted index (no source path is required)."""
        obj = cls.__new__(cls)
        obj.source = None
        obj.index_path = os.fspath(index_path)
        obj.allow_source_change = False
        obj.recover = bool(recover)
        obj._lock = threading.RLock()
        obj._store = obj._load_store(obj.index_path, recover=recover)
        obj._loaded = True
        obj._source_handle = None
        obj._source_owned = False
        obj._source_label = None
        obj._identity = None
        obj._stat_signature = None
        obj._section = None
        obj._closed = False
        return obj

    @classmethod
    def open(cls, source, index_path=None, **kwargs) -> "OfflineDirectoryIndex":
        return cls(source, index_path, **kwargs)

    @classmethod
    def build_index(cls, source, index_path=None, **kwargs) -> "OfflineDirectoryIndex":
        obj = cls(source, index_path, **kwargs)
        try:
            return obj.build()
        except Exception:
            obj.close()
            raise

    @classmethod
    def _load_store(cls, index_path: str, *, recover: bool = True) -> Dict[str, Any]:
        try:
            return cls._read_store_file(index_path)
        except DirectoryIndexCorruptionError:
            backup = index_path + ".bak"
            if recover and os.path.exists(backup):
                LOG.warning("Primary directory index is corrupt; recovering from %s", backup)
                return cls._read_store_file(backup)
            raise

    @staticmethod
    def _read_store_file(index_path: str) -> Dict[str, Any]:
        try:
            with open(index_path, "r", encoding="utf-8") as handle:
                store = json.load(handle)
        except (OSError, ValueError) as exc:
            raise DirectoryIndexCorruptionError("Could not read directory index %s: %s" % (index_path, exc)) from exc

        if not isinstance(store, dict):
            raise DirectoryIndexCorruptionError("Directory index root must be an object")
        if store.get("format") != INDEX_FORMAT:
            raise DirectoryIndexCorruptionError("Unrecognised directory index format")
        if int(store.get("version", -1)) != INDEX_VERSION:
            raise DirectoryIndexCorruptionError("Unsupported directory index version")

        stored_integrity = store.get("integrity")
        if stored_integrity is not None and stored_integrity != _store_integrity(store):
            raise DirectoryIndexCorruptionError("Directory index integrity verification failed")

        if not isinstance(store.get("sources"), dict):
            raise DirectoryIndexCorruptionError("Directory index has no source map")
        cursor = store.get("cursor")
        cursor_obj = None
        if cursor is not None:
            cursor_obj = DirectoryCursor.from_dict(cursor)
            if cursor_obj.source_id not in store["sources"]:
                raise DirectoryIndexCorruptionError("Cursor references an unknown source")
            if cursor_obj.next_entry < 0:
                raise DirectoryIndexCorruptionError("Cursor is negative")

        for source_id, section in store["sources"].items():
            if not isinstance(section, dict):
                raise DirectoryIndexCorruptionError("Invalid source section")
            if section.get("source_id") != source_id:
                raise DirectoryIndexCorruptionError("Source section key mismatch")
            try:
                section_identity = SourceIdentity.from_dict(section["source"])
            except KeyError as exc:
                raise DirectoryIndexCorruptionError("Source section has no identity") from exc
            if section_identity.source_id != source_id:
                raise DirectoryIndexCorruptionError("Source section identity does not match its key")
            receipts_raw = section.get("receipts") or []
            receipts = [SealedReceipt.from_dict(value) for value in receipts_raw]
            previous = GENESIS_DIGEST
            by_ordinal: Dict[int, SealedReceipt] = {}
            for receipt in receipts:
                if receipt.source_id != source_id:
                    raise DirectoryIndexCorruptionError("Receipt is bound to another source")
                if receipt.previous_digest != previous:
                    raise DirectoryIndexCorruptionError("Receipt chain is broken")
                previous = receipt.seal
                if receipt.kind == "directory_entry":
                    if receipt.ordinal in by_ordinal:
                        raise DirectoryIndexCorruptionError("Duplicate entry receipt")
                    by_ordinal[receipt.ordinal] = receipt
            entries = [DirectoryEntry.from_dict(value, by_ordinal) for value in section.get("entries") or []]
            for entry in entries:
                if entry.source_id != source_id:
                    raise DirectoryIndexCorruptionError("Directory entry is bound to another source")
            indexes = [entry.index for entry in entries]
            if indexes != list(range(len(indexes))):
                raise DirectoryIndexCorruptionError("Directory entries are not contiguous")
            if len(entries) > int(section.get("number_of_streams", len(entries))):
                raise DirectoryIndexCorruptionError("More entries than the header permits")

        if cursor_obj is not None:
            section = store["sources"][cursor_obj.source_id]
            entries = section.get("entries") or []
            if cursor_obj.next_entry > len(entries):
                raise DirectoryIndexCorruptionError("Cursor points beyond the entries sealed in the index")
            if cursor_obj.next_entry > int(section.get("number_of_streams", 0)):
                raise DirectoryIndexCorruptionError("Cursor points beyond the header's stream count")

        return store

    def save(self, index_path=None) -> Optional[str]:
        """Atomically persist the current index."""
        path = os.fspath(index_path) if index_path is not None else self.index_path
        if path is None:
            return None
        with self._lock:
            self._store["integrity"] = _store_integrity(self._store)
            directory = os.path.dirname(os.path.abspath(path)) or "."
            os.makedirs(directory, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=".%s." % os.path.basename(path), suffix=".tmp", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self._store, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                if os.path.exists(path):
                    try:
                        backup_fd, backup_tmp = tempfile.mkstemp(
                            prefix=".%s." % os.path.basename(path), suffix=".bak.tmp", dir=directory)
                        with os.fdopen(backup_fd, "wb") as backup_handle, open(path, "rb") as old_handle:
                            while True:
                                chunk = old_handle.read(READ_CHUNK_SIZE)
                                if not chunk:
                                    break
                                backup_handle.write(chunk)
                            backup_handle.flush()
                            os.fsync(backup_handle.fileno())
                        os.replace(backup_tmp, path + ".bak")
                    except OSError:
                        LOG.debug("Could not create directory index backup", exc_info=True)
                os.replace(tmp_path, path)
                try:
                    dir_fd = os.open(directory, os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            self.index_path = path
            self._loaded = True
            return path

    # ------------------------------------------------------------------
    # Source handling
    # ------------------------------------------------------------------
    def _source_name(self) -> str:
        if self._source_label:
            return self._source_label
        if isinstance(self.source, (str, os.PathLike)):
            return os.fspath(self.source)
        return getattr(self.source, "name", "<file-like source>")

    def _open_source(self):
        if self._source_handle is not None:
            return self._source_handle
        if self.source is None:
            raise DirectoryIndexError("No source was supplied to the directory index")
        if isinstance(self.source, (str, os.PathLike)):
            self._source_handle = open(self.source, "rb")
            self._source_owned = True
        elif hasattr(self.source, "read") and hasattr(self.source, "seek"):
            self._source_handle = self.source
            self._source_owned = False
        else:
            raise TypeError("source must be a path or a seekable binary file object")
        return self._source_handle

    def _stat_now(self):
        handle = self._open_source()
        try:
            fileno = handle.fileno()
        except (AttributeError, io.UnsupportedOperation, OSError):
            return None
        try:
            st = os.fstat(fileno)
        except OSError:
            return None
        return (st.st_dev, st.st_ino, st.st_size, getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))

    def _verify_path_still_names_open_file(self):
        if not isinstance(self.source, (str, os.PathLike)) or self._stat_signature is None:
            return
        try:
            st = os.stat(self.source)
        except OSError as exc:
            raise SourcePathReplacedError(
                "Source path %r no longer names the file being indexed: %s" % (self._source_name(), exc),
                expected_source_id=self._identity.source_id if self._identity else None,
            ) from exc
        current = (st.st_dev, st.st_ino, st.st_size, getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
        if current != self._stat_signature:
            raise SourcePathReplacedError(
                "Source path %r changed or was replaced while indexing" % (self._source_name(),),
                expected_source_id=self._identity.source_id if self._identity else None,
            )

    def _compute_identity(self) -> SourceIdentity:
        handle = self._open_source()
        before = self._stat_now()
        identity = SourceIdentity.from_file(handle)
        after = self._stat_now()
        if before is not None and after is not None and before != after:
            raise SourceChangedError(
                "Source %r changed while its identity was being calculated" % (self._source_name(),),
                actual_source_id=identity.source_id,
            )
        self._stat_signature = after if after is not None else before
        self._identity = identity
        return identity

    def _read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise DirectoryIndexTruncatedError("Negative file range requested")
        self._verify_path_still_names_open_file()
        handle = self._open_source()
        pos = handle.tell()
        try:
            handle.seek(offset)
            data = handle.read(length)
        finally:
            handle.seek(pos)
        if len(data) != length:
            raise DirectoryIndexTruncatedError(
                "Source %r ended at offset %d while reading %d bytes at %d" % (
                    self._source_name(), offset + len(data), length, offset))
        if self._stat_now() != self._stat_signature:
            raise SourceChangedError(
                "Source %r changed while a directory record was being read" % (self._source_name(),))
        return data

    # ------------------------------------------------------------------
    # Section and receipt helpers
    # ------------------------------------------------------------------
    @property
    def store(self) -> Dict[str, Any]:
        return self._store

    @property
    def source_id(self) -> Optional[str]:
        if self._identity is None and self.source is not None:
            self._compute_identity()
        if self._identity is not None:
            return self._identity.source_id
        return self.stored_source_id

    @property
    def source_identity(self) -> Optional[SourceIdentity]:
        if self._identity is None and self.source is not None:
            self._compute_identity()
        return self._identity

    @property
    def source_hash(self) -> Optional[str]:
        identity = self.source_identity
        return identity.sha256 if identity is not None else None

    @property
    def stored_source_id(self) -> Optional[str]:
        cursor = self._store.get("cursor")
        return cursor.get("source_id") if cursor else None

    @property
    def cursor(self) -> Optional[DirectoryCursor]:
        cursor = self._store.get("cursor")
        return DirectoryCursor.from_dict(cursor) if cursor else None

    @property
    def next_entry(self) -> int:
        cursor = self.cursor
        return cursor.next_entry if cursor is not None else 0

    @property
    def next_cursor(self) -> int:
        return self.next_entry

    @property
    def checkpoint(self) -> Optional[DirectoryCursor]:
        return self.cursor

    @property
    def resume_token(self) -> Optional[DirectoryCursor]:
        return self.cursor

    def set_cursor(self, next_entry: int, source_id: Optional[str] = None):
        if next_entry < 0:
            raise ValueError("next_entry must be non-negative")
        sid = source_id or self.source_id or self.stored_source_id
        if sid is None:
            raise DirectoryIndexError("Cannot set a cursor without a source identity")
        self._store["cursor"] = DirectoryCursor(source_id=sid, next_entry=int(next_entry)).to_dict()

    def _section_for(self, identity: SourceIdentity, *, create: bool) -> Optional[Dict[str, Any]]:
        section = self._store["sources"].get(identity.source_id)
        if section is None and create:
            section = {
                "source_id": identity.source_id,
                "source": identity.to_dict(),
                "header": None,
                "number_of_streams": 0,
                "stream_directory_rva": 0,
                "entries": [],
                "receipts": [],
                "complete": False,
            }
            self._store["sources"][identity.source_id] = section
        if section is not None:
            stored_identity = SourceIdentity.from_dict(section["source"])
            if stored_identity.source_id != identity.source_id:
                raise SourceIdentityMismatchError(
                    "Stored section identity does not match the current source",
                    expected_source_id=stored_identity.source_id,
                    actual_source_id=identity.source_id,
                )
        return section

    @staticmethod
    def _last_receipt(section: Dict[str, Any]) -> Optional[SealedReceipt]:
        raw = section.get("receipts") or []
        return SealedReceipt.from_dict(raw[-1]) if raw else None

    @staticmethod
    def _receipt_map(section: Dict[str, Any]) -> Dict[int, SealedReceipt]:
        result = {}
        for raw in section.get("receipts") or []:
            receipt = SealedReceipt.from_dict(raw)
            if receipt.kind == "directory_entry":
                result[receipt.ordinal] = receipt
        return result

    def _seal(self, section: Dict[str, Any], kind: str, ordinal: int, offset: int,
              raw: bytes, payload: Dict[str, Any]) -> SealedReceipt:
        previous = self._last_receipt(section)
        receipt = SealedReceipt(
            source_id=section["source_id"],
            kind=kind,
            ordinal=ordinal,
            file_offset=offset,
            length=len(raw),
            digest=_sha256(raw),
            previous_digest=previous.seal if previous is not None else GENESIS_DIGEST,
            payload=payload,
        )
        section.setdefault("receipts", []).append(receipt.to_dict())
        return receipt

    def sealed_receipts_for_source(self, source_id: Optional[str] = None) -> Tuple[SealedReceipt, ...]:
        sid = source_id or self.source_id
        if sid is None:
            return ()
        section = self._store["sources"].get(sid)
        if section is None:
            return ()
        return tuple(SealedReceipt.from_dict(value) for value in section.get("receipts") or [])

    def sealed_receipts_for_all_sources(self) -> Tuple[SealedReceipt, ...]:
        result = []
        for section in self._store["sources"].values():
            result.extend(SealedReceipt.from_dict(value) for value in section.get("receipts") or [])
        return tuple(result)

    @property
    def sealed_receipts(self) -> Tuple[SealedReceipt, ...]:
        receipts = self.sealed_receipts_for_source()
        return receipts if receipts else self.sealed_receipts_for_all_sources()

    @property
    def receipts(self) -> Tuple[SealedReceipt, ...]:
        return self.sealed_receipts

    @property
    def header_receipt(self) -> Optional[SealedReceipt]:
        for receipt in self.sealed_receipts_for_source():
            if receipt.kind == "header":
                return receipt
        return None

    @property
    def entry_receipts(self) -> Tuple[SealedReceipt, ...]:
        return tuple(receipt for receipt in self.sealed_receipts_for_source()
                     if receipt.kind == "directory_entry")

    @property
    def receipt_map(self) -> Dict[int, SealedReceipt]:
        return {
            receipt.ordinal: receipt
            for receipt in self.sealed_receipts_for_source()
            if receipt.kind == "directory_entry"
        }

    @property
    def all_receipts(self) -> Tuple[SealedReceipt, ...]:
        return self.sealed_receipts_for_all_sources()

    @property
    def receipts_by_source(self) -> Dict[str, Tuple[SealedReceipt, ...]]:
        return {
            source_id: tuple(SealedReceipt.from_dict(value) for value in section.get("receipts") or [])
            for source_id, section in self._store["sources"].items()
        }

    # ------------------------------------------------------------------
    # Read/resume path
    # ------------------------------------------------------------------
    def _ensure_header(self, section: Dict[str, Any]) -> None:
        identity = self._identity
        assert identity is not None

        if section.get("header") is None:
            raw = self._read_at(0, 32)
            header = MinidumpHeader.parse(io.BytesIO(raw))
            if header.NumberOfStreams is None or header.NumberOfStreams < 0:
                raise DirectoryIndexCorruptionError("Header contains an invalid stream count")
            if header.NumberOfStreams > MAX_DIRECTORY_ENTRIES:
                raise DirectoryIndexCorruptionError("Header stream count is unreasonably large")
            receipt = self._seal(
                section, "header", -1, 0, raw,
                {
                    "signature": raw[:4].decode("ascii", "replace"),
                    "version": header.Version,
                    "implementation_version": header.ImplementationVersion,
                    "number_of_streams": header.NumberOfStreams,
                    "stream_directory_rva": header.StreamDirectoryRva,
                },
            )
            section["header"] = {
                "raw": _b64(raw),
                "raw_sha256": _sha256(raw),
                "receipt_seal": receipt.seal,
                "signature": raw[:4].decode("ascii", "replace"),
                "version": header.Version,
                "implementation_version": header.ImplementationVersion,
                "number_of_streams": header.NumberOfStreams,
                "stream_directory_rva": header.StreamDirectoryRva,
                "check_sum": header.CheckSum,
                "time_date_stamp": header.TimeDateStamp,
                "flags": int(header.Flags.value) if header.Flags is not None else 0,
            }
            section["number_of_streams"] = int(header.NumberOfStreams)
            section["stream_directory_rva"] = int(header.StreamDirectoryRva)
            self._section = section
            return

        stored = section["header"]
        raw = self._read_at(0, 32)
        if _sha256(raw) != stored.get("raw_sha256") or _b64(raw) != stored.get("raw"):
            raise SourceIdentityMismatchError(
                "Header read from the source does not match the sealed header for this source",
                expected_source_id=identity.source_id,
                actual_source_id=identity.source_id,
            )
        header = MinidumpHeader.parse(io.BytesIO(raw))
        if int(header.NumberOfStreams) != int(section.get("number_of_streams", -1)):
            raise SourceIdentityMismatchError(
                "Header stream count does not match the sealed header",
                expected_source_id=identity.source_id,
                actual_source_id=identity.source_id,
            )
        if int(header.StreamDirectoryRva) != int(section.get("stream_directory_rva", -1)):
            raise SourceIdentityMismatchError(
                "Header directory RVA does not match the sealed header",
                expected_source_id=identity.source_id,
                actual_source_id=identity.source_id,
            )
        receipts = section.get("receipts") or []
        if not receipts or receipts[0].get("kind") != "header":
            raise DirectoryIndexCorruptionError("Header receipt is missing")
        if receipts[0].get("seal") != stored.get("receipt_seal"):
            raise DirectoryIndexCorruptionError("Header receipt does not match its seal")

    def _read_and_confirm_entry(self, section: Dict[str, Any], index: int) -> DirectoryEntry:
        assert self._identity is not None
        header_rva = int(section["stream_directory_rva"])
        number_of_streams = int(section["number_of_streams"])
        if index < 0 or index >= number_of_streams:
            raise DirectoryIndexError("Directory entry index %d is out of range" % index)
        offset = header_rva + index * 12
        raw = self._read_at(offset, 12)
        stream_type, data_size, rva = struct.unpack("<III", raw)

        receipt_map = self._receipt_map(section)
        existing_receipt = receipt_map.get(index)
        entries = section.setdefault("entries", [])
        existing_entry = entries[index] if index < len(entries) else None

        if existing_entry is not None:
            if existing_entry.get("source_id") != self._identity.source_id:
                raise SourceIdentityMismatchError(
                    "Directory entry %d is bound to a different source identity" % index,
                    expected_source_id=existing_entry.get("source_id"),
                    actual_source_id=self._identity.source_id,
                )
            if int(existing_entry["stream_type"]) != stream_type or int(existing_entry["data_size"]) != data_size or int(existing_entry["rva"]) != rva:
                raise DirectoryEntryMismatchError(
                    "Directory entry %d read from the source does not match the previously sealed entry" % index,
                    expected_source_id=existing_entry.get("source_id"),
                    actual_source_id=self._identity.source_id,
                )
            if existing_entry.get("raw_sha256") != _sha256(raw):
                raise DirectoryEntryMismatchError(
                    "Directory entry %d raw bytes do not match the previously sealed bytes" % index,
                    expected_source_id=existing_entry.get("source_id"),
                    actual_source_id=self._identity.source_id,
                )
            if existing_receipt is None:
                raise DirectoryIndexCorruptionError("Directory entry %d has no sealed receipt" % index)
            if existing_receipt.digest != _sha256(raw):
                raise DirectoryEntryMismatchError(
                    "Directory entry %d receipt does not confirm the bytes read now" % index,
                    expected_source_id=existing_receipt.source_id,
                    actual_source_id=self._identity.source_id,
                )
            return DirectoryEntry.from_dict(existing_entry, {index: existing_receipt})

        previous = self._last_receipt(section)
        expected_previous = previous.seal if previous is not None else GENESIS_DIGEST
        if existing_receipt is not None and existing_receipt.previous_digest != expected_previous:
            raise DirectoryIndexCorruptionError("Receipt chain has a gap before entry %d" % index)

        receipt = self._seal(
            section, "directory_entry", index, offset, raw,
            {"stream_type": stream_type, "data_size": data_size, "rva": rva},
        )
        entry = DirectoryEntry(
            index=index,
            stream_type=stream_type,
            stream_type_name=_stream_type_name(stream_type),
            data_size=data_size,
            rva=rva,
            raw_sha256=_sha256(raw),
            source_id=self._identity.source_id,
            receipt=receipt,
            raw=raw,
        )
        entries.append(entry.to_dict())
        return entry

    def _check_cursor_source(self, identity: SourceIdentity) -> None:
        cursor_raw = self._store.get("cursor")
        if cursor_raw is None:
            return
        cursor = DirectoryCursor.from_dict(cursor_raw)
        if cursor.source_id == identity.source_id:
            return
        if not self.allow_source_change:
            raise MisappliedCursorError(
                "Misapplied cursor: the index cursor was sealed for source %r, but %r now has source %r. "
                "Refusing to treat the old index as confirmation of the new file; sealed receipts were preserved." % (
                    cursor.source_id, self._source_name(), identity.source_id),
                expected_source_id=cursor.source_id,
                actual_source_id=identity.source_id,
                cursor=cursor,
            )
        LOG.warning("Explicitly starting a new directory index section for %r; old receipts are retained",
                    identity.source_id)

    def verify_cursor(self, source_id: Optional[str] = None) -> DirectoryCursor:
        """Return the cursor after verifying that it belongs to the source."""
        identity = self._identity or self._compute_identity()
        if source_id is not None and source_id != identity.source_id:
            raise SourceIdentityMismatchError(
                "Requested source identity does not match the current source",
                expected_source_id=source_id,
                actual_source_id=identity.source_id,
            )
        self._check_cursor_source(identity)
        cursor = self.cursor
        if cursor is None:
            cursor = DirectoryCursor(source_id=identity.source_id, next_entry=0)
        return cursor

    assert_cursor = verify_cursor

    def resume(self, max_entries: Optional[int] = None, *, save: bool = True,
               max_new_entries: Optional[int] = None, limit: Optional[int] = None,
               allow_source_change: Optional[bool] = None,
               start_new: bool = False, fresh: bool = False) -> "OfflineDirectoryIndex":
        """Load or continue the index, reading at most *max_entries* new entries."""
        if max_entries is None:
            max_entries = max_new_entries if max_new_entries is not None else limit
        if allow_source_change is not None:
            self.allow_source_change = bool(allow_source_change)
        if start_new or fresh:
            self.allow_source_change = True
        with self._lock:
            self._assert_open()
            identity = self._identity or self._compute_identity()
            self._check_cursor_source(identity)

            section = self._section_for(identity, create=True)
            assert section is not None
            self._section = section

            cursor_raw = self._store.get("cursor")
            if cursor_raw is None or cursor_raw.get("source_id") != identity.source_id:
                next_entry = len(section.get("entries") or [])
                self.set_cursor(next_entry, identity.source_id)
            else:
                next_entry = int(cursor_raw["next_entry"])
                if next_entry > len(section.get("entries") or []):
                    raise DirectoryIndexCorruptionError(
                        "Cursor points beyond the entries sealed in the index")

            self._ensure_header(section)
            if save:
                self.save()

            number_of_streams = int(section["number_of_streams"])
            while next_entry < number_of_streams:
                if max_entries is not None and max_entries <= 0:
                    break
                self._read_and_confirm_entry(section, next_entry)
                next_entry += 1
                if max_entries is not None:
                    max_entries -= 1
                self.set_cursor(next_entry, identity.source_id)
                section["complete"] = next_entry >= number_of_streams
                if save:
                    self.save()
                if max_entries is not None and max_entries <= 0:
                    break

            section["complete"] = next_entry >= number_of_streams
            if save:
                self.save()
            return self

    def build(self, max_entries: Optional[int] = None, *, save: bool = True,
              max_new_entries: Optional[int] = None, limit: Optional[int] = None,
              allow_source_change: Optional[bool] = None,
              start_new: bool = False, fresh: bool = False) -> "OfflineDirectoryIndex":
        return self.resume(max_entries=max_entries, save=save,
                           max_new_entries=max_new_entries, limit=limit,
                           allow_source_change=allow_source_change,
                           start_new=start_new, fresh=fresh)

    def read_next(self, *, save: bool = True) -> Optional[DirectoryEntry]:
        """Read and independently confirm exactly one new directory entry."""
        with self._lock:
            identity = self._identity or self._compute_identity()
            self._check_cursor_source(identity)
            section = self._section_for(identity, create=True)
            assert section is not None
            self._section = section
            cursor_raw = self._store.get("cursor")
            if cursor_raw is None or cursor_raw.get("source_id") != identity.source_id:
                self.set_cursor(len(section.get("entries") or []), identity.source_id)
            self._ensure_header(section)
            next_entry = self.next_entry
            if next_entry >= int(section["number_of_streams"]):
                section["complete"] = True
                if save:
                    self.save()
                return None
            entry = self._read_and_confirm_entry(section, next_entry)
            self.set_cursor(next_entry + 1, identity.source_id)
            section["complete"] = next_entry + 1 >= int(section["number_of_streams"])
            if save:
                self.save()
            return entry

    def step(self, *, save: bool = True) -> Optional[DirectoryEntry]:
        return self.read_next(save=save)

    def next(self, *, save: bool = True) -> Optional[DirectoryEntry]:
        return self.read_next(save=save)

    def start_new_source(self, max_entries: Optional[int] = None) -> "OfflineDirectoryIndex":
        """Explicitly begin a separate section for the file now at the source path."""
        self.allow_source_change = True
        return self.resume(max_entries=max_entries)

    # ------------------------------------------------------------------
    # Public views
    # ------------------------------------------------------------------
    @property
    def header_section(self) -> Optional[Dict[str, Any]]:
        sid = self.source_id
        if sid is None:
            return None
        return self._store["sources"].get(sid, {}).get("header")

    @property
    def header(self) -> Optional[MinidumpHeader]:
        stored = self.header_section
        if stored is None:
            return None
        raw = _unb64(stored["raw"])
        return MinidumpHeader.parse(io.BytesIO(raw))

    @property
    def header_bytes(self) -> Optional[bytes]:
        stored = self.header_section
        return _unb64(stored["raw"]) if stored is not None else None

    @property
    def header_hash(self) -> Optional[str]:
        stored = self.header_section
        return stored.get("raw_sha256") if stored is not None else None

    @property
    def directory_entry_count(self) -> int:
        return len(self.entries)

    @property
    def entries(self) -> List[DirectoryEntry]:
        sid = self.source_id
        if sid is None:
            return []
        section = self._store["sources"].get(sid)
        if section is None:
            return []
        receipts = self._receipt_map(section)
        return [DirectoryEntry.from_dict(value, receipts) for value in section.get("entries") or []]

    @property
    def directory_entries(self) -> List[DirectoryEntry]:
        return self.entries

    def entries_for_source(self, source_id: str) -> List[DirectoryEntry]:
        section = self._store["sources"].get(source_id)
        if section is None:
            return []
        receipts = self._receipt_map(section)
        return [DirectoryEntry.from_dict(value, receipts) for value in section.get("entries") or []]

    def directories_for_source(self, source_id: str) -> List[MINIDUMP_DIRECTORY]:
        return [entry.to_directory() for entry in self.entries_for_source(source_id)]

    @property
    def entries_by_source(self) -> Dict[str, List[DirectoryEntry]]:
        return {
            source_id: self.entries_for_source(source_id)
            for source_id in self._store["sources"]
        }

    @property
    def directories(self) -> List[MINIDUMP_DIRECTORY]:
        return [entry.to_directory() for entry in self.entries]

    @property
    def number_of_streams(self) -> int:
        sid = self.source_id
        if sid is None:
            return 0
        return int(self._store["sources"].get(sid, {}).get("number_of_streams", 0))

    @property
    def remaining(self) -> int:
        return max(0, self.number_of_streams - self.next_entry)

    @property
    def complete(self) -> bool:
        return self.header_section is not None and self.remaining == 0

    @property
    def is_complete(self) -> bool:
        return self.complete

    @property
    def index(self):
        return self

    @property
    def sections(self) -> Dict[str, Any]:
        return self._store["sources"]

    @property
    def closed(self) -> bool:
        return self._closed

    def _assert_open(self):
        if self._closed:
            raise DirectoryIndexError("Directory index is closed")

    def close(self):
        if self._source_owned and self._source_handle is not None:
            try:
                self._source_handle.close()
            except OSError:
                pass
        self._source_handle = None
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __str__(self):
        return "OfflineDirectoryIndex(source=%r, entries=%d/%d, complete=%s)" % (
            self._source_name(), self.next_entry, self.number_of_streams, self.complete)

    def __iter__(self):
        return iter(self.directories)

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, item):
        return self.directories[item]


class OfflineDirectoryIndexBuilder(OfflineDirectoryIndex):
    """Explicit builder spelling for :class:`OfflineDirectoryIndex`."""


class DirectoryIndexBuilder(OfflineDirectoryIndexBuilder):
    pass


class MinidumpDirectoryIndex(OfflineDirectoryIndex):
    pass


class MinidumpOfflineDirectoryIndex(OfflineDirectoryIndex):
    pass


class ResumableDirectoryIndex(OfflineDirectoryIndex):
    pass


DirectoryIndex = OfflineDirectoryIndex
DirectoryIndexStore = OfflineDirectoryIndex
OfflineDirectoryIndexStore = OfflineDirectoryIndex
SourceId = SourceIdentity
ImmutableSourceId = SourceIdentity
ImmutableSourceIdentity = SourceIdentity
DirectoryIndexEntry = DirectoryEntry
DirectoryRecord = DirectoryEntry
ReadReceipt = SealedReceipt
SealedReadReceipt = SealedReceipt
ConfirmedRead = SealedReceipt
ConfirmedReadRecord = SealedReceipt
ReadRecord = SealedReceipt
Cursor = DirectoryCursor
DirectoryIndexCursor = DirectoryCursor


def build_offline_directory_index(source, index_path=None, max_entries: Optional[int] = None,
                                  **kwargs) -> OfflineDirectoryIndex:
    index = OfflineDirectoryIndex(source, index_path, **kwargs)
    try:
        return index.build(max_entries=max_entries)
    except Exception:
        index.close()
        raise


def resume_offline_directory_index(source, index_path=None, max_entries: Optional[int] = None,
                                   **kwargs) -> OfflineDirectoryIndex:
    return build_offline_directory_index(source, index_path, max_entries=max_entries, **kwargs)


def build_directory_index(source, index_path=None, max_entries: Optional[int] = None,
                          **kwargs) -> OfflineDirectoryIndex:
    return build_offline_directory_index(source, index_path, max_entries=max_entries, **kwargs)


def resume_directory_index(source, index_path=None, max_entries: Optional[int] = None,
                           **kwargs) -> OfflineDirectoryIndex:
    return build_offline_directory_index(source, index_path, max_entries=max_entries, **kwargs)


def load_directory_index(index_path, *, recover: bool = True) -> OfflineDirectoryIndex:
    return OfflineDirectoryIndex.load(index_path, recover=recover)


load_index = load_directory_index
build_index = build_directory_index
build_offline_index = build_directory_index
create_directory_index = build_directory_index
resume_index = resume_directory_index
resume_offline_index = resume_directory_index


__all__ = [
    "INDEX_FORMAT", "INDEX_VERSION", "DEFAULT_INDEX_SUFFIX", "GENESIS_DIGEST",
    "DirectoryIndexError", "OfflineDirectoryIndexError", "DirectoryIndexCorruptionError",
    "DirectoryIndexTruncatedError", "SourceIdentityMismatchError", "MisappliedCursorError",
    "DirectoryEntryMismatchError", "SourceChangedError", "SourcePathReplacedError",
    "CursorSourceMismatchError", "StaleCursorError", "WrongCursorError", "IndexCorruptionError",
    "MisusedCursorError", "CursorMisuseError", "SourceMismatchError", "SourceIdentity", "SourceId",
    "ImmutableSourceId", "ImmutableSourceIdentity", "DirectoryCursor", "Cursor", "DirectoryIndexCursor",
    "SealedReceipt", "ReadReceipt", "SealedReadReceipt", "ConfirmedRead", "ConfirmedReadRecord",
    "ReadRecord", "DirectoryEntry", "DirectoryIndexEntry", "DirectoryRecord",
    "OfflineDirectoryIndex", "DirectoryIndexStore", "OfflineDirectoryIndexStore",
    "OfflineDirectoryIndexBuilder", "DirectoryIndexBuilder", "MinidumpDirectoryIndex",
    "MinidumpOfflineDirectoryIndex", "ResumableDirectoryIndex", "DirectoryIndex",
    "default_index_path", "build_offline_directory_index", "resume_offline_directory_index",
    "build_directory_index", "create_directory_index", "build_index", "build_offline_index",
    "resume_directory_index", "resume_index", "resume_offline_index", "load_directory_index",
    "load_index",
]
