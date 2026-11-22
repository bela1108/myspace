#!/usr/bin/env python
"""
olemanifest.py

Read-only extraction manifests for objects embedded in Office documents.

An extraction manifest is a collection of *references*.  Each reference binds
one occurrence of an embedded object to:

* the parent document it was found in,
* the member path within that document (a zip member or an OLE stream path),
* a digest of the extracted content,
* the disclosure level supplied by the caller.

The same content may occur in several parents.  Payload bytes are stored once
in a content-addressed blob store, keyed by SHA-256, while every occurrence
keeps its own reference.  This is intentional: reusing a blob must never make
a restricted occurrence public merely because the same bytes also occur in a
public document.

The module is intentionally read-only with respect to its inputs.  It opens
Office files with olefile/zipfile in read mode and only writes data when the
caller explicitly asks for a manifest or a persistent blob store.

This module is part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

from __future__ import print_function

import argparse
import hashlib
import io
import json
import os
import sys
import zipfile
from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

import olefile

from oletools.common.io_encoding import ensure_stdout_handles_unicode


MANIFEST_SCHEMA = "oletools.extraction-manifest/v1"
DIGEST_ALGORITHM = "sha256"
DEFAULT_DISCLOSURE_LEVEL = "unspecified"
MAX_NESTING_DEPTH = 8

# Markers used to avoid trying to expand arbitrary payloads.
OLE_MAGIC = olefile.MAGIC
ZIP_MAGIC = b"PK\x03\x04"


def digest_bytes(data):
    """Return the canonical (unprefixed) SHA-256 hex digest for *data*."""
    return hashlib.sha256(data).hexdigest()


def _as_bytes(data):
    """Convert a bytes-like object to bytes without altering its contents."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    if hasattr(data, "read"):
        return data.read()
    return bytes(data)


def normalize_disclosure_level(level):
    """Return a JSON-friendly disclosure label supplied by the caller."""
    if level is None:
        return DEFAULT_DISCLOSURE_LEVEL
    # Enum values (for callers that use one) are represented by their value.
    if hasattr(level, "value") and not isinstance(level, (str, int, float)):
        level = level.value
    if isinstance(level, bytes):
        level = level.decode("utf-8", "replace")
    if isinstance(level, (str, int, float, bool)) or level is None:
        return level
    return str(level)


@dataclass(frozen=True)
class ContentBlob:
    """One copy of extracted content, addressed by its SHA-256 digest."""

    content_digest: str
    size: int
    data: bytes
    storage_path: Optional[str] = None

    @property
    def digest(self):
        return self.content_digest

    @property
    def sha256(self):
        return self.content_digest

    @property
    def content_sha256(self):
        return self.content_digest

    @property
    def blob_key(self):
        return self.content_digest

    def to_dict(self, include_references=None):
        result = {
            "content_digest": self.content_digest,
            "digest": self.content_digest,
            "digest_algorithm": DIGEST_ALGORITHM,
            "size": self.size,
            "storage_path": self.storage_path,
        }
        if include_references is not None:
            result["references"] = list(include_references)
        return result


class BlobStore(object):
    """Content-addressed storage that stores identical bytes only once.

    The store is in-memory by default.  If ``root`` is provided, each blob is
    also written below ``root/<first two hex chars>/<full digest>``.  Existing
    files are reused and never overwritten.
    """

    def __init__(self, root=None):
        self.root = os.fspath(root) if root is not None else None
        self._blobs = OrderedDict()

    def put(self, data):
        """Store *data* and return its :class:`ContentBlob`."""
        data = _as_bytes(data)
        digest = digest_bytes(data)
        blob = self._blobs.get(digest)
        if blob is None or (not blob.data and data):
            storage_path = None
            if blob is not None:
                storage_path = blob.storage_path
            elif self.root is not None:
                storage_path = os.path.join(self.root, digest[:2], digest)
                if not os.path.exists(storage_path):
                    parent = os.path.dirname(storage_path)
                    if not os.path.isdir(parent):
                        os.makedirs(parent)
                    with open(storage_path, "wb") as handle:
                        handle.write(data)
            blob = ContentBlob(
                content_digest=digest,
                size=len(data),
                data=data,
                storage_path=storage_path,
            )
            self._blobs[digest] = blob
        return blob

    add = put

    def get_blob(self, digest):
        return self._blobs.get(digest)

    def __getitem__(self, digest):
        return self._blobs[digest]

    def get_data(self, digest):
        return self.get(digest)

    def get(self, digest):
        blob = self._blobs.get(digest)
        return None if blob is None else blob.data

    def __contains__(self, digest):
        return digest in self._blobs

    def __len__(self):
        return len(self._blobs)

    def __iter__(self):
        return iter(self._blobs)

    def items(self):
        return self._blobs.items()

    @property
    def count(self):
        return len(self._blobs)

    @property
    def digests(self):
        return tuple(self._blobs)

    @property
    def blobs(self):
        return self._blobs

    def as_dict(self):
        return OrderedDict(
            (digest, blob.to_dict()) for digest, blob in self._blobs.items()
        )


@dataclass(frozen=True)
class ManifestEntry:
    """Immutable record for one occurrence of an embedded object."""

    reference_id: str
    parent_path: str
    container_member_path: str
    content_digest: str
    size: int
    disclosure_level: Any = DEFAULT_DISCLOSURE_LEVEL
    status: str = "confirmed"
    unconfirmed_range: Optional[Tuple[int, int]] = None
    unconfirmed_scope: Optional[str] = None
    stream_path: Optional[str] = None
    container_type: str = "unknown"
    occurrence: int = 0
    depth: int = 0

    # Common aliases used by callers and by earlier drafts of this module.
    @property
    def digest(self):
        return self.content_digest

    @property
    def sha256(self):
        return self.content_digest

    @property
    def reference(self):
        return self.reference_id

    @property
    def container_path(self):
        return self.parent_path

    @property
    def parent(self):
        return self.parent_path

    @property
    def member_path(self):
        return self.container_member_path

    @property
    def source(self):
        return self.parent_path

    @property
    def source_path(self):
        return self.parent_path

    @property
    def container(self):
        return self.parent_path

    @property
    def member(self):
        return self.container_member_path

    @property
    def path(self):
        return self.locator

    @property
    def locator(self):
        result = "%s!%s" % (self.parent_path, self.container_member_path)
        if (self.stream_path and
                self.stream_path != self.container_member_path):
            prefix = self.container_member_path + "!/"
            if self.stream_path.startswith(prefix):
                result += self.stream_path[len(
                    self.container_member_path):]
            else:
                result += "!/" + self.stream_path
        return result

    @property
    def disclosure(self):
        return self.disclosure_level

    @property
    def level(self):
        return self.disclosure_level

    @property
    def range(self):
        return self.unconfirmed_range

    @property
    def interval(self):
        return self.unconfirmed_range

    @property
    def confirmed(self):
        return self.status == "confirmed" and self.unconfirmed_range is None

    @property
    def is_confirmed(self):
        return self.confirmed

    def to_dict(self):
        result = OrderedDict()
        result["reference_id"] = self.reference_id
        result["parent_path"] = self.parent_path
        result["container_member_path"] = self.container_member_path
        result["stream_path"] = self.stream_path
        result["content_digest"] = self.content_digest
        result["sha256"] = self.content_digest
        result["digest_algorithm"] = DIGEST_ALGORITHM
        result["size"] = self.size
        result["disclosure_level"] = self.disclosure_level
        result["status"] = self.status
        result["confirmed"] = self.confirmed
        result["unconfirmed_range"] = (
            None
            if self.unconfirmed_range is None
            else list(self.unconfirmed_range)
        )
        result["unconfirmed_interval"] = (
            None
            if self.unconfirmed_range is None
            else {
                "start": self.unconfirmed_range[0],
                "end": self.unconfirmed_range[1],
                "length": (self.unconfirmed_range[1] -
                           self.unconfirmed_range[0]),
            }
        )
        result["unconfirmed_scope"] = self.unconfirmed_scope
        result["container_type"] = self.container_type
        result["occurrence"] = self.occurrence
        result["depth"] = self.depth
        result["storage_key"] = self.content_digest

        # Explicit aliases make the JSON convenient to consume while keeping
        # the canonical names above.
        result["reference"] = self.reference_id
        result["container_path"] = self.parent_path
        result["member_path"] = self.container_member_path
        result["digest"] = self.content_digest
        result["disclosure"] = self.disclosure_level
        result["unconfirmed"] = result["unconfirmed_range"]
        result["source"] = self.parent_path
        result["parent"] = self.parent_path
        result["parent_file"] = self.parent_path
        result["locator"] = self.locator
        return result

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)


class ExtractionManifest(object):
    """Read-only manifest of embedded objects extracted from Office files."""

    def __init__(self, sources=None, disclosures=None, blob_store=None,
                 disclosure_level=None, root=None, default_disclosure=None,
                 disclosure=None, **kwargs):
        if blob_store is None:
            blob_store = BlobStore(root=root)
        if disclosure_level is None:
            disclosure_level = (
                disclosure if disclosure is not None
                else default_disclosure)
        self.blob_store = blob_store
        self._entries = []
        self._occurrences = defaultdict(int)
        self._frozen = False
        if sources is not None:
            self.add_many(
                sources,
                disclosures=disclosures,
                default_disclosure=disclosure_level,
            )

    # -- construction -----------------------------------------------------

    def _ensure_writable(self):
        if self._frozen:
            raise RuntimeError("extraction manifest is read-only")

    def freeze(self):
        """Freeze the reference list; subsequent additions are rejected."""
        self._frozen = True
        return self

    @property
    def frozen(self):
        return self._frozen

    @property
    def read_only(self):
        return True

    @property
    def is_read_only(self):
        return True

    def add_file(self, filename, disclosure_level=None, data=None,
                 disclosure=None):
        """Extract embedded objects from one parent file.

        ``data`` may be supplied to avoid reopening the file (matching
        :func:`oletools.oleobj.process_file`).  The source file itself is never
        modified.
        """
        self._ensure_writable()
        if disclosure_level is None:
            disclosure_level = disclosure
        disclosure_level = normalize_disclosure_level(disclosure_level)

        if data is None:
            with open(filename, "rb") as handle:
                data = handle.read()
        else:
            data = _as_bytes(data)

        parent_path = os.fspath(filename)
        start = len(self._entries)
        self._extract_parent(parent_path, data, disclosure_level)
        return tuple(self._entries[start:])

    def add(self, filename, disclosure_level=None, data=None, **kwargs):
        return self.add_file(
            filename, disclosure_level=disclosure_level, data=data, **kwargs
        )

    extract = add

    add_source = add
    add_path = add
    add_document = add
    extract_file = add

    def add_many(self, sources, disclosures=None, default_disclosure=None):
        """Add several sources.

        ``sources`` can be a path, a list of paths, a list of
        ``(path, disclosure)`` pairs, or a mapping of path to disclosure.
        """
        self._ensure_writable()
        if isinstance(sources, Mapping):
            items = list(sources.items())
        elif isinstance(sources, (str, bytes, os.PathLike)):
            items = [(sources, None)]
        elif hasattr(sources, "read") and hasattr(sources, "name"):
            items = [(sources, None)]
        elif (isinstance(sources, tuple) and len(sources) == 2
              and not hasattr(sources[0], "read")):
            items = [self._split_source(sources, default_disclosure)]
        else:
            items = []
            for source in sources:
                items.append(self._split_source(source, None))

        disclosure_map = self._normalize_disclosure_map(disclosures)
        added = []
        for source, level in items:
            filename = self._source_name(source)
            if level is None and filename is not None:
                level = disclosure_map.get(filename)
                if level is None:
                    level = disclosure_map.get(
                        os.path.basename(filename))
            if level is None:
                level = default_disclosure
            data = None
            if hasattr(source, "read"):
                if not hasattr(source, "name"):
                    raise ValueError("file-like sources must have a name")
                data = source.read()
            added.extend(
                self.add_file(filename, disclosure_level=level, data=data)
            )
        return tuple(added)

    @staticmethod
    def _source_name(source):
        if hasattr(source, "name"):
            return source.name
        return os.fspath(source)

    @staticmethod
    def _split_source(source, default_disclosure):
        if isinstance(source, Mapping):
            filename = (
                source.get("filename")
                or source.get("path")
                or source.get("name")
                or source.get("parent_path")
            )
            level = (
                source.get("disclosure_level")
                if "disclosure_level" in source
                else source.get("disclosure", default_disclosure)
            )
            return filename, level
        if (
            isinstance(source, (tuple, list))
            and len(source) == 2
            and not hasattr(source[0], "read")
        ):
            return source[0], source[1]
        return source, default_disclosure

    @staticmethod
    def _normalize_disclosure_map(disclosures):
        if disclosures is None:
            return {}
        if isinstance(disclosures, Mapping):
            result = {}
            for key, value in disclosures.items():
                result[os.fspath(key)] = value
                result[os.path.basename(os.fspath(key))] = value
            return result
        result = {}
        for item in disclosures:
            if isinstance(item, Mapping):
                key = item.get("path") or item.get("filename")
                value = item.get("disclosure_level", item.get("disclosure"))
            else:
                key, value = item
            result[os.fspath(key)] = value
            result[os.path.basename(os.fspath(key))] = value
        return result

    @classmethod
    def from_files(cls, sources, disclosures=None, **kwargs):
        manifest = cls()
        manifest.add_many(sources, disclosures=disclosures, **kwargs)
        return manifest

    # -- extraction -------------------------------------------------------

    def _extract_parent(self, parent_path, data, disclosure_level):
        if data[:len(OLE_MAGIC)] == OLE_MAGIC:
            if self._extract_ppt_parent(
                    parent_path, data, disclosure_level):
                return
            self._extract_ole_parent(parent_path, data, disclosure_level)
        elif data[:4] == ZIP_MAGIC or zipfile.is_zipfile(io.BytesIO(data)):
            self._extract_zip_parent(parent_path, data, disclosure_level)

    def _extract_ppt_parent(self, parent_path, data, disclosure_level):
        """Extract OLE objects stored in PowerPoint record streams."""
        ppt_file = None
        try:
            probe = olefile.OleFileIO(_BytesFile(data))
            try:
                names = [parts[0].lower() for parts in probe.listdir()
                         if parts]
            finally:
                probe.close()
            if "powerpoint document" not in names:
                return False
            from oletools.ppt_record_parser import (
                PptFile, PptRecordExOleVbaActiveXAtom)
            ppt_file = PptFile(_BytesFile(data))
            found = False
            for stream in ppt_file.iter_streams():
                for record_index, record in enumerate(
                        stream.iter_records()):
                    if not isinstance(
                            record, PptRecordExOleVbaActiveXAtom):
                        continue
                    try:
                        start = next(record.iter_uncompressed())
                    except Exception:
                        continue
                    if start[:len(OLE_MAGIC)] != OLE_MAGIC:
                        continue
                    ole = None
                    try:
                        ole = record.get_data_as_olefile()
                    except Exception:
                        continue
                    if ole is None:
                        continue
                    found = True
                    member = "%s#record/%d" % (
                        stream.name, record_index)
                    try:
                        self._extract_payloads_from_ole(
                            ole,
                            parent_path=parent_path,
                            container_member_path=member,
                            stream_prefix=member,
                            disclosure_level=disclosure_level,
                            container_type="ppt",
                            depth=0,
                        )
                    finally:
                        ole.close()
            return found
        except Exception:
            return False
        finally:
            if ppt_file is not None:
                ppt_file.close()

    def _extract_ole_parent(self, parent_path, data, disclosure_level):
        ole = None
        try:
            ole = olefile.OleFileIO(_BytesFile(data))
            self._extract_payloads_from_ole(
                ole,
                parent_path=parent_path,
                container_member_path=None,
                stream_prefix="",
                disclosure_level=disclosure_level,
                container_type="ole",
                depth=0,
            )
        except Exception:
            # A malformed top-level OLE document is not an extracted content
            # occurrence by itself, so there is no reference to add here.
            return
        finally:
            if ole is not None:
                ole.close()

    def _extract_zip_parent(self, parent_path, data, disclosure_level):
        try:
            archive = zipfile.ZipFile(io.BytesIO(data), "r")
        except Exception:
            return
        try:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                try:
                    member_data = archive.read(info)
                except Exception:
                    continue
                self._extract_container_member(
                    parent_path=parent_path,
                    member_path=info.filename,
                    member_data=member_data,
                    disclosure_level=disclosure_level,
                    container_type="zip",
                    depth=0,
                )
        finally:
            archive.close()

    def _extract_container_member(self, parent_path, member_path, member_data,
                                  disclosure_level, container_type, depth):
        if member_data[:len(OLE_MAGIC)] == OLE_MAGIC:
            self._extract_ole_member(
                parent_path=parent_path,
                member_path=member_path,
                member_data=member_data,
                disclosure_level=disclosure_level,
                container_type=container_type,
                depth=depth,
            )
            return

        lowered = member_path.lower()
        if (
            container_type == "zip"
            and ("/embeddings/" in lowered or lowered.endswith("/embeddings"))
            and member_data
        ):
            self._record_payload(
                parent_path=parent_path,
                container_member_path=member_path,
                stream_path=member_path,
                payload=member_data,
                disclosure_level=disclosure_level,
                container_type=container_type,
                depth=depth,
            )

    def _extract_ole_member(self, parent_path, member_path, member_data,
                            disclosure_level, container_type, depth):
        ole = None
        try:
            ole = olefile.OleFileIO(_BytesFile(member_data))
            found = self._extract_payloads_from_ole(
                ole,
                parent_path=parent_path,
                container_member_path=member_path,
                stream_prefix="",
                disclosure_level=disclosure_level,
                container_type=container_type,
                depth=depth,
            )
            if not found:
                # No Ole10Native stream: the OLE member itself may be the
                # attachment.  Keep it as one unsigned payload occurrence.
                self._record_payload(
                    parent_path=parent_path,
                    container_member_path=member_path,
                    stream_path=member_path,
                    payload=member_data,
                    disclosure_level=disclosure_level,
                    container_type=container_type,
                    depth=depth,
                )
        except Exception:
            # A member with an OLE signature that cannot be opened is a
            # synthetic/truncated nested object.  The whole member is the
            # unconfirmed interval.
            self._record_payload(
                parent_path=parent_path,
                container_member_path=member_path,
                stream_path=member_path,
                payload=member_data,
                disclosure_level=disclosure_level,
                container_type=container_type,
                depth=depth,
                status="unconfirmed",
                unconfirmed_range=(0, len(member_data)),
                unconfirmed_scope="container_member",
            )
        finally:
            if ole is not None:
                ole.close()

    def _extract_payloads_from_ole(self, ole, parent_path,
                                   container_member_path, stream_prefix,
                                   disclosure_level, container_type, depth):
        found = 0
        try:
            paths = ole.listdir()
        except Exception:
            return found

        for parts in paths:
            if not parts:
                continue
            name = parts[-1]
            lower = name.lower()
            if lower not in ("\x01ole10native", "\x01package"):
                continue
            stream_path = "/".join(parts)
            if stream_prefix:
                full_stream_path = stream_prefix + "!/" + stream_path
            elif container_member_path is not None:
                full_stream_path = container_member_path + "!/" + stream_path
            else:
                full_stream_path = stream_path
            if container_member_path is None:
                member_path = stream_path
            else:
                member_path = container_member_path

            try:
                stream = ole.openstream(parts)
                try:
                    raw_stream = stream.read()
                finally:
                    stream.close()
            except Exception:
                continue

            try:
                from oletools import oleobj
                opkg = oleobj.OleNativeStream(
                    raw_stream,
                    package=(lower == "\x01package"),
                )
            except Exception:
                self._record_payload(
                    parent_path=parent_path,
                    container_member_path=member_path,
                    stream_path=full_stream_path,
                    payload=raw_stream,
                    disclosure_level=disclosure_level,
                    container_type=container_type,
                    depth=depth,
                    status="unconfirmed",
                    unconfirmed_range=(0, len(raw_stream)),
                    unconfirmed_scope="stream",
                )
                found += 1
                continue

            if opkg.is_link or opkg.data is None:
                continue
            payload = _as_bytes(opkg.data)
            status = "confirmed"
            unconfirmed_range = None
            unconfirmed_scope = None
            if opkg.actual_size is not None and len(payload) < opkg.actual_size:
                status = "unconfirmed"
                start = opkg.data_offset or 0
                unconfirmed_range = (start, start + opkg.actual_size)
                unconfirmed_scope = "stream"

            self._record_payload(
                parent_path=parent_path,
                container_member_path=member_path,
                stream_path=full_stream_path,
                payload=payload,
                disclosure_level=disclosure_level,
                container_type=container_type,
                depth=depth,
                status=status,
                unconfirmed_range=unconfirmed_range,
                unconfirmed_scope=unconfirmed_scope,
            )
            found += 1
        return found

    def _record_payload(self, parent_path, container_member_path, stream_path,
                        payload, disclosure_level, container_type, depth,
                        status="confirmed", unconfirmed_range=None,
                        unconfirmed_scope=None):
        payload = _as_bytes(payload)
        blob = self.blob_store.put(payload)
        digest = blob.content_digest

        # If the payload claims to be a nested container, verify that it can
        # be expanded.  A signature without a valid container is reported as
        # an unconfirmed interval rather than silently treated as opaque data.
        if status == "confirmed" and depth < MAX_NESTING_DEPTH:
            failure = self._nested_container_failure(payload)
            if failure is not None:
                status = "unconfirmed"
                unconfirmed_range = failure
                unconfirmed_scope = "payload"

        occurrence_key = (
            parent_path,
            container_member_path,
            stream_path or "",
            digest,
            repr(disclosure_level),
        )
        occurrence = self._occurrences[occurrence_key]
        self._occurrences[occurrence_key] += 1
        reference_id = self._make_reference_id(
            parent_path,
            container_member_path,
            stream_path,
            digest,
            disclosure_level,
            occurrence,
        )
        entry = ManifestEntry(
            reference_id=reference_id,
            parent_path=parent_path,
            container_member_path=container_member_path,
            content_digest=digest,
            size=len(payload),
            disclosure_level=disclosure_level,
            status=status,
            unconfirmed_range=unconfirmed_range,
            unconfirmed_scope=unconfirmed_scope,
            stream_path=stream_path,
            container_type=container_type,
            occurrence=occurrence,
            depth=depth,
        )
        self._entries.append(entry)

        if depth < MAX_NESTING_DEPTH:
            self._expand_nested(
                parent_path=parent_path,
                container_member_path=container_member_path,
                stream_path=stream_path,
                payload=payload,
                disclosure_level=disclosure_level,
                container_type=container_type,
                depth=depth + 1,
            )
        return entry

    def _nested_container_failure(self, payload):
        if payload[:len(OLE_MAGIC)] == OLE_MAGIC:
            ole = None
            try:
                ole = olefile.OleFileIO(_BytesFile(payload))
                # Force reading the directory so truncated structures fail
                # here rather than during a later traversal.
                ole.listdir()
            except Exception:
                return (0, len(payload))
            finally:
                if ole is not None:
                    ole.close()
        elif payload[:4] == ZIP_MAGIC or zipfile.is_zipfile(io.BytesIO(payload)):
            try:
                archive = zipfile.ZipFile(io.BytesIO(payload), "r")
                try:
                    archive.infolist()
                finally:
                    archive.close()
            except Exception:
                return (0, len(payload))
        return None

    def _expand_nested(self, parent_path, container_member_path, stream_path,
                       payload, disclosure_level, container_type, depth):
        if payload[:len(OLE_MAGIC)] == OLE_MAGIC:
            ole = None
            try:
                ole = olefile.OleFileIO(_BytesFile(payload))
                self._extract_payloads_from_ole(
                    ole,
                    parent_path=parent_path,
                    container_member_path=stream_path or container_member_path,
                    stream_prefix="",
                    disclosure_level=disclosure_level,
                    container_type=container_type,
                    depth=depth,
                )
            except Exception:
                return
            finally:
                if ole is not None:
                    ole.close()
            return

        if payload[:4] == ZIP_MAGIC or zipfile.is_zipfile(io.BytesIO(payload)):
            try:
                archive = zipfile.ZipFile(io.BytesIO(payload), "r")
            except Exception:
                return
            try:
                prefix = stream_path or container_member_path
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    try:
                        member_data = archive.read(info)
                    except Exception:
                        continue
                    nested_member = prefix + "!/" + info.filename
                    self._extract_container_member(
                        parent_path=parent_path,
                        member_path=nested_member,
                        member_data=member_data,
                        disclosure_level=disclosure_level,
                        container_type="zip",
                        depth=depth,
                    )
            finally:
                archive.close()

    @staticmethod
    def _make_reference_id(parent_path, member_path, stream_path, digest,
                           disclosure_level, occurrence):
        material = "\x00".join(
            (
                str(parent_path),
                str(member_path),
                str(stream_path or ""),
                digest,
                repr(disclosure_level),
                str(occurrence),
            )
        )
        return "ref-" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    # -- queries ----------------------------------------------------------

    @property
    def entries(self):
        return tuple(self._entries)

    @property
    def references(self):
        return tuple(self._entries)

    @property
    def blobs(self):
        return self.blob_store.blobs

    @property
    def blob_count(self):
        return len(self.blob_store)

    def get_blob(self, digest):
        return self.blob_store.get_blob(digest)

    def get_content(self, digest):
        return self.blob_store.get(digest)

    blob_for = get_blob

    def __len__(self):
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def __getitem__(self, index):
        return self._entries[index]

    @property
    def records(self):
        return self.entries

    @property
    def items(self):
        return self.entries

    def get_entry(self, reference_id):
        for entry in self._entries:
            if entry.reference_id == reference_id:
                return entry
        return None

    def reference(self, reference_id):
        return self.get_entry(reference_id)

    def entries_for_digest(self, digest):
        if digest.startswith("sha256:"):
            digest = digest.split(":", 1)[1]
        return tuple(
            entry for entry in self._entries
            if entry.content_digest == digest
        )

    def references_for_digest(self, digest):
        return self.entries_for_digest(digest)

    def disclosure_for_reference(self, reference_id):
        entry = self.get_entry(reference_id)
        if entry is None:
            raise KeyError(reference_id)
        return entry.disclosure_level

    # Short aliases for policy code.
    reference_disclosure = disclosure_for_reference
    delivery_level = disclosure_for_reference

    def delivery_allowed(self, reference_id, requested_level=None):
        """Return whether delivery through *reference_id* is allowed.

        The manifest deliberately does not merge disclosure decisions by
        digest.  A caller must name the occurrence it wants to deliver; the
        level bound to that reference is authoritative.  If ``requested_level``
        is supplied, it must match the reference's recorded level.
        """
        entry = self.get_entry(reference_id)
        if entry is None or not entry.confirmed:
            return False
        if requested_level is None:
            return True
        return entry.disclosure_level == normalize_disclosure_level(
            requested_level
        )

    can_deliver = delivery_allowed

    # -- serialization ----------------------------------------------------

    def to_dict(self):
        entries = [entry.to_dict() for entry in self._entries]
        references_by_digest = defaultdict(list)
        for entry in self._entries:
            references_by_digest[entry.content_digest].append(
                entry.reference_id
            )
        blobs = OrderedDict()
        for digest, blob in self.blob_store.items():
            blob_dict = blob.to_dict(
                include_references=references_by_digest.get(digest, ())
            )
            blob_dict["reference_count"] = len(
                references_by_digest.get(digest, ())
            )
            decisions = [
                {
                    "reference_id": entry.reference_id,
                    "parent_path": entry.parent_path,
                    "container_member_path": entry.container_member_path,
                    "disclosure_level": entry.disclosure_level,
                }
                for entry in self._entries
                if entry.content_digest == digest
            ]
            blob_dict["disclosure_decisions"] = decisions
            blob_dict["disclosure_levels"] = list(OrderedDict.fromkeys(
                decision["disclosure_level"] for decision in decisions
            ))
            blobs[digest] = blob_dict
        return OrderedDict(
            (
                ("schema", MANIFEST_SCHEMA),
                ("read_only", True),
                ("digest_algorithm", DIGEST_ALGORITHM),
                ("blobs", blobs),
                ("references", entries),
                ("entries", entries),
            )
        )

    def to_json(self, indent=2, sort_keys=False):
        return json.dumps(
            self.to_dict(), indent=indent, sort_keys=sort_keys,
            ensure_ascii=False,
        )

    def save(self, filename, indent=2):
        with open(filename, "w", encoding="utf-8") as handle:
            handle.write(self.to_json(indent=indent))
            handle.write("\n")

    write = save

    @classmethod
    def from_dict(cls, data):
        manifest = cls()
        raw_blobs = data.get("blobs", {})
        if isinstance(raw_blobs, Mapping):
            for digest, raw_blob in raw_blobs.items():
                if raw_blob is None:
                    raw_blob = {}
                manifest.blob_store._blobs[digest] = ContentBlob(
                    content_digest=digest,
                    size=raw_blob.get("size", 0),
                    data=b"",
                    storage_path=raw_blob.get("storage_path"),
                )
        raw_entries = data.get("references", data.get("entries", ()))
        for raw in raw_entries:
            digest = (
                raw.get("content_digest")
                or raw.get("digest")
                or raw.get("sha256")
            )
            unconfirmed = raw.get("unconfirmed_range")
            if unconfirmed is not None and not isinstance(unconfirmed, tuple):
                unconfirmed = tuple(unconfirmed)
            entry = ManifestEntry(
                reference_id=raw.get("reference_id") or raw.get("reference"),
                parent_path=raw.get("parent_path") or raw.get("container_path"),
                container_member_path=(
                    raw.get("container_member_path") or raw.get("member_path")
                ),
                content_digest=digest,
                size=raw.get("size", 0),
                disclosure_level=(
                    raw.get("disclosure_level", raw.get("disclosure"))
                ),
                status=raw.get("status", "confirmed"),
                unconfirmed_range=unconfirmed,
                unconfirmed_scope=raw.get("unconfirmed_scope"),
                stream_path=raw.get("stream_path"),
                container_type=raw.get("container_type", "unknown"),
                occurrence=raw.get("occurrence", 0),
                depth=raw.get("depth", 0),
            )
            manifest._entries.append(entry)
            key = (
                entry.parent_path,
                entry.container_member_path,
                entry.stream_path or "",
                entry.content_digest,
                repr(entry.disclosure_level),
            )
            manifest._occurrences[key] = max(
                manifest._occurrences[key], entry.occurrence + 1)
        return manifest

    @classmethod
    def from_json(cls, text):
        return cls.from_dict(json.loads(text))

    @classmethod
    def load(cls, filename):
        with open(filename, "r", encoding="utf-8") as handle:
            return cls.from_json(handle.read())


class _BytesFile(io.BytesIO):
    """BytesIO with a stable empty name for olefile compatibility."""

    name = "<memory>"


def extract_manifest(sources, disclosures=None, disclosure_level=None,
                     blob_store=None, root=None, disclosure=None,
                     default_disclosure=None, disclosure_levels=None,
                     **kwargs):
    """Extract a manifest from one or more Office documents.

    :param sources: a path, an iterable of paths, an iterable of
        ``(path, disclosure_level)`` pairs, or a path->level mapping.
    :param disclosures: optional path->level mapping.
    :param disclosure_level: default level for sources without one.
    :param blob_store: optional :class:`BlobStore` to reuse.
    :param root: optional directory for a persistent blob store.
    :return: a frozen :class:`ExtractionManifest`.
    """
    manifest = ExtractionManifest(
        blob_store=blob_store,
        root=root,
    )
    if disclosure_level is None:
        disclosure_level = (
            disclosure if disclosure is not None else default_disclosure)
    if disclosures is None:
        disclosures = disclosure_levels
    if sources is not None:
        manifest.add_many(
            sources,
            disclosures=disclosures,
            default_disclosure=disclosure_level,
        )
    return manifest.freeze()


build_manifest = extract_manifest
create_manifest = extract_manifest
make_manifest = extract_manifest
extract = extract_manifest
Manifest = ExtractionManifest
Entry = ManifestEntry
build_extraction_manifest = extract_manifest
read_only_manifest = extract_manifest
make_extraction_manifest = extract_manifest


def build_parser():
    parser = argparse.ArgumentParser(
        prog="olemanifest",
        description=(
            "Build a read-only manifest of objects embedded in Office files."
        ),
    )
    parser.add_argument(
        "input",
        nargs="+",
        metavar="FILE",
        help="Office document(s) to inspect (never modified).",
    )
    parser.add_argument(
        "-o", "--output",
        help="write the JSON manifest to this file instead of stdout.",
    )
    parser.add_argument(
        "--disclosure",
        "--disclosure-level",
        "--level",
        default=DEFAULT_DISCLOSURE_LEVEL,
        help="default disclosure level for every reference.",
    )
    parser.add_argument(
        "--disclosure-map",
        "--levels",
        help=(
            "JSON file mapping parent paths to disclosure levels, or a "
            "list of {path, disclosure_level} objects."
        ),
    )
    parser.add_argument(
        "--blob-dir",
        help="optional persistent content-addressed blob directory.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation (default: 2).",
    )
    return parser


def _load_disclosure_map(filename):
    if not filename:
        return None
    with open(filename, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(cmd_line_args=None):
    ensure_stdout_handles_unicode()
    options = build_parser().parse_args(cmd_line_args)
    manifest = extract_manifest(
        options.input,
        disclosures=_load_disclosure_map(options.disclosure_map),
        disclosure_level=options.disclosure,
        root=options.blob_dir,
    )
    output = manifest.to_json(indent=options.indent)
    if options.output:
        with open(options.output, "w", encoding="utf-8") as handle:
            handle.write(output)
            handle.write("\n")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
