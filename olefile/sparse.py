"""
Sparse / partial OLE compound document support for forensic analysis.

A forensic image of a compound document may contain only a subset of its
sectors ("pages"): the acquisition tool synchronises the pages that are
available and leaves the remaining pages as unallocated holes.  This module
lets :mod:`olefile` analyse such a partial image **read-only**, driven by an
explicit manifest of the available sectors, and report separately on:

1. *Directory identity* - which streams/storages are described by the
   directory entries that are present.
2. *Allocation-chain evidence* - what the FAT / MiniFAT link tables say about
   each stream, independently of whether the referenced data pages are present.
3. *Actual stream content* - what can really be read and hashed, byte range by
   byte range.

Design rules used throughout:

- A missing page is **never** reported as an all-zero sector.  Reads of a
  missing sector raise :class:`SectorUnavailable`; content reports mark the
  range as a gap instead of padding it with ``\\x00``.
- Two streams that reference the *same* missing page keep independent state:
  every stream owns its chain walk, present/gap ranges and digest, so filling
  the page later is evaluated per stream.
- Every byte that is read is recorded in an evidence ledger keyed by the
  original logical offset and its SHA-256 digest, so the source summary and
  its offset association remain traceable even after the image is repaired.
"""

from __future__ import print_function

import array
import hashlib
import json
import os
import struct
import sys

from .olefile import (
    MAGIC,
    FREESECT,
    FATSECT,
    DIFSECT,
    NOSTREAM,
    MAXREGSECT,
    STGTY_STORAGE,
    STGTY_STREAM,
)

#: directory / chain could be fully resolved and every referenced page present
STATUS_COMPLETE = "complete"

#: link value used when the FAT/MiniFAT page describing a slot is itself missing
UNKNOWN_LINK = 0xFFFFFFFD
#: structure is readable but one or more referenced pages are missing
STATUS_PARTIAL = "partial"
#: a required structural page (directory/FAT/MiniFAT) is missing; unresolved
STATUS_MISSING = "missing"
#: the read content does not match the supplied reference digest
STATUS_MISMATCH = "mismatch"
#: the on-disk structures contradict each other (broken link, loop, ...)
STATUS_CORRUPT = "corrupt"

#: header layout shared with OleFileIO.open()

class SparseOLEError(IOError):
    """Base class for sparse/forensic OLE parsing errors."""


class SectorUnavailable(SparseOLEError):
    """Raised when a read targets a sector that is not in the available set."""

    def __init__(self, sect, offset, size):
        self.sect = sect
        self.offset = offset
        self.size = size
        super(SectorUnavailable, self).__init__(
            'sector %d at offset %d is not present in the partial image'
            % (sect, offset))



class NotSparseOLEError(SparseOLEError):
    """Raised when the source does not carry a valid OLE signature."""


class SectorEvidence(object):
    """Digest and original offset recorded for a sector that was read."""

    def __init__(self, sect, offset, size, digest):
        self.sect = sect
        self.offset = offset
        self.size = size
        self.digest = digest

    def as_dict(self):
        return {
            "sect": self.sect,
            "offset": self.offset,
            "size": self.size,
            "sha256": self.digest,
        }


def _is_regular(sect):
    return 0 <= sect <= MAXREGSECT

__all__ = [
    'SparseOleImage',
    'SparseOleVerifier',
    'StreamReport',
    'DirectoryReport',
    'SectorEvidence',
    'SectorUnavailable',
    'SparseOLEError',
    'NotSparseOLEError',
    'available_sectors_from_holes',
    'open_sparse_image',
    'write_sparse_copy',
    'write_manifest_sidecar',
    'read_manifest_sidecar',
    'STATUS_COMPLETE',
    'STATUS_PARTIAL',
    'STATUS_MISSING',
    'STATUS_MISMATCH',
    'STATUS_CORRUPT',
]


def _mask(value):
    return value & 0xFFFFFFFF

def available_sectors_from_holes(fp, sector_size, logical_size=None):
    """
    Derive the set of present sector indexes from a real sparse file.

    Uses ``os.SEEK_DATA`` / ``os.SEEK_HOLE`` when the platform supports
    them. A byte range reported as allocated data maps to every sector it
    overlaps. Falls back to an empty set if the platform lacks the calls.
    """
    if not hasattr(os, "SEEK_DATA") or not hasattr(os, "SEEK_HOLE"):
        return set()
    if logical_size is None:
        fp.seek(0, os.SEEK_END)
        logical_size = fp.tell()
    result = set()
    pos = 0
    try:
        while pos < logical_size:
            data_start = fp.seek(pos, os.SEEK_DATA)
            if data_start >= logical_size:
                break
            hole_start = fp.seek(data_start, os.SEEK_HOLE)
            first = data_start // sector_size
            last = (hole_start - 1) // sector_size
            result.update(range(first, last + 1))
            pos = hole_start
            if hole_start <= data_start:
                break
    except OSError:
        pass
    return set(result)


class SparseOleImage(object):
    """
    Read-only view of a partially acquired OLE container.

    The underlying file-like ``source`` is never modified. Availability is
    driven by a manifest of sector numbers (or byte ranges discovered through
    SEEK_DATA/SEEK_HOLE). Reading a sector that is not present raises
    :class:`MissingSectorError` instead of returning zero-filled bytes, so a
    missing page can never be confused with a real sector that genuinely
    contains zeros.
    """

    def __init__(self, source, available=None, logical_size=None,
                 sector_size=512):
        if not hasattr(source, 'read') or not hasattr(source, 'seek'):
            raise TypeError('source must be a seekable file-like object')
        self._fp = source
        self.sector_size = sector_size
        self._logical_size = logical_size
        self._available = set()
        self._ranges = []
        if available is not None:
            self.configure(available)
        # evidence ledger: sector number -> SectorEvidence
        self.evidence = {}

        self._closed = False

    # -- configuration -----------------------------------------------------
    def configure(self, available):
        if not available:
            self._available = set()
            self._ranges = []
        elif isinstance(available, (set, frozenset)):
            self._available = set(available)
            self._ranges = []
        elif isinstance(available, (list, tuple)) and available:
            if isinstance(available[0], int):
                self._available = set(available)
                self._ranges = []
            else:
                self._ranges = [(int(a), int(b)) for a, b in available]
                self._available = set()
        return self
    @property
    def logical_size(self):
        if self._logical_size is not None:
            return self._logical_size
        self._fp.seek(0, os.SEEK_END)
        return self._fp.tell()
    @property
    def logical_sector_count(self):
        # the first sector-size block is the header, not a numbered sector
        total_blocks = (self.logical_size + self.sector_size - 1) // self.sector_size
        return max(0, total_blocks - 1)

    def sector_present(self, sect):
        if sect < 0:
            return False
        if self._available:
            return sect in self._available
        if self._ranges:
            start_byte = sect * self.sector_size
            for range_start, range_end in self._ranges:
                if range_start <= start_byte < range_end:
                    return True
            return False
        return True

    # -- accessors --------------------------------------------------------
    @property
    def available_sectors(self):
        return frozenset(self._available)

    @property
    def missing_sectors(self):
        return frozenset(
            s for s in range(self.logical_sector_count)
            if not self.sector_present(s))

    def _sector_offset(self, sect):
        return self.sector_size * (sect + 1)

    def read_header(self):
        self._fp.seek(0)
        # the OLE signature lives in the first 512 bytes even for 4K sectors,
        # but record the whole header block to keep the ledger self-contained
        header = self._fp.read(max(512, self.sector_size))
        digest = hashlib.sha256(header).hexdigest()
        self.evidence[-1] = SectorEvidence(
            sect=-1, offset=0, size=len(header), digest=digest)
        return header

    def read_sector(self, sect):
        """Return the bytes of sector ``sect`` or raise SectorUnavailable."""
        if self._closed:
            raise SparseOLEError("read from a closed sparse image")
        if not self.sector_present(sect):
            offset = self._sector_offset(sect)
            raise SectorUnavailable(sect, offset, self.sector_size)
        offset = self._sector_offset(sect)
        self._fp.seek(offset)
        data = self._fp.read(self.sector_size)
        if len(data) != self.sector_size:
            raise SparseOLEError(
                "sector %d truncated: read %d of %d bytes" %
                (sect, len(data), self.sector_size))
        digest = hashlib.sha256(data).hexdigest()
        self.evidence[sect] = SectorEvidence(
            sect=sect, offset=offset, size=len(data), digest=digest)
        return data

    def mark_sectors_available(self, sectors):
        """Add sectors to the availability manifest (after a page is restored)."""
        for sect in sectors:
            self._available.add(int(sect))
        if self._ranges:
            self._ranges = []

    def manifest_digest(self):
        """Stable hash of the availability manifest, independent of order."""
        payload = b",".join(str(s).encode()
                           for s in sorted(self._available))
        return hashlib.sha256(payload).hexdigest()

    def sector_evidence(self, sect):
        return self.evidence.get(sect)

    def close(self):
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

class DirectoryReport(object):
    """Identity information extracted from the directory entry."""

    def __init__(self, sid, name, entry_type, isect_start, size,
                 is_minifat, available):
        self.sid = sid
        self.name = name
        self.entry_type = entry_type
        self.isect_start = isect_start
        self.declared_size = size
        self.is_minifat = is_minifat
        self.available = available
        self.path = (name,)

    def as_dict(self):
        return {
            "sid": self.sid,
            "name": self.name,
            "entry_type": self.entry_type,
            "isect_start": self.isect_start,
            "declared_size": self.declared_size,
            "is_minifat": self.is_minifat,
            "available": self.available,
        }

class StreamReport(object):
    """Per-stream verification result, kept independent for every stream."""

    def __init__(self, path, directory, chain_status, chain_sectors,
                 missing_sectors, content_status, content_digest,
                 present_bytes, missing_ranges, gap_aware_digest=None):
        self.path = path
        self.directory = directory
        self.chain_status = chain_status
        self.chain_sectors = list(chain_sectors)
        self.missing_sectors = frozenset(missing_sectors)
        self.content_status = content_status
        self.content_digest = content_digest
        self.gap_aware_digest = gap_aware_digest
        self.present_bytes = present_bytes
        self.missing_ranges = list(missing_ranges)

    @property
    def is_complete(self):
        return (self.chain_status == STATUS_COMPLETE
                and self.content_status == STATUS_COMPLETE)

    def as_dict(self):
        return {
            "path": list(self.path),
            "directory": self.directory.as_dict(),
            "chain_status": self.chain_status,
            "chain_sectors": list(self.chain_sectors),
            "missing_sectors": sorted(self.missing_sectors),
            "content_status": self.content_status,
            "content_digest": self.content_digest,
            "gap_aware_digest": self.gap_aware_digest,
            "present_bytes": self.present_bytes,
            "missing_ranges": list(self.missing_ranges),
        }

class SparseOleVerifier(object):
    """Tolerant read-only verifier for a partially acquired OLE container."""

    HEADER_FMT = "<8s16sHHHHHHLLLLLLLLLL"
    DIRENTRY_FMT = "<64sHBBIII16sIQQIII"
    DIRENTRY_SIZE = 128

    def __init__(self, image):
        if not isinstance(image, SparseOleImage):
            raise TypeError("image must be a SparseOleImage")
        self.image = image
        self.defects = []
        self.fat = []
        self.fat_missing = set()
        self.dir_entries = {}
        self.minifat = []
        self.minifat_missing = set()
        self.mini_chain = []
        self.mini_to_normal = {}
        self._reports = {}
        self._stream_deps = {}
        self._parse()

    def _parse(self):
        header = self.image.read_header()
        if len(header) < 512 or header[:8] != MAGIC:
            raise NotSparseOLEError("not an OLE2 structured storage file")
        fields = struct.unpack(self.HEADER_FMT, header[:76])
        (self.header_signature, self.header_clsid, self.minor_version,
         self.dll_version, self.byte_order, sector_shift,
         mini_shift, self.reserved1, self.reserved2,
         self.num_dir_sectors, self.num_fat_sectors,
         self.first_dir_sector, self.transaction_signature,
         self.mini_cutoff, self.first_minifat_sector,
         self.num_minifat_sectors, self.first_difat_sector,
         self.num_difat_sectors) = fields
        self.sector_size = 2 ** sector_shift
        self.mini_sector_size = 2 ** mini_shift
        self.image.sector_size = self.sector_size
        self.nb_sect = ((self.image.logical_size + self.sector_size - 1)
                        // self.sector_size) - 1
        self._difat = list(struct.unpack("<109I", header[76:512]))
        self._load_fat()
        self._load_directory()
        self._load_minifat()
        self._build_dependencies()

    def _safe_read_sector(self, sect):
        try:
            return self.image.read_sector(sect), True
        except SectorUnavailable:
            self.defects.append("missing sector %d" % sect)
            return None, False

    def _walk_chain(self, start):
        """Follow FAT links, tolerating missing FAT entries/sectors."""
        chain = []
        missing = set()
        unknown = False
        seen = set()
        sect = start
        while _is_regular(sect):
            if sect in seen:
                self.defects.append("FAT loop at sector %d" % sect)
                break
            seen.add(sect)
            chain.append(sect)
            if not self.image.sector_present(sect):
                missing.add(sect)
            if sect >= len(self.fat):
                self.defects.append("FAT index %d out of range" % sect)
                break
            sect = _mask(self.fat[sect])
            if sect == UNKNOWN_LINK:
                unknown = True
                self.defects.append("unknown FAT link after sector %d" % chain[-1])
                break
        return chain, missing, unknown

    def _fat_sector_list(self):
        sectors = [s for s in self._difat if _is_regular(s)]
        sect = _mask(self.first_difat_sector)
        guard = 0
        while _is_regular(sect) and guard <= self.nb_sect + 1:
            guard += 1
            data, ok = self._safe_read_sector(sect)
            if not ok:
                break
            pointers = struct.unpack("<%dI" % (self.sector_size // 4), data)
            per = self.sector_size // 4 - 1
            sectors.extend(p for p in pointers[:per] if _is_regular(p))
            sect = _mask(pointers[-1])
        return sectors

    def _load_fat(self):
        fat = array.array("I")
        for sect in self._fat_sector_list():
            data, ok = self._safe_read_sector(sect)
            if not ok:
                self.fat_missing.add(sect)
                entries = self.sector_size // 4
                fat.extend(UNKNOWN_LINK for _ in range(entries))
                continue
            part = array.array("I", data)
            if sys.byteorder == "big":
                part.byteswap()
            fat.extend(part)
        if len(fat) > self.nb_sect:
            fat = fat[:self.nb_sect]
        elif len(fat) < self.nb_sect:
            fat.extend(FREESECT for _ in range(self.nb_sect - len(fat)))
        self.fat = fat

    def _load_directory(self):
        chain, missing, _unknown = self._walk_chain(self.first_dir_sector)
        self.dir_chain = chain
        self.dir_missing = missing
        sector_data = []
        for sect in chain:
            data, ok = self._safe_read_sector(sect)
            sector_data.append((sect, data if ok else None))
        self._dir_sector_data = sector_data
        self._parse_dir_entries()
        self._build_tree()

    def _parse_dir_entries(self):
        per_sector = self.sector_size // self.DIRENTRY_SIZE
        for index, (sect, data) in enumerate(self._dir_sector_data):
            for offset_in in range(per_sector):
                sid = index * per_sector + offset_in
                start = offset_in * self.DIRENTRY_SIZE
                if data is None:
                    self.dir_entries[sid] = None
                    continue
                chunk = data[start:start + self.DIRENTRY_SIZE]
                if len(chunk) < self.DIRENTRY_SIZE or len(chunk.strip(b"\x00")) == 0:
                    self.dir_entries[sid] = None
                    continue
                self.dir_entries[sid] = self._decode_entry(chunk, sid)

    def _decode_entry(self, chunk, sid):
        (name_raw, name_length, entry_type, color, sid_left,
         sid_right, sid_child, clsid, user_flags, create_time,
         modify_time, isect_start, size_low, size_high) = struct.unpack(
            self.DIRENTRY_FMT, chunk)
        try:
            name = name_raw[:max(0, name_length - 2)].decode("UTF-16LE")
        except UnicodeDecodeError:
            name = name_raw[:max(0, name_length - 2)].decode(
                "UTF-16LE", "replace")
        size = size_low if self.sector_size == 512 else size_low + (size_high << 32)
        is_minifat = (entry_type == STGTY_STREAM and size > 0
                      and size < self.mini_cutoff)
        return {
            "sid": sid, "name": name, "entry_type": entry_type,
            "sid_left": sid_left, "sid_right": sid_right,
            "sid_child": sid_child, "isect_start": isect_start,
            "size": size, "is_minifat": is_minifat,
            "clsid": clsid.hex(),
        }

    def _build_tree(self):
        self.root = self.dir_entries.get(0)
        self.paths = {}
        if self.root is None:
            return
        self.paths[0] = []
        self._walk_tree(0, [])

    def _walk_tree(self, sid, prefix):
        entry = self.dir_entries.get(sid)
        if entry is None:
            return
        child = entry["sid_child"]
        if child == NOSTREAM or child not in self.dir_entries:
            return
        self._walk_children(child, prefix)

    def _walk_children(self, sid, prefix):
        entry = self.dir_entries.get(sid)
        if entry is None:
            return
        self._walk_children(entry["sid_left"], prefix) if entry["sid_left"] != NOSTREAM else None
        name = entry["name"]
        path = prefix + [name]
        self.paths[entry["sid"]] = path
        if entry["entry_type"] == STGTY_STORAGE:
            self._walk_tree(entry["sid"], path)
        self._walk_children(entry["sid_right"], prefix) if entry["sid_right"] != NOSTREAM else None

    def _load_minifat(self):
        if not _is_regular(self.first_minifat_sector):
            return
        chain, missing, _unknown = self._walk_chain(self.first_minifat_sector)
        self.minifat_chain = chain
        self.minifat_missing = missing
        mini = array.array("I")
        for sect in chain:
            data, ok = self._safe_read_sector(sect)
            if not ok:
                mini.extend(UNKNOWN_LINK for _ in range(self.sector_size // 4))
                continue
            part = array.array("I", data)
            if sys.byteorder == "big":
                part.byteswap()
            mini.extend(part)
        self.minifat = mini
        root = self.dir_entries.get(0)
        if root is None:
            return
        self.mini_chain, mini_missing, _unknown = self._walk_chain(root["isect_start"])
        self.mini_stream_missing = mini_missing
        self._build_mini_mapping(root)

    def _build_mini_mapping(self, root):
        per_normal = self.sector_size // self.mini_sector_size
        for mini_index in range(len(self.minifat)):
            normal_pos = mini_index // per_normal
            if normal_pos < len(self.mini_chain):
                self.mini_to_normal[mini_index] = self.mini_chain[normal_pos]
            else:
                self.mini_to_normal[mini_index] = None

    def _mini_walk(self, start):
        chain = []
        missing = set()
        unknown = False
        seen = set()
        sect = start
        while _is_regular(sect):
            if sect in seen:
                self.defects.append("MiniFAT loop at sector %d" % sect)
                break
            seen.add(sect)
            chain.append(sect)
            normal = self.mini_to_normal.get(sect)
            if normal is None or not self.image.sector_present(normal):
                missing.add(sect)
            if sect >= len(self.minifat):
                break
            sect = _mask(self.minifat[sect])
            if sect == UNKNOWN_LINK:
                unknown = True
                self.defects.append("unknown MiniFAT link after sector %d" % chain[-1])
                break
        return chain, missing, unknown

    def directory_identities(self):
        """Report directory identity for every known entry."""
        reports = []
        for sid in sorted(self.dir_entries):
            entry = self.dir_entries[sid]
            if entry is None:
                continue
            path = self.paths.get(sid, [entry["name"]])
            available = self._entry_sectors_available(entry)
            report = DirectoryReport(
                sid=sid, name=entry["name"], entry_type=entry["entry_type"],
                isect_start=entry["isect_start"], size=entry["size"],
                is_minifat=entry["is_minifat"], available=available)
            report.path = tuple(path)
            reports.append(report)
        return reports

    def _entry_sectors_available(self, entry):
        if entry["entry_type"] != STGTY_STREAM or entry["size"] == 0:
            return True
        if entry["is_minifat"]:
            _, missing, _u = self._mini_walk(entry["isect_start"])
        else:
            _, missing, _u = self._walk_chain(entry["isect_start"])
        return not missing

    def verify_stream(self, path, expected_digest=None):
        entry = self._find_entry(path)
        directory = self._directory_report(entry)
        if entry["entry_type"] != STGTY_STREAM:
            report = StreamReport(directory.path, directory, STATUS_MISSING,
                                  [], set(), STATUS_MISSING, None, 0, [])
            self._reports[tuple(directory.path)] = report
            return report
        chain_unknown = False
        if entry["is_minifat"]:
            chain, missing, chain_unknown = self._mini_walk(entry["isect_start"])
            normal_missing = set()
            for mini_sect in missing:
                normal = self.mini_to_normal.get(mini_sect)
                if normal is not None:
                    normal_missing.add(normal)
            deps = set(self.mini_to_normal.get(m) for m in chain)
        else:
            chain, missing, chain_unknown = self._walk_chain(entry["isect_start"])
            normal_missing = set(missing)
            deps = set(chain)
        deps.discard(None)
        return self._build_report(entry, directory, chain, missing,
                                  normal_missing, deps, expected_digest,
                                  chain_unknown)

    def _find_entry(self, path):
        if isinstance(path, str):
            parts = path.split("/")
        else:
            parts = list(path)
        target = tuple(parts)
        for sid, entry_path in self.paths.items():
            if tuple(entry_path) == target and entry_path:
                return self.dir_entries[sid]
        raise SparseOLEError("stream not found: %r" % (path,))

    def _directory_report(self, entry):
        path = self.paths.get(entry["sid"], [entry["name"]])
        report = DirectoryReport(
            sid=entry["sid"], name=entry["name"],
            entry_type=entry["entry_type"],
            isect_start=entry["isect_start"], size=entry["size"],
            is_minifat=entry["is_minifat"],
            available=self._entry_sectors_available(entry))
        report.path = tuple(path)
        return report

    def _build_report(self, entry, directory, chain, missing,
                      normal_missing, deps, expected_digest,
                      chain_unknown=False):
        if not chain:
            chain_status = STATUS_MISSING
        elif missing or chain_unknown:
            chain_status = STATUS_PARTIAL
        else:
            chain_status = STATUS_COMPLETE
        pieces, missing_ranges, present_bytes = self._read_content(
            entry, chain, missing)
        present_blob = b"".join(pieces[index] for index in sorted(pieces))
        if len(present_blob) > entry["size"]:
            present_blob = present_blob[:entry["size"]]
        content_digest = hashlib.sha256(present_blob).hexdigest()
        gap_aware_digest = hashlib.sha256(
            self._canonical_bytes(entry, chain, pieces,
                                  missing_ranges)).hexdigest()
        if not chain:
            content_status = STATUS_MISSING
        elif missing or chain_unknown:
            content_status = STATUS_MISSING if not pieces else STATUS_PARTIAL
        elif expected_digest is not None and expected_digest != content_digest:
            content_status = STATUS_MISMATCH
        else:
            content_status = STATUS_COMPLETE
        report = StreamReport(directory.path, directory, chain_status,
                              chain, missing, content_status, content_digest,
                              present_bytes, missing_ranges, gap_aware_digest)
        self._reports[tuple(directory.path)] = report
        self._stream_deps[tuple(directory.path)] = set(deps)
        return report

    def _read_content(self, entry, chain, missing):
        if entry["is_minifat"]:
            return self._read_mini_content(entry, chain, missing)
        pieces = {}
        missing_ranges = []
        present_bytes = 0
        for index, sect in enumerate(chain):
            if sect in missing:
                missing_ranges.append((index * self.sector_size,
                                       (index + 1) * self.sector_size))
                continue
            data, ok = self._safe_read_sector(sect)
            if ok:
                pieces[index] = data
                present_bytes += len(data)
        return pieces, missing_ranges, present_bytes

    def _read_mini_content(self, entry, mini_chain, mini_missing):
        virtual = {}
        for normal_index, normal_sect in enumerate(self.mini_chain):
            data, ok = self._safe_read_sector(normal_sect)
            if ok:
                virtual[normal_index] = data
        pieces = {}
        missing_ranges = []
        present_bytes = 0
        mss = self.mini_sector_size
        per_normal = self.sector_size // mss
        for index, mini_sect in enumerate(mini_chain):
            normal_index = mini_sect // per_normal
            slice_index = mini_sect % per_normal
            if mini_sect in mini_missing or normal_index not in virtual:
                missing_ranges.append((index * mss, (index + 1) * mss))
                continue
            chunk = virtual[normal_index][slice_index * mss:
                                         (slice_index + 1) * mss]
            pieces[index] = chunk
            present_bytes += len(chunk)
        return pieces, missing_ranges, present_bytes

    def _canonical_bytes(self, entry, chain, pieces, missing_ranges):
        unit = self.mini_sector_size if entry["is_minifat"] else self.sector_size
        out = bytearray()
        gap_marker = b"OLE-GAP"
        for index in range(len(chain)):
            if index in pieces:
                out.extend(pieces[index])
            else:
                out.extend(gap_marker + bytes([0]) * (unit - len(gap_marker)))
        declared = entry["size"]
        if len(out) > declared:
            out = out[:declared]
        path_name = "/".join(self.paths.get(entry["sid"], [entry["name"]]))
        header = ("olefile-sparse:v1:" + path_name + ":%d:%d" + chr(10)) % (
            unit, len(missing_ranges))
        return header.encode() + bytes(out)

    def stream_paths(self):
        result = []
        for sid, entry in self.dir_entries.items():
            if entry is not None and entry["entry_type"] == STGTY_STREAM:
                result.append(tuple(self.paths.get(sid, [entry["name"]])))
        return sorted(result)

    def verify_all(self, expected_digests=None):
        expected_digests = expected_digests or {}
        reports = {}
        for path in self.stream_paths():
            key = "/".join(path)
            reports[path] = self.verify_stream(
                path, expected_digests.get(key))
        return reports

    def reverify(self, added_sectors, expected_digests=None):
        added_sectors = set(int(s) for s in added_sectors)
        self.image.mark_sectors_available(added_sectors)
        structural = added_sectors & self._structural_sectors()
        if structural:
            self._reset_parsing_state()
            self._parse()
        affected = self._affected_streams(added_sectors, structural)
        expected_digests = expected_digests or {}
        refreshed = {}
        for path in affected:
            key = "/".join(path)
            refreshed[path] = self.verify_stream(
                path, expected_digests.get(key))
        return refreshed

    def _structural_sectors(self):
        sectors = set()
        sectors.update(getattr(self, "dir_chain", []))
        sectors.update(getattr(self, "minifat_chain", []))
        sectors.update(getattr(self, "fat_missing", set()))
        sectors.update(s for s in range(len(self.fat))
                       if _mask(self.fat[s]) in (FATSECT, DIFSECT))
        return sectors

    def _reset_parsing_state(self):
        self.fat = []
        self.fat_missing = set()
        self.dir_entries = {}
        self.minifat = []
        self.minifat_missing = set()
        self.mini_chain = []
        self.mini_to_normal = {}
        self.paths = {}
        self._reports = {}
        self._stream_deps = {}

    def _affected_streams(self, added_sectors, structural):
        if structural:
            return self.stream_paths()
        affected = set()
        for path, deps in self._stream_deps.items():
            if deps & added_sectors:
                affected.add(path)
        return sorted(affected)

    def _build_dependencies(self):
        self._stream_deps = {}
        for sid, entry in self.dir_entries.items():
            if entry is None or entry["entry_type"] != STGTY_STREAM:
                continue
            if entry["size"] == 0:
                deps = set()
            elif entry["is_minifat"]:
                chain, _, _u = self._mini_walk(entry["isect_start"])
                deps = set(self.mini_to_normal.get(m) for m in chain)
            else:
                chain, _, _u = self._walk_chain(entry["isect_start"])
                deps = set(chain)
            deps.discard(None)
            path = tuple(self.paths.get(sid, [entry["name"]]))
            self._stream_deps[path] = deps

    def evidence_for_sector(self, sect):
        ev = self.image.sector_evidence(sect)
        if ev is None:
            return None
        return ev.as_dict()

    def evidence_ledger(self):
        return {sect: ev.as_dict()
                for sect, ev in sorted(self.image.evidence.items())}

    def source_manifest(self):
        return {
            "sector_size": self.sector_size,
            "logical_size": self.image.logical_size,
            "logical_sector_count": self.image.logical_sector_count,
            "available_sectors": sorted(self.image.available_sectors),
            "missing_sectors": sorted(self.image.missing_sectors),
            "manifest_digest": self.image.manifest_digest(),
        }

def open_sparse_image(source, available=None, logical_size=None,
                      sector_size=512):
    """Open a read-only sparse OLE image and return a verifier."""
    image = SparseOleImage(source, available=available,
                           logical_size=logical_size,
                           sector_size=sector_size)
    return SparseOleVerifier(image)

def write_sparse_copy(source, dest_path, available, logical_size,
                      sector_size=512, write_manifest=True):
    """Create a sparse on-disk copy containing only available sectors."""
    available = sorted(set(available))
    if hasattr(source, "read"):
        src = source
        close = False
    else:
        src = open(source, "rb")
        close = True
    with open(dest_path, "wb") as out:
        out.write(_read_bytes(src, 0, min(sector_size, logical_size)))
        for sect in available:
            offset = sector_size * (sect + 1)
            out.seek(offset)
            out.write(_read_bytes(src, offset, sector_size))
        out.truncate(logical_size)
    if close:
        src.close()
    if write_manifest:
        write_manifest_sidecar(dest_path, available, logical_size,
                               sector_size)
    return dest_path

def _read_bytes(fp, offset, size):
    fp.seek(offset)
    return fp.read(size)

def write_manifest_sidecar(dest_path, available, logical_size,
                           sector_size=512):
    manifest = {
        "format": "olefile-sparse-manifest:v1",
        "sector_size": sector_size,
        "logical_size": logical_size,
        "available_sectors": sorted(int(s) for s in available),
    }
    sidecar = dest_path + ".manifest.json"
    with open(sidecar, "w") as handle:
        json.dump(manifest, handle, sort_keys=True)
    return sidecar

def read_manifest_sidecar(dest_path):
    with open(dest_path + ".manifest.json", "r") as handle:
        return json.load(handle)
