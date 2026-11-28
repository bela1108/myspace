from __future__ import annotations

import ntpath
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from functools import cached_property, lru_cache
from io import BytesIO
from operator import itemgetter
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.ntfs.attr import Attribute, AttributeHeader
from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    DEFAULT_RECORD_SIZE,
    FILE_FILE_NAME_INDEX_PRESENT,
    FILE_NAME_DOS,
    FILE_NUMBER_MFT,
    FILE_NUMBER_ROOT,
    IO_REPARSE_TAG,
    c_ntfs,
)
from dissect.ntfs.exceptions import (
    BrokenMftError,
    Error,
    FileNotFoundError,
    MftNotAvailableError,
    NotADirectoryError,
    NotAReparsePointError,
)
from dissect.ntfs.index import Index
from dissect.ntfs.util import AttributeMap, apply_fixup, segment_reference

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.ntfs.index import IndexEntry
    from dissect.ntfs.ntfs import NTFS
    from dissect.ntfs.util import AttributeCollection


class ReparsePointStatus(str, Enum):
    """The result of explaining a reparse point without following it.

    ``LOCAL_CONFIRMED`` means the referenced material can be identified from
    this volume alone. ``EXTERNAL_PENDING`` means the reference leaves this
    volume (or its target is not present here). ``EXTERNALLY_VERIFIED`` means
    the caller supplied independent archival proof for the target.
    """

    LOCAL_CONFIRMED = "local"
    EXTERNAL_PENDING = "external"
    EXTERNALLY_VERIFIED = "verified"

    # Convenience aliases for callers that use shorter status names.
    LOCAL = LOCAL_CONFIRMED
    CONFIRMED = LOCAL_CONFIRMED  # noqa: PIE796
    IN_VOLUME = LOCAL_CONFIRMED  # noqa: PIE796
    RESOLVED = LOCAL_CONFIRMED  # noqa: PIE796

    EXTERNAL = EXTERNAL_PENDING
    PENDING = EXTERNAL_PENDING  # noqa: PIE796
    OUT_OF_VOLUME = EXTERNAL_PENDING  # noqa: PIE796
    UNRESOLVED = EXTERNAL_PENDING  # noqa: PIE796

    EXTERNAL_VERIFIED = EXTERNALLY_VERIFIED
    VERIFIED = EXTERNALLY_VERIFIED  # noqa: PIE796
    ARCHIVED = EXTERNALLY_VERIFIED  # noqa: PIE796
    PROVEN = EXTERNALLY_VERIFIED  # noqa: PIE796

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class ReparsePointReference:
    """A read-only explanation of a reparse point reference.

    The ``record`` attribute is only populated when the target can be
    identified from this volume or when the caller supplied a concrete target
    record as independent proof. Merely trusting a caller-provided statement
    does not cause any link to be followed.
    """

    source: MftRecord
    target: str | None
    status: ReparsePointStatus
    record: MftRecord | None = None
    reason: str = ""

    @property
    def state(self) -> ReparsePointStatus:
        """Alias for :attr:`status`."""
        return self.status

    @property
    def target_record(self) -> MftRecord | None:
        """Alias for :attr:`record`."""
        return self.record

    @property
    def target_path(self) -> str | None:
        """Alias for :attr:`target`."""
        return self.target

    @property
    def path(self) -> str | None:
        """Alias for :attr:`target`."""
        return self.target

    @property
    def complete(self) -> bool:
        """Return whether the referenced material is accounted for."""
        return self.status != ReparsePointStatus.EXTERNAL_PENDING

    @property
    def is_complete(self) -> bool:
        """Alias for :attr:`complete`."""
        return self.complete

    @property
    def material_complete(self) -> bool:
        """Alias for :attr:`complete`."""
        return self.complete

    @property
    def pending(self) -> bool:
        """Return whether the referenced material still has to be collected."""
        return not self.complete

    @property
    def is_pending(self) -> bool:
        """Alias for :attr:`pending`."""
        return self.pending

    @property
    def local(self) -> bool:
        """Return whether this volume confirms the reference."""
        return self.status == ReparsePointStatus.LOCAL_CONFIRMED

    @property
    def external(self) -> bool:
        """Return whether the reference points outside this volume."""
        return self.status != ReparsePointStatus.LOCAL_CONFIRMED

    @property
    def verified(self) -> bool:
        """Return whether independent archival proof was accepted."""
        return self.status == ReparsePointStatus.EXTERNALLY_VERIFIED

    @property
    def resolved(self) -> bool:
        """Return whether the reference was identified or independently proven."""
        return self.complete

    def __bool__(self) -> bool:
        return self.complete

    def __call__(self, proof: object | None = None, **kwargs: Any) -> ReparsePointReference:
        """Re-explain the reference, optionally with caller-supplied proof."""
        return self.source.resolve_reparse_point(proof, **kwargs)


# Descriptive aliases. ``ReparsePointReference`` is the canonical name, but
# these make the result type discoverable under the wording used by callers.
ReparseReference = ReparsePointReference
ReparsePointResolution = ReparsePointReference
ReferenceResolution = ReparsePointReference
ReparseState = ReparsePointStatus
ReparsePointState = ReparsePointStatus
ReferenceState = ReparsePointStatus


class Mft:
    """Interact with the ``$MFT`` (Master File Table).

    Args:
        fh: A file-like object of the $MFT file.
        ntfs: An optional NTFS class instance.
    """

    def __init__(self, fh: BinaryIO, ntfs: NTFS | None = None):
        self.fh = fh
        self.ntfs = ntfs

        self.get = lru_cache(4096)(self.get)

    def __call__(self, ref: int | str | c_ntfs._MFT_SEGMENT_REFERENCE, *args, **kwargs) -> MftRecord:
        return self.get(ref, *args, **kwargs)

    @cached_property
    def root(self) -> MftRecord:
        """Return the root directory MFT record."""
        return self.get(FILE_NUMBER_ROOT)

    def _get_path(
        self,
        path: str,
        root: MftRecord | None = None,
        follow_symlinks: bool = True,
        read_only: bool | None = None,
    ) -> MftRecord:
        """Resolve a file path to the correct MFT record.

        ``.`` and ``..`` path components are normalized lexically first, like Win32 path normalization does
        (e.g. ``GetFullPathNameW``). This means a ``..`` cancels out the preceding component without that
        component being looked up, and without following any symlinks or mount points. Any leading ``..``
        components are resolved from ``root`` using the parent directory reference of its ``$FILE_NAME``
        attribute. The parent of the root directory is the root directory itself.

        Args:
            path: The path to resolve.
            root: Optional root record to start resolving from. Useful for relative path lookups.
            follow_symlinks: Whether to resolve symlinks and mount points encountered in the path. When
                ``False``, a reparse point in an intermediate path component is not followed.
            read_only: When ``True``, implies ``follow_symlinks=False``.
        """
        if read_only:
            follow_symlinks = False

        root = root or self.root

        # Programmatically we will often use the `/` separator, so replace it with the native path separator of NTFS
        # `/` is an illegal character in NTFS filenames, so it's safe to replace
        search_path = path.replace("/", "\\")

        # Lexically normalize "." and ".." components
        parts: list[str] = []
        num_parents = 0
        for part in search_path.split("\\"):
            if not part or part == ".":
                continue

            if part == "..":
                if parts:
                    parts.pop()
                else:
                    num_parents += 1
                continue

            parts.append(part)

        node = root
        seen_links: set[tuple[int | None, int | None]] = set()
        for _ in range(num_parents):
            node = self._get_parent(node)

        for part in parts:
            while follow_symlinks and (node.is_symlink() or node.is_mount_point()):
                link_id = (node.segment, getattr(node.header, "SequenceNumber", None))
                if link_id in seen_links:
                    raise NotAReparsePointError(f"Reparse point cycle while resolving {path}: {node!r}")
                seen_links.add(link_id)
                node = node.reparse_point_record

            if not node.is_dir():
                raise NotADirectoryError(f"Error finding path {path}: {self!r} is not a directory")

            index = node.index("$I30")
            try:
                node = index.search(part).dereference()
            except KeyError:
                raise FileNotFoundError(f"File not found: {path}")
            except FileNotFoundError:
                # An index can contain stale entries that share a name with a
                # live entry. The file reference sequence number is the
                # independent identity check; only accept an entry that
                # matches the MFT record it points at.
                node = None
                try:
                    for candidate in index.search_all(part):
                        try:
                            node = candidate.dereference()
                        except FileNotFoundError:
                            continue
                        break
                except (AttributeError, TypeError):
                    node = None

                if node is None:
                    raise FileNotFoundError(f"File not found: {path}")

        return node

    def _get_parent(self, record: MftRecord) -> MftRecord:
        """Return the parent directory record of the given record, using its ``$FILE_NAME`` attribute.

        The root directory (and any record without a ``$FILE_NAME`` attribute) is its own parent.
        Records with multiple hard links have multiple parents, in which case a non-DOS name is preferred.
        """
        if record.segment == FILE_NUMBER_ROOT:
            return record

        attrs = record.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]
        if not attrs:
            return record

        attr = next((attr for attr in attrs if attr.flags != FILE_NAME_DOS), attrs[0])
        return self.get(segment_reference(attr.attr.ParentDirectory))

    def get(
        self,
        ref: int | str | c_ntfs._MFT_SEGMENT_REFERENCE,
        root: MftRecord | None = None,
        follow_symlinks: bool = True,
        verify_sequence: bool = True,
        read_only: bool | None = None,
    ) -> MftRecord:
        """Retrieve an MFT record using a variety of methods.

        Supported references are:
            - ``_MFT_SEGMENT_REFERENCE`` cstruct structure
            - integer segment number
            - string file path

        Args:
            ref: Reference to retrieve the record by.
            root: Optional root record to start resolving from. Useful for relative path lookups.
            follow_symlinks: Whether to resolve symlinks and mount points in path lookups.
            verify_sequence: Verify the sequence number when a full MFT segment reference is given.
            read_only: When ``True``, path lookups do not follow reparse points.

        Raises:
            TypeError: If the reference is of an unsupported type.
        """
        sequence_number = None
        if isinstance(ref, c_ntfs._MFT_SEGMENT_REFERENCE):
            sequence_number = ref.SequenceNumber
            ref = segment_reference(ref)

        if isinstance(ref, int):
            record_size = self.ntfs._record_size if self.ntfs else DEFAULT_RECORD_SIZE

            record = MftRecord.from_fh(self.fh, ref * record_size, ntfs=self.ntfs)
            record.segment = ref

            actual_sequence = getattr(getattr(record, "header", None), "SequenceNumber", None)
            if (
                verify_sequence
                and sequence_number is not None
                and isinstance(actual_sequence, int)
                and sequence_number != actual_sequence
            ):
                raise FileNotFoundError(
                    f"MFT reference sequence mismatch for segment {ref}: "
                    f"expected {sequence_number}, found {actual_sequence}"
                )

            return record

        if isinstance(ref, str):
            return self._get_path(ref, root, follow_symlinks=follow_symlinks, read_only=read_only)

        raise TypeError(f"Invalid MFT reference: {ref!r}")

    def resolve_reparse_point(
        self,
        ref: int | str | c_ntfs._MFT_SEGMENT_REFERENCE | MftRecord,
        proof: object | None = None,
        **kwargs: Any,
    ) -> ReparsePointReference:
        """Explain a reparse point reference without following it."""
        record = ref if isinstance(ref, MftRecord) else self.get(ref, follow_symlinks=False)
        return record.resolve_reparse_point(proof, **kwargs)

    get_reference = resolve_reparse_point
    reference = resolve_reparse_point
    reparse_point_reference = resolve_reparse_point
    explain = resolve_reparse_point
    explain_reference = resolve_reparse_point
    resolve_reference = resolve_reparse_point

    def segments(self, start: int = 0, end: int = -1) -> Iterator[MftRecord]:
        """Yield all valid MFT records, regardless if they're allocated or not.

        Args:
            start: The starting segment number. Use ``-1`` to start from the last segment.
            end: The ending segment number. Use ``-1`` to end with the last segment.
        """
        record_size = self.ntfs._record_size if self.ntfs else DEFAULT_RECORD_SIZE
        last_segment = self.get(FILE_NUMBER_MFT).size() // record_size
        start = last_segment if start == -1 else start
        end = last_segment if end == -1 else end
        step = 1 if start <= end else -1

        for segment in range(start, end + step, step):
            try:
                yield self.get(segment)
            except Error:  # noqa: PERF203
                continue
            except EOFError:
                break


class MftRecord:
    """MFT record parsing and interaction.

    Use the :func:`~MftRecord.from_fh` or :func:`~MftRecord.from_bytes` class methods to instantiate.
    """

    def __init__(self):
        self.ntfs: NTFS | None = None
        self.segment: int | None = None
        self.offset: int | None = None
        self.data: bytes | None = None
        self.header: c_ntfs._FILE_RECORD_SEGMENT_HEADER | None = None

    def __repr__(self) -> str:
        return f"<MftRecord {self.segment}#{self.header.SequenceNumber}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MftRecord):
            return self.segment == other.segment and self.header.SequenceNumber == other.header.SequenceNumber
        return False

    __hash__ = object.__hash__

    @classmethod
    def from_fh(cls, fh: BinaryIO, offset: int, ntfs: NTFS | None = None) -> MftRecord:
        """Parse an MFT record from a file-like object.

        Args:
            fh: The file-like object to parse an MFT record from.
            offset: The offset in the file-like object to parse the MFT record from.
            ntfs: An optional NTFS class instance.
        """
        record_size = ntfs._record_size if ntfs else DEFAULT_RECORD_SIZE

        fh.seek(offset)
        data = fh.read(record_size)

        obj = cls.from_bytes(data, ntfs)
        obj.offset = offset
        return obj

    @classmethod
    def from_bytes(cls, data: bytes, ntfs: NTFS | None = None) -> MftRecord:
        """Parse an MFT record from bytes.

        Args:
            data: The bytes object to parse an MFT record from.
            ntfs: An optional NTFS class instance.

        Raises:
            BrokenMftError: If the MFT record signature is invalid.
        """
        obj = cls()
        obj.ntfs = ntfs

        if data[:4] != b"FILE":
            raise BrokenMftError(f"Invalid MFT record Signature: {data[:4]}")

        obj.data = apply_fixup(data)
        obj.header = c_ntfs._FILE_RECORD_SEGMENT_HEADER(obj.data)
        return obj

    def get(
        self,
        path: str,
        follow_symlinks: bool = True,
        verify_sequence: bool = True,
        read_only: bool | None = None,
    ) -> MftRecord:
        """Retrieve a :class:`MftRecord` relative to this one.

        Args:
            path: The path to lookup.
            follow_symlinks: Whether to resolve symlinks and mount points in the path.
            verify_sequence: Verify sequence numbers on directory index references.
            read_only: When ``True``, implies ``follow_symlinks=False``.

        Raises:
            MftNotAvailableError: If no MFT is available.
        """
        if not self.ntfs or not self.ntfs.mft:
            raise MftNotAvailableError
        return self.ntfs.mft.get(
            path,
            root=self,
            follow_symlinks=follow_symlinks,
            verify_sequence=verify_sequence,
            read_only=read_only,
        )

    @cached_property
    def attributes(self) -> AttributeMap:
        """Parse and return the attributes in this MFT record.

        ``$ATTRIBUTE_LIST``'s are only parsed if there's an MFT available on the NTFS object.

        Raises:
            BrokenMftError: If an error occurred parsing the attributes.
        """
        fh = BytesIO(self.data)
        offset = self.header.FirstAttributeOffset
        attrs = AttributeMap()

        attr_list = None
        while True:
            try:
                header = AttributeHeader(fh, offset, self)
            except EOFError:
                break

            if header.type == ATTRIBUTE_TYPE_CODE.END:
                break

            if header.record_length == 0:
                raise BrokenMftError("Attribute RecordLength is 0 but end not yet reached")

            attr = Attribute(header, self)
            attrs.add(attr)

            # If we encounter an attribute list, store it for later use
            # The attribute list can be non-resident, so we need to check if parsing succeeded
            # by checking if attr.attribute exists, in the case we don't have a volume
            if header.type == ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST and attr.attribute:
                attr_list = attr

            offset += header.record_length

        if attr_list and self.ntfs and self.ntfs.mft:
            for attr in attr_list.attributes():
                attrs.add(attr)

        return attrs

    @cached_property
    def resident(self) -> bool:
        """Return whether this record's default ``$DATA`` attribute is resident."""
        return any(attr.header.resident for attr in self.attributes[ATTRIBUTE_TYPE_CODE.DATA])

    @cached_property
    def filename(self) -> str | None:
        """Return the first file name, or ``None`` if this record has no file names."""
        filenames = self.filenames()
        return filenames[0] if filenames else None

    def filenames(self, ignore_dos: bool = False) -> list[str]:
        """Return all file names of this record.

        Args:
            ignore_dos: Ignore DOS file name entries.
        """
        result = []
        for attr in self.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]:
            if ignore_dos and attr.flags == FILE_NAME_DOS:
                continue
            result.append((attr.flags, attr.file_name))
        return [item[1] for item in sorted(result, key=itemgetter(0))]

    def full_path(self, ignore_dos: bool = False) -> str | None:
        """Return the first full path, or ``None`` if this record has no file names.

        Args:
            ignore_dos: Ignore DOS file name entries.
        """
        paths = self.full_paths(ignore_dos)
        return paths[0] if paths else None

    def full_paths(self, ignore_dos: bool = False) -> list[str]:
        """Return all full paths of this record.

        Args:
            ignore_dos: Ignore DOS file name entries.
        """
        result = []

        for attr in self.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]:
            if ignore_dos and attr.flags == FILE_NAME_DOS:
                continue
            result.append((attr.flags, attr.full_path()))

        return [item[1] for item in sorted(result, key=itemgetter(0))]

    def is_dir(self) -> bool:
        """Return whether this record is a directory."""
        return bool(self.header.Flags & FILE_FILE_NAME_INDEX_PRESENT)

    def is_file(self) -> bool:
        """Return whether this record is a file."""
        return not self.is_dir()

    def is_reparse_point(self) -> bool:
        """Return whether this record is a reparse point."""
        return ATTRIBUTE_TYPE_CODE.REPARSE_POINT in self.attributes

    def is_symlink(self) -> bool:
        """Return whether this record is a symlink reparse point."""
        attr = self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]
        return bool(attr) and attr.tag == IO_REPARSE_TAG.SYMLINK

    def is_mount_point(self) -> bool:
        """Return whether this record is a mount point reparse point."""
        attr = self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]
        return bool(attr) and attr.tag == IO_REPARSE_TAG.MOUNT_POINT

    def is_cloud_file(self) -> bool:
        """Return whether this record is a cloud reparse point."""
        attr = self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]
        return bool(attr) and attr.tag in (
            IO_REPARSE_TAG.CLOUD,
            IO_REPARSE_TAG.CLOUD_1,
            IO_REPARSE_TAG.CLOUD_2,
            IO_REPARSE_TAG.CLOUD_3,
            IO_REPARSE_TAG.CLOUD_4,
            IO_REPARSE_TAG.CLOUD_5,
            IO_REPARSE_TAG.CLOUD_6,
            IO_REPARSE_TAG.CLOUD_7,
            IO_REPARSE_TAG.CLOUD_8,
            IO_REPARSE_TAG.CLOUD_9,
            IO_REPARSE_TAG.CLOUD_A,
            IO_REPARSE_TAG.CLOUD_B,
            IO_REPARSE_TAG.CLOUD_C,
            IO_REPARSE_TAG.CLOUD_D,
            IO_REPARSE_TAG.CLOUD_E,
            IO_REPARSE_TAG.CLOUD_F,
        )

    @cached_property
    def reparse_point_name(self) -> str:
        """Return the (printable) name of this reparse point."""
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self!r} is not a reparse point")
        return self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT].print_name

    @cached_property
    def reparse_point_substitute_name(self) -> str:
        """Return the substitute name of this reparse point."""
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self!r} is not a reparse point")
        return self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT].substitute_name

    @cached_property
    def reparse_point_record(self) -> MftRecord:
        """Return the target record if it can be confirmed from this volume.

        Note: absolute links (such as directory junctions) will *always* fail in the context of a single filesystem.
        Absolute links include the drive letter, of which we have no knowledge here.

        This property only performs an in-volume lookup. It never follows an
        absolute or out-of-volume target.
        """
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self!r} is not a reparse point")

        if not self.ntfs or not self.ntfs.mft:
            raise MftNotAvailableError

        result = self.resolve_reparse_point()
        if result.record is not None:
            return result.record

        raise FileNotFoundError(f"Reparse point target is not available on this volume: {self!r}")

    @cached_property
    def reparse_point_reference(self) -> ReparsePointReference:
        """Explain a reparse point without following it.

        The explanation has one of three states: the target is confirmed from
        this volume, the target belongs to material that has not been collected
        (another volume), or the caller supplied independent archival proof for
        the target.

        The returned explanation is also callable, so callers can pass
        independent proof with ``record.reparse_point_reference(proof=...)``.

        Raises:
            NotAReparsePointError: If this record is not a reparse point.
        """
        return self.resolve_reparse_point()

    def resolve_reparse_point(
        self,
        proof: object | None = None,
        *,
        read_only: bool = True,
        **kwargs: Any,
    ) -> ReparsePointReference:
        """Resolve a reparse point to a three-state read-only explanation.

        The target is never followed through an absolute path or a mount point.
        Relative symlinks are only checked with a no-follow lookup in this
        volume. If such a lookup cannot confirm the target, the reference is
        reported as external material that still has to be collected.
        """
        del read_only

        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self!r} is not a reparse point")

        proof = _select_proof(proof, kwargs)
        reparse_point = self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]
        target = reparse_point.print_name or reparse_point.substitute_name

        if target:
            local_target = self._local_reparse_target(reparse_point, target)
            if local_target is not None:
                record = self._lookup_local_target(local_target)
                if record is not None:
                    return ReparsePointReference(
                        source=self,
                        target=target,
                        status=ReparsePointStatus.LOCAL_CONFIRMED,
                        record=record,
                        reason="Target is present in this volume",
                    )

        if proof is not None:
            verified, proof_record = _match_proof(self, target, proof)
            if verified:
                return ReparsePointReference(
                    source=self,
                    target=target,
                    status=ReparsePointStatus.EXTERNALLY_VERIFIED,
                    record=proof_record,
                    reason="Caller supplied independent archival proof",
                )

        if target is None:
            reason = "Reparse point does not contain a usable target"
        elif _is_external_target(reparse_point, target):
            reason = "Target is outside this volume and has not been collected"
        else:
            reason = "Target could not be confirmed from this volume"

        return ReparsePointReference(
            source=self,
            target=target,
            status=ReparsePointStatus.EXTERNAL_PENDING,
            reason=reason,
        )

    # Readable aliases for the explanation operation.
    explain_reference = resolve_reparse_point
    explain_reparse_point = resolve_reparse_point
    resolve_reference = resolve_reparse_point

    def reparse_point_status(self, proof: object | None = None, **kwargs: Any) -> ReparsePointStatus:
        """Return only the three-state explanation status for this reparse point."""
        return self.resolve_reparse_point(proof, **kwargs).status

    @cached_property
    def reparse_point_resolution(self) -> ReparsePointReference:
        """Return the no-proof read-only explanation for this reparse point."""
        return self.resolve_reparse_point()

    def _local_reparse_target(self, reparse_point: Any, target: str) -> str | None:
        """Return a root-relative target path if it can stay inside this volume."""
        if _is_external_target(reparse_point, target):
            return None

        if reparse_point.relative:
            source_path = self.full_path()
            if not source_path:
                return None
            target = ntpath.join(ntpath.dirname(source_path), target)

        target = ntpath.normpath(target)
        drive, tail = ntpath.splitdrive(target)
        if drive or tail.startswith("\\") or target == ".." or target.startswith("..\\"):
            return None

        return target

    def _lookup_local_target(self, target: str) -> MftRecord | None:
        """Look up a target with link following disabled, returning ``None`` on failure."""
        if not self.ntfs or not self.ntfs.mft:
            return None

        try:
            return self.ntfs.mft.get(target, follow_symlinks=False)
        except Exception:
            return None

    def _get_stream_attributes(
        self, name: str, attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA
    ) -> AttributeCollection[Attribute]:
        """Return the :class:`~dissect.ntfs.util.AttributeCollection` of all attributes with the given name and attribute type.

        Args:
            name: The attribute name, often an empty string.
            attr_type: The attribute type to find.

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
        """  # noqa: E501
        attrs = self.attributes.find(name, attr_type)
        if not attrs:
            raise FileNotFoundError(f"No such stream on record {self}: ({name!r}, {attr_type})")
        return attrs

    def open(
        self,
        name: str = "",
        attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA,
        allocated: bool = False,
    ) -> BinaryIO:
        """Open a stream on the given stream name and type.

        Args:
            name: The stream name, an empty string for the "default" data stream.
            attr_type: The attribute type to open a stream on.
            allocated: Whether to use the real stream size or the allocated stream size (i.e. include slack space).

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
        """
        return self._get_stream_attributes(name, attr_type).open(allocated)

    def size(
        self,
        name: str = "",
        attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA,
        allocated: bool = False,
    ) -> int:
        """Return the stream size of the given stream name and type.

        Args:
            name: The stream name, an empty string for the "default" data stream.
            attr_type: The attribute type to find the stream size of.
            allocated: Whether to use the real stream size or the allocated stream size (i.e. include slack space).

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
        """
        return self._get_stream_attributes(name, attr_type).size(allocated)

    def dataruns(
        self, name: str = "", attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA
    ) -> list[tuple[int, int]]:
        """Return the dataruns of the given stream name and type.

        Args:
            name: The stream name, an empty string for the "default" data stream.
            attr_type: The attribute type to get the dataruns of.

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
        """
        return self._get_stream_attributes(name, attr_type).dataruns()

    def has_stream(self, name: str = "", attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA) -> bool:
        """Return whether or not this record has attributes with the given name and type."""
        return bool(self.attributes.find(name, attr_type))

    def index(self, name: str) -> Index:
        """Open an index on this record.

        Args:
            name: The index name to open. For example, ``"$I30"``.
        """
        return Index(self, name)

    def iterdir(self, dereference: bool = False, ignore_dos: bool = False) -> Iterator[IndexEntry | MftRecord]:
        """Yield directory entries of this record.

        Args:
            dereference: Determines whether to resolve the :class:`~dissect.ntfs.index.IndexEntry`'s to :class:`MftRecord`'s. This impacts performance.
            ignore_dos: Ignore DOS file name entries.

        Raises:
            NotADirectoryError: If this record is not a directory.
        """  # noqa: E501
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        for entry in self.index("$I30").entries():
            if ignore_dos and entry.attribute.flags == FILE_NAME_DOS:
                continue
            if dereference:
                try:
                    yield entry.dereference()
                except FileNotFoundError:
                    # Stale index entries can share a name with a live entry.
                    # Skip them so they cannot shadow the verified record.
                    continue
            else:
                yield entry

    def listdir(self, dereference: bool = False, ignore_dos: bool = False) -> dict[str, IndexEntry | MftRecord]:
        """Return a dictionary of the directory entries of this record.

        Args:
            dereference: Determines whether to resolve the :class:`~dissect.ntfs.index.IndexEntry`'s to :class:`MftRecord`'s. This impacts performance.
            ignore_dos: Ignore DOS file name entries.

        Raises:
            NotADirectoryError: If this record is not a directory.
        """  # noqa: E501
        result = {}
        for entry in self.iterdir(dereference, ignore_dos):
            filenames = entry.filenames(ignore_dos) if dereference else [entry.attribute.file_name]
            for filename in filenames:
                result[filename] = entry

        return result


def mft_resolve_reparse_point(
    record: MftRecord,
    proof: object | None = None,
    **kwargs: Any,
) -> ReparsePointReference:
    """Explain a reparse point using a read-only, no-follow policy."""
    return record.resolve_reparse_point(proof, **kwargs)


# The module-level spelling is the most convenient one for callers that just
# have a record and want an explanation.
resolve_reparse_point = mft_resolve_reparse_point
resolve_reference = mft_resolve_reparse_point
explain_reference = mft_resolve_reparse_point


def _select_proof(proof: object | None, kwargs: Mapping[str, Any]) -> object | None:
    if proof is None:
        for key in (
            "archive",
            "archive_proof",
            "archival_proof",
            "custody",
            "custody_proof",
            "evidence",
            "external_proof",
            "independent_proof",
            "caller_proof",
        ):
            if kwargs.get(key) is not None:
                proof = kwargs[key]
                break

    if proof is None:
        for key in ("verified", "archived", "proven"):
            if kwargs.get(key) is True:
                proof = True
                break

    return proof


def _is_external_target(reparse_point: Any, target: str) -> bool:
    if getattr(reparse_point, "tag", None) == IO_REPARSE_TAG.MOUNT_POINT:
        return True

    if getattr(reparse_point, "relative", False):
        return False

    if getattr(reparse_point, "tag", None) == IO_REPARSE_TAG.SYMLINK:
        return True

    drive, tail = ntpath.splitdrive(target)
    return bool(drive) or tail.startswith(("\\", "/"))


def _normalise_reference(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value)).rstrip("\\")


def _source_paths(record: MftRecord) -> list[str]:
    result = []
    try:
        result.extend(record.full_paths())
    except Exception:
        pass

    try:
        if record.filename:
            result.append(record.filename)
    except Exception:
        pass

    return [value for value in result if isinstance(value, str) and value]


def _proof_paths(proof: object) -> list[str]:
    if isinstance(proof, str):
        return [proof]

    if isinstance(proof, MftRecord):
        return _source_paths(proof)

    if isinstance(proof, Mapping):
        return []

    result = []
    for name in ("target", "target_path", "path", "full_path", "source", "source_path", "filename"):
        value = getattr(proof, name, None)
        if callable(value):
            try:
                value = value()
            except TypeError:
                continue
        if isinstance(value, str) and value:
            result.append(value)

    value = getattr(proof, "full_paths", None)
    if callable(value):
        try:
            result.extend(item for item in value() if isinstance(item, str) and item)
        except TypeError:
            pass

    record = getattr(proof, "record", None)
    if isinstance(record, MftRecord):
        result.extend(_source_paths(record))

    return result


def _path_matches(value: str, candidates: set[str]) -> bool:
    normalised = _normalise_reference(value)
    if normalised in candidates:
        return True

    # Only fall back to a basename comparison for a bare filename. A proof that
    # carries a directory must match that directory; otherwise two same-named
    # records in different locations would both be considered verified.
    if "\\" in normalised or "/" in normalised:
        return False

    basename = ntpath.basename(normalised)
    return bool(basename) and basename in candidates


def _match_proof(record: MftRecord, target: str | None, proof: object) -> tuple[bool, MftRecord | None]:
    """Return whether ``proof`` vouches for ``target``, plus any concrete record."""
    if proof is True:
        return True, None
    if proof is False or proof is None:
        return False, None

    candidates = set()
    if target:
        candidates.add(_normalise_reference(target))
        candidates.add(ntpath.basename(_normalise_reference(target)).casefold())

    source_paths = _source_paths(record)
    candidates.update(_normalise_reference(value) for value in source_paths)
    candidates.update(ntpath.basename(_normalise_reference(value)).casefold() for value in source_paths)
    candidates.discard("")

    if isinstance(proof, Mapping):
        for key, value in proof.items():
            if isinstance(key, str) and _path_matches(key, candidates):
                return _match_proof(record, target, value)
            if isinstance(key, MftRecord) and key == record:
                return _match_proof(record, target, value)
            if isinstance(key, int) and key == record.segment:
                return _match_proof(record, target, value)
            if (
                isinstance(key, tuple)
                and key
                and key[0] == record.segment
                and (len(key) == 1 or key[1:] == (getattr(record.header, "SequenceNumber", None),))
            ):
                return _match_proof(record, target, value)

        for key in ("*", "default", "any"):
            if key in proof:
                return _match_proof(record, target, proof[key])

        return False, None

    if isinstance(proof, (list, set, frozenset)):
        for item in proof:
            verified, proof_record = _match_proof(record, target, item)
            if verified:
                return True, proof_record
        return False, None

    if isinstance(proof, tuple) and len(proof) == 2 and all(isinstance(item, int) for item in proof):
        return proof == (record.segment, getattr(record.header, "SequenceNumber", None)), None

    if isinstance(proof, (int, c_ntfs._MFT_SEGMENT_REFERENCE)):
        # A caller-provided reference is itself independent evidence. We do not
        # use it to perform a lookup or follow the link.
        return True, None

    paths = _proof_paths(proof)
    if paths:
        if any(_path_matches(path, candidates) for path in paths):
            proof_record = proof if isinstance(proof, MftRecord) else getattr(proof, "record", None)
            return True, proof_record if isinstance(proof_record, MftRecord) else None
        return False, None

    # An opaque object supplied by the caller is still explicit evidence. It
    # can only be honoured as "caller vouches for this reference"; no lookup is
    # attempted.
    proof_record = proof if isinstance(proof, MftRecord) else getattr(proof, "record", None)
    return True, proof_record if isinstance(proof_record, MftRecord) else None
