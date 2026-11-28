from __future__ import annotations

import io
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, IO_REPARSE_TAG, c_ntfs
from dissect.ntfs.exceptions import FileNotFoundError
from dissect.ntfs.index import IndexEntry
from dissect.ntfs.mft import MftRecord, ReparsePointStatus


class FakeReparsePoint:
    def __init__(self, target: str, relative: bool = True):
        self.tag = IO_REPARSE_TAG.SYMLINK
        self.print_name = target
        self.substitute_name = target
        self.relative = relative
        self.absolute = not relative


class FakeMft:
    def __init__(self, result: MftRecord | None = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def get(self, target: str, **kwargs) -> MftRecord | None:
        self.calls.append((target, kwargs))
        if self.error:
            raise self.error
        return self.result


def make_record(
    target: str,
    *,
    path: str = "evidence\\links\\link",
    relative: bool = True,
    mft: FakeMft | None = None,
    segment: int = 10,
    sequence: int = 1,
) -> MftRecord:
    record = MftRecord()
    record.segment = segment
    record.header = SimpleNamespace(SequenceNumber=sequence)
    record.ntfs = SimpleNamespace(mft=mft or FakeMft())
    record.attributes = {ATTRIBUTE_TYPE_CODE.REPARSE_POINT: FakeReparsePoint(target, relative)}
    record.full_path = lambda ignore_dos=False: path
    record.full_paths = lambda ignore_dos=False: [path]
    return record


def test_relative_target_confirmed_from_this_volume() -> None:
    target = make_record("target.txt", segment=11)
    mft = FakeMft(result=target)
    link = make_record("target.txt", mft=mft)

    reference = link.resolve_reparse_point()

    assert reference.status is ReparsePointStatus.LOCAL_CONFIRMED
    assert reference.complete
    assert reference.record is target
    assert mft.calls == [("evidence\\links\\target.txt", {"follow_symlinks": False})]


def test_absolute_target_is_not_followed() -> None:
    mft = FakeMft(error=AssertionError("must not be called"))
    link = make_record("C:\\outside\\material.bin", relative=False, mft=mft)

    reference = link.resolve_reparse_point()

    assert reference.status is ReparsePointStatus.EXTERNAL_PENDING
    assert not reference.complete
    assert mft.calls == []

    with pytest.raises(FileNotFoundError):
        _ = link.reparse_point_record
    assert mft.calls == []


def test_independent_proof_completes_external_material() -> None:
    archive = make_record("material.bin", path="D:\\archive\\material.bin", relative=False, segment=20)
    mft = FakeMft(error=AssertionError("must not be called"))
    link = make_record("D:\\archive\\material.bin", relative=False, mft=mft)

    reference = link.resolve_reparse_point(proof=archive)

    assert reference.status is ReparsePointStatus.EXTERNALLY_VERIFIED
    assert reference.complete
    assert reference.record is archive
    assert mft.calls == []


def test_only_the_matching_same_named_record_is_complete() -> None:
    target = "D:\\archive\\material.bin"
    first = make_record(target, path="evidence\\a\\material.bin", relative=False, segment=30)
    second = make_record(target, path="evidence\\b\\material.bin", relative=False, segment=31)

    first_reference = first.resolve_reparse_point(proof="evidence\\a\\material.bin")
    second_reference = second.resolve_reparse_point(proof="evidence\\a\\material.bin")

    assert first_reference.status is ReparsePointStatus.EXTERNALLY_VERIFIED
    assert first_reference.complete
    assert second_reference.status is ReparsePointStatus.EXTERNAL_PENDING
    assert not second_reference.complete


def test_index_dereference_requires_matching_sequence() -> None:
    reference = c_ntfs._MFT_SEGMENT_REFERENCE(SegmentNumberLowPart=42, SequenceNumber=7)
    header = c_ntfs._INDEX_ENTRY()
    header.FileReference = reference
    header.Length = len(header)

    record = SimpleNamespace(header=SimpleNamespace(SequenceNumber=8))
    mft = Mock()
    mft.get.return_value = record
    index = Mock()
    index.record.ntfs.mft = mft

    entry = IndexEntry(index, io.BytesIO(header.dumps()), 0)

    with pytest.raises(FileNotFoundError):
        entry.dereference()

    record.header.SequenceNumber = 7
    assert entry.dereference() is record
