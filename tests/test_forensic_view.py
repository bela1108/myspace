import pytest

from minidump.authorized_reader import AuthorizedMinidumpReader
from minidump.forensic import (
    AddressRange,
    AuthorizationDeniedError,
    CrossFragmentReadError,
    EvidenceSource,
    ForensicView,
    IncompleteForensicRead,
    MultipleAuthorizedSourcesError,
    SourceSegment,
    synthetic_case,
)
from minidump.forensic_view import ForensicReceipt


def test_two_synthetic_snapshots_are_short_and_non_process():
    case = synthetic_case()

    assert len(case["view"].sources) == 2
    assert case["alpha"].source_id == "synthetic-alpha"
    assert case["beta"].source_id == "synthetic-beta"
    assert sum(segment.size for segment in case["alpha"].segments) == 8
    assert case["beta"].segments[0].size == 16


def test_cross_page_continuous_read_retains_actual_fragments():
    case = synthetic_case()

    receipt = case["view"].read(case["cross_page_request"])

    assert isinstance(receipt, ForensicReceipt)
    assert receipt.complete is True
    assert receipt.ok is True
    assert receipt.status == "complete"
    assert receipt.data == b"ALFABETA"
    assert receipt.bytes_read == 8
    assert receipt.fragment_count == 2
    assert [fragment.start_address for fragment in receipt.fragments] == [0x0FFC, 0x1000]
    assert [fragment.end_address for fragment in receipt.fragments] == [0x1000, 0x1004]
    assert [fragment.data for fragment in receipt.fragments] == [b"ALFA", b"BETA"]
    assert receipt.source_ids == ["synthetic-alpha"]
    assert all(fragment.sha256 for fragment in receipt.fragments)

    serialized = receipt.to_dict()
    assert serialized["complete"] is True
    assert serialized["data_hex"] == b"ALFABETA".hex()
    assert [item["data_hex"] for item in serialized["fragments"]] == [
        b"ALFA".hex(),
        b"BETA".hex(),
    ]


def test_partial_authorization_has_distinct_receipt():
    case = synthetic_case()

    receipt = case["view"].read(case["partial_request"])

    assert receipt.complete is False
    assert receipt.ok is False
    assert receipt.status == "partial"
    assert receipt.partial is True
    assert receipt.data is None
    assert receipt.buffer is None
    assert receipt.bytes_read == 8
    assert receipt.fragment_count == 1
    assert receipt.fragments[0].range == AddressRange(0x2000, 0x2008)
    assert receipt.fragments[0].data == b"01234567"
    assert len(receipt.unauthorized) == 1
    assert receipt.unauthorized[0].range == AddressRange(0x2008, 0x2010)
    assert receipt.unauthorized[0].source_ids == ["synthetic-beta"]
    assert receipt.uncollected == []
    assert receipt.multiple_sources == []

    with pytest.raises(AuthorizationDeniedError) as exc_info:
        case["view"].read_strict(0x2000, 16)

    assert exc_info.value.receipt.status == "partial"
    assert exc_info.value.receipt.data is None


def test_uncollected_and_unauthorized_ranges_are_recorded_separately():
    source = EvidenceSource(
        source_id="synthetic-known",
        data=b"KNOWN",
        start_address=0x3000,
        authorized_ranges=[
            AddressRange(0x3000, 0x3005),
            AddressRange(0x4000, 0x4004),
        ],
    )
    view = ForensicView(sources=[source])

    uncollected = view.read(0x4000, 4)
    assert uncollected.complete is False
    assert uncollected.status == "uncollected"
    assert uncollected.uncollected[0].range == AddressRange(0x4000, 0x4004)
    assert uncollected.uncollected[0].authorized_source_ids == ["synthetic-known"]
    assert uncollected.unauthorized == []

    partial_missing = view.read(0x3003, 4)
    assert partial_missing.status == "partial"
    assert partial_missing.fragments[0].data == b"WN"
    assert partial_missing.uncollected[0].range == AddressRange(0x3005, 0x3007)


def test_multiple_authorized_sources_are_recorded_and_fail_closed():
    view = ForensicView(sources=[
        EvidenceSource(
            source_id="snapshot-one",
            data=b"ONE!",
            start_address=0x6000,
            authorized_ranges=[(0x6000, 0x6004)],
        ),
        EvidenceSource(
            source_id="snapshot-two",
            data=b"TWO!",
            start_address=0x6000,
            authorized_ranges=[(0x6000, 0x6004)],
        ),
    ])

    receipt = view.read(0x6000, 4)

    assert receipt.complete is False
    assert receipt.status == "multiple_authorized_sources"
    assert len(receipt.multiple_sources) == 1
    assert receipt.multiple_sources[0].source_ids == ["snapshot-one", "snapshot-two"]
    assert receipt.data is None

    with pytest.raises(MultipleAuthorizedSourcesError):
        bytes(receipt)


def test_cross_fragment_failure_never_becomes_complete_material():
    def fail_second(address, size):
        raise IOError("synthetic fragment read failure")

    source = EvidenceSource(
        source_id="faulty-snapshot",
        authorized_ranges=[(0, 8)],
        segments=[
            SourceSegment(0, b"head"),
            SourceSegment(4, size=4, read=fail_second),
        ],
    )
    strict_view = ForensicView(sources=[source])

    with pytest.raises(CrossFragmentReadError) as exc_info:
        strict_view.read(0, 8)

    error_receipt = exc_info.value.receipt
    assert isinstance(exc_info.value.__cause__, IOError)
    assert error_receipt.complete is False
    assert error_receipt.status == "error"
    assert error_receipt.data is None
    assert len(error_receipt.fragments) == 1
    assert error_receipt.fragments[0].data == b"head"
    assert error_receipt.partial_data == b"head"
    with pytest.raises(IncompleteForensicRead):
        bytes(error_receipt)

    safe_view = ForensicView(sources=[source], raise_on_error=False)
    safe_receipt = safe_view.read(0, 8)
    assert safe_receipt.status == "error"
    assert safe_receipt.data is None
    assert safe_receipt.bytes_read == 4


class FakeMinidumpSegment:
    def __init__(self, start, data, rva):
        self.start_virtual_address = start
        self.size = len(data)
        self.end_virtual_address = start + len(data)
        self.start_file_address = rva
        self.data = data

    def read(self, virtual_address, size, file_handle):
        assert file_handle == "fake-handle"
        offset = virtual_address - self.start_virtual_address
        return self.data[offset:offset + size]


class FakeMinidumpReader:
    file_handle = "fake-handle"
    memory_segments = [
        FakeMinidumpSegment(0x7000, b"PAGE", 0x100),
        FakeMinidumpSegment(0x7004, b"BOUNDARY", 0x104),
    ]


def test_minidump_reader_adapter_crosses_memory_segments():
    reader = FakeMinidumpReader()
    view = AuthorizedMinidumpReader(
        reader,
        authorized_ranges=[AddressRange(0x7000, 0x700C)],
    )

    receipt = view.read(0x7000, 12)

    assert receipt.complete is True
    assert receipt.data == b"PAGEBOUNDARY"
    assert receipt.fragment_count == 2
    assert receipt.fragments[0].file_offset == 0x100
    assert receipt.fragments[1].file_offset == 0x104


def test_existing_reader_gets_forensic_entrypoint():
    from minidump.minidumpreader import MinidumpFileReader

    assert hasattr(MinidumpFileReader, "forensic_view")
    assert hasattr(MinidumpFileReader, "read_authorized")


def test_authorized_and_unauthorized_overlapping_sources_are_both_recorded():
    allowed = EvidenceSource(
        source_id="allowed-snapshot",
        data=b"GOOD",
        start_address=0x9000,
        authorized_ranges=[(0x9000, 0x9004)],
    )
    secret = EvidenceSource(
        source_id="secret-snapshot",
        data=b"SECR",
        start_address=0x9000,
    )

    receipt = ForensicView(sources=[allowed, secret]).read(0x9000, 4)

    assert receipt.complete is True
    assert receipt.data == b"GOOD"
    assert [fragment.source_id for fragment in receipt.fragments] == ["allowed-snapshot"]
    assert len(receipt.unauthorized) == 1
    assert receipt.unauthorized[0].source_ids == ["secret-snapshot"]


def test_read_range_takes_exclusive_end():
    case = synthetic_case()

    receipt = case["view"].read_range(0x0FFC, 0x1004)

    assert receipt.complete is True
    assert receipt.data == b"ALFABETA"


def test_adjacent_distinct_licensed_sources_concatenate_with_provenance():
    view = ForensicView(sources=[
        EvidenceSource(
            source_id="page-source-a",
            data=b"AAAA",
            start_address=0xC000,
            authorized_ranges=[(0xC000, 0xC004)],
        ),
        EvidenceSource(
            source_id="page-source-b",
            data=b"BBBB",
            start_address=0xC004,
            authorized_ranges=[(0xC004, 0xC008)],
        ),
    ])

    receipt = view.read(0xC000, 8)

    assert receipt.complete is True
    assert receipt.data == b"AAAABBBB"
    assert receipt.fragment_count == 2
    assert receipt.spans_multiple_sources is True
    assert receipt.sources == ["page-source-a", "page-source-b"]
    assert receipt.multiple_sources == []


def test_identical_authorized_overlap_can_be_resolved_with_audit_record():
    view = ForensicView(
        allow_identical_overlaps=True,
        sources=[
            EvidenceSource(
                source_id="first",
                data=b"SAME",
                start_address=0xB000,
                authorized_ranges=[(0xB000, 0xB004)],
            ),
            EvidenceSource(
                source_id="second",
                data=b"SAME",
                start_address=0xB000,
                authorized_ranges=[(0xB000, 0xB004)],
            ),
        ],
    )

    receipt = view.read(0xB000, 4)

    assert receipt.complete is True
    assert receipt.data == b"SAME"
    assert len(receipt.multiple_sources) == 1
    assert receipt.multiple_sources[0].blocking is False
    assert receipt.multiple_sources[0].source_ids == ["first", "second"]
    assert len(receipt.verification_fragments) == 2


def test_real_minidump_bytes_support_forensic_entrypoint():
    import io
    import struct

    from minidump.minidumpfile import MinidumpFile

    def directory_entry(stream_type, size, rva):
        return struct.pack("<III", stream_type, size, rva)

    module_stream = struct.pack("<I", 0)
    system_info = (
        struct.pack("<HHHBBIIIIIHH", 9, 0, 0, 1, 1, 10, 0, 19045, 2, 0, 0, 0)
        + b"\0" * 16
    )
    directory_rva = 32
    rva = directory_rva + 3 * 12
    module_rva = rva
    rva += len(module_stream)
    system_rva = rva
    rva += len(system_info)
    memory_rva = rva
    memory_size = 4 + 16 * 2
    rva += memory_size

    memory_list = struct.pack("<I", 2)
    memory_data = b""
    for address, payload in [(0xA000, b"PAGE"), (0xA004, b"END!")]:
        memory_list += struct.pack("<QII", address, len(payload), rva)
        memory_data += payload
        rva += len(payload)

    header = (
        b"MDMP"
        + struct.pack("<HHIIIII", 0, 0, 3, directory_rva, 0, 0, 0)
        + b"\0" * 4
    )
    directory = (
        directory_entry(4, len(module_stream), module_rva)
        + directory_entry(7, len(system_info), system_rva)
        + directory_entry(5, memory_size, memory_rva)
    )
    blob = header + directory + module_stream + system_info + memory_list + memory_data

    minidump = MinidumpFile.parse_buff(io.BytesIO(blob))
    receipt = minidump.forensic_view(
        authorized_ranges=[AddressRange(0xA000, 0xA008)]
    ).read(0xA000, 8)

    assert receipt.complete is True
    assert receipt.data == b"PAGEEND!"
    assert receipt.fragment_count == 2
