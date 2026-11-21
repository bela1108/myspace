import io
import struct

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.coverage_audit import (
    FULL_COVERAGE,
    INSUFFICIENT_EVIDENCE,
    LIMITED_COVERAGE,
    ORIGIN_CAPTURE_SOURCE,
    ORIGIN_EXPORT,
    ExportDescription,
    audit_capture_coverage,
)

PACKET_DATAS = (b"\x00\x01\x02\x03 packet one", b"\x04\x05\x06\x07 packet two")


def build_capture(
    if_options=None,
    isb_options=None,
    packet_datas=PACKET_DATAS,
    shb_options=None,
):
    """Build an in-memory pcapng capture with one section/interface."""
    stream = io.BytesIO()
    shb = blocks.SectionHeader(options=shb_options or {})
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options=if_options or {},
    )
    # FileWriter writes the SHB and its IDBs right away.
    writer = FileWriter(stream, shb)

    for packet_data in packet_datas:
        epb = shb.new_member(blocks.EnhancedPacket)
        epb.packet_data = packet_data
        writer.write_block(epb)

    if isb_options is not None:
        isb = shb.new_member(
            blocks.InterfaceStatistics, interface_id=0, options=isb_options
        )
        writer.write_block(isb)

    stream.seek(0)
    return stream


def read_packet_datas(stream):
    return [
        block.packet_data
        for block in FileScanner(stream)
        if isinstance(block, blocks.EnhancedPacket)
    ]


def test_source_filter_and_drops_are_explicit_limitations():
    stream = build_capture(
        if_options={"if_filter": [(0, b"tcp port 80")]},
        isb_options={"isb_ifrecv": 1000, "isb_ifdrop": 5},
    )
    report = audit_capture_coverage(
        stream,
        export_description=ExportDescription(
            "exported unfiltered", limited=False
        ),
    )

    assert report.conclusion == LIMITED_COVERAGE
    assert len(report.sections) == 1

    section = report.sections[0]
    assert section.index == 0
    assert section.conclusion == LIMITED_COVERAGE

    interface = section.interfaces[0]
    assert interface.conclusion == LIMITED_COVERAGE
    assert interface.packet_count == len(PACKET_DATAS)

    origins = [item.origin for item in interface.limitations]
    assert origins == [ORIGIN_CAPTURE_SOURCE, ORIGIN_CAPTURE_SOURCE]
    assert "tcp port 80" in interface.limitations[0].detail
    assert "5 packets dropped" in interface.limitations[1].detail

    # Everything was declared: nothing left undeclared or unexplained.
    assert interface.undeclared == []
    assert interface.unexplained == []


def test_export_description_is_an_explicit_limitation():
    stream = build_capture(
        if_options={"if_filter": [(0, b"")]},
        isb_options={"isb_ifrecv": 2, "isb_usrdeliv": 2},
    )
    report = audit_capture_coverage(
        stream,
        export_description=ExportDescription(
            "full capture, filtered to tcp/80 at export time"
        ),
    )

    interface = report.sections[0].interfaces[0]
    assert interface.conclusion == LIMITED_COVERAGE
    assert len(interface.limitations) == 1
    limitation = interface.limitations[0]
    assert limitation.origin == ORIGIN_EXPORT
    assert "tcp/80" in limitation.detail


def test_missing_interface_options_degrade_to_insufficient_evidence():
    # The same time window, the same packets -- but the second record
    # had its interface options stripped. Identical packet content must
    # not let it inherit the first record's conclusion.
    limited_stream = build_capture(
        if_options={"if_filter": [(0, b"tcp port 80")]},
        isb_options={"isb_ifrecv": 1000, "isb_ifdrop": 5},
    )
    stripped_stream = build_capture()

    assert read_packet_datas(limited_stream) == read_packet_datas(stripped_stream)
    limited_stream.seek(0)
    stripped_stream.seek(0)

    limited_report = audit_capture_coverage(
        limited_stream,
        export_description=ExportDescription(
            "exported unfiltered", limited=False
        ),
    )
    stripped_report = audit_capture_coverage(stripped_stream)

    limited_interface = limited_report.sections[0].interfaces[0]
    stripped_interface = stripped_report.sections[0].interfaces[0]

    assert limited_interface.conclusion == LIMITED_COVERAGE
    assert stripped_interface.conclusion == INSUFFICIENT_EVIDENCE
    assert stripped_report.conclusion == INSUFFICIENT_EVIDENCE

    # Same packets, same count -- but no inherited conclusion.
    assert stripped_interface.packet_count == limited_interface.packet_count
    assert stripped_interface.limitations == []

    aspects = [item.aspect for item in stripped_interface.undeclared]
    assert aspects == [
        "capture_filter",
        "sampling_statistics",
        "export_filtering",
    ]


def test_full_coverage_requires_all_aspects_declared():
    stream = build_capture(
        if_options={"if_filter": [(0, b"")]},
        isb_options={
            "isb_ifrecv": 2,
            "isb_ifdrop": 0,
            "isb_filteraccept": 2,
            "isb_osdrop": 0,
            "isb_usrdeliv": 2,
        },
    )
    report = audit_capture_coverage(
        stream,
        export_description=ExportDescription(
            "complete export, no filtering", limited=False
        ),
    )

    interface = report.sections[0].interfaces[0]
    assert interface.limitations == []
    assert interface.undeclared == []
    assert interface.unexplained == []
    assert interface.conclusion == FULL_COVERAGE
    assert report.sections[0].conclusion == FULL_COVERAGE
    assert report.conclusion == FULL_COVERAGE


def test_unknown_filter_type_is_unexplainable():
    stream = build_capture(
        if_options={"if_filter": [(7, b"some-proprietary-filter")]},
        isb_options={"isb_ifrecv": 2, "isb_usrdeliv": 2},
    )
    report = audit_capture_coverage(
        stream,
        export_description=ExportDescription("no filtering", limited=False),
    )

    interface = report.sections[0].interfaces[0]
    assert interface.conclusion == INSUFFICIENT_EVIDENCE
    assert interface.limitations == []
    assert [item.setting for item in interface.unexplained] == ["if_filter"]
    assert "unknown filter type code 7" in interface.unexplained[0].detail


def test_bpf_bytecode_filter_is_a_source_limitation():
    stream = build_capture(
        if_options={"if_filter": [(1, b"\x06\x00\x00\x00\xff\xff\x00\x00")]},
        isb_options={"isb_ifrecv": 2, "isb_usrdeliv": 2},
    )
    report = audit_capture_coverage(
        stream,
        export_description=ExportDescription("no filtering", limited=False),
    )

    interface = report.sections[0].interfaces[0]
    assert interface.conclusion == LIMITED_COVERAGE
    assert len(interface.limitations) == 1
    assert interface.limitations[0].origin == ORIGIN_CAPTURE_SOURCE
    assert "BPF bytecode" in interface.limitations[0].detail


def test_unknown_interface_option_is_unexplainable():
    # Hand-craft a capture whose interface carries an option code this
    # library does not know about.
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1)
    shb += struct.pack("<I", 28)
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_body += struct.pack("<HH", 42, 4) + b"test"  # unknown option
    idb_body += struct.pack("<I", 0)  # opt_endofopt
    idb = struct.pack("<II", 0x00000001, 12 + len(idb_body)) + idb_body
    idb += struct.pack("<I", 12 + len(idb_body))

    report = audit_capture_coverage(io.BytesIO(shb + idb))

    interface = report.sections[0].interfaces[0]
    assert interface.conclusion == INSUFFICIENT_EVIDENCE
    assert [item.setting for item in interface.unexplained] == ["if_option_42"]


def test_inconsistent_statistics_are_unexplainable():
    stream = build_capture(
        if_options={"if_filter": [(0, b"")]},
        isb_options={"isb_ifrecv": 10, "isb_filteraccept": 42},
    )
    report = audit_capture_coverage(
        stream,
        export_description=ExportDescription("no filtering", limited=False),
    )

    interface = report.sections[0].interfaces[0]
    assert interface.conclusion == INSUFFICIENT_EVIDENCE
    assert [item.setting for item in interface.unexplained] == [
        "isb_filteraccept"
    ]


def test_conclusions_are_stored_per_section_and_interface():
    stream = io.BytesIO()

    # Section 0: source-limited interface.
    shb1 = blocks.SectionHeader()
    shb1.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={"if_filter": [(0, b"udp")]},
    )
    writer = FileWriter(stream, shb1)
    writer.write_block(
        shb1.new_member(
            blocks.InterfaceStatistics,
            interface_id=0,
            options={"isb_ifrecv": 5, "isb_usrdeliv": 5},
        )
    )

    # Section 1: interface with no declarations at all.
    shb2 = blocks.SectionHeader()
    shb2.new_member(
        blocks.InterfaceDescription, link_type=1, snaplen=65535
    )
    writer.write_block(shb2)

    stream.seek(0)
    report = audit_capture_coverage(
        stream,
        export_description=ExportDescription(
            "exported unfiltered", limited=False
        ),
    )

    assert len(report.sections) == 2
    assert report.sections[0].interfaces[0].conclusion == LIMITED_COVERAGE
    assert report.sections[0].conclusion == LIMITED_COVERAGE
    assert report.sections[1].interfaces[0].conclusion == INSUFFICIENT_EVIDENCE
    assert report.sections[1].conclusion == INSUFFICIENT_EVIDENCE
    assert report.conclusion == LIMITED_COVERAGE


def test_export_description_can_be_mapped_per_interface():
    stream = io.BytesIO()
    shb = blocks.SectionHeader()
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={"if_filter": [(0, b"")]},
    )
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={"if_filter": [(0, b"")]},
    )
    writer = FileWriter(stream, shb)
    for interface_id in (0, 1):
        writer.write_block(
            shb.new_member(
                blocks.InterfaceStatistics,
                interface_id=interface_id,
                options={"isb_ifrecv": 1, "isb_usrdeliv": 1},
            )
        )

    stream.seek(0)
    report = audit_capture_coverage(
        stream,
        export_description={
            0: ExportDescription("no filtering", limited=False),
            1: "filtered to host 192.0.2.1 at export time",
        },
    )

    section = report.sections[0]
    assert section.interfaces[0].conclusion == FULL_COVERAGE
    assert section.interfaces[1].conclusion == LIMITED_COVERAGE
    assert section.interfaces[1].limitations[0].origin == ORIGIN_EXPORT
    assert section.conclusion == LIMITED_COVERAGE


def test_real_capture_without_declarations_is_insufficient_evidence():
    # test002.ntar: section header + bare interface description, no
    # options, no statistics, no export description.
    with open("test_data/test002.ntar", "rb") as fp:
        report = audit_capture_coverage(fp)

    assert report.conclusion == INSUFFICIENT_EVIDENCE
    interface = report.sections[0].interfaces[0]
    assert interface.conclusion == INSUFFICIENT_EVIDENCE
    assert interface.limitations == []
    assert [item.aspect for item in interface.undeclared] == [
        "capture_filter",
        "sampling_statistics",
        "export_filtering",
    ]
