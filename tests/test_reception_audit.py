import io

import pcapng.blocks as blocks
from pcapng import FileWriter
from pcapng.reception import audit_reception


def make_volume(timestamps=(), simple_packets=0):
    shb = blocks.SectionHeader(endianness="<")
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for timestamp in timestamps:
        raw = int(timestamp * 1_000_000)
        packet = shb.new_member(blocks.EnhancedPacket)
        packet.interface_id = 0
        packet.timestamp_high = raw >> 32
        packet.timestamp_low = raw & 0xFFFFFFFF
        packet.packet_data = b"packet"
        packet.packet_len = len(b"packet")
        writer.write_block(packet)
    for _ in range(simple_packets):
        packet = shb.new_member(blocks.SimplePacket, packet_data=b"simple")
        writer.write_block(packet)
    stream.seek(0)
    return stream


def takeovers():
    return [
        {"source": "a", "interface_id": 0, "start": 0, "end": 15, "group": "A"},
        {"source": "b", "interface_id": 0, "start": 15, "end": 30, "group": "B"},
    ]


def test_cross_group_bilateral_gaps_are_volume_order_independent():
    volume_a = make_volume([0, 10])
    volume_b = make_volume([20, 30])
    kwargs = dict(
        location="DC1",
        takeover_intervals=takeovers(),
        flush_times={"a": 10, "b": 30},
    )

    first = audit_reception(volumes=[("a", volume_a), ("b", volume_b)], **kwargs)
    second = audit_reception(
        volumes=[("b", make_volume([20, 30])), ("a", make_volume([0, 10]))],
        location="DC1",
        takeover_intervals=list(reversed(takeovers())),
        flush_times={"b": 30, "a": 10},
    )

    expected = [(10, 15), (15, 20)]
    assert first.bilateral_gaps == expected
    assert second.bilateral_gaps == expected
    assert first.bilateral_gaps == second.bilateral_gaps
    assert first.missing_handovers == second.missing_handovers
    assert first.early_handovers == [(10, 15)]
    assert first.interfaces[0].interface_key == "a/s0/i0"
    assert first.interfaces[1].interface_key == "b/s0/i0"


def test_empty_manifest_window_is_separate_from_data_loss():
    volume_a = make_volume([0, 10])
    volume_b = make_volume([20, 30])
    report = audit_reception(
        volumes=[("a", volume_a), ("b", volume_b)],
        takeover_intervals=takeovers(),
        flush_times={"a": 10, "b": 30},
        empty_windows=[{"start": 12, "end": 13, "reason": "silent"}],
    )

    assert report.empty_windows == [(12, 13)]
    assert report.data_loss == [(10, 12), (13, 15), (15, 20)]
    assert (12, 13) not in report.data_loss


def test_packet_without_timestamp_keeps_volume_location():
    volume = make_volume([1], simple_packets=1)
    report = audit_reception(
        volumes=[("material-a", volume)],
        takeover_intervals=[{
            "source": "material-a", "interface_id": 0,
            "start": 0, "end": 2,
        }],
    )

    assert len(report.untimestamped_packets) == 1
    location = report.untimestamped_packets[0].location
    assert location.volume == "material-a"
    assert location.source == "material-a"
    assert location.interface_key == "material-a/s0/i0"
    assert isinstance(location.offset, int)
    assert location.block_index >= 1
