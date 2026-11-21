"""
Synthetic two-tap pcapng capture builder for forensic pairing reviews.

The generated data is fully deterministic and covers the cases an
investigation must be able to distinguish:

* identical frames seen on both sides (clean pair);
* truncation on either side and on both sides at different offsets;
* two distinct original frames sharing an identical header/prefix
  (duplicate prefix that must NOT be auto-paired);
* frames whose payloads diverge after a common prefix;
* a frame observed by one tap only;
* a same-header/different-payload pair that must stay undecided.

Different interfaces (Ethernet vs raw IP, different snap lengths and
timestamp resolutions) are used on purpose, mirroring real collections
where the two capture points were configured independently.
"""

import io

import pcapng.blocks as blocks
from pcapng import FileWriter
from pcapng.constants.link_types import LINKTYPE_ETHERNET, LINKTYPE_RAW
from pcapng.utils import pack_timestamp_resolution

# Fixed 5-tuple-ish headers so the "identical header" trap is realistic.
ETH_DST = b"\x02\x00\x00\x00\x00\x01"
ETH_SRC = b"\x02\x00\x00\x00\x00\x02"
IPV4_HEADER = (
    b"\x45\x00\x00\x64\x12\x34\x00\x00\x40\x06"
    b"\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
)
TCP_HEADER = b"\x04\xd2\x00\x50\x00\x00\x00\x01\x00\x00\x00\x02\x50\x18\x01\x00"


def ethernet_frame(payload, ethertype=0x0800):
    """Build a minimal Ethernet/IPv4-looking frame carrying ``payload``."""
    return ETH_DST + ETH_SRC + bytes(
        (ethertype >> 8, ethertype & 0xFF)
    ) + IPV4_HEADER + TCP_HEADER + payload


def raw_ip_frame(payload):
    """Build the same L3+ bytes without an Ethernet header (LINKTYPE_RAW)."""
    return IPV4_HEADER + TCP_HEADER + payload


def _timestamp_parts(timestamp_seconds, resolution):
    units = int(round(timestamp_seconds / resolution))
    return units >> 32, units & 0xFFFFFFFF


def write_capture(path, link_type, snaplen, tsresol_exponent, ts_base,
                  packets):
    """Write a pcapng file.

    :param packets: iterable of ``(timestamp_seconds, frame_bytes,
        original_len)`` tuples.  ``original_len`` may exceed the frame
        length to model snap-length truncation.
    """
    shb = blocks.SectionHeader(endianness="<")
    idb = shb.new_member(
        blocks.InterfaceDescription,
        link_type=link_type,
        snaplen=snaplen,
        options={"if_tsresol": pack_timestamp_resolution(10, tsresol_exponent)},
    )
    resolution = 10 ** (-tsresol_exponent)
    with open(path, "wb") as stream:
        writer = FileWriter(stream, shb)
        for timestamp, frame, original_len in packets:
            high, low = _timestamp_parts(timestamp - ts_base, resolution)
            epb = shb.new_member(blocks.EnhancedPacket)
            epb.interface_id = idb.interface_id
            epb.timestamp_high = high
            epb.timestamp_low = low
            epb.packet_data = bytes(frame)
            epb.packet_len = int(original_len)
            writer.write_block(epb)


def build_capture_pair(left_path, right_path, base_time=1_700_000_000.0):
    """Create two synthetic captures of the same original frames.

    Returns a dictionary describing every injected ground-truth frame so
    tests can assert against it.
    """
    # Original L7 payloads of the frames "on the wire".
    payload_p1 = b"ORIGINAL-BYTES-001:" + b"A" * 120
    payload_p2 = b"ORIGINAL-BYTES-002:" + b"B" * 120
    payload_p3 = b"ORIGINAL-BYTES-003:" + b"C" * 120
    payload_p4 = b"ORIGINAL-BYTES-004:" + b"D" * 120
    payload_p5 = b"ORIGINAL-BYTES-005:" + b"E" * 120
    payload_p6 = b"ORIGINAL-BYTES-006:" + b"F" * 120

    originals = [payload_p1, payload_p2, payload_p3,
                 payload_p4, payload_p5, payload_p6]

    left_full = [ethernet_frame(p) for p in originals]
    right_full = [raw_ip_frame(p) for p in originals]

    # Left tap (Ethernet, snap 120).  Each tuple is
    # (time offset, captured frame, declared on-the-wire length).
    left_specs = [
        (0.000, left_full[0], len(left_full[0])),           # clean pair
        (0.010, left_full[1][:120], len(left_full[1])),     # left truncated
        (0.020, left_full[2], len(left_full[2])),           # right truncated
        (0.030, left_full[3][:120], len(left_full[3])),     # both truncated
        (0.040, left_full[4], len(left_full[4])),           # duplicate prefix
        (0.050, left_full[5], len(left_full[5])),           # divergence pair
        (0.090, left_full[0], len(left_full[0])),           # left-only frame
    ]

    # Right tap (raw IP, snap 110).  original_len always refers to the
    # actual raw-IP frame length, never the Ethernet one.
    # The spurious frame differs from left p5 only past byte 100:
    # every byte this tap keeps is byte-identical to that frame.
    spurious = raw_ip_frame(
        b'ORIGINAL-BYTES-005:' + b'E' * 100 + b'X' * 20
    )
    diverging_frame = (
        IPV4_HEADER + TCP_HEADER + b'ORIGINAL-BYTES-006:' + b'Z' * 20
    )
    right_specs = [
        (0.002, right_full[0], len(right_full[0])),         # clean pair
        (0.012, right_full[1], len(right_full[1])),         # full on right
        (0.022, right_full[2][:90], len(right_full[2])),    # right truncated
        (0.032, right_full[3][:100], len(right_full[3])),   # both truncated
        # Two different original frames (left p5 and the spurious one)
        # share an identical captured prefix because the tap snapped both
        # before their tails diverge.  Both stay undecided: duplicate
        # prefixes are never auto-paired even when headers match.
        (0.042, right_full[4][:90], len(right_full[4])),
        (0.041, spurious[:100], len(spurious)),
        # Same header and same 19-byte marker as left p6, then a
        # genuinely different payload byte that BOTH taps retain.
        (0.052, diverging_frame, len(diverging_frame)),
        # No right-side packet near 0.090: the last left frame is
        # one-sided and must surface as NO_CANDIDATE.
    ]

    write_capture(
        left_path,
        link_type=LINKTYPE_ETHERNET,
        snaplen=120,
        tsresol_exponent=6,
        ts_base=base_time,
        packets=[(base_time + ts, frame, orig)
                 for ts, frame, orig in left_specs],
    )
    write_capture(
        right_path,
        link_type=LINKTYPE_RAW,
        snaplen=110,
        tsresol_exponent=6,
        ts_base=base_time,
        packets=[(base_time + ts, frame, orig)
                 for ts, frame, orig in right_specs],
    )

    return {
        "originals": originals,
        "clock_offset": 0.002,
        "left_specs": left_specs,
        "right_specs": right_specs,
    }
