# -*- coding: utf-8 -*-
"""Truncation-aware offline interpretation of pcap savefiles.

A capture taken with a small snaplen stores only the first bytes of each
frame while the record header keeps the frame's original length.  Feeding
such a savefile to a protocol stack makes TCP application data look empty
even when the sender did transmit a payload, and a reviewer cannot tell
the difference from the decoded packets alone.

This module keeps the per-layer headers and the lengths each record
claims, and classifies the TCP payload of every packet so downstream
tools can tell apart:

- PAYLOAD_EMPTY: the claimed lengths prove there was no payload;
- PAYLOAD_PRESENT: the claimed payload bytes are fully captured;
- PAYLOAD_TRUNCATED: the capture boundary cut the frame, so it
  cannot be proven whether payload bytes followed;
- PAYLOAD_LENGTH_MISMATCH: the claimed lengths contradict each
  other or the captured bytes.
"""
from __future__ import print_function
from __future__ import absolute_import

import struct

from . import pcap

PAYLOAD_EMPTY = 'empty'
PAYLOAD_PRESENT = 'present'
PAYLOAD_TRUNCATED = 'truncated'
PAYLOAD_LENGTH_MISMATCH = 'length_mismatch'

ETH_HDR_LEN = 14
ETH_TYPE_IP = 0x0800
ETH_TYPE_IPV6 = 0x86dd
ETH_TYPE_VLAN = (0x8100, 0x88a8)  # 802.1Q, 802.1ad

IP_HDR_MIN_LEN = 20
IP6_HDR_LEN = 40
IP_PROTO_TCP = 6

TCP_HDR_MIN_LEN = 20


class LayerInfo(object):
    """Header bytes and claimed on-wire length of one decoded layer.

    Attributes:
        name: layer name, e.g. 'ethernet', 'ipv4', 'tcp'
        header: captured header bytes of this layer, including options
        claimed_length: total bytes this layer claims to occupy on the
            wire including its header, or None if the layer carries no
            such length field
    """
    def __init__(self, name, header, claimed_length=None):
        self.name = name
        self.header = header
        self.claimed_length = claimed_length

    def __repr__(self):
        return 'LayerInfo(name=%r, claimed_length=%r, header_len=%d)' % (
            self.name, self.claimed_length, len(self.header))


class PacketReport(object):
    """Interpretation of a single captured record.

    Attributes:
        ts: record timestamp
        caplen: bytes stored for this record in the savefile
        wirelen: bytes the record claims were on the wire
        layers: list of LayerInfo, one per decoded layer
        payload: captured TCP payload bytes; may be only a prefix of the
            real payload when the capture was truncated
        payload_claimed: TCP payload bytes the headers claim, or None
            when the headers could not be decoded
        status: one of the PAYLOAD_* values, or None for non-TCP packets
        error: human readable detail for PAYLOAD_LENGTH_MISMATCH and for
            packets that could not be decoded
    """
    def __init__(self, ts, caplen, wirelen):
        self.ts = ts
        self.caplen = caplen
        self.wirelen = wirelen
        self.layers = []
        self.payload = b''
        self.payload_claimed = None
        self.status = None
        self.error = None

    @property
    def capture_truncated(self):
        """True when the record claims more bytes on the wire than stored."""
        return self.caplen < self.wirelen

    def __repr__(self):
        return 'PacketReport(status=%r, payload_claimed=%r, payload_len=%d, caplen=%d, wirelen=%d)' % (
            self.status, self.payload_claimed, len(self.payload), self.caplen, self.wirelen)


def interpret_record(ts, buf, caplen, wirelen, linktype=pcap.DLT_EN10MB):
    """Interpret one captured record and classify its TCP payload.

    Args:
        ts: record timestamp
        buf: captured bytes of the record
        caplen: bytes the record header says were stored
        wirelen: bytes the record header says were on the wire
        linktype: pcap datalink type; Ethernet and raw IPv4/IPv6 are
            supported

    Returns:
        PacketReport
    """
    report = PacketReport(ts, caplen, wirelen)

    if caplen > wirelen:
        report.status = PAYLOAD_LENGTH_MISMATCH
        report.error = 'record caplen %d exceeds claimed wire length %d' % (caplen, wirelen)
        return report

    captured = bytes(buf[:caplen])
    # snaplen cut or a savefile that ends mid-record
    truncated = len(captured) < wirelen

    def out_of_bytes(detail):
        # Ran off the end of the captured bytes: only a truncated capture
        # leaves the question open; a complete record that ends early
        # contradicts its own headers.
        if truncated:
            report.status = PAYLOAD_TRUNCATED
        else:
            report.status = PAYLOAD_LENGTH_MISMATCH
            report.error = detail

    def mismatch(detail):
        report.status = PAYLOAD_LENGTH_MISMATCH
        report.error = detail

    off = 0
    if linktype == pcap.DLT_EN10MB:
        if len(captured) < off + ETH_HDR_LEN:
            out_of_bytes('frame ends inside the ethernet header')
            return report
        ethertype = struct.unpack('>H', captured[off + 12:off + 14])[0]
        report.layers.append(LayerInfo('ethernet', captured[off:off + ETH_HDR_LEN]))
        off += ETH_HDR_LEN
        while ethertype in ETH_TYPE_VLAN:
            if len(captured) < off + 4:
                out_of_bytes('frame ends inside a vlan tag')
                return report
            ethertype = struct.unpack('>H', captured[off + 2:off + 4])[0]
            report.layers.append(LayerInfo('vlan', captured[off:off + 4]))
            off += 4
    elif linktype in (pcap.DLT_RAW, pcap.DLT_IPV4):
        ethertype = ETH_TYPE_IP
    elif linktype == pcap.DLT_IPV6:
        ethertype = ETH_TYPE_IPV6
    else:
        report.error = 'unsupported linktype %d' % linktype
        return report

    if ethertype == ETH_TYPE_IP:
        if len(captured) < off + IP_HDR_MIN_LEN:
            out_of_bytes('frame ends inside the ipv4 header')
            return report
        ihl = (captured[off] & 0x0f) << 2
        if ihl < IP_HDR_MIN_LEN:
            mismatch('ipv4 header length %d below minimum' % ihl)
            return report
        if len(captured) < off + ihl:
            out_of_bytes('frame ends inside the ipv4 options')
            return report
        total_len = struct.unpack('>H', captured[off + 2:off + 4])[0]
        proto = captured[off + 9]
        report.layers.append(LayerInfo('ipv4', captured[off:off + ihl], total_len))
        if total_len < ihl:
            mismatch('ipv4 total length %d below header length %d' % (total_len, ihl))
            return report
        if len(captured) - off < total_len and not truncated:
            mismatch('ipv4 claims %d bytes but the complete record holds %d'
                     % (total_len, len(captured) - off))
            return report
        segment_claimed = total_len - ihl
        off += ihl
    elif ethertype == ETH_TYPE_IPV6:
        if len(captured) < off + IP6_HDR_LEN:
            out_of_bytes('frame ends inside the ipv6 header')
            return report
        plen = struct.unpack('>H', captured[off + 4:off + 6])[0]
        nxt = captured[off + 6]
        report.layers.append(LayerInfo('ipv6', captured[off:off + IP6_HDR_LEN], IP6_HDR_LEN + plen))
        if len(captured) - off < IP6_HDR_LEN + plen and not truncated:
            mismatch('ipv6 claims %d payload bytes but the complete record holds %d'
                     % (plen, len(captured) - off - IP6_HDR_LEN))
            return report
        proto = nxt  # no extension header support; TCP must follow directly
        segment_claimed = plen
        off += IP6_HDR_LEN
    else:
        report.error = 'unsupported ethertype 0x%04x' % ethertype
        return report

    if proto != IP_PROTO_TCP:
        # not TCP; layers and claimed lengths are still preserved above
        return report

    if len(captured) < off + TCP_HDR_MIN_LEN:
        out_of_bytes('frame ends inside the tcp header')
        return report
    tcp_hl = (captured[off + 12] >> 4) << 2
    if tcp_hl < TCP_HDR_MIN_LEN:
        mismatch('tcp header length %d below minimum' % tcp_hl)
        return report
    if len(captured) < off + tcp_hl:
        out_of_bytes('frame ends inside the tcp options')
        return report
    report.layers.append(LayerInfo('tcp', captured[off:off + tcp_hl], segment_claimed))
    if tcp_hl > segment_claimed:
        mismatch('tcp header length %d exceeds claimed segment length %d' % (tcp_hl, segment_claimed))
        return report

    report.payload_claimed = segment_claimed - tcp_hl
    report.payload = captured[off + tcp_hl:off + tcp_hl + report.payload_claimed]

    if report.payload_claimed == 0:
        # the headers claim a header-only segment; once the whole claimed
        # segment is captured this is provably empty regardless of any
        # truncation beyond it
        if len(captured) - off >= segment_claimed:
            report.status = PAYLOAD_EMPTY
        else:
            out_of_bytes('frame ends inside the claimed tcp segment')
    elif len(report.payload) >= report.payload_claimed:
        report.status = PAYLOAD_PRESENT
    else:
        out_of_bytes('capture holds %d of %d claimed payload bytes'
                     % (len(report.payload), report.payload_claimed))
    return report


class Interpreter(object):
    """Iterate a pcap savefile yielding a PacketReport per record.

    Wraps pcap.Reader and keeps each record's claimed lengths so that
    snaplen-truncated captures are reported as PAYLOAD_TRUNCATED instead
    of showing up with seemingly empty TCP application data.
    """
    def __init__(self, fileobj):
        self._reader = pcap.Reader(fileobj)
        self.linktype = self._reader.datalink()
        self.snaplen = self._reader.snaplen

    def __iter__(self):
        for ts, buf, hdr in self._reader.iter_with_hdr():
            yield interpret_record(ts, buf, hdr.caplen, hdr.len, self.linktype)


################################################################################
#                                    TESTS                                     #
################################################################################

def _build_frame(payload):
    from .ethernet import Ethernet
    from .ip import IP
    from .tcp import TCP, TH_ACK, TH_PUSH

    tcp = TCP(sport=49152, dport=80, seq=1, ack=1, flags=TH_ACK | TH_PUSH, data=payload)
    ip = IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=IP_PROTO_TCP, data=tcp)
    eth = Ethernet(src=b'\x00\x01\x02\x03\x04\x05', dst=b'\x00\x06\x07\x08\x09\x0a',
                   type=ETH_TYPE_IP, data=ip)
    return bytes(eth)


def _savefile(records):
    """Build a little-endian pcap savefile from (buf, wirelen) records."""
    from .compat import BytesIO

    fobj = BytesIO()
    fobj.write(bytes(pcap.LEFileHdr(snaplen=65535, linktype=pcap.DLT_EN10MB,
                                    magic=pcap.TCPDUMP_MAGIC)))
    for buf, wirelen in records:
        fobj.write(bytes(pcap.LEPktHdr(tv_sec=1, tv_usec=0, caplen=len(buf), len=wirelen)))
        fobj.write(buf)
    fobj.seek(0)
    return fobj


def _interpret(records):
    return list(Interpreter(_savefile(records)))


def test_full_frame_payload_present():
    frame = _build_frame(b'GET / HTTP/1.0\r\n\r\n')
    (report,) = _interpret([(frame, len(frame))])

    assert report.status == PAYLOAD_PRESENT
    assert report.payload == b'GET / HTTP/1.0\r\n\r\n'
    assert report.payload_claimed == len(b'GET / HTTP/1.0\r\n\r\n')
    assert not report.capture_truncated
    # per-layer headers and claimed lengths are preserved
    assert [layer.name for layer in report.layers] == ['ethernet', 'ipv4', 'tcp']
    assert report.layers[0].header == frame[:14]
    assert report.layers[1].claimed_length == len(frame) - 14
    assert report.layers[2].claimed_length == len(frame) - 14 - 20
    assert report.layers[2].header == frame[34:54]


def test_truncated_copy_is_not_empty():
    # acceptance: a full frame and its snaplen-truncated copy must not both
    # read as empty; the copy that cannot prove what followed the TCP
    # header must not be registered as an empty payload
    payload = b'x' * 100
    frame = _build_frame(payload)
    cut = 14 + 20 + 20  # ethernet + ipv4 + tcp headers, payload fully cut
    truncated = frame[:cut]

    (full_report,) = _interpret([(frame, len(frame))])
    assert full_report.status == PAYLOAD_PRESENT

    (copy_report,) = _interpret([(truncated, len(frame))])
    assert copy_report.capture_truncated
    assert copy_report.payload == b''
    assert copy_report.payload_claimed == len(payload)
    assert copy_report.status == PAYLOAD_TRUNCATED
    assert copy_report.status != PAYLOAD_EMPTY


def test_truncated_mid_payload():
    payload = b'y' * 100
    frame = _build_frame(payload)
    cut = 14 + 20 + 20 + 10  # only a prefix of the payload captured
    truncated = frame[:cut]

    (report,) = _interpret([(truncated, len(frame))])
    assert report.status == PAYLOAD_TRUNCATED
    assert report.payload == payload[:10]
    assert report.payload_claimed == len(payload)


def test_empty_payload_full_capture():
    frame = _build_frame(b'')
    (report,) = _interpret([(frame, len(frame))])

    assert report.status == PAYLOAD_EMPTY
    assert report.payload == b''
    assert report.payload_claimed == 0


def test_empty_payload_provable_despite_truncation():
    # a header-only segment stays provably empty when the capture cut
    # happens beyond the claimed segment end (e.g. trailing padding)
    frame = _build_frame(b'')
    (report,) = _interpret([(frame, len(frame) + 10)])

    assert report.capture_truncated
    assert report.status == PAYLOAD_EMPTY


def test_length_mismatch_complete_record():
    # the record claims to be complete but the captured bytes do not hold
    # what the ipv4 header claims: length information is inconsistent
    frame = _build_frame(b'z' * 100)
    cut = 14 + 20 + 20
    truncated = frame[:cut]

    (report,) = _interpret([(truncated, len(truncated))])
    assert not report.capture_truncated
    assert report.status == PAYLOAD_LENGTH_MISMATCH
    assert report.error


def test_record_caplen_exceeds_wirelen():
    frame = _build_frame(b'')
    report = interpret_record(0.0, frame, caplen=len(frame), wirelen=len(frame) - 1)

    assert report.status == PAYLOAD_LENGTH_MISMATCH
    assert 'caplen' in report.error


def test_truncated_inside_tcp_header():
    frame = _build_frame(b'x' * 10)
    cut = 14 + 20 + 10  # capture ends inside the tcp header
    truncated = frame[:cut]

    (report,) = _interpret([(truncated, len(frame))])
    assert report.status == PAYLOAD_TRUNCATED
    assert report.payload_claimed is None
    assert [layer.name for layer in report.layers] == ['ethernet', 'ipv4']


def test_unsupported_linktype():
    report = interpret_record(0.0, b'\x00' * 60, caplen=60, wirelen=60, linktype=pcap.DLT_FDDI)
    assert report.status is None
    assert 'unsupported linktype' in report.error
