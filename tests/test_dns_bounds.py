# -*- coding: utf-8 -*-
"""Bounds and budget tests for DNS name/record parsing."""
from __future__ import absolute_import

import os
import struct

import pytest

import dpkt
from dpkt.dns import (
    DNS,
    DNSLabelError,
    DNS_MAX_POINTER_HOPS,
    DNS_MAX_SECTION_RECORDS,
    DNS_A,
    DNS_IN,
    DNS_OPT,
    define_testdata,
    unpack_name,
)


def hdr(qd=0, an=0, ns=0, ar=0, op=0x8180):
    return struct.pack('>HHHHHH', 0x1234, op, qd, an, ns, ar)


def question(name=b'\x07example\x03com\x00', qtype=DNS_A, qcls=DNS_IN):
    return name + struct.pack('>HH', qtype, qcls)


def answer(name=b'\xc0\x0c', rdata=b'\x01\x02\x03\x04', rtype=DNS_A, ttl=60):
    return name + struct.pack('>HHIH', rtype, DNS_IN, ttl, len(rdata)) + rdata


def test_self_pointer_raises_with_offset():
    # owner name is a pointer to itself
    buf = hdr(qd=1) + b'\xc0\x0c' + struct.pack('>HH', DNS_A, DNS_IN)
    with pytest.raises(dpkt.UnpackError, match=r'offset 12 \(target 12\)'):
        DNS(buf)


def test_forward_pointer_raises_with_offset():
    # pointer targets an offset beyond the current read position
    buf = hdr(qd=1) + b'\xc0\x40' + struct.pack('>HH', DNS_A, DNS_IN)
    with pytest.raises(dpkt.UnpackError, match=r'offset 12 \(target 64\)'):
        DNS(buf)


def test_unpack_name_forward_pointer():
    with pytest.raises(dpkt.UnpackError, match='Invalid label compression pointer'):
        unpack_name(b'\xc0\x05', 0)


def test_pointer_loop_consumes_fixed_steps():
    # name at 12 is "a" followed by a pointer back to 12: an infinite loop
    # without a hop budget
    buf = hdr(qd=1) + b'\x01a\xc0\x0c' + struct.pack('>HH', DNS_A, DNS_IN)
    with pytest.raises(dpkt.UnpackError, match='Too many label compression pointers'):
        DNS(buf)


def test_pointer_hop_budget_is_fixed():
    # a two-offset bounce must terminate after DNS_MAX_POINTER_HOPS hops
    buf = b'\x01a\xc0\x00' + b'\x00' * 64
    with pytest.raises(dpkt.UnpackError, match='Too many'):
        unpack_name(buf, 0)


def test_legit_compression_chain_unchanged():
    buf = define_testdata().ptr_resp
    dns = DNS(buf)
    assert dns.qd[0].name == '1.1.211.141.in-addr.arpa'
    assert dns.an[0].ptrname == 'default.v-umce-ifs.umnet.umich.edu'
    assert dns.ns[0].nsname == 'shabby.ifs.umich.edu'
    assert dns.ns[2].nsname == 'dns2.itd.umich.edu'
    assert bytes(dns) == buf


def test_name_length_budget():
    # 16 labels of 16 bytes each exceed the 255 octet name budget
    name = b'\x10abcdef0123456789' * 16 + b'\x00'
    buf = hdr(qd=1) + name + struct.pack('>HH', DNS_A, DNS_IN)
    with pytest.raises(dpkt.UnpackError, match='name longer than 255 bytes'):
        DNS(buf)


def test_truncated_name_reports_offset():
    # label claims 5 bytes, only 2 are present
    buf = hdr(qd=1) + b'\x05ab'
    with pytest.raises(dpkt.NeedData, match='truncated name at offset 18'):
        DNS(buf)


def test_truncated_answers_keep_safe_prefix():
    q = question()
    ans1 = answer()
    # second answer is cut off in the middle of the RR header
    partial = b'\xc0\x0c' + struct.pack('>HHI', DNS_A, DNS_IN, 60)
    buf = hdr(qd=1, an=3) + q + ans1 + partial

    dns = DNS(buf)
    assert len(dns.qd) == 1
    assert dns.qd[0].name == 'example.com'
    assert len(dns.an) == 1
    assert dns.an[0].name == 'example.com'
    assert dns.an[0].ip == b'\x01\x02\x03\x04'
    # leftover bytes are exposed at their original offset in buf
    assert dns.data == partial
    assert len(buf) - len(dns.data) == len(hdr(qd=1, an=3)) + len(q) + len(ans1)


def test_truncated_rdata_keeps_safe_prefix():
    q = question()
    ans1 = answer()
    # rdlen claims far more than the buffer holds
    bad = b'\xc0\x0c' + struct.pack('>HHIH', DNS_A, DNS_IN, 60, 0xFFFF) + b'\x01\x02'
    buf = hdr(qd=1, an=2) + q + ans1 + bad

    dns = DNS(buf)
    assert len(dns.qd) == 1
    assert len(dns.an) == 1
    assert dns.data == bad


def test_huge_answer_count_stops_at_buffer_end():
    # header advertises thousands of answers, buffer holds two
    buf = hdr(qd=1, an=2000) + question() + answer() + answer(b'\xc0\x0c', b'\x05\x06\x07\x08')
    dns = DNS(buf)
    assert len(dns.qd) == 1
    assert len(dns.an) == 2
    assert dns.an[1].ip == b'\x05\x06\x07\x08'
    assert dns.data == b''


def test_answer_count_capped():
    count = DNS_MAX_SECTION_RECORDS + 44
    buf = hdr(qd=1, an=count) + question() + answer() * count
    dns = DNS(buf)
    assert len(dns.an) == DNS_MAX_SECTION_RECORDS
    assert all(rr.ip == b'\x01\x02\x03\x04' for rr in dns.an)


def test_nonminimal_label_keeps_safe_prefix():
    q = question()
    # 0x40 sets the reserved 01 label form: non-minimal/invalid encoding
    bad = b'\x40\x01' + struct.pack('>HHIH', DNS_A, DNS_IN, 60, 4) + b'\x01\x02\x03\x04'
    buf = hdr(qd=1, an=1) + q + bad

    dns = DNS(buf)
    assert len(dns.qd) == 1
    assert dns.an == []
    assert dns.data == bad


def test_nonminimal_label_raises_without_prefix():
    buf = hdr(qd=1) + b'\x7f' + b'a' * 20
    with pytest.raises(DNSLabelError, match='Invalid label length 7f'):
        DNS(buf)


def test_pointer_violation_raises_even_with_prefix():
    # a forward pointer in the answer section must still fail loudly
    q = question()
    bad = b'\xc0\x7f' + struct.pack('>HHIH', DNS_A, DNS_IN, 60, 4) + b'\x01\x02\x03\x04'
    buf = hdr(qd=1, an=1) + q + bad
    with pytest.raises(dpkt.UnpackError, match='Invalid label compression pointer'):
        DNS(buf)


def test_edns_opt_preserved():
    opt = b'\x00' + struct.pack('>HHIH', DNS_OPT, 4096, 0, 0)
    buf = hdr(qd=1, ar=1) + question() + opt
    dns = DNS(buf)
    assert len(dns.ar) == 1
    assert dns.ar[0].type == DNS_OPT
    assert dns.ar[0].cls == 4096
    assert dns.ar[0].rdata == b''
    assert bytes(dns) == buf


def test_edns_opt_response_sample():
    buf = define_testdata().a_resp
    dns = DNS(buf)
    assert dns.qd[0].name == 'google.com'
    assert dns.an[0].ip == b'\xd8:\xce.'
    assert dns.ar[0].type == DNS_OPT
    assert bytes(dns) == buf


def _dns_payloads(pcap_path):
    """Yield UDP/53 payloads from a pcap, tolerating a truncated capture tail."""
    with open(pcap_path, 'rb') as f:
        reader = dpkt.pcap.Reader(f)
        try:
            for _, pkt in reader:
                eth = dpkt.ethernet.Ethernet(pkt)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                udp = ip.data
                if udp.sport == 53 or udp.dport == 53:
                    yield udp.data
        except dpkt.NeedData:
            pass


def test_examples_data_smoke():
    data_dir = os.path.join(os.path.dirname(__file__), os.pardir, 'examples', 'data')
    seen = 0
    for name in ('dns_icmp.pcap', 'truncated_dns.pcap', 'truncated_dns_2.pcap'):
        for payload in _dns_payloads(os.path.join(data_dir, name)):
            dns = DNS(payload)  # must terminate, never hang or raise
            seen += 1
            assert len(dns.qd) >= 1
    assert seen > 0


def test_examples_truncated_pcaps_keep_prefix():
    data_dir = os.path.join(os.path.dirname(__file__), os.pardir, 'examples', 'data')
    for name in ('truncated_dns.pcap', 'truncated_dns_2.pcap'):
        payloads = list(_dns_payloads(os.path.join(data_dir, name)))
        assert payloads
        dns = DNS(payloads[0])
        assert len(dns.qd) == 1
        # the capture is truncated, so the unparsed tail is preserved
        assert dns.data == payloads[0][len(payloads[0]) - len(dns.data):]
