# $Id: tcp.py 42 2007-08-02 22:38:47Z jon.oberheide $
# -*- coding: utf-8 -*-
"""Transmission Control Protocol."""
from __future__ import print_function
from __future__ import absolute_import

from . import dpkt
from .compat import compat_ord

# TCP control flags
TH_FIN = 0x01  # end of data
TH_SYN = 0x02  # synchronize sequence numbers
TH_RST = 0x04  # reset connection
TH_PUSH = 0x08  # push
TH_ACK = 0x10  # acknowledgment number set
TH_URG = 0x20  # urgent pointer set
TH_ECE = 0x40  # ECN echo, RFC 3168
TH_CWR = 0x80  # congestion window reduced
TH_NS = 0x100  # nonce sum, RFC 3540

TCP_PORT_MAX = 65535  # maximum port
TCP_WIN_MAX = 65535  # maximum (unscaled) window


def tcp_flags_to_str(val):
    ff = []
    if val & TH_FIN:
        ff.append('FIN')
    if val & TH_SYN:
        ff.append('SYN')
    if val & TH_RST:
        ff.append('RST')
    if val & TH_PUSH:
        ff.append('PUSH')
    if val & TH_ACK:
        ff.append('ACK')
    if val & TH_URG:
        ff.append('URG')
    if val & TH_ECE:
        ff.append('ECE')
    if val & TH_CWR:
        ff.append('CWR')
    if val & TH_NS:
        ff.append('NS')
    return ','.join(ff)


class TCP(dpkt.Packet):
    """Transmission Control Protocol.

    The Transmission Control Protocol (TCP) is one of the main protocols of the Internet protocol suite.
    It originated in the initial network implementation in which it complemented the Internet Protocol (IP).

    Attributes:
        sport - source port
        dport - destination port
        seq   - sequence number
        ack   - acknowledgement number
        off   - data offset in 32-bit words
        flags - TCP flags
        win   - TCP window size
        sum   - checksum
        urp   - urgent pointer
        opts  - TCP options buffer; call parse_opts() to parse
        parsed_opts - parsed TCP options; see parse_opts()
        headers_truncated - True if the options were malformed or truncated
    """

    __hdr__ = (
        ('sport', 'H', 0xdead),
        ('dport', 'H', 0),
        ('seq', 'I', 0xdeadbeef),
        ('ack', 'I', 0),
        ('_off_flags', 'H', ((5 << 12) | TH_SYN)),
        ('win', 'H', TCP_WIN_MAX),
        ('sum', 'H', 0),
        ('urp', 'H', 0)
    )
    __bit_fields__ = {
        '_off_flags': (
            ('off', 4),    # 4 hi bits
            ('_rsv', 3),   # 3 bits reserved
            ('flags', 9),  # 9 lo bits
        )
    }
    __pprint_funcs__ = {
        'flags': tcp_flags_to_str,
        'sum': hex,  # display checksum in hex
    }
    opts = b''
    _parsed_opts = None
    _headers_truncated = False

    def __len__(self):
        return self.__hdr_len__ + len(self.opts) + len(self.data)

    def __bytes__(self):
        return self.pack_hdr() + bytes(self.opts) + bytes(self.data)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        ol = ((self._off_flags >> 12) << 2) - self.__hdr_len__
        if ol < 0:
            raise dpkt.UnpackError('invalid header length')
        hdr_len = self.__hdr_len__
        options_end = hdr_len + ol
        options_truncated = options_end > len(buf)
        self.opts = buf[hdr_len:options_end]
        self.data = b'' if options_truncated else buf[options_end:]

        self._parsed_opts = parse_opts(self.opts)
        self._headers_truncated = bool(
            options_truncated or self._parsed_opts.truncated)

    @property
    def parsed_opts(self):
        """Return parsed TCP options as a TCPOptions sequence."""
        if self._parsed_opts is None:
            self._parsed_opts = parse_opts(self.opts)
        return self._parsed_opts

    @property
    def headers_truncated(self):
        """True if the TCP options were truncated or malformed."""
        if self._parsed_opts is None:
            self._parsed_opts = parse_opts(self.opts)
            self._headers_truncated = self._parsed_opts.truncated
        return self._headers_truncated

    @property
    def opts_truncated(self):
        """Backwards-friendly alias for headers_truncated."""
        return self.headers_truncated

    def parse_opts(self, buf=None, dedupe=True):
        """Parse self.opts, or buf when supplied, using a bounded cursor."""
        parsed = parse_opts(self.opts if buf is None else buf, dedupe=dedupe)
        if buf is None:
            self._parsed_opts = parsed
            self._headers_truncated = parsed.truncated
        return parsed


# Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL = 0  # end of option list
TCP_OPT_NOP = 1  # no operation
TCP_OPT_MSS = 2  # maximum segment size
TCP_OPT_WSCALE = 3  # window scale factor, RFC 1072
TCP_OPT_SACKOK = 4  # SACK permitted, RFC 2018
TCP_OPT_SACK = 5  # SACK, RFC 2018
TCP_OPT_ECHO = 6  # echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY = 7  # echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP = 8  # timestamp, RFC 1323
TCP_OPT_POCONN = 9  # partial order conn, RFC 1693
TCP_OPT_POSVC = 10  # partial order service, RFC 1693
TCP_OPT_CC = 11  # connection count, RFC 1644
TCP_OPT_CCNEW = 12  # CC.NEW, RFC 1644
TCP_OPT_CCECHO = 13  # CC.ECHO, RFC 1644
TCP_OPT_ALTSUM = 14  # alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA = 15  # alt checksum data, RFC 1146
TCP_OPT_SKEETER = 16  # Skeeter
TCP_OPT_BUBBA = 17  # Bubba
TCP_OPT_TRAILSUM = 18  # trailer checksum
TCP_OPT_MD5 = 19  # MD5 signature, RFC 2385
TCP_OPT_SCPS = 20  # SCPS capabilities
TCP_OPT_SNACK = 21  # selective negative acks
TCP_OPT_REC = 22  # record boundaries
TCP_OPT_CORRUPT = 23  # corruption experienced
TCP_OPT_SNAP = 24  # SNAP
TCP_OPT_TCPCOMP = 26  # TCP compression filter
TCP_OPT_MAX = 27


class TCPOptions(list):
    """Parsed TCP options with bounded-parser status.

    The sequence keeps valid options in wire order.  ``first_by_kind`` gives
    first-valid-value semantics for options which must not be overwritten by
    later duplicates, notably SACK and timestamp.
    """

    def __init__(self, options=(), truncated=False, raw_options=None):
        list.__init__(self, options)
        self.truncated = bool(truncated)
        self.headers_truncated = self.truncated
        self.raw_options = list(options if raw_options is None else raw_options)

    @property
    def first_by_kind(self):
        """Map option kind to its first valid value."""
        first = {}
        for kind, data in self:
            if kind in first or not _option_value_is_valid(kind, data):
                continue
            first[kind] = data
        return first

    @property
    def options_by_kind(self):
        """Alias for first_by_kind."""
        return self.first_by_kind

    def get(self, kind, default=None):
        """Return the first valid value for kind, or default."""
        return self.first_by_kind.get(kind, default)


def _option_value_is_valid(kind, data):
    """Validate option values whose encodings have a fixed shape."""
    if kind == TCP_OPT_SACK:
        return len(data) >= 8 and len(data) % 8 == 0
    if kind == TCP_OPT_TIMESTAMP:
        return len(data) == 8
    return True


def parse_opts(buf, dedupe=True):
    """Parse a bounded TCP option buffer.

    Returns a TCPOptions sequence.  Each option is validated against the
    remaining bytes before its kind and length are consumed.  EOL terminates
    parsing and all following bytes must be zero padding.  NOP occupies one
    byte, unknown kinds are skipped by their declared length, and later SACK
    or timestamp duplicates do not replace the first valid value.

    On failure, options parsed before the malformed item are retained and
    ``truncated``/``headers_truncated`` are set.
    """
    opts = []
    raw_options = []
    seen_singletons = set()
    truncated = False
    pos = 0
    end = len(buf)

    while pos < end:
        remaining = end - pos
        kind = compat_ord(buf[pos])

        if kind == TCP_OPT_EOL:
            raw_options.append((kind, b''))
            opts.append((kind, b''))
            if any(compat_ord(b) != 0 for b in buf[pos + 1:]):
                truncated = True
            break

        if kind == TCP_OPT_NOP:
            raw_options.append((kind, b''))
            opts.append((kind, b''))
            pos += 1
            continue

        if remaining < 2:
            truncated = True
            break

        opt_len = compat_ord(buf[pos + 1])
        if opt_len < 2 or opt_len > remaining:
            truncated = True
            break

        data = buf[pos + 2:pos + opt_len]
        option = (kind, data)
        raw_options.append(option)

        if kind in (TCP_OPT_SACK, TCP_OPT_TIMESTAMP):
            if not _option_value_is_valid(kind, data):
                pos += opt_len
                continue
            if dedupe and kind in seen_singletons:
                pos += opt_len
                continue
            seen_singletons.add(kind)
        opts.append(option)
        pos += opt_len

    return TCPOptions(opts, truncated=truncated,
                      raw_options=raw_options)


def test_parse_opts():
    # normal scenarios
    buf = b'\x02\x04\x23\x00\x01\x01\x04\x02'
    opts = parse_opts(buf)
    assert opts == [
        (TCP_OPT_MSS, b'\x23\x00'),
        (TCP_OPT_NOP, b''),
        (TCP_OPT_NOP, b''),
        (TCP_OPT_SACKOK, b'')
    ]

    buf = b'\x01\x01\x05\x0a\x37\xf8\x19\x70\x37\xf8\x29\x78'
    opts = parse_opts(buf)
    assert opts == [
        (TCP_OPT_NOP, b''),
        (TCP_OPT_NOP, b''),
        (TCP_OPT_SACK, b'\x37\xf8\x19\x70\x37\xf8\x29\x78')
    ]

    # test a zero-length option
    buf = b'\x02\x00\x01'
    opts = parse_opts(buf)
    assert opts == []
    assert opts.truncated

    # test a one-byte malformed option
    buf = b'\xff'
    opts = parse_opts(buf)
    assert opts == []
    assert opts.truncated

    # EOL ends parsing; the remaining bytes must be zero padding
    opts = parse_opts(b'\x00' + b'\x00' * 20)
    assert opts == [(TCP_OPT_EOL, b'')]
    assert not opts.truncated

    opts = parse_opts(b'\x00\xff')
    assert opts == [(TCP_OPT_EOL, b'')]
    assert opts.truncated


def test_offset():
    tcpheader = TCP(b'\x01\xbb\xc0\xd7\xb6\x56\xa8\xb9\xd1\xac\xaa\xb1\x50\x18\x40\x00\x56\xf8\x00\x00')
    assert tcpheader.off == 5

    # test setting header offset
    tcpheader.off = 8
    assert bytes(tcpheader) == b'\x01\xbb\xc0\xd7\xb6\x56\xa8\xb9\xd1\xac\xaa\xb1\x80\x18\x40\x00\x56\xf8\x00\x00'


def test_tcp_flags_to_str():
    assert tcp_flags_to_str(0x18) == 'PUSH,ACK'
    assert tcp_flags_to_str(0x12) == 'SYN,ACK'
    # for code coverage
    assert tcp_flags_to_str(0x1ff) == 'FIN,SYN,RST,PUSH,ACK,URG,ECE,CWR,NS'


def test_tcp_unpack():
    data = (b'\x00\x50\x0d\x2c\x11\x4c\x61\x8b\x38\xaf\xfe\x14\x70\x12\x16\xd0'
            b'\x5b\xdc\x00\x00\x02\x04\x05\x64\x01\x01\x04\x02')
    tcp = TCP(data)
    assert tcp.flags == (TH_SYN | TH_ACK)
    assert tcp.off == 7
    assert tcp.win == 5840
    assert tcp.dport == 3372
    assert tcp.seq == 290218379
    assert tcp.ack == 951057940


def test_tcp_pack():
    tcp = TCP(
        sport=3372,
        dport=80,
        seq=951057939,
        ack=0,
        off=7,
        flags=TH_SYN,
        win=8760,
        sum=0xc30c,
        urp=0,
        opts=b'\x02\x04\x05\xb4\x01\x01\x04\x02'
    )
    assert bytes(tcp) == (
        b'\x0d\x2c\x00\x50\x38\xaf\xfe\x13\x00\x00\x00\x00\x70\x02\x22\x38'
        b'\xc3\x0c\x00\x00\x02\x04\x05\xb4\x01\x01\x04\x02')

    # TODO: add checksum calculation
