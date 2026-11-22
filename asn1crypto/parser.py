# coding: utf-8

"""
Functions for parsing and dumping using the ASN.1 DER encoding. Exports the
following items:

 - emit()
 - parse()
 - peek()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import hashlib

from ._types import byte_cls, chr_cls, type_name
from .util import int_from_bytes, int_to_bytes

_PY2 = sys.version_info <= (3,)
_INSUFFICIENT_DATA_MESSAGE = 'Insufficient data - %s bytes requested but only %s available'
_MAX_DEPTH = 10


class ByteSource(object):
    """
    A read-only view over a contiguous range of encoded bytes.

    A ByteSource never owns a mutable buffer. It stores the original byte
    string and an offset/length pair, so values parsed from it can retain
    exact, locatable references to their original encoding without copying
    or normalizing it.
    """

    __slots__ = ('_buffer', '_offset', '_length', '_memoryview')

    def __init__(self, data, offset=0, length=None):
        """
        :param data:
            A byte string, memoryview, bytearray, or another ByteSource

        :param offset:
            The offset, relative to data, of the first byte in the view

        :param length:
            The number of bytes in the view - defaults to the remainder of data

        :raises:
            TypeError - when data is not a byte-like object
            ValueError - when offset or length is out of range
        """

        if isinstance(data, ByteSource):
            buffer = data._buffer
            if offset == 0 and length is None:
                offset = data._offset
                length = data._length
            else:
                offset = data._offset + offset
        elif isinstance(data, memoryview):
            buffer = data.tobytes()
        elif isinstance(data, bytearray):
            buffer = bytes(data)
        elif isinstance(data, byte_cls):
            buffer = data
        else:
            raise TypeError('data must be a byte string, not %s' % type_name(data))

        buffer_len = len(buffer)

        if not isinstance(offset, int):
            raise TypeError('offset must be an integer, not %s' % type_name(offset))
        if length is not None and not isinstance(length, int):
            raise TypeError('length must be an integer, not %s' % type_name(length))
        if offset < 0 or offset > buffer_len:
            raise ValueError('offset must be between 0 and %d, not %d' % (buffer_len, offset))

        if length is None:
            length = buffer_len - offset
        if length < 0 or offset + length > buffer_len:
            raise ValueError(
                'length must describe a range within the buffer, not %d at offset %d' % (length, offset)
            )

        self._buffer = buffer
        self._offset = offset
        self._length = length

        raw_view = memoryview(buffer)[offset:offset + length]
        if hasattr(raw_view, 'toreadonly'):
            raw_view = raw_view.toreadonly()
        self._memoryview = raw_view

    @property
    def buffer(self):
        """
        :return:
            The complete, immutable byte string that backs this view
        """

        return self._buffer

    @property
    def offset(self):
        """
        :return:
            The absolute offset of the start of this view in .buffer
        """

        return self._offset

    @property
    def start(self):
        """
        :return:
            An alias for .offset
        """

        return self._offset

    @property
    def length(self):
        """
        :return:
            The number of bytes in this view
        """

        return self._length

    @property
    def end(self):
        """
        :return:
            The absolute offset immediately after this view
        """

        return self._offset + self._length

    @property
    def data(self):
        """
        :return:
            A byte string of the bytes in this view
        """

        return self._buffer[self._offset:self.end]

    @property
    def bytes(self):
        """
        :return:
            An alias for .data
        """

        return self.data

    @property
    def raw(self):
        """
        :return:
            An alias for .data
        """

        return self.data

    @property
    def raw_bytes(self):
        """
        :return:
            An alias for .data
        """

        return self.data

    @property
    def value(self):
        """
        :return:
            An alias for .data
        """

        return self.data

    @property
    def memoryview(self):
        """
        :return:
            A read-only memoryview of this range
        """

        return self._memoryview

    @property
    def read_only(self):
        """
        :return:
            True, since the view can never be modified
        """

        return True

    @property
    def readonly(self):
        """
        :return:
            An alias for .read_only
        """

        return True

    def view(self, offset=0, length=None):
        """
        Constructs a child view relative to the start of this view

        :param offset:
            The offset of the child view, relative to this view

        :param length:
            The number of bytes in the child view

        :return:
            A ByteSource object sharing the same immutable buffer
        """

        if offset < 0 or offset > self._length:
            raise ValueError('offset must be between 0 and %d, not %d' % (self._length, offset))
        if length is None:
            length = self._length - offset
        return ByteSource(self._buffer, self._offset + offset, length)

    def slice(self, start=0, end=None):
        """
        Constructs a child view using Python slice semantics

        :param start:
            The relative start offset

        :param end:
            The relative end offset, exclusive

        :return:
            A ByteSource object
        """

        if start < 0:
            start += self._length
        if end is None:
            end = self._length
        elif end < 0:
            end += self._length
        return self.view(start, end - start)

    def read(self, offset=0, length=None):
        """
        Reads bytes relative to the start of this view

        :param offset:
            The relative offset to read from

        :param length:
            The number of bytes to read

        :return:
            A byte string
        """

        if length is None:
            length = self._length - offset
        return self._buffer[self._offset + offset:self._offset + offset + length]

    def contains(self, other):
        """
        :param other:
            A ByteSource or an integer absolute offset

        :return:
            A boolean indicating if the offset or entire span is contained
        """

        if isinstance(other, int):
            return self._offset <= other < self.end
        if isinstance(other, ByteSource):
            return self._offset <= other.offset and other.end <= self.end
        if isinstance(other, ParseEvidence):
            return self._offset <= other.offset and other.end <= self.end
        raise TypeError('other must be an integer, ByteSource or ParseEvidence')

    def overlaps(self, other):
        """
        :param other:
            A ByteSource object

        :return:
            A boolean indicating if the two spans overlap
        """

        if not isinstance(other, ByteSource):
            raise TypeError('other must be a ByteSource, not %s' % type_name(other))
        return self._offset < other.end and other.offset < self.end

    def hex(self):
        """
        :return:
            A unicode hexadecimal representation of the bytes in this view
        """

        value = self.data
        if _PY2:
            return value.encode('hex')
        return value.hex()

    def sha256(self):
        """
        :return:
            A byte string of the SHA-256 digest of this view
        """

        return hashlib.sha256(self.data).digest()

    def tobytes(self):
        """
        :return:
            An alias for .data
        """

        return self.data

    def to_bytes(self):
        """
        :return:
            An alias for .data
        """

        return self.data

    def __len__(self):
        return self._length

    def __iter__(self):
        for index in range(self._length):
            yield self[index]

    def __bytes__(self):
        return self.data

    def __str__(self):
        return self.__repr__()

    def __unicode__(self):
        return self.__repr__()

    def __repr__(self):
        return '<ByteSource offset=%d length=%d>' % (self._offset, self._length)

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(self._length)
            if step != 1:
                return self.data[start:stop:step]
            return self.data[start:stop]
        if key < 0:
            key += self._length
        if key < 0 or key >= self._length:
            raise IndexError('ByteSource index out of range')
        value = self._buffer[self._offset + key]
        if not isinstance(value, int):
            return ord(value)
        return value

    def __setitem__(self, key, value):
        raise TypeError('ByteSource is read-only')

    def __delitem__(self, key):
        raise TypeError('ByteSource is read-only')

    def write(self, value):
        raise TypeError('ByteSource is read-only')

    def __eq__(self, other):
        if isinstance(other, ByteSource):
            return self.data == other.data
        if isinstance(other, memoryview):
            return self.data == other.tobytes()
        if isinstance(other, (bytes, bytearray)):
            return self.data == bytes(other)
        return False

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.data)

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return ByteSource(self._buffer, self._offset, self._length)

    def __reduce__(self):
        return (ByteSource, (self._buffer, self._offset, self._length))


# A descriptive alias for callers that want the intent to be explicit
ReadOnlyByteSource = ByteSource
SourceView = ByteSource


class ParseEvidence(object):
    """
    A locatable record of parsing behavior that must be retained for audit
    purposes, such as an acceptable non-DER encoding, an explicitly encoded
    default value, or an element that was not interpreted by a schema.
    """

    __slots__ = (
        '_kind',
        '_reason',
        '_source',
        '_path',
        '_detail',
        '_spec',
        '_node_type',
        '_value',
    )

    ALTERNATE_ENCODING = 'alternate_encoding'
    EXPLICIT_DEFAULT = 'explicit_default'
    UNINTERPRETED = 'uninterpreted'

    # Specific reasons for .ALTERNATE_ENCODING evidence
    INDEFINITE_LENGTH = 'indefinite_length'
    CONSTRUCTED_STRING = 'constructed_string'
    NONMINIMAL_LENGTH = 'nonminimal_length'
    NONMINIMAL_INTEGER = 'nonminimal_integer'
    NONCANONICAL_BOOLEAN = 'noncanonical_boolean'
    CANONICAL_ENCODING = 'canonical_encoding'

    def __init__(self, kind, source, reason=None, path=None, detail=None, spec=None,
                 node_type=None, value=None):
        """
        :param kind:
            One of ALTERNATE_ENCODING, EXPLICIT_DEFAULT or UNINTERPRETED

        :param source:
            A ByteSource covering the exact original bytes of the evidence

        :param reason:
            An optional more-specific reason for the evidence

        :param path:
            An optional tuple of field names/indexes locating the evidence

        :param detail:
            An optional unicode string with a human-readable explanation

        :param spec:
            The ASN.1 spec class associated with the evidence, if any

        :param node_type:
            The unicode name of the parsed value class, if any

        :param value:
            The native value of the parsed element, if it could be determined
        """

        if not isinstance(source, ByteSource):
            raise TypeError('source must be a ByteSource, not %s' % type_name(source))

        self._kind = kind
        self._reason = reason
        self._source = source
        self._path = tuple(path) if path is not None else ()
        self._detail = detail
        self._spec = spec
        self._node_type = node_type
        self._value = value

    @property
    def kind(self):
        """
        :return:
            The evidence category
        """

        return self._kind

    @property
    def reason(self):
        """
        :return:
            A more-specific reason, or None
        """

        return self._reason

    @property
    def source(self):
        """
        :return:
            A ByteSource covering the original bytes
        """

        return self._source

    @property
    def span(self):
        """
        :return:
            An alias for .source
        """

        return self._source

    @property
    def offset(self):
        """
        :return:
            The absolute offset of the evidence in the original source
        """

        return self._source.offset

    @property
    def start(self):
        """
        :return:
            An alias for .offset
        """

        return self._source.offset

    @property
    def end(self):
        """
        :return:
            The absolute offset immediately after the evidence
        """

        return self._source.end

    @property
    def length(self):
        """
        :return:
            The number of bytes of evidence
        """

        return self._source.length

    @property
    def data(self):
        """
        :return:
            A byte string of the original evidence bytes
        """

        return self._source.data

    @property
    def raw_bytes(self):
        """
        :return:
            An alias for .data
        """

        return self._source.data

    @property
    def raw(self):
        """
        :return:
            An alias for .data
        """

        return self._source.data

    @property
    def encoded(self):
        """
        :return:
            An alias for .data
        """

        return self._source.data

    @property
    def byte_range(self):
        """
        :return:
            A 2-element tuple of (start, end)
        """

        return (self._source.offset, self._source.end)

    @property
    def path(self):
        """
        :return:
            A tuple of field names and indexes locating the evidence
        """

        return self._path

    @property
    def detail(self):
        """
        :return:
            A human-readable explanation, or None
        """

        return self._detail

    @property
    def description(self):
        """
        :return:
            A human-readable description of the evidence
        """

        if self._detail:
            return self._detail
        if self._reason:
            return '%s (%s)' % (self._kind, self._reason)
        return self._kind

    @property
    def spec(self):
        """
        :return:
            The ASN.1 spec class associated with the evidence, or None
        """

        return self._spec

    @property
    def node_type(self):
        """
        :return:
            The unicode name of the parsed value class, or None
        """

        return self._node_type

    @property
    def value(self):
        """
        :return:
            The native value associated with the evidence, or None
        """

        return self._value

    @property
    def category(self):
        """
        :return:
            An alias for .kind
        """

        return self._kind

    @property
    def type(self):
        """
        :return:
            An alias for .kind
        """

        return self._kind

    @property
    def absolute_offset(self):
        """
        :return:
            An alias for .offset
        """

        return self._source.offset

    @property
    def is_alternate_encoding(self):
        """
        :return:
            A boolean indicating if this is an acceptable alternate encoding
        """

        return self._kind == self.ALTERNATE_ENCODING

    @property
    def is_acceptable_alternate(self):
        """
        :return:
            An alias for .is_alternate_encoding
        """

        return self.is_alternate_encoding

    @property
    def is_explicit_default(self):
        """
        :return:
            A boolean indicating if the evidence is an explicit default
        """

        return self._kind == self.EXPLICIT_DEFAULT

    @property
    def is_uninterpreted(self):
        """
        :return:
            A boolean indicating if the value was left uninterpreted
        """

        return self._kind == self.UNINTERPRETED

    def __repr__(self):
        return '<ParseEvidence %s%s offset=%d length=%d path=%r>' % (
            self._kind,
            ' (%s)' % self._reason if self._reason else '',
            self.offset,
            self.length,
            self._path,
        )


class ComparisonResult(object):
    """
    The result of comparing two ASN.1 values both semantically and by their
    original encoded bytes.
    """

    __slots__ = (
        '_value_equal',
        '_bytes_equal',
        '_evidence',
        '_left_evidence',
        '_right_evidence',
        '_left_bytes',
        '_right_bytes',
    )

    def __init__(self, value_equal, bytes_equal, evidence=(), left_evidence=(),
                 right_evidence=(), left_bytes=None, right_bytes=None):
        self._value_equal = bool(value_equal)
        self._bytes_equal = bool(bytes_equal)
        self._evidence = tuple(evidence)
        self._left_evidence = tuple(left_evidence)
        self._right_evidence = tuple(right_evidence)
        self._left_bytes = left_bytes
        self._right_bytes = right_bytes

    @property
    def value_equal(self):
        """
        :return:
            True if the two values are semantically equal
        """

        return self._value_equal

    @property
    def values_equal(self):
        """
        :return:
            An alias for .value_equal
        """

        return self._value_equal

    @property
    def equal_value(self):
        """
        :return:
            An alias for .value_equal
        """

        return self._value_equal

    @property
    def semantic_equal(self):
        """
        :return:
            An alias for .value_equal
        """

        return self._value_equal

    @property
    def bytes_equal(self):
        """
        :return:
            True if the original encodings are byte-for-byte identical
        """

        return self._bytes_equal

    @property
    def raw_bytes_equal(self):
        """
        :return:
            An alias for .bytes_equal
        """

        return self._bytes_equal

    @property
    def raw_equal(self):
        """
        :return:
            An alias for .bytes_equal
        """

        return self._bytes_equal

    @property
    def encoding_equal(self):
        """
        :return:
            An alias for .bytes_equal
        """

        return self._bytes_equal

    @property
    def byte_equal(self):
        """
        :return:
            An alias for .bytes_equal
        """

        return self._bytes_equal

    @property
    def equal_bytes(self):
        """
        :return:
            An alias for .bytes_equal
        """

        return self._bytes_equal

    @property
    def identical(self):
        """
        :return:
            An alias for .bytes_equal
        """

        return self._bytes_equal

    @property
    def evidence(self):
        """
        :return:
            A tuple of all evidence retained from both sides
        """

        return self._evidence

    @property
    def left_evidence(self):
        """
        :return:
            A tuple of evidence from the left value
        """

        return self._left_evidence

    @property
    def right_evidence(self):
        """
        :return:
            A tuple of evidence from the right value
        """

        return self._right_evidence

    @property
    def left_bytes(self):
        """
        :return:
            The original bytes of the left value, if available
        """

        return self._left_bytes

    @property
    def right_bytes(self):
        """
        :return:
            The original bytes of the right value, if available
        """

        return self._right_bytes

    def as_dict(self):
        """
        :return:
            A dict with the two comparison results and evidence
        """

        return {
            'value_equal': self._value_equal,
            'bytes_equal': self._bytes_equal,
            'evidence': self._evidence,
        }

    def __iter__(self):
        yield self._value_equal
        yield self._bytes_equal

    def __len__(self):
        return 2

    def __getitem__(self, index):
        if index in ('value_equal', 'values_equal', 'semantic_equal'):
            return self._value_equal
        if index in ('bytes_equal', 'raw_bytes_equal', 'raw_equal', 'identical'):
            return self._bytes_equal
        if index == 'evidence':
            return self._evidence
        return (self._value_equal, self._bytes_equal)[index]

    def __bool__(self):
        return self._value_equal

    def __nonzero__(self):
        return self._value_equal

    def __eq__(self, other):
        if isinstance(other, ComparisonResult):
            return (
                self._value_equal == other._value_equal and
                self._bytes_equal == other._bytes_equal
            )
        if isinstance(other, tuple) and len(other) == 2:
            return (self._value_equal, self._bytes_equal) == other
        return False

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return '<ComparisonResult value_equal=%s bytes_equal=%s>' % (
            self._value_equal,
            self._bytes_equal,
        )


def emit(class_, method, tag, contents):
    """
    Constructs a byte string of an ASN.1 DER-encoded value

    This is typically not useful. Instead, use one of the standard classes from
    asn1crypto.core, or construct a new class with specific fields, and call the
    .dump() method.

    :param class_:
        An integer ASN.1 class value: 0 (universal), 1 (application),
        2 (context), 3 (private)

    :param method:
        An integer ASN.1 method value: 0 (primitive), 1 (constructed)

    :param tag:
        An integer ASN.1 tag value

    :param contents:
        A byte string of the encoded byte contents

    :return:
        A byte string of the ASN.1 DER value (header and contents)
    """

    if not isinstance(class_, int):
        raise TypeError('class_ must be an integer, not %s' % type_name(class_))

    if class_ < 0 or class_ > 3:
        raise ValueError('class_ must be one of 0, 1, 2 or 3, not %s' % class_)

    if not isinstance(method, int):
        raise TypeError('method must be an integer, not %s' % type_name(method))

    if method < 0 or method > 1:
        raise ValueError('method must be 0 or 1, not %s' % method)

    if not isinstance(tag, int):
        raise TypeError('tag must be an integer, not %s' % type_name(tag))

    if tag < 0:
        raise ValueError('tag must be greater than zero, not %s' % tag)

    if not isinstance(contents, byte_cls):
        raise TypeError('contents must be a byte string, not %s' % type_name(contents))

    return _dump_header(class_, method, tag, contents) + contents


def parse(contents, strict=False):
    """
    Parses a byte string of ASN.1 BER/DER-encoded data.

    This is typically not useful. Instead, use one of the standard classes from
    asn1crypto.core, or construct a new class with specific fields, and call the
    .load() class method.

    :param contents:
        A byte string of BER/DER-encoded data

    :param strict:
        A boolean indicating if trailing data should be forbidden - if so, a
        ValueError will be raised when trailing data exists

    :raises:
        ValueError - when the contents do not contain an ASN.1 header or are truncated in some way
        TypeError - when contents is not a byte string

    :return:
        A 6-element tuple:
         - 0: integer class (0 to 3)
         - 1: integer method
         - 2: integer tag
         - 3: byte string header
         - 4: byte string content
         - 5: byte string trailer
    """

    if not isinstance(contents, byte_cls):
        raise TypeError('contents must be a byte string, not %s' % type_name(contents))

    contents_len = len(contents)
    info, consumed = _parse(contents, contents_len)
    if strict and consumed != contents_len:
        raise ValueError('Extra data - %d bytes of trailing data were provided' % (contents_len - consumed))
    return info


def peek(contents):
    """
    Parses a byte string of ASN.1 BER/DER-encoded data to find the length

    This is typically used to look into an encoded value to see how long the
    next chunk of ASN.1-encoded data is. Primarily it is useful when a
    value is a concatenation of multiple values.

    :param contents:
        A byte string of BER/DER-encoded data

    :raises:
        ValueError - when the contents do not contain an ASN.1 header or are truncated in some way
        TypeError - when contents is not a byte string

    :return:
        An integer with the number of bytes occupied by the ASN.1 value
    """

    if not isinstance(contents, byte_cls):
        raise TypeError('contents must be a byte string, not %s' % type_name(contents))

    info, consumed = _parse(contents, len(contents))
    return consumed


def _parse(encoded_data, data_len, pointer=0, lengths_only=False, depth=0):
    """
    Parses a byte string into component parts

    :param encoded_data:
        A byte string that contains BER-encoded data

    :param data_len:
        The integer length of the encoded data

    :param pointer:
        The index in the byte string to parse from

    :param lengths_only:
        A boolean to cause the call to return a 2-element tuple of the integer
        number of bytes in the header and the integer number of bytes in the
        contents. Internal use only.

    :param depth:
        The recursion depth when evaluating indefinite-length encoding.

    :return:
        A 2-element tuple:
         - 0: A tuple of (class_, method, tag, header, content, trailer)
         - 1: An integer indicating how many bytes were consumed
    """

    if depth > _MAX_DEPTH:
        raise ValueError('Indefinite-length recursion limit exceeded')

    start = pointer

    if data_len < pointer + 1:
        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
    first_octet = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]

    pointer += 1

    tag = first_octet & 31
    constructed = (first_octet >> 5) & 1
    # Base 128 length using 8th bit as continuation indicator
    if tag == 31:
        tag = 0
        while True:
            if data_len < pointer + 1:
                raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
            num = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]
            pointer += 1
            if num == 0x80 and tag == 0:
                raise ValueError('Non-minimal tag encoding')
            tag *= 128
            tag += num & 127
            if num >> 7 == 0:
                break
        if tag < 31:
            raise ValueError('Non-minimal tag encoding')

    if data_len < pointer + 1:
        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
    length_octet = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]
    pointer += 1
    trailer = b''

    if length_octet >> 7 == 0:
        contents_end = pointer + (length_octet & 127)

    else:
        length_octets = length_octet & 127
        if length_octets:
            if data_len < pointer + length_octets:
                raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (length_octets, data_len - pointer))
            pointer += length_octets
            contents_end = pointer + int_from_bytes(encoded_data[pointer - length_octets:pointer], signed=False)

        else:
            # To properly parse indefinite length values, we need to scan forward
            # parsing headers until we find a value with a length of zero. If we
            # just scanned looking for \x00\x00, nested indefinite length values
            # would not work.
            if not constructed:
                raise ValueError('Indefinite-length element must be constructed')
            contents_end = pointer
            while data_len < contents_end + 2 or encoded_data[contents_end:contents_end+2] != b'\x00\x00':
                _, contents_end = _parse(encoded_data, data_len, contents_end, lengths_only=True, depth=depth+1)
            contents_end += 2
            trailer = b'\x00\x00'

    if contents_end > data_len:
        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (contents_end - pointer, data_len - pointer))

    if lengths_only:
        return (pointer, contents_end)

    return (
        (
            first_octet >> 6,
            constructed,
            tag,
            encoded_data[start:pointer],
            encoded_data[pointer:contents_end-len(trailer)],
            trailer
        ),
        contents_end
    )


def _dump_header(class_, method, tag, contents):
    """
    Constructs the header bytes for an ASN.1 object

    :param class_:
        An integer ASN.1 class value: 0 (universal), 1 (application),
        2 (context), 3 (private)

    :param method:
        An integer ASN.1 method value: 0 (primitive), 1 (constructed)

    :param tag:
        An integer ASN.1 tag value

    :param contents:
        A byte string of the encoded byte contents

    :return:
        A byte string of the ASN.1 DER header
    """

    header = b''

    id_num = 0
    id_num |= class_ << 6
    id_num |= method << 5

    if tag >= 31:
        cont_bit = 0
        while tag > 0:
            header = chr_cls(cont_bit | (tag & 0x7f)) + header
            if not cont_bit:
                cont_bit = 0x80
            tag = tag >> 7
        header = chr_cls(id_num | 31) + header
    else:
        header += chr_cls(id_num | tag)

    length = len(contents)
    if length <= 127:
        header += chr_cls(length)
    else:
        length_bytes = int_to_bytes(length)
        header += chr_cls(0x80 | len(length_bytes))
        header += length_bytes

    return header
