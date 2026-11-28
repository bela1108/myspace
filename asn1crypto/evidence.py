# coding: utf-8

"""
Read-only evidence views that tie the parsed values of CMS signed attributes
to the exact bytes they were decoded from.

A reviewer is normally handed a CMS envelope and a list of attribute
explanations. The explanations look interchangeable, but only some of them are
backed by bytes that were actually present in the signed envelope. This module
never re-encodes or mutates the input; instead it records, for every parsed
attribute:

 * the parsed value and the attribute type OID,
 * the original byte location (offset and length) inside the envelope,
 * the envelope boundaries the location is measured against,
 * a status describing duplicates, unknown fields and any movement that would
   occur if the same value were re-encoded to canonical DER,
 * whether an explanation can be cross-checked against the original bytes.

Exports the following items:

 - PacketBounds()
 - ByteLocation()
 - AttributeEvidence()
 - AttributeEvidenceView()
 - AttributeExplanation()
 - ExplanationEvidence()
 - ExplanationEvidenceView()
 - evidence_for_packet()

Status constants:

 - STATUS_ORIGINAL
 - STATUS_DUPLICATE
 - STATUS_UNKNOWN
 - STATUS_RELOCATED
 - STATUS_UNLOCATED
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._errors import unwrap
from ._ordereddict import OrderedDict
from ._types import byte_cls, str_cls, type_name
from .cms import CMSAttribute, CMSAttributeType, ContentInfo
from .core import VOID
from .parser import _parse


#: The attribute was decoded from a single location inside the envelope and a
#: canonical DER re-encoding occupies the same bytes.
STATUS_ORIGINAL = 'original'

#: Another attribute using the same type OID was already recorded. CMS SET OF
#: attributes must not repeat the same attribute type.
STATUS_DUPLICATE = 'duplicate'

#: The type OID is not present in :attr:`cms.CMSAttributeType._map`, so no
#: semantic name is known for the field.
STATUS_UNKNOWN = 'unknown'

#: The value round-trips, but canonical DER re-encoding changes the byte
#: layout (for example DER sorting of a SET OF), so the canonical location
#: differs from the original location.
STATUS_RELOCATED = 'relocated'

#: An explanation could not be matched to any signed byte range, so there is
#: no original location that can be used to verify it.
STATUS_UNLOCATED = 'unlocated'


class PacketBounds(object):
    """
    The immutable byte boundaries of the CMS envelope that was reviewed.

    Locations recorded by an evidence view are always offsets relative to the
    ``start`` offset of these bounds, inside a buffer that is ``length`` bytes
    long. The bounds never change while the view is alive.
    """

    __slots__ = ['_buffer_length', '_start', '_end', '_indefinite']

    def __init__(self, buffer_length, start=0, end=None, indefinite=False):
        if not isinstance(buffer_length, int):
            raise TypeError(unwrap(
                '''
                buffer_length must be an integer, not %s
                ''',
                type_name(buffer_length)
            ))
        if end is None:
            end = buffer_length
        if start < 0 or end < start or end > buffer_length:
            raise ValueError(unwrap(
                '''
                Invalid packet bounds [%d, %d) for a buffer of length %d
                ''',
                start,
                end,
                buffer_length
            ))
        self._buffer_length = buffer_length
        self._start = start
        self._end = end
        self._indefinite = bool(indefinite)

    def __repr__(self):
        return 'PacketBounds(buffer_length=%d, start=%d, end=%d, indefinite=%r)' % (
            self._buffer_length,
            self._start,
            self._end,
            self._indefinite,
        )

    def __eq__(self, other):
        if not isinstance(other, PacketBounds):
            return NotImplemented
        return (
            self._buffer_length == other._buffer_length and
            self._start == other._start and
            self._end == other._end and
            self._indefinite == other._indefinite
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self._buffer_length, self._start, self._end, self._indefinite))

    @property
    def buffer_length(self):
        """
        :return:
            The total length, in bytes, of the buffer containing the packet
        """
        return self._buffer_length

    @property
    def start(self):
        """
        :return:
            The absolute offset of the first packet byte
        """
        return self._start

    @property
    def end(self):
        """
        :return:
            The absolute offset immediately after the last packet byte
        """
        return self._end

    @property
    def length(self):
        """
        :return:
            The number of bytes occupied by the packet
        """
        return self._end - self._start

    @property
    def indefinite(self):
        """
        :return:
            A boolean - True if the packet was encoded using BER indefinite
            length rather than DER definite length
        """
        return self._indefinite

    def contains(self, offset, length=0):
        """
        Checks that a byte range lies inside the packet boundaries.

        :param offset:
            The absolute start offset of the range

        :param length:
            The number of bytes in the range

        :return:
            A boolean
        """
        return self._start <= offset and offset + length <= self._end

    def relative_offset(self, absolute_offset):
        """
        Converts an absolute buffer offset into an offset from the packet
        start.

        :param absolute_offset:
            An integer absolute offset inside the source buffer

        :return:
            An integer offset relative to :attr:`start`
        """
        return absolute_offset - self._start


class ByteLocation(object):
    """
    A recorded byte range inside a :class:`PacketBounds`.

    The range is half-open: ``[offset, offset + length)``. Locations are
    read-only snapshots; they are computed once and never updated when other
    parts of the envelope are inspected.
    """

    __slots__ = ['_offset', '_length', '_header_length', '_trailer_length', '_bounds']

    def __init__(self, offset, length, bounds, header_length=0, trailer_length=0):
        if not isinstance(bounds, PacketBounds):
            raise TypeError(unwrap(
                '''
                bounds must be an instance of PacketBounds, not %s
                ''',
                type_name(bounds)
            ))
        if header_length < 0 or trailer_length < 0 or length < header_length + trailer_length:
            raise ValueError(unwrap(
                '''
                Invalid header/trailer lengths for a location of length %d
                ''',
                length
            ))
        if not bounds.contains(offset, length):
            raise ValueError(unwrap(
                '''
                Byte range [%d, %d) falls outside of %r
                ''',
                offset,
                offset + length,
                bounds
            ))
        self._offset = offset
        self._length = length
        self._header_length = header_length
        self._trailer_length = trailer_length
        self._bounds = bounds

    def __repr__(self):
        return 'ByteLocation(offset=%d, length=%d, relative_offset=%d)' % (
            self._offset,
            self._length,
            self.relative_offset,
        )

    def __eq__(self, other):
        if not isinstance(other, ByteLocation):
            return NotImplemented
        return (
            self._offset == other._offset and
            self._length == other._length and
            self._header_length == other._header_length and
            self._trailer_length == other._trailer_length and
            self._bounds == other._bounds
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self._offset, self._length, self._header_length, self._trailer_length))

    @property
    def offset(self):
        """
        :return:
            The absolute start offset of the range in the source buffer
        """
        return self._offset

    @property
    def length(self):
        """
        :return:
            The number of bytes in the range
        """
        return self._length

    @property
    def end(self):
        """
        :return:
            The absolute offset immediately after the last byte of the range
        """
        return self._offset + self._length

    @property
    def relative_offset(self):
        """
        :return:
            The start offset measured from the packet start
        """
        return self._bounds.relative_offset(self._offset)

    @property
    def header_length(self):
        """
        :return:
            The number of ASN.1 header bytes (tag and length) in the range
        """
        return self._header_length

    @property
    def trailer_length(self):
        """
        :return:
            The number of trailing bytes (such as a BER end-of-contents marker)
        """
        return self._trailer_length

    @property
    def bounds(self):
        """
        :return:
            The :class:`PacketBounds` the offset is measured within
        """
        return self._bounds

    def bytes_from(self, data):
        """
        Returns the original bytes of this range from a source buffer,
        allowing a reviewer to re-check the value against the original packet.

        :param data:
            The byte string buffer the location was recorded against

        :return:
            A byte string covering ``[offset, offset + length)``
        """
        if not isinstance(data, byte_cls):
            raise TypeError(unwrap(
                '''
                data must be a byte string, not %s
                ''',
                type_name(data)
            ))
        if len(data) != self._bounds.buffer_length:
            raise ValueError(unwrap(
                '''
                data has length %d, but the bounds were recorded against a
                buffer of length %d
                ''',
                len(data),
                self._bounds.buffer_length
            ))
        return data[self._offset:self._offset + self._length]


class AttributeEvidence(object):
    """
    Read-only evidence for one CMS attribute decoded from the packet.

    The object records the parsed attribute alongside its original byte
    location and the status that describes how trustworthy the parsed value is
    as evidence of what was signed. It never modifies the parsed attribute or
    the source buffer.
    """

    __slots__ = [
        '_index', '_attribute', '_location', '_statuses', '_canonical_location',
        '_original_bytes', '_canonical_bytes', '_type_name', '_type_oid',
    ]

    def __init__(self, index, attribute, location, statuses, type_oid, type_name,
                 canonical_location=None, original_bytes=None, canonical_bytes=None):
        self._index = index
        self._attribute = attribute
        self._location = location
        self._statuses = tuple(statuses)
        self._canonical_location = canonical_location
        self._original_bytes = original_bytes
        self._canonical_bytes = canonical_bytes
        self._type_oid = type_oid
        self._type_name = type_name

    def __repr__(self):
        return 'AttributeEvidence(index=%d, type=%r, oid=%r, statuses=%r)' % (
            self._index,
            self._type_name,
            self._type_oid,
            self._statuses,
        )

    @property
    def index(self):
        """
        :return:
            The zero-based position of the attribute in the parsed SET OF
        """
        return self._index

    @property
    def attribute(self):
        """
        :return:
            The parsed :class:`cms.CMSAttribute` object
        """
        return self._attribute

    @property
    def type_oid(self):
        """
        :return:
            A unicode string of the dotted attribute type OID
        """
        return self._type_oid

    @property
    def type_name(self):
        """
        :return:
            The mapped semantic name of the attribute type, or the dotted OID
            when the field is unknown
        """
        return self._type_name

    @property
    def known(self):
        """
        :return:
            A boolean - False when the type OID has no semantic mapping
        """
        return STATUS_UNKNOWN not in self._statuses

    @property
    def duplicate(self):
        """
        :return:
            A boolean - True when an earlier attribute used the same type OID
        """
        return STATUS_DUPLICATE in self._statuses

    @property
    def relocated(self):
        """
        :return:
            A boolean - True when canonical DER re-encoding changes the byte
            layout of the attribute set
        """
        return STATUS_RELOCATED in self._statuses

    @property
    def statuses(self):
        """
        :return:
            A tuple of status constant strings, always containing at least
            :data:`STATUS_ORIGINAL` for a located attribute
        """
        return self._statuses

    @property
    def location(self):
        """
        :return:
            The :class:`ByteLocation` of the original encoded attribute
        """
        return self._location

    @property
    def canonical_location(self):
        """
        :return:
            The :class:`ByteLocation` the attribute occupies after canonical
            DER re-encoding, or None when re-encoding does not move it
        """
        return self._canonical_location

    @property
    def original_bytes(self):
        """
        :return:
            The original encoded bytes of the attribute, exactly as signed
        """
        return self._original_bytes

    @property
    def canonical_bytes(self):
        """
        :return:
            The canonical DER bytes, or None when they match the original
        """
        return self._canonical_bytes

    @property
    def value(self):
        """
        :return:
            The native Python value of the attribute, including the parsed
            type and value set
        """
        return self._attribute.native

    def verify_bytes(self, data):
        """
        Re-checks the evidence against the packet bytes supplied by the
        reviewer.

        :param data:
            The original CMS packet byte string

        :return:
            A boolean - True only when the recorded location still contains
            the exact bytes the attribute was parsed from
        """
        return self._location.bytes_from(data) == self._original_bytes


class AttributeEvidenceView(object):
    """
    A read-only collection of :class:`AttributeEvidence` for the signed
    attributes of one CMS signer.

    Instances are created through :func:`evidence_for_packet`; they are not
    intended to be constructed directly. All offsets are absolute offsets in
    the original packet buffer and are also exposed relative to the packet
    bounds for reviewer-facing reports.
    """

    __slots__ = ['_bounds', '_data', '_evidence', '_signer_index', '_set_location']

    def __init__(self, data, bounds, signer_index, set_location, evidence):
        self._data = data
        self._bounds = bounds
        self._signer_index = signer_index
        self._set_location = set_location
        self._evidence = tuple(evidence)

    def __repr__(self):
        return 'AttributeEvidenceView(signer_index=%d, attributes=%d)' % (
            self._signer_index,
            len(self._evidence),
        )

    def __iter__(self):
        return iter(self._evidence)

    def __len__(self):
        return len(self._evidence)

    def __getitem__(self, index):
        return self._evidence[index]

    @property
    def bounds(self):
        """
        :return:
            The :class:`PacketBounds` of the CMS packet
        """
        return self._bounds

    @property
    def signer_index(self):
        """
        :return:
            The zero-based index of the signer within the CMS SignedData
        """
        return self._signer_index

    @property
    def signed_attrs_location(self):
        """
        :return:
            The :class:`ByteLocation` of the whole signed attributes set,
            including its implicit context tag
        """
        return self._set_location

    @property
    def data(self):
        """
        :return:
            The original packet byte string
        """
        return self._data

    def by_type(self, type_name_or_oid):
        """
        Returns all evidence entries matching an attribute type name or OID.

        :param type_name_or_oid:
            A unicode string of a mapped type name or dotted OID

        :return:
            A tuple of :class:`AttributeEvidence` objects, possibly empty
        """
        return tuple(
            item for item in self._evidence
            if item.type_name == type_name_or_oid or item.type_oid == type_name_or_oid
        )

    @property
    def duplicates(self):
        """
        :return:
            A tuple of evidence entries flagged as duplicates
        """
        return tuple(item for item in self._evidence if item.duplicate)

    @property
    def unknown(self):
        """
        :return:
            A tuple of evidence entries using an unmapped type OID
        """
        return tuple(item for item in self._evidence if not item.known)

    @property
    def relocated(self):
        """
        :return:
            A tuple of evidence entries whose canonical DER location differs
            from the original location
        """
        return tuple(item for item in self._evidence if item.relocated)


def _walk_der(data, start, end, nodes=None):
    """
    Walks a definite-length (DER) region and records every TLV node as a
    tuple of ``(tag, method, start, end, header_length, trailer_length)``,
    where start and end are absolute offsets in ``data``.

    Only definite-length DER regions are descended into. The signed attribute
    sets of a CMS packet are DER encoded even when the outer envelope uses BER
    indefinite length.
    """
    if nodes is None:
        nodes = []
    pointer = start
    while pointer < end:
        info, consumed = _parse(data, len(data), pointer)
        class_, method, tag, header, content, trailer = info
        node_end = consumed + len(trailer)
        nodes.append((tag, method, pointer, node_end, len(header), len(trailer)))
        if method == 1 and content and not trailer:
            # The header occupies [pointer, pointer + len(header)). Content
            # starts immediately after it and, for DER, runs to node_end.
            content_start = pointer + len(header)
            _walk_der(data, content_start, node_end, nodes)
        pointer = node_end
    return nodes


def _locate_tlv(data, needle, start, end):
    """
    Finds the unique TLV node whose bytes equal ``needle`` inside a walked
    DER region.

    :return:
        A tuple of ``(absolute_start, absolute_end, header_length,``
        ``trailer_length)``, or None when there is not exactly one match
    """
    nodes = _walk_der(data, start, end)
    matches = [
        (node_start, node_end, header_length, trailer_length)
        for (tag, method, node_start, node_end, header_length, trailer_length) in nodes
        if data[node_start:node_end] == needle
    ]
    if len(matches) == 1:
        return matches[0]
    return None


class AttributeExplanation(object):
    """
    A reviewer-facing explanation of one CMS attribute.

    An explanation is only a claim about what an attribute means. It carries
    the attribute type it refers to, plus an optional expected value and free
    text. Whether the claim is backed by the signed bytes is decided by the
    :class:`ExplanationEvidenceView`, not assumed from the explanation itself.
    """

    __slots__ = ['_label', '_type_oid', '_expected_value', '_detail']

    def __init__(self, label, type_oid, expected_value=None, detail=None):
        if not isinstance(label, str_cls):
            raise TypeError(unwrap(
                '''
                label must be a unicode string, not %s
                ''',
                type_name(label)
            ))
        if not isinstance(type_oid, str_cls):
            raise TypeError(unwrap(
                '''
                type_oid must be a unicode string, not %s
                ''',
                type_name(type_oid)
            ))
        self._label = label
        self._type_oid = type_oid
        self._expected_value = expected_value
        self._detail = detail

    def __repr__(self):
        return 'AttributeExplanation(label=%r, type_oid=%r)' % (self._label, self._type_oid)

    @property
    def label(self):
        """
        :return:
            A unicode string with the human-readable name of the explanation
        """
        return self._label

    @property
    def type_oid(self):
        """
        :return:
            A unicode string of the dotted attribute type OID the
            explanation refers to
        """
        return self._type_oid

    @property
    def expected_value(self):
        """
        :return:
            The value the explanation claims, or None when no value is given
        """
        return self._expected_value

    @property
    def detail(self):
        """
        :return:
            Optional free-text detail about the explanation
        """
        return self._detail


class ExplanationEvidence(object):
    """
    The verdict for one :class:`AttributeExplanation`.

    A verifiable explanation is linked to the :class:`AttributeEvidence` of
    the bytes it explains. An explanation without provenance is kept, with
    status :data:`STATUS_UNLOCATED`, so reviewers can treat it differently
    from one that can be cross-checked against the original packet.
    """

    __slots__ = ['_explanation', '_statuses', '_attribute_evidence']

    def __init__(self, explanation, statuses, attribute_evidence=None):
        self._explanation = explanation
        self._statuses = tuple(statuses)
        self._attribute_evidence = attribute_evidence

    def __repr__(self):
        return 'ExplanationEvidence(label=%r, statuses=%r)' % (
            self._explanation.label,
            self._statuses,
        )

    @property
    def explanation(self):
        """
        :return:
            The underlying :class:`AttributeExplanation`
        """
        return self._explanation

    @property
    def statuses(self):
        """
        :return:
            A tuple of status constants. Contains :data:`STATUS_ORIGINAL`
            when backed by signed bytes, otherwise :data:`STATUS_UNLOCATED`
        """
        return self._statuses

    @property
    def verifiable(self):
        """
        :return:
            A boolean - True only when signed bytes back the explanation
        """
        return self._attribute_evidence is not None

    @property
    def attribute_evidence(self):
        """
        :return:
            The matching :class:`AttributeEvidence`, or None for an
            explanation without provenance
        """
        return self._attribute_evidence

    @property
    def location(self):
        """
        :return:
            The :class:`ByteLocation` of the backing attribute, or None
        """
        if self._attribute_evidence is None:
            return None
        return self._attribute_evidence.location

    def verify_bytes(self, data):
        """
        Re-checks the backing attribute bytes against the packet supplied by
        the reviewer. Unlocated explanations always return False.

        :param data:
            The original CMS packet byte string

        :return:
            A boolean
        """
        if self._attribute_evidence is None:
            return False
        return self._attribute_evidence.verify_bytes(data)


class ExplanationEvidenceView(object):
    """
    Links a list of :class:`AttributeExplanation` objects to the signed bytes
    of one packet.

    Explanations that match a parsed attribute are verifiable and expose the
    original location; explanations whose type OID never appears in the signed
    bytes are reported as unlocated rather than silently dropped.
    """

    __slots__ = ['_attribute_view', '_results']

    def __init__(self, attribute_view, explanations):
        by_oid = OrderedDict()
        for item in attribute_view:
            by_oid.setdefault(item.type_oid, []).append(item)

        results = []
        for explanation in explanations:
            matches = by_oid.get(explanation.type_oid, [])
            if matches:
                attribute_evidence = matches[0]
                statuses = list(attribute_evidence.statuses)
                if len(matches) > 1 and STATUS_DUPLICATE not in statuses:
                    statuses.append(STATUS_DUPLICATE)
                results.append(ExplanationEvidence(explanation, statuses, attribute_evidence))
            else:
                results.append(ExplanationEvidence(explanation, [STATUS_UNLOCATED]))
        self._attribute_view = attribute_view
        self._results = tuple(results)

    def __repr__(self):
        return 'ExplanationEvidenceView(verifiable=%d, unlocated=%d)' % (
            len(self.verifiable),
            len(self.unlocated),
        )

    def __iter__(self):
        return iter(self._results)

    def __len__(self):
        return len(self._results)

    def __getitem__(self, index):
        return self._results[index]

    @property
    def attribute_view(self):
        """
        :return:
            The underlying :class:`AttributeEvidenceView`
        """
        return self._attribute_view

    @property
    def verifiable(self):
        """
        :return:
            A tuple of explanations backed by signed bytes
        """
        return tuple(item for item in self._results if item.verifiable)

    @property
    def unlocated(self):
        """
        :return:
            A tuple of explanations with no provenance in the packet
        """
        return tuple(item for item in self._results if not item.verifiable)


def _resolve_oid(type_field):
    """
    Returns both the dotted OID and the semantic name (or dotted OID when the
    field is unknown) for a parsed CMSAttributeType.
    """
    dotted = type_field.dotted
    mapped = CMSAttributeType._map.get(dotted)
    if mapped is None:
        return dotted, dotted
    return dotted, mapped


def _signed_attr_offsets(data, signer_infos):
    """
    Returns a list with the absolute packet offset of each signer's encoded
    signed attribute set, in signer order. A single forward scan is used so
    that byte-identical sets from different signers each get their own offset.
    """
    offsets = []
    cursor = 0
    for signer in signer_infos:
        encoded = signer['signed_attrs'].dump()
        offset = data.find(encoded, cursor)
        if offset < 0:
            offset = data.find(encoded)
            if offset < 0:
                raise ValueError(unwrap(
                    '''
                    Could not locate the signed attributes of one of the
                    signers within the packet bytes
                    '''
                ))
        offsets.append(offset)
        # Advance past this occurrence to keep the scan monotonic.
        cursor = offset + len(encoded)
    return offsets


def _build_evidence_for_signer(data, bounds, signer_index, signer, set_offset):
    """
    Builds an AttributeEvidenceView for one SignerInfo, locating every signed
    attribute in the original packet bytes.
    """
    signed_attrs = signer['signed_attrs']
    set_encoded = signed_attrs.dump()
    set_end = set_offset + len(set_encoded)
    set_location = ByteLocation(
        set_offset,
        len(set_encoded),
        bounds,
        header_length=len(signed_attrs._header or b''),
        trailer_length=len(signed_attrs._trailer or b''),
    )

    # The signed attribute SET is DER encoded; walking its region gives every
    # attribute TLV an unambiguous location even when values repeat elsewhere
    # in the envelope.
    region_nodes = _walk_der(data, set_offset, set_end)
    attribute_nodes = [
        node for node in region_nodes
        if node[0] == 16 and node[1] == 1
    ]

    # Canonical DER of the whole set is used to detect layout changes such as
    # DER re-sorting of an out-of-order SET OF.
    canonical_set = signed_attrs.dump(force=True)
    set_relocated = canonical_set != set_encoded

    # Walk the canonical encoding once, then map each canonical attribute to
    # its type OID. Canonical DER sorts SET OF members, so canonical positions
    # do not correspond to parsed (wire) positions; matching by OID keeps the
    # two coordinate systems honest. Duplicate OIDs are kept in order.
    canonical_by_oid = OrderedDict()
    canonical_occurrence = {}
    if set_relocated:
        canonical_nodes = _walk_der(canonical_set, 0, len(canonical_set))
        canonical_attribute_nodes = [
            node for node in canonical_nodes
            if node[0] == 16 and node[1] == 1
        ]
        for node in canonical_attribute_nodes:
            node_start, node_end = node[2], node[3]
            node_bytes = canonical_set[node_start:node_end]
            parsed_node = CMSAttribute.load(node_bytes)
            node_oid = parsed_node['type'].dotted
            canonical_by_oid.setdefault(node_oid, []).append(node)

    seen_oids = set()
    evidence = []
    for index, attribute in enumerate(signed_attrs):
        type_oid, type_name = _resolve_oid(attribute['type'])
        encoded = attribute.dump()

        node = None
        if index < len(attribute_nodes):
            candidate = attribute_nodes[index]
            if data[candidate[2]:candidate[3]] == encoded:
                node = candidate
        if node is None:
            # Fall back to a unique full-bytes match inside the attribute set
            located = _locate_tlv(data, encoded, set_offset, set_end)
            if located is not None:
                node = (16, 1, located[0], located[1], located[2], located[3])
        if node is None:
            raise ValueError(unwrap(
                '''
                Could not uniquely locate signed attribute %d (type %s) in
                the packet bytes
                ''',
                index,
                type_oid
            ))

        location = ByteLocation(
            node[2],
            node[3] - node[2],
            bounds,
            header_length=node[4],
            trailer_length=node[5],
        )

        statuses = [STATUS_ORIGINAL]
        if type_oid not in CMSAttributeType._map:
            statuses.append(STATUS_UNKNOWN)
        if type_oid in seen_oids:
            statuses.append(STATUS_DUPLICATE)
        seen_oids.add(type_oid)

        canonical_location = None
        canonical_bytes = None
        occurrence = canonical_occurrence.get(type_oid, 0)
        canonical_occurrence[type_oid] = occurrence + 1
        canonical_candidates = canonical_by_oid.get(type_oid, [])
        if set_relocated and occurrence < len(canonical_candidates):
            canonical_node = canonical_candidates[occurrence]
            # Canonical nodes are offsets in the canonical buffer. The outer
            # implicit tag header occupies the same number of bytes as the
            # original set header, so add the original set start to map back
            # onto an absolute packet offset.
            canonical_abs_offset = set_offset + canonical_node[2]
            canonical_location = ByteLocation(
                canonical_abs_offset,
                canonical_node[3] - canonical_node[2],
                bounds,
                header_length=canonical_node[4],
                trailer_length=canonical_node[5],
            )
            canonical_bytes = canonical_set[canonical_node[2]:canonical_node[3]]
            if (canonical_location.offset != location.offset or
                    canonical_location.length != location.length or
                    canonical_bytes != encoded):
                statuses.append(STATUS_RELOCATED)

        evidence.append(AttributeEvidence(
            index=index,
            attribute=attribute,
            location=location,
            statuses=statuses,
            type_oid=type_oid,
            type_name=type_name,
            canonical_location=canonical_location,
            original_bytes=encoded,
            canonical_bytes=canonical_bytes,
        ))

    return AttributeEvidenceView(
        data=data,
        bounds=bounds,
        signer_index=signer_index,
        set_location=set_location,
        evidence=evidence,
    )


def evidence_for_packet(packet, signer_index=0, explanations=None):
    """
    Builds a read-only evidence view for the signed attributes in a CMS
    ContentInfo packet.

    The packet is parsed but never modified. Every signed attribute is tied to
    its original byte location and the packet boundaries, and each entry is
    flagged for duplicates, unknown fields and canonical-DER relocation. When
    explanations are supplied, each one is either linked to the bytes it can
    be verified against, or reported as lacking provenance.

    :param packet:
    A byte string of a DER/BER-encoded CMS ContentInfo, or an already
    parsed :class:`cms.ContentInfo`. Passing a bare ContentInfo re-encodes it
    to DER for locating, so BER indefinite-length boundaries are normalized;
    pass the raw bytes (or a ``(content_info, raw_bytes)`` tuple) to preserve
    the original boundaries.

    :param signer_index:
        The zero-based index of the signer to inspect. Defaults to the first
        signer.

    :param explanations:
        An optional iterable of :class:`AttributeExplanation` objects to
        cross-check against the signed bytes

    :raises:
        TypeError - when packet or explanations have the wrong type
        ValueError - when the packet is not signed CMS, the signer index is
            invalid, or an attribute cannot be located in the packet bytes

    :return:
        An :class:`ExplanationEvidenceView` when explanations are given,
        otherwise an :class:`AttributeEvidenceView`
    """
    if isinstance(packet, tuple):
        if len(packet) != 2 or not isinstance(packet[0], ContentInfo) or not isinstance(packet[1], byte_cls):
            raise TypeError(unwrap(
                '''
                packet tuple must be (ContentInfo, byte string), not %r
                ''',
                packet
            ))
        content_info, raw = packet
    elif isinstance(packet, byte_cls):
        raw = packet
        content_info = ContentInfo.load(raw)
    elif isinstance(packet, ContentInfo):
        content_info = packet
        raw = content_info.dump()
    else:
        raise TypeError(unwrap(
            '''
            packet must be a byte string or ContentInfo, not %s
            ''',
            type_name(packet)
        ))

    if content_info['content_type'].native != 'signed_data':
        raise ValueError(unwrap(
            '''
            Evidence views are only available for signed_data CMS packets, not
            %s
            ''',
            content_info['content_type'].native
        ))

    signed_data = content_info['content']
    signer_infos = signed_data['signer_infos']
    if not isinstance(signer_index, int) or signer_index < 0 or signer_index >= len(signer_infos):
        raise ValueError(unwrap(
            '''
            signer_index %d is out of range for %d signer(s)
            ''',
            signer_index,
            len(signer_infos)
        ))

    signer = signer_infos[signer_index]
    if signer['signed_attrs'] is VOID:
        raise ValueError(unwrap(
            '''
            Signer %d has no signed attributes to build evidence from
            ''',
            signer_index
        ))

    # The packet boundary is the whole ContentInfo. A BER indefinite-length
    # outer encoding retains an end-of-contents trailer; record it so reviewers
    # know the original was not DER even though the signed attributes are.
    indefinite = bool(content_info._trailer)
    bounds = PacketBounds(len(raw), 0, len(raw), indefinite=indefinite)

    set_offsets = _signed_attr_offsets(raw, signer_infos)
    attribute_view = _build_evidence_for_signer(
        raw,
        bounds,
        signer_index,
        signer,
        set_offsets[signer_index]
    )

    if explanations is None:
        return attribute_view

    explanations = list(explanations)
    for explanation in explanations:
        if not isinstance(explanation, AttributeExplanation):
            raise TypeError(unwrap(
                '''
                explanations must contain AttributeExplanation objects, not %s
                ''',
                type_name(explanation)
            ))
    return ExplanationEvidenceView(attribute_view, explanations)
