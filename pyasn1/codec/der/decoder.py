#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import warnings

from pyasn1 import error
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.streaming import readFromStream
from pyasn1.codec.cer import decoder
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

__all__ = ['decode', 'StreamingDecoder']


class BitStringPayloadDecoder(decoder.BitStringPayloadDecoder):
    supportConstructedForm = False


class OctetStringPayloadDecoder(decoder.OctetStringPayloadDecoder):
    supportConstructedForm = False


# TODO: prohibit non-canonical encoding
RealPayloadDecoder = decoder.RealPayloadDecoder


class _StrictComponentsMixin(object):
    """Strict SEQUENCE/SET rules for the DER dialect.

    BER normalization is unsafe for a verifier that compares the original
    TLV against a re-encoded object: an explicitly encoded DEFAULT value
    disappears on re-encoding, while duplicate tags, ambiguous candidate
    fields and trailing components silently overwrite or extend slots.
    Structural problems are therefore detected while the substrate is still
    raw bytes, before the half-populated container object is constructed.
    Error messages carry the component position and tag, never the value.
    """

    strictComponents = True

    @staticmethod
    def _isNonBlockingStream(substrate, length):
        # A non-blocking stream returns no bytes while data may still
        # arrive later. Probe with a single-octet non-consuming read.
        if not length:
            return False
        current = substrate.tell()
        octet = substrate.read(1)
        if octet:
            substrate.seek(current)
            return False
        substrate.seek(current)
        return True

    @staticmethod
    def _readOctet(substrate, options):
        for chunk in readFromStream(substrate, 1, options):
            if isinstance(chunk, error.SubstrateUnderrunError):
                raise chunk
        return ord(chunk)

    @classmethod
    def _readComponentHeader(cls, substrate, options):
        firstOctet = cls._readOctet(substrate, options)
        tagClass = firstOctet & 0xC0
        tagFormat = firstOctet & 0x20
        tagId = firstOctet & 0x1F

        if tagId == 0x1F:
            tagId = 0
            while True:
                octet = cls._readOctet(substrate, options)
                tagId = (tagId << 7) | (octet & 0x7F)
                if not octet & 0x80:
                    break

        firstOctet = cls._readOctet(substrate, options)
        if firstOctet < 0x80:
            length = firstOctet
        else:
            size = firstOctet & 0x7F
            length = 0
            for _ in range(size):
                length = (length << 8) | cls._readOctet(substrate, options)

        return tag.Tag(tagClass, tagFormat, tagId), length

    def _validateStrictComponents(self, substrate, length, namedTypes,
                                 options):
        originalPosition = substrate.tell()
        endPosition = originalPosition + length
        seenPositions = set()
        idx = 0
        isSetType = self.protoComponent.__class__ is univ.Set

        if isSetType:
            uniqueTagMap = namedTypes.tagMapUnique
            if isinstance(uniqueTagMap, namedtype.NamedTypes.PostponedError):
                raise error.PyAsn1Error(
                    'Ambiguous component tags in %s schema' % (
                        namedTypes,))

        while substrate.tell() < endPosition:
            componentTag, componentLength = self._readComponentHeader(
                substrate, options)
            componentTagSet = tag.TagSet((), componentTag)

            if isSetType:
                try:
                    componentPosition = namedTypes.getPositionByType(
                        componentTagSet)
                except error.PyAsn1Error:
                    raise error.PyAsn1Error(
                        'Unexpected component tag %s at position %s' % (
                            componentTagSet, idx))
            else:
                componentPosition = namedTypes.getStrictComponentPosition(
                    componentTagSet, idx)

            if componentPosition in seenPositions:
                raise error.PyAsn1Error(
                    'Duplicate component tag %s at position %s' % (
                        componentTagSet, componentPosition))

            seenPositions.add(componentPosition)
            idx = componentPosition + 1
            substrate.seek(componentLength, 1)

        missing = namedTypes.requiredComponents - seenPositions
        if missing:
            raise error.PyAsn1Error(
                'Missing required component(s) at position(s) %s' % (
                    sorted(missing),))

        substrate.seek(originalPosition)

    def _validateExplicitDefault(self, namedTypes, component, idx):
        try:
            namedType = namedTypes[idx]
        except IndexError:
            return

        if not namedType.isDefaulted:
            return

        if component == namedType.asn1Object:
            raise error.PyAsn1Error(
                'Explicitly encoded DEFAULT component at position %s '
                'with tag %s equals the schema default' % (
                    idx, component.effectiveTagSet))

    def _fillDefaultedComponents(self, asn1Object):
        asn1Object.fillDefaultedComponents()

    def _validateDecodedComponent(self, namedTypes, component, idx,
                                  seenIndices):
        # Streaming fallback for the checks the raw-bytes pre-pass performs
        # on the one-shot path. Fires before setComponentByPosition stores the
        # component, so duplicate and ambiguous tags never reach the object.
        if self.protoComponent.__class__ is univ.Set:
            componentPosition = namedTypes.getPositionByType(
                component.effectiveTagSet)
        else:
            componentPosition = namedTypes.getStrictComponentPosition(
                component.effectiveTagSet, idx)
        if componentPosition in seenIndices:
            raise error.PyAsn1Error(
                'Duplicate component tag %s at position %s' % (
                    component.effectiveTagSet, componentPosition))

    def valueDecoder(self, substrate, asn1Spec,
                     tagSet=None, length=None, state=None,
                     decodeFun=None, substrateFun=None,
                     **options):
        if (asn1Spec is not None and substrateFun is None
                and length != -1 and asn1Spec.componentType
                and not self._isNonBlockingStream(substrate, length)):
            # Fully buffered input (the one-shot Decoder() path, including
            # bytes) gets the raw-bytes structural pass before any component
            # object exists, so duplicate tags, ambiguous candidates,
            # trailing fields and truncated payloads are rejected up front.
            # A non-blocking/resumable stream cannot promise the whole
            # payload at once: the component loop below enforces the same
            # checks incrementally through _validateDecodedComponent, which
            # underruns and resumes without disturbing frame accounting.
            self._validateStrictComponents(
                substrate, length, asn1Spec.componentType, options)

        base_value_decoder = (
            ber_decoder.ConstructedPayloadDecoderBase.valueDecoder)
        for asn1Object in base_value_decoder(
                self, substrate, asn1Spec,
                tagSet=tagSet, length=length, state=state,
                decodeFun=decodeFun, substrateFun=substrateFun,
                **options):
            yield asn1Object


class SequencePayloadDecoder(
        _StrictComponentsMixin, ber_decoder.SequencePayloadDecoder):
    protoComponent = univ.Sequence()


class SetPayloadDecoder(
        _StrictComponentsMixin, ber_decoder.SetPayloadDecoder):
    protoComponent = univ.Set()


TAG_MAP = decoder.TAG_MAP.copy()
TAG_MAP.update(
    {univ.BitString.tagSet: BitStringPayloadDecoder(),
     univ.OctetString.tagSet: OctetStringPayloadDecoder(),
     univ.Real.tagSet: RealPayloadDecoder()}
)

TYPE_MAP = decoder.TYPE_MAP.copy()

# Strict SEQUENCE/SET schema-driven decoding; see _StrictComponentsMixin
TYPE_MAP[univ.Sequence.typeId] = SequencePayloadDecoder()
TYPE_MAP[univ.Set.typeId] = SetPayloadDecoder()

# Put in non-ambiguous types for faster codec lookup
for typeDecoder in TAG_MAP.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None and typeId not in TYPE_MAP:
            TYPE_MAP[typeId] = typeDecoder


class SingleItemDecoder(decoder.SingleItemDecoder):
    __doc__ = decoder.SingleItemDecoder.__doc__

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP

    supportIndefLength = False


class StreamingDecoder(decoder.StreamingDecoder):
    __doc__ = decoder.StreamingDecoder.__doc__

    SINGLE_ITEM_DECODER = SingleItemDecoder


class Decoder(decoder.Decoder):
    __doc__ = decoder.Decoder.__doc__

    STREAMING_DECODER = StreamingDecoder


#: Turns DER octet stream into an ASN.1 object.
#:
#: Takes DER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes`
#:     DER octet-stream
#:
#: Keyword Args
#: ------------
#: asn1Spec: any pyasn1 type object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A pyasn1 type object to act as a template guiding the decoder. Depending on the ASN.1 structure
#:     being decoded, *asn1Spec* may or may not be required. Most common reason for
#:     it to require is that ASN.1 structure is encoded in *IMPLICIT* tagging mode.
#:
#: Returns
#: -------
#: : :py:class:`tuple`
#:     A tuple of pyasn1 object recovered from DER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode DER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03')
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
#: Decode DER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03', asn1Spec=seq)
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
decode = Decoder()

def __getattr__(attr: str):
    if newAttr := {"tagMap": "TAG_MAP", "typeMap": "TYPE_MAP"}.get(attr):
        warnings.warn(f"{attr} is deprecated. Please use {newAttr} instead.", DeprecationWarning, stacklevel=2)
        return globals()[newAttr]
    raise AttributeError(attr)
