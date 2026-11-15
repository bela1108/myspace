#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError


def _sequence_schema():
    # SEQUENCE { place-holder NULL, first-name OCTET STRING OPTIONAL,
    #            age INTEGER DEFAULT 33 }
    return univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType('place-holder', univ.Null(b'')),
            namedtype.OptionalNamedType('first-name', univ.OctetString()),
            namedtype.DefaultedNamedType('age', univ.Integer(33)),
        )
    )


def _same_tag_schema():
    # An OPTIONAL and a DEFAULT field sharing the OCTET STRING tag.
    return univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType('place-holder', univ.Null(b'')),
            namedtype.OptionalNamedType('first-name', univ.OctetString()),
            namedtype.DefaultedNamedType('nick', univ.OctetString(b'def')),
        )
    )


class ExplicitDefaultDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.schema = _sequence_schema()

    def testExplicitDefaultIsRejected(self):
        # SEQUENCE { NULL, INTEGER 33 }: the INTEGER equals the DEFAULT.
        substrate = bytes((48, 5, 5, 0, 2, 1, 33))
        try:
            decoder.decode(substrate, asn1Spec=self.schema.clone())
        except PyAsn1Error:
            pass
        else:
            assert 0, 'explicit DEFAULT encoding tolerated'

    def testExplicitDefaultErrorCarriesPositionAndTag(self):
        substrate = bytes((48, 5, 5, 0, 2, 1, 33))
        try:
            decoder.decode(substrate, asn1Spec=self.schema.clone())
        except PyAsn1Error as exc:
            message = str(exc)
            assert 'position 2' in message, message
            assert '0:0:2' in message, message
            assert '33' not in message, 'error message leaks the field value'
        else:
            assert 0, 'explicit DEFAULT encoding tolerated'

    def testExplicitNonDefaultValueIsAccepted(self):
        # INTEGER 7 differs from the DEFAULT 33 and stays on the wire.
        substrate = bytes((48, 5, 5, 0, 2, 1, 7))
        value, rest = decoder.decode(substrate, asn1Spec=self.schema.clone())
        assert rest == b''
        assert value[2] == 7
        assert encoder.encode(value) == substrate

    def testBerStillAcceptsExplicitDefault(self):
        # BER stays lenient: historical explicit DEFAULT data decodes.
        substrate = bytes((48, 5, 5, 0, 2, 1, 33))
        value, rest = ber_decoder.decode(
            substrate, asn1Spec=self.schema.clone())
        assert rest == b''
        assert value[2] == 33

    def testSetExplicitDefaultIsRejected(self):
        schema = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.OctetString()),
                namedtype.DefaultedNamedType('age', univ.Integer(33)),
            )
        )
        # SET { OCTET STRING, INTEGER 33 } with the DEFAULT explicit.
        substrate = bytes((49, 6, 4, 1, 5, 2, 1, 33))
        try:
            decoder.decode(substrate, asn1Spec=schema.clone())
        except PyAsn1Error:
            pass
        else:
            assert 0, 'explicit SET DEFAULT encoding tolerated'


class ExplicitTaggedDefaultDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.schema = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('p', univ.Null(b'')),
                namedtype.DefaultedNamedType(
                    'big', univ.Integer(5).subtype(implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 100))),
            )
        )

    def testExplicitTaggedDefaultIsRejected(self):
        # SEQUENCE { NULL, [100] IMPLICIT INTEGER 5 } with 5 == DEFAULT.
        substrate = bytes.fromhex('300605009f640105')
        try:
            decoder.decode(substrate, asn1Spec=self.schema.clone())
        except PyAsn1Error as exc:
            assert 'position 1' in str(exc)
            assert '128:0:100' in str(exc)
        else:
            assert 0, 'explicit tagged DEFAULT tolerated'

    def testTaggedNonDefaultValueIsAccepted(self):
        substrate = bytes.fromhex('300605009f640106')
        value, rest = decoder.decode(
            substrate, asn1Spec=self.schema.clone())
        assert rest == b''
        assert value.getComponentByPosition(1, instantiate=False) == 6
        assert encoder.encode(value) == substrate

    def testMissingTaggedDefaultIsFilled(self):
        substrate = bytes.fromhex('30020500')
        value, _ = decoder.decode(
            substrate, asn1Spec=self.schema.clone())
        assert value.getComponentByPosition(1, instantiate=False) == 5
        assert encoder.encode(value) == substrate


class MissingDefaultFillTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.schema = _sequence_schema()

    def testMissingDefaultIsFilledFromSchema(self):
        # SEQUENCE { NULL }: the DEFAULT age is absent on the wire.
        substrate = bytes((48, 2, 5, 0))
        value, rest = decoder.decode(substrate, asn1Spec=self.schema.clone())
        assert rest == b''
        age = value.getComponentByPosition(2, instantiate=False)
        assert age == 33
        assert age.isValue

    def testFilledDefaultRoundTripsThroughEncoder(self):
        substrate = bytes((48, 2, 5, 0))
        value, _ = decoder.decode(substrate, asn1Spec=self.schema.clone())
        assert encoder.encode(value) == substrate

    def testOptionalStaysAbsentWhenDefaultIsFilled(self):
        substrate = bytes((48, 2, 5, 0))
        value, _ = decoder.decode(substrate, asn1Spec=self.schema.clone())
        optional = value.getComponentByPosition(1, instantiate=False)
        assert optional is univ.noValue
        age = value.getComponentByPosition(2, instantiate=False)
        assert age == 33

    def testBerKeepsMissingDefaultAbsent(self):
        substrate = bytes((48, 2, 5, 0))
        value, _ = ber_decoder.decode(
            substrate, asn1Spec=self.schema.clone())
        assert (value.getComponentByPosition(2, instantiate=False)
                is univ.noValue)

    def testNestedWireContainerDefaultsAreFilled(self):
        inner = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType('first-name', univ.OctetString()),
                namedtype.DefaultedNamedType('age', univ.Integer(33)),
            )
        )
        outer = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('inner', inner),
            )
        )
        # outer id=5, inner present with only first-name; inner age absent.
        substrate = bytes.fromhex("300a02010530050403616263")
        value, _ = decoder.decode(substrate, asn1Spec=outer.clone())
        assert (value['inner'].getComponentByPosition(1, instantiate=False)
                == 33)
        assert encoder.encode(value) == substrate

    def testAbsentConstructedDefaultStaysEqualToSchemaDefault(self):
        inner = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.DefaultedNamedType('age', univ.Integer(33)),
            )
        )
        outer = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.DefaultedNamedType('inner', inner),
            )
        )
        record = outer.clone()
        record.clear()
        record['id'] = 5
        substrate = encoder.encode(record)
        value, _ = decoder.decode(substrate, asn1Spec=outer.clone())
        # The absent constructed DEFAULT must not gain bytes on re-encode.
        assert encoder.encode(value) == substrate


class AmbiguousComponentDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.schema = _same_tag_schema()

    def testSameTagOptionalAndDefaultIsRejected(self):
        # Two OCTET STRING components, one for the OPTIONAL and one for
        # the DEFAULT field sharing the same tag.
        substrate = bytes((48, 9, 5, 0, 4, 1, 97, 4, 1, 98))
        try:
            decoder.decode(substrate, asn1Spec=self.schema.clone())
        except PyAsn1Error:
            pass
        else:
            assert 0, 'ambiguous same-tag components tolerated'

    def testAmbiguityErrorCarriesTagAndPosition(self):
        substrate = bytes((48, 9, 5, 0, 4, 1, 97, 4, 1, 98))
        try:
            decoder.decode(substrate, asn1Spec=self.schema.clone())
        except PyAsn1Error as exc:
            message = str(exc)
            assert '0:0:4' in message, message
            # Field names may appear, but the encoded component payload
            # (the single-octet strings a/b) must not.
            assert "payload" not in message, message
        else:
            assert 0, 'ambiguous same-tag components tolerated'

    def testBerDoesNotGainDerStrictnessForSingleOptional(self):
        # A single, unambiguous OPTIONAL component must remain readable by
        # the lenient BER decoder exactly as it was before the DER hardening.
        schema = _sequence_schema()
        substrate = bytes((48, 5, 5, 0, 4, 1, 97))
        value, rest = ber_decoder.decode(
            substrate, asn1Spec=schema.clone())
        assert rest == b''
        assert value['first-name'] == univ.OctetString(b'a')

    def testSingleComponentWithDistinctTagsIsAccepted(self):
        # With the ambiguous schema absent, a single OPTIONAL OCTET STRING
        # following the mandatory NULL decodes normally.
        schema = _sequence_schema()
        substrate = bytes((48, 5, 5, 0, 4, 1, 97))
        value, rest = decoder.decode(substrate, asn1Spec=schema.clone())
        assert rest == b''
        assert value['first-name'] == univ.OctetString(b'a')

    def testTwoMandatorySameTagFieldsResolveByPosition(self):
        # Two mandatory OCTET STRING fields share a tag but are ordered, so a
        # full SEQUENCE maps each component to its slot positionally.
        schema = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('attributeDesc', univ.OctetString()),
                namedtype.NamedType('assertionValue', univ.OctetString()),
            )
        )
        substrate = bytes(
            (48, 12, 4, 3, 117, 105, 100, 4, 5, 117, 115, 101, 114, 49))
        value, rest = decoder.decode(substrate, asn1Spec=schema.clone())
        assert rest == b''
        assert value['attributeDesc'] == b'uid'
        assert value['assertionValue'] == b'user1'
        assert encoder.encode(value) == substrate

    def testOptionalAndDefaultBothPresentIsRejectedBeforeBuild(self):
        # The exact attack from the hardening brief: the same-tag OPTIONAL
        # and DEFAULT fields are both stuffed into one SEQUENCE.
        schema = _same_tag_schema()
        substrate = bytes((48, 9, 5, 0, 4, 1, 97, 4, 1, 98))
        try:
            decoder.decode(substrate, asn1Spec=schema.clone())
        except PyAsn1Error as exc:
            message = str(exc)
            assert '0:0:4' in message
            assert 'position' in message
        else:
            assert 0, 'OPTIONAL and DEFAULT both present tolerated'

    def testRejectionLeavesNoHalfBuiltObjectObservable(self):
        # Every strict failure raises out of decode(); no object is returned.
        schema = _same_tag_schema()
        substrate = bytes((48, 9, 5, 0, 4, 1, 97, 4, 1, 98))
        try:
            result = decoder.decode(substrate, asn1Spec=schema.clone())
        except PyAsn1Error:
            pass
        else:
            assert 0, 'decode returned a half-built object: %r' % (result,)

    def testUnknownTagIsRejected(self):
        schema = _sequence_schema()
        # OBJECT IDENTIFIER is not part of the schema.
        substrate = bytes((48, 4, 5, 0, 6, 0))
        try:
            decoder.decode(substrate, asn1Spec=schema.clone())
        except PyAsn1Error as exc:
            assert '0:0:6' in str(exc)
        else:
            assert 0, 'unknown component tag tolerated'

    def testTrailingComponentIsRejected(self):
        schema = _sequence_schema()
        # NULL plus two INTEGER components; the second has no field.
        substrate = bytes((48, 8, 5, 0, 2, 1, 1, 2, 1, 2))
        try:
            decoder.decode(substrate, asn1Spec=schema.clone())
        except PyAsn1Error as exc:
            assert '0:0:2' in str(exc)
        else:
            assert 0, 'trailing component tolerated'

    def testMissingRequiredComponentIsRejected(self):
        schema = _sequence_schema()
        # Only the DEFAULT INTEGER, the mandatory NULL is missing.
        substrate = bytes((48, 3, 2, 1, 7))
        try:
            decoder.decode(substrate, asn1Spec=schema.clone())
        except PyAsn1Error as exc:
            assert 'position' in str(exc)
        else:
            assert 0, 'missing required component tolerated'


class StrictSetDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.schema = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.OctetString()),
                namedtype.DefaultedNamedType('age', univ.Integer(33)),
            )
        )

    def testSetMissingDefaultIsFilled(self):
        substrate = bytes((49, 3, 4, 1, 5))
        value, rest = decoder.decode(substrate, asn1Spec=self.schema.clone())
        assert rest == b''
        assert value.getComponentByPosition(1, instantiate=False) == 33
        assert encoder.encode(value) == substrate

    def testSetAmbiguousSchemaIsRejectedBeforeObjectBuild(self):
        schema = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType('a', univ.OctetString()),
                namedtype.DefaultedNamedType('b', univ.OctetString(b'x')),
            )
        )
        substrate = bytes((49, 6, 4, 1, 97, 4, 1, 98))
        try:
            decoder.decode(substrate, asn1Spec=schema.clone())
        except PyAsn1Error as exc:
            assert '0:0:4' in str(exc)
        else:
            assert 0, 'ambiguous SET schema tolerated'

    def testSetDuplicateTagIsRejected(self):
        schema = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('first', univ.Integer()),
                namedtype.NamedType('second', univ.OctetString()),
            )
        )
        # Two INTEGER encodings where only one INTEGER field exists.
        substrate = bytes((49, 6, 2, 1, 1, 2, 1, 2))
        try:
            decoder.decode(substrate, asn1Spec=schema.clone())
        except PyAsn1Error as exc:
            assert '0:0:2' in str(exc)
        else:
            assert 0, 'duplicate SET tag tolerated'


class _NonBlockingStream(io.BytesIO):
    # Alternates between "no data right now" and a real read, mimicking
    # the resumable non-blocking streams exercised in the BER suite.
    block = False

    def read(self, size=-1):
        self.block = not self.block
        if self.block:
            return
        return io.BytesIO.read(self, size)


class StreamingStrictDecoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.schema = _sequence_schema()

    def testResumableDecodeFillsDefault(self):
        stream = _NonBlockingStream(bytes((48, 2, 5, 0)))
        results = list(
            decoder.StreamingDecoder(stream, asn1Spec=self.schema.clone()))
        objects = [item for item in results
                   if not isinstance(item, SubstrateUnderrunError)]
        assert len(objects) == 1
        assert objects[0].getComponentByPosition(2, instantiate=False) == 33

    def testResumableDecodeRejectsAmbiguousComponents(self):
        stream = _NonBlockingStream(
            bytes((48, 9, 5, 0, 4, 1, 97, 4, 1, 98)))
        try:
            list(decoder.StreamingDecoder(
                stream, asn1Spec=_same_tag_schema().clone()))
        except PyAsn1Error as exc:
            assert '0:0:4' in str(exc)
        else:
            assert 0, 'resumable ambiguous input tolerated'

    def testResumableExplicitDefaultIsRejected(self):
        stream = _NonBlockingStream(bytes((48, 5, 5, 0, 2, 1, 33)))
        try:
            list(decoder.StreamingDecoder(
                stream, asn1Spec=self.schema.clone()))
        except PyAsn1Error:
            pass
        else:
            assert 0, 'resumable explicit DEFAULT tolerated'

    def testResumableSetFillsMissingDefault(self):
        set_schema = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.OctetString()),
                namedtype.DefaultedNamedType('age', univ.Integer(33)),
            )
        )
        stream = _NonBlockingStream(bytes((49, 3, 4, 1, 5)))
        results = list(decoder.StreamingDecoder(
            stream, asn1Spec=set_schema.clone()))
        objects = [item for item in results
                   if not isinstance(item, SubstrateUnderrunError)]
        assert len(objects) == 1
        assert (objects[0].getComponentByPosition(1, instantiate=False)
                == 33)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
