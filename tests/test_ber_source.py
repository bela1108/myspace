# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest

from asn1crypto import core


class ArchiveInner(core.Sequence):
    _fields = [
        ('text', core.UTF8String),
        ('counter', core.Integer),
    ]


class ArchiveRecord(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('digest', core.OctetString),
        ('payload', ArchiveInner),
        ('retain', core.Integer, {'default': 1}),
    ]


class OneInteger(core.Sequence):
    _fields = [
        ('value', core.Integer),
    ]


class OneBoolean(core.Sequence):
    _fields = [
        ('value', core.Boolean),
    ]


class IntegerList(core.SequenceOf):
    _child_spec = core.Integer


class IntegerSet(core.Set):
    _fields = [
        ('a', core.Integer),
        ('b', core.UTF8String),
    ]


# The two controls encode exactly the same ArchiveRecord value. The first
# uses definite lengths throughout and explicitly encodes the DEFAULT field.
# The second uses legal BER indefinite lengths and constructed strings.
DEFINITE_HEX = (
    '301402010104040102030430060c0161020107020101'
)
INDEFINITE_HEX = (
    '3080020101248004020102040203040000'
    '30802c800c01610c0000000201070000'
    '0201010000'
)
CANONICAL_WITHOUT_DEFAULT_HEX = (
    '301102010104040102030430060c0161020107'
)


def _load_hex(value, spec=None, **kwargs):
    context = core.ParseContext(bytes.fromhex(value), **kwargs)
    return context, context.load(spec=spec)


class BERByteSourceTests(unittest.TestCase):

    def test_byte_source_is_read_only(self):
        source = core.ByteSource(b'abcdef', 1, 3)
        self.assertEqual(b'bcd', source.data)
        self.assertEqual(1, source.offset)
        self.assertEqual(4, source.end)
        self.assertEqual(b'cd', source.view(1).data)
        self.assertEqual(b'bc', bytes(source.slice(0, 2)))
        self.assertTrue(source.memoryview.readonly)
        self.assertTrue(source.read_only)

        with self.assertRaises(TypeError):
            source[0] = 0x41
        with self.assertRaises(TypeError):
            source.write(b'x')
        with self.assertRaises(TypeError):
            source.memoryview[0] = 0x41

    def test_value_and_raw_bytes_are_separate_results(self):
        ctx_der, der_value = _load_hex(DEFINITE_HEX, ArchiveRecord)
        ctx_ber, ber_value = _load_hex(INDEFINITE_HEX, ArchiveRecord)

        result = der_value.compare(ber_value)
        self.assertTrue(result.value_equal)
        self.assertFalse(result.bytes_equal)
        self.assertTrue(result.values_equal)
        self.assertFalse(result.raw_bytes_equal)
        self.assertEqual(
            {'value_equal': True, 'bytes_equal': False, 'evidence': result.evidence},
            result.as_dict()
        )

        # The same two answers are available without constructing a context
        self.assertTrue(der_value.value_equal(ber_value))
        self.assertFalse(der_value.bytes_equal(ber_value))

        # The DER form and the omitted-default form are semantically equal
        ctx_omitted, omitted_value = _load_hex(CANONICAL_WITHOUT_DEFAULT_HEX, ArchiveRecord)
        self.assertTrue(der_value.value_equal(omitted_value))
        self.assertFalse(der_value.bytes_equal(omitted_value))

        self.assertTrue(ctx_der.root.value_equal(ctx_ber.root))
        self.assertFalse(ctx_der.root.bytes_equal(ctx_ber.root))

    def test_deep_reads_never_replace_the_source(self):
        data = bytes.fromhex(INDEFINITE_HEX)
        context = core.ParseContext(data)
        value = context.load(spec=ArchiveRecord)

        before_context = context.bytes
        before_root = value.raw_bytes
        before_dump = value.dump()
        before_digest = value['digest'].raw_bytes
        before_payload = value['payload'].raw_bytes

        # Force lazy child parsing at several depths
        self.assertEqual(b'', value['digest'].native)
        self.assertEqual('a', value['payload']['text'].native)
        self.assertEqual(7, value['payload']['counter'].native)
        self.assertEqual(1, value['retain'].native)

        self.assertEqual(before_context, context.bytes)
        self.assertEqual(before_root, value.raw_bytes)
        self.assertEqual(before_dump, value.dump())
        self.assertEqual(before_digest, value['digest'].raw_bytes)
        self.assertEqual(before_payload, value['payload'].raw_bytes)

        # Every parsed node points back into the original, read-only source
        self.assertEqual(0, value.source.offset)
        self.assertEqual(len(data), value.source.end)
        self.assertEqual(2, value['version'].source.offset)
        self.assertEqual(5, value['digest'].source.offset)
        self.assertEqual(17, value['payload'].source.offset)
        self.assertEqual(19, value['payload']['text'].source.offset)
        self.assertEqual(33, value['retain'].source.offset)
        self.assertEqual(('payload', 'text'), value['payload']['text'].path)

        # A forced DER re-encoding is available, but it does not alter either
        # the retained raw bytes or the context's byte source.
        normalized = value.dump(force=True)
        self.assertNotEqual(data, normalized)
        self.assertEqual(data, context.bytes)
        self.assertEqual(data, value.raw_bytes)
        self.assertEqual(before_digest, value['digest'].raw_bytes)

    def test_explicit_default_is_locatable_evidence(self):
        context, value = _load_hex(DEFINITE_HEX, ArchiveRecord)
        defaults = context.explicit_defaults
        self.assertEqual(1, len(defaults))
        evidence = defaults[0]
        self.assertEqual(core.ParseEvidence.EXPLICIT_DEFAULT, evidence.kind)
        self.assertEqual(('retain',), evidence.path)
        self.assertEqual(bytes.fromhex('020101'), evidence.data)
        self.assertEqual(19, evidence.offset)
        self.assertEqual(22, evidence.end)
        self.assertEqual(bytes.fromhex('020101'), value['retain'].raw_bytes)

        # The explicit default is dropped by a forced DER encoding
        self.assertEqual(bytes.fromhex('3003020101')[-3:], value['retain'].dump(force=True))

    def test_alternate_encodings_are_locatable_evidence(self):
        context, value = _load_hex(INDEFINITE_HEX, ArchiveRecord)
        reasons = set(item.reason for item in context.alternate_encodings)
        self.assertIn(core.ParseEvidence.INDEFINITE_LENGTH, reasons)
        self.assertIn(core.ParseEvidence.CONSTRUCTED_STRING, reasons)

        digest_evidence = context.find_evidence(path=('digest',))
        self.assertTrue(any(item.kind == core.ParseEvidence.ALTERNATE_ENCODING for item in digest_evidence))
        self.assertEqual(bytes.fromhex('248004020102040203040000'), value['digest'].raw_bytes)

    def test_uninterpreted_children_and_any(self):
        class OneField(core.Sequence):
            _fields = [
                ('value', core.Integer),
            ]

        data = bytes.fromhex('3006020101040141')
        context = core.ParseContext(data)
        value = context.load(spec=OneField)

        self.assertEqual(b'A', value[1].native)
        self.assertEqual(('1',), value[1].path)
        evidence = [item for item in context.evidence if item.kind == core.ParseEvidence.UNINTERPRETED]
        self.assertEqual(1, len(evidence))
        self.assertEqual(bytes.fromhex('040141'), evidence[0].data)
        self.assertEqual(5, evidence[0].offset)

        class OneAny(core.Sequence):
            _fields = [
                ('value', core.Any),
            ]

        any_data = bytes.fromhex('30072c800c01610000')
        any_context = core.ParseContext(any_data)
        any_value = any_context.load(spec=OneAny)['value']
        self.assertEqual('a', any_value.native)
        self.assertEqual('a', any_value.parsed.native)
        self.assertEqual(any_data[2:], any_value.raw_bytes)
        self.assertEqual(2, any_value.parsed.source.offset)
        self.assertTrue(any(
            item.kind == core.ParseEvidence.UNINTERPRETED and item.path == ('value',)
            for item in any_context.evidence
        ))

    def test_nonminimal_variants_still_compare_equal(self):
        # BOOLEAN TRUE encoded as 01 instead of FF
        canonical = bytes.fromhex('30030101ff')
        variant = bytes.fromhex('3003010101')
        ctx_c, v_c = _load_hex(canonical.hex(), OneBoolean)
        ctx_v, v_v = _load_hex(variant.hex(), OneBoolean)
        self.assertTrue(v_c.value_equal(v_v))
        self.assertFalse(v_c.bytes_equal(v_v))
        self.assertTrue(any(
            item.reason == core.ParseEvidence.NONCANONICAL_BOOLEAN
            for item in ctx_v.alternate_encodings
        ))

        # INTEGER 1 with a redundant leading zero
        canonical = bytes.fromhex('3003020101')
        variant = bytes.fromhex('300402020001')
        ctx_c, v_c = _load_hex(canonical.hex(), OneInteger)
        ctx_v, v_v = _load_hex(variant.hex(), OneInteger)
        self.assertTrue(v_c.value_equal(v_v))
        self.assertFalse(v_c.bytes_equal(v_v))
        self.assertTrue(any(
            item.reason == core.ParseEvidence.NONMINIMAL_INTEGER
            for item in ctx_v.alternate_encodings
        ))

        # Long-form length used for a value shorter than 128 bytes
        variant = bytes.fromhex('308103020101')
        ctx_v, v_v = _load_hex(variant.hex(), OneInteger)
        self.assertEqual(1, v_v['value'].native)
        self.assertTrue(any(
            item.reason == core.ParseEvidence.NONMINIMAL_LENGTH
            for item in ctx_v.alternate_encodings
        ))

    def test_containers_keep_child_spans(self):
        data = bytes.fromhex('31060c0161020102')
        context = core.ParseContext(data)
        value = context.load(spec=IntegerSet)
        self.assertEqual(2, value['a'].native)
        self.assertEqual('a', value['b'].native)
        self.assertEqual(5, value['a'].source.offset)
        self.assertEqual(2, value['b'].source.offset)
        self.assertEqual(('a',), value['a'].path)
        self.assertEqual(('b',), value['b'].path)

        list_data = bytes.fromhex('3006020101020102')
        list_context = core.ParseContext(list_data)
        list_value = list_context.load(spec=IntegerList)
        self.assertEqual([1, 2], [child.native for child in list_value])
        self.assertEqual([2, 5], [child.source.offset for child in list_value])
        self.assertEqual([(0,), (1,)], [child.path for child in list_value])

    def test_parse_context_accepts_spec_positionally(self):
        context = core.ParseContext(bytes.fromhex('3003020101'))
        value = context.load(OneInteger)
        self.assertEqual(1, value['value'].native)
        self.assertEqual(bytes.fromhex('3003020101'), context.bytes)


if __name__ == '__main__':
    unittest.main()
