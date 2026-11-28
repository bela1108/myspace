# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys
import unittest

from asn1crypto import cms, core, evidence
from asn1crypto.parser import _dump_header

from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')

CONTENT_TYPE_OID = '1.2.840.113549.1.9.3'
MESSAGE_DIGEST_OID = '1.2.840.113549.1.9.4'
SIGNING_TIME_OID = '1.2.840.113549.1.9.5'
UNKNOWN_OID = '1.2.3.4.5.6.7'
GHOST_OID = '9.9.9.9.9'


def _make_attr(type_oid, values):
    attr = cms.CMSAttribute()
    attr['type'] = cms.CMSAttributeType(type_oid)
    attr['values'] = values
    return attr


def _build_packet(attributes):
    signer = cms.SignerInfo()
    signer['version'] = 'v1'
    signer['sid'] = cms.SignerIdentifier({
        'issuer_and_serial_number': cms.IssuerAndSerialNumber({
            'issuer': cms.Name.build({}),
            'serial_number': 1,
        })
    })
    signer['digest_algorithm'] = {'algorithm': 'sha256'}
    signer['signed_attrs'] = cms.CMSAttributes(attributes)
    signer['signature_algorithm'] = {'algorithm': 'rsassa_pkcs1v15'}
    signer['signature'] = b'\x00\x01'

    signed_data = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': cms.DigestAlgorithms([{'algorithm': 'sha256'}]),
        'encap_content_info': {
            'content_type': 'data',
            'content': b'evidence',
        },
        'signer_infos': cms.SignerInfos([signer]),
    })
    content_info = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    })
    return content_info.dump()


def _standard_attributes():
    return [
        _make_attr('content_type', cms.SetOfContentType([cms.ContentType('data')])),
        _make_attr('message_digest', cms.SetOfOctetString([core.OctetString(b'\xaa\xbb')])),
        _make_attr(UNKNOWN_OID, cms.SetOfAny([core.OctetString(b'\x01')])),
        _make_attr('content_type', cms.SetOfContentType([cms.ContentType('data')])),
    ]


def _reorder_signed_attrs(packet):
    """
    Replaces the canonical signed attribute encoding with the same attributes
    in reverse wire order, without changing any of the attribute values.
    """
    parsed = cms.ContentInfo.load(packet)
    signed_attrs = parsed['content']['signer_infos'][0]['signed_attrs']
    original = signed_attrs.dump()
    children = [attr.dump() for attr in signed_attrs]
    reordered = b''.join(reversed(children))
    # signed_attrs is a SET OF with an implicit context [0] constructed tag
    rewrapped = _dump_header(2, 1, 0, reordered) + reordered
    offset = packet.find(original)
    if offset < 0:
        raise AssertionError('signed attributes not found in packet')
    return packet[:offset] + rewrapped + packet[offset + len(original):]


class PacketBoundsTests(unittest.TestCase):
    def test_bounds_are_immutable_and_relative(self):
        bounds = evidence.PacketBounds(100, 10, 90)
        self.assertEqual(100, bounds.buffer_length)
        self.assertEqual(10, bounds.start)
        self.assertEqual(90, bounds.end)
        self.assertEqual(80, bounds.length)
        self.assertEqual(35, bounds.relative_offset(45))
        self.assertTrue(bounds.contains(10, 80))
        self.assertFalse(bounds.contains(10, 81))
        self.assertFalse(bounds.indefinite)

    def test_bounds_reject_invalid_ranges(self):
        with self.assertRaises(ValueError):
            evidence.PacketBounds(10, 5, 11)
        with self.assertRaises(ValueError):
            evidence.PacketBounds(10, 8, 7)

    def test_byte_location_is_bounded_and_recovers_bytes(self):
        bounds = evidence.PacketBounds(10)
        location = evidence.ByteLocation(2, 4, bounds, header_length=1)
        self.assertEqual(2, location.offset)
        self.assertEqual(6, location.end)
        self.assertEqual(4, location.length)
        self.assertEqual(1, location.header_length)
        data = b'\x00\x01abcdefgh'
        self.assertEqual(10, len(data))
        self.assertEqual(b'abcd', location.bytes_from(data))
        with self.assertRaises(ValueError):
            evidence.ByteLocation(8, 5, bounds)
        with self.assertRaises(ValueError):
            location.bytes_from(b'\x00' * 11)


class AttributeEvidenceViewTests(unittest.TestCase):
    def setUp(self):
        self.packet = _build_packet(_standard_attributes())
        self.view = evidence.evidence_for_packet(self.packet)

    def test_locations_point_into_the_same_signed_bytes(self):
        self.assertIsInstance(self.view, evidence.AttributeEvidenceView)
        self.assertEqual(4, len(self.view))
        bounds = self.view.bounds
        self.assertEqual(len(self.packet), bounds.length)
        set_location = self.view.signed_attrs_location
        self.assertTrue(bounds.contains(set_location.offset, set_location.length))
        self.assertEqual(
            self.packet[set_location.offset:set_location.end],
            set_location.bytes_from(self.packet)
        )
        for item in self.view:
            location = item.location
            self.assertTrue(bounds.contains(location.offset, location.length))
            self.assertEqual(item.original_bytes, location.bytes_from(self.packet))
            self.assertTrue(item.verify_bytes(self.packet))
            # The location is inside the signed attribute set boundaries
            self.assertGreaterEqual(location.offset, set_location.offset)
            self.assertLessEqual(location.end, set_location.end)

    def test_duplicate_and_unknown_are_flagged(self):
        by_name = {item.type_oid: item for item in self.view if not item.duplicate}
        self.assertTrue(by_name[CONTENT_TYPE_OID].known)
        self.assertFalse(by_name[UNKNOWN_OID].known)
        self.assertEqual(evidence.STATUS_UNKNOWN, by_name[UNKNOWN_OID].statuses[-1])

        duplicates = self.view.duplicates
        self.assertEqual(1, len(duplicates))
        self.assertEqual(CONTENT_TYPE_OID, duplicates[0].type_oid)
        self.assertIn(evidence.STATUS_DUPLICATE, duplicates[0].statuses)
        self.assertEqual(2, len(self.view.by_type(CONTENT_TYPE_OID)))

        unknown = self.view.unknown
        self.assertEqual(1, len(unknown))
        self.assertEqual(UNKNOWN_OID, unknown[0].type_oid)

    def test_canonical_packet_has_no_relocation(self):
        for item in self.view:
            self.assertFalse(item.relocated)
            self.assertIsNone(item.canonical_location)
            self.assertIsNone(item.canonical_bytes)
            self.assertEqual((evidence.STATUS_ORIGINAL,), item.statuses[:1])

    def test_relocated_locations_follow_canonical_der_order(self):
        relocated_packet = _reorder_signed_attrs(self.packet)
        view = evidence.evidence_for_packet(relocated_packet)
        self.assertEqual(4, len(view.relocated))

        original_offsets = {item.type_oid: item.location.offset for item in view}
        canonical_offsets = {}
        for item in view:
            self.assertIsNotNone(item.canonical_location)
            self.assertEqual(item.location.length, item.canonical_location.length)
            self.assertNotEqual(item.location.offset, item.canonical_location.offset)
            self.assertIsNotNone(item.canonical_bytes)
            canonical_offsets.setdefault(item.type_oid, item.canonical_location.offset)

        # Canonical DER sorts by attribute encoding; the unknown OID sorts first
        ordered = sorted(canonical_offsets, key=lambda oid: canonical_offsets[oid])
        self.assertEqual(UNKNOWN_OID, ordered[0])

        # The original locations still verify against the actual packet bytes
        for item in view:
            self.assertTrue(item.verify_bytes(relocated_packet))
            self.assertEqual(item.original_bytes, item.location.bytes_from(relocated_packet))

        # Original and canonical views agree on the set of attribute values
        canonical_view = evidence.evidence_for_packet(self.packet)
        self.assertEqual(
            sorted(item.type_oid for item in canonical_view),
            sorted(item.type_oid for item in view)
        )
        self.assertEqual(original_offsets, {item.type_oid: item.location.offset for item in view})

    def test_values_are_read_only_parsed_values(self):
        item = self.view.by_type(MESSAGE_DIGEST_OID)[0]
        value = item.value
        self.assertEqual('message_digest', value['type'])
        self.assertEqual(b'\xaa\xbb', value['values'][0])
        # The view exposes the parsed object but does not provide setters
        with self.assertRaises(AttributeError):
            item.location = None


class ExplanationEvidenceViewTests(unittest.TestCase):
    def setUp(self):
        self.packet = _build_packet(_standard_attributes())
        self.explanations = [
            evidence.AttributeExplanation(
                'Content type explanation',
                CONTENT_TYPE_OID,
                expected_value='data',
                detail='Can be checked against the signed bytes',
            ),
            evidence.AttributeExplanation(
                'Explanation without provenance',
                GHOST_OID,
                detail='No attribute with this OID exists in the packet',
            ),
        ]
        self.view = evidence.evidence_for_packet(self.packet, explanations=self.explanations)

    def test_verifiable_and_unlocated_explanations_are_distinguished(self):
        self.assertIsInstance(self.view, evidence.ExplanationEvidenceView)
        self.assertEqual(2, len(self.view))

        verifiable = self.view.verifiable
        unlocated = self.view.unlocated
        self.assertEqual(1, len(verifiable))
        self.assertEqual(1, len(unlocated))

        backed = verifiable[0]
        missing = unlocated[0]
        self.assertTrue(backed.verifiable)
        self.assertFalse(missing.verifiable)
        self.assertEqual((evidence.STATUS_ORIGINAL,), backed.statuses[:1])
        self.assertEqual((evidence.STATUS_UNLOCATED,), missing.statuses)
        self.assertIsNone(missing.location)
        self.assertIsNone(missing.attribute_evidence)

        # The verifiable explanation is tied to an original, reviewable location
        self.assertEqual(CONTENT_TYPE_OID, backed.attribute_evidence.type_oid)
        self.assertIsNotNone(backed.location)
        self.assertTrue(backed.verify_bytes(self.packet))
        # An unlocated explanation can never verify against packet bytes
        self.assertFalse(missing.verify_bytes(self.packet))

    def test_duplicate_status_propagates_to_explanations(self):
        view = evidence.evidence_for_packet(
            self.packet,
            explanations=[evidence.AttributeExplanation('dup', CONTENT_TYPE_OID)]
        )
        result = view.verifiable[0]
        self.assertIn(evidence.STATUS_DUPLICATE, result.statuses)

    def test_explanations_keep_their_identity(self):
        backed, missing = list(self.view)
        self.assertEqual('Content type explanation', backed.explanation.label)
        self.assertEqual('data', backed.explanation.expected_value)
        self.assertEqual(GHOST_OID, missing.explanation.type_oid)


class EvidenceEntryPointTests(unittest.TestCase):
    def test_accepts_parsed_content_info_tuple(self):
        packet = _build_packet(_standard_attributes()[:1])
        content_info = cms.ContentInfo.load(packet)
        view = evidence.evidence_for_packet((content_info, packet))
        self.assertEqual(1, len(view))
        self.assertTrue(view[0].verify_bytes(packet))

    def test_rejects_non_signed_packet(self):
        info = cms.ContentInfo({
            'content_type': 'data',
            'content': core.OctetString(b'hello'),
        })
        with self.assertRaises(ValueError):
            evidence.evidence_for_packet(info.dump())

    def test_rejects_bad_signer_index(self):
        packet = _build_packet(_standard_attributes()[:1])
        with self.assertRaises(ValueError):
            evidence.evidence_for_packet(packet, signer_index=5)

    def test_rejects_signer_without_signed_attributes(self):
        signer = cms.SignerInfo()
        signer['version'] = 'v1'
        signer['sid'] = cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': cms.Name.build({}),
                'serial_number': 2,
            })
        })
        signer['digest_algorithm'] = {'algorithm': 'sha256'}
        signer['signature_algorithm'] = {'algorithm': 'rsassa_pkcs1v15'}
        signer['signature'] = b'\x00'
        signed_data = cms.SignedData({
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms([{'algorithm': 'sha256'}]),
            'encap_content_info': {'content_type': 'data', 'content': b'none'},
            'signer_infos': cms.SignerInfos([signer]),
        })
        packet = cms.ContentInfo({
            'content_type': 'signed_data',
            'content': signed_data,
        }).dump()
        with self.assertRaises(ValueError):
            evidence.evidence_for_packet(packet)

    def test_rejects_bad_types(self):
        with self.assertRaises(TypeError):
            evidence.evidence_for_packet(12345)
        packet = _build_packet(_standard_attributes()[:1])
        with self.assertRaises(TypeError):
            evidence.evidence_for_packet(packet, explanations=['not an explanation'])
        with self.assertRaises(TypeError):
            evidence.AttributeExplanation(b'label', CONTENT_TYPE_OID)

    def test_real_fixtures_locate_every_attribute(self):
        for fixture_name in ('cms-signed.der', 'cms-signed-indefinite-length.der'):
            with open(os.path.join(fixtures_dir, fixture_name), 'rb') as f:
                raw = f.read()
            view = evidence.evidence_for_packet(raw)
            expected_indefinite = fixture_name == 'cms-signed-indefinite-length.der'
            self.assertEqual(expected_indefinite, view.bounds.indefinite)
            parsed = cms.ContentInfo.load(raw)['content']['signer_infos'][0]['signed_attrs']
            self.assertEqual(len(parsed), len(view))
            for item in view:
                self.assertTrue(item.verify_bytes(raw))
                self.assertEqual(item.original_bytes, item.location.bytes_from(raw))

    def test_signer_index_selects_distinct_locations(self):
        def make_signer(serial, digest):
            signer = cms.SignerInfo()
            signer['version'] = 'v1'
            signer['sid'] = cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': cms.Name.build({}),
                    'serial_number': serial,
                })
            })
            signer['digest_algorithm'] = {'algorithm': 'sha256'}
            attr = _make_attr(
                MESSAGE_DIGEST_OID,
                cms.SetOfOctetString([core.OctetString(digest)])
            )
            signer['signed_attrs'] = cms.CMSAttributes([attr])
            signer['signature_algorithm'] = {'algorithm': 'rsassa_pkcs1v15'}
            signer['signature'] = b'\x00'
            return signer

        signer_one = make_signer(1, b'\xaa')
        signer_two = make_signer(2, b'\xbb')
        signed_data = cms.SignedData({
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms([{'algorithm': 'sha256'}]),
            'encap_content_info': {'content_type': 'data', 'content': b'two'},
            'signer_infos': cms.SignerInfos([signer_one, signer_two]),
        })
        packet = cms.ContentInfo({
            'content_type': 'signed_data',
            'content': signed_data,
        }).dump()

        view_zero = evidence.evidence_for_packet(packet, signer_index=0)
        view_one = evidence.evidence_for_packet(packet, signer_index=1)
        self.assertEqual(0, view_zero.signer_index)
        self.assertEqual(1, view_one.signer_index)
        self.assertNotEqual(
            view_zero[0].location.offset,
            view_one[0].location.offset
        )
        self.assertTrue(view_zero[0].verify_bytes(packet))
        self.assertTrue(view_one[0].verify_bytes(packet))

    def test_identical_signers_get_distinct_locations(self):
        def make_signer(serial):
            signer = cms.SignerInfo()
            signer['version'] = 'v1'
            signer['sid'] = cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': cms.Name.build({}),
                    'serial_number': serial,
                })
            })
            signer['digest_algorithm'] = {'algorithm': 'sha256'}
            attr = _make_attr(
                MESSAGE_DIGEST_OID,
                cms.SetOfOctetString([core.OctetString(b'\x01\x02')])
            )
            signer['signed_attrs'] = cms.CMSAttributes([attr])
            signer['signature_algorithm'] = {'algorithm': 'rsassa_pkcs1v15'}
            signer['signature'] = b'\x00'
            return signer

        signed_data = cms.SignedData({
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms([{'algorithm': 'sha256'}]),
            'encap_content_info': {'content_type': 'data', 'content': b'identical'},
            'signer_infos': cms.SignerInfos([make_signer(1), make_signer(2)]),
        })
        packet = cms.ContentInfo({
            'content_type': 'signed_data',
            'content': signed_data,
        }).dump()

        first = evidence.evidence_for_packet(packet, signer_index=0)
        second = evidence.evidence_for_packet(packet, signer_index=1)
        self.assertNotEqual(
            first.signed_attrs_location.offset,
            second.signed_attrs_location.offset
        )
        self.assertTrue(first[0].verify_bytes(packet))
        self.assertTrue(second[0].verify_bytes(packet))
