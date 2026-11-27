# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest
from datetime import datetime

from asn1crypto import evidence, ocsp, util


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class EvidenceTests(unittest.TestCase):

    def test_disjoint_coverage_does_not_conflict(self):
        records = [
            {
                'record_id': 'before',
                'object_id': 'certificate-1',
                'coverage_domain': 'issuer-a',
                'coverage_start': '2020-01-01T00:00:00Z',
                'coverage_end': '2020-01-02T00:00:00Z',
                'observed_at': '2020-01-01T00:05:00Z',
                'status': 'good',
                'verification': {'conclusion': 'caller verified before'},
            },
            {
                'record_id': 'after',
                'object_id': 'certificate-1',
                'coverage_domain': 'issuer-a',
                'coverage_start': '2020-01-02T00:00:00Z',
                'coverage_end': '2020-01-03T00:00:00Z',
                'observed_at': '2020-01-02T00:05:00Z',
                'status': 'revoked',
                'verification': {'conclusion': 'caller verified after'},
            },
            {
                'record_id': 'other-domain',
                'object_id': 'certificate-1',
                'coverage_domain': 'issuer-b',
                'coverage_start': '2020-01-01T12:00:00Z',
                'coverage_end': '2020-01-02T12:00:00Z',
                'observed_at': '2020-01-01T12:05:00Z',
                'status': 'revoked',
            },
            {
                'record_id': 'overlap',
                'object_id': 'certificate-1',
                'coverage_domain': 'issuer-a',
                'coverage': (
                    '2020-01-01T12:00:00Z',
                    '2020-01-01T18:00:00Z',
                ),
                'observed_at': '2020-01-01T18:05:00Z',
                'status': 'revoked',
            },
        ]

        result = evidence.compare_evidence(
            records,
            verification={'conclusion': 'caller-owned, not parser-owned'}
        )

        self.assertEqual(4, len(result.records))
        self.assertEqual(1, result.conflict_count)
        self.assertEqual(1, len(result.conflicts))
        conflict = result.conflicts[0]
        self.assertEqual('certificate-1', conflict.object_id)
        self.assertEqual('issuer-a', conflict.domain)
        self.assertEqual('before', conflict.left.record_id)
        self.assertEqual('overlap', conflict.right.record_id)
        self.assertEqual(
            (
                datetime(2020, 1, 1, 12, 0, tzinfo=util.timezone.utc),
                datetime(2020, 1, 1, 18, 0, tzinfo=util.timezone.utc),
            ),
            conflict.overlap
        )
        self.assertIs(records[0], conflict.left.record)
        self.assertEqual(
            {'conclusion': 'caller verified before'},
            conflict.left.verification
        )
        self.assertEqual(
            {'conclusion': 'caller-owned, not parser-owned'},
            conflict.right.verification
        )

    def test_normalizes_coverage_observation_and_testimony(self):
        original = {
            'object_id': 'certificate-2',
            'scope': {
                'start': '2020-02-01T01:00:00+01:00',
                'end': '2020-02-01T02:00:00+01:00',
            },
            'observed_time': '2020-02-01T00:30:00Z',
            'cert_status': 'Certificate Revoked',
            'original_testimony': {'response': 'preserved verbatim'},
        }

        normalized = evidence.normalize_evidence([original])[0]

        self.assertEqual('certificate-2', normalized.object_id)
        self.assertEqual(None, normalized.domain)
        self.assertEqual('revoked', normalized.claim)
        self.assertEqual(
            {'response': 'preserved verbatim'},
            normalized.testimony
        )
        self.assertEqual(
            datetime(2020, 2, 1, 0, 0, tzinfo=util.timezone.utc),
            normalized.coverage[0]
        )
        self.assertEqual(
            datetime(2020, 2, 1, 1, 0, tzinfo=util.timezone.utc),
            normalized.coverage[1]
        )
        self.assertEqual(
            datetime(2020, 2, 1, 0, 30, tzinfo=util.timezone.utc),
            normalized.observed_at
        )
        self.assertIs(original, normalized.record)

    def test_normalizes_ocsp_single_response(self):
        with open(os.path.join(fixtures_dir, 'ocsp_response'), 'rb') as f:
            response = ocsp.OCSPResponse.load(f.read())

        result = evidence.compare_evidence(
            response,
            verification={'conclusion': 'caller verified signature'}
        )

        self.assertEqual(1, len(result.records))
        self.assertEqual(0, result.conflict_count)
        normalized = result.records[0]
        single_response = response.response_data['responses'][0]
        self.assertEqual('ocsp_response', normalized.source)
        self.assertEqual(
            single_response['cert_id']['serial_number'].native,
            normalized.object_id[0]
        )
        self.assertEqual('good', normalized.claim)
        self.assertEqual(
            single_response['this_update'].native,
            normalized.coverage[0]
        )
        self.assertEqual(
            single_response['next_update'].native,
            normalized.coverage[1]
        )
        self.assertEqual(
            {'conclusion': 'caller verified signature'},
            normalized.verification
        )

    def test_different_claims_without_overlap_coexist(self):
        result = evidence.compare_evidence([
            {
                'object_id': 'certificate-3',
                'coverage_start': '2020-03-01T00:00:00Z',
                'coverage_end': '2020-03-02T00:00:00Z',
                'status': 'good',
            },
            {
                'object_id': 'certificate-3',
                'coverage_start': '2020-03-02T00:00:00Z',
                'coverage_end': '2020-03-03T00:00:00Z',
                'status': 'unknown',
            },
        ])

        self.assertEqual((), result.conflicts)
        self.assertEqual(0, result.conflict_count)

    def test_negative_utc_offset_and_missing_claim_errors(self):
        normalized = evidence.normalize_evidence([
            {
                'object_id': 'certificate-4',
                'coverage_start': '2020-04-01T00:00:00-05:00',
                'coverage_end': '2020-04-01T01:00:00-05:00',
                'status': 'good',
            }
        ])[0]

        self.assertEqual(
            datetime(2020, 4, 1, 5, 0, tzinfo=util.timezone.utc),
            normalized.coverage[0]
        )

        with self.assertRaises(ValueError):
            evidence.normalize_evidence([{'object_id': 'certificate-5'}])

    def test_container_verification_is_preserved_for_records(self):
        record = {
            'object_id': 'certificate-6',
            'coverage_start': '2020-05-01T00:00:00Z',
            'coverage_end': '2020-05-02T00:00:00Z',
            'status': 'good',
        }
        result = evidence.normalize_evidence({
            'records': [record],
            'verification': {'conclusion': 'independent'},
        })

        self.assertEqual(
            {'conclusion': 'independent'},
            result[0].verification
        )
