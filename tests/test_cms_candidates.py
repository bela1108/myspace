# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest

from asn1crypto import cms, x509
from ._unittest_compat import patch


patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures', 'cms-signer-candidates')
keys_dir = os.path.join(tests_root, 'fixtures', 'keys')


def load_content_info(name):
    with open(os.path.join(fixtures_dir, name), 'rb') as f:
        return cms.ContentInfo.load(f.read())


def load_certificate(name):
    with open(os.path.join(keys_dir, name), 'rb') as f:
        return x509.Certificate.load(f.read())


class CertificateCandidateTests(unittest.TestCase):

    def test_issuer_serial_duplicate_candidate(self):
        report = cms.get_signer_certificates(load_content_info('issuer-serial-duplicate.der'))

        self.assertEqual(1, len(report['outer']))
        signer = report['outer'][0]
        self.assertEqual('duplicate_certificate', signer['status'])
        self.assertEqual('duplicate', signer['state'])
        self.assertEqual('issuer_and_serial_number', signer['sid_type'])
        self.assertEqual(2, len(signer['candidates']))
        self.assertEqual([0, 1], [candidate['certificate_index'] for candidate in signer['candidates']])
        self.assertTrue(all(candidate['duplicate'] for candidate in signer['candidates']))
        self.assertFalse(any(candidate['conflict'] for candidate in signer['candidates']))

        self.assertEqual(1, len(report['duplicates']))
        self.assertEqual(2, report['duplicates'][0]['count'])
        self.assertEqual([], report['conflicts'])
        self.assertEqual([], report['nested'])

    def test_subject_key_identifier_conflict_candidate(self):
        report = cms.get_signer_certificates(load_content_info('ski-conflict.der'))

        signer = report['outer'][0]
        self.assertEqual('certificate_conflict', signer['status'])
        self.assertEqual('conflict', signer['state'])
        self.assertEqual('subject_key_identifier', signer['sid_type'])
        self.assertEqual(2, len(signer['candidates']))
        self.assertTrue(all(candidate['subject_key_identifier_match'] for candidate in signer['candidates']))
        self.assertTrue(all(candidate['conflict'] for candidate in signer['candidates']))
        self.assertEqual([], report['duplicates'])

        conflicts = report['conflicts']
        self.assertEqual(1, len(conflicts))
        self.assertEqual('subject_key_identifier', conflicts[0]['identifier_type'])
        self.assertEqual(2, conflicts[0]['distinct_certificate_count'])

    def test_nested_missing_certificate_is_separate(self):
        report = cms.get_signer_certificates(load_content_info('nested-missing.der'))

        self.assertEqual(1, len(report['outer']))
        self.assertEqual(1, len(report['nested']))

        outer = report['outer'][0]
        nested = report['nested'][0]
        self.assertEqual('ok', outer['status'])
        self.assertEqual(1, len(outer['candidates']))
        self.assertEqual('missing_certificate', nested['status'])
        self.assertEqual([], nested['candidates'])
        self.assertTrue(nested['missing_certificate'])
        self.assertEqual(1, nested['depth'])
        self.assertEqual([0, 0], nested['layer_path'])
        self.assertIn('microsoft_nested_signature', nested['layer_id'])
        self.assertEqual(0, nested['signer_index'])
        self.assertEqual('outer', outer['candidates'][0]['layer'])
        self.assertEqual(0, outer['candidates'][0]['signer_index'])

        self.assertEqual(1, len(report['missing']))
        self.assertIs(nested, report['missing'][0])
        self.assertNotIn(outer, report['nested'])

    def test_identifier_checks_are_available_separately(self):
        certificate = load_certificate('test-der.crt')
        issuer_serial_sid = {
            'issuer_and_serial_number': {
                'issuer': certificate.issuer,
                'serial_number': certificate.serial_number,
            }
        }
        ski_sid = {'subject_key_identifier': certificate.key_identifier}
        issuer_serial_signer = cms.SignerInfo({
            'version': 'v1',
            'sid': issuer_serial_sid,
            'digest_algorithm': {'algorithm': 'sha256'},
            'signature_algorithm': {'algorithm': 'sha256_rsa'},
            'signature': b'\x01',
        })
        ski_signer = cms.SignerInfo({
            'version': 'v1',
            'sid': ski_sid,
            'digest_algorithm': {'algorithm': 'sha256'},
            'signature_algorithm': {'algorithm': 'sha256_rsa'},
            'signature': b'\x01',
        })

        self.assertTrue(issuer_serial_signer.issuer_serial_matches(certificate))
        self.assertFalse(issuer_serial_signer.subject_key_identifier_matches(certificate))
        self.assertFalse(ski_signer.issuer_serial_matches(certificate))
        self.assertTrue(ski_signer.subject_key_identifier_matches(certificate))
        self.assertTrue(issuer_serial_signer.matches_certificate(certificate))
        self.assertTrue(ski_signer.matches_certificate(certificate))

        candidates = ski_signer.certificate_candidates([certificate])
        self.assertEqual(1, len(candidates))
        self.assertEqual('subject_key_identifier', candidates[0]['match'])
        self.assertIs(certificate, candidates[0]['certificate'])

    def test_report_aliases_and_signature(self):
        content_info = load_content_info('issuer-serial-duplicate.der')
        report = content_info['content'].signer_certificate_candidates()

        self.assertIs(report['outer'], report['outer_signers'])
        self.assertIs(report['nested'], report['nested_signers'])
        self.assertIs(report['signers'], report['all_signers'])
        self.assertIs(report['duplicates'], report['duplicate_certificates'])
        self.assertIs(report['conflicts'], report['certificate_conflicts'])


if __name__ == '__main__':
    unittest.main()
