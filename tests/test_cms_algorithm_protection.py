# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest

from asn1crypto import algos, cms, cms_algorithm_protection, core, pem

from .cms_algorithm_protection_samples import sample_set
from ._unittest_compat import patch


patch()


EXPECTED = {
    'signed_protected': ('protected', 'migrate'),
    'signed_legacy_unprotected': ('unprotected', 'supplement'),
    'signed_unsigned_only': ('unauthenticated', 'supplement'),
    'signed_duplicate_attribute': ('duplicate', 'supplement'),
    'signed_duplicate_value': ('duplicate', 'supplement'),
    'signed_protected_unauth_copy': ('duplicate', 'supplement'),
    'signed_algorithm_mismatch': ('algorithm_mismatch', 'supplement'),
    'signed_parameter_mismatch': ('parameter_mismatch', 'supplement'),
    'signed_missing_signature_component': ('malformed', 'supplement'),
    'signed_unsupported_parameters': ('indeterminate', 'manual_review'),
    'signed_null_vs_absent': ('protected', 'migrate'),
    'signed_alias_equivalent': ('protected', 'migrate'),
    'signed_generic_rsa_equivalent': ('protected', 'migrate'),
    'signed_pss_defaults_equivalent': ('protected', 'migrate'),
    'authenticated_data_protected': ('protected', 'migrate'),
    'authenticated_data_unauth_only': ('unauthenticated', 'supplement'),
    'authenticated_data_mac_mismatch': ('algorithm_mismatch', 'supplement'),
}


class CMSAlgorithmProtectionTests(unittest.TestCase):

    def _review(self, name):
        content_info = sample_set()[name]
        der = content_info.dump()
        # Every sample must survive an in-memory DER round trip before it is
        # reviewed, so the tests exercise the same path as a real ledger file.
        reloaded = cms.ContentInfo.load(der)
        return cms_algorithm_protection.review(reloaded), der

    def test_sample_round_trip_and_classification(self):
        samples = sample_set()
        for name in EXPECTED:
            self.assertIn(name, samples)
            review, _ = self._review(name)
            self.assertEqual(1, len(review.results), name)
            result = review.results[0]
            expected_status, expected_verdict = EXPECTED[name]
            self.assertEqual(expected_status, result.status, name)
            self.assertEqual(expected_verdict, result.verdict, name)

    def test_identity_and_attribute_path_are_locatable(self):
        review, _ = self._review('signed_protected')
        result = review.results[0]
        self.assertEqual('issuer_and_serial_number', result.identity['type'])
        self.assertEqual(1, result.identity['serial_number'])
        self.assertEqual(1, len(result.attribute_locations))
        self.assertTrue(result.attribute_locations[0]['authenticated'])
        self.assertEqual('signed_attrs', result.attribute_locations[0]['location'])
        self.assertTrue(result.attribute_locations[0]['path'].startswith('signer_infos[0].signed_attrs['))
        self.assertEqual(1, result.attribute_locations[0]['value_count'])

    def test_unprotected_legacy_is_not_a_conflict(self):
        review, _ = self._review('signed_legacy_unprotected')
        result = review.results[0]
        self.assertEqual('unprotected', result.status)
        self.assertEqual('missing_protection_attribute', result.issues[0]['code'])
        self.assertNotEqual('algorithm_mismatch', result.status)
        self.assertNotEqual('parameter_mismatch', result.status)

    def test_unauthenticated_location_is_rejected(self):
        review, _ = self._review('signed_unsigned_only')
        result = review.results[0]
        self.assertEqual('unauthenticated', result.status)
        self.assertEqual('unsigned_attrs', result.attribute_locations[0]['location'])
        self.assertFalse(result.attribute_locations[0]['authenticated'])
        self.assertEqual('unauthenticated_location', result.issues[0]['code'])

    def test_duplicate_attribute_and_duplicate_value_are_distinct(self):
        duplicate_attr, _ = self._review('signed_duplicate_attribute')
        duplicate_value, _ = self._review('signed_duplicate_value')
        self.assertEqual('duplicate_attribute', duplicate_attr.results[0].issues[0]['code'])
        self.assertEqual('duplicate_attribute_value', duplicate_value.results[0].issues[0]['code'])

    def test_same_name_different_parameters_is_a_parameter_conflict(self):
        review, _ = self._review('signed_parameter_mismatch')
        result = review.results[0]
        self.assertEqual('parameter_mismatch', result.status)
        self.assertEqual('signature_parameter_mismatch', result.issues[0]['code'])
        reasons = [check.reason for check in result.checks]
        self.assertTrue(any('salt_length' in reason for reason in reasons))

    def test_uninterpretable_parameters_are_manual_review(self):
        review, _ = self._review('signed_unsupported_parameters')
        result = review.results[0]
        self.assertEqual('indeterminate', result.status)
        self.assertEqual('manual_review', result.verdict)
        self.assertTrue(any('interpret' in issue['message'] for issue in result.issues))

    def test_null_and_absent_parameters_are_equivalent(self):
        review, _ = self._review('signed_null_vs_absent')
        result = review.results[0]
        self.assertEqual('protected', result.status)
        self.assertEqual('migrate', result.verdict)
        signatures = [check for check in result.checks if check.role == 'signature']
        self.assertEqual('equivalent', signatures[0].status)
        self.assertIn('legacy CMS files', signatures[0].reason)
        self.assertTrue(any('legacy CMS files' in note for note in result.notes))

    def test_oid_alias_is_explained_as_equivalent(self):
        review, _ = self._review('signed_alias_equivalent')
        result = review.results[0]
        self.assertEqual('protected', result.status)
        self.assertTrue(any('OID alias' in note for note in result.notes))

    def test_generic_and_digest_specific_signature_oids_are_equivalent(self):
        review, _ = self._review('signed_generic_rsa_equivalent')
        result = review.results[0]
        self.assertEqual('protected', result.status)
        self.assertTrue(any('generic RSA PKCS#1 v1.5 OID' in note for note in result.notes))

    def test_pss_defaults_are_equivalent(self):
        review, _ = self._review('signed_pss_defaults_equivalent')
        result = review.results[0]
        self.assertEqual('protected', result.status)
        self.assertTrue(any('ASN.1 defaults' in check.reason for check in result.checks))

    def test_authenticated_data_is_reviewed_independently(self):
        review, _ = self._review('authenticated_data_protected')
        self.assertEqual('authenticated_data', review.content_type)
        self.assertEqual(1, len(review.authenticated_data))
        self.assertEqual('authenticated_data', review.results[0].kind)
        self.assertEqual('auth_attrs', review.results[0].attribute_locations[0]['location'])
        self.assertEqual('protected', review.results[0].status)

    def test_authenticated_data_mac_mismatch(self):
        review, _ = self._review('authenticated_data_mac_mismatch')
        result = review.results[0]
        self.assertEqual('algorithm_mismatch', result.status)
        self.assertEqual('mac_algorithm_mismatch', result.issues[0]['code'])

    def test_mixed_ledger_shows_who_can_migrate(self):
        review, _ = self._review('signed_mixed_ledger')
        self.assertEqual(2, len(review.results))
        self.assertEqual(1, review.summary['migrate'])
        self.assertEqual(1, review.summary['supplement'])
        self.assertEqual(0, review.summary['manual_review'])
        by_common_name = {}
        for result in review.results:
            issuer = result.identity['issuer']
            by_common_name[issuer['common_name']] = result.verdict
        self.assertEqual('migrate', by_common_name['Ivan'])
        self.assertEqual('supplement', by_common_name['Judy'])
        text = review.format_text()
        self.assertIn('Ivan', text)
        self.assertIn('Judy', text)
        self.assertIn('migrate', text)
        self.assertIn('supplement', text)

    def test_der_and_pem_bytes_are_accepted(self):
        content_info = sample_set()['signed_protected']
        der = content_info.dump()
        from_der = cms_algorithm_protection.review(der)
        from_pem = cms_algorithm_protection.review(pem.armor('CMS', der))
        self.assertEqual('protected', from_der.results[0].status)
        self.assertEqual('protected', from_pem.results[0].status)

    def test_direct_signer_and_authenticated_data_objects(self):
        content_info = sample_set()['signed_protected']
        signed_data = content_info['content']
        signer = signed_data['signer_infos'][0]
        result = cms_algorithm_protection.review_signer_info(signer)
        self.assertEqual('protected', result.status)
        self.assertEqual('protected', signer.algorithm_protection_review().status)
        self.assertEqual('protected', cms.review_algorithm_protection(signed_data).results[0].status)
        self.assertEqual('protected', content_info.review_algorithm_protection().results[0].status)

        authenticated_data = sample_set()['authenticated_data_protected']['content']
        result = cms_algorithm_protection.review_authenticated_data(authenticated_data)
        self.assertEqual('protected', result.status)
        self.assertEqual('protected', authenticated_data.algorithm_protection_review().status)

    def test_compare_algorithm_identifiers_public_helper(self):
        left_digest = algos.DigestAlgorithm.load(
            b'\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
        )
        right_digest = algos.DigestAlgorithm({
            'algorithm': 'sha256',
            'parameters': core.Null(),
        })
        comparison = cms_algorithm_protection.compare_algorithm_identifiers(
            left_digest,
            right_digest,
            'digest',
        )
        self.assertEqual('equivalent', comparison.status)
        self.assertTrue(comparison.equivalent)

    def test_signature_and_mac_verification_is_not_performed(self):
        review, _ = self._review('signed_protected')
        self.assertFalse(review.native['signature_verified'])
        self.assertEqual('not_performed', review.native['verification'])
        self.assertFalse(review.results[0].native['signature_verified'])


if __name__ == '__main__':
    unittest.main()
