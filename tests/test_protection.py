import json
import unittest
from struct import pack
from unittest.mock import patch

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.protection import (
    ACTION_ARCHIVE,
    ACTION_SUPPLEMENT,
    ProtectionPolicy,
    ProtectionRecord,
    ProtectionStatus,
    build_report,
    inspect_protection,
    parse_cryptoapi_header,
    record_from_attributes,
)

DATA_DIR = 'tests/inputs'
ENCRYPTED = (
    'rc4cryptoapi_password.doc',
    'rc4cryptoapi_password.xls',
    'rc4cryptoapi_password.ppt',
)
PLAIN = ('plain.doc', 'plain.xls', 'plain.ppt')
RECORD_KEYS = {
    'source',
    'format',
    'encrypted',
    'protection_type',
    'algorithm',
    'key_size',
    'hash_algorithm',
    'spin_count',
    'provider_type',
    'parameters_known',
    'missing_parameters',
    'details',
    'status',
    'compliant',
    'action',
    'reasons',
}


def path(name):
    return '{}/{}'.format(DATA_DIR, name)


def synthetic_header(
    alg_id=0x00006801,
    alg_id_hash=0x00008004,
    key_size=128,
    provider_type=1,
    csp_name='Test Provider',
):
    fields = pack(
        '<IIIIIIII',
        0,
        0,
        alg_id,
        alg_id_hash,
        key_size,
        provider_type,
        0,
        0,
    )
    header = fields + csp_name.encode('utf-16le') + b'\x00\x00'
    return pack('<II', 0x00000004, len(header)) + header


class ProtectionInspectionTest(unittest.TestCase):
    def test_plain_files_are_plaintext(self):
        for name in PLAIN:
            with self.subTest(name=name):
                record = inspect_protection(path(name))
                self.assertEqual(record.status, ProtectionStatus.PLAINTEXT)
                self.assertFalse(record.is_encrypted)
                self.assertEqual(record.action, ACTION_ARCHIVE)
                self.assertEqual(set(record), RECORD_KEYS)
                self.assertEqual(record['format'], name.rsplit('.', 1)[1] + '97')

    def test_encrypted_legacy_files_have_public_parameters(self):
        for name in ENCRYPTED:
            with self.subTest(name=name):
                record = inspect_protection(path(name))
                self.assertEqual(record.status, ProtectionStatus.COMPLIANT)
                self.assertTrue(record.is_encrypted)
                self.assertEqual(record.protection_type, 'rc4_cryptoapi')
                self.assertEqual(record.algorithm, 'RC4')
                self.assertEqual(record.key_size, 128)
                self.assertEqual(record.hash_algorithm, 'SHA1')
                self.assertTrue(record.parameters_known)
                self.assertEqual(record.action, ACTION_ARCHIVE)
                self.assertEqual(set(record), RECORD_KEYS)

    def test_xor_record_is_distinguished(self):
        record = inspect_protection(path('xor_password_123456789012345.xls'))
        self.assertTrue(record.is_encrypted)
        self.assertEqual(record.protection_type, 'xor')
        self.assertEqual(record.algorithm, 'XOR')
        self.assertEqual(record.action, ACTION_ARCHIVE)

    def test_office_file_class_exposes_the_same_record(self):
        with open(path('rc4cryptoapi_password.doc'), 'rb') as handle:
            officefile = OfficeFile(handle)
            self.assertEqual(officefile.protection.status, ProtectionStatus.COMPLIANT)
            self.assertEqual(
                officefile.get_protection_info()['key_size'],
                officefile.get_protection()['key_size'],
            )
            self.assertEqual(
                officefile.protection_record()['protection_type'],
                'rc4_cryptoapi',
            )

    def test_ooxml_agile_attributes_are_public(self):
        record = inspect_protection(path('example_password.xlsx'))
        self.assertEqual(record.format, 'ooxml')
        self.assertEqual(record.protection_type, 'agile')
        self.assertEqual(record.key_size, 256)
        self.assertEqual(record.hash_algorithm, 'SHA512')
        self.assertEqual(record.spin_count, 100000)
        self.assertEqual(record.status, ProtectionStatus.COMPLIANT)

    def test_record_aliases(self):
        record = inspect_protection(path('rc4cryptoapi_password.doc'))
        self.assertIsInstance(record, ProtectionRecord)
        self.assertEqual(record.type, 'rc4_cryptoapi')
        self.assertEqual(record.key_bits, 128)
        self.assertEqual(record.cipher, 'RC4')
        self.assertFalse(record.is_plaintext)
        self.assertEqual(record.status_label, 'parameters compliant')


class PolicyTest(unittest.TestCase):
    def test_minimum_key_size_fails(self):
        policy = ProtectionPolicy(min_key_size=256)
        for name in ENCRYPTED:
            with self.subTest(name=name):
                record = inspect_protection(path(name), policy)
                self.assertEqual(record.status, ProtectionStatus.NON_COMPLIANT)
                self.assertFalse(record.compliant)
                self.assertEqual(record.action, ACTION_SUPPLEMENT)
                self.assertTrue(any('256' in reason for reason in record.reasons))

    def test_disallowed_algorithm_fails(self):
        record = inspect_protection(
            path('rc4cryptoapi_password.xls'), {'allowed_algorithms': ['AES']}
        )
        self.assertEqual(record.status, ProtectionStatus.NON_COMPLIANT)
        self.assertTrue(any('algorithm' in reason for reason in record.reasons))

    def test_allowed_type_and_key_size_pass(self):
        policy = {
            'allowed_types': ['rc4_cryptoapi'],
            'min_key_size': 128,
            'allowed_hash_algorithms': ['SHA1'],
        }
        record = inspect_protection(path('rc4cryptoapi_password.doc'), policy)
        self.assertEqual(record.status, ProtectionStatus.COMPLIANT)
        self.assertEqual(record.action, ACTION_ARCHIVE)

    def test_plaintext_can_be_rejected_by_policy(self):
        record = inspect_protection(path('plain.doc'), {'require_encryption': True})
        self.assertEqual(record.status, ProtectionStatus.PLAINTEXT)
        self.assertFalse(record.compliant)
        self.assertEqual(record.action, ACTION_SUPPLEMENT)
        self.assertTrue(any('plaintext' in reason for reason in record.reasons))

    def test_callable_policies(self):
        def allow(record):
            return record['key_size'] == 128

        record = inspect_protection(path('rc4cryptoapi_password.doc'), allow)
        self.assertEqual(record.status, ProtectionStatus.COMPLIANT)

        record = inspect_protection(
            path('rc4cryptoapi_password.doc'), lambda record: None
        )
        self.assertEqual(record.status, ProtectionStatus.UNKNOWN)

        record = inspect_protection(
            path('rc4cryptoapi_password.doc'),
            lambda record: {'status': 'non_compliant', 'reasons': ['manual']},
        )
        self.assertEqual(record.status, ProtectionStatus.NON_COMPLIANT)
        self.assertEqual(record.reasons, ['manual'])


class SyntheticHeaderTest(unittest.TestCase):
    def test_parse_cryptoapi_header(self):
        header = parse_cryptoapi_header(synthetic_header(key_size=40))
        self.assertEqual(header['alg_id'], 0x00006801)
        self.assertEqual(header['alg_id_hash'], 0x00008004)
        self.assertEqual(header['key_size'], 40)
        self.assertEqual(header['provider_type'], 1)
        self.assertEqual(header['csp_name'], 'Test Provider')

    def test_truncated_header_is_rejected(self):
        with self.assertRaises(exceptions.ParseError):
            parse_cryptoapi_header(b'\x00\x00\x00\x00')

    def test_synthetic_headers_flow_through_all_three_formats(self):
        for name in ENCRYPTED:
            with self.subTest(name=name):
                with patch(
                    'msoffcrypto.protection.parse_cryptoapi_header',
                    return_value=_header_dict(key_size=40),
                ):
                    record = inspect_protection(
                        path(name), {'min_key_size': 128}
                    )
                self.assertEqual(record.status, ProtectionStatus.NON_COMPLIANT)
                self.assertEqual(record.key_size, 40)
                self.assertTrue(any('40' in reason for reason in record.reasons))

    def test_unknown_algorithm_is_unknown_not_non_compliant(self):
        for name in ENCRYPTED:
            with self.subTest(name=name):
                with patch(
                    'msoffcrypto.protection.parse_cryptoapi_header',
                    return_value=_header_dict(alg_id=0x0000DEAD, key_size=128),
                ):
                    record = inspect_protection(
                        path(name), {'allowed_types': ['rc4_cryptoapi']}
                    )
                self.assertEqual(record.status, ProtectionStatus.UNKNOWN)
                self.assertEqual(record.action, ACTION_SUPPLEMENT)
                self.assertIn('algorithm', record.missing_parameters)

    def test_unreadable_header_is_unknown(self):
        for name in ENCRYPTED:
            with self.subTest(name=name):
                with patch(
                    'msoffcrypto.protection.parse_cryptoapi_header',
                    side_effect=exceptions.ParseError('truncated'),
                ):
                    record = inspect_protection(path(name))
                self.assertEqual(record.status, ProtectionStatus.UNKNOWN)
                self.assertFalse(record.parameters_known)
                self.assertIn('key_size', record.missing_parameters)

    def test_record_from_raw_attributes(self):
        record = record_from_attributes(
            format='doc97',
            encrypted=True,
            protection_type='rc4_cryptoapi',
            algorithm='RC4',
            key_size=40,
            hash_algorithm='SHA1',
            policy={'min_key_size': 128},
        )
        self.assertEqual(record.status, ProtectionStatus.NON_COMPLIANT)
        self.assertIsInstance(record, ProtectionRecord)


class ReportTest(unittest.TestCase):
    def test_same_report_schema_for_three_formats(self):
        report = build_report([path(name) for name in ENCRYPTED])
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['summary']['total'], 3)
        self.assertEqual(report['summary']['archive'], 3)
        self.assertEqual(report['summary']['supplement'], 0)
        self.assertEqual(set(report['summary']['by_format']), {'doc97', 'xls97', 'ppt97'})
        for record in report['records']:
            self.assertEqual(set(record), RECORD_KEYS)
        json.loads(report.to_json())
        text = report.format_text()
        self.assertIn('doc97', text)
        self.assertIn('archive', text)

    def test_mixed_report_tells_operator_what_to_do(self):
        with patch(
            'msoffcrypto.protection.parse_cryptoapi_header',
            side_effect=exceptions.ParseError('truncated'),
        ):
            ppt = inspect_protection(path('rc4cryptoapi_password.ppt'))
        doc = inspect_protection(path('rc4cryptoapi_password.doc'))
        xls = inspect_protection(
            path('rc4cryptoapi_password.xls'), {'min_key_size': 256}
        )
        report = build_report([doc, xls, ppt])
        self.assertEqual(report['summary']['archive'], 1)
        self.assertEqual(report['summary']['supplement'], 2)
        self.assertEqual(report['summary']['by_status']['compliant'], 1)
        self.assertEqual(report['summary']['by_status']['non_compliant'], 1)
        self.assertEqual(report['summary']['by_status']['unknown'], 1)
        actions = {record['format']: record['action'] for record in report['records']}
        self.assertEqual(actions['doc97'], ACTION_ARCHIVE)
        self.assertEqual(actions['xls97'], ACTION_SUPPLEMENT)
        self.assertEqual(actions['ppt97'], ACTION_SUPPLEMENT)

    def test_inspection_does_not_need_a_password(self):
        from msoffcrypto.format.doc97 import Doc97File
        from msoffcrypto.format.ppt97 import Ppt97File
        from msoffcrypto.format.xls97 import Xls97File

        def fail(*args, **kwargs):
            raise AssertionError('load_key must not be called')

        with patch.object(Doc97File, 'load_key', fail), patch.object(
            Xls97File, 'load_key', fail
        ), patch.object(Ppt97File, 'load_key', fail):
            for name in PLAIN + ENCRYPTED:
                with self.subTest(name=name):
                    record = inspect_protection(path(name))
                    self.assertIn(record.status, list(ProtectionStatus))


def _header_dict(
    alg_id=0x00006801,
    alg_id_hash=0x00008004,
    key_size=128,
    provider_type=1,
    csp_name='Test Provider',
):
    return {
        'flags': 0x00000004,
        'header_size': 32,
        'header_flags': 0,
        'size_extra': 0,
        'alg_id': alg_id,
        'alg_id_hash': alg_id_hash,
        'key_size': key_size,
        'provider_type': provider_type,
        'reserved1': 0,
        'reserved2': 0,
        'csp_name': csp_name,
    }


if __name__ == '__main__':
    unittest.main()
