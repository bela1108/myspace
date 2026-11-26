# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import json
import os
import unittest

from asn1crypto.core import OctetString
from asn1crypto.pkcs12 import SafeBag, SafeContents
from asn1crypto.cms import ContentInfo
from asn1crypto.pkcs12 import AuthenticatedSafe, Pfx
from asn1crypto.keys import EncryptedPrivateKeyInfo

from cert_audit.archive import load_archive
from cert_audit.chains import SIGNATURE_VERIFY_AVAILABLE
from cert_audit.cli import main as cli_main
from cert_audit.manifest import load_manifest
from cert_audit.pfx_builder import build_cert_only_pfx
from cert_audit.report import build_comparison, build_report, render_text
from cert_audit.review import (
    FINDING_DUPLICATE_FRIENDLY_NAME,
    FINDING_NO_CONFIRMABLE_CHAIN,
    FINDING_UNAUTHORIZED_USAGE,
)

try:
    from .cert_audit_fixtures import build_test_material
except ImportError:  # pragma: no cover
    build_test_material = None


@unittest.skipIf(build_test_material is None, 'cryptography is required for fixture generation')
class CertAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = build_test_material()
        cls.manifest = load_manifest(cls.material['manifest'])
        cls.archive_a = load_archive('batch-a.p12', cls.material['batch_a_pfx'])
        cls.archive_b = load_archive('batch-b.p12', cls.material['batch_b_pfx'])

    def test_archives_contain_no_key_bags(self):
        for archive in (self.archive_a, self.archive_b):
            self.assertEqual(0, archive.key_bag_count)
            self.assertEqual(0, archive.shrouded_key_bag_count)
            self.assertFalse(archive.private_key_material_present)

    def test_distinct_certificates_and_friendly_names(self):
        # Two leaf certs share one friendly name in both batches.
        self.assertEqual(4, self.archive_a.inventory()['distinct_certificates'])
        self.assertEqual(5, self.archive_b.inventory()['distinct_certificates'])
        display_certs = self.archive_a.friendly_name_index['display-cert']
        subjects = set(cert.subject for cert in display_certs)
        self.assertEqual(2, len(display_certs))
        self.assertEqual(2, len(subjects))

    def test_duplicate_friendly_name_finding_keeps_same_topic_flag(self):
        review_b = build_report(self.archive_b, self.manifest)
        duplicate = next(
            finding for finding in review_b['findings']
            if finding['type'] == FINDING_DUPLICATE_FRIENDLY_NAME
        )
        self.assertEqual('display-cert', duplicate['friendly_name'])
        self.assertTrue(duplicate['same_subject'])
        self.assertEqual(2, len(duplicate['certificates']))

    def test_review_retains_all_three_finding_categories(self):
        review_a = build_report(self.archive_a, self.manifest)
        finding_types = set(finding['type'] for finding in review_a['findings'])
        self.assertEqual(
            {FINDING_DUPLICATE_FRIENDLY_NAME, FINDING_NO_CONFIRMABLE_CHAIN,
             FINDING_UNAUTHORIZED_USAGE},
            finding_types,
        )
        summary = review_a['summary']
        self.assertEqual(1, summary['duplicate_friendly_name_count'])
        self.assertEqual(1, summary['no_confirmable_chain_count'])
        self.assertEqual(1, summary['unauthorized_usage_count'])
        self.assertFalse(summary['ready_for_handover'])

    def test_orphan_leaf_has_no_confirmable_chain(self):
        review_a = build_report(self.archive_a, self.manifest)
        orphan = next(
            leaf for leaf in review_a['leaves']
            if leaf['fingerprint_sha256'] == self.material['leaf_orphan'].fingerprint
        )
        self.assertFalse(orphan['chain']['confirmed'])
        self.assertEqual('missing_issuer', orphan['chain']['reason'])

    def test_complete_batch_is_ready_for_handover(self):
        review_b = build_report(self.archive_b, self.manifest)
        summary = review_b['summary']
        self.assertEqual(3, summary['leaf_count'])
        self.assertEqual(3, summary['confirmable_chain_count'])
        self.assertEqual(3, summary['approved_leaf_count'])
        self.assertTrue(summary['ready_for_handover'])
        self.assertEqual(0, summary['no_confirmable_chain_count'])
        self.assertEqual(0, summary['unauthorized_usage_count'])
        if SIGNATURE_VERIFY_AVAILABLE:
            for leaf in review_b['leaves']:
                self.assertTrue(leaf['chain']['signature_verified'])

    def test_comparison_identifies_complete_archive(self):
        review_a = build_report(self.archive_a, self.manifest)
        review_b = build_report(self.archive_b, self.manifest)
        comparison = build_comparison(review_a, review_b)
        self.assertEqual('one_ready', comparison['verdict'])
        self.assertEqual(['batch-b.p12'], comparison['ready_sources'])
        text = render_text(review_a, review_b, comparison)
        self.assertIn('Complete public handover material is present in: batch-b.p12', text)

    def test_structural_only_review_also_identifies_chain(self):
        review_b = build_report(self.archive_b, self.manifest, verify_signatures=False)
        self.assertTrue(review_b['summary']['ready_for_handover'])
        self.assertFalse(review_b['signature_verification']['enabled'])
        self.assertTrue(review_b['signature_verification']['cryptography_available'])

    def test_tampered_signature_breaks_chain_confirmation(self):
        if not SIGNATURE_VERIFY_AVAILABLE:
            self.skipTest('cryptography required for signature verification')
        from asn1crypto.core import OctetBitString
        tampered_intermediate = self.material['intermediate'].asn1.copy()
        original_signature = bytearray(tampered_intermediate['signature_value'].native)
        original_signature[0] ^= 0x01
        tampered_intermediate['signature_value'] = OctetBitString(bytes(original_signature))

        from cert_audit.pfx_builder import build_cert_only_pfx
        pfx_bytes = build_cert_only_pfx([
            {'certificate': self.material['root'].der},
            {'certificate': tampered_intermediate.dump()},
            {'certificate': self.material['leaf_server'].der},
        ])
        archive = load_archive('tampered.p12', pfx_bytes)
        review = build_report(archive, self.manifest)
        server_leaf = next(
            leaf for leaf in review['leaves']
            if leaf['fingerprint_sha256'] == self.material['leaf_server'].fingerprint
        )
        self.assertFalse(server_leaf['chain']['confirmed'])
        self.assertEqual('issuer_not_ca_or_bad_signature', server_leaf['chain']['reason'])

        # Without signature verification the structural chain is still visible.
        structural_review = build_report(archive, self.manifest, verify_signatures=False)
        structural_leaf = next(
            leaf for leaf in structural_review['leaves']
            if leaf['fingerprint_sha256'] == self.material['leaf_server'].fingerprint
        )
        self.assertTrue(structural_leaf['chain']['confirmed'])

    def test_manifest_allowed_issuer_mismatch_is_unauthorized(self):
        manifest_dict = json.loads(json.dumps(self.material['manifest']))
        manifest_dict['leaves'][0]['allowed_issuers'] = [
            {'sha256_fingerprint': self.material['leaf_orphan'].fingerprint}
        ]
        review_b = build_report(self.archive_b, load_manifest(manifest_dict))
        server_leaf = next(
            leaf for leaf in review_b['leaves']
            if leaf['fingerprint_sha256'] == self.material['leaf_server'].fingerprint
        )
        self.assertFalse(server_leaf['approved'])
        self.assertTrue(any('approved issuer absent' in note for note in server_leaf['approval_notes']))

    def test_pem_certificate_input_is_supported(self):
        der = self.material['leaf_server'].der
        pem_bytes = b'-----BEGIN CERTIFICATE-----\n'
        import base64
        encoded = base64.b64encode(der).decode('ascii')
        pem_bytes += '\n'.join(encoded[i:i + 64] for i in range(0, len(encoded), 64)).encode('ascii')
        pem_bytes += b'\n-----END CERTIFICATE-----\n'
        archive = load_archive('leaf.pem', pem_bytes)
        self.assertEqual(1, archive.inventory()['distinct_certificates'])

    def test_private_key_pem_is_rejected(self):
        private_pem = b'-----BEGIN PRIVATE KEY-----\nAAEC\n-----END PRIVATE KEY-----\n'
        with self.assertRaises(ValueError):
            load_archive('key.pem', private_pem)

    def test_key_bags_are_counted_but_never_exported(self):
        # Valid EPki structure whose ciphertext is a fixed placeholder, never a
        # real private key.
        shrouded = EncryptedPrivateKeyInfo({
            'encryption_algorithm': {'algorithm': 'aes256_cbc', 'parameters': OctetString(b'\x00' * 16)},
            'encrypted_data': b'opaque-no-key-material',
        })
        key_safe_bag = SafeBag({
            'bag_id': 'pkcs8_shrouded_key_bag',
            'bag_value': shrouded,
        })
        cert_safe_contents = SafeContents()
        cert_safe_contents.append(key_safe_bag)
        data_info = ContentInfo({'content_type': 'data', 'content': cert_safe_contents.dump()})
        auth_safe = AuthenticatedSafe()
        auth_safe.append(data_info)
        pfx = Pfx({
            'version': 'v3',
            'auth_safe': ContentInfo({'content_type': 'data', 'content': auth_safe.dump()}),
        })
        archive = load_archive('with-keybag.p12', pfx.dump())
        self.assertEqual(1, archive.shrouded_key_bag_count)
        self.assertTrue(archive.private_key_material_present)
        self.assertEqual(0, archive.inventory()['distinct_certificates'])
        inventory_text = json.dumps(archive.inventory())
        self.assertNotIn('opaque-no-key-material', inventory_text)

    def test_cli_writes_json_report(self):
        import tempfile
        temp_dir = tempfile.mkdtemp()
        archive_path = os.path.join(temp_dir, 'batch.p12')
        manifest_path = os.path.join(temp_dir, 'manifest.json')
        output_path = os.path.join(temp_dir, 'report.json')
        with open(archive_path, 'wb') as handle:
            handle.write(self.material['batch_b_pfx'])
        with open(manifest_path, 'w') as handle:
            json.dump(self.material['manifest'], handle)

        exit_code = cli_main([archive_path, '-m', manifest_path, '-o', output_path])
        self.assertEqual(0, exit_code)
        with open(output_path) as handle:
            payload = json.load(handle)
        self.assertTrue(payload['reports'][0]['summary']['ready_for_handover'])

    def test_build_cert_only_pfx_round_trips_through_asn1crypto(self):
        pfx_bytes = build_cert_only_pfx([
            {'certificate': self.material['root'].der, 'friendly_name': 'root'},
        ])
        archive = load_archive('roundtrip.p12', pfx_bytes)
        self.assertEqual(1, archive.inventory()['distinct_certificates'])
        self.assertEqual(['root'], archive.certs[0].friendly_names)

    def test_duplicate_cert_bags_are_deduplicated_but_counted(self):
        pfx_bytes = build_cert_only_pfx([
            {'certificate': self.material['root'].der, 'friendly_name': 'root-a'},
            {'certificate': self.material['root'].der, 'friendly_name': 'root-b'},
        ])
        archive = load_archive('dup.p12', pfx_bytes)
        self.assertEqual(1, len(archive.certs))
        self.assertEqual(2, archive.cert_bag_count)
        self.assertEqual(['root-a', 'root-b'], archive.certs[0].friendly_names)

    def test_local_key_id_and_trusted_usage_are_captured(self):
        pfx_bytes = build_cert_only_pfx([
            {
                'certificate': self.material['leaf_server'].der,
                'friendly_name': 'leaf',
                'local_key_id': b'\xab\xcd',
                'trusted_usages': ['server_auth'],
            },
        ])
        archive = load_archive('trusted.p12', pfx_bytes)
        cert = archive.certs[0]
        self.assertEqual(['ABCD'], cert.local_key_ids)
        self.assertEqual(['server_auth'], cert.trusted_key_usages)

    def test_der_certificate_is_supported(self):
        archive = load_archive('root.der', self.material['root'].der)
        self.assertEqual(1, len(archive.certs))
        self.assertTrue(archive.certs[0].is_ca)

    def test_invalid_manifest_selector_is_rejected(self):
        with self.assertRaises(ValueError):
            load_manifest({'leaves': [{'unknown_field': 'x'}]})

    def test_encrypted_safe_content_is_flagged_without_decryption(self):
        from asn1crypto.cms import EncryptedData
        encrypted_data = EncryptedData({
            'version': 0,
            'encrypted_content_info': {
                'content_type': 'data',
                'content_encryption_algorithm': {
                    'algorithm': 'aes256_cbc',
                    'parameters': OctetString(b'\x00' * 16),
                },
                'encrypted_content': b'opaque',
            },
        })
        content_info = ContentInfo({
            'content_type': 'encrypted_data',
            'content': encrypted_data,
        })
        auth_safe = AuthenticatedSafe()
        auth_safe.append(content_info)
        pfx = Pfx({
            'version': 'v3',
            'auth_safe': ContentInfo({'content_type': 'data', 'content': auth_safe.dump()}),
        })
        archive = load_archive('encrypted.p12', pfx.dump())
        self.assertEqual(1, archive.encrypted_safe_count)
        self.assertTrue(archive.private_key_material_present)
        self.assertEqual(0, len(archive.certs))


if __name__ == '__main__':
    unittest.main()
