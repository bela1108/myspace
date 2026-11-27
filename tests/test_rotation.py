# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs7

from asn1crypto import cms, rotation, x509 as asn1_x509


class RotationTests(unittest.TestCase):
    def _certificate(self, subject_name, issuer_name, issuer_key, public_key, serial):
        now = datetime(2026, 11, 28, 0, 0, 0)
        builder = crypto_x509.CertificateBuilder()
        builder = builder.subject_name(subject_name)
        builder = builder.issuer_name(issuer_name)
        builder = builder.public_key(public_key)
        builder = builder.serial_number(serial)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=30))
        return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def _approval(self, certificate, private_key, content):
        builder = pkcs7.PKCS7SignatureBuilder()
        builder = builder.set_data(content)
        builder = builder.add_signer(
            certificate,
            private_key,
            hashes.SHA256(),
        )
        return builder.sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.NoCapabilities]
        )

    def _approval_content(self, previous_der, current_der):
        previous = asn1_x509.Certificate.load(previous_der)
        current = asn1_x509.Certificate.load(current_der)
        previous_certificate_hash = hashlib.sha256(previous_der).digest()
        current_certificate_hash = hashlib.sha256(current_der).digest()
        previous_key_hash = hashlib.sha256(previous.public_key.dump()).digest()
        current_key_hash = hashlib.sha256(current.public_key.dump()).digest()
        return b''.join([
            previous_certificate_hash,
            current_certificate_hash,
            previous_key_hash,
            current_key_hash,
        ])

    def _archives(self):
        subject_name = crypto_x509.Name([
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, 'CN'),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Factory'),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, 'registered-service'),
        ])
        renamed_name = crypto_x509.Name([
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, 'CN'),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Factory'),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, 'renamed-service'),
        ])
        subject_issuer_key = ec.generate_private_key(ec.SECP256R1())
        key_issuer_key = ec.generate_private_key(ec.SECP256R1())
        approval_key = ec.generate_private_key(ec.SECP256R1())

        subject_old_key = ec.generate_private_key(ec.SECP256R1())
        subject_new_key = ec.generate_private_key(ec.SECP256R1())
        key_old_name = crypto_x509.Name([
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, 'CN'),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Factory'),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, 'old-service'),
        ])
        shared_key = ec.generate_private_key(ec.SECP256R1())

        subject_old = self._certificate(
            subject_name, subject_name, subject_issuer_key, subject_old_key.public_key(), 1001
        )
        subject_new = self._certificate(
            subject_name, subject_name, subject_issuer_key, subject_new_key.public_key(), 1002
        )
        key_old = self._certificate(
            key_old_name, key_old_name, key_issuer_key, shared_key.public_key(), 2001
        )
        key_new = self._certificate(
            renamed_name, renamed_name, key_issuer_key, shared_key.public_key(), 2002
        )

        approval_certificate = crypto_x509.CertificateBuilder()
        approval_certificate = approval_certificate.subject_name(renamed_name)
        approval_certificate = approval_certificate.issuer_name(renamed_name)
        approval_certificate = approval_certificate.public_key(approval_key.public_key())
        approval_certificate = approval_certificate.serial_number(9001)
        approval_certificate = approval_certificate.not_valid_before(datetime(2026, 11, 28))
        approval_certificate = approval_certificate.not_valid_after(datetime(2027, 11, 28))
        approval_certificate = approval_certificate.sign(approval_key, hashes.SHA256())

        subject_approval = self._approval(
            approval_certificate,
            approval_key,
            self._approval_content(subject_old, subject_new)
        )
        key_approval = self._approval(
            approval_certificate,
            approval_key,
            self._approval_content(key_old, key_new)
        )

        return [
            {
                'label': 'subject-reuse-archive',
                'exhibits': [
                    {'label': 'exhibit-A', 'data': subject_old},
                    {'label': 'exhibit-B', 'data': subject_new, 'approval_data': subject_approval},
                ],
            },
            {
                'label': 'key-reuse-archive',
                'exhibits': [
                    {'label': 'exhibit-C', 'data': key_old},
                    {'label': 'exhibit-D', 'data': key_new, 'approval_data': key_approval},
                ],
            },
        ]

    def test_reconciliation_separates_identity_and_public_key_evidence(self):
        archives = self._archives()
        report = rotation.build_rotation_reconciliation(archives)
        encoded = report.dump()
        parsed = rotation.RotationReconciliationReport.load(encoded)

        self.assertEqual(2, len(parsed['links']))

        subject_link = parsed['links'][0]
        self.assertEqual('subject-reuse-archive', subject_link['group_label'].native)
        self.assertEqual('unchanged', subject_link['subject_status'].native)
        self.assertEqual('rotated', subject_link['serial_status'].native)
        self.assertEqual('rotated', subject_link['public_key_status'].native)
        self.assertEqual([], subject_link['conflict_reasons'].native)

        key_link = parsed['links'][1]
        self.assertEqual('key-reuse-archive', key_link['group_label'].native)
        self.assertEqual('rotated', key_link['subject_status'].native)
        self.assertEqual('rotated', key_link['serial_status'].native)
        self.assertEqual('unchanged', key_link['public_key_status'].native)
        self.assertEqual([], key_link['conflict_reasons'].native)

        approval = cms.ContentInfo.load(archives[1]['exhibits'][1]['approval_data'])
        signer = approval['content']['signer_infos'][0]
        self.assertEqual(
            key_link['external_approval']['signature_fingerprint'].native,
            hashlib.sha256(signer['signature'].native).digest()
        )
        signer_certificate = approval['content']['certificates'][0].chosen
        self.assertEqual(
            key_link['external_approval']['signer_certificate_evidence']['serial_number'].native,
            signer_certificate.serial_number
        )
        self.assertEqual(
            key_link['external_approval']['signer_certificate_evidence']['public_key']['sha256_fingerprint'].native,
            hashlib.sha256(signer_certificate.public_key.dump()).digest()
        )

    def test_conflicting_approval_is_not_merged_by_name(self):
        archives = self._archives()
        archives[0]['exhibits'][1]['approval_data'] = (
            archives[1]['exhibits'][1]['approval_data']
        )
        report = rotation.build_rotation_reconciliation(archives)
        subject_link = report['links'][0]

        self.assertTrue(subject_link['approval_conflict'].native)
        self.assertEqual(
            ['approval does not identify both certificate fingerprints'],
            subject_link['conflict_reasons'].native
        )
        self.assertEqual('rotated', subject_link['public_key_status'].native)

    def test_missing_approval_is_reported_as_a_conflict(self):
        archives = self._archives()
        del archives[0]['exhibits'][1]['approval_data']
        report = rotation.build_rotation_reconciliation(archives)

        self.assertTrue(report['links'][0]['approval_conflict'].native)
        self.assertEqual(
            ['missing external rotation approval'],
            report['links'][0]['conflict_reasons'].native
        )

    def test_path_inputs_are_loaded_without_mutating_archive_bytes(self):
        archives = self._archives()
        original_previous = archives[0]['exhibits'][0]['data']
        original_current = archives[0]['exhibits'][1]['data']
        original_approval = archives[0]['exhibits'][1]['approval_data']
        with tempfile.NamedTemporaryFile(delete=False) as previous_file:
            previous_path = previous_file.name
            previous_file.write(archives[0]['exhibits'][0]['data'])
        with tempfile.NamedTemporaryFile(delete=False) as current_file:
            current_path = current_file.name
            current_file.write(archives[0]['exhibits'][1]['data'])
        with tempfile.NamedTemporaryFile(delete=False) as approval_file:
            approval_path = approval_file.name
            approval_file.write(archives[0]['exhibits'][1]['approval_data'])

        try:
            path_archives = [{
                'label': 'path-archive',
                'exhibits': [
                    {'path': previous_path},
                    {
                        'path': current_path,
                        'approval_path': approval_path,
                    },
                ],
            }]
            report = rotation.build_rotation_reconciliation(path_archives)
            with open(previous_path, 'rb') as file_handle:
                self.assertEqual(original_previous, file_handle.read())
            with open(current_path, 'rb') as file_handle:
                self.assertEqual(original_current, file_handle.read())
            with open(approval_path, 'rb') as file_handle:
                self.assertEqual(original_approval, file_handle.read())

            self.assertEqual(
                os.path.basename(current_path),
                report['links'][0]['current_evidence']['exhibit_label'].native
            )
            self.assertEqual([], report['links'][0]['conflict_reasons'].native)
        finally:
            os.unlink(previous_path)
            os.unlink(current_path)
            os.unlink(approval_path)

    def test_report_evidence_objects_are_read_only(self):
        archives = self._archives()
        report = rotation.build_rotation_reconciliation(archives)
        reloaded = rotation.RotationReconciliationReport.load(report.dump())
        with self.assertRaises(TypeError):
            report['links'][0]['public_key_status'] = 'unchanged'
        with self.assertRaises(TypeError):
            report['links'][0]['conflict_reasons'][0] = 'name accepted'
        with self.assertRaises(TypeError):
            report['links'][0]['public_key_status'].set('unchanged')
        with self.assertRaises(TypeError):
            reloaded['links'][0]['public_key_status'] = 'unchanged'
        with self.assertRaises(TypeError):
            reloaded['links'][0]['public_key_status'].set('unchanged')
