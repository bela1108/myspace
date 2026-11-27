# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest
from datetime import datetime

from asn1crypto import csr, handoff, pem, util, x509

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class HandoffTests(unittest.TestCase):

    @staticmethod
    def _public_key_info():
        with open(os.path.join(fixtures_dir, 'test-inter-der.csr'), 'rb') as f:
            source = csr.CertificationRequest.load(f.read())
        return source['certification_request_info']['subject_pk_info']

    def _application(self, common_name, public_key_info, lab):
        request = csr.CertificationRequest({
            'certification_request_info': {
                'version': 'v1',
                'subject': x509.Name.build({
                    'common_name': common_name,
                }),
                'subject_pk_info': public_key_info,
            },
            'signature_algorithm': {
                'algorithm': 'sha256_rsa',
            },
            'signature': b'\xaa' * 16,
        })
        return handoff.load_application(
            pem.armor('CERTIFICATE REQUEST', request.dump()),
            application_id='app-%s' % lab,
            lab=lab
        )

    def _certificate(self, serial_number, common_name, public_key_info):
        certificate = x509.Certificate({
            'tbs_certificate': {
                'version': 'v3',
                'serial_number': serial_number,
                'signature': {
                    'algorithm': 'sha256_rsa',
                },
                'issuer': x509.Name.build({
                    'common_name': 'Synthetic Offline CA',
                }),
                'validity': {
                    'not_before': x509.Time({
                        'utc_time': datetime(2026, 1, 1, tzinfo=util.timezone.utc),
                    }),
                    'not_after': x509.Time({
                        'utc_time': datetime(2027, 1, 1, tzinfo=util.timezone.utc),
                    }),
                },
                'subject': x509.Name.build({
                    'common_name': common_name,
                }),
                'subject_public_key_info': public_key_info,
            },
            'signature_algorithm': {
                'algorithm': 'sha256_rsa',
            },
            'signature_value': b'\x55' * 16,
        })
        return handoff.load_certificate(
            pem.armor('CERTIFICATE', certificate.dump()),
            certificate_id='cert-%d' % serial_number
        )

    def test_same_public_key_requires_one_approval_constraint_for_uniqueness(self):
        public_key_info = self._public_key_info()
        alpha = self._application('shared-device-alpha', public_key_info, 'alpha')
        beta = self._application('shared-device-beta', public_key_info, 'beta')
        first_certificate = self._certificate(1, 'shared-device-cert-1', public_key_info)
        second_certificate = self._certificate(2, 'shared-device-cert-2', public_key_info)

        self.assertEqual(alpha.public_key_fingerprint, beta.public_key_fingerprint)
        self.assertEqual(alpha.public_key_fingerprint, first_certificate.public_key_fingerprint)
        self.assertFalse(alpha.signature_verified)
        self.assertFalse(beta.signature_verified)
        self.assertFalse(first_certificate.signature_verified)
        self.assertFalse(second_certificate.signature_verified)

        approvals = [
            handoff.make_approval('approval-alpha', alpha.public_key_fingerprint, lab='alpha'),
            handoff.make_approval('approval-beta', beta.public_key_fingerprint, lab='beta'),
        ]
        ledger = handoff.HandoffLedger([alpha, beta], [first_certificate, second_certificate], approvals)

        result = ledger.result()
        self.assertEqual(2, len(result.solutions))
        self.assertEqual(1, result.minimum_confirmations)
        self.assertEqual(1, len(result.confirmation_facts))

        constrained_approvals = [
            handoff.make_approval(
                'approval-alpha',
                alpha.public_key_fingerprint,
                lab='alpha',
                certificate_id='cert-1'
            ),
            approvals[1],
        ]
        constrained_ledger = handoff.HandoffLedger(
            [alpha, beta],
            [first_certificate, second_certificate],
            constrained_approvals
        )

        constrained_result = constrained_ledger.result()
        self.assertTrue(constrained_result.is_unique)
        self.assertEqual(0, constrained_result.minimum_confirmations)
        self.assertEqual({
            'app-alpha': {
                'application': 'app-alpha',
                'certificate': 'cert-1',
                'approval': 'approval-alpha',
            },
            'app-beta': {
                'application': 'app-beta',
                'certificate': 'cert-2',
                'approval': 'approval-beta',
            },
        }, constrained_result.solutions[0])

    def test_confirmation_fact_filters_solutions(self):
        public_key_info = self._public_key_info()
        applications = [
            self._application('shared-device-alpha', public_key_info, 'alpha'),
            self._application('shared-device-beta', public_key_info, 'beta'),
        ]
        certificates = [
            self._certificate(1, 'shared-device-cert-1', public_key_info),
            self._certificate(2, 'shared-device-cert-2', public_key_info),
        ]
        ledger = handoff.HandoffLedger(applications, certificates)

        self.assertEqual(2, len(ledger.solve()))
        solutions = ledger.solve(confirmations=[
            {'application': 'app-alpha', 'certificate': 'cert-1'}
        ])

        self.assertEqual(1, len(solutions))
        self.assertEqual('cert-1', solutions[0]['app-alpha']['certificate'])
        self.assertEqual('cert-2', solutions[0]['app-beta']['certificate'])

    def test_result_limit_still_calculates_minimum_confirmation(self):
        public_key_info = self._public_key_info()
        applications = [
            self._application('shared-device-alpha', public_key_info, 'alpha'),
            self._application('shared-device-beta', public_key_info, 'beta'),
        ]
        certificates = [
            self._certificate(1, 'shared-device-cert-1', public_key_info),
            self._certificate(2, 'shared-device-cert-2', public_key_info),
        ]
        result = handoff.handoff_result(applications, certificates, limit=1)

        self.assertEqual(1, len(result.solutions))
        self.assertEqual(1, result.minimum_confirmations)
        self.assertEqual(1, len(result.confirmation_facts))

    def test_generic_records_accept_spki_der(self):
        public_key_info = self._public_key_info()
        spki_der = public_key_info.dump()
        ledger = handoff.HandoffLedger(
            [
                {'id': 'app-1', 'spki_der': spki_der},
                {'id': 'app-2', 'spki_der': spki_der},
            ],
            [
                {'id': 'cert-1', 'spki_der': spki_der, 'serial': 1},
                {'id': 'cert-2', 'spki_der': spki_der, 'serial': 2},
            ]
        )

        result = ledger.result()

        self.assertEqual(2, len(result.solutions))
        self.assertEqual(
            ledger.applications[0].public_key_fingerprint,
            ledger.certificates[0].public_key_fingerprint
        )
        self.assertEqual(1, result.minimum_confirmations)

    def test_certificate_approval_confirmation_is_scoped_to_certificate(self):
        public_key_info = self._public_key_info()
        alpha = self._application('shared-device-alpha', public_key_info, 'alpha')
        beta = self._application('shared-device-beta', public_key_info, 'beta')
        first_certificate = self._certificate(1, 'shared-device-cert-1', public_key_info)
        second_certificate = self._certificate(2, 'shared-device-cert-2', public_key_info)
        approvals = [
            handoff.make_approval('approval-alpha', alpha.public_key_fingerprint, lab='alpha'),
            handoff.make_approval('approval-beta', beta.public_key_fingerprint, lab='beta'),
        ]
        ledger = handoff.HandoffLedger([alpha, beta], [first_certificate, second_certificate], approvals)

        solutions = ledger.solve(confirmations=[
            {'certificate': 'cert-1', 'approval': 'approval-alpha'}
        ])

        self.assertEqual(1, len(solutions))
        self.assertEqual('approval-alpha', solutions[0]['app-alpha']['approval'])
        self.assertEqual('cert-1', solutions[0]['app-alpha']['certificate'])
