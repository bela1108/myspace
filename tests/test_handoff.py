# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import copy
import os
import unittest

from asn1crypto import core
from asn1crypto.handoff import (
    EvidenceIdentity,
    HandoffBundle,
    LocalSignoff,
    PENDING,
    STALE,
    VERIFIED,
    VerificationRequired,
    VerifiableMaterial,
    PresentableProjection,
    cms_report,
)


CMS_FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'cms-signed.der')


class WorkerDefaults(core.Sequence):
    _fields = [
        ('job_name', core.UTF8String),
        ('retries', core.Integer, {'default': 3}),
    ]


class CountingVerifier(object):
    def __init__(self, receipt):
        self.receipt = receipt
        self.calls = 0

    def __call__(self, material, scope, identity):
        self.calls += 1
        return self.receipt


class HandoffTests(unittest.TestCase):
    def setUp(self):
        with open(CMS_FIXTURE, 'rb') as fixture:
            self.cms_der = fixture.read()
        self.scope = {'operation': 'print', 'sections': ['header', 'approval']}
        self.material = VerifiableMaterial(self.cms_der, spec='cms')
        self.identity = self.material.evidence_identity(self.scope)
        self.receipt = LocalSignoff.sign_off(
            self.identity,
            decision=VERIFIED,
            signed_by='local-approval-clerk',
            secret='unit-test-secret',
        )

    def make_bundle(self, projection_text='Approval report: signed CMS'):
        return HandoffBundle(
            projection=PresentableProjection(projection_text),
            material=self.material,
            receipt=self.receipt,
            scope=self.scope,
            receipt_secret='unit-test-secret',
        )

    def test_viewing_report_does_not_reverify_or_change_conclusion(self):
        lazy_calls = []

        def build_report():
            lazy_calls.append(1)
            return 'Approval report: signed CMS'

        bundle = HandoffBundle(
            projection=PresentableProjection(loader=build_report),
            material=self.material,
            receipt=self.receipt,
            scope=self.scope,
            receipt_secret='unit-test-secret',
        )
        verifier = CountingVerifier(self.receipt)

        self.assertEqual(VERIFIED, bundle.status)
        first_view = bundle.view_report()
        second_view = bundle.view_report()

        self.assertEqual('Approval report: signed CMS', str(first_view))
        self.assertEqual(first_view, second_view)
        self.assertEqual(1, len(lazy_calls))
        self.assertEqual(0, verifier.calls)
        self.assertEqual(VERIFIED, bundle.conclusion)
        bundle.verify(verifier)
        self.assertEqual(0, verifier.calls)

    def test_clone_deepcopy_and_wire_roundtrip_keep_identity(self):
        bundle = self.make_bundle()
        clones = [bundle.clone(), copy.copy(bundle), copy.deepcopy(bundle)]

        for clone in clones:
            self.assertEqual(bundle.evidence_id, clone.evidence_id)
            self.assertEqual(bundle.status, clone.status)
            self.assertEqual(bundle.view_report(), clone.view_report())
            self.assertTrue(clone.receipt.verify_signature('unit-test-secret'))

        restored = HandoffBundle.from_bytes(bundle.to_bytes())
        self.assertEqual(bundle.evidence_id, restored.evidence_id)
        self.assertEqual(VERIFIED, restored.status)
        self.assertEqual(bundle.view_report(), restored.view_report())

    def test_lazy_projection_clone_remains_independent(self):
        calls = []

        def loader():
            calls.append('loaded')
            return 'lazy report'

        projection = PresentableProjection(loader=loader)
        lazy_clone = projection.clone()

        self.assertFalse(projection.expanded)
        self.assertFalse(lazy_clone.expanded)
        self.assertEqual('lazy report', lazy_clone.text)
        self.assertEqual(1, len(calls))
        self.assertFalse(projection.expanded)

        self.assertEqual('lazy report', projection.text)
        self.assertEqual(2, len(calls))

    def test_standard_der_reencode_preserves_identity(self):
        parsed = self.material.parse()
        self.assertEqual(self.cms_der, parsed.dump(force=True))

        reencoded = self.material.reencode(force=True)
        self.assertEqual(self.cms_der, reencoded.raw)
        self.assertEqual(self.identity, reencoded.evidence_identity(self.scope))

        bundle = self.make_bundle()
        transferred = bundle.reencode(force=True)
        self.assertEqual(bundle.evidence_id, transferred.evidence_id)
        self.assertEqual(VERIFIED, transferred.status)
        self.assertFalse(transferred.needs_reverification)

    def test_scope_change_with_same_display_text_waits_for_new_receipt(self):
        bundle = self.make_bundle()
        wider_scope = dict(self.scope)
        wider_scope['sections'] = ['header', 'approval', 'certificates']

        widened = bundle.with_scope(wider_scope)

        self.assertEqual(str(bundle.view_report()), str(widened.view_report()))
        self.assertNotEqual(bundle.evidence_id, widened.evidence_id)
        self.assertEqual(PENDING, widened.status)
        self.assertTrue(widened.needs_reverification)
        with self.assertRaises(VerificationRequired):
            widened.require_current_receipt()

        stale_copy = bundle.with_scope(wider_scope, keep_receipt=True)
        self.assertEqual(STALE, stale_copy.status)
        self.assertEqual(PENDING, stale_copy.conclusion)
        self.assertEqual(VERIFIED, stale_copy.evidence_conclusion['prior_conclusion'])

        new_receipt = LocalSignoff.sign_off(
            widened.identity,
            signed_by='second-clerk',
            secret='unit-test-secret',
        )
        widened.attach_receipt(new_receipt)
        self.assertEqual(VERIFIED, widened.status)
        self.assertFalse(widened.needs_reverification)

    def test_in_place_scope_mutation_changes_identity(self):
        scope = {'sections': ['header']}
        identity = self.material.evidence_identity(scope)
        receipt = LocalSignoff.sign_off(identity, secret='unit-test-secret')
        bundle = HandoffBundle('same text', self.material, receipt, scope,
                               receipt_secret='unit-test-secret')

        self.assertEqual(VERIFIED, bundle.status)
        scope['sections'].append('approval')

        self.assertTrue(bundle.needs_reverification)
        self.assertEqual(STALE, bundle.status)
        self.assertNotEqual(identity, bundle.identity)

    def test_worker_default_reconstruction_changes_material_identity(self):
        original = WorkerDefaults({'job_name': 'print-job'})
        reconstructed = WorkerDefaults({'job_name': 'print-job', 'retries': 0})
        original_der = original.dump(force=True)
        reconstructed_der = reconstructed.dump(force=True)
        self.assertNotEqual(original_der, reconstructed_der)

        original_material = VerifiableMaterial(original_der)
        rebuilt_material = VerifiableMaterial(reconstructed_der)
        original_id = original_material.evidence_identity(self.scope)
        rebuilt_id = rebuilt_material.evidence_identity(self.scope)

        receipt = LocalSignoff.sign_off(original_id, signed_by='verifier')
        bundle = HandoffBundle('same report text', rebuilt_material, receipt, self.scope)

        self.assertEqual(STALE, bundle.status)
        self.assertTrue(bundle.needs_reverification)
        self.assertNotEqual(original_id, rebuilt_id)

    def test_cms_report_is_separate_display_projection(self):
        projection = cms_report(self.cms_der)
        text = projection.text

        self.assertIn('CMS content type: signed_data', text)
        self.assertIn('Signer infos: 1', text)

        bundle = HandoffBundle(projection, self.material, self.receipt, self.scope)
        self.assertEqual(text, str(bundle.view_report()))
        self.assertEqual(VERIFIED, bundle.status)

    def test_identity_ignores_projection_changes(self):
        first = self.make_bundle('same text')
        second = self.make_bundle('same text')
        third = self.make_bundle('different text after lazy formatting')

        self.assertEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(first.evidence_id, third.evidence_id)
        self.assertIsInstance(first.identity, EvidenceIdentity)

    def test_local_signoff_asn1_roundtrip(self):
        der = self.receipt.dump()
        restored = LocalSignoff.from_asn1(der)

        self.assertEqual(self.receipt.evidence_id, restored.evidence_id)
        self.assertEqual(self.receipt.verdict, restored.verdict)
        self.assertTrue(restored.verify_signature('unit-test-secret'))
        self.assertTrue(restored.covers(self.identity))


if __name__ == '__main__':
    unittest.main()
