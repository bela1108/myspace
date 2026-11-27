# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

from unittest import TestCase

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import ComponentType
from cyclonedx.retirement import (
    AssetLevel,
    BookNotClosableError,
    DuplicateProofError,
    RetirementBom,
    ServiceSettlementState,
    UnknownAssetError,
    UnknownServiceError,
)


class TestRetirementBom(TestCase):
    def setUp(self) -> None:
        self.rb = RetirementBom()
        self.asset = self.rb.register_asset('root-key', bom_ref='asset-1', description='retired KEK')
        self.billing = self.rb.register_service('billing', bom_ref='svc-billing')
        self.archive = self.rb.register_service('archive-search', bom_ref='svc-archive')

    def test_asset_flagged_external_deactivated_and_archive_queryable(self) -> None:
        self.assertEqual(ComponentType.CRYPTOGRAPHIC_ASSET, self.asset.type)
        props = {p.name: p.value for p in self.asset.properties}
        self.assertEqual('true', props['retirement:external-deactivated'])
        self.assertEqual('true', props['retirement:archive-queryable'])
        self.assertEqual('false', props['retirement:closed'])
        self.assertEqual(AssetLevel.READ_ONLY, self.rb.effective_level('asset-1'))

    def test_two_services_share_asset_but_settle_independently(self) -> None:
        self.rb.reference_asset('svc-billing', 'asset-1')
        self.rb.reference_asset('svc-archive', 'asset-1')

        refs = self.rb.legal_references('asset-1')
        self.assertEqual(2, len(refs))
        self.assertEqual({'svc-billing', 'svc-archive'}, {ref.service_ref for ref in refs})
        self.assertTrue(all(ref.state is ServiceSettlementState.PENDING for ref in refs))

        self.rb.submit_end_proof('svc-billing', 'asset-1', 'billing-owner', 'proof-billing')

        refs = {ref.service_ref: ref for ref in self.rb.legal_references('asset-1')}
        self.assertIs(ServiceSettlementState.SETTLED, refs['svc-billing'].state)
        self.assertEqual('billing-owner', refs['svc-billing'].end_proof.role)
        self.assertEqual('proof-billing', refs['svc-billing'].end_proof.reference)
        self.assertIs(ServiceSettlementState.PENDING, refs['svc-archive'].state)
        self.assertIsNone(refs['svc-archive'].end_proof)
        self.assertEqual(['billing-owner'], self.rb.proof_roles('asset-1'))

    def test_dependency_graph_recorded_in_underlying_bom(self) -> None:
        self.rb.reference_asset('svc-billing', 'asset-1')
        dependencies = {dep.ref.value: {d.ref.value for d in dep.dependencies}
                        for dep in self.rb.bom.dependencies}
        self.assertEqual({'asset-1'}, dependencies['svc-billing'])

    def test_duplicate_end_proof_from_same_role_rejected(self) -> None:
        self.rb.reference_asset('svc-billing', 'asset-1')
        self.rb.submit_end_proof('svc-billing', 'asset-1', 'billing-owner', 'proof-1')
        with self.assertRaises(DuplicateProofError):
            self.rb.submit_end_proof('svc-billing', 'asset-1', 'billing-owner', 'proof-2')

    def test_book_stays_read_only_until_all_receipts_present(self) -> None:
        self.rb.record_destruction_receipt('asset-1', 'receipt-hsm', 'hsm-admin')
        with self.assertRaises(BookNotClosableError) as ctx:
            self.rb.close_book('asset-1', expected_receipts=['receipt-hsm', 'receipt-archive'])
        self.assertIn('receipt-archive', str(ctx.exception))
        self.assertNotIn('receipt-hsm', str(ctx.exception))
        self.assertEqual(AssetLevel.READ_ONLY, self.rb.effective_level('asset-1'))

        self.rb.record_destruction_receipt('asset-1', 'receipt-archive', 'archive-admin')
        report = self.rb.close_book(
            'asset-1', expected_receipts=['receipt-hsm', 'receipt-archive'])

        self.assertTrue(report.closed)
        self.assertIs(AssetLevel.DESTROYED, report.level)
        self.assertTrue(report.external_deactivated)
        self.assertTrue(report.archive_queryable)
        self.assertEqual(2, len(report.destruction_receipts))
        props = {p.name: p.value for p in self.asset.properties}
        self.assertEqual('destroyed', props['retirement:level'])
        self.assertEqual('true', props['retirement:closed'])

    def test_close_without_any_receipt_is_rejected(self) -> None:
        with self.assertRaises(BookNotClosableError):
            self.rb.close_book('asset-1')
        self.assertFalse(self.rb.report('asset-1').closed)

    def test_report_is_snapshot_and_lists_legal_references(self) -> None:
        self.rb.reference_asset('svc-billing', 'asset-1')
        self.rb.reference_asset('svc-archive', 'asset-1')
        self.rb.submit_end_proof('svc-billing', 'asset-1', 'billing-owner', 'proof-1')

        report = self.rb.report('asset-1')
        self.assertEqual('asset-1', report.asset_ref)
        self.assertEqual('root-key', report.asset_name)
        self.assertEqual(2, len(report.legal_refs))
        with self.assertRaises(AttributeError):
            report.closed = True  # type: ignore[misc]

    def test_unknown_asset_and_service(self) -> None:
        with self.assertRaises(UnknownAssetError):
            self.rb.effective_level('missing')
        with self.assertRaises(UnknownServiceError):
            self.rb.reference_asset('missing', 'asset-1')

    def test_works_with_externally_provided_bom(self) -> None:
        bom = Bom()
        rb = RetirementBom(bom)
        rb.register_asset('key', bom_ref='k1')
        rb.register_service('svc', bom_ref='s1')
        rb.reference_asset('s1', 'k1')
        self.assertIs(bom, rb.bom)
        self.assertIn('k1', [component.bom_ref.value for component in bom.components])
