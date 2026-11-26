# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import json
import unittest
from pathlib import Path

from asn1crypto.pem import unarmor
from registration_acceptance import (
    ApprovedNameChanges,
    ArchiveRecord,
    attribute_type_set,
    compare_archive_csr,
    compare_csr_pair,
    flat_attribute_key,
    flattened_name_text,
    hierarchy_key,
    is_same_registered_entity,
    load_csr,
    subject_of,
)


TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
FIXTURE_DIR = TESTS_DIR / 'fixtures' / 'acceptance'
DECLARATION_PATH = (
    REPO_ROOT / 'registration_acceptance' / 'approved_name_changes.json'
)
AS_OF = '2026-11-27'


class RegistrationAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.declarations = ApprovedNameChanges.load(str(DECLARATION_PATH))
        with (FIXTURE_DIR / 'application_archive.json').open('r', encoding='utf-8') as handle:
            archive = json.load(handle)
        cls.archive_data = archive['records'][0]
        cls.archive_record = ArchiveRecord.from_dict(cls.archive_data)

        cls.hierarchy_a = FIXTURE_DIR / 'same-text-hierarchy-a.csr'
        cls.hierarchy_b = FIXTURE_DIR / 'same-text-hierarchy-b.csr'
        cls.order_swap = FIXTURE_DIR / 'same-text-order-swap.csr'
        cls.legacy_csr = FIXTURE_DIR / cls.archive_data['legacy_csr']
        cls.current_csr = FIXTURE_DIR / cls.archive_data['current_csr']
        cls.extra_csr = FIXTURE_DIR / 'procurement-current-extra-attribute.csr'

    def test_synthetic_csrs_have_valid_signatures(self):
        try:
            from cryptography import x509
        except ImportError:
            self.skipTest('cryptography is available in the local acceptance venv')

        for path in FIXTURE_DIR.glob('*.csr'):
            with self.subTest(path=path.name):
                request = x509.load_pem_x509_csr(path.read_bytes())
                self.assertTrue(request.is_signature_valid)

    def test_same_flat_text_is_separated_by_rdn_hierarchy(self):
        request_a = load_csr(str(self.hierarchy_a))
        request_b = load_csr(str(self.hierarchy_b))
        request_c = load_csr(str(self.order_swap))
        name_a = subject_of(request_a)
        name_b = subject_of(request_b)
        name_c = subject_of(request_c)

        flat_text_a = flattened_name_text(name_a)
        flat_text_b = flattened_name_text(name_b)
        flat_text_c = flattened_name_text(name_c)
        self.assertEqual(flat_attribute_key(name_a), flat_attribute_key(name_b))
        self.assertEqual(flat_text_a, flat_text_b)
        self.assertEqual(flat_text_a, flat_text_c)
        self.assertEqual(attribute_type_set(name_a), attribute_type_set(name_b))
        self.assertEqual(attribute_type_set(name_a), attribute_type_set(name_c))
        self.assertNotEqual(hierarchy_key(name_a), hierarchy_key(name_b))
        self.assertNotEqual(hierarchy_key(name_a), hierarchy_key(name_c))
        self.assertNotEqual(name_a, name_b)
        self.assertNotEqual(name_a, name_c)

        self.assertEqual(3, len(name_a.chosen))
        self.assertEqual(1, len(name_a.chosen[0]))
        self.assertEqual(2, len(name_b.chosen))
        self.assertEqual(2, len(name_b.chosen[0]))
        self.assertEqual(3, len(name_c.chosen))
        self.assertEqual('organizational_unit_name', name_c.chosen[0][0]['type'].native)

        self.assertFalse(
            is_same_registered_entity(
                request_a,
                request_b,
                declarations=self.declarations,
                as_of=AS_OF,
            )
        )
        decision = compare_csr_pair(
            request_a,
            request_b,
            self.declarations,
            as_of=AS_OF,
        )
        self.assertFalse(decision.accepted)
        self.assertEqual('no_approved_normalization_mapping', decision.code)

        order_decision = compare_csr_pair(
            request_a,
            request_c,
            self.declarations,
            as_of=AS_OF,
        )
        self.assertFalse(order_decision.accepted)
        self.assertEqual('no_approved_normalization_mapping', order_decision.code)

    def test_archive_and_new_csr_connect_through_checked_in_declaration(self):
        decision = compare_archive_csr(
            self.archive_record,
            str(self.current_csr),
            self.declarations,
            as_of=AS_OF,
        )

        self.assertTrue(decision.accepted, decision.to_dict())
        self.assertEqual('same_registered_entity', decision.code)
        self.assertEqual(self.archive_data['change_id'], decision.mapping_id)
        self.assertTrue(decision.period_applicable)
        self.assertTrue(decision.attribute_set_matches)
        self.assertTrue(decision.mapping_approved)
        self.assertTrue(decision.hierarchy_matches)

    def test_csr_pair_connects_only_with_declaration(self):
        legacy = load_csr(str(self.legacy_csr))
        current = load_csr(str(self.current_csr))

        self.assertNotEqual(subject_of(legacy), subject_of(current))
        self.assertFalse(is_same_registered_entity(legacy, current))

        missing = compare_csr_pair(legacy, current, None, as_of=AS_OF)
        self.assertFalse(missing.accepted)
        self.assertEqual('no_approved_normalization_mapping', missing.code)

        accepted = compare_csr_pair(
            legacy,
            current,
            self.declarations,
            as_of=AS_OF,
            archive_record=self.archive_record,
        )
        self.assertTrue(accepted.accepted, accepted.to_dict())
        self.assertEqual(self.archive_data['change_id'], accepted.mapping_id)
        self.assertTrue(
            is_same_registered_entity(
                legacy,
                current,
                declarations=self.declarations,
                as_of=AS_OF,
                archive_record=self.archive_record,
            )
        )

    def test_applicable_period_is_enforced(self):
        before = compare_archive_csr(
            self.archive_record,
            str(self.current_csr),
            self.declarations,
            as_of='2025-12-31',
        )
        after = compare_archive_csr(
            self.archive_record,
            str(self.current_csr),
            self.declarations,
            as_of='2028-01-01',
        )

        for decision in (before, after):
            self.assertFalse(decision.accepted)
            self.assertFalse(decision.period_applicable)
            self.assertIn('outside_applicable_period', decision.reasons)
            self.assertTrue(decision.attribute_set_matches)
            self.assertTrue(decision.hierarchy_matches)

    def test_attribute_set_is_enforced_separately_from_hierarchy(self):
        decision = compare_archive_csr(
            self.archive_record,
            str(self.extra_csr),
            self.declarations,
            as_of=AS_OF,
        )
        self.assertFalse(decision.accepted)
        self.assertFalse(decision.attribute_set_matches)
        self.assertIn('attribute_set_mismatch', decision.reasons)

        declaration_data = json.loads(DECLARATION_PATH.read_text(encoding='utf-8'))
        mapping = declaration_data['mappings'][0]
        mapping['new_attribute_types'] = [
            'common_name',
            'organizational_unit_name',
            'organization_name',
        ]
        declarations = ApprovedNameChanges.from_dict(declaration_data)
        mismatched_set = compare_archive_csr(
            self.archive_record,
            str(self.current_csr),
            declarations,
            as_of=AS_OF,
        )
        self.assertFalse(mismatched_set.accepted)
        self.assertFalse(mismatched_set.attribute_set_matches)
        self.assertTrue(mismatched_set.hierarchy_matches)
        self.assertIn('attribute_set_mismatch', mismatched_set.reasons)

    def test_only_approved_mapping_can_connect(self):
        declaration_data = json.loads(DECLARATION_PATH.read_text(encoding='utf-8'))
        declaration_data['mappings'][0]['status'] = 'pending'
        declarations = ApprovedNameChanges.from_dict(declaration_data)

        decision = compare_archive_csr(
            self.archive_record,
            str(self.current_csr),
            declarations,
            as_of=AS_OF,
        )
        self.assertFalse(decision.accepted)
        self.assertFalse(decision.mapping_approved)
        self.assertIn('mapping_not_approved', decision.reasons)

        wrong_archive = ArchiveRecord(
            'APP-OTHER',
            'OTHER-DEPT',
            self.archive_record.normalized_name,
        )
        missing = compare_archive_csr(
            wrong_archive,
            str(self.current_csr),
            self.declarations,
            as_of=AS_OF,
        )
        self.assertFalse(missing.accepted)
        self.assertEqual('no_approved_normalization_mapping', missing.code)

    def test_csr_der_content_is_not_rewritten_by_acceptance(self):
        for path in FIXTURE_DIR.glob('*.csr'):
            with self.subTest(path=path.name):
                pem_bytes = path.read_bytes()
                _, _, original_der = unarmor(pem_bytes)
                parsed = load_csr(pem_bytes)

                compare_archive_csr(
                    self.archive_record,
                    parsed,
                    self.declarations,
                    as_of=AS_OF,
                )

                self.assertEqual(original_der, parsed.dump())


if __name__ == '__main__':
    unittest.main()
