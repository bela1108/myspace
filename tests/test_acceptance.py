"""Tests for offline acceptance planning."""
import unittest

from plyara import AcceptancePlanner
from plyara import plan_acceptance


BOX_RULES = r'''
private rule shared_box_witness {
    meta:
        witness = "box-number"
    strings:
        $box = /BOX-[0-9]{3}/
    condition:
        $box
}

rule alpha_box_route : box_group_a {
    meta:
        proves = "box_identity,route_check"
    strings:
        $route = "ALPHA-ROUTE"
    condition:
        $route and shared_box_witness
}

rule beta_box_lot : box_group_b {
    meta:
        proves = "box_identity"
    strings:
        $lot = "BETA-LOT"
    condition:
        $lot and shared_box_witness
}

rule independent_seal_check {
    meta:
        proves = "box_identity"
    strings:
        $seal = "INDEPENDENT-SEAL"
    condition:
        $seal
}
'''


class AcceptancePlanningTests(unittest.TestCase):
    """Verify minimum package selection and witness de-duplication."""

    def setUp(self):
        """Create the finite box-number acceptance fixture."""
        self.samples = [
            {
                'id': 'BOX-101',
                'package': 'alpha-boxes',
                'approved': True,
                'approval_id': 'approval-101',
                'hits': ['alpha_box_route'],
            },
            {
                'id': 'BOX-202',
                'package': 'beta-boxes',
                'approved': True,
                'approval_id': 'approval-202',
                'hits': ['beta_box_lot'],
            },
            {
                'id': 'BOX-303',
                'package': 'gamma-seals',
                'approved': True,
                'approval_id': 'approval-303',
                'hits': ['independent_seal_check'],
            },
            {
                'id': 'BOX-404',
                'package': 'delta-backup',
                'approved': True,
                'approval_id': 'approval-404',
                'hits': ['independent_seal_check'],
            },
            {
                'id': 'BOX-505',
                'package': 'epsilon-unapproved',
                'approved': False,
                'hits': ['independent_seal_check'],
            },
        ]
        self.obligations = [
            {'id': 'route-obligation', 'use': 'route_check'},
            {'id': 'dual-box-obligation', 'use': 'box_identity', 'dual': True},
        ]
        self.effort = {
            'alpha-boxes': 1,
            'beta-boxes': 1,
            'gamma-seals': 4,
            'delta-backup': 9,
            'epsilon-unapproved': 1,
        }

    def test_parse_structure_exposes_shared_private_witness(self):
        planner = AcceptancePlanner(BOX_RULES)

        self.assertIn('shared_box_witness', planner.rules)
        self.assertTrue(planner.rules['shared_box_witness']['private'])
        self.assertEqual(
            ('shared_box_witness',),
            planner.rules['alpha_box_route']['witness_rules'],
        )
        self.assertEqual(
            ('shared_box_witness',),
            planner.rules['beta_box_lot']['witness_rules'],
        )
        self.assertNotIn(
            'shared_box_witness',
            planner.rules['independent_seal_check']['witness_rules'],
        )

    def test_minimum_plan_rejects_two_detections_with_shared_witness(self):
        plan = plan_acceptance(
            BOX_RULES,
            self.samples,
            self.obligations,
            self.effort,
        )

        self.assertTrue(plan['feasible'])
        self.assertEqual(('alpha-boxes', 'gamma-seals'), plan['selected_packages'])
        self.assertEqual(5, plan['total_effort'])
        self.assertEqual(('BOX-101', 'BOX-303'), plan['selected_samples'])

        dual_evidence = plan['coverage']['dual-box-obligation']
        self.assertEqual(2, len(dual_evidence))
        self.assertEqual(
            {'alpha_box_route', 'independent_seal_check'},
            {item['rule'] for item in dual_evidence},
        )

        route_evidence = plan['coverage']['route-obligation']
        self.assertEqual(1, len(route_evidence))
        self.assertEqual('alpha_box_route', route_evidence[0]['rule'])

    def test_same_rule_on_distinct_packages_can_be_dual_evidence(self):
        yar = '''
        private rule parsed_witness {
            strings: $w = "WITNESS"
            condition: $w
        }
        rule reusable_box_check {
            meta:
                proves = "box_identity"
            condition:
                parsed_witness
        }
        '''
        samples = [
            {'id': 'BOX-1', 'package': 'package-a', 'hits': ['reusable_box_check']},
            {'id': 'BOX-2', 'package': 'package-b', 'hits': ['reusable_box_check']},
        ]
        obligation = {'id': 'dual', 'use': 'box_identity', 'count': 2}

        plan = plan_acceptance(yar, samples, obligation, {'package-a': 3, 'package-b': 2})

        self.assertTrue(plan['feasible'])
        self.assertEqual(('package-a', 'package-b'), plan['selected_packages'])
        self.assertEqual(5, plan['total_effort'])

    def test_explicit_shared_witness_cannot_be_used_twice(self):
        samples = [
            {
                'id': 'sample-a',
                'package': 'package-a',
                'witnesses': ['same-box-number-777'],
                'hits': ['independent_seal_check'],
            },
            {
                'id': 'sample-b',
                'package': 'package-b',
                'witnesses': ['same-box-number-777'],
                'hits': ['independent_seal_check'],
            },
            {
                'id': 'sample-c',
                'package': 'package-c',
                'witnesses': ['different-box-number-888'],
                'hits': ['independent_seal_check'],
            },
        ]
        obligation = {'id': 'dual', 'use': 'box_identity', 'dual': True}

        plan = plan_acceptance(
            BOX_RULES,
            samples,
            obligation,
            {'package-a': 1, 'package-b': 1, 'package-c': 3},
        )

        self.assertTrue(plan['feasible'])
        self.assertEqual(('package-a', 'package-c'), plan['selected_packages'])
        self.assertEqual(4, plan['total_effort'])

    def test_hit_cannot_expand_rule_proven_uses(self):
        samples = [{
            'id': 'BOX-909',
            'package': 'package-a',
            'hits': [{'rule': 'independent_seal_check', 'uses': ['manifest_check']}],
        }]
        obligation = {'id': 'manifest', 'use': 'manifest_check'}

        plan = plan_acceptance(BOX_RULES, samples, obligation, {'package-a': 1})

        self.assertFalse(plan['feasible'])
        self.assertIn('manifest', plan['uncovered'])

    def test_missing_second_package_is_infeasible(self):
        samples = [self.samples[0]]
        obligation = {'id': 'dual', 'use': 'box_identity', 'dual': True}

        plan = plan_acceptance(BOX_RULES, samples, obligation, self.effort)

        self.assertFalse(plan['feasible'])
        self.assertIsNone(plan['total_effort'])
        self.assertEqual(('dual',), plan['uncovered'])


if __name__ == '__main__':
    unittest.main()
